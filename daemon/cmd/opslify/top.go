package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/trace"
	"github.com/spf13/cobra"
)

// topCmd is the terminal-native counterpart of `opslify ui` for headless hosts:
// a live session table plus the streamed output of a selected session, consuming
// the SAME session API + F3.2 SSE trace stream (no new data source). It is a
// dependency-free polling TUI (see topModel) rather than a full Bubble Tea app —
// a deliberate v1 trim documented in the F3.5 report: it avoids a new dependency
// and keeps the whole loop unit-testable, at the cost of TUI polish (no mouse,
// no scrollback pane). Data parity with the web UI is the requirement, and it
// holds.
func topCmd() *cobra.Command {
	var (
		socket   string
		session  string
		interval time.Duration
		once     bool
	)
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Live session table + selected-session stream in the terminal (same API as `ui`)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(socket)
			m := &topModel{selected: session, maxStream: 200}

			// Stream the selected session's output in the background, if one is set.
			ctx := cmd.Context()
			if session != "" {
				go func() {
					_ = c.streamTrace(ctx, session, 0, func(ev trace.Event) {
						m.addEvent(ev)
					})
				}()
			}

			out := cmd.OutOrStdout()
			render := func() error {
				views, err := c.listSessions(ctx)
				if err != nil {
					m.setErr(err)
				} else {
					m.setSessions(views)
				}
				fmt.Fprint(out, m.render(clearScreen))
				return nil
			}
			if once {
				return render()
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			if err := render(); err != nil {
				return err
			}
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					if err := render(); err != nil {
						return err
					}
				}
			}
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&session, "session", "", "stream this session's live output beneath the table")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "refresh interval")
	cmd.Flags().BoolVar(&once, "once", false, "render a single frame and exit (non-interactive / CI)")
	return cmd
}

// clearScreen is the ANSI home+clear sequence prepended to each live frame.
const clearScreen = "\x1b[H\x1b[2J"

// topModel is the `opslify top` view state. It is concurrency-safe (the trace
// stream mutates it from a goroutine while the ticker reads it) and its render
// method is pure, so a single frame can be unit-tested without a real daemon.
type topModel struct {
	mu        sync.Mutex
	sessions  []sessionView
	selected  string
	stream    []string // recent rendered output lines from the selected session
	maxStream int
	err       error
}

func (m *topModel) setSessions(v []sessionView) {
	m.mu.Lock()
	m.sessions = v
	m.err = nil
	m.mu.Unlock()
}
func (m *topModel) setErr(err error) { m.mu.Lock(); m.err = err; m.mu.Unlock() }

// addEvent folds a trace event into the streamed-output tail (exec.output chunks)
// and appends structured lifecycle markers, capped to maxStream lines.
func (m *topModel) addEvent(ev trace.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := ev.Payload
	switch ev.Type {
	case trace.TypeExecOutput:
		if t, _ := p["truncated"].(bool); t {
			m.appendLocked("[output truncated at cap]")
			return
		}
		if chunk, ok := p["chunk"].(string); ok {
			for _, ln := range strings.Split(strings.TrimRight(stripAnsiGo(chunk), "\n"), "\n") {
				m.appendLocked(ln)
			}
		}
	case trace.TypeExecStart:
		m.appendLocked(fmt.Sprintf("$ %v", p["argv"]))
	case trace.TypeExecEnd:
		m.appendLocked(fmt.Sprintf("[exit %v]", p["exit_code"]))
	case trace.TypeSessionEnd:
		m.appendLocked(fmt.Sprintf("[session end: %v]", p["reason"]))
	}
}

func (m *topModel) appendLocked(line string) {
	m.stream = append(m.stream, line)
	if len(m.stream) > m.maxStream {
		m.stream = m.stream[len(m.stream)-m.maxStream:]
	}
}

// render produces one frame: a header, the session table, and (if a session is
// selected) its recent streamed output. prefix is prepended (e.g. the ANSI
// clear-screen for live mode; empty for a captured single frame).
func (m *topModel) render(prefix string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	b.WriteString(prefix)
	fmt.Fprintf(&b, "opslify top — %d session(s) @ %s   (same data as `opslify ui`)\n\n",
		len(m.sessions), time.Now().Format("15:04:05"))

	if m.err != nil {
		fmt.Fprintf(&b, "daemon unreachable: %v\n", m.err)
		return b.String()
	}

	renderTopTable(&b, m.sessions, m.selected)

	if m.selected != "" {
		fmt.Fprintf(&b, "\n── stream: %s ──\n", m.selected)
		if len(m.stream) == 0 {
			b.WriteString("(waiting for output…)\n")
		} else {
			for _, ln := range m.stream {
				b.WriteString(ln)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func renderTopTable(w io.Writer, views []sessionView, selected string) {
	if len(views) == 0 {
		fmt.Fprintln(w, "(no active sessions)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  \tSESSION ID\tMODE\tTIER\tSTATE\tAGE\tTTL REMAINING")
	for _, v := range views {
		marker := "  "
		if v.SessionID == selected {
			marker = "▶ "
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			marker, v.SessionID, v.Mode, v.Tier, v.State,
			humanSeconds(v.AgeSeconds), ttlLabel(v.TTLRemaining))
	}
	tw.Flush()
}

// stripAnsiGo mirrors the web UI's ANSI stripper for the terminal stream tail so
// control sequences don't corrupt the frame layout.
func stripAnsiGo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !(s[j] >= '@' && s[j] <= '~') {
				j++
			}
			if j < len(s) {
				j++ // consume the final byte
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
