package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/opslify-com/opslifyd/internal/daemon"
	"github.com/opslify-com/opslifyd/internal/wssync"
	"github.com/spf13/cobra"
)

// pollInterval is how often the sync engine re-reads the sandbox manifest to
// catch the agent's edits. A debounced fsnotify watcher catches host edits
// promptly; sandbox edits are only visible through this poll, so ~2s is the
// documented worst-case sandbox→host latency.
const pollInterval = 2 * time.Second

// debounceWindow coalesces a burst of host fsnotify events (an editor's
// write-rename-chmod dance, a `git checkout`) into a single reconcile.
const debounceWindow = 400 * time.Millisecond

// workspaceCmd is the F7.3 host-linked-workspace surface: sync a host dir into a
// sandbox /workspace and keep them bidirectionally in sync (sync), or pull a
// /workspace out one-shot (export).
func workspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Link a host directory to a sandbox /workspace (sync, export)",
	}
	cmd.AddCommand(workspaceSyncCmd(), workspaceExportCmd(), workspaceInstallCmd())
	return cmd
}

func workspaceSyncCmd() *cobra.Command {
	var (
		socket    string
		sessionID string
		newSess   bool
		once      bool
		tier      string
		name      string
	)
	cmd := &cobra.Command{
		Use:   "sync <host-dir>",
		Short: "Copy a host dir into a sandbox /workspace and keep them in sync (copy-not-bind)",
		Long: "Copies <host-dir> into the target session's /workspace (excluding secrets), then\n" +
			"watches both sides: host edits flow in, the agent's edits flow back out.\n" +
			"No bind mount is created — all movement is explicit, excludable, undoable file transfer.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostDir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if fi, err := os.Stat(hostDir); err != nil || !fi.IsDir() {
				return fmt.Errorf("host dir %q is not a directory", hostDir)
			}
			if newSess == (sessionID != "") {
				return fmt.Errorf("specify exactly one of --new or --session <id>")
			}
			c := newClient(socket)
			ctx := cmd.Context()

			id := sessionID
			if newSess {
				created, err := c.createSession(ctx, createReq{Mode: "workspace", Tier: tier, Name: name})
				if err != nil {
					return err
				}
				id = created.SessionID
				fmt.Fprintf(cmd.OutOrStdout(), "created session %s\n", id)
			}

			eng := newSyncEngine(c, id, hostDir, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err := eng.initialCopyIn(ctx); err != nil {
				return err
			}
			if once {
				return eng.reconcile(ctx)
			}
			return eng.watch(ctx)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	cmd.Flags().StringVar(&sessionID, "session", "", "target an existing session id")
	cmd.Flags().BoolVar(&newSess, "new", false, "create a fresh workspace session to sync into")
	cmd.Flags().BoolVar(&once, "once", false, "do a single bidirectional reconcile and exit")
	cmd.Flags().StringVar(&tier, "tier", "", "isolation tier for --new (default: daemon default)")
	cmd.Flags().StringVar(&name, "name", "", "workspace name for --new")
	return cmd
}

func workspaceExportCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "export <session-id> <host-dir>",
		Short: "One-shot pull of a session's /workspace to a host dir (no watch)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			hostDir, err := filepath.Abs(args[1])
			if err != nil {
				return err
			}
			if err := os.MkdirAll(hostDir, 0o755); err != nil {
				return err
			}
			c := newClient(socket)
			ctx := cmd.Context()
			eng := newSyncEngine(c, id, hostDir, cmd.OutOrStdout(), cmd.ErrOrStderr())
			man, err := c.fetchManifest(ctx, id)
			if err != nil {
				return err
			}
			n := 0
			for _, e := range man {
				if wssync.Excluded(e.RelPath) {
					continue
				}
				if err := eng.pull(ctx, e.RelPath); err != nil {
					return err
				}
				n++
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exported %d file(s) from %s to %s\n", n, id, hostDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocketPath, "daemon Unix socket path")
	return cmd
}

// syncEngine holds the CLI-side bidirectional-sync state for one host↔sandbox
// pairing. All watcher and diff logic lives here (portable); the daemon only
// serves the read-only manifest and the existing file PUT/GET.
type syncEngine struct {
	c       *client
	id      string
	hostDir string
	out     io.Writer
	errOut  io.Writer
	filter  *wssync.Filter

	// base is the last-reconciled content hash per rel path (the merge base for
	// three-way conflict detection). A rel absent from base is unseen/new.
	base map[string]string
	// tombstone marks a rel deleted on one side that we deliberately do NOT
	// resurrect from the other (avoids fighting an intentional delete).
	tombstone map[string]bool
	// lastConflict records the sandbox hash we already wrote a conflict sibling
	// for, so we don't rewrite it on every poll.
	lastConflict map[string]string

	backupDone bool
}

func newSyncEngine(c *client, id, hostDir string, out, errOut io.Writer) *syncEngine {
	return &syncEngine{
		c:            c,
		id:           id,
		hostDir:      hostDir,
		out:          out,
		errOut:       errOut,
		filter:       wssync.LoadFilter(hostDir),
		base:         map[string]string{},
		tombstone:    map[string]bool{},
		lastConflict: map[string]string{},
	}
}

// initialCopyIn walks the host dir and uploads every non-excluded file into the
// sandbox /workspace, seeding the merge base. Secrets are filtered BEFORE any
// upload — the deny-list is a security control applied at the trust boundary.
func (e *syncEngine) initialCopyIn(ctx context.Context) error {
	files, err := e.hostFiles()
	if err != nil {
		return err
	}
	n := 0
	for rel, h := range files {
		content, err := os.ReadFile(e.hostPath(rel))
		if err != nil {
			return err
		}
		if err := e.c.uploadFile(ctx, e.id, rel, content); err != nil {
			return fmt.Errorf("copy-in %s: %w", rel, err)
		}
		e.base[rel] = h
		n++
	}
	fmt.Fprintf(e.out, "copied %d file(s) into %s /workspace (secrets excluded); watching\n", n, e.id)
	return nil
}

// hostFiles returns the non-excluded host files as rel→contentHash. Symlinks are
// not followed (they could point out of the tree).
func (e *syncEngine) hostFiles() (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(e.hostDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(e.hostDir, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if e.filter.Excluded(rel) {
			return nil
		}
		h, err := hashHostFile(p)
		if err != nil {
			return nil
		}
		out[rel] = h
		return nil
	})
	return out, err
}

// reconcile runs one full bidirectional diff+apply pass over host and sandbox.
func (e *syncEngine) reconcile(ctx context.Context) error {
	hostFiles, err := e.hostFiles()
	if err != nil {
		return err
	}
	man, err := e.c.fetchManifest(ctx, e.id)
	if err != nil {
		return err
	}
	sandbox := map[string]string{}
	for _, m := range man {
		if wssync.Excluded(m.RelPath) {
			continue // never treat a deny-listed file as a user file (defence in depth)
		}
		sandbox[m.RelPath] = m.SHA256
	}

	// Union of every rel we know about across both sides and the base.
	rels := map[string]struct{}{}
	for r := range hostFiles {
		rels[r] = struct{}{}
	}
	for r := range sandbox {
		rels[r] = struct{}{}
	}
	for r := range e.base {
		rels[r] = struct{}{}
	}

	for _, rel := range sortedKeys(rels) {
		if err := e.reconcileOne(ctx, rel, hostFiles, sandbox); err != nil {
			return err
		}
	}
	return nil
}

// reconcileOne applies the sync decision for a single rel path.
func (e *syncEngine) reconcileOne(ctx context.Context, rel string, host, sandbox map[string]string) error {
	hostHash, onHost := host[rel]
	sbHash, onSandbox := sandbox[rel]
	baseHash, hadBase := e.base[rel]

	switch {
	case onHost && onSandbox:
		if hostHash == sbHash {
			e.base[rel] = hostHash // converged
			return nil
		}
		hostChanged := !hadBase || hostHash != baseHash
		sbChanged := !hadBase || sbHash != baseHash
		switch {
		case hostChanged && !sbChanged:
			return e.push(ctx, rel, host)
		case sbChanged && !hostChanged:
			return e.pull(ctx, rel)
		default:
			// Both sides diverged from base: never clobber the operator's edit.
			return e.conflict(ctx, rel, sbHash)
		}
	case onHost && !onSandbox:
		if e.tombstone[rel] {
			return nil // agent deleted it deliberately; don't re-push
		}
		if hadBase {
			// Was synced, now gone from the sandbox: the agent deleted it. Keep the
			// host copy (never let the sandbox silently delete a host file) and
			// tombstone so we don't fight it. Warn.
			fmt.Fprintf(e.errOut, "[opslify: sandbox deleted %s — host copy kept (quarantine); rm it yourself to confirm]\n", rel)
			e.tombstone[rel] = true
			delete(e.base, rel)
			return nil
		}
		// New host file (or the initial-copy path): push it in.
		return e.push(ctx, rel, host)
	case !onHost && onSandbox:
		if e.tombstone[rel] {
			return nil // host deleted it deliberately; don't re-pull
		}
		if hadBase {
			// Was synced, now gone from the host: the operator deleted it. We cannot
			// propagate a delete into the sandbox through the mediated (read/write-
			// only) transfer surface, so warn and tombstone rather than resurrecting.
			fmt.Fprintf(e.errOut, "[opslify: host deleted %s — cannot propagate delete into sandbox via mediated transfer (v1); sandbox copy retained]\n", rel)
			e.tombstone[rel] = true
			delete(e.base, rel)
			return nil
		}
		// New sandbox file: pull it out.
		return e.pull(ctx, rel)
	default:
		// On neither side any more; forget it.
		delete(e.base, rel)
		delete(e.tombstone, rel)
		return nil
	}
}

// push uploads the host copy of rel into the sandbox /workspace.
func (e *syncEngine) push(ctx context.Context, rel string, host map[string]string) error {
	content, err := os.ReadFile(e.hostPath(rel))
	if err != nil {
		return err
	}
	if err := e.c.uploadFile(ctx, e.id, rel, content); err != nil {
		return fmt.Errorf("push %s: %w", rel, err)
	}
	e.base[rel] = host[rel]
	delete(e.tombstone, rel)
	fmt.Fprintf(e.out, "→ %s (host→sandbox)\n", rel)
	return nil
}

// pull downloads the sandbox copy of rel and writes it to the host dir, after
// taking the one-time safety backup for a non-git host dir.
func (e *syncEngine) pull(ctx context.Context, rel string) error {
	content, err := e.c.downloadFile(ctx, e.id, rel)
	if err != nil {
		return fmt.Errorf("pull %s: %w", rel, err)
	}
	if err := e.ensureBackup(); err != nil {
		return err
	}
	dst, err := e.safeHostPath(rel)
	if err != nil {
		fmt.Fprintf(e.errOut, "[opslify: refused to write %s outside host dir]\n", rel)
		return nil
	}
	if err := writeHostFile(dst, content); err != nil {
		return err
	}
	e.base[rel] = sha256Hex(content)
	delete(e.tombstone, rel)
	fmt.Fprintf(e.out, "← %s (sandbox→host)\n", rel)
	return nil
}

// conflict writes the sandbox version of a both-sides-changed file to a
// `.opslify-conflict` sibling instead of overwriting the operator's newer edit,
// and warns. Both the host file and the sandbox file are left in place until the
// operator resolves the conflict; the sandbox version is preserved in the sibling
// so nothing is lost.
func (e *syncEngine) conflict(ctx context.Context, rel, sbHash string) error {
	if e.lastConflict[rel] == sbHash {
		return nil // already recorded this sandbox version
	}
	content, err := e.c.downloadFile(ctx, e.id, rel)
	if err != nil {
		return fmt.Errorf("conflict %s: %w", rel, err)
	}
	if err := e.ensureBackup(); err != nil {
		return err
	}
	dst, err := e.safeHostPath(rel + ".opslify-conflict")
	if err != nil {
		return nil
	}
	if err := writeHostFile(dst, content); err != nil {
		return err
	}
	e.lastConflict[rel] = sbHash
	fmt.Fprintf(e.errOut, "[opslify: conflict on %s — both sides changed; sandbox version saved to %s.opslify-conflict (your file untouched)]\n", rel, rel)
	return nil
}

// ensureBackup takes the one-time safety snapshot before the first sync-back
// write. A git host dir is left to git (reviewable/revertable); a non-git dir
// gets a timestamped `.opslify-backup-<ts>/` copy with printed restore steps.
func (e *syncEngine) ensureBackup() error {
	if e.backupDone {
		return nil
	}
	e.backupDone = true
	if fi, err := os.Stat(filepath.Join(e.hostDir, ".git")); err == nil && fi.IsDir() {
		fmt.Fprintf(e.out, "[opslify: %s is a git repo — review sync-back with `git status` / revert with `git checkout`]\n", e.hostDir)
		return nil
	}
	ts := time.Now().Format("20060102-150405")
	backup := filepath.Join(e.hostDir, ".opslify-backup-"+ts)
	if err := os.MkdirAll(backup, 0o755); err != nil {
		return err
	}
	files, err := e.hostFiles()
	if err != nil {
		return err
	}
	for rel := range files {
		src := e.hostPath(rel)
		dst := filepath.Join(backup, filepath.FromSlash(rel))
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if err := writeHostFile(dst, data); err != nil {
			return err
		}
	}
	fmt.Fprintf(e.out, "[opslify: non-git host dir — backed up current state to %s]\n", backup)
	fmt.Fprintf(e.out, "[opslify: to restore, copy files back from that directory (cp -a %s/. %s/)]\n", backup, e.hostDir)
	return nil
}

// watch runs the continuous sync loop: a debounced fsnotify watcher on the host
// dir plus a periodic sandbox manifest poll, until interrupted (Ctrl-C), then a
// final reconcile.
func (e *syncEngine) watch(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	e.addWatchesRecursive(w, e.hostDir)

	if err := e.reconcile(ctx); err != nil {
		fmt.Fprintf(e.errOut, "[opslify: reconcile error: %v]\n", err)
	}

	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	var debounce <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(e.out, "[opslify: stopping — final reconcile]")
			// Fresh context: the signalled one is already cancelled.
			return e.reconcile(context.Background())
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			// A newly-created directory needs its own watch to see files under it.
			if ev.Op&fsnotify.Create != 0 {
				if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
					e.addWatchesRecursive(w, ev.Name)
				}
			}
			debounce = time.After(debounceWindow)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(e.errOut, "[opslify: watcher error: %v]\n", err)
		case <-debounce:
			debounce = nil
			if err := e.reconcile(ctx); err != nil {
				fmt.Fprintf(e.errOut, "[opslify: reconcile error: %v]\n", err)
			}
		case <-poll.C:
			if err := e.reconcile(ctx); err != nil {
				fmt.Fprintf(e.errOut, "[opslify: reconcile error: %v]\n", err)
			}
		}
	}
}

// addWatchesRecursive adds a watch on dir and every subdirectory (fsnotify is
// not recursive). Excluded dirs (e.g. .git) are skipped to avoid churn.
func (e *syncEngine) addWatchesRecursive(w *fsnotify.Watcher, dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(e.hostDir, p)
		if err == nil && rel != "." {
			rel = filepath.ToSlash(rel)
			if e.filter.Excluded(rel + "/x") { // probe a child to test dir exclusion
				return filepath.SkipDir
			}
		}
		_ = w.Add(p)
		return nil
	})
}

// hostPath maps a rel path to its absolute host path (no escape check — used
// only for rels produced by our own host walk).
func (e *syncEngine) hostPath(rel string) string {
	return filepath.Join(e.hostDir, filepath.FromSlash(rel))
}

// safeHostPath maps a rel path (which may originate from the untrusted sandbox
// manifest) to a host path, refusing anything that would escape the host dir.
func (e *syncEngine) safeHostPath(rel string) (string, error) {
	if strings.ContainsRune(rel, '\x00') {
		return "", fmt.Errorf("NUL in path")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("path escapes host dir")
	}
	host := filepath.Join(e.hostDir, clean)
	rootClean := filepath.Clean(e.hostDir)
	if host != rootClean && !strings.HasPrefix(host, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes host dir")
	}
	return host, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func writeHostFile(dst string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, content, 0o644)
}

func hashHostFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
