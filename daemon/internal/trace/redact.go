package trace

import (
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// F3.3 — Redaction v1.
//
// PatternRedactor is the real Redactor that drops into the F3.1 emit seam
// (Recorder.Emit calls Redactor.Redact BEFORE the sink hashes the payload, so
// the chain commits to the REDACTED bytes — there is no window where a raw
// secret is hashed, buffered, or written).
//
// It walks a payload's string values (argv elements, output chunks, cwd, file
// paths, reason, …) and replaces any secret-shaped substring with a fixed
// [REDACTED:<type>] marker. Integers (exit_code, duration_ms, size, offset,
// seq) are structurally never touched — only strings are scanned — so replay
// and hashing of numeric fields is unaffected.
//
// Guarantees:
//   - Deterministic: pattern order is a fixed slice, entropy tokenisation is a
//     left-to-right scan, no map-iteration-order dependence, no randomness.
//     Same input → same output → stable hashes.
//   - Fail closed: Redact never returns a raw payload. Any panic in scanning is
//     recovered and the whole payload is HARD-redacted (every string value
//     replaced with [REDACTED:error]); a scan is otherwise pure and bounded.
//   - No catastrophic backtracking: every regex is linear/bounded (no nested
//     unbounded quantifiers, bounded {0,N} spans), and the entropy pass is a
//     single O(n) scan — a hostile output chunk cannot hang the daemon.
//
// KNOWN v1 GAP (documented, not silently ignored): redaction is per-string. A
// secret split across two exec.output chunks (each emitted as a separate event)
// is scanned independently, so a token straddling the chunk boundary can evade
// the per-chunk scan. This is a v1 limitation; the real secret-never-in-sandbox
// guarantee comes from P5 (broker), and this pass is defence-in-depth for the
// trace. See RedactorConfig for the tunables. Callers that need boundary-safe
// redaction must reassemble the stream before emitting.

// RedactType is the bucket a redaction is counted under and the label written
// into the [REDACTED:<type>] marker.
type RedactType string

const (
	RedactAWSKey     RedactType = "aws-key"
	RedactGCPSA      RedactType = "gcp-sa"
	RedactBearer     RedactType = "bearer"
	RedactJWT        RedactType = "jwt"
	RedactAssignment RedactType = "assignment"
	RedactEntropy    RedactType = "entropy"
	// redactError is the hard-redaction marker used only on the fail-closed
	// panic path; it is intentionally NOT in the configurable pattern set.
	redactError RedactType = "error"
)

// Default redaction tunables. The entropy defaults are chosen to catch the
// known secret shapes (base64/base62 tokens, AWS secret keys) while NOT
// over-scrubbing ordinary DevOps output: pure-hex output (git SHAs, hex UUIDs)
// has a per-char Shannon entropy ceiling of log2(16) = 4.0 bits, so a threshold
// strictly above 4.0 excludes all hex by construction, and a 24-char length
// floor keeps short identifiers out.
const (
	DefaultEntropyThreshold   = 4.2 // bits/char; > 4.0 hex ceiling
	DefaultEntropyLengthFloor = 24
)

// RedactorConfig configures the PatternRedactor. Zero-value fields are filled
// with safe defaults by NewPatternRedactor, so an operator config with no
// redaction section still redacts (fail-safe defaults, never fail-open).
type RedactorConfig struct {
	// EntropyThreshold is the minimum per-char Shannon entropy (bits) for the
	// generic high-entropy catch-all. <= 0 => DefaultEntropyThreshold.
	EntropyThreshold float64
	// EntropyLengthFloor is the minimum token length the entropy heuristic
	// considers. <= 0 => DefaultEntropyLengthFloor.
	EntropyLengthFloor int
	// DisabledPatterns lists RedactType buckets to turn OFF (opt-out, so the
	// default of an empty list keeps every pattern ON — never fail-open on an
	// unset config). The entropy catch-all is disabled with "entropy".
	DisabledPatterns []string
}

// namedPattern is one fixed-order regex rule. Order is significant and stable:
// specific shapes run before the generic entropy pass, and the markers they
// insert contain no high-entropy token, so the entropy pass never re-flags a
// prior replacement.
type namedPattern struct {
	typ RedactType
	re  *regexp.Regexp
	// keepPrefixGroup, when >0, is the submatch index preserved verbatim in the
	// replacement (e.g. the "password=" key in an assignment) with only the
	// value scrubbed. 0 means the whole match is replaced.
	keepPrefixGroup int
}

// PatternRedactor is the production Redactor. It is safe for concurrent use by
// many session recorders (the shared instance the daemon wires): the compiled
// patterns are immutable and the only mutable state is atomic counters.
type PatternRedactor struct {
	patterns     []namedPattern
	entropyOn    bool
	entropyMin   float64
	entropyFloor int

	// panicHook is a test-only seam to force the fail-closed path; nil in
	// production. It runs inside the recover scope, so a panic here proves the
	// hard-redaction fallback rather than crashing the daemon or leaking raw.
	panicHook func()

	// counts is the process-cumulative redaction tally bucketed by type — an
	// observability metric only. It records COUNTS, never contents: no length,
	// prefix, or any byte of the original value is retained.
	counts sync.Map // RedactType -> *int64
}

var _ Redactor = (*PatternRedactor)(nil)

// Compiled once at package init. Every span is bounded ({0,N}) — no nested
// unbounded quantifier — so none can backtrack catastrophically.
var (
	// AWS access-key / temporary-key IDs.
	reAWSKey = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	// PEM private-key blocks (GCP service-account JSON embeds one). The body is a
	// bounded [\s\S]{0,4096} with a non-greedy close; bounded => linear.
	// Go's regexp is RE2: guaranteed linear time with NO backtracking, so even an
	// unbounded lazy body cannot hang the daemon (RE2 caps bounded repeats at a
	// product of 1000, too small for a full PEM key, so the body stays unbounded
	// and relies on RE2's linearity rather than a span cap).
	reGCPSA = regexp.MustCompile(`-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----[\s\S]*?-----END [A-Z ]{0,32}PRIVATE KEY-----`)
	// Bearer <token> authorization values.
	reBearer = regexp.MustCompile(`\bBearer\s+[A-Za-z0-9\-._~+/]{8,512}={0,2}`)
	// JWTs (eyJ… header . payload . signature). Each segment bounded.
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,512}\.[A-Za-z0-9_-]{4,1000}\.[A-Za-z0-9_-]{4,512}`)
	// key=value / key: value secret assignments. Group 1 (the key + delimiter)
	// is preserved; the value is scrubbed. Value span bounded to 256.
	reAssign = regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret[_-]?access[_-]?key|access[_-]?key[_-]?id|access[_-]?key|secret[_-]?key|api[_-]?key|auth[_-]?token|token|secret)\s*[=:]\s*)("?[^\s"',;&]{3,256}"?)`)
)

// NewPatternRedactor builds the v1 redactor from cfg, applying safe defaults for
// any unset field. Disabled patterns are omitted from the fixed-order slice.
func NewPatternRedactor(cfg RedactorConfig) *PatternRedactor {
	disabled := map[RedactType]bool{}
	for _, d := range cfg.DisabledPatterns {
		disabled[RedactType(strings.TrimSpace(d))] = true
	}

	all := []namedPattern{
		{typ: RedactAWSKey, re: reAWSKey},
		{typ: RedactGCPSA, re: reGCPSA},
		{typ: RedactJWT, re: reJWT},
		{typ: RedactBearer, re: reBearer},
		{typ: RedactAssignment, re: reAssign, keepPrefixGroup: 1},
	}
	pats := make([]namedPattern, 0, len(all))
	for _, p := range all {
		if !disabled[p.typ] {
			pats = append(pats, p)
		}
	}

	th := cfg.EntropyThreshold
	if th <= 0 {
		th = DefaultEntropyThreshold
	}
	floor := cfg.EntropyLengthFloor
	if floor <= 0 {
		floor = DefaultEntropyLengthFloor
	}

	return &PatternRedactor{
		patterns:     pats,
		entropyOn:    !disabled[RedactEntropy],
		entropyMin:   th,
		entropyFloor: floor,
	}
}

// Redact implements Redactor. It scrubs every string value in the payload and
// returns the payload to hash+store. It is deterministic and fails CLOSED: on
// any panic it returns a fully hard-redacted payload rather than the raw one.
func (r *PatternRedactor) Redact(_ EventType, payload map[string]any) (out map[string]any) {
	if payload == nil {
		return payload
	}
	defer func() {
		if rec := recover(); rec != nil {
			// Fail closed: never return the raw payload. Hard-redact every string
			// value in a fresh copy so no raw byte can leak downstream.
			out = hardRedact(payload)
		}
	}()

	if r.panicHook != nil {
		r.panicHook()
	}
	counts := map[RedactType]int{}
	out = r.scrubValue(payload, counts).(map[string]any)
	r.addCounts(counts)
	return out
}

// scrubValue recursively scrubs a payload value. Only strings are scanned;
// numbers, bools and nil pass through untouched (integers are never redacted).
// It returns a new value graph (no in-place mutation) for determinism and to
// avoid corrupting a caller's map.
func (r *PatternRedactor) scrubValue(v any, counts map[RedactType]int) any {
	switch t := v.(type) {
	case string:
		return r.scrubString(t, counts)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = r.scrubString(s, counts)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = r.scrubValue(e, counts)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = r.scrubValue(e, counts)
		}
		return out
	default:
		return v
	}
}

// scrubString applies each enabled fixed-order pattern, then the entropy pass.
// It counts matches by type into counts (counts only — never the value).
func (r *PatternRedactor) scrubString(s string, counts map[RedactType]int) string {
	for _, p := range r.patterns {
		marker := "[REDACTED:" + string(p.typ) + "]"
		if p.keepPrefixGroup > 0 {
			// Count then replace, preserving the key/delimiter prefix group.
			n := len(p.re.FindAllStringIndex(s, -1))
			if n == 0 {
				continue
			}
			counts[p.typ] += n
			s = p.re.ReplaceAllString(s, "${1}"+marker)
			continue
		}
		n := len(p.re.FindAllStringIndex(s, -1))
		if n == 0 {
			continue
		}
		counts[p.typ] += n
		s = p.re.ReplaceAllString(s, marker)
	}
	if r.entropyOn {
		s = r.scrubEntropy(s, counts)
	}
	return s
}

// entropyMarker is the fixed replacement the entropy pass emits.
const entropyMarker = "[REDACTED:" + string(RedactEntropy) + "]"

// tokenChar reports whether c can be part of a secret-shaped token. It spans the
// FULL std-base64 alphabet — [A-Za-z0-9+/] plus '=' '_' '-' — so a std-base64
// secret is scored as ONE contiguous run even when it contains '/' (an earlier
// refinement that split on '/' caused slashed AWS secret keys to fragment below
// the length floor and leak RAW — a security regression this restores). Ordinary
// prose still splits on spaces/punctuation into short sub-floor words.
func tokenChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+' || c == '/' || c == '=' || c == '_' || c == '-':
		return true
	default:
		return false
	}
}

// looksLikePath reports whether a token run is a filesystem PATH rather than a
// standalone secret, so the entropy pass can score it per-segment (keeping
// benign paths readable) instead of as a whole.
//
// Discriminator: a benign absolute/relative path run starts with '/' (leading
// './' and '../' fall outside the run because '.' is not a token char, so the
// run itself still begins with '/') AND contains no base64-only characters
// ('+'/'='), which real paths do not use but std-base64 secrets often do. A
// standalone base64 secret almost never starts with '/', so it fails this test
// and is scored whole — restoring ~0% leak for slashed secrets.
func looksLikePath(run string) bool {
	if len(run) == 0 || run[0] != '/' {
		return false
	}
	return !strings.ContainsAny(run, "+=")
}

// scrubEntropy walks maximal token runs left-to-right (single O(n) scan,
// deterministic, no backtracking) and redacts high-entropy secrets:
//   - A path-like run (looksLikePath) is scored PER SEGMENT: only the '/'-
//     delimited segment(s) clearing floor+threshold are replaced, leaving the
//     rest of the path and its separators intact and readable. An embedded
//     high-entropy secret segment is still caught.
//   - Any other run is scored as a WHOLE, so a std-base64 secret that merely
//     contains '/' is redacted in one piece.
//
// The markers inserted by the pattern pass ("REDACTED", "aws-key", …) are
// low-entropy and never re-flagged.
//
// RESIDUAL (honest, alongside the chunk-boundary gap in the package doc): a
// std-base64 secret that BOTH begins with '/' AND contains interior '/' that
// fragment it into sub-floor segments (and has no '+'/'=') can still evade the
// entropy pass. This is far narrower than scoring per-segment unconditionally
// (which leaked ~17.6% of slashed AWS secret keys); such a leading-'/' secret is
// rare (~1/64 of std-base64 strings), and the named patterns catch the
// structured secrets (AKIA IDs, JWTs, bearer, assignments) regardless.
func (r *PatternRedactor) scrubEntropy(s string, counts map[RedactType]int) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	n := len(s)
	for i < n {
		if !tokenChar(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < n && tokenChar(s[j]) {
			j++
		}
		b.WriteString(r.scoreRun(s[i:j], counts))
		i = j
	}
	return b.String()
}

// scoreRun redacts one maximal token run, per-segment for paths and whole
// otherwise (see scrubEntropy).
func (r *PatternRedactor) scoreRun(run string, counts map[RedactType]int) string {
	if looksLikePath(run) {
		parts := strings.Split(run, "/")
		for idx, p := range parts {
			if len(p) >= r.entropyFloor && shannonBits(p) >= r.entropyMin {
				parts[idx] = entropyMarker
				counts[RedactEntropy]++
			}
		}
		return strings.Join(parts, "/")
	}
	if len(run) >= r.entropyFloor && shannonBits(run) >= r.entropyMin {
		counts[RedactEntropy]++
		return entropyMarker
	}
	return run
}

// shannonBits is the per-character Shannon entropy (bits) of s over its byte
// distribution. Pure hex tops out at log2(16)=4.0; mixed-case base64 tokens
// clear ~4.5–6.0, so a threshold just above 4.0 separates secrets from SHAs.
func shannonBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// hardRedact returns a deep copy of payload with every string value replaced by
// the [REDACTED:error] marker — the fail-closed result when scanning panics.
func hardRedact(v any) map[string]any {
	marker := "[REDACTED:" + string(redactError) + "]"
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			return marker
		case []string:
			out := make([]string, len(t))
			for i := range t {
				out[i] = marker
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, e := range t {
				out[i] = walk(e)
			}
			return out
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, e := range t {
				out[k] = walk(e)
			}
			return out
		default:
			return x
		}
	}
	if m, ok := v.(map[string]any); ok {
		return walk(m).(map[string]any)
	}
	return map[string]any{}
}

func (r *PatternRedactor) addCounts(counts map[RedactType]int) {
	for typ, n := range counts {
		if n == 0 {
			continue
		}
		v, _ := r.counts.LoadOrStore(typ, new(int64))
		atomic.AddInt64(v.(*int64), int64(n))
	}
}

// Counts returns a snapshot of the process-cumulative redaction tally bucketed
// by type — an observability metric. It exposes COUNTS only; no byte, length,
// or prefix of any redacted value is retained anywhere in the redactor.
func (r *PatternRedactor) Counts() map[RedactType]int64 {
	out := map[RedactType]int64{}
	r.counts.Range(func(k, v any) bool {
		out[k.(RedactType)] = atomic.LoadInt64(v.(*int64))
		return true
	})
	return out
}
