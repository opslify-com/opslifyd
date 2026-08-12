package trace

import (
	"context"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// newRedactor builds a default-config redactor (all patterns on, default
// entropy tunables) — the production wiring.
func newRedactor() *PatternRedactor { return NewPatternRedactor(RedactorConfig{}) }

// Seeded FAKE secrets (shared-engineering §4: clearly fake, never real) — they
// exist only to prove redaction fires.
const (
	fakeAWSKey    = "AKIAIOSFODNN7EXAMPLE"                     // AKIA + 16
	fakeAWSSecret = "wJa1rXUt7FEMI9K2QzPq3vB8tR4xN6mL0cD5fH7g" // 40-char base64 (entropy)
	fakeJWT       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	fakeBearer    = "Bearer abc123DEF456ghi789JKLmno0"
	fakeEntropy   = "Zx9Kq2Wm7Lp4Rt6Yb8Nc0Vd3Fg5Hj1Aa2Bb3" // 37-char high-entropy blob
	fakeGCPSA     = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQFAKESECRETBODY\nQ2FrZQ==\n-----END PRIVATE KEY-----"
	// Non-secret DevOps tokens that must NOT be over-scrubbed at defaults.
	gitSHA   = "e83c5163316f89bfbde7d9ab23ca2e25604af290"
	uuidVal  = "550e8400-e29b-41d4-a716-446655440000"
	base64ok = "SGVsbG8gV29ybGQ=" // short benign base64 ("Hello World")
)

// TestPatternTypesRedacted — every v1 pattern, seeded in a payload string,
// appears as [REDACTED:<type>] and never raw.
func TestPatternTypesRedacted(t *testing.T) {
	r := newRedactor()
	cases := []struct {
		name   string
		secret string
		field  string // the [REDACTED:<type>] marker expected
	}{
		{"aws-key", fakeAWSKey, "[REDACTED:aws-key]"},
		{"aws-secret-via-entropy", fakeAWSSecret, "[REDACTED:entropy]"},
		{"jwt", fakeJWT, "[REDACTED:jwt]"},
		{"bearer", fakeBearer, "[REDACTED:bearer]"},
		{"gcp-sa", fakeGCPSA, "[REDACTED:gcp-sa]"},
		{"entropy", fakeEntropy, "[REDACTED:entropy]"},
	}
	for _, tc := range cases {
		t.Run("argv/"+tc.name, func(t *testing.T) {
			p := r.Redact(TypeExecStart, map[string]any{
				"argv": []string{"run", "--key=" + tc.secret},
				"cwd":  "/workspace",
			})
			blob := mustJSON(t, p)
			if strings.Contains(blob, tc.secret) {
				t.Fatalf("raw secret leaked in argv payload: %s", blob)
			}
			if !strings.Contains(blob, tc.field) {
				t.Fatalf("expected marker %s, got: %s", tc.field, blob)
			}
		})
		t.Run("output/"+tc.name, func(t *testing.T) {
			p := r.Redact(TypeExecOutput, map[string]any{
				"stream": "stdout", "offset": 0,
				"chunk": "log line " + tc.secret + " end",
			})
			blob := mustJSON(t, p)
			if strings.Contains(blob, tc.secret) {
				t.Fatalf("raw secret leaked in output chunk: %s", blob)
			}
			if !strings.Contains(blob, tc.field) {
				t.Fatalf("expected marker %s, got: %s", tc.field, blob)
			}
		})
	}
}

// TestAssignmentRedactedKeepsKey — password=/token=/api_key= scrub the VALUE and
// keep the readable key prefix.
func TestAssignmentRedactedKeepsKey(t *testing.T) {
	r := newRedactor()
	for _, in := range []string{
		"password=hunter2SuperSecret",
		"api_key: sk_live_0123456789abc",
		"AWS_SECRET_ACCESS_KEY=" + fakeAWSSecret,
	} {
		out := r.scrubString(in, map[RedactType]int{})
		if !strings.Contains(out, "[REDACTED:") {
			t.Fatalf("assignment %q not redacted: %q", in, out)
		}
		if strings.Contains(out, "hunter2SuperSecret") || strings.Contains(out, "sk_live_0123456789abc") {
			t.Fatalf("assignment value leaked: %q", out)
		}
	}
}

// TestIntegersNeverRedacted — numeric payload fields pass through untouched.
func TestIntegersNeverRedacted(t *testing.T) {
	r := newRedactor()
	p := r.Redact(TypeExecEnd, map[string]any{"exit_code": 0, "duration_ms": 4211, "size": 65535})
	if p["exit_code"] != 0 || p["duration_ms"] != 4211 || p["size"] != 65535 {
		t.Fatalf("integer field altered: %#v", p)
	}
}

// TestNoOverScrubCommonTokens — git SHA / UUID / short base64 are NOT redacted
// at the default threshold (false-positive characterization).
func TestNoOverScrubCommonTokens(t *testing.T) {
	r := newRedactor()
	for _, tok := range []string{
		gitSHA, uuidVal, base64ok, "v1.2.3",
		"/var/lib/opslify/workspaces/sess-1",
		"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // image digest
		"nginx-deployment-66b6c48dd5-abcde",                                       // kubectl pod name
	} {
		out := r.scrubString("value "+tok+" ok", map[RedactType]int{})
		if strings.Contains(out, "[REDACTED:") {
			t.Fatalf("over-scrubbed benign token %q -> %q", tok, out)
		}
	}
}

// TestEntropyPathAware — the entropy pass scores per slash-delimited segment:
// a normal long path stays fully intact; a path with an embedded high-entropy
// secret segment has ONLY that segment redacted; a contiguous base64 secret is
// still caught whole.
func TestEntropyPathAware(t *testing.T) {
	r := newRedactor()

	// 1. Realistic long benign path — fully readable, nothing redacted.
	benign := "/var/lib/opslify/workspaces/session-abcdef/output/build-123456789"
	if out := r.scrubString(benign, map[RedactType]int{}); out != benign {
		t.Fatalf("benign path altered:\n in:  %q\n out: %q", benign, out)
	}

	// 2. High-entropy secret segment embedded in a path — only that segment goes,
	//    the surrounding path (and its '/' separators) stay intact.
	secretSeg := "Ae9fKq2Lm8Zx1pQr7Wc3Nv6Yb0Ht4Uj5Sd2Gf8" // 39 chars, high entropy
	embedded := "/tmp/dl/" + secretSeg + "/artifact.tgz"
	out := r.scrubString(embedded, map[RedactType]int{})
	if strings.Contains(out, secretSeg) {
		t.Fatalf("secret segment leaked: %q", out)
	}
	if want := "/tmp/dl/[REDACTED:entropy]/artifact.tgz"; out != want {
		t.Fatalf("embedded-secret path:\n got:  %q\n want: %q", out, want)
	}

	// 3. Contiguous base64 secret (0 slashes) still redacted whole (regression).
	if out := r.scrubString(fakeAWSSecret, map[RedactType]int{}); out != "[REDACTED:entropy]" {
		t.Fatalf("contiguous base64 secret not caught: %q", out)
	}
}

// TestEntropySlashedSecretRedacted — the security regression fix: a std-base64
// / AWS secret key that merely CONTAINS '/' is scored as a whole run and
// redacted (it does not start with '/', so it is not mistaken for a path).
// QA's concrete leaker plus a randomized N=5000 sweep asserting ~0% leak.
func TestEntropySlashedSecretRedacted(t *testing.T) {
	r := newRedactor()

	// QA's exact concrete example (40-char std base64 with two interior '/').
	concrete := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	if out := r.scrubString(concrete, map[RedactType]int{}); strings.Contains(out, concrete) || !strings.Contains(out, "[REDACTED:entropy]") {
		t.Fatalf("slashed AWS secret leaked: in=%q out=%q", concrete, out)
	}

	// Randomized sweep mirroring QA's methodology: 40-char std-base64 secrets
	// each containing >=1 '/'. Assert the leak rate is driven back to ~0.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	rng := rand.New(rand.NewSource(0xF3D3AC)) // fixed seed => deterministic test
	const N = 5000
	leaks := 0
	for i := 0; i < N; i++ {
		var sb strings.Builder
		for k := 0; k < 40; k++ {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		secret := sb.String()
		if !strings.Contains(secret, "/") {
			// Force at least one '/' at a random interior position.
			pos := 1 + rng.Intn(38)
			secret = secret[:pos] + "/" + secret[pos+1:]
		}
		out := r.scrubString(secret, map[RedactType]int{})
		if strings.Contains(out, secret) {
			leaks++
		}
	}
	rate := float64(leaks) / float64(N)
	t.Logf("slashed-secret leak rate: %d/%d = %.4f%%", leaks, N, rate*100)
	if rate >= 0.01 { // tiny documented bound (leading-'/' fragmentation residual)
		t.Fatalf("slashed-secret leak rate %.4f%% too high (regression)", rate*100)
	}
}

// TestDeterministic — same input twice yields identical output (stable hashes).
func TestDeterministic(t *testing.T) {
	r := newRedactor()
	in := func() map[string]any {
		return map[string]any{
			"argv":  []string{"curl", "-H", fakeBearer, fakeAWSKey},
			"chunk": "tok=" + fakeEntropy + " " + fakeJWT,
			"cwd":   "/workspace",
		}
	}
	a := mustJSON(t, r.Redact(TypeExecStart, in()))
	b := mustJSON(t, r.Redact(TypeExecStart, in()))
	if a != b {
		t.Fatalf("non-deterministic redaction:\n%s\n%s", a, b)
	}
}

// TestRedactBeforeHash — end-to-end through the F3.1 Recorder + MemSink: the
// stored/exported payload is redacted, no raw secret is ever hashed, and the
// sealed chain verifies over the redacted form.
func TestRedactBeforeHash(t *testing.T) {
	sink := NewMemSink(newTestSigner(t))
	ctx := context.Background()
	rec := NewRecorder(sink, "sess-redact", newRedactor(), fixedClock())

	must(t, rec.Emit(ctx, TypeSessionStart, startPayload()))
	must(t, rec.Emit(ctx, TypeExecStart, map[string]any{
		"argv": []string{"deploy", fakeAWSKey}, "cwd": "/workspace",
	}))
	must(t, rec.Emit(ctx, TypeExecOutput, map[string]any{
		"stream": "stdout", "offset": 0, "chunk": "using " + fakeBearer + "\n",
	}))
	if _, err := rec.Seal(ctx); err != nil {
		t.Fatalf("seal: %v", err)
	}

	events, gotSeal, ok := sink.Export("sess-redact")
	if !ok {
		t.Fatal("no events")
	}
	blob := mustJSON(t, events)
	for _, raw := range []string{fakeAWSKey, "abc123DEF456ghi789JKLmno0"} {
		if strings.Contains(blob, raw) {
			t.Fatalf("raw secret persisted in chain: %s", raw)
		}
	}
	if !strings.Contains(blob, "[REDACTED:aws-key]") || !strings.Contains(blob, "[REDACTED:bearer]") {
		t.Fatalf("expected redaction markers in stored chain: %s", blob)
	}
	if res := Verify(events, gotSeal, sink.signer.Public()); !res.OK {
		t.Fatalf("chain over redacted payloads failed verify at seq %d: %s", res.BrokenSeq, res.Reason)
	}
}

// TestFailClosed — a forced panic in the scan yields a hard-redacted payload
// (every string [REDACTED:error]), never the raw value.
func TestFailClosed(t *testing.T) {
	r := newRedactor()
	r.panicHook = func() { panic("boom") }
	p := r.Redact(TypeExecStart, map[string]any{
		"argv": []string{"run", fakeAWSKey}, "cwd": "/secret/" + fakeBearer, "exit_code": 0,
	})
	blob := mustJSON(t, p)
	if strings.Contains(blob, fakeAWSKey) || strings.Contains(blob, "abc123DEF456") {
		t.Fatalf("fail-closed leaked raw secret: %s", blob)
	}
	if !strings.Contains(blob, "[REDACTED:error]") {
		t.Fatalf("expected hard-redaction marker: %s", blob)
	}
	// Integers still survive the hard-redaction (structure preserved).
	if p["exit_code"] != 0 {
		t.Fatalf("hard-redact altered integer: %#v", p)
	}
}

// TestCounts — per-event counts are correct and bucketed by type, and the
// cumulative Counts() metric never carries the secret's bytes/length.
func TestCounts(t *testing.T) {
	r := newRedactor()
	counts := map[RedactType]int{}
	_ = r.scrubString("a="+fakeAWSKey+" "+fakeJWT+" "+fakeBearer, counts)
	if counts[RedactAWSKey] != 1 || counts[RedactJWT] != 1 || counts[RedactBearer] != 1 {
		t.Fatalf("per-event counts wrong: %#v", counts)
	}
	// Drive cumulative counters via Redact and confirm the snapshot.
	r.Redact(TypeExecStart, map[string]any{"argv": []string{fakeAWSKey}})
	if got := r.Counts()[RedactAWSKey]; got < 1 {
		t.Fatalf("cumulative aws-key count = %d, want >=1", got)
	}
}

// TestAdversarialNoBacktracking — a long hostile string completes within a
// tight time bound (proves no catastrophic backtracking can hang the daemon).
func TestAdversarialNoBacktracking(t *testing.T) {
	r := newRedactor()
	// ~1 MB of adversarial partial-match fodder: unterminated Bearer/PEM/JWT
	// prefixes plus one giant high-entropy token. RE2 is linear, so even under
	// the race detector this must finish well within the bound.
	hostile := strings.Repeat("Bearer ", 20_000) +
		strings.Repeat("-----BEGIN PRIVATE KEY-----", 2_000) +
		strings.Repeat("eyJ.eyJ.", 20_000) +
		strings.Repeat("Aa1Bb2Cc3", 20_000)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		_ = r.scrubString(hostile, map[RedactType]int{})
		close(done)
	}()
	select {
	case <-done:
		t.Logf("hostile input (%d bytes) redacted in %s", len(hostile), time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("redaction did not complete within 5s on hostile input (possible backtracking)")
	}
}

// TestPerPatternDisable — a disabled pattern stops firing; entropy can be turned
// off independently.
func TestPerPatternDisable(t *testing.T) {
	r := NewPatternRedactor(RedactorConfig{DisabledPatterns: []string{"aws-key", "entropy"}})
	out := r.scrubString(fakeAWSKey+" "+fakeEntropy, map[RedactType]int{})
	if strings.Contains(out, "[REDACTED:") {
		t.Fatalf("disabled patterns still fired: %q", out)
	}
	// A non-disabled pattern still works.
	if !strings.Contains(r.scrubString(fakeJWT, map[RedactType]int{}), "[REDACTED:jwt]") {
		t.Fatal("jwt should still redact when only aws-key/entropy disabled")
	}
}

// TestChunkBoundaryGapDocumented — characterizes the KNOWN v1 gap: a secret
// split across two chunks evades the per-chunk scan. This asserts the current
// (documented) behavior so a future boundary-safe change is a conscious update.
func TestChunkBoundaryGapDocumented(t *testing.T) {
	r := newRedactor()
	half1, half2 := fakeAWSKey[:10], fakeAWSKey[10:]
	o1 := r.scrubString(half1, map[RedactType]int{})
	o2 := r.scrubString(half2, map[RedactType]int{})
	if strings.Contains(o1, "[REDACTED") || strings.Contains(o2, "[REDACTED") {
		t.Fatalf("split halves unexpectedly redacted (gap changed): %q %q", o1, o2)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
