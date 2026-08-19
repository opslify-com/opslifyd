package egressproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/policy"
	"github.com/opslify-com/opslifyd/internal/trace"
)

func TestScanBody_EntropyAndCap(t *testing.T) {
	// Low-entropy (all zeros) large body: capped but low entropy.
	low := make([]byte, 2048)
	if r := scanBody(low, AnomalyConfig{EntropyThreshold: 7.5}); r.Flagged {
		t.Fatalf("low-entropy small body should not flag: %+v", r)
	}
	// High-entropy body >= min bytes => flagged high-entropy.
	high := make([]byte, 4096)
	rand.Read(high)
	if r := scanBody(high, AnomalyConfig{EntropyThreshold: 7.0}); !r.Flagged || !strings.Contains(r.Reason, "high-entropy") {
		t.Fatalf("random body should flag high-entropy: %+v", r)
	}
	// Oversized => capped.
	big := make([]byte, 100)
	if r := scanBody(big, AnomalyConfig{UploadCap: 50}); !r.Capped || !r.Flagged {
		t.Fatalf("oversized body should be capped: %+v", r)
	}
}

// An oversized/high-entropy upload emits egress.anomaly through the proxy, and the
// body content never appears in the event.
func TestForward_OversizedUpload_EmitsAnomaly(t *testing.T) {
	ref := "gh"
	brk := testBroker(t, ref, fakeToken)
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: ref}}),
		[]InjectRule{{Host: "api.github.com", CredRef: ref, HeaderName: "Authorization"}},
		nil,
	)
	sink := &memSink{}
	rec := trace.NewRecorder(sink, "s", nil, nil)
	// Tiny cap so a modest body trips it.
	p := New("s", cfg, mustCA(t, "s"), brk, []policy.Cred{{Name: ref}}, rec, AnomalyConfig{UploadCap: 64}, &stubTransport{})

	payload := bytes.Repeat([]byte("EXFILTRATE-"), 50) // > 64 bytes
	req, _ := http.NewRequest("POST", "https://api.github.com/upload", io.NopCloser(bytes.NewReader(payload)))
	resp, err := p.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	resp.Body.Close()

	var saw bool
	for _, e := range sink.events {
		if e.Type != trace.TypeEgressAnomaly {
			continue
		}
		saw = true
		if got := e.Payload["reason"]; got != "upload-cap" && !strings.Contains(toStr(got), "upload-cap") {
			t.Fatalf("anomaly reason = %v", got)
		}
		// No body content in the event.
		if strings.Contains(stringifyEvent(e), "EXFILTRATE") {
			t.Fatal("anomaly event leaked body content")
		}
	}
	if !saw {
		t.Fatal("no egress.anomaly emitted for oversized upload")
	}
}

// non-HTTP / default-deny is unaffected here: an unlisted host never reaches the
// anomaly scanner at all (denied before body read).
func TestForward_DeniedBeforeBodyScan(t *testing.T) {
	cfg := BuildConfig(resolvedWith([]string{"ok.com"}, nil), nil, nil)
	sink := &memSink{}
	rec := trace.NewRecorder(sink, "s", nil, nil)
	p := New("s", cfg, mustCA(t, "s"), nil, nil, rec, AnomalyConfig{}, &stubTransport{})
	req, _ := http.NewRequest("POST", "https://denied.com/x", strings.NewReader("data"))
	if _, err := p.Forward(context.Background(), req); err == nil {
		t.Fatal("expected deny")
	}
	for _, e := range sink.events {
		if e.Type == trace.TypeEgressAnomaly {
			t.Fatal("denied host should not produce an anomaly scan")
		}
	}
	_ = policy.Cred{}
}
