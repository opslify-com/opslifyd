package egressproxy

import (
	"context"
	"math"

	"github.com/opslify-com/opslifyd/internal/trace"
)

// Anomaly bounds are per-session, fail-closed exfil signals on OUTBOUND bodies.
const (
	// DefaultUploadCap is the per-request outbound-body byte cap above which an
	// egress.anomaly is raised. It is a SIGNAL + a hard read bound, not a silent
	// drop: the proxy stops reading at the cap (bounded memory) and marks capped.
	DefaultUploadCap = 8 << 20 // 8 MiB
	// DefaultEntropyThreshold is the Shannon-entropy (bits/byte, 0..8) at or above
	// which a body of at least entropyMinBytes is flagged high-entropy — a
	// compressed/encrypted-blob exfil signal.
	DefaultEntropyThreshold = 7.5
	// entropyMinBytes avoids flagging tiny bodies whose entropy is meaningless.
	entropyMinBytes = 1024
)

// AnomalyConfig tunes the outbound-body scan. Zero values fall back to the
// DefaultUploadCap / DefaultEntropyThreshold so an unconfigured proxy is still
// bounded (fail-closed, never unbounded).
type AnomalyConfig struct {
	UploadCap        int64
	EntropyThreshold float64
}

func (a AnomalyConfig) cap() int64 {
	if a.UploadCap <= 0 {
		return DefaultUploadCap
	}
	return a.UploadCap
}

func (a AnomalyConfig) threshold() float64 {
	if a.EntropyThreshold <= 0 {
		return DefaultEntropyThreshold
	}
	return a.EntropyThreshold
}

// AnomalyResult is the outcome of scanning one outbound body.
type AnomalyResult struct {
	Bytes   int64
	Entropy float64
	Capped  bool // the body reached/exceeded the byte cap (read was bounded)
	Flagged bool // an anomaly was detected (capped OR high entropy)
	Reason  string
}

// scanBody computes the byte count + Shannon entropy of body (already read, bounded
// by the caller to cap+1 bytes) and decides whether it is anomalous.
func scanBody(body []byte, cfg AnomalyConfig) AnomalyResult {
	res := AnomalyResult{Bytes: int64(len(body)), Entropy: shannonEntropy(body)}
	if res.Bytes >= cfg.cap() {
		res.Capped = true
		res.Flagged = true
		res.Reason = "upload-cap"
	}
	if res.Bytes >= entropyMinBytes && res.Entropy >= cfg.threshold() {
		res.Flagged = true
		if res.Reason == "" {
			res.Reason = "high-entropy"
		} else {
			res.Reason += "+high-entropy"
		}
	}
	return res
}

// shannonEntropy is the per-byte entropy (bits/byte, 0..8) of b. An empty body is
// 0. It is a cheap, bounded single pass — it cannot be turned into an unbounded
// cost by the sandbox (the caller already capped the read).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// emitAnomaly records an egress.anomaly event. It carries only the NON-SECRET
// signal (host/method/path/reason/bytes/entropy/capped) — never body content and
// never the injected credential.
func emitAnomaly(ctx context.Context, rec *trace.Recorder, method, host, path string, res AnomalyResult) {
	_ = rec.Emit(ctx, trace.TypeEgressAnomaly, map[string]any{
		"host":    host,
		"method":  method,
		"path":    path,
		"reason":  res.Reason,
		"bytes":   res.Bytes,
		"entropy": math.Round(res.Entropy*1000) / 1000,
		"capped":  res.Capped,
	})
}
