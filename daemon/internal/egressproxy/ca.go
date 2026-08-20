package egressproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// caTTL bounds a per-session CA's validity. It is minted at session create and
// scrapped at teardown, so a session-length window is ample; a bounded lifetime
// means even a leaked CA cert cannot be used indefinitely.
const caTTL = 24 * time.Hour

// SessionCA is the per-session TLS-terminate trust anchor (F5.2). It is a HARD
// trust boundary:
//   - It is minted FRESH per session (NewSessionCA) with its own P-256 key, so no
//     two sessions ever share a CA and one session's CA can never validate a leaf
//     the proxy minted for another session.
//   - Its certificate (CertPEM) is injected READ-ONLY into that one sandbox's
//     trust store so TLS-terminate works for injection targets — and ONLY there.
//   - It signs leaves ONLY for hosts the proxy is actively TLS-terminating for
//     this session (LeafFor). It is never handed to the sandbox as a signing key
//     (the private key never leaves the daemon) and never reused across sessions.
//
// The private key stays daemon-side; only the public cert crosses into the
// sandbox. A second session gets a wholly independent SessionCA.
type SessionCA struct {
	sessionID string
	cert      *x509.Certificate
	certDER   []byte
	key       *ecdsa.PrivateKey
	now       func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate // host -> minted leaf (per session)
	serial int64
}

// NewSessionCA mints a fresh CA bound to sessionID. now is injectable for tests
// (nil => time.Now). The returned CA's private key never leaves the daemon.
func NewSessionCA(sessionID string, now func() time.Time) (*SessionCA, error) {
	if now == nil {
		now = time.Now
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("egressproxy: generate session CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// The session id is stamped into the subject so a cert is visibly
			// scoped to its session (audit) — it is NOT a security control on its
			// own; the independent per-session key is.
			CommonName:   "opslify-session-ca:" + sessionID,
			Organization: []string{"opslify per-session egress CA"},
		},
		NotBefore:             now().Add(-1 * time.Minute),
		NotAfter:              now().Add(caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("egressproxy: create session CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("egressproxy: parse session CA cert: %w", err)
	}
	return &SessionCA{
		sessionID: sessionID,
		cert:      cert,
		certDER:   der,
		key:       key,
		now:       now,
		leaves:    map[string]*tls.Certificate{},
	}, nil
}

// SessionID is the session this CA is bound to.
func (c *SessionCA) SessionID() string { return c.sessionID }

// CertPEM is the CA certificate in PEM, for READ-ONLY injection into the one
// session's sandbox trust store. Only the public cert is exposed — never the key.
func (c *SessionCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
}

// LeafFor mints (and caches) a TLS leaf for host, signed by this session's CA. It
// is only ever called for a host the proxy is TLS-terminating for THIS session.
// The leaf is scoped to host via its SAN, so a leaf minted for one host cannot
// authenticate another.
func (c *SessionCA) LeafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("egressproxy: generate leaf key for %s: %w", host, err)
	}
	c.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(c.serial),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    c.now().Add(-1 * time.Minute),
		NotAfter:     c.now().Add(caTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("egressproxy: sign leaf for %s: %w", host, err)
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  key,
	}
	c.leaves[host] = leaf
	return leaf, nil
}

// CertPool returns a fresh x509 pool trusting ONLY this session's CA. It is what a
// test (and the sandbox, once integration-wired) uses to validate the proxy's
// terminate leaves — proving a leaf validates under its own session CA and NOT
// under another session's.
func (c *SessionCA) CertPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("egressproxy: serial: %w", err)
	}
	return n, nil
}
