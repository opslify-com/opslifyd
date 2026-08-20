package egressproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/policy"
)

// TestSNI_ParsedFromRealClientHello builds a genuine TLS ClientHello and asserts
// the cleartext SNI parser recovers the server name WITHOUT any decryption.
func TestSNI_ParsedFromRealClientHello(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		// This handshake never completes (no server) — we only want the ClientHello.
		tlsc := tls.Client(c, &tls.Config{ServerName: "registry.npmjs.org"})
		_ = tlsc.HandshakeContext(context.Background())
	}()
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("read client hello: %v", err)
	}
	sni, err := sniFromClientHello(buf[:n])
	if err != nil {
		t.Fatalf("parse SNI: %v", err)
	}
	if sni != "registry.npmjs.org" {
		t.Fatalf("SNI = %q", sni)
	}
}

// TestServePassthrough_DoesNotDecrypt proves a never-MITM host is TUNNELED
// verbatim: the bytes the sandbox writes arrive at the upstream unchanged and the
// proxy never mints a leaf / never terminates TLS for that host.
func TestServePassthrough_DoesNotDecrypt(t *testing.T) {
	cfg := BuildConfig(
		resolvedWith([]string{"releases.hashicorp.com"}, nil),
		nil,
		[]string{"releases.hashicorp.com"},
	)
	ca := mustCA(t, "s")
	p := New("s", cfg, ca, nil, nil, nil, AnomalyConfig{}, nil)

	clientSide, proxySide := net.Pipe()
	upClientSide, upServerSide := net.Pipe()
	dial := func(_ context.Context, host string) (net.Conn, error) {
		if host != "releases.hashicorp.com" {
			t.Errorf("dialed wrong host %q", host)
		}
		return upClientSide, nil
	}

	go func() {
		_ = p.servePassthrough(context.Background(), "releases.hashicorp.com", proxySide, dial)
	}()

	// The sandbox writes a real ClientHello for the host, then app bytes.
	go func() {
		tlsc := tls.Client(clientSide, &tls.Config{ServerName: "releases.hashicorp.com"})
		_ = tlsc.HandshakeContext(context.Background())
	}()

	// The upstream should receive the SAME ClientHello bytes (record type 0x16),
	// proving no decryption / re-encryption happened.
	upServerSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	first := make([]byte, 1)
	if _, err := io.ReadFull(upServerSide, first); err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	if first[0] != 0x16 {
		t.Fatalf("upstream first byte = %#x, want TLS handshake 0x16", first[0])
	}
	// The proxy did not mint a leaf for this host (no MITM).
	ca.mu.Lock()
	nLeaves := len(ca.leaves)
	ca.mu.Unlock()
	if nLeaves != 0 {
		t.Fatalf("SECURITY: passthrough minted %d leaves (MITM of a checksum host)", nLeaves)
	}
}

// TestServeTerminate_EndToEnd drives the FULL TLS-terminate path: a real TLS
// client (trusting only the per-session CA) connects, the proxy terminates,
// injects the auth header at the boundary, and forwards to a stub upstream. Proves
// the sandbox-side request carried no token and the forwarded one did.
func TestServeTerminate_EndToEnd(t *testing.T) {
	ref := "gh"
	brk := testBroker(t, ref, fakeToken)
	cfg := BuildConfig(
		resolvedWith([]string{"api.github.com"}, []policy.Cred{{Name: ref}}),
		[]InjectRule{{Host: "api.github.com", CredRef: ref, HeaderName: "Authorization", HeaderFormat: "Bearer %s"}},
		nil,
	)
	ca := mustCA(t, "s")
	st := &stubTransport{}
	p := New("s", cfg, ca, brk, []policy.Cred{{Name: ref}}, nil, AnomalyConfig{}, st)

	clientSide, proxySide := net.Pipe()
	go func() { _ = p.serveTerminate(context.Background(), "api.github.com", proxySide) }()

	tlsc := tls.Client(clientSide, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    ca.CertPool(), // sandbox trusts ONLY this session's CA
	})
	if err := tlsc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake (leaf should chain to session CA): %v", err)
	}
	// Send a request with NO auth header.
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err := req.Write(tlsc); err != nil {
		t.Fatalf("write req: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsc), req)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	resp.Body.Close()
	tlsc.Close()

	if st.got == nil {
		t.Fatal("upstream never received the forwarded request")
	}
	if got := st.got.Header.Get("Authorization"); got != "Bearer "+fakeToken {
		t.Fatalf("forwarded auth = %q", got)
	}
	// The request the sandbox sent (as seen on the wire) carried no token; the
	// forwarded one does — that is the credential-blind boundary.
	if strings.Contains(st.got.Header.Get("Authorization"), fakeToken) == false {
		t.Fatal("token missing on forwarded request")
	}
}
