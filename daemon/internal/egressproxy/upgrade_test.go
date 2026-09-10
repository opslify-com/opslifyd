package egressproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opslify-com/opslifyd/internal/broker"
	"github.com/opslify-com/opslifyd/internal/policy"
)

// upgradeUpstream is a fake upstream that performs a protocol upgrade the way the
// Kubernetes API server does for exec/attach/port-forward: 101 Switching
// Protocols, then a raw bidirectional stream.
//
// It also RECORDS the Authorization header it received, so the test can assert
// the credential rode the upstream leg and nothing else.
type upgradeUpstream struct {
	gotAuth chan string
	ln      net.Listener
}

func newUpgradeUpstream(t *testing.T) *upgradeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &upgradeUpstream{gotAuth: make(chan string, 4), ln: ln}
	go u.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return u
}

func (u *upgradeUpstream) serve() {
	for {
		conn, err := u.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			select {
			case u.gotAuth <- req.Header.Get("Authorization"):
			default:
			}
			// The upgrade handshake, then echo whatever arrives — which is how the
			// test proves the stream is genuinely bidirectional after 101.
			_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: SPDY/3.1\r\nConnection: Upgrade\r\n\r\n")
			_, _ = io.Copy(c, br)
		}(conn)
	}
}

func (u *upgradeUpstream) addr() string { return u.ln.Addr().String() }

// TestUpgradePassesThroughTheTerminatingProxy is the F8.2 acceptance criterion
// that would otherwise fail selectively and confusingly: `kubectl get pods` works
// while exec, attach, port-forward and cp hang, because only those use
// SPDY/WebSocket upgrades.
//
// The proxy TLS-terminates (so it can inject the token), which means it owns the
// HTTP framing — and after a 101 there is no more framing to own. This asserts
// the bytes flow both ways afterwards, and that the credential appears ONLY on
// the upstream request.
func TestUpgradePassesThroughTheTerminatingProxy(t *testing.T) {
	const token = "CANARY-k8s-token-upstream-only"
	up := newUpgradeUpstream(t)
	// A NAME, not an address: the per-session CA issues DNS SANs, and the sandbox's
	// kubectl connects to the cluster by name via the proxy. The transport below
	// dials the fake upstream's real address.
	const host = "api.k8s.test"

	resolved := policy.ResolveDefault(policy.Policy{
		Egress: policy.Egress{Domains: []string{host}},
		Creds:  []policy.Cred{{Name: "k8s-token", Provider: "kubernetes"}},
	})
	p, err := NewSessionProxy("s1", resolved, SessionConfig{
		Rules: []InjectRule{{
			Host: host, CredRef: "k8s-token", HeaderName: "Authorization", HeaderFormat: "Bearer %s",
		}},
	}, upgradeTestBroker(t, "k8s-token", token), nil, staticTokenTransport{dial: up.addr()})
	if err != nil {
		t.Fatalf("NewSessionProxy: %v", err)
	}

	// A client speaking TLS to the proxy, trusting the per-session CA — exactly
	// what the generated kubeconfig tells kubectl to do.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CACertPEM()) {
		t.Fatal("per-session CA did not parse")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- p.serveTerminate(context.Background(), host, server)
	}()

	tlsClient := tls.Client(client, &tls.Config{RootCAs: pool, ServerName: host})
	if err := tlsClient.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// The upgrade request kubectl exec sends.
	if _, err := fmt.Fprintf(tlsClient,
		"GET /api/v1/namespaces/default/pods/p/exec HTTP/1.1\r\nHost: %s\r\n"+
			"Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n", host); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	br := bufio.NewReader(tlsClient)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status = %q, want 101 Switching Protocols", status)
	}
	// Drain the headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// THE POINT: after 101 the stream must carry bytes both ways. Without splicing
	// the proxy would try to parse the next client bytes as an HTTP request and the
	// exec session would die here.
	_ = tlsClient.SetDeadline(time.Now().Add(5 * time.Second))
	const payload = "stdin-bytes-from-kubectl-exec\n"
	if _, err := io.WriteString(tlsClient, payload); err != nil {
		t.Fatalf("write into the upgraded stream: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("the upgraded stream did not carry bytes back (kubectl exec would hang here): %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}

	// The credential rode the UPSTREAM request only.
	select {
	case auth := <-up.gotAuth:
		if auth != "Bearer "+token {
			t.Errorf("upstream Authorization = %q, want the injected bearer token", auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never saw a request")
	}
	if strings.Contains(status, token) {
		t.Fatal("the token appeared in the response the sandbox reads")
	}
}

// TestUpgradeFailsLoudlyWhenTheStreamCannotBeCarried: writing 101 and then being
// unable to splice would leave the client waiting on a connection that will never
// speak, which is far harder to diagnose than an error.
func TestUpgradeFailsLoudlyWhenTheStreamCannotBeCarried(t *testing.T) {
	p := &Proxy{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	// A 101 whose body is read-only — not an io.ReadWriteCloser.
	resp := &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Upgrade": []string{"SPDY/3.1"}},
		Body:       io.NopCloser(strings.NewReader("")),
	}
	if err := p.spliceUpgrade(server, resp); err == nil {
		t.Fatal("an un-spliceable upgrade must be an error, not a silently dead connection")
	}
}

// upgradeTestBroker builds a real broker over a real vault, so the injection this
// test asserts is the production path rather than a stub. Testing the upgrade
// splice without real injection would leave the combination that actually matters
// — does a credential still get injected on an UPGRADE request? — unproven.
func upgradeTestBroker(t *testing.T, ref, token string) *broker.Broker {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	v, err := broker.OpenVault(t.TempDir()+"/vault.db", broker.StaticKeySource(key))
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := v.Put(context.Background(), ref, []byte(token), broker.PutMeta{Provider: "kubernetes"}, false); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return broker.NewBroker(v)
}

// staticTokenTransport dials the fake upstream and asserts nothing itself; the
// injection is done by the proxy before RoundTrip is called.
type staticTokenTransport struct {
	dial string
}

func (s staticTokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", s.dial)
		},
	}
	// The fake upstream speaks cleartext; the proxy built an https URL.
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	return tr.RoundTrip(clone)
}

func hostOnly(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}
