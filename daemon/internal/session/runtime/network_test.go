package runtime

import (
	"context"
	"errors"
	"testing"
)

// TestParseNetworkInfo pins the inspect-output parsing: the first COMPLETE
// (ip, gateway) pair wins, "<no value>"/empty are skipped, and the default-bridge
// (top-level) and named-network (ranged) layouts both resolve.
func TestParseNetworkInfo(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		wantIP string
		wantGW string
	}{
		{"default-bridge", "10.88.0.5|10.88.0.1\n", "10.88.0.5", "10.88.0.1"},
		{"named-network-only", "|\n10.89.0.7|10.89.0.1\n", "10.89.0.7", "10.89.0.1"},
		{"empty-top-then-network", "|\n172.20.0.3|172.20.0.1\n", "172.20.0.3", "172.20.0.1"},
		{"half-pair-skipped", "10.0.0.4|\n10.1.0.9|10.1.0.1\n", "10.1.0.9", "10.1.0.1"},
		{"no-value-tokens", "<no value>|<no value>\n", "", ""},
		{"none", "|\n", "", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, gw := parseNetworkInfo(tc.out)
			if ip != tc.wantIP || gw != tc.wantGW {
				t.Fatalf("parseNetworkInfo(%q) = (%q,%q), want (%q,%q)", tc.out, ip, gw, tc.wantIP, tc.wantGW)
			}
		})
	}
}

// TestPodmanNetworkInfo proves the podman impl issues an inspect and returns the
// parsed pair, and that an empty handle / a runner error fail legibly.
func TestPodmanNetworkInfo(t *testing.T) {
	r := newRuncRuntime(&fakeRunner{out: []byte("10.88.0.5|10.88.0.1\n")})
	ip, gw, err := r.NetworkInfo(context.Background(), ContainerHandle{ID: "ctr-1"})
	if err != nil {
		t.Fatalf("NetworkInfo: %v", err)
	}
	if ip != "10.88.0.5" || gw != "10.88.0.1" {
		t.Fatalf("got (%q,%q), want (10.88.0.5,10.88.0.1)", ip, gw)
	}

	if _, _, err := r.NetworkInfo(context.Background(), ContainerHandle{}); err == nil {
		t.Fatalf("expected an error for an empty container id")
	}

	rErr := newRuncRuntime(&fakeRunner{runErr: errors.New("boom")})
	if _, _, err := rErr.NetworkInfo(context.Background(), ContainerHandle{ID: "ctr-2"}); err == nil {
		t.Fatalf("expected a wrapped inspect error")
	}
}

// TestNetworkInfoCapabilityWiring proves the local Podman base satisfies the
// optional NetworkInfo capability while the remote stub does not.
func TestNetworkInfoCapabilityWiring(t *testing.T) {
	var runc Runtime = newRuncRuntime(&fakeRunner{})
	if _, ok := runc.(NetworkInfo); !ok {
		t.Fatalf("RuncRuntime must implement NetworkInfo")
	}
	var remote Runtime = NewRemoteRuntime()
	if _, ok := remote.(NetworkInfo); ok {
		t.Fatalf("RemoteRuntime must NOT implement NetworkInfo (P6 concern)")
	}
}
