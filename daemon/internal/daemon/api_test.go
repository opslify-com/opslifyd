package daemon

import (
	"testing"

	"github.com/opslify-com/opslifyd/internal/broker"
)

// TestHandlerRegistersEveryRouteWithEverythingWired is the test whose absence let
// a startup panic reach a running daemon.
//
// Every other daemon test constructs a Daemon with SOME services wired, so two
// routes registering the same pattern never met. Building the handler with ALL of
// them is the only way that collision is visible — and http.ServeMux panics on a
// duplicate, so a daemon with the full P8 surface would refuse to start.
func TestHandlerRegistersEveryRouteWithEverythingWired(t *testing.T) {
	d, err := New(Options{
		Verifier:     okVerifier(),
		Sessions:     &fakeManager{},
		Projects:     nil,
		Secrets:      nil,
		SecretsSvc:   nil,
		Connections:  &fakeConnectionService{},
		Agents:       &fakeAgentRegistry{},
		Changes:      &fakeChangeService{},
		PolicyEditor: &fakeEditor{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Handler() panics on a duplicate pattern; this call is the assertion.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registering every P8 route panicked — the daemon would not start: %v", r)
		}
	}()
	if d.Handler() == nil {
		t.Fatal("Handler returned nil")
	}
}

// fakeConnectionService satisfies the connection surface for the wiring test.
type fakeConnectionService struct{}

func (fakeConnectionService) Add(broker.ConnectionSpec) error      { return nil }
func (fakeConnectionService) Validate(broker.ConnectionSpec) error { return nil }
func (fakeConnectionService) List() ([]broker.ConnectionSpec, error) {
	return nil, nil
}
func (fakeConnectionService) Remove(string, string, string) error { return nil }
