package broker

import (
	"fmt"
	"sync"
	"testing"
)

// TestConsumerIndexRegisterIsSafeUnderConcurrentReads pins F11. Register is
// documented for post-construction wiring (F8.2 connections) while All is called
// from live HTTP handlers, so the two genuinely race — -race confirmed a write/read
// data race on the sources slice. Latent only because nothing calls Register at
// runtime yet, which is exactly why it needed a test before F8.2 trips it.
func TestConsumerIndexRegisterIsSafeUnderConcurrentReads(t *testing.T) {
	idx := NewConsumerIndex(ConsumerSourceFunc(func() (map[string][]Consumer, error) {
		return map[string][]Consumer{"base": {{Kind: ConsumerPolicyGrant, Name: "base"}}}, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("late-%d", i)
			idx.Register(ConsumerSourceFunc(func() (map[string][]Consumer, error) {
				return map[string][]Consumer{name: {{Kind: ConsumerConnection, Name: name}}}, nil
			}))
		}(i)
	}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := idx.All(); err != nil {
				t.Errorf("All: %v", err)
			}
		}()
	}
	wg.Wait()

	all, err := idx.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 9 { // base + 8 late registrations
		t.Errorf("got %d refs, want 9 — a registration was lost", len(all))
	}
}
