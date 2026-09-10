package broker

import "testing"

// PlantLegacyRefForTest stores a record under a ref the CURRENT naming rule
// refuses, reproducing a secret written by an earlier release.
//
// It is exported (in non-test code, guarded by taking a *testing.T) so the daemon
// package can build the same on-disk state. The alternative — a hand-rolled JSON
// fixture — would let a test pass against a shape the real loader rejects, and
// the property under test is precisely that the real loader accepts it and the
// delete route still removes it.
func PlantLegacyRefForTest(t *testing.T, v *Vault, legacy string) {
	t.Helper()
	const stand = "legacy-stand-in"
	if err := v.Put(nil, stand, []byte("v"), PutMeta{Provider: "gitlab"}, false); err != nil { //nolint:staticcheck // nil ctx is unused by Put
		t.Fatalf("plant legacy ref: %v", err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	rec := v.data.Secrets[stand]
	delete(v.data.Secrets, stand)
	rec.Ref = legacy
	v.data.Secrets[legacy] = rec
	if err := v.persist(); err != nil {
		t.Fatalf("plant legacy ref: persist: %v", err)
	}
}
