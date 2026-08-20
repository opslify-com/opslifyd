package regproxy

import "context"

// AttestationVerifier is the F5.5 supply-chain attestation SEAM. It decides
// whether a fetched artifact has a verifiable attestation (e.g. a Sigstore/cosign
// signature + provenance) for its {ecosystem, name, version}. It is consulted only
// when the artifact's Upstream sets RequireAttestation: the proxy refuses to serve
// an artifact that is not positively attested (fail-closed) — a poisoned/unsigned
// package cannot slip through.
//
// INTEGRATION-GATED: the REAL verifier (Sigstore transparency-log inclusion +
// cosign signature + provenance predicate checks) is integration-gated and would
// pull the sigstore-go SDK; we intentionally do NOT vendor that heavy dependency
// behind a unit-tested seam. The path to wire it: implement this one-method
// interface with a cosign/sigstore-backed verifier and pass it to NewProxy — no
// other code changes. Unit tests use StubVerifier to exercise both the attested
// and unattested (refused) branches deterministically, with no network.
type AttestationVerifier interface {
	// Attested reports whether artifact for ref is verifiably attested. An error is
	// treated by the proxy exactly like a false result (fail-closed) but is surfaced
	// for failure legibility. The artifact bytes are the REAL upstream bytes, so a
	// real verifier can check a detached signature/digest against them.
	Attested(ctx context.Context, ref Ref, artifact []byte) (bool, error)
}

// StubVerifier is the deterministic, no-network verifier for tests (and for an
// operator who wants an explicit static allowlist of attested packages before the
// real Sigstore verifier is wired). It attests exactly the {ecosystem,name,version}
// tuples it is seeded with; everything else is unattested (refused where required).
type StubVerifier struct {
	attested map[attestKey]struct{}
}

type attestKey struct {
	eco     Ecosystem
	name    string
	version string
}

// NewStubVerifier builds a StubVerifier attesting nothing (so RequireAttestation
// refuses everything until Attest is called) — fail-closed by default.
func NewStubVerifier() *StubVerifier {
	return &StubVerifier{attested: map[attestKey]struct{}{}}
}

// Attest marks a specific {ecosystem,name,version} as attested.
func (s *StubVerifier) Attest(eco Ecosystem, name, version string) {
	s.attested[attestKey{eco: eco, name: normalizeName(eco, name), version: version}] = struct{}{}
}

// Attested implements AttestationVerifier against the seeded set.
func (s *StubVerifier) Attested(_ context.Context, ref Ref, _ []byte) (bool, error) {
	_, ok := s.attested[attestKey{eco: ref.Ecosystem, name: normalizeName(ref.Ecosystem, ref.Name), version: ref.Version}]
	return ok, nil
}
