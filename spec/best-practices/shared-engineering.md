# Shared Engineering Practices — every agent obeys

These rules bind the orchestrator, both builders, and QA. Violations block approval.

## 1. The reference chain is law
- Never build from memory. Resolve scope through [../global.md](../global.md) → phase README → feature file.
- If scope is ambiguous, walk *up* the chain. If still ambiguous, **stop and ask the human** — do not guess.

## 2. Interfaces first
- The four shared interfaces (`Runtime`, `EnvBuilder`, `TraceSink`, `SecretBackend`) are defined in P0 with single impls. Never bypass them; extend via new impls.
- A change to a shared interface is a breaking change: it must update [../architecture.md](../architecture.md) and re-verify all dependents.

## 3. Security acceptance = automated tests
- Every security claim in a feature (isolation, no-secret-leak, egress-deny) ships as a **red-team / escape script that runs in CI on every PR** — not a manual check.
- The public escape/exfil suite exists from **P1, day one**, and runs on runc AND gVisor.

## 4. Secrets hygiene (absolute)
- No secret, token, key, or plaintext credential is ever written to logs, traces, test fixtures, error messages, or stdout.
- Trace redaction (P3) is defense-in-depth, not permission to be sloppy upstream.
- Test credentials are clearly fake and never real. Seeded fake secrets exist only to prove redaction works.

## 5. Reproducibility & supply chain
- Toolchains are Nix-locked, cosign-signed, digest-pinned (D1). The daemon refuses unsigned/mismatched layers.
- Dependencies are pinned. New deps require justification in the PR and a license check.
- Builds are reproducible (Dagger); the toolchain `flake.lock` hash is recorded per built env.

## 6. Determinism & failure legibility
- Every failure must tell the operator **which layer denied it**: sandbox vs egress vs policy vs cred. Cryptic failures are bugs (this is a core UX differentiator).
- No silent truncation or silent cap without a logged/emitted marker.

## 7. Commits, branches, PRs
- One feature = one branch = one PR, titled `Fx.y: <title>`.
- Never commit to the default branch directly.
- PR body links the feature file, lists acceptance criteria with evidence, and lists which red-team scripts run.
- Commit messages end with the required Co-Authored-By trailer.

## 8. Testing baseline
- Unit tests for logic; integration tests exercising the real socket/runtime for lifecycle features.
- No feature is `qa`-ready without tests that a reviewer can run.
- Coverage is not a number to game; untested security paths are unacceptable regardless of coverage %.

## 9. Versioning
- Daemon ↔ dashboard API versioned `v1` from the start.
- Trace schema carries `schema_version`.
- Breaking changes bump versions and update migration notes.

## 10. Documentation debt is real debt
- If a feature changes behavior an operator sees, update the quickstart/policy-reference docs in the same PR.
