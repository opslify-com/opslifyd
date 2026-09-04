# Contributing

opslifyd is open source. Contributions — code, docs, bug reports — are welcome.

## Repository layout

| Path | What |
|---|---|
| `daemon/` | Go module: `cmd/opslifyd` (daemon), `cmd/opslify` (CLI), `internal/…` (session, broker, egress, policy, trace, …). |
| `scripts/` | `install.sh`, `uninstall.sh`, `get-opslify.sh` (the one-liner bootstrap). |
| `spec/` | Design specs, phase/feature docs, manual-test walkthroughs, the dependency graph. |
| `docs/` | This documentation site (MkDocs Material). |
| `INSTALL.md` | Quick install reference (the docs site is the full version). |

## Building & testing

```bash
cd daemon
go build ./...
go test ./... -race
gofmt -l internal/ cmd/     # should be empty
go vet ./...
```

The spec dependency graph is validated by:

```bash
python3 spec/tools/specgraph.py     # must say VALIDATION OK
```

## Feature workflow

The project develops feature-by-feature with a spec, an implementation, and an adversarial
QA pass before merge. Each feature has a spec under `spec/phases/<phase>/features/` with
acceptance criteria and a QA checklist; security-relevant features get a manual-test
walkthrough under `spec/manual-tests/`.

## Working on the docs

The site is Markdown built with MkDocs Material:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install mkdocs-material
mkdocs serve         # live preview at http://127.0.0.1:8000
mkdocs build         # static site into ./site
```

Add a page by creating `docs/<section>/<page>.md` and adding it to `nav:` in `mkdocs.yml`.
CI builds and deploys to GitHub Pages on merge to `main`.

## Releases

Binaries are published as GitHub Release assets by `.github/workflows/release.yml`
(requires Actions enabled on the repo):

- **push to `main`** → refreshes a rolling **`latest`** release, so
  `curl -fsSL <site>/install.sh | sudo sh` (which defaults to `latest`) always downloads
  fresh binaries;
- **push a `vX.Y.Z` tag** → a pinned, versioned release (installable with
  `OPSLIFY_VERSION=vX.Y.Z`).

Each release carries `opslify-linux-amd64.tar.gz` and `opslify-linux-arm64.tar.gz` (each
containing `opslify` + `opslifyd`) — the exact names `scripts/get-opslify.sh` downloads.

## Reporting security issues

Report vulnerabilities privately via the repository's security policy, not a public issue.

## License

See the repository `LICENSE`.
