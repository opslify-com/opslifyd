// Package install implements F0.1 — the interactive install & tool-selection
// flow behind `opslify init`. It detects a project's shape, lets the operator
// curate the DevOps toolset their agents will get, writes the declarative
// artifacts (opslify.env.yaml, devbox.json, flake.nix, /etc/opslify/config.yaml),
// generates the daemon Ed25519 identity, and drives F0.2's EnvBuilder to produce
// the signed, digest-pinned toolchain layer.
//
// Every external-tool and TTY interaction sits behind a narrow, fakeable seam
// (Prompter, Capabilities probe, env.EnvBuilder), so detection, catalog mapping,
// artifact generation, config defaults and key generation are all unit-testable
// with no tools, no TTY and no root. Missing tools never fail the flow: they
// downgrade to a legible warning and a gated skip.
package install

import "sort"

// CatalogEntry is one curated tool: a stable operator-facing ID, the Nix package
// it maps to (what F0.2's composer resolves), the project markers that suggest
// it, and a short description for the prompt.
type CatalogEntry struct {
	// ID is the stable, operator-facing tool id (e.g. "terraform", "kubectl").
	ID string
	// NixPackage is the nixpkgs attribute the composer resolves (e.g.
	// "kubernetes-helm" for helm). This is the Name carried into env.ToolSelection.
	NixPackage string
	// Markers are filenames/globs whose presence in a project suggests this tool.
	Markers []string
	// Desc is a one-line description shown in the selection prompt.
	Desc string
	// Base marks utilities suggested for every project (git, jq, curl).
	Base bool
}

// catalog is the curated tool set. Each entry maps a familiar DevOps tool to a
// concrete nixpkgs attribute so the operator never has to know Nix names. Custom
// Nix packages can still be added on top via the prompt.
var catalog = []CatalogEntry{
	{ID: "terraform", NixPackage: "terraform", Markers: []string{"*.tf", "main.tf", "terraform.tfvars"}, Desc: "Infrastructure as code (HashiCorp Terraform)"},
	{ID: "kubectl", NixPackage: "kubectl", Markers: []string{"kustomization.yaml", "kustomization.yml"}, Desc: "Kubernetes CLI"},
	{ID: "helm", NixPackage: "kubernetes-helm", Markers: []string{"Chart.yaml"}, Desc: "Kubernetes package manager"},
	{ID: "aws", NixPackage: "awscli2", Markers: nil, Desc: "AWS CLI v2"},
	{ID: "gcloud", NixPackage: "google-cloud-sdk", Markers: nil, Desc: "Google Cloud SDK"},
	{ID: "az", NixPackage: "azure-cli", Markers: nil, Desc: "Azure CLI"},
	{ID: "docker-cli", NixPackage: "docker-client", Markers: []string{"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}, Desc: "Docker client CLI"},
	{ID: "go", NixPackage: "go", Markers: []string{"go.mod"}, Desc: "Go toolchain"},
	{ID: "node", NixPackage: "nodejs", Markers: []string{"package.json"}, Desc: "Node.js runtime"},
	{ID: "python3", NixPackage: "python3", Markers: []string{"requirements.txt", "pyproject.toml", "setup.py"}, Desc: "Python 3 interpreter"},
	{ID: "git", NixPackage: "git", Markers: nil, Desc: "Version control", Base: true},
	{ID: "jq", NixPackage: "jq", Markers: nil, Desc: "JSON processor", Base: true},
	{ID: "curl", NixPackage: "curl", Markers: nil, Desc: "HTTP client", Base: true},
}

// Catalog returns a copy of the curated tool catalog in a stable order.
func Catalog() []CatalogEntry {
	out := make([]CatalogEntry, len(catalog))
	copy(out, catalog)
	return out
}

// entryByID indexes the catalog for lookups.
func entryByID(id string) (CatalogEntry, bool) {
	for _, e := range catalog {
		if e.ID == id {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// baseToolIDs returns the always-suggested base utility ids, sorted.
func baseToolIDs() []string {
	var out []string
	for _, e := range catalog {
		if e.Base {
			out = append(out, e.ID)
		}
	}
	sort.Strings(out)
	return out
}
