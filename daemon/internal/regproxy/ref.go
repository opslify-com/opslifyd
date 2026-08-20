package regproxy

import (
	"fmt"
	"path"
	"strings"
)

// Ref is what an inbound registry request resolves to: the ecosystem, the package
// name + version (best-effort parsed from the path), and whether the request is
// for an ARTIFACT (a downloadable, hashable file) versus metadata/index. The
// allowlist gates on {ecosystem, name}; the `pkg.install` event records
// {ecosystem, name, version, sha256}; IsArtifact decides whether a fetch is a
// hashable install worth an event.
type Ref struct {
	Ecosystem  Ecosystem
	Name       string
	Version    string
	IsArtifact bool
	// upstreamPath is the path (with any leading "/") to append to the upstream
	// BaseURL — i.e. the inbound path with the ecosystem prefix stripped.
	upstreamPath string
}

// parseRequest splits an inbound proxy request path into {ecosystem, remainder}
// and parses a Ref. The leading segment selects the ecosystem (fail-closed: an
// unknown segment errors). The remainder is parsed per-ecosystem to extract the
// package name/version. A path that cannot yield a package name is refused
// (fail-closed) — the allowlist cannot gate what it cannot name.
//
// Layouts handled (the standard client layouts):
//   - pip:  /pypi/simple/<name>/                         (index)
//     /pypi/packages/.../<name>-<version>...whl    (artifact)
//     /pypi/packages/.../<name>-<version>.tar.gz   (sdist artifact)
//   - npm:  /npm/<name>                                  (metadata; scoped @s/n)
//     /npm/<name>/-/<file>-<version>.tgz           (tarball artifact)
//   - go:   /go/<module...>/@v/<version>.(info|mod|zip)  (GOPROXY)
//     /go/<module...>/@latest                      (GOPROXY)
func parseRequest(reqPath string) (Ref, error) {
	clean := path.Clean("/" + strings.TrimPrefix(reqPath, "/"))
	// path.Clean collapses any "..", but reject explicitly so a traversal attempt is
	// a legible refusal rather than a silently-normalized fetch.
	if strings.Contains(reqPath, "..") {
		return Ref{}, fmt.Errorf("regproxy: path %q contains ..", reqPath)
	}
	trimmed := strings.TrimPrefix(clean, "/")
	seg := strings.SplitN(trimmed, "/", 2)
	if len(seg) < 2 || seg[1] == "" {
		return Ref{}, fmt.Errorf("regproxy: path %q has no ecosystem/remainder", reqPath)
	}
	eco := Ecosystem(seg[0])
	if !knownEcosystems[eco] {
		return Ref{}, fmt.Errorf("regproxy: unknown ecosystem %q in path %q", seg[0], reqPath)
	}
	remainder := "/" + seg[1]
	ref := Ref{Ecosystem: eco, upstreamPath: remainder}
	var err error
	switch eco {
	case EcosystemPyPI:
		err = parsePyPI(&ref, seg[1])
	case EcosystemNPM:
		err = parseNPM(&ref, seg[1])
	case EcosystemGo:
		err = parseGo(&ref, seg[1])
	}
	if err != nil {
		return Ref{}, err
	}
	if ref.Name == "" {
		return Ref{}, fmt.Errorf("regproxy: could not extract a package name from %q", reqPath)
	}
	return ref, nil
}

func parsePyPI(ref *Ref, rest string) error {
	parts := strings.Split(rest, "/")
	if parts[0] == "simple" {
		if len(parts) >= 2 && parts[1] != "" {
			ref.Name = parts[1]
		}
		return nil
	}
	// Artifact: the final path element is the distribution filename.
	file := parts[len(parts)-1]
	name, version := parsePyPIFilename(file)
	ref.Name = name
	ref.Version = version
	ref.IsArtifact = name != "" && version != ""
	return nil
}

// parsePyPIFilename extracts (name, version) from a wheel or sdist filename.
// wheel:  <name>-<version>-<pytag>-<abitag>-<plat>.whl
// sdist:  <name>-<version>.tar.gz | .zip
func parsePyPIFilename(file string) (name, version string) {
	switch {
	case strings.HasSuffix(file, ".whl"):
		base := strings.TrimSuffix(file, ".whl")
		fields := strings.Split(base, "-")
		if len(fields) >= 2 {
			return fields[0], fields[1]
		}
	case strings.HasSuffix(file, ".tar.gz"), strings.HasSuffix(file, ".tgz"), strings.HasSuffix(file, ".zip"):
		base := file
		for _, suf := range []string{".tar.gz", ".tgz", ".zip"} {
			base = strings.TrimSuffix(base, suf)
		}
		if i := strings.LastIndexByte(base, '-'); i > 0 {
			return base[:i], base[i+1:]
		}
	}
	return "", ""
}

func parseNPM(ref *Ref, rest string) error {
	// Tarball: <name>/-/<file>-<version>.tgz  (name may be @scope/pkg).
	if i := strings.Index(rest, "/-/"); i >= 0 {
		ref.Name = rest[:i]
		file := rest[i+len("/-/"):]
		if strings.HasSuffix(file, ".tgz") {
			base := strings.TrimSuffix(file, ".tgz")
			if j := strings.LastIndexByte(base, '-'); j > 0 {
				ref.Version = base[j+1:]
			}
		}
		ref.IsArtifact = ref.Version != ""
		return nil
	}
	// Metadata: /<name> or /@scope/name.
	if strings.HasPrefix(rest, "@") {
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 2 {
			ref.Name = parts[0] + "/" + parts[1]
		}
		return nil
	}
	ref.Name = strings.SplitN(rest, "/", 2)[0]
	return nil
}

func parseGo(ref *Ref, rest string) error {
	// GOPROXY: <module>/@v/<version>.<ext> or <module>/@latest.
	if i := strings.Index(rest, "/@v/"); i >= 0 {
		ref.Name = rest[:i]
		file := rest[i+len("/@v/"):]
		for _, ext := range []string{".zip", ".info", ".mod"} {
			if strings.HasSuffix(file, ext) {
				ref.Version = strings.TrimSuffix(file, ext)
				ref.IsArtifact = ext == ".zip"
				break
			}
		}
		return nil
	}
	if i := strings.Index(rest, "/@latest"); i >= 0 {
		ref.Name = rest[:i]
		return nil
	}
	ref.Name = rest
	return nil
}
