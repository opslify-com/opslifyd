package regproxy

import "testing"

func TestParseRequest(t *testing.T) {
	cases := []struct {
		path       string
		eco        Ecosystem
		name       string
		version    string
		isArtifact bool
	}{
		{"/pypi/simple/requests/", EcosystemPyPI, "requests", "", false},
		{"/pypi/packages/aa/requests-2.31.0-py3-none-any.whl", EcosystemPyPI, "requests", "2.31.0", true},
		{"/pypi/packages/bb/urllib3-2.0.7.tar.gz", EcosystemPyPI, "urllib3", "2.0.7", true},
		{"/npm/left-pad", EcosystemNPM, "left-pad", "", false},
		{"/npm/@babel/core", EcosystemNPM, "@babel/core", "", false},
		{"/npm/left-pad/-/left-pad-1.3.0.tgz", EcosystemNPM, "left-pad", "1.3.0", true},
		{"/go/golang.org/x/text/@v/v0.14.0.zip", EcosystemGo, "golang.org/x/text", "v0.14.0", true},
		{"/go/golang.org/x/text/@v/v0.14.0.info", EcosystemGo, "golang.org/x/text", "v0.14.0", false},
		{"/go/golang.org/x/text/@latest", EcosystemGo, "golang.org/x/text", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			ref, err := parseRequest(tc.path)
			if err != nil {
				t.Fatalf("parseRequest: %v", err)
			}
			if ref.Ecosystem != tc.eco || ref.Name != tc.name || ref.Version != tc.version || ref.IsArtifact != tc.isArtifact {
				t.Fatalf("got %+v", ref)
			}
		})
	}
}

func TestParseRequestRejects(t *testing.T) {
	for _, p := range []string{"/", "/pypi", "/cargo/foo", "/pypi/../x", "/unknown/pkg"} {
		if _, err := parseRequest(p); err == nil {
			t.Fatalf("expected error for %q", p)
		}
	}
}

func TestNormalizeNamePyPI(t *testing.T) {
	if normalizeName(EcosystemPyPI, "Flask_Cors") != normalizeName(EcosystemPyPI, "flask-cors") {
		t.Fatal("PEP 503 normalization mismatch")
	}
	if normalizeName(EcosystemNPM, "Left-Pad") == normalizeName(EcosystemNPM, "left-pad") {
		t.Fatal("npm names must stay case-sensitive")
	}
}
