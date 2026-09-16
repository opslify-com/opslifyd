package session

import (
	"strings"
	"testing"
)

func TestLabelReadsAsAName(t *testing.T) {
	l := MakeLabel("tripon", "tripon.staging")
	// The environment id is usually "project.env"; keeping the prefix would give
	// "tripon-tripon.staging-maple".
	if strings.Contains(l, "tripon.staging") {
		t.Fatalf("label = %q; the project prefix should be dropped from the environment", l)
	}
	if !strings.HasPrefix(l, "tripon-staging-") {
		t.Fatalf("label = %q, want tripon-staging-<word>", l)
	}
	if strings.Count(l, "-") != 2 {
		t.Errorf("label = %q, want exactly three parts", l)
	}
}

func TestLabelWithoutAScope(t *testing.T) {
	if l := MakeLabel("", ""); l == "" || strings.Contains(l, "-") {
		t.Fatalf("label = %q, want a bare word when there is no scope", l)
	}
}

func TestLabelDoesNotRepeatTheProject(t *testing.T) {
	// An environment named the same as its project would otherwise read
	// "default-default-maple".
	l := MakeLabel("default", "default")
	if strings.HasPrefix(l, "default-default") {
		t.Fatalf("label = %q", l)
	}
}

// TestLabelsVary: math/rand without a seed makes every daemon produce the same
// sequence, so "amber" would be the first sandbox on every machine — which looks
// like a bug the first time two people compare notes.
func TestLabelsVary(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		seen[MakeLabel("p", "p.e")] = true
	}
	if len(seen) < 5 {
		t.Fatalf("40 labels produced only %d distinct values", len(seen))
	}
}

// TestNoLabelWordDescribesAState: "tripon-prod-broken" is a sentence somebody
// will misread at the wrong moment.
func TestNoLabelWordDescribesAState(t *testing.T) {
	bad := map[string]bool{
		"failed": true, "broken": true, "live": true, "dead": true, "error": true,
		"stale": true, "pending": true, "ready": true, "down": true, "up": true,
	}
	for _, w := range labelWords {
		if bad[w] {
			t.Errorf("%q describes a state and will be misread as one", w)
		}
	}
}
