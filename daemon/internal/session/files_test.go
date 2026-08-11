package session

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWorkspacePath(t *testing.T) {
	root := "/srv/ws/sess-1"
	cases := []struct {
		in      string
		wantErr bool
		want    string
	}{
		{"/workspace/foo.txt", false, "/srv/ws/sess-1/foo.txt"},
		{"foo/bar.txt", false, "/srv/ws/sess-1/foo/bar.txt"},
		{"/workspace/a/../b", false, "/srv/ws/sess-1/b"},
		{"/workspace/../../etc/passwd", true, ""},
		{"/etc/passwd", true, ""},
		{"../escape", true, ""},
		{"/workspace", true, ""}, // directory itself, not a file
		{"foo\x00bar", true, ""},
	}
	for _, c := range cases {
		got, err := resolveWorkspacePath(root, c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("resolveWorkspacePath(%q) = %q, want error", c.in, got)
			}
			if err != nil && !errors.Is(err, ErrInvalidInput) {
				t.Errorf("resolveWorkspacePath(%q) err = %v, want ErrInvalidInput", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveWorkspacePath(%q) unexpected err: %v", c.in, err)
			continue
		}
		if got != filepath.Clean(c.want) {
			t.Errorf("resolveWorkspacePath(%q) = %q, want %q", c.in, got, c.want)
		}
		if !strings.HasPrefix(got, root+"/") {
			t.Errorf("resolveWorkspacePath(%q) escaped root: %q", c.in, got)
		}
	}
}
