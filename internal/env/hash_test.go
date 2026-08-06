package env

import "testing"

func TestNormalizeSelection_SortsDedupesTrims(t *testing.T) {
	in := ToolSelection{
		Tools: []Tool{
			{Name: " kubectl "},
			{Name: "terraform", Version: "1.7.0"},
			{Name: "kubectl"}, // dup after trim
			{Name: "jq"},
			{Name: ""}, // dropped
		},
		BaseImageDigest: " sha256:base ",
	}
	got := normalizeSelection(in)
	if got.BaseImageDigest != "sha256:base" {
		t.Fatalf("base digest not trimmed: %q", got.BaseImageDigest)
	}
	want := []Tool{{Name: "jq"}, {Name: "kubectl"}, {Name: "terraform", Version: "1.7.0"}}
	if len(got.Tools) != len(want) {
		t.Fatalf("got %d tools, want %d: %+v", len(got.Tools), len(want), got.Tools)
	}
	for i := range want {
		if got.Tools[i] != want[i] {
			t.Fatalf("tool[%d] = %+v, want %+v", i, got.Tools[i], want[i])
		}
	}
}

func TestEnvIDFor_StableAndOrderIndependent(t *testing.T) {
	a := ToolSelection{Tools: []Tool{{Name: "terraform"}, {Name: "kubectl"}, {Name: "jq"}}}
	b := ToolSelection{Tools: []Tool{{Name: "jq"}, {Name: "terraform"}, {Name: "kubectl"}}}
	ida, err := envIDFor(a)
	if err != nil {
		t.Fatal(err)
	}
	idb, err := envIDFor(b)
	if err != nil {
		t.Fatal(err)
	}
	if ida != idb {
		t.Fatalf("order-independent selections got different ids: %s vs %s", ida, idb)
	}
	c := ToolSelection{Tools: []Tool{{Name: "jq"}, {Name: "kubectl"}}}
	idc, _ := envIDFor(c)
	if idc == ida {
		t.Fatalf("different selections collided on id: %s", idc)
	}
}

func TestDigestSHA256_Stable(t *testing.T) {
	got := digestSHA256([]byte("hello"))
	want := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}
