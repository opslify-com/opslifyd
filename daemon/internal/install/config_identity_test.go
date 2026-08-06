package install

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
	"gopkg.in/yaml.v3"
)

func TestDefaultConfigDefaults(t *testing.T) {
	c := DefaultConfig()
	if c.SessionTTL != "30m" {
		t.Errorf("session_ttl default: got %q want 30m", c.SessionTTL)
	}
	if c.WarmPoolSize != 1 {
		t.Errorf("warm_pool_size default: got %d want 1", c.WarmPoolSize)
	}
	if c.Tier != string(runtime.TierLocalHardened) {
		t.Errorf("tier default: got %q want %q", c.Tier, runtime.TierLocalHardened)
	}
	if c.WorkspaceDir == "" {
		t.Error("workspace_dir should have a default")
	}
}

func TestWriteConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "opslify", "config.yaml")
	c := DefaultConfig()
	c.Image = "repo@sha256:deadbeef"
	if err := WriteConfig(path, c); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Image != "repo@sha256:deadbeef" || got.SessionTTL != "30m" || got.Tier != string(runtime.TierLocalHardened) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	// No secret material in the config file.
	if strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatal("config file must not contain key material")
	}
}

func TestGenerateIdentityPermsAndKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "identity.key")
	id, err := GenerateIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Private key perms MUST be 0600.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("private key perms: got %o want 0600", perm)
	}
	// Parent dir must not be world-traversable.
	dinfo, _ := os.Stat(filepath.Dir(keyPath))
	if dinfo.Mode().Perm()&0o007 != 0 {
		t.Errorf("key dir world-accessible: %o", dinfo.Mode().Perm())
	}
	// The private key parses and its public half matches the returned key.
	b, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("private key not PEM PKCS#8")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not an ed25519 key")
	}
	pub := edPriv.Public().(ed25519.PublicKey)
	if id.PublicKeyHex == "" || len(pub) != ed25519.PublicKeySize {
		t.Fatal("bad public key")
	}
	// Public key file present, 0644, and does NOT contain the private key.
	pb, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pb), "PRIVATE") {
		t.Fatal("public key file leaked private material")
	}
}

func TestSystemdUnitRender(t *testing.T) {
	unit, err := RenderSystemdUnit(DefaultSystemdUnitParams("/etc/opslify/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=opslify", "Group=opslify", "NoNewPrivileges=true", "opslifyd"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q", want)
		}
	}
}
