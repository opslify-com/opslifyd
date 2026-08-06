package env

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultBaseDir is the production attestation/artifact root. Tests and
// non-root callers override it via Store.BaseDir — nothing here requires root.
const DefaultBaseDir = "/var/lib/opslify"

// Store persists per-environment artifacts: the attestation record, the raw
// layer bytes (so Verify can re-derive the content digest), and the SBOM.
//
// Layout under BaseDir:
//
//	envs/<env_id>.json    attestation record (no secrets)
//	layers/<env_id>.tar   content-addressed layer bytes
//	sbom/<env_id>.json    SBOM document
//
// BaseDir is configurable so tests default to a temp dir and never touch
// /var/lib/opslify.
type Store struct {
	BaseDir string
	// now is injectable for deterministic tests.
	now func() time.Time
}

// NewStore returns a Store rooted at baseDir (falling back to DefaultBaseDir).
func NewStore(baseDir string) *Store {
	if baseDir == "" {
		baseDir = DefaultBaseDir
	}
	return &Store{BaseDir: baseDir, now: time.Now}
}

func (s *Store) envsDir() string   { return filepath.Join(s.BaseDir, "envs") }
func (s *Store) layersDir() string { return filepath.Join(s.BaseDir, "layers") }
func (s *Store) sbomDir() string   { return filepath.Join(s.BaseDir, "sbom") }

func (s *Store) attestationPath(envID string) string {
	return filepath.Join(s.envsDir(), envID+".json")
}
func (s *Store) layerPath(envID string) string {
	return filepath.Join(s.layersDir(), envID+".tar")
}
func (s *Store) sbomPath(envID string) string {
	return filepath.Join(s.sbomDir(), envID+".json")
}

// putLayer writes the content-addressed layer bytes. Layer content is not
// secret. Files are written 0600/dirs 0700 as defence-in-depth.
func (s *Store) putLayer(envID string, layer []byte) (string, error) {
	if err := os.MkdirAll(s.layersDir(), 0o700); err != nil {
		return "", fmt.Errorf("env: create layers dir: %w", err)
	}
	p := s.layerPath(envID)
	if err := os.WriteFile(p, layer, 0o600); err != nil {
		return "", fmt.Errorf("env: write layer: %w", err)
	}
	return p, nil
}

// getLayer reads the stored layer bytes for envID.
func (s *Store) getLayer(envID string) ([]byte, error) {
	b, err := os.ReadFile(s.layerPath(envID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrLayerNotFound, envID)
		}
		return nil, fmt.Errorf("env: read layer: %w", err)
	}
	return b, nil
}

// putSBOM writes the SBOM document and returns its ref (path).
func (s *Store) putSBOM(envID string, sbom []byte) (string, error) {
	if err := os.MkdirAll(s.sbomDir(), 0o700); err != nil {
		return "", fmt.Errorf("env: create sbom dir: %w", err)
	}
	p := s.sbomPath(envID)
	if err := os.WriteFile(p, sbom, 0o600); err != nil {
		return "", fmt.Errorf("env: write sbom: %w", err)
	}
	return p, nil
}

// putAttestation persists the attestation record for a baked layer.
func (s *Store) putAttestation(locked LockedEnv, layer SignedLayer) error {
	if err := os.MkdirAll(s.envsDir(), 0o700); err != nil {
		return fmt.Errorf("env: create envs dir: %w", err)
	}
	rec := Attestation{
		SchemaVersion: AttestationSchemaVersion,
		EnvID:         layer.EnvID,
		ToolSelection: locked.Selection,
		FlakeLockHash: locked.FlakeLockHash,
		LayerDigest:   layer.LayerDigest,
		SBOMRef:       layer.SBOMRef,
		Signature:     base64.StdEncoding.EncodeToString(layer.Signature),
		CreatedAt:     s.now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("env: marshal attestation: %w", err)
	}
	if err := os.WriteFile(s.attestationPath(layer.EnvID), b, 0o600); err != nil {
		return fmt.Errorf("env: write attestation: %w", err)
	}
	return nil
}

// GetAttestation retrieves a persisted attestation record by env_id.
func (s *Store) GetAttestation(envID string) (Attestation, error) {
	var rec Attestation
	b, err := os.ReadFile(s.attestationPath(envID))
	if err != nil {
		return rec, fmt.Errorf("env: read attestation %s: %w", envID, err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("env: unmarshal attestation %s: %w", envID, err)
	}
	return rec, nil
}
