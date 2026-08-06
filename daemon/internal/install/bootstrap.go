package install

import (
	"bytes"
	"fmt"
	"os/exec"
	"text/template"

	"github.com/opslify-com/opslifyd/internal/session/runtime"
)

// Capabilities reports which host prerequisites are present. It is a pure probe:
// it never installs anything and never fails the init flow — a missing tool is a
// legible warning plus a fallback, per the spec.
type Capabilities struct {
	Podman bool
	Runsc  bool
	Runc   bool
}

// lookPath is the injectable seam over exec.LookPath so capability probing is
// unit-testable without the real binaries present.
var lookPath = exec.LookPath

// ProbeCapabilities checks the host for the container engine and OCI runtimes.
func ProbeCapabilities() Capabilities {
	has := func(bin string) bool { _, err := lookPath(bin); return err == nil }
	return Capabilities{
		Podman: has("podman"),
		Runsc:  has("runsc"),
		Runc:   has("runc"),
	}
}

// RecommendTier returns the isolation tier the host can actually run today, plus
// a legible reason. The default is local-hardened (gVisor/runsc); when runsc is
// absent it recommends the local-docker (runc) compat rung rather than crashing.
func (c Capabilities) RecommendTier() (runtime.Tier, string) {
	if c.Runsc {
		return runtime.TierLocalHardened, "runsc present: using hardened gVisor rung"
	}
	if c.Runc {
		return runtime.TierLocalDocker, "runsc not found: falling back to the runc compat rung (weaker isolation)"
	}
	return runtime.TierLocalHardened, "no OCI runtime found: keeping local-hardened default; install runsc before running sessions"
}

// SocketPermsNote documents the daemon Unix-socket permission requirement.
const SocketPermsNote = "daemon API socket /run/opslify/opslifyd.sock must be mode 0660, group `opslify` (group-gated access)"

// SystemdUnitParams parameterises the systemd unit template.
type SystemdUnitParams struct {
	// ExecStart is the daemon binary invocation.
	ExecStart string
	// ConfigPath is the daemon config file path passed to the daemon.
	ConfigPath string
	// User/Group the daemon runs as.
	User  string
	Group string
	// SocketPath is the Unix API socket path.
	SocketPath string
}

// DefaultSystemdUnitParams returns the standard production unit parameters.
func DefaultSystemdUnitParams(configPath string) SystemdUnitParams {
	return SystemdUnitParams{
		ExecStart:  "/usr/bin/opslifyd --config " + configPath,
		ConfigPath: configPath,
		User:       "opslify",
		Group:      "opslify",
		SocketPath: "/run/opslify/opslifyd.sock",
	}
}

var systemdTmpl = template.Must(template.New("unit").Parse(`[Unit]
Description=opslify daemon (opslifyd) — the only sandbox executor
Documentation=https://github.com/opslify-com/opslifyd
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart={{ .ExecStart }}
User={{ .User }}
Group={{ .Group }}
# Socket is created 0660, group {{ .Group }} (group-gated local access).
RuntimeDirectory=opslify
RuntimeDirectoryMode=0750
# Hardening: the daemon needs no elevated ambient privileges of its own.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`))

// RenderSystemdUnit renders the daemon systemd unit template.
func RenderSystemdUnit(p SystemdUnitParams) (string, error) {
	var buf bytes.Buffer
	if err := systemdTmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("install: render systemd unit: %w", err)
	}
	return buf.String(), nil
}
