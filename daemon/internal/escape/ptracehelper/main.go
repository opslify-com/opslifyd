// Command ptracehelper is the escape suite's genuine ptrace(PTRACE_ATTACH)
// probe. It is compiled (CGO-free, static) by the gated escape test and copied
// into the sandbox, where it attempts to PTRACE_ATTACH a process it must NOT be
// able to trace (the sandbox init, PID 1). Under the hardened config — all caps
// dropped (no CAP_SYS_PTRACE), the default seccomp profile, and on the hardened
// rung gVisor's ptrace restrictions — the attach MUST be denied.
//
// It prints exactly one line:
//   - "PTRACE_DENIED errno=<n>"   when the attach is refused (the SECURE posture)
//   - "PTRACE_ATTACHED pid=<p>"   when the attach SUCCEEDS (a real escape)
//
// It targets PID 1, which is the sandbox's own init (sleep) and is NOT this
// helper's child — so success genuinely means the sandbox could attach to an
// unrelated process, i.e. CAP_SYS_PTRACE/seccomp did not contain it. A parent
// tracing its own child (always permitted) is deliberately NOT what we test.
package main

import (
	"fmt"
	"syscall"
)

func main() {
	const target = 1 // the sandbox init; not our child
	// PTRACE_ATTACH stops and attaches to the target. errno==0 means it worked.
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_ATTACH), uintptr(target), 0, 0, 0, 0)
	if errno == 0 {
		// Detach so we don't wedge PID 1, then report the escape.
		_, _, _ = syscall.Syscall6(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_DETACH), uintptr(target), 0, 0, 0, 0)
		fmt.Printf("PTRACE_ATTACHED pid=%d\n", target)
		return
	}
	fmt.Printf("PTRACE_DENIED errno=%d\n", int(errno))
}
