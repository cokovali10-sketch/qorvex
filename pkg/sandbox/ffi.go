//go:build linux

package sandbox

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/target/release -lqorvex_sandbox -lpthread -ldl -lm
#include <stdlib.h>
#include <string.h>

// Forward declarations for Rust FFI
typedef struct SandboxConfig SandboxConfig;
typedef struct ExecutionResult ExecutionResult;
typedef char* CStr;

ExecutionResult* run_sandbox(const char* cmd, const char* args, const char* input, SandboxConfig* cfg);
void free_result(ExecutionResult* r);
void free_string(CStr s);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// SandboxResult maps Rust ExecutionResult to Go Finding-oriented output
type SandboxResult struct {
	ExitCode           int      `json:"exit_code"`
	Stdout             string   `json:"stdout"`
	Stderr             string   `json:"stderr"`
	CPUTimeMs          uint64   `json:"cpu_time_ms"`
	MemoryPeakBytes    uint64   `json:"memory_peak_bytes"`
	ElapsedTimeMs      uint64   `json:"elapsed_time_ms"`
	TimedOut           bool     `json:"timed_out"`
	OomKilled          bool     `json:"oom_killed"`
	SandboxViolations  []string `json:"sandbox_violations"`
	OutputTrimmed      bool     `json:"output_trimmed"`
}

// Finding maps a sandbox violation to a security finding
type Finding struct {
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Description  string `json:"description"`
	FilePath     string `json:"file_path,omitempty"`
	LineStart    int    `json:"line_start,omitempty"`
	CWE          string `json:"cwe,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	RuleID       string `json:"rule_id,omitempty"`
}

// Run executes command via Rust sandbox and converts to sandbox result
func Run(cmd string, args []string, input []byte, cfg *SandboxConfig) (*SandboxResult, error) {
	// Build args string for FFI (simplified — in production use structured FFI)
	argsStr := ""
	for _, a := range args {
		argsStr += a + "\n"
	}

	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	cArgs := C.CString(argsStr)
	defer C.free(unsafe.Pointer(cArgs))

	cInput := C.CString(string(input))
	defer C.free(unsafe.Pointer(cInput))

	var cCfg *C.SandboxConfig
	if cfg != nil {
		// Would construct from Go struct via FFI mapping
		cCfg = nil // placeholder for real cfg mapping
	}

	// Call Rust
	res := C.run_sandbox(cCmd, cArgs, cInput, cCfg)
	if res == nil {
		return nil, fmt.Errorf("sandbox execution failed")
	}
	defer C.free_result(res)

	s := &SandboxResult{
		ExitCode: int(res.exit_code),
		TimedOut: bool(res.timed_out),
		OomKilled: bool(res.oom_killed),
	}

	// Convert stdout/stderr strings
	if res.stdout != nil {
		s.Stdout = C.GoString(res.stdout)
		C.free_string(res.stdout)
	}
	if res.stderr != nil {
		s.Stderr = C.GoString(res.stderr)
		C.free_string(res.stderr)
	}

	s.CPUTimeMs = uint64(res.cpu_time_ms)
	s.MemoryPeakBytes = uint64(res.memory_peak_bytes)
	s.ElapsedTimeMs = uint64(res.elapsed_time_ms)
	s.OutputTrimmed = bool(res.output_trimmed)

	// Convert violations to findings
	if res.sandbox_violations != nil {
		violations := C.GoString(res.sandbox_violations)
		C.free_string(res.sandbox_violations)
		// Simplified — split by delimiter in production
		s.SandboxViolations = []string{violations}
	}

	return s, nil
}

// ToFindings converts sandbox violations into security findings
type SandboxConfig struct {
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
	CPUTimeMs        uint64 `json:"cpu_time_ms"`
	TimeoutSecs      uint64 `json:"timeout_secs"`
	NetworkBlocked   bool   `json:"network_blocked"`
}
