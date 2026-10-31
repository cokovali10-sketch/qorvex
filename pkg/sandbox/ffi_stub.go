//go:build !linux

package sandbox

import "fmt"

// SandboxResult mirrors the Linux implementation's result type.
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

// Finding mirrors the Linux implementation's finding type.
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

// SandboxConfig mirrors the Linux implementation's config type.
type SandboxConfig struct {
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
	CPUTimeMs        uint64 `json:"cpu_time_ms"`
	TimeoutSecs      uint64 `json:"timeout_secs"`
	NetworkBlocked   bool   `json:"network_blocked"`
}

// Run is a stub on non-Linux platforms where the Rust sandbox is unavailable.
func Run(cmd string, args []string, input []byte, cfg *SandboxConfig) (*SandboxResult, error) {
	return nil, fmt.Errorf("sandbox not available on this platform")
}

// ToFindings converts sandbox violations into security findings.
func ToFindings(violations []string) []Finding {
	return nil
}