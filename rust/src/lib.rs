// Qorvex Execution Engine (Rust)
// 
// Isolated execution of untrusted code using OS-level isolation primitives.
// On Linux: seccomp-bpf + user namespaces + mount namespaces + cgroups
// On Windows: job objects + restricted tokens (fallback)
//
// Current version: v0.2.0 with basic sandbox implementations

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Configuration for a sandboxed execution environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub cpu_limit_ms: u64,           // CPU time limit in milliseconds
    pub memory_limit_bytes: u64,     // Memory limit in bytes
    pub disk_limit_bytes: u64,       // Disk write limit in bytes
    pub process_limit: u32,          // Max number of child processes
    pub timeout_secs: u64,           // Wall-clock timeout in seconds
    pub network_blocked: bool,       // Whether network is blocked
    pub readonly_root: bool,         // Whether rootfs is readonly
    pub work_dir: String,            // Working directory inside sandbox
    pub env_whitelist: Vec<String>,  // Allowed environment variables
    pub rlimits: map::Map<String, u64>, // Resource limits (NOFILE, NPROC, FSIZE, etc.)
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            cpu_limit_ms: 30_000,
            memory_limit_bytes: 512 * 1024 * 1024, // 512 MB
            disk_limit_bytes: 100 * 1024 * 1024,   // 100 MB
            process_limit: 16,
            timeout_secs: 60,
            network_blocked: true,
            readonly_root: true,
            work_dir: "/workspace".to_string(),
            env_whitelist: vec!["PATH".to_string(), "HOME".to_string()],
            rlimits: /* will be initialized per-OS */,
        }
    }
}

/// Result of a sandboxed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub cpu_time_ms: u64,
    pub memory_peak_bytes: u64,
    pub elapsed_time_ms: u64,
    pub timed_out: bool,
    pub oom_killed: bool,
    pub sandbox_violations: Vec<String>,
    pub output_trimmed: bool,
}

/// Sandbox returns an execution result for a given command.
///
/// # Arguments
/// * `cmd` - The command to execute within the sandbox
/// * `args` - Arguments to the command
/// * `input` - stdin content
/// * `config` - sandbox configuration
///
/// # Returns
/// `Ok(ExecutionResult)` on completion, `Err` on sandbox setup failure.
pub fn execute(
    cmd: &str,
    args: &[String],
    input: &[u8],
    config: &SandboxConfig,
) -> Result<ExecutionResult, String> {
    #[cfg(target_os = "linux")]
    {
        linux::run_sandboxed(cmd, args, input, config)
    }

    #[cfg(target_os = "windows")]
    {
        windows::run_sandboxed(cmd, args, input, config)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (cmd, args, input, config);
        Err("sandbox not supported on this OS".to_string())
    }
}

// ============================================================================
// Linux implementation (seccomp-bpf + namespaces + cgroups)
// ============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::sys::fd::RawFd;

    // seccomp BPF helpers
    const SECCOMP_SET_MODE_STRICT: i32 = 0;
    const SECCOMP_FILTER_FLAG_SCORE_KILL: i32 = 1 << 0;
    const SECCOMP_RET_KILL: i32 = 0x00000000;
    const SECCOMP_RET_ALLOW: i32 = 0x00000000 | SECCOMP_FILTER_FLAG_SCORE_KILL;
    const SECCOMP_ERRNO: i32 = 65536;

    // CLONE flags for namespaces
    const CLONE_NEWNS: i32 = 0x00020000;
    const CLONE_NEWPID: i32 = 0x20000000;
    const CLONE_NEWNET: i32 = 0x40000000;
    const CLONE_NEWUSER: i32 = 0x10000000;
    const CLONE_NEWIPC: i32 = 0x80000000;
    const CLONE_NEWUTS: i32 = 0x04000000;

    // cgroup paths
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const CGROUP_MEMORY: &str = "/sys/fs/cgroup/memory";
    const CGROUP_PIDS: &str = "/sys/fs/cgroup/pids";

    pub fn run_sandboxed(
        cmd: &str,
        args: &[String],
        input: &[u8],
        config: &SandboxConfig,
    ) -> Result<ExecutionResult, String> {
        // 1. Create new user namespace (needed for unprivileged user namespace tricks)
        // 2. Create mount namespace
        // 3. Create PID namespace
        // 4. Create network namespace (if needed)
        // 5. Set up seccomp BPF filter
        // 6. Set up cgroup limits
        // 7. Fork and execute in sandbox
        // 8. Monitor and collect results

        // For now, implement a minimal sandbox that:
        // - Creates necessary namespaces
        // - Sets up basic seccomp filter
        // - Applies cgroup limits
        // - Executes the command
        // - Collects results

        let pid = unsafe {
            // Clone with namespaces
            let clone_flags: i32 = CLONE_NEWUSER
                | CLONE_NEWPID
                | CLONE_NEWNS
                | CLONE_NEWIPC
                | SIGCHLD;

            let (read_fd, write_fd) = create_pipe_pair()?;

            let child_pid = fork()?;
            if child_pid == 0 {
                // Child process
                // Set up seccomp in child
                setup_seccomp_filter()?;

                // Enter new namespaces
                // (handled by clone)

                // Set up cgroup limits if cgroup paths exist
                // setup_cgroup_limits(config)?;

                // Redirect stdin/stdout/stderr
                dup2(read_fd, 0).map_err(|e| format!("dup2 stdin: {}", e))?;
                dup2(write_fd, 1).map_err(|e| format!("dup2 stdout: {}", e))?;
                dup2(write_fd, 2).map_err(|e| format!("dup2 stderr: {}", e))?;

                // Close parent fds
                close_fd(read_fd);
                close_fd(write_fd);

                // Exec the command
                let c_args: Vec<*const i8> = std::iter::once(cmd.as_ptr() as *const i8)
                    .chain(args.iter().map(|s| s.as_ptr() as *const i8))
                    .collect();
                let exec_result = execve(cmd.as_ptr(), &c_args, &[] as *const *const i8);
                // If execve returns, an error occurred
                eprintln!("execve failed: {:?}", std::io::Error::last());
                std::process::exit(1);
            } else {
                // Parent process
                close_fd(child_pid); // We don't need the child's PID fd directly, waitpid will use it

                // Wait for child with timeout
                let start = std::time::Instant::now();
                let mut exited = false;
                let mut exit_code: i32 = 0;
                let mut stdout_data = String::new();
                let mut stderr_data = String::new();

                loop {
                    // Check timeout
                    if start.elapsed() > Duration::from_secs(config.timeout_secs) {
                        // Timeout - kill child
                        let _ = kill(child_pid, 9);
                        timed_out = true;
                        break;
                    }

                    match waitpid(child_pid, Some(exit_code)) {
                        Ok(status) => {
                            exited = true;
                            // Get actual exit code
                            // ...
                            break;
                        }
                        Err(_) => {
                            // Child still running, continue waiting
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                }

                // Read stdout/stderr from pipes
                // ...

                Ok(ExecutionResult {
                    exit_code,
                    stdout: stdout_data,
                    stderr: stderr_data,
                    cpu_time_ms: 0, // would need clock_gettime etc.
                    memory_peak_bytes: 0,
                    elapsed_time_ms: start.elapsed().as_millis() as u64,
                    timed_out,
                    oom_killed: false,
                    sandbox_violations: vec![],
                    output_trimmed: false,
                })
            }
        }?;

        Ok(pid)
    }
}

// ============================================================================
// Windows implementation (Job Objects + Restricted Tokens)
// ============================================================================

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
    use winapi::shared::minwinerror::{ERROR_SUCCESS, PROCESS_ALL_ACCESS};
    use winapi::shared::ntdef::HANDLE;
    use winapi::um::handleapi::{CloseHandle, DuplicateHandle, GetCurrentProcess};
    use winapi::um::jobapiapi::{CreateJobObjectW, SetInformationJobObject, QueryInformationJobObject};
    use winapi::um::libloaderapi::GetModuleFileNameW;
    use winapi::um::processthreadsapi::{
        CreateProcessW, GetCurrentProcessId, TerminateProcess, OpenProcess, PROCESS_INFORMATION,
    };
    use winapi::um::securitybaseapi::LookUpPrivilegeValueW;
    use winapi::um::winbase::{JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION};
    use winapi::um::winnt::{HANDLE, LARGE_INTEGER, PROCESS_ALL_ACCESS, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};

    pub fn run_sandboxed(
        cmd: &str,
        args: &[String],
        input: &[u8],
        config: &SandboxConfig,
    ) -> Result<ExecutionResult, String> {
        // Windows sandbox using Job Objects
        // 1. Create a job object
        // 2. Set job limits (memory, processes, time)
        // 3. Create a restricted token
        // 4. Create the process in the job
        // 5. Capture stdout/stderr
        // 6. Wait and collect results

        // For now, implement the core structure
        let job_name = format!("Qorvex_Sandbox_{}", std::process::id());

        let job_handle = unsafe {
            CreateJobObjectW(NULL, wstring::from_utf16_lossy(job_name.as_bytes()).as_ptr())
        };
        if job_handle.is_null() {
            return Err("failed to create job object".to_string());
        }

        // Set job basic limits
        let mut basic_limit = JOBOBJECT_BASIC_LIMIT_INFORMATION {
            PerProcessUserTimeLimit: std::mem::zeroed(),
            ProcessMemoryLimit: config.memory_limit_bytes as DWORD,
            ProcessActiveProcessLimit: config.process_limit,
            Affinity: 0,
            PriorityClass: 0,
            AffinityMask: 0,
        };

        let result = unsafe {
            SetInformationJobObject(
                job_handle,
                3 /* JobObjectBasicLimitInformation */,
                &basic_limit as *const _ as *const std::os::raw::c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as DWORD,
            )
        };
        if result == 0 {
            let err = std::io::Error::last().raw_os_error().unwrap_or(0);
            return Err(format!("failed to set job limits: error {}", err));
        }

        // Set extended limits (process memory and active process count)
        let mut extended_limit = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: basic_limit,
            ProcessMemoryLimit: config.memory_limit_bytes as DWORD,
            ProcessActiveProcessLimit: config.process_limit,
            JobMemoryLimit: config.disk_limit_bytes as DWORD,
            JobProcessMemoryLimit: config.disk_limit_bytes as DWORD,
            ProcessExecutionLimit: 0,
            JobExecutionLimit: 0,
        };

        let result = unsafe {
            SetInformationJobObject(
                job_handle,
                9 /* JobObjectExtendedLimitInformation */,
                &extended_limit as *const _ as *const std::os::raw::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            )
        };
        if result == 0 {
            return Err("failed to set extended job limits".to_string());
        }

        // Create a restricted token (simplified - in production would remove privileges)
        // For now, just assign the process to the job

        // Build command line
        let mut cmd_line = String::from(cmd);
        for arg in args {
            cmd_line.push_str(&format!(" \"{}\"", arg));
        }

        // Create startup info
        let mut si = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = WINSTATION_NAME_FORMAT; // or STARTF_USESHOWWINDOW

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let cmd_line_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

        let create_result = unsafe {
            CreateProcessW(
                NULL,                   // no module name (use command line)
                cmd_line_wide.as_ptr() as *mut u8, // command line
                None,                   // process security attributes
                None,                   // primary thread security attributes
                FALSE,                  // inherit handles
                CREATE_SUSPENDED,         // creation flags
                None,                   // environment
                None,                   // current directory
                &si,                    // startup info
                &mut pi,                // process information
            )
        };

        if create_result == 0 {
            return Err("failed to create process".to_string());
        }

        // Assign process to job object
        let _ = unsafe {
            AssignProcessToJobObject(job_handle, pi.hProcess)
        };

        // Resume the process
        let _ = unsafe { ResumeThread(pi.hThread) };

        // Wait for process completion with timeout
        let start = std::time::Instant::now();
        let mut waited = 0u64;
        let mut exit_code: DWORD = 0;

        loop {
            if waited > (config.timeout_secs * 1000) {
                // Timeout - terminate
                let _ = TerminateProcess(pi.hProcess, 1);
                return Ok(ExecutionResult {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: String::new(),
                    cpu_time_ms: 0,
                    memory_peak_bytes: 0,
                    elapsed_time_ms: (std::time::Instant::now() - start).as_millis() as u64,
                    timed_out: true,
                    oom_killed: false,
                    sandbox_violations: vec![],
                    output_trimmed: false,
                });
            }

            // Wait for single object
            let mut waited_ms = 0;
            let mut exit_status: DWORD = 0;
            let result = unsafe {
                WaitForSingleObject(pi.hProcess, 100) // 100ms timeout
            };

            match result {
                // WAIT_OBJECT_0 = 0 - process finished
                0 => {
                    // Get exit code
                    let _ = GetProcessExitCode(pi.hProcess, &mut exit_code);
                    break;
                }
                // WAIT_TIMEOUT = 258 - still running
                258 => {
                    waited += 100;
                    continue;
                }
                _ => {
                    break;
                }
            }
        }

        // Read stdout/stderr (simplified - in production would use pipes)
        // For now, return empty output

        Ok(ExecutionResult {
            exit_code: exit_code as i32,
            stdout: String::new(),
            stderr: String::new(),
            cpu_time_ms: 0,
            memory_peak_bytes: 0,
            elapsed_time_ms: (std::time::Instant::now() - start).as_millis() as u64,
            timed_out: false,
            oom_killed: false,
            sandbox_violations: vec![],
            output_trimmed: false,
        })
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn create_pipe_pair() -> Result<(std::fs::File, std::fs::File), String> {
    use std::os::unix::io::FromRawFd;
    let (a, b) = std::os::unix::io::pipe()?;
    Ok((a, b))
}

fn close_fd(fd: RawFd) {
    let _ = unsafe { libc::close(fd) };
}

fn fork() -> Result<i32, String> {
    unsafe {
        let pid = libc::fork();
        if pid == -1 {
            Err(std::io::Error::last().unwrap_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                "fork failed",
            )).to_string())
        } else {
            Ok(pid)
        }
    }
}

fn waitpid(pid: i32, options: Option<i32>) -> Result<i32, String> {
    unsafe {
        let mut status: i32 = 0;
        let result = libc::waitpid(pid, &mut status, options.unwrap_or(0));
        if result == -1 {
            Err(std::io::Error::last().unwrap_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                "waitpid failed",
            )).to_string())
        } else {
            Ok(status)
        }
    }
}

fn kill(pid: i32, sig: i32) -> Result<(), String> {
    unsafe {
        let result = libc::kill(pid, sig);
        if result == -1 {
            Err(std::io::Error::last().unwrap_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                "kill failed",
            )).to_string())
        } else {
            Ok(())
        }
    }
}

fn execve(
    filename: *const i8,
    argv: &[*const i8],
    envp: &[*const *const i8],
) -> i32 {
    unsafe { libc::execve(filename, argv.as_ptr() as *const *const i8, envp.as_ptr() as *const *const i8) }
}

fn waitpid_blocking(pid: i32) -> Result<i32, String> {
    let mut status: i32 = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, 0) };
    if result == -1 {
        Err(std::io::Error::last().unwrap_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "waitpid blocked failed",
        )).to_string())
    } else {
        Ok(status)
    }
}

// String conversion for Windows
mod wstring {
    pub fn from_utf16_lossy(input: &[u8]) -> std::ffi::OsString {
        // Simplified - in production would use proper UTF-16 to OSString conversion
        std::ffi::OsString::from(std::str::from_utf8_lossy(input))
    }
}