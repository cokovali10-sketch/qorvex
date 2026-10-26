package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"qorvex/pkg/platform"
)

const (
	// maxScanFiles bounds the number of files inspected by a single stage.
	// The bound keeps hostile trees (e.g. millions of tiny files) from
	// exhausting memory or wall-clock time.
	maxScanFiles = 5000

	// maxScanFileBytes is the largest file read into memory for content
	// scanning. Larger files are skipped rather than truncated, so a
	// finding is never reported against partial content.
	maxScanFileBytes = 1 << 20 // 1 MiB

	// maxCommandOutput caps captured stdout/stderr from external tools.
	maxCommandOutput = 64 << 10 // 64 KiB

	// maxPathDepth bounds directory traversal depth.
	maxPathDepth = 64

	// skippedDirs are never traversed: VCS metadata, dependency caches and
	// build outputs are untrusted noise for a source verification pass.
	skippedDirs = ".git|.hg|.svn|node_modules|target|dist|build|.venv|venv|__pycache__|.mypy_cache|.pytest_cache|vendor"
)

// projectFile is a bounded description of a file inside a project.
type projectFile struct {
	Abs   string
	Rel   string
	Size  int64
	Mode  os.FileMode
	IsDir bool
}

// resolveProjectRoot returns the canonical absolute root of a project and
// fails closed when the path is empty, missing or not a directory.
func resolveProjectRoot(p *platform.Project) (string, error) {
	if p == nil {
		return "", errors.New("project is nil")
	}
	if strings.TrimSpace(p.Path) == "" {
		return "", errors.New("project path is empty")
	}

	abs, err := filepath.Abs(p.Path)
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}
	abs = filepath.Clean(abs)

	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("project path is not accessible: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project path is not a directory: %s", abs)
	}

	// Resolve symlinks on the root itself so containment checks compare
	// real paths. On Windows this also normalises case-insensitive paths.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve project symlinks: %w", err)
	}
	return filepath.Clean(real), nil
}

// safeJoin joins rel onto root and guarantees the result stays inside root.
// It is the only supported way to build a path from untrusted input.
func safeJoin(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths are not allowed: %s", rel)
	}
	joined := filepath.Join(root, rel)
	if !isWithin(root, joined) {
		return "", fmt.Errorf("path escapes project root: %s", rel)
	}
	return joined, nil
}

// isWithin reports whether target is root or a descendant of root.
func isWithin(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if strings.EqualFold(root, target) {
		return true
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// walkProject walks root without following symlinks, skipping noisy
// directories. It returns the collected files, whether the maxFiles bound was
// hit, and an error only for failures on the root itself.
func walkProject(root string, maxFiles int) ([]projectFile, bool, error) {
	if maxFiles <= 0 {
		maxFiles = maxScanFiles
	}

	files := make([]projectFile, 0, 256)
	truncated := false
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Unreadable entries inside the tree are skipped, not fatal.
			if path == root {
				return err
			}
			return nil
		}

		depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
		if depth > maxPathDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if path != root && matchesAny(name, skippedDirs) {
				return filepath.SkipDir
			}
			return nil
		}

		if len(files) >= maxFiles {
			truncated = true
			return filepath.SkipAll
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		files = append(files, projectFile{
			Abs:  path,
			Rel:  rel,
			Size: info.Size(),
			Mode: info.Mode(),
		})
		return nil
	})
	if err != nil {
		return nil, truncated, err
	}
	return files, truncated, nil
}

// readFileBounded reads at most maxBytes from path. It returns an error when
// the file is larger than the bound so callers never scan partial content.
func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

// looksBinary reports whether data appears to be non-text content.
func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	return !utf8.Valid(sample)
}

// commandResult captures a bounded external command execution.
type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// runCommand executes name with args in dir, bounded by timeout and output
// limits. No shell is involved, so arguments are never re-parsed.
func runCommand(timeout time.Duration, dir, name string, args ...string) commandResult {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = minimalEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, remaining: maxCommandOutput}
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: maxCommandOutput}

	err := cmd.Run()
	res := commandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Err:    err,
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res.Err = fmt.Errorf("command %q timed out after %s", name, timeout)
		res.ExitCode = -1
	}
	return res
}

// minimalEnv passes through PATH and platform essentials while dropping
// unrelated secrets from the parent environment.
func minimalEnv() []string {
	keep := []string{
		"PATH", "Path", "PATHEXT", "SystemRoot", "SYSTEMROOT", "WINDIR",
		"TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
		"PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "COMSPEC",
		"GOPATH", "GOCACHE", "GOMODCACHE", "GOTOOLCHAIN",
		"CARGO_HOME", "RUSTUP_HOME", "LANG", "LC_ALL",
	}
	env := make([]string, 0, len(keep))
	for _, key := range keep {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	return env
}

// limitedWriter caps how many bytes are retained from a command stream.
type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	original := len(p)
	if l.remaining <= 0 {
		return original, nil
	}
	if len(p) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.w.Write(p)
	l.remaining -= n
	if err != nil {
		return n, err
	}
	// Report the full length so the child process never sees a short write.
	return original, nil
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// lookPath wraps exec.LookPath for testability.
func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// toolAvailable reports whether an executable can be resolved on PATH.
func toolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// dirExists reports whether path is an existing directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// matchesAny reports whether s equals one of the pipe-separated alternatives.
func matchesAny(s, alternatives string) bool {
	for _, alt := range strings.Split(alternatives, "|") {
		if s == alt {
			return true
		}
	}
	return false
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// findRepoSubdir locates a repository-relative directory (e.g. "python")
// starting from the current working directory and walking upwards.
func findRepoSubdir(rel string) (string, bool) {
	if env := os.Getenv("QORVEX_ROOT"); env != "" {
		cand := filepath.Join(env, rel)
		if dirExists(cand) {
			return cand, true
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, rel)
		if dirExists(cand) {
			return cand, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}
