package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultImageName = "mini-linux-sandbox:latest"
)

type runOptions struct {
	sample        string
	tag           string
	timeout       int
	reportsDir    string
	network       bool
	keepContainer bool
}

type metadata struct {
	RunID          string `json:"run_id"`
	SamplePath     string `json:"sample_path"`
	SampleName     string `json:"sample_name"`
	SampleSize     int64  `json:"sample_size"`
	SHA256         string `json:"sha256"`
	SHA1           string `json:"sha1"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	NetworkEnabled bool   `json:"network_enabled"`
	Image          string `json:"image"`
	StartedAt      string `json:"started_at"`
}

type syscallCount struct {
	Syscall string `json:"syscall"`
	Count   int    `json:"count"`
}

type indicators struct {
	FilePaths    []string `json:"file_paths"`
	NetworkCalls []string `json:"network_calls"`
	ProcessCalls []string `json:"process_calls"`
	Errors       []string `json:"errors"`
}

type summary struct {
	DockerExitCode int            `json:"docker_exit_code"`
	SampleExitCode any            `json:"sample_exit_code"`
	ElapsedSeconds float64        `json:"elapsed_seconds"`
	TopSyscalls    []syscallCount `json:"top_syscalls"`
	Indicators     indicators     `json:"indicators"`
	Logs           []string       `json:"logs"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errExit(2)
	}

	switch args[0] {
	case "build":
		return buildCommand(args[1:])
	case "run":
		return runCommand(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Println(`mini-sandbox - Docker based Linux malware sandbox prototype

Usage:
  mini-sandbox build [--tag mini-linux-sandbox:latest]
  mini-sandbox run <sample> [--tag mini-linux-sandbox:latest] [--timeout 15] [--reports-dir reports] [--network] [--keep-container]

Commands:
  build    Build the Docker sandbox image.
  run      Execute a Linux sample in the sandbox and collect logs.`)
}

func buildCommand(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	tag := fs.String("tag", defaultImageName, "Docker image tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("build does not accept positional arguments")
	}
	if err := ensureDocker(); err != nil {
		return err
	}

	root, err := projectRoot()
	if err != nil {
		return err
	}
	dockerfile := filepath.Join(root, "Dockerfile")
	if _, err := os.Stat(dockerfile); err != nil {
		return fmt.Errorf("Dockerfile not found at %s: %w", dockerfile, err)
	}

	cmd := exec.Command("docker", "build", "-t", *tag, root)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	opts := runOptions{}
	fs.StringVar(&opts.tag, "tag", defaultImageName, "Docker image tag")
	fs.IntVar(&opts.timeout, "timeout", 15, "Execution timeout in seconds")
	fs.StringVar(&opts.reportsDir, "reports-dir", "reports", "Output directory")
	fs.BoolVar(&opts.network, "network", false, "Enable container networking")
	fs.BoolVar(&opts.keepContainer, "keep-container", false, "Do not auto-remove the container")
	if err := fs.Parse(normalizeRunArgs(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("run requires exactly one sample path")
	}
	opts.sample = fs.Arg(0)
	if opts.timeout < 1 {
		return fmt.Errorf("--timeout must be at least 1 second")
	}
	return runSample(opts)
}

func normalizeRunArgs(args []string) []string {
	boolFlags := map[string]bool{
		"-network":         true,
		"--network":        true,
		"-keep-container":  true,
		"--keep-container": true,
	}
	valueFlags := map[string]bool{
		"-tag":          true,
		"--tag":         true,
		"-timeout":      true,
		"--timeout":     true,
		"-reports-dir":  true,
		"--reports-dir": true,
	}

	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name := arg
		if idx := strings.IndexRune(arg, '='); idx >= 0 {
			name = arg[:idx]
		}
		switch {
		case boolFlags[name]:
			flags = append(flags, arg)
		case valueFlags[name]:
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func runSample(opts runOptions) error {
	if err := ensureDocker(); err != nil {
		return err
	}

	sample, err := filepath.Abs(opts.sample)
	if err != nil {
		return err
	}
	info, err := os.Stat(sample)
	if err != nil {
		return fmt.Errorf("sample file not found: %s", sample)
	}
	if info.IsDir() {
		return fmt.Errorf("sample path is a directory: %s", sample)
	}

	runID := time.Now().Format("20060102-150405") + "-" + shortID()
	reportsRoot, err := filepath.Abs(opts.reportsDir)
	if err != nil {
		return err
	}
	reportDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return err
	}

	meta := metadata{
		RunID:          runID,
		SamplePath:     sample,
		SampleName:     filepath.Base(sample),
		SampleSize:     info.Size(),
		SHA256:         mustDigest(sample, sha256.New()),
		SHA1:           mustDigest(sample, sha1.New()),
		TimeoutSeconds: opts.timeout,
		NetworkEnabled: opts.network,
		Image:          opts.tag,
		StartedAt:      time.Now().Format(time.RFC3339),
	}
	if err := writeJSON(filepath.Join(reportDir, "metadata.json"), meta); err != nil {
		return err
	}

	containerName := "mini-sandbox-" + runID
	dockerArgs := []string{
		"run",
		"--name", containerName,
		"--cpus", "1",
		"--memory", "512m",
		"--pids-limit", "256",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"-e", fmt.Sprintf("SANDBOX_TIMEOUT=%d", opts.timeout),
		"-v", fmt.Sprintf("%s:/sample/input:ro", sample),
		"-v", fmt.Sprintf("%s:/out:rw", reportDir),
	}
	if !opts.keepContainer {
		dockerArgs = append(dockerArgs, "--rm")
	}
	if !opts.network {
		dockerArgs = append(dockerArgs, "--network", "none")
	}
	dockerArgs = append(dockerArgs, opts.tag)

	fmt.Printf("Run ID: %s\n", runID)
	fmt.Printf("Report: %s\n", reportDir)

	started := time.Now()
	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	dockerStatus := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			dockerStatus = exitErr.ExitCode()
		} else {
			return err
		}
	}

	sum := summarize(reportDir, dockerStatus, time.Since(started).Seconds())
	if err := writeJSON(filepath.Join(reportDir, "summary.json"), sum); err != nil {
		return err
	}
	printSummary(sum, reportDir)
	if dockerStatus != 0 {
		return errExit(dockerStatus)
	}
	return nil
}

func summarize(reportDir string, dockerStatus int, elapsed float64) summary {
	stracePath := filepath.Join(reportDir, "strace.log")
	stderrPath := filepath.Join(reportDir, "stderr.log")
	exitCodePath := filepath.Join(reportDir, "exit_code")

	return summary{
		DockerExitCode: dockerStatus,
		SampleExitCode: readSampleExitCode(exitCodePath),
		ElapsedSeconds: round(elapsed, 3),
		TopSyscalls:    extractSyscalls(stracePath),
		Indicators:     extractIndicators(stracePath, stderrPath),
		Logs:           listReportFiles(reportDir),
	}
}

func extractSyscalls(path string) []syscallCount {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	callPattern := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\(`)
	counts := map[string]int{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := callPattern.FindStringSubmatch(scanner.Text())
		if len(match) == 2 {
			counts[match[1]]++
		}
	}

	items := make([]syscallCount, 0, len(counts))
	for name, count := range counts {
		items = append(items, syscallCount{Syscall: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Syscall < items[j].Syscall
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > 20 {
		return items[:20]
	}
	return items
}

func extractIndicators(stracePath, stderrPath string) indicators {
	out := indicators{
		FilePaths:    []string{},
		NetworkCalls: []string{},
		ProcessCalls: []string{},
		Errors:       []string{},
	}

	readLines(stracePath, func(line string) {
		if containsAny(line, "connect(", "socket(", "sendto(", "recvfrom(") {
			out.NetworkCalls = appendUnique(out.NetworkCalls, line, 25)
		}
		if containsAny(line, "execve(", "clone(", "fork(", "vfork(") {
			out.ProcessCalls = appendUnique(out.ProcessCalls, line, 25)
		}
		if containsAny(line, "openat(", "stat(", "access(") {
			out.FilePaths = appendUnique(out.FilePaths, line, 25)
		}
	})

	readLines(stderrPath, func(line string) {
		if strings.TrimSpace(line) != "" {
			out.Errors = appendUnique(out.Errors, line, 10)
		}
	})
	return out
}

func readLines(path string, fn func(string)) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fn(scanner.Text())
	}
}

func appendUnique(values []string, value string, limit int) []string {
	value = strings.TrimSpace(value)
	if value == "" || len(values) >= limit {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func readSampleExitCode(path string) any {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return nil
	}
	var code int
	if _, err := fmt.Sscanf(value, "%d", &code); err == nil {
		return code
	}
	return value
}

func listReportFiles(reportDir string) []string {
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return nil
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	return files
}

func printSummary(sum summary, reportDir string) {
	fmt.Println("\nSummary")
	fmt.Printf("- Docker exit code: %d\n", sum.DockerExitCode)
	fmt.Printf("- Sample exit code: %v\n", sum.SampleExitCode)
	fmt.Printf("- Elapsed seconds: %.3f\n", sum.ElapsedSeconds)
	fmt.Println("- Top syscalls:")
	for i, item := range sum.TopSyscalls {
		if i >= 8 {
			break
		}
		fmt.Printf("  %s: %d\n", item.Syscall, item.Count)
	}
	fmt.Printf("\nFull logs: %s\n", reportDir)
}

func ensureDocker() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("Docker CLI is required but was not found in PATH")
	}
	return nil
}

func projectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "Dockerfile")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("could not find project root containing Dockerfile")
		}
		wd = parent
	}
}

func mustDigest(path string, hasher hash.Hash) string {
	digest, err := fileDigest(path, hasher)
	if err != nil {
		panic(err)
	}
	return digest
}

func fileDigest(path string, hasher hash.Hash) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeJSON(path string, payload any) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func shortID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%08x", uint32(now^(now>>32)))
}

func round(value float64, places int) float64 {
	scale := 1.0
	for i := 0; i < places; i++ {
		scale *= 10
	}
	return float64(int(value*scale+0.5)) / scale
}

type cliError struct {
	code int
}

func (e cliError) Error() string {
	return fmt.Sprintf("exit status %d", e.code)
}

func errExit(code int) error {
	return cliError{code: code}
}

func exitCode(err error) int {
	var cliErr cliError
	if errors.As(err, &cliErr) {
		return cliErr.code
	}
	return 1
}
