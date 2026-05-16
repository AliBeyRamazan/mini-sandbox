package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
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

type inspectOptions struct {
	target       string
	reportsDir   string
	stringsLimit int
	maxEntries   int
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

type inspectReport struct {
	RunID       string         `json:"run_id"`
	TargetPath  string         `json:"target_path"`
	TargetName  string         `json:"target_name"`
	IsDirectory bool           `json:"is_directory"`
	Size        int64          `json:"size"`
	FileType    string         `json:"file_type,omitempty"`
	MIME        string         `json:"mime,omitempty"`
	SHA256      string         `json:"sha256,omitempty"`
	SHA1        string         `json:"sha1,omitempty"`
	MagicHex    string         `json:"magic_hex,omitempty"`
	Extension   string         `json:"extension,omitempty"`
	PE          map[string]any `json:"pe,omitempty"`
	ELF         map[string]any `json:"elf,omitempty"`
	Entries     []archiveEntry `json:"entries,omitempty"`
	Strings     []string       `json:"strings,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
	StartedAt   string         `json:"started_at"`
}

type archiveEntry struct {
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	Compressed   int64  `json:"compressed,omitempty"`
	IsDirectory  bool   `json:"is_directory"`
	ModifiedTime string `json:"modified_time,omitempty"`
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
	case "inspect":
		return inspectCommand(args[1:])
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
  mini-sandbox inspect <file-or-directory> [--reports-dir reports] [--strings-limit 80] [--max-entries 200]

Commands:
  build    Build the Docker sandbox image.
  run      Execute a Linux sample in the sandbox and collect logs.
  inspect  Statically inspect PDF, EXE, ZIP, DOCX, folders, and other files without executing them.`)
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

func inspectCommand(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	opts := inspectOptions{}
	fs.StringVar(&opts.reportsDir, "reports-dir", "reports", "Output directory")
	fs.IntVar(&opts.stringsLimit, "strings-limit", 80, "Maximum printable strings to collect")
	fs.IntVar(&opts.maxEntries, "max-entries", 200, "Maximum directory/archive entries to collect")
	if err := fs.Parse(normalizeInspectArgs(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("inspect requires exactly one file or directory path")
	}
	opts.target = fs.Arg(0)
	if opts.stringsLimit < 0 {
		return fmt.Errorf("--strings-limit cannot be negative")
	}
	if opts.maxEntries < 1 {
		return fmt.Errorf("--max-entries must be at least 1")
	}
	return inspectTarget(opts)
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

func normalizeInspectArgs(args []string) []string {
	valueFlags := map[string]bool{
		"-reports-dir":    true,
		"--reports-dir":   true,
		"-strings-limit":  true,
		"--strings-limit": true,
		"-max-entries":    true,
		"--max-entries":   true,
	}

	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name := arg
		if idx := strings.IndexRune(arg, '='); idx >= 0 {
			name = arg[:idx]
		}
		if valueFlags[name] {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
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

func inspectTarget(opts inspectOptions) error {
	target, err := filepath.Abs(opts.target)
	if err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("target not found: %s", target)
	}

	runID := "inspect-" + time.Now().Format("20060102-150405") + "-" + shortID()
	reportsRoot, err := filepath.Abs(opts.reportsDir)
	if err != nil {
		return err
	}
	reportDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return err
	}

	report := inspectReport{
		RunID:       runID,
		TargetPath:  target,
		TargetName:  filepath.Base(target),
		IsDirectory: info.IsDir(),
		Size:        info.Size(),
		Extension:   strings.ToLower(filepath.Ext(target)),
		StartedAt:   time.Now().Format(time.RFC3339),
		Notes:       []string{"Static inspection only. Target was not executed."},
	}

	if info.IsDir() {
		report.FileType = "directory"
		report.Entries = inspectDirectory(target, opts.maxEntries)
	} else {
		if err := inspectFile(target, opts, &report); err != nil {
			return err
		}
	}

	if err := writeJSON(filepath.Join(reportDir, "inspect.json"), report); err != nil {
		return err
	}
	printInspectSummary(report, reportDir)
	return nil
}

func inspectFile(path string, opts inspectOptions, report *inspectReport) error {
	head, err := readHead(path, 512)
	if err != nil {
		return err
	}

	report.SHA256 = mustDigest(path, sha256.New())
	report.SHA1 = mustDigest(path, sha1.New())
	report.MagicHex = hex.EncodeToString(head[:min(len(head), 16)])
	report.MIME = http.DetectContentType(head)
	report.FileType = detectFileType(head, report.Extension)
	report.Strings = extractPrintableStrings(path, opts.stringsLimit)

	switch report.FileType {
	case "windows-pe":
		report.PE = inspectPE(path)
	case "linux-elf":
		report.ELF = inspectELF(path)
	case "zip", "docx", "xlsx", "pptx", "jar":
		report.Entries = inspectZip(path, opts.maxEntries)
	case "pdf":
		report.Notes = append(report.Notes, "PDF was not opened with a viewer. Use strings and metadata for first-pass analysis.")
	}
	return nil
}

func readHead(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := make([]byte, limit)
	n, err := file.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

func detectFileType(head []byte, ext string) string {
	switch {
	case len(head) >= 4 && string(head[:4]) == "%PDF":
		return "pdf"
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return "windows-pe"
	case len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		return "linux-elf"
	case len(head) >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 0x03 && head[3] == 0x04:
		return zipTypeFromExt(ext)
	}
	if ext != "" {
		return strings.TrimPrefix(ext, ".")
	}
	return "unknown"
}

func zipTypeFromExt(ext string) string {
	switch ext {
	case ".docx":
		return "docx"
	case ".xlsx":
		return "xlsx"
	case ".pptx":
		return "pptx"
	case ".jar":
		return "jar"
	default:
		return "zip"
	}
}

func inspectPE(path string) map[string]any {
	file, err := pe.Open(path)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer file.Close()

	sections := make([]string, 0, len(file.Sections))
	for _, section := range file.Sections {
		sections = append(sections, section.Name)
	}
	return map[string]any{
		"machine":             fmt.Sprintf("0x%x", file.FileHeader.Machine),
		"number_of_sections":  file.FileHeader.NumberOfSections,
		"time_date_stamp":     file.FileHeader.TimeDateStamp,
		"characteristics":     fmt.Sprintf("0x%x", file.FileHeader.Characteristics),
		"section_names":       sections,
		"imported_libraries":  importedLibraries(file),
		"has_import_metadata": len(importedLibraries(file)) > 0,
	}
}

func importedLibraries(file *pe.File) []string {
	libs, err := file.ImportedLibraries()
	if err != nil {
		return nil
	}
	sort.Strings(libs)
	return libs
}

func inspectELF(path string) map[string]any {
	file, err := elf.Open(path)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer file.Close()

	sections := make([]string, 0, len(file.Sections))
	for _, section := range file.Sections {
		sections = append(sections, section.Name)
	}
	if len(sections) > 40 {
		sections = sections[:40]
	}
	return map[string]any{
		"class":         file.Class.String(),
		"data":          file.Data.String(),
		"osabi":         file.OSABI.String(),
		"type":          file.Type.String(),
		"machine":       file.Machine.String(),
		"entry":         fmt.Sprintf("0x%x", file.Entry),
		"section_names": sections,
	}
}

func inspectZip(path string, maxEntries int) []archiveEntry {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return []archiveEntry{{Path: "zip error: " + err.Error()}}
	}
	defer reader.Close()

	entries := make([]archiveEntry, 0, min(len(reader.File), maxEntries))
	for i, file := range reader.File {
		if i >= maxEntries {
			break
		}
		entries = append(entries, archiveEntry{
			Path:         file.Name,
			Size:         int64(file.UncompressedSize64),
			Compressed:   int64(file.CompressedSize64),
			IsDirectory:  file.FileInfo().IsDir(),
			ModifiedTime: file.Modified.Format(time.RFC3339),
		})
	}
	return entries
}

func inspectDirectory(path string, maxEntries int) []archiveEntry {
	entries := []archiveEntry{}
	_ = filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil || current == path {
			return nil
		}
		if len(entries) >= maxEntries {
			return filepath.SkipAll
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(path, current)
		if relErr != nil {
			rel = current
		}
		entries = append(entries, archiveEntry{
			Path:         filepath.ToSlash(rel),
			Size:         info.Size(),
			IsDirectory:  entry.IsDir(),
			ModifiedTime: info.ModTime().Format(time.RFC3339),
		})
		return nil
	})
	return entries
}

func extractPrintableStrings(path string, limit int) []string {
	if limit == 0 {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	const maxBytes = 2 * 1024 * 1024
	reader := io.LimitReader(file, maxBytes)
	var values []string
	var current strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buf)
		for _, b := range buf[:n] {
			if b >= 32 && b <= 126 {
				current.WriteByte(b)
				continue
			}
			values = flushString(values, &current, limit)
			if len(values) >= limit {
				return values
			}
		}
		if readErr != nil {
			break
		}
	}
	values = flushString(values, &current, limit)
	return values
}

func flushString(values []string, current *strings.Builder, limit int) []string {
	if current.Len() >= 4 {
		values = appendUnique(values, current.String(), limit)
	}
	current.Reset()
	return values
}

func printInspectSummary(report inspectReport, reportDir string) {
	fmt.Println("Inspect summary")
	fmt.Printf("- Target: %s\n", report.TargetPath)
	fmt.Printf("- Type: %s\n", report.FileType)
	fmt.Printf("- Size: %d bytes\n", report.Size)
	if report.SHA256 != "" {
		fmt.Printf("- SHA256: %s\n", report.SHA256)
	}
	if len(report.Entries) > 0 {
		fmt.Printf("- Entries captured: %d\n", len(report.Entries))
	}
	if len(report.Strings) > 0 {
		fmt.Printf("- Strings captured: %d\n", len(report.Strings))
	}
	fmt.Printf("\nFull report: %s\n", filepath.Join(reportDir, "inspect.json"))
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
