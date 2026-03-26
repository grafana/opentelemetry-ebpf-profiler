package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

const (
	otelPrefix  = "go.opentelemetry.io/"
	alloyModule = "github.com/grafana/alloy"
)

var skippedDeps = map[string]struct{}{
	"go.opentelemetry.io/proto/otlp":                        {},
	"go.opentelemetry.io/proto/otlp/profiles/v1development": {},
}

var scriptOutputBuf strings.Builder

func shouldSkipDep(dep string) bool {
	_, ok := skippedDeps[dep]
	return ok
}

// logf writes to both stdout and the script output buffer (used for PR body).
func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Print(msg)
	scriptOutputBuf.WriteString(msg)
}

// logln writes to both stdout and the script output buffer (used for PR body).
func logln(args ...any) {
	msg := fmt.Sprintln(args...)
	fmt.Print(msg)
	scriptOutputBuf.WriteString(msg)
}

type goModDownloadResult struct {
	Dir     string `json:"Dir"`
	Version string `json:"Version"`
	Error   string `json:"Error"`
	Origin  struct {
		Hash string `json:"Hash"`
	} `json:"Origin"`
}

func run(repoRoot string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = repoRoot

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf(
			"%s %s failed: %w\nstdout:\n%s\nstderr:\n%s",
			name,
			strings.Join(args, " "),
			err,
			stdout.String(),
			stderr.String(),
		)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// runPassthrough runs a command with stdout/stderr connected to the terminal.
func runPassthrough(repoRoot string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// runExitCode runs a command and returns its exit code without treating non-zero as an error.
func runExitCode(repoRoot string, name string, args ...string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
}

func readModFile(path string) (*modfile.File, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	parsed, err := modfile.Parse(path, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return parsed, nil
}

func otelRequirements(parsed *modfile.File) map[string]string {
	reqs := make(map[string]string)
	for _, req := range parsed.Require {
		if strings.HasPrefix(req.Mod.Path, otelPrefix) {
			reqs[req.Mod.Path] = req.Mod.Version
		}
	}
	return reqs
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func downloadAlloy(repoRoot string, revision string) (dir string, resolvedVersion string, resolvedHash string, err error) {
	out, err := run(repoRoot, "go", "mod", "download", "-json", alloyModule+"@"+revision)
	if err != nil {
		return "", "", "", err
	}

	var result goModDownloadResult
	if unmarshalErr := json.Unmarshal([]byte(out), &result); unmarshalErr != nil {
		return "", "", "", fmt.Errorf("decode go mod download output: %w\nraw output:\n%s", unmarshalErr, out)
	}
	if result.Error != "" {
		return "", "", "", errors.New(result.Error)
	}
	if result.Dir == "" {
		return "", "", "", fmt.Errorf("go mod download did not return Dir for %s", revision)
	}
	if result.Version == "" {
		result.Version = revision
	}
	return result.Dir, result.Version, result.Origin.Hash, nil
}

func applyAlloyVersions(repoRoot string, profilerDeps map[string]string, alloyDeps map[string]string) error {
	for _, dep := range sortedKeys(profilerDeps) {
		currentVersion := profilerDeps[dep]
		if shouldSkipDep(dep) {
			logf("  - %s: %s => %s (skipping dependency)\n", dep, currentVersion, currentVersion)
			continue
		}

		alloyVersion, ok := alloyDeps[dep]
		if !ok {
			return fmt.Errorf("dependency %s was not found in alloy", dep)
		}
		logf("  - %s: %s => %s\n", dep, currentVersion, alloyVersion)
		if _, err := run(repoRoot, "go", "mod", "edit", "-require="+dep+"@"+alloyVersion); err != nil {
			return err
		}
	}
	return nil
}

func verifyAligned(profilePath string, profilerDeps map[string]string, alloyDeps map[string]string) error {
	finalMod, err := readModFile(profilePath)
	if err != nil {
		return err
	}
	finalDeps := otelRequirements(finalMod)

	for _, dep := range sortedKeys(profilerDeps) {
		if shouldSkipDep(dep) {
			finalVersion, ok := finalDeps[dep]
			if !ok {
				return fmt.Errorf("%s disappeared after go mod tidy", dep)
			}
			logf("  - %s: %s => %s (skipping verification)\n", dep, finalVersion, finalVersion)
			continue
		}

		expected, ok := alloyDeps[dep]
		if !ok {
			return fmt.Errorf("no expected alloy version found for %s", dep)
		}

		finalVersion, ok := finalDeps[dep]
		if !ok {
			return fmt.Errorf("%s disappeared after go mod tidy (expected %s)", dep, expected)
		}
		if finalVersion != expected {
			return fmt.Errorf("%s is %s after go mod tidy, expected %s", dep, finalVersion, expected)
		}
		logf("  - %s: %s => %s (verified)\n", dep, expected, finalVersion)
	}
	return nil
}

// sanitizeRevision makes a revision string safe for use in branch names.
func sanitizeRevision(rev string) string {
	replacer := strings.NewReplacer("/", "-", ":", "-", "@", "-", " ", "-")
	safe := replacer.Replace(rev)

	var buf strings.Builder
	for _, r := range safe {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			buf.WriteRune(r)
		}
	}
	result := buf.String()
	if result == "" {
		return "revision"
	}
	return result
}

func composePRBody(revision string, scriptOutput string) string {
	if scriptOutput == "" {
		scriptOutput = "(no output captured)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Sync all `go.opentelemetry.io/*` dependencies in `go.mod` to versions from the specified Alloy revision.\n\n")
	fmt.Fprintf(&b, "- Source revision: `%s`\n", revision)
	fmt.Fprintf(&b, "- Script: `tools/denovate-opentelemetry-from-alloy.go`\n")
	fmt.Fprintf(&b, "- Includes `go mod tidy` and strict post-tidy version verification\n\n")
	fmt.Fprintf(&b, "### Script output\n")
	fmt.Fprintf(&b, "```text\n%s\n```\n\n", scriptOutput)
	fmt.Fprintf(&b, "If CI workflows do not start automatically on this PR, close and reopen the PR to retrigger `pull_request` workflows.\n")
	return b.String()
}

func main() {
	dryRun := flag.Bool("dry-run", false, "show git diff without committing, pushing, or creating a PR")
	baseBranch := flag.String("base-branch", "pyroscope_alloy", "base branch for the PR")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] [alloy-revision]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Syncs go.opentelemetry.io/* dependencies to match a given Alloy revision.\n")
		fmt.Fprintf(os.Stderr, "Set GOTOOLCHAIN=auto if Alloy requires a newer Go version.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	alloyRevision := "main"
	usedDefaultRevision := true
	if flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] [alloy-revision]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	if flag.NArg() == 1 {
		alloyRevision = strings.TrimSpace(flag.Arg(0))
		if alloyRevision == "" {
			alloyRevision = "main"
		} else {
			usedDefaultRevision = false
		}
	}
	if usedDefaultRevision {
		logln("No alloy revision provided; defaulting to latest main.")
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get cwd: %v\n", err)
		os.Exit(1)
	}
	goModPath := filepath.Join(repoRoot, "go.mod")

	profilerMod, err := readModFile(goModPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read profiler go.mod: %v\n", err)
		os.Exit(1)
	}
	profilerDeps := otelRequirements(profilerMod)
	if len(profilerDeps) == 0 {
		logln("No go.opentelemetry.io/* dependencies found; nothing to do.")
		return
	}

	logln("Downloading grafana/alloy with go mod...")
	alloyDir, resolvedRevision, resolvedHash, err := downloadAlloy(repoRoot, alloyRevision)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to download alloy module: %v\n", err)
		os.Exit(1)
	}
	if usedDefaultRevision {
		if strings.TrimSpace(resolvedHash) == "" {
			logln("No alloy revision provided; resolved to main (commit hash unavailable).")
		} else {
			logf("No alloy revision provided; resolved main to commit %s.\n", resolvedHash)
		}
	}

	alloyGoModPath := filepath.Join(alloyDir, "go.mod")
	alloyMod, err := readModFile(alloyGoModPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read alloy go.mod: %v\n", err)
		os.Exit(1)
	}
	alloyDeps := otelRequirements(alloyMod)

	logf("Collecting go.opentelemetry.io/* dependency versions from alloy go.mod (%s)...\n", resolvedRevision)
	logln("Applying alloy versions to profiler go.opentelemetry.io/* dependencies...")
	if err := applyAlloyVersions(repoRoot, profilerDeps, alloyDeps); err != nil {
		fmt.Fprintf(os.Stderr, "failed to apply alloy versions: %v\n", err)
		os.Exit(1)
	}

	logln("Running go mod tidy...")
	if _, err := run(repoRoot, "go", "mod", "tidy"); err != nil {
		fmt.Fprintf(os.Stderr, "go mod tidy failed: %v\n", err)
		os.Exit(1)
	}

	logln("Verifying resulting versions...")
	if err := verifyAligned(goModPath, profilerDeps, alloyDeps); err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		os.Exit(1)
	}

	logf("Success: all go.opentelemetry.io/* dependencies match alloy revision %s.\n", alloyRevision)

	// --- Post-sync workflow: check changes, build, commit, push, create PR ---

	fmt.Println("\nChecking for changes...")
	exitCode, err := runExitCode(repoRoot, "git", "diff", "--quiet")
	if err != nil {
		fmt.Fprintf(os.Stderr, "git diff failed: %v\n", err)
		os.Exit(1)
	}
	if exitCode == 0 {
		fmt.Println("No dependency changes detected; nothing to do.")
		return
	}
	fmt.Println("Changes detected in go.mod/go.sum.")

	if *dryRun {
		fmt.Println("\n--- Dry-run mode: showing git diff ---")
		_ = runPassthrough(repoRoot, "git", "diff")
		fmt.Println("\nDry-run complete. No commits, pushes, or PRs were created.")
		return
	}

	fmt.Println("\nVerifying build...")
	if err := runPassthrough(repoRoot, "go", "build", "."); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Build succeeded.")

	// Determine branch name.
	safeRevision := sanitizeRevision(alloyRevision)
	uniqueSuffix := os.Getenv("GITHUB_RUN_ID")
	if uniqueSuffix == "" {
		uniqueSuffix = fmt.Sprintf("%d", time.Now().Unix())
	}
	branchName := fmt.Sprintf("automation/denovate-otel-%s-%s", safeRevision, uniqueSuffix)

	// Configure git identity.
	fmt.Println("\nConfiguring git...")
	if _, err := run(repoRoot, "git", "config", "user.name", "github-actions[bot]"); err != nil {
		fmt.Fprintf(os.Stderr, "git config user.name failed: %v\n", err)
		os.Exit(1)
	}
	if _, err := run(repoRoot, "git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"); err != nil {
		fmt.Fprintf(os.Stderr, "git config user.email failed: %v\n", err)
		os.Exit(1)
	}

	// Create branch, stage, commit, push.
	fmt.Printf("Creating branch %s...\n", branchName)
	if _, err := run(repoRoot, "git", "checkout", "-b", branchName); err != nil {
		fmt.Fprintf(os.Stderr, "git checkout -b failed: %v\n", err)
		os.Exit(1)
	}
	if _, err := run(repoRoot, "git", "add", "go.mod", "go.sum"); err != nil {
		fmt.Fprintf(os.Stderr, "git add failed: %v\n", err)
		os.Exit(1)
	}
	commitMsg := fmt.Sprintf("chore: denovate opentelemetry deps from alloy %s", alloyRevision)
	if _, err := run(repoRoot, "git", "commit", "-m", commitMsg); err != nil {
		fmt.Fprintf(os.Stderr, "git commit failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Pushing branch...")
	if _, err := run(repoRoot, "git", "push", "origin", branchName); err != nil {
		fmt.Fprintf(os.Stderr, "git push failed: %v\n", err)
		os.Exit(1)
	}

	// Create pull request.
	fmt.Println("Creating pull request...")
	prTitle := fmt.Sprintf("chore: denovate OpenTelemetry deps from alloy %s", alloyRevision)
	prBody := composePRBody(alloyRevision, scriptOutputBuf.String())
	if err := runPassthrough(repoRoot, "gh", "pr", "create",
		"--base", *baseBranch,
		"--head", branchName,
		"--title", prTitle,
		"--body", prBody,
	); err != nil {
		fmt.Fprintf(os.Stderr, "gh pr create failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Done.")
}
