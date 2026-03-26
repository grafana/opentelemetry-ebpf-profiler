package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

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

func shouldSkipDep(dep string) bool {
	_, ok := skippedDeps[dep]
	return ok
}

type goModDownloadResult struct {
	Dir     string `json:"Dir"`
	Version string `json:"Version"`
	Error   string `json:"Error"`
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

func downloadAlloy(repoRoot string, revision string) (dir string, resolvedVersion string, err error) {
	out, err := run(repoRoot, "go", "mod", "download", "-json", alloyModule+"@"+revision)
	if err != nil {
		return "", "", err
	}

	var result goModDownloadResult
	if unmarshalErr := json.Unmarshal([]byte(out), &result); unmarshalErr != nil {
		return "", "", fmt.Errorf("decode go mod download output: %w\nraw output:\n%s", unmarshalErr, out)
	}
	if result.Error != "" {
		return "", "", errors.New(result.Error)
	}
	if result.Dir == "" {
		return "", "", fmt.Errorf("go mod download did not return Dir for %s", revision)
	}
	if result.Version == "" {
		result.Version = revision
	}
	return result.Dir, result.Version, nil
}

func applyAlloyVersions(repoRoot string, profilerDeps map[string]string, alloyDeps map[string]string) error {
	for _, dep := range sortedKeys(profilerDeps) {
		currentVersion := profilerDeps[dep]
		if shouldSkipDep(dep) {
			fmt.Printf("  - %s: %s => %s (skipping dependency)\n", dep, currentVersion, currentVersion)
			continue
		}

		alloyVersion, ok := alloyDeps[dep]
		if !ok {
			return fmt.Errorf("dependency %s was not found in alloy", dep)
		}
		fmt.Printf("  - %s: %s => %s\n", dep, currentVersion, alloyVersion)
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
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <alloy-revision>\n", os.Args[0])
		os.Exit(1)
	}
	alloyRevision := os.Args[1]

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
		fmt.Println("No go.opentelemetry.io/* dependencies found; nothing to do.")
		return
	}

	fmt.Println("Downloading grafana/alloy with go mod...")
	alloyDir, resolvedRevision, err := downloadAlloy(repoRoot, alloyRevision)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to download alloy module: %v\n", err)
		os.Exit(1)
	}

	alloyGoModPath := filepath.Join(alloyDir, "go.mod")
	alloyMod, err := readModFile(alloyGoModPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read alloy go.mod: %v\n", err)
		os.Exit(1)
	}
	alloyDeps := otelRequirements(alloyMod)

	fmt.Printf("Collecting go.opentelemetry.io/* dependency versions from alloy go.mod (%s)...\n", resolvedRevision)
	fmt.Println("Applying alloy versions to profiler go.opentelemetry.io/* dependencies...")
	if err := applyAlloyVersions(repoRoot, profilerDeps, alloyDeps); err != nil {
		fmt.Fprintf(os.Stderr, "failed to apply alloy versions: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Running go mod tidy...")
	if _, err := run(repoRoot, "go", "mod", "tidy"); err != nil {
		fmt.Fprintf(os.Stderr, "go mod tidy failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Verifying resulting versions...")
	if err := verifyAligned(goModPath, profilerDeps, alloyDeps); err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Success: all go.opentelemetry.io/* dependencies match alloy revision %s.\n", alloyRevision)
}
