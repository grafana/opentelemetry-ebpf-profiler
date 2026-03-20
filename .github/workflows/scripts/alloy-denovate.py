#!/usr/bin/env python3
"""
Denovate OpenTelemetry dependencies in opentelemetry-ebpf-profiler
to match the versions used by a specific Grafana Alloy revision.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

OTEL_PREFIX = "go.opentelemetry.io/"
ALLOY_REPO = "https://github.com/grafana/alloy.git"
MODULE_LINE = "go.opentelemetry.io/ebpf-profiler"

# Regex to match a dependency line inside a require block:
#   go.opentelemetry.io/otel v1.42.0
#   go.opentelemetry.io/otel v1.42.0 // indirect
DEP_RE = re.compile(r"^\s+(go\.opentelemetry\.io/\S+)\s+(v\S+)")


def parse_otel_deps(gomod_path: str) -> dict[str, str]:
    """Parse go.mod and return {module: version} for all go.opentelemetry.io/* deps."""
    deps: dict[str, str] = {}
    in_require = False
    in_replace = False

    with open(gomod_path) as f:
        for line in f:
            stripped = line.strip()

            # Track replace blocks to skip them
            if stripped.startswith("replace ("):
                in_replace = True
                continue
            if stripped.startswith("replace ") and "(" not in stripped:
                # single-line replace, skip
                continue
            if in_replace:
                if stripped == ")":
                    in_replace = False
                continue

            # Track require blocks
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue

            if not in_require:
                continue

            m = DEP_RE.match(line)
            if m:
                module, version = m.group(1), m.group(2)
                # Skip the module declaration itself
                if module == MODULE_LINE:
                    continue
                deps[module] = version

    return deps


def clone_alloy(revision: str, dest: str) -> None:
    """Clone grafana/alloy at a specific revision into dest."""
    print(f"Cloning grafana/alloy at revision {revision}...")
    subprocess.run(["git", "init", dest], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", dest, "remote", "add", "origin", ALLOY_REPO],
        check=True,
        capture_output=True,
    )
    # Try shallow fetch first (works for branches, tags, and full SHAs).
    # Falls back to a partial clone for short SHAs or other refs.
    fetch = subprocess.run(
        ["git", "-C", dest, "fetch", "--depth", "1", "origin", revision],
        capture_output=True,
        text=True,
    )
    if fetch.returncode != 0:
        print(f"Shallow fetch failed, falling back to partial clone...")
        # Use a blobless clone (fast, fetches trees but not file contents until checkout)
        import shutil

        shutil.rmtree(dest)
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", ALLOY_REPO, dest],
            check=True,
        )
        subprocess.run(
            ["git", "-C", dest, "checkout", revision],
            check=True,
            capture_output=True,
        )
    else:
        subprocess.run(
            ["git", "-C", dest, "checkout", "FETCH_HEAD"],
            check=True,
            capture_output=True,
        )
    print("Alloy cloned successfully.")


def run_go_mod_edit(profiler_dir: str, module: str, version: str) -> None:
    """Run go mod edit -require=module@version."""
    subprocess.run(
        ["go", "mod", "edit", f"-require={module}@{version}"],
        check=True,
        cwd=profiler_dir,
    )


def run_go_mod_tidy(profiler_dir: str) -> None:
    """Run go mod tidy."""
    print("Running go mod tidy...")
    subprocess.run(["go", "mod", "tidy"], check=True, cwd=profiler_dir)
    print("go mod tidy completed.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Denovate OpenTelemetry deps in ebpf-profiler to match Alloy"
    )
    parser.add_argument("alloy_revision", help="Alloy git revision (SHA, tag, or branch)")
    args = parser.parse_args()

    # Determine profiler directory (script lives in .github/workflows/scripts/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profiler_dir = os.path.normpath(os.path.join(script_dir, "..", "..", ".."))
    gomod_path = os.path.join(profiler_dir, "go.mod")

    if not os.path.isfile(gomod_path):
        print(f"ERROR: go.mod not found at {gomod_path}", file=sys.stderr)
        sys.exit(1)

    # Step 1: Clone alloy at the specified revision
    with tempfile.TemporaryDirectory(prefix="alloy-denovate-") as tmpdir:
        alloy_dir = os.path.join(tmpdir, "alloy")
        clone_alloy(args.alloy_revision, alloy_dir)

        alloy_gomod = os.path.join(alloy_dir, "go.mod")
        if not os.path.isfile(alloy_gomod):
            print(f"ERROR: go.mod not found in alloy clone at {alloy_gomod}", file=sys.stderr)
            sys.exit(1)

        # Step 2: Parse alloy's otel deps
        alloy_deps = parse_otel_deps(alloy_gomod)
        print(f"Found {len(alloy_deps)} go.opentelemetry.io/* deps in Alloy.")

        # Step 3: Parse ebpf-profiler's otel deps
        profiler_deps = parse_otel_deps(gomod_path)
        print(f"Found {len(profiler_deps)} go.opentelemetry.io/* deps in ebpf-profiler.")

        # Step 4: For each profiler dep, find the version in alloy
        missing = []
        updates: list[tuple[str, str, str]] = []  # (module, old_version, new_version)
        for module, current_version in sorted(profiler_deps.items()):
            if module not in alloy_deps:
                missing.append(module)
                continue
            alloy_version = alloy_deps[module]
            updates.append((module, current_version, alloy_version))

        if missing:
            print("\nERROR: The following deps are in ebpf-profiler but NOT in Alloy:", file=sys.stderr)
            for m in missing:
                print(f"  - {m} {profiler_deps[m]}", file=sys.stderr)
            sys.exit(1)

        # Step 5: Apply version changes
        print("\nApplying version changes:")
        for module, old_ver, new_ver in updates:
            marker = " (unchanged)" if old_ver == new_ver else ""
            print(f"  {module}: {old_ver} -> {new_ver}{marker}")
            run_go_mod_edit(profiler_dir, module, new_ver)

    # Step 6: Run go mod tidy (outside the tempdir context so alloy clone is cleaned up)
    run_go_mod_tidy(profiler_dir)

    # Step 7: Verify deps haven't drifted after go mod tidy
    print("\nVerifying deps after go mod tidy...")
    final_deps = parse_otel_deps(gomod_path)

    drifted = []
    for module, _old_ver, expected_ver in updates:
        actual_ver = final_deps.get(module)
        if actual_ver is None:
            # Dep was removed by go mod tidy — that's acceptable
            print(f"  {module}: removed by go mod tidy (was {expected_ver})")
            continue
        if actual_ver != expected_ver:
            drifted.append((module, expected_ver, actual_ver))

    if drifted:
        print("\nERROR: The following deps drifted after go mod tidy:", file=sys.stderr)
        for module, expected, actual in drifted:
            print(f"  {module}: expected {expected}, got {actual}", file=sys.stderr)
        sys.exit(1)

    print("\nAll go.opentelemetry.io/* deps successfully aligned with Alloy.")


if __name__ == "__main__":
    main()
