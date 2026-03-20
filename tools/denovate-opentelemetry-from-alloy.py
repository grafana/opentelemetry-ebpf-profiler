#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

OTEL_PREFIX = "go.opentelemetry.io/"


def run(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        raise SystemExit(result.returncode)
    return result.stdout.strip()


def read_otel_requirements(go_mod_path: Path) -> dict[str, str]:
    raw = run(["go", "mod", "edit", "-json", str(go_mod_path)])
    data = json.loads(raw)
    requirements: dict[str, str] = {}
    for req in (data.get("Require") or []):
        dep_path = req["Path"]
        if dep_path.startswith(OTEL_PREFIX):
            requirements[dep_path] = req["Version"]
    return requirements


def collect_alloy_versions(alloy_dir: Path) -> dict[str, str]:
    go_mod_files = [
        line.strip()
        for line in run(["git", "-C", str(alloy_dir), "ls-files", "**/go.mod"]).splitlines()
        if line.strip()
    ]

    versions: dict[str, str] = {}
    sources: dict[str, str] = {}
    for rel_path in sorted(go_mod_files):
        go_mod = alloy_dir / rel_path
        for dep_path, version in read_otel_requirements(go_mod).items():
            current = versions.get(dep_path)
            if current is not None and current != version:
                src = sources[dep_path]
                raise SystemExit(
                    "Failed: conflicting versions in alloy for "
                    f"{dep_path}: {current} (from {src}) vs {version} (from {rel_path})"
                )
            versions[dep_path] = version
            sources[dep_path] = rel_path
    return versions


def apply_versions(repo_root: Path, versions: dict[str, str], deps: list[str]) -> None:
    for dep in deps:
        version = versions.get(dep)
        if version is None:
            raise SystemExit(f"Failed: dependency {dep} was not found in alloy")
        print(f"  - {dep} => {version}")
        run(["go", "mod", "edit", f"-require={dep}@{version}"], cwd=repo_root)


def verify_versions(
    go_mod_path: Path,
    expected_versions: dict[str, str],
    original_deps: list[str],
) -> None:
    final_versions = read_otel_requirements(go_mod_path)
    for dep in original_deps:
        expected = expected_versions.get(dep)
        if expected is None:
            raise SystemExit(f"Failed: no expected alloy version found for {dep}")

        final = final_versions.get(dep)
        if final is None:
            raise SystemExit(
                f"Failed: {dep} disappeared after go mod tidy (expected {expected})"
            )
        if final != expected:
            raise SystemExit(
                f"Failed: {dep} is {final} after go mod tidy, expected {expected}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sync go.opentelemetry.io/* dependencies in this repo to versions "
            "used by a specified grafana/alloy revision."
        )
    )
    parser.add_argument("alloy_revision", help="Alloy tag, branch, or commit")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    go_mod_path = repo_root / "go.mod"
    if not go_mod_path.exists():
        raise SystemExit(f"Failed: go.mod not found at {go_mod_path}")

    profiler_versions = read_otel_requirements(go_mod_path)
    if not profiler_versions:
        print("No go.opentelemetry.io/* dependencies found; nothing to do.")
        return 0

    original_deps = sorted(profiler_versions.keys())

    with tempfile.TemporaryDirectory() as tmp:
        alloy_dir = Path(tmp) / "alloy"
        print("Cloning grafana/alloy...")
        run(["git", "clone", "https://github.com/grafana/alloy.git", str(alloy_dir)])
        run(["git", "-C", str(alloy_dir), "checkout", args.alloy_revision])
        resolved_revision = run(["git", "-C", str(alloy_dir), "rev-parse", "HEAD"])

        print(
            "Collecting go.opentelemetry.io/* dependency versions from alloy "
            f"({resolved_revision})..."
        )
        alloy_versions = collect_alloy_versions(alloy_dir)

    print("Applying alloy versions to profiler go.opentelemetry.io/* dependencies...")
    apply_versions(repo_root, alloy_versions, original_deps)

    print("Running go mod tidy...")
    run(["go", "mod", "tidy"], cwd=repo_root)

    print("Verifying resulting versions...")
    verify_versions(go_mod_path, alloy_versions, original_deps)

    print(
        "Success: all go.opentelemetry.io/* dependencies match alloy revision "
        f"{args.alloy_revision}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
