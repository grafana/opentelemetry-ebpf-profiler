#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
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


def download_alloy_module(alloy_revision: str, cwd: Path) -> tuple[Path, str]:
    raw = run(
        ["go", "mod", "download", "-json", f"github.com/grafana/alloy@{alloy_revision}"],
        cwd=cwd,
    )
    data = json.loads(raw)

    alloy_dir = Path(data.get("Dir", ""))
    if not alloy_dir.exists():
        raise SystemExit(f"Failed: could not resolve alloy module dir for {alloy_revision}")

    resolved_version = data.get("Version", alloy_revision)
    return alloy_dir, resolved_version


def collect_alloy_versions(alloy_dir: Path) -> dict[str, str]:
    alloy_go_mod = alloy_dir / "go.mod"
    if not alloy_go_mod.exists():
        raise SystemExit(f"Failed: alloy go.mod not found at {alloy_go_mod}")
    return read_otel_requirements(alloy_go_mod)


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

    print("Downloading grafana/alloy with go mod...")
    alloy_dir, resolved_revision = download_alloy_module(args.alloy_revision, repo_root)
    print(
        "Collecting go.opentelemetry.io/* dependency versions from alloy go.mod "
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
