#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <alloy-revision>"
  echo
  echo "Example:"
  echo "  $0 v1.11.0"
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but was not found"
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "go is required but was not found"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required but was not found"
  exit 1
fi

readonly ALLOY_REVISION="$1"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly GO_MOD_PATH="${REPO_ROOT}/go.mod"

if [[ ! -f "${GO_MOD_PATH}" ]]; then
  echo "go.mod not found at ${GO_MOD_PATH}"
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

readonly ALLOY_DIR="${tmp_dir}/alloy"
readonly PROFILER_OLD_VERSIONS_FILE="${tmp_dir}/profiler_old_versions.txt"
readonly PROFILER_DEP_LIST_FILE="${tmp_dir}/profiler_deps.txt"
readonly ALLOY_VERSIONS_FILE="${tmp_dir}/alloy_versions.txt"
readonly PROFILER_FINAL_VERSIONS_FILE="${tmp_dir}/profiler_final_versions.txt"

echo "Cloning grafana/alloy..."
git clone https://github.com/grafana/alloy.git "${ALLOY_DIR}"
git -C "${ALLOY_DIR}" checkout "${ALLOY_REVISION}"

echo "Collecting go.opentelemetry.io/* dependencies from profiler..."
python3 - "${GO_MOD_PATH}" "${PROFILER_OLD_VERSIONS_FILE}" <<'PY'
import json
import subprocess
import sys

go_mod_path = sys.argv[1]
out_path = sys.argv[2]

data = json.loads(
    subprocess.check_output(["go", "mod", "edit", "-json", go_mod_path], text=True)
)

seen = set()
deps = []
for req in (data.get("Require") or []):
    path = req["Path"]
    if path.startswith("go.opentelemetry.io/") and path not in seen:
        seen.add(path)
        deps.append((path, req["Version"]))

with open(out_path, "w", encoding="utf-8") as f:
    for path, version in sorted(deps):
        f.write(f"{path} {version}\n")
PY

if [[ ! -s "${PROFILER_OLD_VERSIONS_FILE}" ]]; then
  echo "No go.opentelemetry.io/* dependencies found in ${GO_MOD_PATH}; nothing to do."
  exit 0
fi

cut -d' ' -f1 "${PROFILER_OLD_VERSIONS_FILE}" >"${PROFILER_DEP_LIST_FILE}"

echo "Collecting go.opentelemetry.io/* dependency versions from alloy (${ALLOY_REVISION})..."
python3 - "${ALLOY_DIR}" "${ALLOY_VERSIONS_FILE}" <<'PY'
import json
import os
import subprocess
import sys

alloy_dir = sys.argv[1]
out_path = sys.argv[2]

go_mods = [
    path.strip()
    for path in subprocess.check_output(
        ["git", "-C", alloy_dir, "ls-files", "**/go.mod"], text=True
    ).splitlines()
    if path.strip()
]

versions = {}
sources = {}

for rel_go_mod in sorted(go_mods):
    abs_go_mod = os.path.join(alloy_dir, rel_go_mod)
    data = json.loads(
        subprocess.check_output(["go", "mod", "edit", "-json", abs_go_mod], text=True)
    )
    for req in (data.get("Require") or []):
        path = req["Path"]
        if not path.startswith("go.opentelemetry.io/"):
            continue

        version = req["Version"]
        if path in versions and versions[path] != version:
            print(
                (
                    "conflicting versions in alloy for module "
                    f"{path}: {versions[path]} (from {sources[path]}) vs "
                    f"{version} (from {rel_go_mod})"
                ),
                file=sys.stderr,
            )
            sys.exit(1)

        versions[path] = version
        sources[path] = rel_go_mod

with open(out_path, "w", encoding="utf-8") as f:
    for path, version in sorted(versions.items()):
        f.write(f"{path} {version}\n")
PY

echo "Applying alloy versions to profiler go.opentelemetry.io/* dependencies..."
while IFS= read -r dep; do
  [[ -z "${dep}" ]] && continue

  alloy_version="$(awk -v dep="${dep}" '$1 == dep { print $2 }' "${ALLOY_VERSIONS_FILE}")"
  if [[ -z "${alloy_version}" ]]; then
    echo "Failed: dependency ${dep} was not found in alloy revision ${ALLOY_REVISION}"
    exit 1
  fi

  echo "  - ${dep} => ${alloy_version}"
  (cd "${REPO_ROOT}" && go mod edit -require "${dep}@${alloy_version}")
done <"${PROFILER_DEP_LIST_FILE}"

echo "Running go mod tidy..."
(cd "${REPO_ROOT}" && go mod tidy)

echo "Verifying resulting versions..."
python3 - "${GO_MOD_PATH}" "${PROFILER_FINAL_VERSIONS_FILE}" <<'PY'
import json
import subprocess
import sys

go_mod_path = sys.argv[1]
out_path = sys.argv[2]

data = json.loads(
    subprocess.check_output(["go", "mod", "edit", "-json", go_mod_path], text=True)
)

versions = {}
for req in (data.get("Require") or []):
    path = req["Path"]
    if path.startswith("go.opentelemetry.io/"):
        versions[path] = req["Version"]

with open(out_path, "w", encoding="utf-8") as f:
    for path, version in sorted(versions.items()):
        f.write(f"{path} {version}\n")
PY

while read -r dep _; do
  [[ -z "${dep}" ]] && continue

  expected_version="$(awk -v dep="${dep}" '$1 == dep { print $2 }' "${ALLOY_VERSIONS_FILE}")"
  final_version="$(awk -v dep="${dep}" '$1 == dep { print $2 }' "${PROFILER_FINAL_VERSIONS_FILE}")"

  if [[ -z "${expected_version}" ]]; then
    echo "Failed: no expected alloy version found for ${dep}"
    exit 1
  fi

  if [[ -z "${final_version}" ]]; then
    echo "Failed: ${dep} disappeared after go mod tidy (expected ${expected_version})"
    exit 1
  fi

  if [[ "${final_version}" != "${expected_version}" ]]; then
    echo "Failed: ${dep} is ${final_version} after go mod tidy, expected ${expected_version}"
    exit 1
  fi
done <"${PROFILER_OLD_VERSIONS_FILE}"

echo "Success: all go.opentelemetry.io/* dependencies match alloy revision ${ALLOY_REVISION}."
