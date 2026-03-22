#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <artifact-dir> <binary-name>" >&2
  exit 64
fi

artifact_dir=$1
binary_name=$2

if [[ ! -d "$artifact_dir" ]]; then
  echo "artifact directory not found: $artifact_dir" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 1
fi

if ! cargo audit --help >/dev/null 2>&1; then
  echo "cargo-audit is required" >&2
  exit 1
fi

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

audited=0

extract_archive() {
  local archive=$1
  local dest=$2

  case "$archive" in
    *.zip)
      unzip -qq "$archive" -d "$dest"
      ;;
    *.tar.gz|*.tar.xz|*.tar.zst|*.tar.zstd)
      tar -xf "$archive" -C "$dest"
      ;;
    *)
      return 1
      ;;
  esac
}

while IFS= read -r -d '' archive; do
  extract_dir="$tmp_root/archive-$audited"
  mkdir -p "$extract_dir"

  if ! extract_archive "$archive" "$extract_dir"; then
    continue
  fi

  while IFS= read -r -d '' binary; do
    cargo audit bin "$binary"
    audited=$((audited + 1))
  done < <(
    find "$extract_dir" -type f \
      \( -name "$binary_name" -o -name "$binary_name.exe" \) \
      -print0
  )
done < <(find "$artifact_dir" -type f -print0)

if [[ $audited -eq 0 ]]; then
  echo "no release binaries named '$binary_name' were found in $artifact_dir" >&2
  exit 1
fi

echo "audited $audited release binary file(s)"
