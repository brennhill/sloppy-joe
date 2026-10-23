#!/usr/bin/env bash
# Install a sloppy-joe release binary for the GitHub Action.
#
# Usage: install-action-binary.sh <archive-url> <archive-name> <target> <ext>
#
# The working directory is usually the PR checkout, which is untrusted: nothing
# is downloaded into, extracted into, or put on PATH from it. The archive must
# match the SHA-256 published next to it (<archive-url>.sha256).
set -euo pipefail

URL="$1"
ARCHIVE="$2"
TARGET="$3"
EXT="$4"

fail() {
  echo "::error::$1"
  exit 1
}

case "${ARCHIVE}" in
  */* | *..* | "") fail "Invalid archive name: ${ARCHIVE}" ;;
esac

TMP_ROOT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if command -v cygpath >/dev/null 2>&1; then
  TMP_ROOT="$(cygpath -u "${TMP_ROOT}")"
fi
WORK="$(mktemp -d "${TMP_ROOT%/}/sloppy-joe-install.XXXXXX")"
cd "${WORK}"

echo "Downloading ${URL}"
curl -fsSL "${URL}" -o "${ARCHIVE}" || fail "Could not download ${URL}"
curl -fsSL "${URL}.sha256" -o "${ARCHIVE}.sha256" \
  || fail "Could not download checksum ${URL}.sha256; refusing to install an unverified binary"

EXPECTED="$(awk 'NR==1 {print tolower($1)}' "${ARCHIVE}.sha256")"
if ! [[ "${EXPECTED}" =~ ^[0-9a-f]{64}$ ]]; then
  fail "Malformed checksum file for ${ARCHIVE}"
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${ARCHIVE}" | awk '{print tolower($1)}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${ARCHIVE}" | awk '{print tolower($1)}')"
else
  fail "No SHA-256 tool available to verify ${ARCHIVE}"
fi
if [ "${ACTUAL}" != "${EXPECTED}" ]; then
  fail "SHA-256 checksum mismatch for ${ARCHIVE} (expected ${EXPECTED}, got ${ACTUAL})"
fi

mkdir extract
if [ "${EXT}" = "tar.xz" ]; then
  tar -xf "${ARCHIVE}" -C extract
  BIN="extract/sloppy-joe-${TARGET}/sloppy-joe"
  NAME="sloppy-joe"
elif [ "${EXT}" = "zip" ]; then
  unzip -q "${ARCHIVE}" -d extract
  BIN="extract/sloppy-joe.exe"
  NAME="sloppy-joe.exe"
else
  fail "Unsupported archive type: ${EXT}"
fi

if [ ! -f "${BIN}" ] || [ -L "${BIN}" ]; then
  fail "Could not find the sloppy-joe binary in ${ARCHIVE}"
fi

mkdir bin
mv "${BIN}" "bin/${NAME}"
chmod +x "bin/${NAME}"

BIN_DIR="${WORK}/bin"
if command -v cygpath >/dev/null 2>&1; then
  BIN_DIR="$(cygpath -w "${BIN_DIR}")"
fi
echo "${BIN_DIR}" >> "${GITHUB_PATH}"
echo "sloppy-joe installed to ${BIN_DIR}"
