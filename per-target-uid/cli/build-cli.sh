#!/usr/bin/env bash
# Build ksu_susfs with the per-target UID patches applied (CLI only).
#
# usage: ./cli/build-cli.sh <susfs_src_dir> [out_dir]
#
# Requires: python3, Android NDK (ANDROID_NDK_HOME or ANDROID_NDK_ROOT).
set -euo pipefail

SUSFS_DIR=${1:?usage: build-cli.sh <susfs_src_dir> [out_dir]}
OUT_DIR=${2:-$PWD/out}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
if [ -z "$NDK" ] || [ ! -x "$NDK/ndk-build" ]; then
  echo "::error::Android NDK not found (set ANDROID_NDK_HOME)" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "[1/4] hide_from (CLI only)"
python3 "$REPO_ROOT/patches/patch_hide_from_cli_only.py" "$SUSFS_DIR"

echo "[2/4] global hidden uid"
python3 "$REPO_ROOT/patches/patch_susfs_hidden_uid.py" "$SUSFS_DIR"

echo "[3/4] per-target hidden uid (CLI only)"
ABK_CLI_ONLY=1 python3 "$REPO_ROOT/patches/patch_susfs_hidden_uid_from.py" "$SUSFS_DIR" "$SUSFS_DIR"

echo "[4/4] ndk-build"
"$NDK/ndk-build" -C "$SUSFS_DIR/ksu_susfs" -j"$(nproc 2>/dev/null || echo 4)"

BIN="$SUSFS_DIR/ksu_susfs/libs/arm64-v8a/ksu_susfs"
[ -f "$BIN" ] || { echo "::error::ksu_susfs binary not produced" >&2; exit 1; }
cp -f "$BIN" "$OUT_DIR/ksu_susfs"
echo "built: $OUT_DIR/ksu_susfs ($(wc -c < "$OUT_DIR/ksu_susfs") bytes)"

for cmd in add_sus_path_hide_from add_hidden_uid add_hidden_uid_from; do
  grep -q "$cmd" "$OUT_DIR/ksu_susfs" || { echo "::error::missing command $cmd" >&2; exit 1; }
done
echo "all three commands present"
