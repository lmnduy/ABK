#!/usr/bin/env sh
# Apply the kernel-side patches in the required order.
#
# usage: ./patches/apply-all.sh <susfs_src_dir> <kernel_root>
#
# Order matters:
#   hide_from(CLI-safe when no kernel) -> global hidden uid -> per-target hidden uid
set -eu

SUSFS_DIR=${1:?usage: apply-all.sh <susfs_src_dir> <kernel_root>}
KERNEL_ROOT=${2:?usage: apply-all.sh <susfs_src_dir> <kernel_root>}
HERE=$(cd "$(dirname "$0")" && pwd)

python3 "$HERE/patch_hide_from_cli_only.py" "$SUSFS_DIR"
python3 "$HERE/patch_susfs_hidden_uid.py" "$SUSFS_DIR"
python3 "$HERE/patch_susfs_hidden_uid_from.py" "$SUSFS_DIR" "$KERNEL_ROOT"

echo "patches applied; rebuild the kernel and ksu_susfs"
