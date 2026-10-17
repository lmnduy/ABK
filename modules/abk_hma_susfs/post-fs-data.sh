#!/system/bin/sh
# Early pass: /data/app and /data/data exist before zygote starts.
MODDIR=${0%/*}
[ -f "$MODDIR/sync.sh" ] || exit 0
ABK_SUSFS_BIN="${ABK_SUSFS_BIN:-}"
export ABK_SUSFS_BIN
sh "$MODDIR/sync.sh" >/dev/null 2>&1
