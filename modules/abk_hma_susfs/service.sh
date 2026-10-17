#!/system/bin/sh
# Late pass: /sdcard and /data/media are mounted by now.
MODDIR=${0%/*}
sleep 15
[ -f "$MODDIR/sync.sh" ] || exit 0
ABK_SUSFS_BIN="${ABK_SUSFS_BIN:-}"
export ABK_SUSFS_BIN
sh "$MODDIR/sync.sh"
