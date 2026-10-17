#!/system/bin/sh
# ABK HMA SUSFS bridge - re-apply every hide target on boot.
#
# Reads (all optional):
#   /data/adb/hma_susfs/enabled          0 disables the bridge
#   /data/adb/hma_susfs/pkgs.txt         one package per line (extra fields ignored)
#   /data/adb/hma_susfs/targets.txt      one package per line
#   /data/adb/hma_susfs/extra_paths.txt  one absolute path per line
#   /data/adb/hma_susfs/hide_app_dirs.txt one package per line (ABK extension)
#
# For every package it hides the whole on-disk footprint, not only /data/data:
#   /data/app/<pkg>-*  /data/app/*/<pkg>-*  /data/data/<pkg>
#   /data/user/0/<pkg>  /data/user_de/0/<pkg>
#   /sdcard/Android/data/<pkg>  /data/media/0/Android/data/<pkg>
# Each path is registered with add_sus_kstat_statically BEFORE add_sus_path, so
# stat()/fstat() on something that still reaches the inode reports the real
# (dev, ino) - the kernel autoreg patch does the same for add_sus_path.

BASE=/data/adb/hma_susfs
LOG_TAG="ABK-HMA"

log() { echo "$LOG_TAG: $*"; }

[ -f "$BASE/enabled" ] && [ "$(cat "$BASE/enabled" 2>/dev/null)" = "0" ] && {
    log "disabled by $BASE/enabled"
    exit 0
}

SUSFS_BIN="${ABK_SUSFS_BIN:-}"
if [ -z "$SUSFS_BIN" ] || [ ! -x "$SUSFS_BIN" ]; then
    for candidate in \
        /data/adb/ksu/bin/ksu_susfs \
        /data/adb/ap/bin/ksu_susfs \
        /data/adb/modules/abk_susfs/bin/ksu_susfs \
        /data/adb/modules/abk_susfs/system/bin/ksu_susfs; do
        [ -x "$candidate" ] && SUSFS_BIN="$candidate" && break
    done
fi
[ -x "$SUSFS_BIN" ] || { log "ksu_susfs not found"; exit 1; }

hide_path() {
    p="$1"
    [ -e "$p" ] || return 1
    kstat="$(stat -c "%i %d default %s %X 0 %Y 0 %Z 0 %b %B" "$p" 2>/dev/null)"
    [ -n "$kstat" ] && "$SUSFS_BIN" add_sus_kstat_statically "$p" $kstat >/dev/null 2>&1
    "$SUSFS_BIN" add_sus_path "$p" >/dev/null 2>&1
}

hide_pkg() {
    pkg="$1"
    case "$pkg" in
        *.*) ;;
        *) return 0 ;;
    esac
    for d in /data/app/*"$pkg"-* /data/app/*/*"$pkg"-* /data/app/*/*"$pkg" \
             /data/data/"$pkg" /data/user/0/"$pkg" /data/user_de/0/"$pkg" \
             /sdcard/Android/data/"$pkg" /data/media/0/Android/data/"$pkg"; do
        hide_path "$d"
    done
}

apply_pkg_file() {
    f="$1"
    [ -f "$f" ] || return 0
    while IFS= read -r line; do
        case "$line" in ""|\#*) continue ;; esac
        hide_pkg "$(echo "$line" | awk '{print $1}')"
    done < "$f"
}

apply_path_file() {
    f="$1"
    [ -f "$f" ] || return 0
    while IFS= read -r line; do
        case "$line" in ""|\#*) continue ;; esac
        hide_path "$(echo "$line" | awk '{print $1}')"
    done < "$f"
}

apply_path_file "$BASE/targets.txt"
apply_path_file "$BASE/extra_paths.txt"
apply_pkg_file "$BASE/pkgs.txt"
apply_pkg_file "$BASE/hide_app_dirs.txt"

# Hide module libraries from app mappings (needs the kernel sus_map app gate).
for lib in /data/adb/modules/*/zygisk/*.so /data/adb/modules/*/system/lib64/*.so \
           /data/adb/modules/*/system/lib/*.so; do
    [ -f "$lib" ] || continue
    "$SUSFS_BIN" add_sus_map "$lib" >/dev/null 2>&1
done

log "re-applied $(wc -l < "$BASE/pkgs.txt" 2>/dev/null || echo 0) pkgs entries"
exit 0
