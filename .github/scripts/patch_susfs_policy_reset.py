#!/usr/bin/env python3
"""ABK: make a policy reload mirror the file instead of only adding to it.

Usage:
    patch_susfs_policy_reset.py <kernel_root>

Problem (2026-11-24):

    Editing the HMA whitelist template shrinks the hidden set, the sync rewrites
    policy.tsv, and the loader re-applies it - but the kernel side only ever calls
    susfs_sus_path_uid_upsert() and susfs_loop_queue_path().  Nothing ever removes
    an entry, so every app that left the hidden set keeps its (ino, dev, uid) row
    in SUS_PATH_UID_HLIST and its (path, uid, mode 1) row in LH_SUS_PATH_LOOP.
    The loop worker re-applies those stale rows on every app spawn, so the disk
    layer keeps hiding apps that the PM layer now shows - the two layers disagree
    until the next reboot (the tables are RAM only).

    Observed as 春秋's "隐藏应用列表生效 (2)" appearing right after a template
    edit and disappearing after a reboot, with no kernel "hiding path" log and a
    correct policy file.

This patcher adds abk_policy_reset_tables() - it drains both tables under their
own locks, waits one RCU grace period and frees the drained rows - and calls it at
the start of susfs_load_policy_file(), after the empty/short-file checks and
before the first rule is replayed.  The loader then rebuilds both tables from the
file, so the kernel mirrors policy.tsv exactly.

Touched file: fs/susfs.c.  Requires patch_susfs_policy_file.py,
patch_susfs_upsert_result.py and patch_susfs_loop_mode.py to have run first.
Re-running is a no-op; missing anchors abort with exit code 2.
"""
import os
import re
import sys

MARKER = "POLICY_RESET_ABK"
REL_SRC = os.path.join("fs", "susfs.c")

CHUNK = 256

HELPERS = (
    "\n"
    "/* ABK " + MARKER + ": a reload must mirror the policy file, not only add to it.\n"
    " * Both tables below are add-only by construction: the uid map is upserted and the\n"
    " * loop queue is appended to.  When the hidden set shrinks (whitelist template edit)\n"
    " * the rows of the apps that left it survive and the loop worker keeps re-applying\n"
    " * them on every app spawn, so the disk layer disagrees with the PM layer until the\n"
    " * next reboot.  Drain both, then let the loader repopulate them from the file.\n"
    " */\n"
    "static void abk_policy_reset_tables(void)\n"
    "{\n"
    "\tstruct st_susfs_sus_path_hlist *entry;\n"
    
    "\tstruct hlist_node *tmp;\n"
    "\tstruct st_susfs_sus_path_list *cursor, *tmp_list;\n"
    "\tvoid **doomed = NULL;\n"
    "\tint bucket, n, i, pass;\n"
    "\tint freed_uid = 0, freed_loop = 0;\n"
    "\n"
    "\tdoomed = kvmalloc_array(" + str(CHUNK) + ", sizeof(*doomed), GFP_KERNEL);\n"
    "\tif (!doomed) {\n"
    "\t\tSUSFS_LOGE(\"policy: reset skipped, cannot allocate\\n\");\n"
    "\t\treturn;\n"
    "\t}\n"
    "\n"
    "\t/* per-uid hide entries */\n"
    "\tfor (pass = 0; pass < 1000000; pass++) {\n"
    "\t\tn = 0;\n"
    "\t\tmutex_lock(&susfs_mutex_lock_sus_path_uid);\n"
    "\t\tfor (bucket = 0; bucket < HASH_SIZE(SUS_PATH_UID_HLIST) && n < " + str(CHUNK) + "; bucket++) {\n"
    "\t\t\thlist_for_each_entry_safe(entry, tmp, &SUS_PATH_UID_HLIST[bucket], node) {\n"
    "\t\t\t\thash_del_rcu(&entry->node);\n"
    "\t\t\t\tdoomed[n++] = entry;\n"
    "\t\t\t\tif (n == " + str(CHUNK) + ")\n"
    "\t\t\t\t\tbreak;\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t\tmutex_unlock(&susfs_mutex_lock_sus_path_uid);\n"
    "\t\tif (!n)\n"
    "\t\t\tbreak;\n"
    "\t\tsynchronize_rcu();\n"
    "\t\tfor (i = 0; i < n; i++)\n"
    "\t\t\tkfree(doomed[i]);\n"
    "\t\tfreed_uid += n;\n"
    "\t}\n"
    "\n"
    "\t/* loop queue */\n"
    "\tfor (pass = 0; pass < 1000000; pass++) {\n"
    "\t\tn = 0;\n"
    "\t\tmutex_lock(&susfs_mutex_lock_sus_path);\n"
    "\t\tlist_for_each_entry_safe(cursor, tmp_list, &LH_SUS_PATH_LOOP, list) {\n"
    "\t\t\tlist_del_rcu(&cursor->list);\n"
    "\t\t\tdoomed[n++] = cursor;\n"
    "\t\t\tif (n == " + str(CHUNK) + ")\n"
    "\t\t\t\tbreak;\n"
    "\t\t}\n"
    "\t\tmutex_unlock(&susfs_mutex_lock_sus_path);\n"
    "\t\tif (!n)\n"
    "\t\t\tbreak;\n"
    "\t\tsynchronize_rcu();\n"
    "\t\tfor (i = 0; i < n; i++)\n"
    "\t\t\tkfree(doomed[i]);\n"
    "\t\tfreed_loop += n;\n"
    "\t}\n"
    "\n"
    "\tkvfree(doomed);\n"
    "\tif (freed_uid || freed_loop)\n"
    "\t\tSUSFS_LOGI(\"policy: reset %d stale uid entr(ies), %d stale loop entr(ies)\\n\",\n"
    "\t\t\t   freed_uid, freed_loop);\n"
    "}\n"
    "\n"
)

FN_ANCHOR = "static int susfs_load_policy_file(void)\n{\n"

CALL_ANCHOR = "\tbuf[len] = '\\0';\n"
CALL_ADD = (
    "\n"
    "\t/* ABK " + MARKER + ": drop every row left by the previous policy before replaying\n"
    "\t * this one - otherwise apps that left the hidden set stay hidden until reboot.\n"
    "\t */\n"
    "\tabk_policy_reset_tables();\n"
)


def die(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(2)


def resolve(root):
    for base in (os.path.join(root, "common"), root):
        p = os.path.join(base, REL_SRC)
        if os.path.isfile(p):
            return p
    die("expected file not found: " + REL_SRC + " (looked in <root>/common and <root>)")


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: patch_susfs_policy_reset.py <kernel_root>\n")
        return 2
    path = resolve(sys.argv[1])
    with open(path, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()

    if MARKER in text:
        print("[skip] " + REL_SRC + " (already patched)")
        return 0

    if text.count(FN_ANCHOR) != 1:
        die("loader definition anchor matched %d times (expected 1) in %s"
            % (text.count(FN_ANCHOR), path))
    if text.count(CALL_ANCHOR) != 1:
        die("loader call anchor matched %d times (expected 1) in %s"
            % (text.count(CALL_ANCHOR), path))
    for need in ("LH_SUS_PATH_LOOP", "SUS_PATH_UID_HLIST",
                 "susfs_mutex_lock_sus_path_uid", "susfs_mutex_lock_sus_path"):
        if need not in text:
            die("required symbol missing: " + need)

    text = text.replace(FN_ANCHOR, HELPERS + FN_ANCHOR, 1)
    text = text.replace(CALL_ANCHOR, CALL_ANCHOR + CALL_ADD, 1)

    # self-check: the call must land inside the loader, before the first upsert
    call_pos = text.find("abk_policy_reset_tables();")
    first_upsert = text.find("susfs_sus_path_uid_upsert(", call_pos + 1)
    if call_pos < 0 or first_upsert < 0 or call_pos > first_upsert:
        die("verification failed: reset call is not before the first upsert")
    if text.count("abk_policy_reset_tables();") != 1:
        die("verification failed: reset call inserted more than once")

    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    print("[patch] " + REL_SRC + " (policy reload now mirrors the file)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
