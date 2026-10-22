#!/usr/bin/env python3
"""ABK: hide container-runtime debugfs mounts under /dev/ from app processes.

Why: container runtimes (Droidspaces/Anland) mount debugfs under a random
/dev/<x>/<y> path.  That mount carries a peer-group id far away from the
system's 1..82 range (e.g. shared:200000), so a detector that validates
peer-group continuity in /proc/self/mountinfo reports a "mount gap".
The mount is created at runtime, so a boot-time hook misses it.

This patcher adds a filter inside SUSFS' filtered mountinfo/mounts paths
(fs/proc_namespace.c, used for app-uid processes only): entries whose fstype is
debugfs AND whose mountpoint is under /dev/ are skipped.  /sys/kernel/debug and
every su/system view stay untouched.

Usage:
    patch_hide_dev_debugfs.py <kernel_root>

Idempotent; every missing anchor aborts with ::error:: and exit 2.
"""
import os
import sys

MARKER = "HIDE_DEV_DEBUGFS_ABK"
REL = "common/fs/proc_namespace.c"
INCLUDE_ANCHOR = '#include "internal.h"\n'

INCLUDE_ADD = (
    '#include <linux/gfp.h>   /* ABK ' + MARKER + ' */\n'
    '#include <linux/dcache.h> /* ABK ' + MARKER + ' */\n'
)
FWD_DECL = (
    "/* ABK " + MARKER + " */\n"
    "static bool abk_should_hide_dev_debugfs(struct vfsmount *mnt);\n"
)

HELPER = (
    "\n"
    "/* ABK " + MARKER + ": container runtimes mount debugfs at a random\n"
    " * /dev/<x>/<y> path. That mount gets a far-away peer-group id and makes a\n"
    " * detector's peer-group continuity check report a mount gap. Hide exactly\n"
    " * those entries from app processes; su/ksu and system views keep them.\n"
    " */\n"
    "extern bool susfs_is_current_app_uid(void);\n"
    "extern bool susfs_is_current_ksu_domain(void);\n"
    "static bool abk_should_hide_dev_debugfs(struct vfsmount *mnt)\n"
    "{\n"
    "\tstruct super_block *sb = mnt->mnt_sb;\n"
    "\tstruct path p = { .dentry = mnt->mnt_root, .mnt = mnt };\n"
    "\tchar *page, *path;\n"
    "\tbool hide = false;\n"
    "\n"
    "\tif (!sb || !sb->s_type || !sb->s_type->name)\n"
    "\t\treturn false;\n"
    "\tif (strcmp(sb->s_type->name, \"debugfs\"))\n"
    "\t\treturn false;\n"
    "\tif (!susfs_is_current_app_uid() || susfs_is_current_ksu_domain())\n"
    "\t\treturn false;\n"
    "\n"
    "\tpage = (char *)__get_free_page(GFP_KERNEL);\n"
    "\tif (!page)\n"
    "\t\treturn false;\n"
    "\tpath = d_path(&p, page, PAGE_SIZE);\n"
    "\tif (!IS_ERR(path) && !strncmp(path, \"/dev/\", 5))\n"
    "\t\thide = true;\n"
    "\tfree_page((unsigned long)page);\n"
    "\treturn hide;\n"
    "}\n"
    "\n"
)

SKIP = (
    "\t/* ABK " + MARKER + " */\n"
    "\tif (abk_should_hide_dev_debugfs(mnt))\n"
    "\t\treturn 0;\n"
)

FUNCS = (
    "static int susfs_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)",
    "static int susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)",
)
MNT_ID_CHECK = "\tif (r->mnt_id >= DEFAULT_KSU_MNT_ID)\n\t\treturn 0;\n"


def die(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        die("usage: patch_hide_dev_debugfs.py <kernel_root>")
    root = sys.argv[1]
    path = os.path.join(root, REL)
    if not os.path.isfile(path):
        die("expected file not found: " + path + " (SUSFS mount patch missing?)")
    with open(path, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    if MARKER in text:
        print("[ABK] hide-dev-debugfs: skip " + path)
        return 0
    if INCLUDE_ANCHOR not in text:
        die("anchor '#include \"internal.h\"' not found in " + path)

    text = text.replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE_ADD + FWD_DECL, 1)

    # Insert the definition before the EARLIEST of the two consumers, so the
    # function is always defined before any call site (C99 forbids implicit
    # declarations, and a static definition after a call is an error).
    positions = []
    for fn in FUNCS:
        idx = text.find(fn)
        if idx == -1:
            die("function not found: " + fn + " in " + path)
        positions.append(idx)
    insert_at = min(positions)
    text = text[:insert_at] + HELPER + text[insert_at:]

    # Now add the filter call at each consumer's mnt_id check.
    for fn in FUNCS:
        start = text.find(fn)
        if start == -1:
            die("function vanished: " + fn + " in " + path)
        pos = text.find(MNT_ID_CHECK, start)
        if pos == -1:
            die("mnt_id check not found after " + fn + " in " + path)
        at = pos + len(MNT_ID_CHECK)
        text = text[:at] + SKIP + text[at:]

    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)

    call_sites = text.count("if (abk_should_hide_dev_debugfs(mnt))")
    defn = text.find("static bool abk_should_hide_dev_debugfs(struct vfsmount *mnt)\n{")
    first_call = text.find("if (abk_should_hide_dev_debugfs(mnt))")
    checks = [
        (MARKER in text, "marker"),
        (defn != -1, "definition"),
        (call_sites == 2, "two skip sites"),
        (defn < first_call, "definition precedes first call"),
    ]
    bad = [name for ok, name in checks if not ok]
    if bad:
        die("self-check failed: " + ", ".join(bad))
    print("[ABK] hide-dev-debugfs: patched " + path + " (definition@%d, calls@%d/%d)"
          % (defn, first_call,
             text.find("if (abk_should_hide_dev_debugfs(mnt))", first_call + 1)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
