#!/usr/bin/env python3
"""ABK: collapse app-visible mount tables to one view.

Usage:
    patch_susfs_mount_view_consistency.py <kernel_root>

Duck Detector's "Cross-process mount views" check reads the mount tables of
an app's own processes and expects one distinct view.  On Android those
processes legitimately live in different namespaces, and the tables differ by
a small, fixed set of namespace-only entries (measured on zorn / 6.1.138):

    main app process : /storage (tmpfs), /storage/emulated (fuse)
    app-zygote       : no /storage, plus tmpfs over /data/data, /data/user,
                       /data/user_de, /data/misc/profiles/{cur,ref}
    isolated probe   : no /storage

This patcher hides exactly those entries from every app-uid reader, so all
app-visible tables (self and cross-process) converge to the same set:

    app uid >= 10000 -> variant entries skipped
    root / ksu       -> real view
    uid < 10000      -> real view

Mounts are not removed; only their mountinfo/mounts/mountstats lines are
filtered for app readers.

Touched file: fs/proc_namespace.c (SUSFS viewers).
Idempotent; every missing/ambiguous anchor aborts with exit code 2.
"""
import os
import sys

MARKER = "ABK_MOUNT_VIEW_CONSISTENCY"
HELPER = "abk_hide_ns_variant"
REL_C = os.path.join("fs", "proc_namespace.c")

HELPER_ANCHOR = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "static int susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)\n"
)
HELPER_TEXT = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "/* ABK " + MARKER + ": namespace-only mounts differ between an app's main\n"
    " * process, its app-zygote and its isolated observers. Hide them from the\n"
    " * app-uid view so every readable mount table is identical. The mounts\n"
    " * themselves are untouched; root/ksu and uid < 10000 keep the real view.\n"
    " */\n"
    "static bool " + HELPER + "(struct vfsmount *mnt, struct dentry *dentry,\n"
    "\t\t\t  struct super_block *sb)\n"
    "{\n"
    "\tstruct path path = { .mnt = mnt, .dentry = dentry };\n"
    "\tchar *buf, *p;\n"
    "\tbool hide = false;\n"
    "\n"
    "\tif (!susfs_is_current_app_uid())\n"
    "\t\treturn false;\n"
    "\tif (!sb->s_type || !sb->s_type->name)\n"
    "\t\treturn false;\n"
    "\n"
    "\tbuf = kmalloc(PATH_MAX, GFP_KERNEL);\n"
    "\tif (!buf)\n"
    "\t\treturn false;\n"
    "\tp = d_path(&path, buf, PATH_MAX);\n"
    "\tif (!IS_ERR(p)) {\n"
    "\t\tif (!strcmp(p, \"/storage\") || !strncmp(p, \"/storage/\", 9))\n"
    "\t\t\thide = true;\n"
    "\t\telse if (!strcmp(sb->s_type->name, \"tmpfs\") &&\n"
    "\t\t\t (!strcmp(p, \"/data/data\") ||\n"
    "\t\t\t  !strcmp(p, \"/data/user\") ||\n"
    "\t\t\t  !strcmp(p, \"/data/user_de\") ||\n"
    "\t\t\t  !strcmp(p, \"/data/misc/profiles/cur\") ||\n"
    "\t\t\t  !strcmp(p, \"/data/misc/profiles/ref\")))\n"
    "\t\t\thide = true;\n"
    "\t}\n"
    "\tkfree(buf);\n"
    "\treturn hide;\n"
    "}\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "\n"
)

CALL = (
    "\tif (r->mnt_id >= DEFAULT_KSU_MNT_ID)\n"
    "\t\treturn 0;\n"
)
CALL_NEW = (
    "\tif (r->mnt_id >= DEFAULT_KSU_MNT_ID)\n"
    "\t\treturn 0;\n"
    "\tif (" + HELPER + "(mnt, mnt->mnt_root, sb))\n"
    "\t\treturn 0;\n"
)

PROLOGUES = {
    "susfs_show_vfsmnt": (
        "static int susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)\n"
        "{\n"
        "\tstruct proc_mounts *p = m->private;\n"
        "\tstruct mount *r = real_mount(mnt);\n"
        "\tstruct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };\n"
        "\tstruct super_block *sb = mnt_path.dentry->d_sb;\n"
        "\tint err;\n"
        "\n"
    ),
    "susfs_show_mountinfo": (
        "static int susfs_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)\n"
        "{\n"
        "\tstruct proc_mounts *p = m->private;\n"
        "\tstruct mount *r = real_mount(mnt);\n"
        "\tstruct super_block *sb = mnt->mnt_sb;\n"
        "\tstruct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };\n"
        "\tint err;\n"
        "\n"
    ),
    "susfs_show_vfsstat": (
        "static int susfs_show_vfsstat(struct seq_file *m, struct vfsmount *mnt)\n"
        "{\n"
        "\tstruct proc_mounts *p = m->private;\n"
        "\tstruct mount *r = real_mount(mnt);\n"
        "\tstruct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };\n"
        "\tstruct super_block *sb = mnt_path.dentry->d_sb;\n"
        "\tint err;\n"
        "\n"
    ),
}


def die(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(2)


def load(path):
    if not os.path.isfile(path):
        die("expected file not found: " + path)
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def save(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def sub_one(text, needle, repl, path, label):
    count = text.count(needle)
    if count != 1:
        die("anchor '" + label + "' matched " + str(count) + " times (expected 1) in " + path)
    return text.replace(needle, repl, 1)


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_mount_view_consistency.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if os.path.isfile(os.path.join(candidate, REL_C)):
            base = candidate
            break
    if base is None:
        die("fs/proc_namespace.c not found under " + root)
    cp = os.path.join(base, REL_C)
    print("[ABK] kernel tree: " + base)

    c = load(cp)
    if MARKER in c:
        print("[ABK] skip: " + cp + " already carries " + MARKER)
    else:
        c = sub_one(c, HELPER_ANCHOR,
                    HELPER_TEXT +
                    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n" +
                    "static int susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)\n",
                    cp, "susfs_show_vfsmnt definition")
        for fn, prologue in PROLOGUES.items():
            c = sub_one(c, prologue + CALL, prologue + CALL_NEW, cp, fn + " mnt_id gate")
        save(cp, c)
        print("[ABK] patch: " + cp)

    c = load(cp)
    if c.count(HELPER + "(mnt, mnt->mnt_root, sb)") != 3:
        die("verification failed: helper call sites != 3")
    print("[ABK] mount view consistency OK: " + MARKER +
          " (app-uid mountinfo/mounts/mountstats hide /storage* + app-zygote /data tmpfs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
