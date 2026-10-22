#!/usr/bin/env python3
"""ABK: hide debugfs mounts living under /dev from the app-visible mount view.

Usage:
    patch_susfs_hide_dev_debugfs.py <kernel_root>

Background:
  Container runtimes (droidspaces and friends) create a scratch debugfs mount
  at /dev/<random>/<random>.  It is visible to app processes in
  /proc/<pid>/mountinfo and /proc/<pid>/mounts, and shows up in a detector's
  mount scan as a mount-id / peer-group outlier (shared:200000), i.e. the
  "mount gap" class of finding.

  SUSFS already routes every non-ksu process through its own mount viewers:

      mountinfo_open() -> susfs_show_mountinfo()
      mounts_open()    -> susfs_show_vfsmnt()
      mountstats_open()-> susfs_show_vfsstat()

  This patcher adds one rule to those app-visible viewers: a mount whose
  filesystem type is debugfs and whose mountpoint is under /dev is skipped.
  The rule is gated on susfs_is_current_app_uid(), so:
      app uid >= 10000            -> entry hidden
      root / ksu domain           -> real view (unchanged)
      uid < 10000 (system)        -> real view (unchanged)
  The mount itself is untouched; containers keep using it.

Idempotent: re-running is a no-op once the marker is present.
Every missing or ambiguous anchor aborts with exit code 2 and an ::error::.
"""
import os
import sys

MARKER = "DEBUGFS_DEV_MOUNT_HIDE_ABK"
HELPER = "abk_hide_dev_debugfs"
REL = os.path.join("fs", "proc_namespace.c")

INC_OLD = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "#include <linux/susfs_def.h>\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
)
INC_NEW = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "#include <linux/susfs_def.h>\n"
    "#include <linux/dcache.h>\n"
    "#include <linux/limits.h>\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
)

HELPER_ANCHOR = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "static int susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)\n"
)

HELPER_TEXT = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "/* ABK " + MARKER + ": container runtimes mount a scratch debugfs under\n"
    " * /dev/<random>/<random>. Keep that mount out of the app-visible view\n"
    " * (mountinfo/mounts/mountstats); su/ksu and uid < 10000 keep it.\n"
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
    "\tif (!sb->s_type || !sb->s_type->name ||\n"
    "\t    strcmp(sb->s_type->name, \"debugfs\"))\n"
    "\t\treturn false;\n"
    "\n"
    "\tbuf = kmalloc(PATH_MAX, GFP_KERNEL);\n"
    "\tif (!buf)\n"
    "\t\treturn false;\n"
    "\tp = d_path(&path, buf, PATH_MAX);\n"
    "\tif (!IS_ERR(p) && !strncmp(p, \"/dev/\", 5))\n"
    "\t\thide = true;\n"
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
        die("usage: patch_susfs_hide_dev_debugfs.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if os.path.isfile(os.path.join(candidate, REL)):
            base = candidate
            break
    if base is None:
        die("fs/proc_namespace.c not found under " + root +
            " (directly or in common/); the SUSFS mount patch is missing")
    path = os.path.join(base, REL)
    print("[ABK] kernel tree: " + base)

    text = load(path)
    if MARKER in text:
        print("[ABK] skip: " + path + " already carries " + MARKER)
    else:
        text = sub_one(text, INC_OLD, INC_NEW, path, "SUSFS include block")
        text = sub_one(text, HELPER_ANCHOR,
                       HELPER_TEXT +
                       "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n" +
                       "static int susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)\n",
                       path, "susfs_show_vfsmnt definition")
        for fn, prologue in PROLOGUES.items():
            text = sub_one(text, prologue + CALL, prologue + CALL_NEW, path,
                           fn + " umounted gate")
        save(path, text)
        print("[ABK] patch: " + path)

    # ---- verification ---------------------------------------------------
    text = load(path)
    if MARKER not in text:
        die("verification failed: " + MARKER + " missing from " + path)
    if "static bool " + HELPER + "(struct vfsmount *mnt, struct dentry *dentry," not in text:
        die("verification failed: " + HELPER + " definition missing from " + path)
    if text.count(HELPER + "(mnt, mnt->mnt_root, sb)") != 3:
        die("verification failed: " + HELPER + " call sites = " +
            str(text.count(HELPER + "(mnt, mnt->mnt_root, sb)")) +
            " (expected 3: mounts, mountinfo, mountstats)")
    if "#include <linux/dcache.h>" not in text:
        die("verification failed: <linux/dcache.h> include missing from " + path)

    print("[ABK] debugfs(/dev) mount hide OK: " + MARKER +
          " (fs/proc_namespace.c app-uid view: mounts + mountinfo + mountstats; ksu/uid<10000 unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
