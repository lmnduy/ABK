#!/usr/bin/env python3
"""ABK: make a hidden sus_path / sus mount answer ENOENT, not EACCES/EPERM.

Usage:
    patch_susfs_enoent_map.py <kernel_root>

Background: the detector (com.chunqiunativecheck) treats an EACCES/EPERM from
a native probe as "INCOMPLETE_NO_PRIVILEGE_REQUIRED" instead of a definitive
"absent".  SUSFS' namei hooks already answer -ENOENT when a sus_path entry is
looked up, but two other spots can still leak a permission error for a target
this build hides:

  * fs/statfs.c  vfs_statfs() -> statfs_by_dentry() -> security_sb_statfs()
    can return -EACCES/-EPERM after the susfs mount/kstat redirection, even
    though the path or mount is hidden from the caller;
  * fs/namei.c   inode_permission() can return -EACCES/-EPERM for a sus_path
    inode (open/access/stat/exec permission checks) when a dentry was already
    resolved before the hide gate applied.

This patcher adds one narrow predicate in fs/susfs.c:

    bool susfs_abk_target_is_hidden(struct inode *inode, struct vfsmount *mnt)

which is true ONLY when
    - the caller passes the existing susfs_is_current_app_proc_target() gate
      (app uid >= 10000, outside the ksu domain, kill switch on), AND
    - the inode is a sus_path entry hidden from this caller
      (susfs_is_inode_sus_path() is true), OR the mount is a SUSFS sus mount
      (real_mount(mnt)->mnt_id >= DEFAULT_KSU_MNT_ID).

and uses it to remap -EACCES/-EPERM to -ENOENT in:

    fs/statfs.c    all vfs_statfs() return paths (kstat spoof + mount + plain)
    fs/namei.c     inode_permission() return value

Nothing else changes: every other errno, every non-hidden path, every su/ksu
caller and every uid < 10000 keep the original behaviour.  The existing
abk_sus_path_app_uid_gate=0 boot parameter disables the new predicate too.

Touched files (relative to <kernel_root>, directly or under common/):
    include/linux/susfs.h
    fs/susfs.c
    fs/statfs.c
    fs/namei.c

Every missing or ambiguous anchor aborts with exit code 2 and an ::error::
line, so CI never silently ships an unpatched kernel.  Re-running is a no-op.
"""
import os
import re
import sys

MARKER = "SUS_PATH_ENOENT_MAP_ABK"
HELPER = "susfs_abk_target_is_hidden"
STATFS_HELPER = "abk_statfs_enoent"
NAMEI_ORIG = "abk_inode_permission_orig"

REL = {
    "hdr": os.path.join("include", "linux", "susfs.h"),
    "src": os.path.join("fs", "susfs.c"),
    "statfs": os.path.join("fs", "statfs.c"),
    "namei": os.path.join("fs", "namei.c"),
}

# --- include/linux/susfs.h -------------------------------------------------
HDR_ANCHOR = "void susfs_add_sus_path_loop(void __user **user_info);\n"
HDR_ADD = (
    "bool " + HELPER + "(struct inode *inode, struct vfsmount *mnt); /* ABK " + MARKER + " */\n"
)

# --- fs/susfs.c ------------------------------------------------------------
SRC_TAIL = (
    "\tif (is_i_uid_not_allowed(sus_i_uid)) {\n"
    "\t\tSUSFS_LOGI(\"hiding path with ino '%lu'\\n\", inode->i_ino);\n"
    "\t\treturn true;\n"
    "\t}\n"
    "\treturn false;\n"
    "}\n"
    "\n"
)
SRC_ANCHOR = SRC_TAIL + "int susfs_get_data_path(struct path *path) {"

SRC_HELPER = (
    "/* ABK " + MARKER + ": a target this app-uid caller is not allowed to\n"
    " * observe must answer \"does not exist\", never a permission error.\n"
    " * True only when the caller passed the existing app-uid gate AND the\n"
    " * inode is a sus_path entry hidden from it, or the mount is a SUSFS\n"
    " * sus mount.  su/ksu domain and uid < 10000 never reach this point.\n"
    " */\n"
    "bool " + HELPER + "(struct inode *inode, struct vfsmount *mnt)\n"
    "{\n"
    "\tstruct mount *m = NULL;\n"
    "\n"
    "\tif (!susfs_is_current_app_proc_target())\n"
    "\t\treturn false;\n"
    "\n"
    "\tif (inode && susfs_is_inode_sus_path(inode))\n"
    "\t\treturn true;\n"
    "\n"
    "\tif (!mnt)\n"
    "\t\treturn false;\n"
    "\n"
    "\tm = real_mount(mnt);\n"
    "\tif (m && m->mnt_id >= DEFAULT_KSU_MNT_ID)\n"
    "\t\treturn true;\n"
    "\n"
    "\treturn false;\n"
    "}\n"
    "\n"
)

# --- fs/statfs.c -----------------------------------------------------------
STATFS_DECL_ANCHOR = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "extern struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt);\n"
    "#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
)

STATFS_DECL_ADD = (
    "\n"
    "#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n"
    "extern bool " + HELPER + "(struct inode *inode, struct vfsmount *mnt); /* ABK " + MARKER + " */\n"
    "\n"
    "/* ABK " + MARKER + ": statfs on a path/mount we hide must answer ENOENT\n"
    " * instead of leaking a permission error.  Only an app-uid caller that\n"
    " * passed the sus_path gate and targets one of our hidden inodes/mounts\n"
    " * is remapped; every other errno is returned unchanged.\n"
    " */\n"
    "static int " + STATFS_HELPER + "(const struct path *path, int error)\n"
    "{\n"
    "\tif (unlikely((error == -EACCES || error == -EPERM) &&\n"
    "\t\t     " + HELPER + "(d_backing_inode(path->dentry), path->mnt)))\n"
    "\t\treturn -ENOENT;\n"
    "\treturn error;\n"
    "}\n"
    "#else\n"
    "#define " + STATFS_HELPER + "(path, error) (error)\n"
    "#endif // CONFIG_KSU_SUSFS_SUS_PATH\n"
)

# susfs4ksu gki-android14-6.1 before/after the extra vfsmount argument
STATFS_KSTAT_PAIRS = (
    (
        "\t\t\treturn susfs_statfs_by_dentry(path->dentry, path->mnt, buf, &is_fuse);\n",
        "\t\t\treturn " + STATFS_HELPER + "(path,\n"
        "\t\t\t\tsusfs_statfs_by_dentry(path->dentry, path->mnt, buf, &is_fuse));\n",
    ),
    (
        "\t\t\treturn susfs_statfs_by_dentry(path->dentry, buf, &is_fuse);\n",
        "\t\t\treturn " + STATFS_HELPER + "(path,\n"
        "\t\t\t\tsusfs_statfs_by_dentry(path->dentry, buf, &is_fuse));\n",
    ),
)

STATFS_MNT_SAME_OLD = (
    "\t\t\terror = statfs_by_dentry(path->dentry, buf);\n"
    "\t\t\tif (!error)\n"
    "\t\t\t\tbuf->f_flags = calculate_f_flags(path->mnt);\n"
    "\t\t\treturn error;\n"
)
STATFS_MNT_SAME_NEW = (
    "\t\t\terror = statfs_by_dentry(path->dentry, buf);\n"
    "\t\t\tif (!error)\n"
    "\t\t\t\tbuf->f_flags = calculate_f_flags(path->mnt);\n"
    "\t\t\treturn " + STATFS_HELPER + "(path, error);\n"
)

STATFS_MNT_NOSUS_OLD = (
    "\t\terror = statfs_by_dentry(no_sus_vfsmnt->mnt_root, buf);\n"
    "\t\tif (!error)\n"
    "\t\t\tbuf->f_flags = calculate_f_flags(no_sus_vfsmnt);\n"
    "\t\tdput(no_sus_vfsmnt->mnt_root);\n"
    "\t\tmntput(no_sus_vfsmnt);\n"
    "\t\treturn error;\n"
)
STATFS_MNT_NOSUS_NEW = (
    "\t\terror = statfs_by_dentry(no_sus_vfsmnt->mnt_root, buf);\n"
    "\t\tif (!error)\n"
    "\t\t\tbuf->f_flags = calculate_f_flags(no_sus_vfsmnt);\n"
    "\t\tdput(no_sus_vfsmnt->mnt_root);\n"
    "\t\tmntput(no_sus_vfsmnt);\n"
    "\t\treturn " + STATFS_HELPER + "(path, error);\n"
)

STATFS_PLAIN_OLD = (
    "\terror = statfs_by_dentry(path->dentry, buf);\n"
    "\tif (!error)\n"
    "\t\tbuf->f_flags = calculate_f_flags(path->mnt);\n"
    "\treturn error;\n"
)
STATFS_PLAIN_NEW = (
    "\terror = statfs_by_dentry(path->dentry, buf);\n"
    "\tif (!error)\n"
    "\t\tbuf->f_flags = calculate_f_flags(path->mnt);\n"
    "\treturn " + STATFS_HELPER + "(path, error);\n"
)

# --- fs/namei.c ------------------------------------------------------------
NAMEI_DECL_ANCHOR = "extern const struct qstr susfs_fake_qstr_name;\n"
NAMEI_DECL_ADD = (
    NAMEI_DECL_ANCHOR
    + "extern bool " + HELPER + "(struct inode *inode, struct vfsmount *mnt); /* ABK " + MARKER + " */\n"
)

NAMEI_SIG_OLD = (
    "int inode_permission(struct user_namespace *mnt_userns,\n"
    "\t\t     struct inode *inode, int mask)\n"
    "{\n"
)
NAMEI_SIG_NEW = (
    "static int " + NAMEI_ORIG + "(struct user_namespace *mnt_userns,\n"
    "\t\t     struct inode *inode, int mask)\n"
    "{\n"
)

NAMEI_TAIL_OLD = (
    "\treturn security_inode_permission(inode, mask);\n"
    "}\n"
)
NAMEI_TAIL_NEW = (
    "\treturn security_inode_permission(inode, mask);\n"
    "}\n"
    "\n"
    "int inode_permission(struct user_namespace *mnt_userns,\n"
    "\t\t     struct inode *inode, int mask)\n"
    "{\n"
    "\tint retval = " + NAMEI_ORIG + "(mnt_userns, inode, mask);\n"
    "\n"
    "#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n"
    "\tif (unlikely((retval == -EACCES || retval == -EPERM) &&\n"
    "\t\t     " + HELPER + "(inode, NULL)))\n"
    "\t\tretval = -ENOENT;\n"
    "#endif\n"
    "\treturn retval;\n"
    "}\n"
)


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


def sub_any(text, pairs, path, label):
    hits = [(old, new) for old, new in pairs if text.count(old) == 1]
    if len(hits) != 1:
        die("anchor '" + label + "' matched " + str(len(hits)) +
            " known variants (expected exactly 1) in " + path)
    old, new = hits[0]
    return text.replace(old, new, 1)


def patch_hdr(path):
    text = load(path)
    if MARKER in text:
        return "skip"
    save(path, sub_one(text, HDR_ANCHOR, HDR_ANCHOR + HDR_ADD, path,
                       "susfs_add_sus_path_loop prototype"))
    return "patch"


def patch_src(path):
    text = load(path)
    if MARKER in text:
        return "skip"
    if "susfs_is_current_app_proc_target" not in text:
        die("the ABK app-uid gate is missing from " + path +
            "; run patch_susfs_app_uid_gate.py before this patcher")
    if "SUS_PATH_UID_HLIST" not in text:
        die("the ABK per-UID sus_path table is missing from " + path +
            "; run patch_susfs_hide_from_uid.py before this patcher")
    save(path, sub_one(text, SRC_ANCHOR,
                       SRC_TAIL + SRC_HELPER + "int susfs_get_data_path(struct path *path) {",
                       path, "susfs_is_inode_sus_path tail"))
    return "patch"


def patch_statfs(path):
    text = load(path)
    if MARKER in text:
        return "skip"
    if "susfs_sus_kstat_spoof_vfs_statfs" not in text:
        die("fs/statfs.c lacks the SUSFS kstat statfs hook; unexpected kernel baseline")
    text = sub_one(text, STATFS_DECL_ANCHOR, STATFS_DECL_ANCHOR + STATFS_DECL_ADD, path,
                   "susfs_get_non_sus_vfsmnt_from_vfsmnt declaration")
    text = sub_any(text, STATFS_KSTAT_PAIRS, path, "sus_kstat statfs return")
    text = sub_one(text, STATFS_MNT_SAME_OLD, STATFS_MNT_SAME_NEW, path,
                   "statfs same-mount return")
    text = sub_one(text, STATFS_MNT_NOSUS_OLD, STATFS_MNT_NOSUS_NEW, path,
                   "statfs non-sus-mount return")
    text = sub_one(text, STATFS_PLAIN_OLD, STATFS_PLAIN_NEW, path, "statfs plain return")
    save(path, text)
    return "patch"


def patch_namei(path):
    text = load(path)
    if MARKER in text:
        return "skip"
    if NAMEI_SIG_OLD not in text:
        die("anchor 'inode_permission(struct user_namespace *, struct inode *, int)' "
            "not found in " + path + "; this hook targets GKI android14-6.1")
    text = sub_one(text, NAMEI_DECL_ANCHOR, NAMEI_DECL_ADD, path,
                   "susfs_fake_qstr_name declaration")
    text = sub_one(text, NAMEI_SIG_OLD, NAMEI_SIG_NEW, path, "inode_permission signature")
    text = sub_one(text, NAMEI_TAIL_OLD, NAMEI_TAIL_NEW, path, "inode_permission tail")
    save(path, text)
    return "patch"


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_enoent_map.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if all(os.path.isfile(os.path.join(candidate, rel)) for rel in REL.values()):
            base = candidate
            break
    if base is None:
        die("kernel tree incomplete under " + root +
            " (need fs/susfs.c, fs/statfs.c, fs/namei.c, include/linux/susfs.h)")

    hdr = os.path.join(base, REL["hdr"])
    src = os.path.join(base, REL["src"])
    statfs = os.path.join(base, REL["statfs"])
    namei = os.path.join(base, REL["namei"])

    print("[ABK] kernel tree: " + base)
    for label, fn, path in (("susfs.h", patch_hdr, hdr), ("susfs.c", patch_src, src),
                            ("statfs.c", patch_statfs, statfs),
                            ("namei.c", patch_namei, namei)):
        print("[ABK] " + fn(path) + ": " + path)

    # ---- verification ----------------------------------------------------
    h = load(hdr)
    if ("bool " + HELPER + "(struct inode *inode, struct vfsmount *mnt);") not in h:
        die("verification failed: " + HELPER + " prototype missing from " + hdr)

    s = load(src)
    for needle, label in (
        ("bool " + HELPER + "(struct inode *inode, struct vfsmount *mnt)\n{", "helper definition"),
        ("susfs_is_current_app_proc_target()", "app-uid gate"),
        ("real_mount(mnt)", "sus mount test"),
        ("m->mnt_id >= DEFAULT_KSU_MNT_ID", "sus mount id"),
    ):
        if needle not in s:
            die("verification failed: " + label + " missing from " + src)
    if s.count(HELPER) != 1:
        die("verification failed: " + HELPER + " referenced " + str(s.count(HELPER)) +
            " times in " + src + " (expected 1: the definition)")

    st = load(statfs)
    for needle, label in (
        ("static int " + STATFS_HELPER + "(const struct path *path, int error)", "statfs mapper"),
        ("error == -EACCES || error == -EPERM", "errno filter"),
        ("return -ENOENT;", "ENOENT result"),
    ):
        if needle not in st:
            die("verification failed: " + label + " missing from " + statfs)
    calls = st.count("return " + STATFS_HELPER + "(path,")
    if calls != 4:
        die("verification failed: " + str(calls) + " " + STATFS_HELPER +
            "(path, ...) call sites in " + statfs + " (expected 4)")

    ni = load(namei)
    for needle, label in (
        ("static int " + NAMEI_ORIG + "(struct user_namespace *mnt_userns,", "original function"),
        ("int retval = " + NAMEI_ORIG + "(mnt_userns, inode, mask);", "wrapper call"),
        (HELPER + "(inode, NULL)", "hidden-inode test"),
    ):
        if needle not in ni:
            die("verification failed: " + label + " missing from " + namei)
    if ni.count("int inode_permission(struct user_namespace *mnt_userns,") != 1:
        die("verification failed: inode_permission wrapper count is " +
            str(ni.count("int inode_permission(struct user_namespace *mnt_userns,")) +
            " in " + namei + " (expected 1)")
    if "EXPORT_SYMBOL(inode_permission);" not in ni:
        die("verification failed: EXPORT_SYMBOL(inode_permission) missing from " + namei)

    print("[ABK] sus_path ENOENT map OK: " + MARKER +
          " (EACCES/EPERM -> ENOENT for app-uid callers on sus_path inodes/sus mounts; "
          "su/ksu + uid<10000 unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
