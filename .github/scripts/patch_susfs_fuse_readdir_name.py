#!/usr/bin/env python3
"""ABK: hide sus_path entries from FUSE directory listings (by parent + name).

Usage:
    patch_susfs_fuse_readdir_name.py <kernel_root>

Why: /sdcard on Android is a FUSE view served by MediaProvider.  The readdir
filter matches the inode number carried by the dirent (ilookup ->
AS_FLAGS_SUS_PATH), but FUSE readdir does not instantiate child inodes and the
number it reports usually does not map (often 0), so entries such as
/sdcard/xinhao stay in getdents() even though the inode carries the flag.

Instead of touching the VFS-wide struct dir_context (which every filesystem and
every readdir caller shares - that variant bootlooped), filter inside FUSE's own
readdir parser, where the directory's file/inode is available:

    fuse_emit(file, ctx, dirent)  ->  skip when (parent inode, name) is hidden

The hidden set is maintained by fs/susfs.c from every sus_path add:
add_sus_path, add_sus_path_loop (worker re-flag) and add_sus_path_hide_from, so
nothing is hard coded and this is the fallback for sus_path_loop.

Semantics mirror the inode path:
    uid < 0        global hide (root/ksu keep the view, every app uid loses it)
    mode == 1      hidden from that uid only   (hide list / per target)
    mode == 0      visible to that uid only

Touched files (relative to <kernel_root>/common):
    fs/susfs.c              name table + predicate + dir wrapper
    include/linux/susfs.h   prototypes
    fs/fuse/readdir.c       fuse_emit() filter

Run after patch_susfs_readdir_filter.py, patch 60 and
patch_susfs_hide_from_uid.py.  Re-running is a no-op.
"""
import os
import sys

MARKER = "SUS_PATH_NAME_ABK"

REL_SRC = os.path.join("fs", "susfs.c")
REL_HDR = os.path.join("include", "linux", "susfs.h")
REL_FUSE = os.path.join("fs", "fuse", "readdir.c")

HDR_ANCHOR = "void susfs_add_sus_path_loop(void __user **user_info);\n"
HDR_ADD = (
    HDR_ANCHOR +
    "/* ABK " + MARKER + ": (parent inode, name) listing filter for fuse readdir */\n"
    "bool susfs_is_name_sus_path_hidden(unsigned long parent_ino, unsigned long parent_dev,\n"
    "\t\t\t\t   const char *name, int namelen);\n"
    "bool susfs_is_name_sus_path_hidden_for_dir(struct inode *dir, const char *name, int namelen);\n"
)

SRC_ANCHOR = 'const struct qstr susfs_fake_qstr_name = QSTR_INIT("..5.u.S", 7);'

SRC_BLOCK = (
    "/* ABK " + MARKER + ": sus_path entries keyed by parent directory + name, so a\n"
    " * directory listing can filter entries whose inode the VFS never resolved\n"
    " * (fuse readdir reports numbers that ilookup() cannot map).\n"
    " */\n"
    "struct st_susfs_sus_path_name {\n"
    "\tstruct hlist_node node;\n"
    "\tunsigned long parent_ino;\n"
    "\tunsigned long parent_dev;\n"
    "\tunsigned short namelen;\n"
    "\tint uid;\n"
    "\tint mode; /* 0 = visible to uid, 1 = hidden from uid, uid < 0 = global */\n"
    "\tchar name[256];\n"
    "};\n"
    "\n"
    "static DEFINE_HASHTABLE(SUS_PATH_NAME_HLIST, 10);\n"
    "static DEFINE_MUTEX(susfs_mutex_lock_sus_path_name);\n"
    "\n"
    "static void susfs_name_path_upsert(struct dentry *dentry, int uid, int mode)\n"
    "{\n"
    "\tstruct st_susfs_sus_path_name *entry = NULL, *new_entry = NULL;\n"
    "\tstruct dentry *parent = NULL;\n"
    "\tstruct inode *pinode = NULL;\n"
    "\tconst char *name = NULL;\n"
    "\tint namelen = 0;\n"
    "\n"
    "\tif (!dentry || !dentry->d_inode)\n"
    "\t\treturn;\n"
    "\tname = dentry->d_name.name;\n"
    "\tnamelen = dentry->d_name.len;\n"
    "\tif (!name || namelen <= 0 || namelen >= 256)\n"
    "\t\treturn;\n"
    "\n"
    "\tparent = dget_parent(dentry);\n"
    "\tif (!parent)\n"
    "\t\treturn;\n"
    "\tpinode = d_inode(parent);\n"
    "\tif (!pinode)\n"
    "\t\tgoto out_put_parent;\n"
    "\n"
    "\tmutex_lock(&susfs_mutex_lock_sus_path_name);\n"
    "\thash_for_each_possible(SUS_PATH_NAME_HLIST, entry, node, pinode->i_ino) {\n"
    "\t\tif (entry->parent_ino == pinode->i_ino &&\n"
    "\t\t    entry->parent_dev == pinode->i_sb->s_dev &&\n"
    "\t\t    entry->namelen == namelen &&\n"
    "\t\t    !memcmp(entry->name, name, namelen) &&\n"
    "\t\t    entry->uid == uid) {\n"
    "\t\t\tentry->mode = mode;\n"
    "\t\t\tmutex_unlock(&susfs_mutex_lock_sus_path_name);\n"
    "\t\t\tgoto out_put_parent;\n"
    "\t\t}\n"
    "\t}\n"
    "\n"
    "\tnew_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);\n"
    "\tif (!new_entry) {\n"
    "\t\tmutex_unlock(&susfs_mutex_lock_sus_path_name);\n"
    "\t\tgoto out_put_parent;\n"
    "\t}\n"
    "\tnew_entry->parent_ino = pinode->i_ino;\n"
    "\tnew_entry->parent_dev = pinode->i_sb->s_dev;\n"
    "\tnew_entry->namelen = (unsigned short)namelen;\n"
    "\tnew_entry->uid = uid;\n"
    "\tnew_entry->mode = mode;\n"
    "\tmemcpy(new_entry->name, name, namelen);\n"
    "\tnew_entry->name[namelen] = '\\0';\n"
    "\thash_add_rcu(SUS_PATH_NAME_HLIST, &new_entry->node, new_entry->parent_ino);\n"
    "\tmutex_unlock(&susfs_mutex_lock_sus_path_name);\n"
    "\n"
    "out_put_parent:\n"
    "\tdput(parent);\n"
    "}\n"
    "\n"
    "bool susfs_is_name_sus_path_hidden(unsigned long parent_ino, unsigned long parent_dev,\n"
    "\t\t\t\t   const char *name, int namelen)\n"
    "{\n"
    "\tstruct st_susfs_sus_path_name *entry = NULL;\n"
    "\tuid_t uid;\n"
    "\tbool denied = false, allowed = false, other = false, global = false;\n"
    "\n"
    "\tif (!namelen || !name || !parent_ino)\n"
    "\t\treturn false;\n"
    "\tif (!susfs_is_current_app_uid() || susfs_is_current_ksu_domain())\n"
    "\t\treturn false;\n"
    "\tuid = current_uid().val;\n"
    "\n"
    "\trcu_read_lock();\n"
    "\thash_for_each_possible_rcu(SUS_PATH_NAME_HLIST, entry, node, parent_ino) {\n"
    "\t\tif (entry->parent_ino != parent_ino || entry->parent_dev != parent_dev)\n"
    "\t\t\tcontinue;\n"
    "\t\tif (entry->namelen != namelen || memcmp(entry->name, name, namelen))\n"
    "\t\t\tcontinue;\n"
    "\t\tif (entry->uid < 0) {\n"
    "\t\t\t/* global sus_path (add_sus_path <path> -1) */\n"
    "\t\t\tglobal = true;\n"
    "\t\t\tcontinue;\n"
    "\t\t}\n"
    "\t\tif ((uid_t)entry->uid == uid) {\n"
    "\t\t\tif (entry->mode == 1) {\n"
    "\t\t\t\tdenied = true;\n"
    "\t\t\t\tbreak;\n"
    "\t\t\t}\n"
    "\t\t\tallowed = true;\n"
    "\t\t} else if (entry->mode == 0) {\n"
    "\t\t\tother = true;\n"
    "\t\t}\n"
    "\t}\n"
    "\trcu_read_unlock();\n"
    "\n"
    "\tif (denied || global || (other && !allowed)) {\n"
    "\t\tSUSFS_LOGI(\"readdir: hiding name '%s' (parent ino '%lu') from uid '%u'\\n\",\n"
    "\t\t\t    name, parent_ino, uid);\n"
    "\t\treturn true;\n"
    "\t}\n"
    "\treturn false;\n"
    "}\n"
    "\n"
    "bool susfs_is_name_sus_path_hidden_for_dir(struct inode *dir, const char *name, int namelen)\n"
    "{\n"
    "\tif (!dir || !dir->i_sb)\n"
    "\t\treturn false;\n"
    "\treturn susfs_is_name_sus_path_hidden(dir->i_ino, dir->i_sb->s_dev, name, namelen);\n"
    "}\n"
    "\n"
)

FUSE_INCLUDE_ANCHOR = '#include "fuse_i.h"\n'
FUSE_INCLUDE_ADD = (
    FUSE_INCLUDE_ANCHOR +
    "#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n"
    "#include <linux/susfs.h> /* ABK " + MARKER + " */\n"
    "#endif\n"
)

FUSE_EMIT_OLD = (
    "static bool fuse_emit(struct file *file, struct dir_context *ctx,\n"
    "\t\t      struct fuse_dirent *dirent)\n"
    "{\n"
)
FUSE_EMIT_NEW = (
    "static bool fuse_emit(struct file *file, struct dir_context *ctx,\n"
    "\t\t      struct fuse_dirent *dirent)\n"
    "{\n"
    "#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n"
    "\t/* ABK " + MARKER + ": fuse readdir never instantiates the child inode,\n"
    "\t * so the inode-number based sus_path filter cannot see it; filter by\n"
    "\t * the directory inode + entry name instead. */\n"
    "\tif (susfs_is_name_sus_path_hidden_for_dir(file_inode(file),\n"
    "\t\t\t\t\t\t  dirent->name, dirent->namelen))\n"
    "\t\treturn true;\n"
    "#endif\n"
)

UPSERTS = (
    ("susfs_sus_path_uid_upsert(&fi->inode, info.uid, 0);",
     "susfs_name_path_upsert(path.dentry, info.uid, 0);"),
    ("susfs_sus_path_uid_upsert(inode, info.uid, 0);",
     "susfs_name_path_upsert(path.dentry, info.uid, 0);"),
    ("susfs_sus_path_uid_upsert(&fi->inode, info.uid, 1);",
     "susfs_name_path_upsert(path.dentry, info.uid, 1);"),
    ("susfs_sus_path_uid_upsert(inode, info.uid, 1);",
     "susfs_name_path_upsert(path.dentry, info.uid, 1);"),
    ("susfs_sus_path_uid_upsert(&fi->inode, cursor->info.uid, 0);",
     "susfs_name_path_upsert(path.dentry, cursor->info.uid, 0);"),
    ("susfs_sus_path_uid_upsert(inode, cursor->info.uid, 0);",
     "susfs_name_path_upsert(path.dentry, cursor->info.uid, 0);"),
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


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_fuse_readdir_name.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if all(os.path.isfile(os.path.join(candidate, rel))
               for rel in (REL_SRC, REL_HDR, REL_FUSE)):
            base = candidate
            break
    if base is None:
        die("kernel sources not found under " + root + " (fs/susfs.c, include/linux/susfs.h, fs/fuse/readdir.c)")

    src = os.path.join(base, REL_SRC)
    hdr = os.path.join(base, REL_HDR)
    fuse = os.path.join(base, REL_FUSE)

    if MARKER in load(hdr):
        print("[ABK] skip: " + hdr + " already carries " + MARKER)
    else:
        h = load(hdr)
        if HDR_ANCHOR not in h:
            die("anchor 'susfs_add_sus_path_loop prototype' missing from " + hdr)
        save(hdr, h.replace(HDR_ANCHOR, HDR_ADD, 1))

    s = load(src)
    if MARKER in s:
        print("[ABK] skip: " + src + " already carries " + MARKER)
    else:
        if SRC_ANCHOR not in s:
            die("anchor 'susfs_fake_qstr_name' missing from " + src)
        s = s.replace(SRC_ANCHOR, SRC_BLOCK + SRC_ANCHOR, 1)
        added = 0
        for old, new in UPSERTS:
            if old in s:
                s = s.replace(old, old + "\n\t" + new, 1)
                added += 1
        if added < 4:
            die("expected >= 4 sus_path registration sites in " + src + ", found " + str(added) +
                "; run patch 60 and patch_susfs_hide_from_uid.py first")
        save(src, s)

    f = load(fuse)
    if MARKER in f:
        print("[ABK] skip: " + fuse + " already carries " + MARKER)
    else:
        if FUSE_INCLUDE_ANCHOR not in f:
            die("anchor '#include \"fuse_i.h\"' missing from " + fuse)
        f = f.replace(FUSE_INCLUDE_ANCHOR, FUSE_INCLUDE_ADD, 1)
        if FUSE_EMIT_OLD not in f:
            die("anchor 'fuse_emit()' definition missing from " + fuse)
        f = f.replace(FUSE_EMIT_OLD, FUSE_EMIT_NEW, 1)
        save(fuse, f)

    for path, rel in ((hdr, REL_HDR), (src, REL_SRC), (fuse, REL_FUSE)):
        if MARKER not in load(path):
            die("verification failed: " + MARKER + " missing from " + rel)
    print("[ABK] SUSFS fuse readdir name filter OK: " + MARKER +
          " (fs/fuse/readdir.c fuse_emit, fed by add_sus_path / loop / hide_from)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
