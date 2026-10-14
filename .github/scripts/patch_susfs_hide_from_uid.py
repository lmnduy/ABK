#!/usr/bin/env python3
"""ABK: add per-target "hide from uid" support to the SUSFS sus_path feature.

Usage:
    patch_susfs_hide_from_uid.py <susfs4ksu_dir>

Edits the susfs4ksu checkout used by the ABK kernel build so a path can be
hidden from ONE specific uid (per-target) instead of being hidden globally.

Touched files (relative to <susfs4ksu_dir>):
    kernel_patches/include/linux/susfs_def.h
    kernel_patches/include/linux/susfs.h
    kernel_patches/fs/susfs.c
    kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch
    ksu_susfs/jni/features/sus_path.c
    ksu_susfs/jni/features/sus_path.h
    ksu_susfs/jni/main.c

Every missing or ambiguous anchor aborts with exit code 2 and an ::error:: line,
so CI never silently ships an unpatched kernel. Re-running is a no-op.
"""
import os
import re
import sys

MARKER = "SUS_PATH_UID_HIDE_FROM_ABK"
CMD = "CMD_SUSFS_ADD_SUS_PATH_HIDE_FROM"
FLAG = "AS_FLAGS_SUS_PATH_HIDE_FROM"
HANDLER = "susfs_add_sus_path_hide_from"

REL = {
    "def": "kernel_patches/include/linux/susfs_def.h",
    "hdr": "kernel_patches/include/linux/susfs.h",
    "src": "kernel_patches/fs/susfs.c",
    "ksu": "kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch",
    "cli": "ksu_susfs/jni/features/sus_path.c",
    "clih": "ksu_susfs/jni/features/sus_path.h",
    "clim": "ksu_susfs/jni/main.c",
}

MODE_FIELD = "\tint                                     mode; /* ABK " + MARKER + ": 0=allow(visible), 1=deny(hidden) */\n"

IS_DENIED = (
    "\n"
    "/* ABK " + MARKER + ": deny the path for one specific uid only */\n"
    "static bool susfs_sus_path_uid_is_denied(struct inode *inode) {\n"
    "\tstruct st_susfs_sus_path_hlist *entry = NULL;\n"
    "\tbool denied = false;\n"
    "\n"
    "\tif (!inode)\n"
    "\t\treturn false;\n"
    "\n"
    "\trcu_read_lock();\n"
    "\thash_for_each_possible_rcu(SUS_PATH_UID_HLIST, entry, node, inode->i_ino) {\n"
    "\t\tif (entry->target_ino == inode->i_ino &&\n"
    "\t\t\tentry->target_dev == inode->i_sb->s_dev &&\n"
    "\t\t\tentry->mode == 1 &&\n"
    "\t\t\t(uid_t)entry->allowed_uid == current_uid().val)\n"
    "\t\t{\n"
    "\t\t\tdenied = true;\n"
    "\t\t\tbreak;\n"
    "\t\t}\n"
    "\t}\n"
    "\trcu_read_unlock();\n"
    "\treturn denied;\n"
    "}\n"
)

FUSE_TAIL_RE = (
    r"(\tif \(inode->i_sb->s_magic == FUSE_SUPER_MAGIC\) \{\n"
    r"\t\tfi = get_fuse_inode\(inode\);\n"
    r"\t\tif \(!fi \|\| !fi->inode\.i_mapping\) \{\n"
    r"\t\t\tSUSFS_LOGE\(\"fi \|\| fi->inode\.i_mapping is NULL\\n\"\);\n"
    r"\t\t\treturn false;\n"
    r"\t\t\}\n"
    r"\t\tif \(!test_bit\(AS_FLAGS_SUS_PATH, &fi->inode\.i_mapping->flags\)\) \{\n"
    r"\t\t\treturn false;\n"
    r"\t\t\}\n"
    r"\t\tsus_inode = &fi->inode;\n"
    r"\t\} else \{\n"
    r"\t\tif \(!test_bit\(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags\)\) \{\n"
    r"\t\t\treturn false;\n"
    r"\t\t\}\n"
    r"\t\tsus_inode = inode;\n"
    r"\t\}\n)"
)

NEW_FUSE_BLOCK = (
    "\tif (inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {\n"
    "\t\tfi = get_fuse_inode(inode);\n"
    "\t\tif (!fi || !fi->inode.i_mapping) {\n"
    "\t\t\tSUSFS_LOGE(\"fi || fi->inode.i_mapping is NULL\\n\");\n"
    "\t\t\treturn false;\n"
    "\t\t}\n"
    "\t\tsus_inode = &fi->inode;\n"
    "\t} else {\n"
    "\t\tsus_inode = inode;\n"
    "\t}\n"
    "\t/* ABK " + MARKER + ": per-target hide-from-uid deny fast path */\n"
    "\tif (unlikely(test_bit(" + FLAG + ", &sus_inode->i_mapping->flags) &&\n"
    "\t\tsusfs_sus_path_uid_is_denied(sus_inode))) {\n"
    "\t\tSUSFS_LOGI(\"hiding path with ino '%lu' from uid '%u'\\n\", inode->i_ino, current_uid().val);\n"
    "\t\treturn true;\n"
    "\t}\n"
    "\tif (!test_bit(AS_FLAGS_SUS_PATH, &sus_inode->i_mapping->flags)) {\n"
    "\t\treturn false;\n"
    "\t}\n"
)

HIDE_FROM_FN = (
    "/* ABK " + MARKER + ": hide one path from one specific uid only (no AS_FLAGS_SUS_PATH) */\n"
    "void " + HANDLER + "(void __user **user_info) {\n"
    "\tstruct st_susfs_sus_path info = {0};\n"
    "\tstruct path path;\n"
    "\tstruct inode *inode = NULL;\n"
    "\tstruct fuse_inode *fi = NULL;\n"
    "\n"
    "\tif (copy_from_user(&info, (struct st_susfs_sus_path __user*)*user_info, sizeof(info))) {\n"
    "\t\tinfo.err = -EFAULT;\n"
    "\t\tgoto out_copy_to_user;\n"
    "\t}\n"
    "\n"
    "\tif (info.uid < 0) {\n"
    "\t\tSUSFS_LOGE(\"hide_from: invalid uid '%d'\\n\", info.uid);\n"
    "\t\tinfo.err = -EINVAL;\n"
    "\t\tgoto out_copy_to_user;\n"
    "\t}\n"
    "\n"
    "\tinfo.err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);\n"
    "\tif (info.err) {\n"
    "\t\tSUSFS_LOGE(\"failed opening file '%s'\\n\", info.target_pathname);\n"
    "\t\tgoto out_copy_to_user;\n"
    "\t}\n"
    "\n"
    "\tinode = d_backing_inode(path.dentry);\n"
    "\tif (!inode || !inode->i_mapping) {\n"
    "\t\tSUSFS_LOGE(\"inode || inode->i_mapping is NULL\\n\");\n"
    "\t\tinfo.err = -ENOENT;\n"
    "\t\tgoto out_path_put_path;\n"
    "\t}\n"
    "\n"
    "\tif (inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {\n"
    "\t\tfi = get_fuse_inode(inode);\n"
    "\t\tif (!fi || !fi->inode.i_mapping) {\n"
    "\t\t\tSUSFS_LOGE(\"fi || fi->inode.i_mapping is NULL\\n\");\n"
    "\t\t\tinfo.err = -ENOENT;\n"
    "\t\t\tgoto out_path_put_path;\n"
    "\t\t}\n"
    "\t\tset_bit(" + FLAG + ", &fi->inode.i_mapping->flags);\n"
    "\t\tset_bit(" + FLAG + ", &inode->i_mapping->flags);\n"
    "\t\tsusfs_sus_path_uid_upsert(&fi->inode, info.uid, 1);\n"
    "\t\tSUSFS_LOGI(\"flagged " + FLAG + " on pathname: '%s', fi->inode.i_ino: %lu, uid: %d\\n\",\n"
    "\t\t\t\t\tinfo.target_pathname, fi->inode.i_ino, info.uid);\n"
    "\t\tinfo.err = 0;\n"
    "\t\tgoto out_path_put_path;\n"
    "\t}\n"
    "\n"
    "\tset_bit(" + FLAG + ", &inode->i_mapping->flags);\n"
    "\tsusfs_sus_path_uid_upsert(inode, info.uid, 1);\n"
    "\tSUSFS_LOGI(\"flagged " + FLAG + " on pathname: '%s', ino: '%lu', uid: %d\\n\",\n"
    "\t\t\t\tinfo.target_pathname, inode->i_ino, info.uid);\n"
    "\tinfo.err = 0;\n"
    "out_path_put_path:\n"
    "\tpath_put(&path);\n"
    "out_copy_to_user:\n"
    "\tif (copy_to_user(&((struct st_susfs_sus_path __user*)*user_info)->err, &info.err, sizeof(info.err))) {\n"
    "\t\tinfo.err = -EFAULT;\n"
    "\t}\n"
    "\tSUSFS_LOGI(\"" + CMD + " -> ret: %d\\n\", info.err);\n"
    "}\n"
)

HELP_RE = r"(\tlog\(\"\\n\"\);\n\}\n\nstatic void print_help\(void\)\{)"

HELP_LINES = (
    "\tlog(\"    add_sus_path_hide_from </path/of/file_or_directory> <uid>\\n\");\n"
    "\tlog(\"      |--> Added path and all its sub-paths are hidden ONLY from the given uid, other app procs still see it (per-target hide)\\n\");\n"
    "\tlog(\"      |--> <uid> is REQUIRED; combine with add_sus_path to hide a path from everyone except one uid\\n\");\n"
    "\tlog(\"      * Important Notes *\\n\");\n"
    "\tlog(\"      - Only effective for umounted process with uid >= 10000\\n\");\n"
)

CLI_FN = (
    "int " + HANDLER + "(int argc, char *argv[]) {\n"
    "\tstruct st_susfs_sus_path info = {0};\n"
    "\tchar resolved_pathname[PATH_MAX];\n"
    "\n"
    "\tif (argc != 4) {\n"
    "\t\tprint_help();\n"
    "\t\treturn -EINVAL;\n"
    "\t}\n"
    "\n"
    "\tif (*argv[2] == '\\0') {\n"
    "\t\tlog(\"[-] argv[2] is empty'\\n\");\n"
    "\t\treturn -EINVAL;\n"
    "\t}\n"
    "\n"
    "\tif (!realpath(argv[2], resolved_pathname)) {\n"
    "\t\tlog(\"[-] failed to get realpath from path: %s\\n\", argv[2]);\n"
    "\t\treturn errno;\n"
    "\t}\n"
    "\n"
    "\tinfo.uid = (int)strtol(argv[3], NULL, 10);\n"
    "\tif (info.uid < 0) {\n"
    "\t\tlog(\"[-] invalid uid: %s\\n\", argv[3]);\n"
    "\t\treturn -EINVAL;\n"
    "\t}\n"
    "\tstrncpy(info.target_pathname, resolved_pathname, SUSFS_MAX_LEN_PATHNAME-1);\n"
    "\tinfo.err = ERR_CMD_NOT_SUPPORTED;\n"
    "\tsyscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, " + CMD + ", &info);\n"
    "\tPRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, " + CMD + ");\n"
    "\treturn info.err;\n"
    "}\n"
)


def die(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(2)


def load(root, key):
    p = os.path.join(root, REL[key])
    if not os.path.isfile(p):
        die("expected file not found: " + REL[key])
    with open(p, "r", encoding="utf-8", newline="") as fh:
        return p, fh.read()


def save(p, text):
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def sub_re(text, pattern, repl, p, label):
    found = re.findall(pattern, text)
    if len(found) != 1:
        die("anchor '" + label + "' matched " + str(len(found)) + " times (expected 1) in " + p)
    return re.sub(pattern, repl, text, count=1)


def patch_def(root):
    p, text = load(root, "def")
    if MARKER in text:
        return "skip", REL["def"]
    text = sub_re(text, r"(#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553\n)",
                  lambda m: m.group(1) + "#define " + CMD + " 0x55554 /* ABK " + MARKER + " */\n",
                  p, "CMD_SUSFS_ADD_SUS_PATH_LOOP")
    text = sub_re(text, r"(#define AS_FLAGS_SUS_PATH\s+33\n)",
                  lambda m: m.group(1) + "#define " + FLAG + " 37 /* ABK " + MARKER + " */\n",
                  p, "AS_FLAGS_SUS_PATH")
    save(p, text)
    return "patch", REL["def"]


def patch_hdr(root):
    p, text = load(root, "hdr")
    if MARKER in text:
        return "skip", REL["hdr"]
    text = sub_re(text, r"(\tint\s+allowed_uid;\n)(\};)",
                  lambda m: m.group(1) + MODE_FIELD + m.group(2),
                  p, "st_susfs_sus_path_hlist allowed_uid")
    text = sub_re(text, r"(void susfs_add_sus_path_loop\(void __user \*\*user_info\);\n)",
                  lambda m: m.group(1) + "void " + HANDLER + "(void __user **user_info); /* ABK " + MARKER + " */\n",
                  p, "susfs_add_sus_path_loop prototype")
    save(p, text)
    return "patch", REL["hdr"]


def patch_src(root):
    p, text = load(root, "src")
    if MARKER in text:
        return "skip", REL["src"]

    text = sub_re(text, r"(static void susfs_sus_path_uid_upsert\(struct inode \*inode, int allowed_uid\);\n)",
                  lambda m: "static void susfs_sus_path_uid_upsert(struct inode *inode, int uid, int mode); /* ABK " + MARKER + " */\n",
                  p, "upsert forward declaration")

    text = sub_re(text, r"(\t\tsusfs_sus_path_uid_upsert\(&fi->inode, info\.uid\);\n)",
                  lambda m: "\t\tsusfs_sus_path_uid_upsert(&fi->inode, info.uid, 0);\n",
                  p, "upsert call fuse/add")

    text = sub_re(text, r"(\tsusfs_sus_path_uid_upsert\(inode, info\.uid\);\n)",
                  lambda m: "\tsusfs_sus_path_uid_upsert(inode, info.uid, 0);\n",
                  p, "upsert call add")

    text = sub_re(text, r"(\t\t\t\tsusfs_sus_path_uid_upsert\(&fi->inode, cursor->info\.uid\);\n)",
                  lambda m: "\t\t\t\tsusfs_sus_path_uid_upsert(&fi->inode, cursor->info.uid, 0);\n",
                  p, "upsert call loop/fuse")

    text = sub_re(text, r"(\t\t\t\tsusfs_sus_path_uid_upsert\(inode, cursor->info\.uid\);\n)",
                  lambda m: "\t\t\t\tsusfs_sus_path_uid_upsert(inode, cursor->info.uid, 0);\n",
                  p, "upsert call loop")

    text = sub_re(text, r"(\t\t\tentry->target_dev == inode->i_sb->s_dev &&\n)",
                  lambda m: m.group(1) + "\t\t\tentry->mode == 0 &&\n",
                  p, "is_allowed mode gate")

    text = sub_re(text, r"(\trcu_read_unlock\(\);\n\treturn allowed;\n\}\n)",
                  lambda m: m.group(1) + IS_DENIED,
                  p, "is_denied insertion")

    text = sub_re(text, r"(static void susfs_sus_path_uid_upsert\(struct inode \*inode, int allowed_uid\) \{\n)",
                  lambda m: "static void susfs_sus_path_uid_upsert(struct inode *inode, int uid, int mode) {\n",
                  p, "upsert definition signature")

    text = sub_re(text, r"(if \(!inode \|\| allowed_uid < 0\)\n\t\treturn;\n)",
                  lambda m: "if (!inode || uid < 0)\n\t\treturn;\n",
                  p, "upsert guard")

    text = sub_re(text, r"(entry->target_dev == inode->i_sb->s_dev\)\n\t\t\{\n\t\t\tentry->allowed_uid = allowed_uid;\n)",
                  lambda m: "entry->target_dev == inode->i_sb->s_dev &&\n\t\t\tentry->allowed_uid == uid)\n\t\t{\n\t\t\tentry->mode = mode;\n",
                  p, "upsert match block")

    text = sub_re(text, r"(\t\tentry->allowed_uid = allowed_uid;\n\t\thash_add_rcu)",
                  lambda m: "\t\tentry->allowed_uid = uid;\n\t\tentry->mode = mode;\n\t\thash_add_rcu",
                  p, "upsert alloc block")

    text = sub_re(text, r"(SUSFS_LOGI\(\"sus_path visible-to-uid set: ino '%lu', dev '%u', allowed_uid '%d'\\n\",\n\t\t\tinode->i_ino, inode->i_sb->s_dev, allowed_uid\);\n)",
                  lambda m: "SUSFS_LOGI(\"sus_path uid entry set: ino '%lu', dev '%u', uid '%d', mode '%d'\\n\",\n\t\t\tinode->i_ino, inode->i_sb->s_dev, uid, mode);\n",
                  p, "upsert log line")

    text = sub_re(text, FUSE_TAIL_RE,
                  lambda m: NEW_FUSE_BLOCK,
                  p, "susfs_is_inode_sus_path fuse block")

    text = sub_re(text, r"(\tSUSFS_LOGI\(\"CMD_SUSFS_ADD_SUS_PATH -> ret: %d\\n\", info\.err\);\n\}\n\nvoid susfs_add_sus_path_loop)",
                  lambda m: "\tSUSFS_LOGI(\"CMD_SUSFS_ADD_SUS_PATH -> ret: %d\\n\", info.err);\n}\n\n" + HIDE_FROM_FN + "\nvoid susfs_add_sus_path_loop",
                  p, "hide_from handler insertion")

    save(p, text)
    return "patch", REL["src"]


def patch_ksu(root):
    p, text = load(root, "ksu")
    if CMD in text:
        return "skip", REL["ksu"]
    text = sub_re(text, r"(\+            case CMD_SUSFS_ADD_SUS_PATH_LOOP:\n\+                susfs_add_sus_path_loop\(arg\);\n\+                return 0;\n)",
                  lambda m: m.group(1) + "+            case " + CMD + ":\n+                " + HANDLER + "(arg);\n+                return 0;\n",
                  p, "supercall dispatch")
    save(p, text)
    return "patch", REL["ksu"]


def patch_cli(root):
    p, text = load(root, "cli")
    if MARKER in text:
        return "skip", REL["cli"]
    text = sub_re(text, r"(#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553\n)",
                  lambda m: m.group(1) + "#define " + CMD + " 0x55554 /* ABK " + MARKER + " */\n",
                  p, "CLI CMD define")
    text = sub_re(text, HELP_RE, lambda m: HELP_LINES + m.group(1), p, "CLI help text")
    text = sub_re(text, r"(PRT_MSG_IF_CMD_NOT_SUPPORTED\(info\.err, CMD_SUSFS_ADD_SUS_PATH_LOOP\);\n\treturn info\.err;\n\}\n)",
                  lambda m: m.group(1) + "\n" + CLI_FN,
                  p, "CLI hide_from function")
    save(p, text)
    return "patch", REL["cli"]


def patch_clih(root):
    p, text = load(root, "clih")
    if HANDLER in text:
        return "skip", REL["clih"]
    text = sub_re(text, r"(int add_sus_path_loop\(int argc, char \*argv\[\]\);\n)",
                  lambda m: m.group(1) + "int " + HANDLER + "(int argc, char *argv[]); /* ABK " + MARKER + " */\n",
                  p, "CLI header prototype")
    save(p, text)
    return "patch", REL["clih"]


def patch_clim(root):
    p, text = load(root, "clim")
    if "add_sus_path_hide_from" in text:
        return "skip", REL["clim"]
    text = sub_re(text, r"(\tif \(!strcmp\(argv\[1\], \"add_sus_path_loop\"\)\)\n\t\treturn add_sus_path_loop\(argc, argv\);\n)",
                  lambda m: m.group(1) + "\tif (!strcmp(argv[1], \"add_sus_path_hide_from\"))\n\t\treturn add_sus_path_hide_from(argc, argv);\n",
                  p, "CLI dispatch table")
    save(p, text)
    return "patch", REL["clim"]


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_hide_from_uid.py <susfs4ksu_dir>")
    root = sys.argv[1]
    if not os.path.isdir(os.path.join(root, "kernel_patches")):
        die("susfs4ksu checkout not found at " + root)

    for fn in (patch_def, patch_hdr, patch_src, patch_ksu, patch_cli, patch_clih, patch_clim):
        action, rel = fn(root)
        print("[ABK] " + action + ": " + rel)

    checks = [
        ("def", CMD), ("def", FLAG),
        ("hdr", HANDLER), ("hdr", "mode;"),
        ("src", MARKER), ("src", CMD), ("src", HANDLER), ("src", FLAG),
        ("ksu", CMD), ("ksu", HANDLER),
        ("cli", CMD), ("cli", HANDLER),
        ("clih", HANDLER),
        ("clim", "add_sus_path_hide_from"),
    ]
    for key, needle in checks:
        p, text = load(root, key)
        if needle not in text:
            die("verification failed: '" + needle + "' missing from " + REL[key])

    print("[ABK] hide-from-uid sus_path patch OK: " + CMD + " / " + FLAG + " / " + HANDLER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
