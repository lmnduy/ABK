#!/usr/bin/env python3
"""ABK: add a kernel-level hidden-UID set plus the ksu_susfs add_hidden_uid CLI.

Usage:
    patch_susfs_hidden_uid.py <susfs4ksu_dir>

Why: com.chunqiunativecheck cross-checks the PackageManager view with UID
existence oracles.  A package can be hidden from PM while its uid is still
alive, and getpriority(PRIO_USER, uid) / setpriority(PRIO_USER, uid, ...)
then answer "this uid exists" (canonical Linux UID-existence oracle).

This patcher adds:
  * CMD_SUSFS_ADD_HIDDEN_UID = 0x55555 (kernel + ksu_susfs)
  * an RCU-safe hidden-uid hash set with abk_hidden_uid_upsert() and
    bool susfs_uid_is_hidden(uid_t uid)
  * susfs_add_hidden_uid(): the supercall handler
  * ksu_susfs add_hidden_uid <uid>

The lookup is gated exactly like the sus_path app-uid gate: the caller must
be an app uid outside the ksu domain; su/system keep the truth.  The set is
add-only (rebuilt by the device scripts on every boot).

Touched files (relative to <susfs4ksu_dir>):
    kernel_patches/include/linux/susfs_def.h
    kernel_patches/include/linux/susfs.h
    kernel_patches/fs/susfs.c
    ksu_susfs/jni/features/sus_path.c
    ksu_susfs/jni/features/sus_path.h
    ksu_susfs/jni/main.c

Every missing or ambiguous anchor aborts with exit code 2 and an ::error::
line, so CI never silently ships an unpatched kernel.  Re-running is a no-op.
"""
import os
import sys

MARKER = "SUSFS_HIDDEN_UID_ABK"
CMD = "CMD_SUSFS_ADD_HIDDEN_UID"
HANDLER = "susfs_add_hidden_uid"
LOOKUP = "susfs_uid_is_hidden"
CLI = "add_hidden_uid"

REL = {
    "def": "kernel_patches/include/linux/susfs_def.h",
    "hdr": "kernel_patches/include/linux/susfs.h",
    "src": "kernel_patches/fs/susfs.c",
    "cli": "ksu_susfs/jni/features/sus_path.c",
    "clih": "ksu_susfs/jni/features/sus_path.h",
    "clim": "ksu_susfs/jni/main.c",
}

# --- susfs_def.h -----------------------------------------------------------
DEF_LOOP = "#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553\n"
DEF_HIDE = "#define CMD_SUSFS_ADD_SUS_PATH_HIDE_FROM 0x55554"
DEF_LINE = "#define " + CMD + " 0x55555 /* ABK " + MARKER + " */\n"

# --- susfs.h ---------------------------------------------------------------
HDR_INCLUDE = "#include <linux/types.h>\n"
HDR_INCLUDE_ADD = HDR_INCLUDE + "#include <linux/uidgid.h> /* ABK " + MARKER + " */\n"

HDR_STRUCT_ANCHOR = (
    "struct st_susfs_sus_path_list {\n"
    "\tstruct list_head                        list;\n"
    "\tstruct st_susfs_sus_path                info;\n"
    "\tchar                                    target_pathname[SUSFS_MAX_LEN_PATHNAME];\n"
    "};\n"
)

HDR_STRUCT_ADD = (
    "\n"
    "/* ABK " + MARKER + ": userspace ABI for the hidden-uid oracle set */\n"
    "struct st_susfs_hidden_uid {\n"
    "\tuid_t                                   uid;\n"
    "\tint                                     err;\n"
    "};\n"
    "\n"
    "struct st_susfs_hidden_uid_hlist {\n"
    "\tstruct hlist_node                       node;\n"
    "\tuid_t                                   uid;\n"
    "};\n"
)

HDR_PROTO_ANCHOR = "void susfs_add_sus_path_loop(void __user **user_info);\n"
HDR_PROTO_ADD = (
    HDR_PROTO_ANCHOR
    + "void " + HANDLER + "(void __user **user_info); /* ABK " + MARKER + " */\n"
    + "bool " + LOOKUP + "(uid_t uid); /* ABK " + MARKER + " */\n"
)

# --- fs/susfs.c ------------------------------------------------------------
SRC_GATE_ANCHOR = (
    "static inline bool is_i_uid_not_allowed(uid_t i_uid) {\n"
    "\treturn likely(current_uid().val != i_uid);\n"
    "}\n"
)

SRC_BLOCK = (
    "\n"
    "/* ABK " + MARKER + ": RCU-safe set of uids whose existence must look dead\n"
    " * to app processes.  Entries are add-only; the device scripts rebuild the\n"
    " * set on every boot via ksu_susfs add_hidden_uid <uid>.\n"
    " */\n"
    "static DEFINE_HASHTABLE(ABK_HIDDEN_UID_HLIST, 8);\n"
    "static DEFINE_MUTEX(abk_hidden_uid_mutex);\n"
    "\n"
    "static int abk_hidden_uid_upsert(uid_t uid)\n"
    "{\n"
    "\tstruct st_susfs_hidden_uid_hlist *entry = NULL;\n"
    "\tstruct st_susfs_hidden_uid_hlist *new_entry = NULL;\n"
    "\n"
    "\tmutex_lock(&abk_hidden_uid_mutex);\n"
    "\thash_for_each_possible(ABK_HIDDEN_UID_HLIST, entry, node, uid) {\n"
    "\t\tif (entry->uid == uid) {\n"
    "\t\t\tmutex_unlock(&abk_hidden_uid_mutex);\n"
    "\t\t\treturn 0;\n"
    "\t\t}\n"
    "\t}\n"
    "\n"
    "\tnew_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);\n"
    "\tif (!new_entry) {\n"
    "\t\tmutex_unlock(&abk_hidden_uid_mutex);\n"
    "\t\treturn -ENOMEM;\n"
    "\t}\n"
    "\tnew_entry->uid = uid;\n"
    "\thash_add_rcu(ABK_HIDDEN_UID_HLIST, &new_entry->node, uid);\n"
    "\tmutex_unlock(&abk_hidden_uid_mutex);\n"
    "\n"
    "\tSUSFS_LOGI(\"hidden uid set: added uid '%u'\\n\", uid);\n"
    "\treturn 0;\n"
    "}\n"
    "\n"
    "/* Same gate as the sus_path app-uid gate: su/ksu tooling and non-app uids\n"
    " * (uid < 10000) keep the full truth.  READ_ONCE/kill switch are the ones\n"
    " * installed by patch_susfs_app_uid_gate.py.\n"
    " */\n"
    "bool " + LOOKUP + "(uid_t uid)\n"
    "{\n"
    "\tstruct st_susfs_hidden_uid_hlist *entry = NULL;\n"
    "\tbool hidden = false;\n"
    "\n"
    "\tif (unlikely(!READ_ONCE(abk_sus_path_app_uid_gate)))\n"
    "\t\treturn false;\n"
    "\tif (susfs_is_current_ksu_domain())\n"
    "\t\treturn false;\n"
    "\tif (!susfs_is_current_app_uid())\n"
    "\t\treturn false;\n"
    "\tif (uid < 10000)\n"
    "\t\treturn false;\n"
    "\n"
    "\trcu_read_lock();\n"
    "\thash_for_each_possible_rcu(ABK_HIDDEN_UID_HLIST, entry, node, uid) {\n"
    "\t\tif (entry->uid == uid) {\n"
    "\t\t\thidden = true;\n"
    "\t\t\tbreak;\n"
    "\t\t}\n"
    "\t}\n"
    "\trcu_read_unlock();\n"
    "\n"
    "\treturn hidden;\n"
    "}\n"
    "\n"
    "void " + HANDLER + "(void __user **user_info)\n"
    "{\n"
    "\tstruct st_susfs_hidden_uid info = {0};\n"
    "\n"
    "\tif (copy_from_user(&info, (struct st_susfs_hidden_uid __user *)*user_info, sizeof(info))) {\n"
    "\t\tinfo.err = -EFAULT;\n"
    "\t\tgoto out_copy_to_user;\n"
    "\t}\n"
    "\n"
    "\tif (info.uid < 10000) {\n"
    "\t\tSUSFS_LOGE(\"hidden uid: rejecting non-app uid '%u'\\n\", info.uid);\n"
    "\t\tinfo.err = -EINVAL;\n"
    "\t\tgoto out_copy_to_user;\n"
    "\t}\n"
    "\n"
    "\tinfo.err = abk_hidden_uid_upsert(info.uid);\n"
    "\tSUSFS_LOGI(\"CMD_SUSFS_ADD_HIDDEN_UID -> ret: %d, uid: '%u'\\n\", info.err, info.uid);\n"
    "\n"
    "out_copy_to_user:\n"
    "\tif (copy_to_user(&((struct st_susfs_hidden_uid __user *)*user_info)->err,\n"
    "\t\t\t &info.err, sizeof(info.err)))\n"
    "\t\tinfo.err = -EFAULT;\n"
    "}\n"
)

# --- ksu_susfs/jni/features/sus_path.c ------------------------------------
CLI_STRUCT_ANCHOR = "void sus_path_print_help(void){\n"
CLI_STRUCT_ADD = (
    "/* ABK " + MARKER + ": add_hidden_uid ABI (must match include/linux/susfs.h) */\n"
    "struct st_susfs_hidden_uid {\n"
    "\tunsigned int            uid;\n"
    "\tint                     err;\n"
    "};\n"
    "\n"
)

CLI_HELP_ANCHOR = "\tlog(\"\\n\");\n}\n\nstatic void print_help(void){\n"
CLI_HELP_ADD = (
    "\tlog(\"    add_hidden_uid <uid>\\n\");\n"
    "\tlog(\"      |--> Marks a user id as hidden: getpriority(PRIO_USER, uid) / setpriority(PRIO_USER, uid, ...) return ESRCH to app processes\\n\");\n"
    "\tlog(\"      |--> su / ksu domain and uid < 10000 keep the real answer\\n\");\n"
)

CLI_TAIL_ANCHOR = (
    "\tPRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_PATH_LOOP);\n"
    "\treturn info.err;\n"
    "}\n"
)

CLI_FN = (
    "\n"
    "int " + CLI + "(int argc, char *argv[]) {\n"
    "\tstruct st_susfs_hidden_uid info = {0};\n"
    "\tchar *end = NULL;\n"
    "\tunsigned long uid;\n"
    "\n"
    "\tif (argc != 3) {\n"
    "\t\tprint_help();\n"
    "\t\treturn -EINVAL;\n"
    "\t}\n"
    "\n"
    "\terrno = 0;\n"
    "\tuid = strtoul(argv[2], &end, 10);\n"
    "\tif (errno || !end || *end != '\\0' || uid < 10000 || uid > 0xffffffffUL) {\n"
    "\t\tlog(\"[-] invalid uid: %s\\n\", argv[2]);\n"
    "\t\treturn -EINVAL;\n"
    "\t}\n"
    "\n"
    "\tinfo.uid = (unsigned int)uid;\n"
    "\tinfo.err = ERR_CMD_NOT_SUPPORTED;\n"
    "\tsyscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, " + CMD + ", &info);\n"
    "\tPRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, " + CMD + ");\n"
    "\treturn info.err;\n"
    "}\n"
)

CLIH_ANCHOR = "int add_sus_path_loop(int argc, char *argv[]);\n"
CLIH_ADD = CLIH_ANCHOR + "int " + CLI + "(int argc, char *argv[]); /* ABK " + MARKER + " */\n"

CLIM_ANCHOR = (
    "\tif (!strcmp(argv[1], \"add_sus_path_loop\"))\n"
    "\t\treturn add_sus_path_loop(argc, argv);\n"
)
CLIM_ADD = (
    CLIM_ANCHOR
    + "\tif (!strcmp(argv[1], \"" + CLI + "\"))\n"
    "\t\treturn " + CLI + "(argc, argv);\n"
)


def die(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(2)


def load(root, key):
    path = os.path.join(root, REL[key])
    if not os.path.isfile(path):
        die("expected file not found: " + REL[key])
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return path, fh.read()


def save(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def sub_one(text, needle, repl, path, label):
    count = text.count(needle)
    if count != 1:
        die("anchor '" + label + "' matched " + str(count) + " times (expected 1) in " + path)
    return text.replace(needle, repl, 1)


def insert_after_line(text, prefix, addition, path, label):
    hits = [i for i, line in enumerate(text.splitlines(True)) if line.startswith(prefix)]
    if len(hits) != 1:
        die("line anchor '" + label + "' matched " + str(len(hits)) + " times (expected 1) in " + path)
    lines = text.splitlines(True)
    i = hits[0]
    lines[i] = lines[i] + addition
    return "".join(lines)


def patch_def(root):
    path, text = load(root, "def")
    if MARKER in text:
        return "skip", REL["def"]
    if DEF_HIDE in text:
        text = insert_after_line(text, DEF_HIDE, DEF_LINE, path, DEF_HIDE)
    else:
        text = sub_one(text, DEF_LOOP, DEF_LOOP + DEF_LINE, path, "CMD_SUSFS_ADD_SUS_PATH_LOOP")
    save(path, text)
    return "patch", REL["def"]


def patch_hdr(root):
    path, text = load(root, "hdr")
    if MARKER in text:
        return "skip", REL["hdr"]
    text = sub_one(text, HDR_INCLUDE, HDR_INCLUDE_ADD, path, "linux/types.h include")
    text = sub_one(text, HDR_STRUCT_ANCHOR, HDR_STRUCT_ANCHOR + HDR_STRUCT_ADD, path,
                   "st_susfs_sus_path_list")
    text = sub_one(text, HDR_PROTO_ANCHOR, HDR_PROTO_ADD, path, "susfs_add_sus_path_loop prototype")
    save(path, text)
    return "patch", REL["hdr"]


def patch_src(root):
    path, text = load(root, "src")
    if MARKER in text:
        return "skip", REL["src"]
    text = sub_one(text, SRC_GATE_ANCHOR, SRC_GATE_ANCHOR + SRC_BLOCK, path,
                   "is_i_uid_not_allowed helper")
    save(path, text)
    return "patch", REL["src"]


def patch_cli(root):
    path, text = load(root, "cli")
    if MARKER in text:
        return "skip", REL["cli"]
    hide_def = "#define CMD_SUSFS_ADD_SUS_PATH_HIDE_FROM 0x55554"
    if hide_def in text:
        text = insert_after_line(text, hide_def, "#define " + CMD + " 0x55555 /* ABK " + MARKER + " */\n",
                                 path, hide_def)
    else:
        text = sub_one(text, DEF_LOOP, DEF_LOOP + "#define " + CMD + " 0x55555 /* ABK " + MARKER + " */\n",
                       path, "CLI CMD_SUSFS_ADD_SUS_PATH_LOOP")
    text = sub_one(text, CLI_STRUCT_ANCHOR, CLI_STRUCT_ADD + CLI_STRUCT_ANCHOR, path,
                   "sus_path_print_help")
    text = sub_one(text, CLI_HELP_ANCHOR, CLI_HELP_ADD + CLI_HELP_ANCHOR, path, "CLI help tail")
    text = sub_one(text, CLI_TAIL_ANCHOR, CLI_TAIL_ANCHOR + CLI_FN, path, "add_sus_path_loop tail")
    save(path, text)
    return "patch", REL["cli"]


def patch_clih(root):
    path, text = load(root, "clih")
    if CLI in text:
        return "skip", REL["clih"]
    text = sub_one(text, CLIH_ANCHOR, CLIH_ADD, path, "add_sus_path_loop prototype")
    save(path, text)
    return "patch", REL["clih"]


def patch_clim(root):
    path, text = load(root, "clim")
    if CLI in text:
        return "skip", REL["clim"]
    text = sub_one(text, CLIM_ANCHOR, CLIM_ADD, path, "CLI dispatch table")
    save(path, text)
    return "patch", REL["clim"]


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_hidden_uid.py <susfs4ksu_dir>")
    root = sys.argv[1]
    if not os.path.isdir(os.path.join(root, "kernel_patches")):
        die("susfs4ksu checkout not found at " + root)

    for fn in (patch_def, patch_hdr, patch_src, patch_cli, patch_clih, patch_clim):
        action, rel = fn(root)
        print("[ABK] " + action + ": " + rel)

    checks = [
        ("def", CMD),
        ("hdr", HANDLER), ("hdr", LOOKUP), ("hdr", "struct st_susfs_hidden_uid"),
        ("src", MARKER), ("src", HANDLER), ("src", LOOKUP), ("src", CMD),
        ("cli", CMD), ("cli", CLI), ("cli", "struct st_susfs_hidden_uid"),
        ("clih", CLI),
        ("clim", CLI),
    ]
    for key, needle in checks:
        path, text = load(root, key)
        if needle not in text:
            die("verification failed: '" + needle + "' missing from " + REL[key])

    path, src = load(root, "src")
    if src.count(LOOKUP) != 1:
        die("verification failed: " + LOOKUP + " referenced " + str(src.count(LOOKUP)) +
            " times (expected 1: the definition) in " + REL["src"])
    if src.index(SRC_GATE_ANCHOR) > src.index("bool " + LOOKUP + "(uid_t uid)"):
        die("verification failed: " + LOOKUP + " was inserted before its gate variables in " + REL["src"])

    print("[ABK] hidden-uid patch OK: " + CMD + " 0x55555 / " + LOOKUP + " / " + CLI)
    return 0


if __name__ == "__main__":
    sys.exit(main())
