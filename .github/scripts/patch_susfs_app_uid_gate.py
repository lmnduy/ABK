#!/usr/bin/env python3
"""ABK: make sus_path hiding apply to every app-uid process, not only umounted ones.

Usage:
    patch_susfs_app_uid_gate.py <kernel_root>

Background (measured against susfs4ksu gki-android14-6.1, SUSFS v2.3.0):

    susfs_is_inode_sus_path() and the ABK readdir predicate
    susfs_is_ino_sus_path_hidden() both opened with

        if (!susfs_is_current_proc_umounted_app())
                return false;

    TIF_PROC_UMOUNTED is only set by ksu on processes it explicitly unmounted.
    On this build (BakaSU + KernelSU usermode) no app process ever carries that
    flag, so neither the global (mode 0) nor the per-target (mode 1) sus_path
    entries took effect for any app, and the detector read the raw disk truth.

This patcher replaces both gates with one predicate:

    bool susfs_is_current_app_proc_target(void)
    {
            if (unlikely(!READ_ONCE(abk_sus_path_app_uid_gate)))
                    return false;
            if (susfs_is_current_ksu_domain())      /* su / ksu tools keep truth */
                    return false;
            if (!susfs_is_current_app_uid())        /* uid < 10000 untouched   */
                    return false;
            return true;
    }

Behaviour matrix:
    su / ksu domain                       -> unchanged (sees everything)
    uid < 10000 (system, root, daemons)   -> unchanged
    ordinary app (u0_aNN, uid >= 10000)   -> sus_path now hidden
    isolated app (u0_iNN, uid >= 10000)   -> sus_path now hidden

The kill switch is a plain bool defaulting to true, exposed as a standard
kernel boot parameter (no custom sysfs/proc interface is added):

    abk_sus_path_app_uid_gate=0

so a regression can be backed out by repacking the boot image with that
parameter, without rebuilding the kernel.  Where the kernel publishes
built-in parameters it is also visible as
/sys/module/kernel/parameters/abk_sus_path_app_uid_gate.

Touched file (relative to <kernel_root>, directly or under common/):
    fs/susfs.c      helper + both sus_path gates

Requires patch_susfs_readdir_filter.py to have run first (it owns the readdir
predicate).  Every missing or ambiguous anchor aborts with exit code 2 and an
::error:: line, so CI never silently ships an unpatched kernel.  Re-running is
a no-op.
"""
import os
import sys

MARKER = "SUS_PATH_APP_UID_GATE_ABK"
HELPER = "susfs_is_current_app_proc_target"
REL = os.path.join("fs", "susfs.c")

INCLUDE_ANCHOR = "#include <linux/jump_label.h>\n"
INCLUDE_ADD = INCLUDE_ANCHOR + "#include <linux/moduleparam.h> /* ABK " + MARKER + " */\n"

HELPER_ANCHOR = (
    "static inline bool is_i_uid_not_allowed(uid_t i_uid) {\n"
    "\treturn likely(current_uid().val != i_uid);\n"
    "}\n"
)

HELPER_TEXT = (
    "\n"
    "/* ABK " + MARKER + ": sus_path hiding used to be gated on\n"
    " * TIF_PROC_UMOUNTED (susfs_is_current_proc_umounted_app()).  ksu only sets\n"
    " * that flag on processes it explicitly unmounted; on this build no app\n"
    " * process ever carries it, so global (mode 0) and per-target (mode 1)\n"
    " * sus_path entries never applied to any app.  Relax the gate to \"any\n"
    " * app-uid process outside the ksu domain\":\n"
    " *   - su / ksu tooling keeps the real view (unchanged),\n"
    " *   - non-app uids (system, uid < 10000) are untouched,\n"
    " *   - ordinary and isolated app processes (uid >= 10000) are hidden.\n"
    " *\n"
    " * Default: enabled.  Boot-time override, no kernel rebuild needed:\n"
    " *     abk_sus_path_app_uid_gate=0\n"
    " */\n"
    "static bool abk_sus_path_app_uid_gate __read_mostly = true;\n"
    "core_param(abk_sus_path_app_uid_gate, abk_sus_path_app_uid_gate, bool, 0644);\n"
    "\n"
    "static inline bool " + HELPER + "(void)\n"
    "{\n"
    "\tif (unlikely(!READ_ONCE(abk_sus_path_app_uid_gate)))\n"
    "\t\treturn false;\n"
    "\tif (susfs_is_current_ksu_domain())\n"
    "\t\treturn false;\n"
    "\tif (!susfs_is_current_app_uid())\n"
    "\t\treturn false;\n"
    "\treturn true;\n"
    "}\n"
)

# susfs_is_inode_sus_path(): the inode-level check used by namei/open/readdir.
INODE_GATE = (
    "\tif (!susfs_is_current_proc_umounted_app()) {\n"
    "\t\treturn false;\n"
    "\t}\n"
)
INODE_GATE_NEW = (
    "\t/* ABK " + MARKER + ": relaxed from susfs_is_current_proc_umounted_app() */\n"
    "\tif (!" + HELPER + "()) {\n"
    "\t\treturn false;\n"
    "\t}\n"
)

# susfs_is_ino_sus_path_hidden(): the readdir/getdents fallback predicate that
# patch_susfs_readdir_filter.py installs.  Its comment is part of the anchor so
# the replacement cannot hit the inode-level gate by accident.
READDIR_GATE = (
    "\t/* cheapest check first: only umounted app processes are affected */\n"
    "\tif (!susfs_is_current_proc_umounted_app())\n"
    "\t\treturn false;\n"
)
READDIR_GATE_NEW = (
    "\t/* ABK " + MARKER + ": any app-uid process outside the ksu domain is targeted */\n"
    "\tif (!" + HELPER + "())\n"
    "\t\treturn false;\n"
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


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_app_uid_gate.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if os.path.isfile(os.path.join(candidate, REL)):
            base = candidate
            break
    if base is None:
        die("fs/susfs.c not found under " + root + " (directly or in common/)")

    path = os.path.join(base, REL)
    text = load(path)
    print("[ABK] kernel tree: " + base)

    if MARKER in text:
        print("[ABK] skip: " + path + " already carries " + MARKER)
    else:
        if "CONFIG_KSU_SUSFS_SUS_PATH" not in text:
            die("fs/susfs.c has no CONFIG_KSU_SUSFS_SUS_PATH block; the SUSFS patch is missing")
        if "susfs_is_current_ksu_domain" not in text:
            die("fs/susfs.c does not know susfs_is_current_ksu_domain(); unexpected SUSFS baseline")
        if READDIR_GATE not in text:
            die("the ABK readdir sus_path predicate is missing from " + path +
                "; run patch_susfs_readdir_filter.py before this patcher")

        text = sub_one(text, INCLUDE_ANCHOR, INCLUDE_ADD, path, "jump_label include")
        text = sub_one(text, HELPER_ANCHOR, HELPER_ANCHOR + HELPER_TEXT, path,
                       "is_i_uid_not_allowed helper")
        text = sub_one(text, INODE_GATE, INODE_GATE_NEW, path,
                       "sus_path inode gate (umounted app)")
        text = sub_one(text, READDIR_GATE, READDIR_GATE_NEW, path,
                       "readdir sus_path gate (umounted app)")
        save(path, text)
        print("[ABK] patch: " + path)

    # verification
    text = load(path)
    checks = [
        ("#include <linux/moduleparam.h> /* ABK " + MARKER + " */", "moduleparam include"),
        ("static bool abk_sus_path_app_uid_gate __read_mostly = true;", "gate default"),
        ("core_param(abk_sus_path_app_uid_gate", "boot/cmdline override"),
        ("static inline bool " + HELPER + "(void)", "predicate definition"),
        ("\tif (!" + HELPER + "()) {", "inode-level gate"),
        ("\tif (!" + HELPER + "())\n\t\treturn false;", "readdir gate"),
        ("if (susfs_is_current_ksu_domain())", "ksu-domain bypass"),
        ("if (!susfs_is_current_app_uid())", "app-uid check"),
    ]
    for needle, label in checks:
        if needle not in text:
            die("verification failed: " + label + " missing from " + path)
    if text.count(HELPER) != 3:
        die("verification failed: predicate referenced " + str(text.count(HELPER)) +
            " times (expected 3: definition + 2 gates) in " + path)
    if "if (!susfs_is_current_proc_umounted_app())" in text:
        die("verification failed: an umounted-app sus_path gate is still present in " + path)

    print("[ABK] sus_path app-uid gate OK: " + MARKER + " (" + HELPER + ", " +
          "su/ksu + uid<10000 unchanged, apps hidden)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
