#!/usr/bin/env python3
"""ABK: make statfs()/fstatfs() agree with the filtered mountinfo view.

Usage:
    patch_susfs_statfs_consistency.py <kernel_root>

Background (measured against susfs4ksu gki-android14-6.1, SUSFS v2.3.0):

  * fs/proc_namespace.c filters /proc/self/mountinfo, /proc/self/mounts and
    /proc/self/mountstats for EVERY process outside the ksu domain as soon as
    CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS is enabled:
        if (r->mnt_id >= DEFAULT_KSU_MNT_ID) return 0;

  * fs/statfs.c rewrites statfs() to the *shadowed* (non-sus) mount, but only
    when TIF_PROC_UMOUNTED is set:
        if (likely(susfs_is_current_proc_umounted())) { ... }

  A process that is not umounted (an isolated :nms/:msi probe process, or any
  app-uid process that ksu did not mark) therefore sees:
      mountinfo -> no overlay mount at /system
      statfs(/system) -> overlay f_type
  which is exactly the 'mountinfo vs statfs mismatch' class of check.

This patcher installs a single predicate that answers 'would my mountinfo view
be filtered right now?' and uses it for the statfs rewrite too:

    umounted                        -> spoof (unchanged)
    hide_sus_mnts enabled + app uid + not ksu domain -> spoof (new)
    everything else                 -> real statfs (unchanged)

So su/ksu-domain tools and non-app processes keep the real values.

Touched file (relative to <kernel_root>, directly or under common/):
    fs/statfs.c

Every missing or ambiguous anchor aborts with exit code 2 and an ::error::
line, so CI never silently ships an unpatched kernel. Re-running is a no-op.
"""
import os
import sys

MARKER = "SUS_STATFS_CONSISTENCY_ABK"
REL = os.path.join("fs", "statfs.c")

INCLUDE_ANCHOR = "#include <linux/susfs_def.h>\n"
INCLUDE_ADD = "#include <linux/susfs_def.h>\n#include <linux/jump_label.h> /* ABK " + MARKER + " */\n"

FN_ANCHOR = "int vfs_statfs(const struct path *path, struct kstatfs *buf)\n{\n"

COND_ANCHOR = ("\tif (likely(susfs_is_current_proc_umounted())) {\n"
               "\t\tstruct vfsmount *no_sus_vfsmnt = NULL;\n")

HELPER = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "/* ABK " + MARKER + ": keep statfs()/fstatfs() in sync with the mountinfo\n"
    " * view that susfs exports to non-ksu processes.\n"
    " *\n"
    " * fs/proc_namespace.c drops every mount with\n"
    " *   mnt_id >= DEFAULT_KSU_MNT_ID\n"
    " * for all processes outside the ksu domain as soon as\n"
    " * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS is enabled, but the statfs\n"
    " * rewrite in vfs_statfs() used to fire for TIF_PROC_UMOUNTED only.  An\n"
    " * isolated probe process (u0_i*) is an app-uid process that ksu never\n"
    " * marks umounted, so its mountinfo lost the overlay while statfs() still\n"
    " * reported it.  Use the same predicate for both views.\n"
    " */\n"
    "extern bool susfs_is_current_ksu_domain(void);\n"
    "extern struct static_key_false susfs_is_hide_sus_mnts_for_non_su_procs_enabled;\n"
    "\n"
    "static bool abk_statfs_must_use_non_sus_mnt(void)\n"
    "{\n"
    "\tif (likely(susfs_is_current_proc_umounted()))\n"
    "\t\treturn true;\n"
    "\tif (!static_branch_likely(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled))\n"
    "\t\treturn false;\n"
    "\tif (!susfs_is_current_app_uid())\n"
    "\t\treturn false;\n"
    "\treturn !susfs_is_current_ksu_domain();\n"
    "}\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "\n"
)

COND_REPL = "\tif (likely(abk_statfs_must_use_non_sus_mnt())) {\n"


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
        die("usage: patch_susfs_statfs_consistency.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if os.path.isfile(os.path.join(candidate, REL)):
            base = candidate
            break
    if base is None:
        die("fs/statfs.c not found under " + root + " (directly or in common/)")

    path = os.path.join(base, REL)
    text = load(path)
    print("[ABK] kernel tree: " + base)

    if MARKER in text:
        print("[ABK] skip: " + path + " already carries " + MARKER)
    else:
        if "CONFIG_KSU_SUSFS_SUS_MOUNT" not in text:
            die("fs/statfs.c has no CONFIG_KSU_SUSFS_SUS_MOUNT block; the SUSFS patch "
                "is missing or too old (expected the susfs4ksu gki-android14-6.1 hunk)")
        if "susfs_get_non_sus_vfsmnt_from_vfsmnt" not in text:
            die("fs/statfs.c lacks the susfs vfs_statfs rewrite; cannot anchor the "
                "statfs/mountinfo consistency fix")

        text = sub_one(text, INCLUDE_ANCHOR, INCLUDE_ADD, path, "susfs_def.h include")
        text = sub_one(text, FN_ANCHOR, HELPER + FN_ANCHOR, path, "vfs_statfs definition")
        text = sub_one(text, COND_ANCHOR, COND_REPL + "\t\tstruct vfsmount *no_sus_vfsmnt = NULL;\n",
                       path, "umounted-only statfs gate")
        save(path, text)
        print("[ABK] patch: " + path)

    # verification
    text = load(path)
    checks = [
        ("#include <linux/jump_label.h> /* ABK " + MARKER + " */", "jump_label include"),
        ("static bool abk_statfs_must_use_non_sus_mnt(void)", "predicate definition"),
        ("\tif (likely(abk_statfs_must_use_non_sus_mnt())) {", "vfs_statfs gate"),
        ("return !susfs_is_current_ksu_domain();", "ksu-domain bypass"),
    ]
    for needle, label in checks:
        if needle not in text:
            die("verification failed: " + label + " missing from " + path)
    if text.count("abk_statfs_must_use_non_sus_mnt") != 2:
        die("verification failed: predicate is referenced " +
            str(text.count("abk_statfs_must_use_non_sus_mnt")) + " times (expected 2)")
    if "if (likely(susfs_is_current_proc_umounted())) {\n\t\tstruct vfsmount *no_sus_vfsmnt" in text:
        die("verification failed: the old umounted-only statfs gate is still present in " + path)

    print("[ABK] statfs/mountinfo consistency OK: " + MARKER + " in " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
