#!/usr/bin/env python3
"""ABK: let sus_map (and open_redirect) actually apply to app-uid processes.

Usage:
    patch_susfs_sus_map_app_uid.py <kernel_root>

Background (measured against susfs4ksu gki-android14-6.1, SUSFS v2.3.0):

  include/linux/susfs_def.h gates both inode predicates on TIF_PROC_UMOUNTED:

    #define SUSFS_IS_INODE_SUS_MAP(inode) \
            ... && susfs_is_current_proc_umounted_app()
    #define SUSFS_IS_INODE_OPEN_REDIRECT(inode) \
            ... && susfs_is_current_proc_umounted_app()

  Every caller (mm/memory.c, fs/proc/task_mmu.c, fs/proc/base.c map_files,
  fs/open.c) therefore ignores sus_map and open_redirect entries for any app
  process that ksu did not explicitly unmount.  On this build (BakaSU +
  KernelSU usermode) that is ALL app processes, so add_sus_map has never
  hidden a single module .so mapping.

This patcher widens both predicates to the same rule used by the other ABK
gates:

    umounted app                 -> hidden (unchanged)
    app uid + not ksu domain     -> hidden (new; includes u0_iNN isolated procs)
    su / ksu / uid < 10000       -> real view (unchanged)

Touched file (relative to <kernel_root>, directly or under common/):
    include/linux/susfs_def.h

Every missing or ambiguous anchor aborts with exit code 2 and an ::error::
line.  Re-running is a no-op.
"""
import os
import sys

MARKER = "SUS_MAP_APP_UID_GATE_ABK"
REL = os.path.join("include", "linux", "susfs_def.h")

DECL_ANCHOR = "#define DEFAULT_KSU_MNT_ID 2000000000 /* used for mounts created or single cloned by ksu process */\n"
DECL_ADD = (
    "\n"
    "#ifdef CONFIG_KSU_SUSFS\n"
    "/* ABK " + MARKER + ": the app-uid gates below need the ksu-domain test */\n"
    "extern bool susfs_is_current_ksu_domain(void);\n"
    "#endif\n"
)

MAP_OLD = (
    "#define SUSFS_IS_INODE_SUS_MAP(inode) \\\n"
    "\t\tinode && inode->i_mapping && \\\n"
    "\t\tunlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)) && \\\n"
    "\t\tsusfs_is_current_proc_umounted_app()\n"
)
MAP_NEW = (
    "#define SUSFS_IS_INODE_SUS_MAP(inode) \\\n"
    "\t\tinode && inode->i_mapping && \\\n"
    "\t\tunlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)) && \\\n"
    "\t\t(susfs_is_current_proc_umounted_app() || \\\n"
    "\t\t (susfs_is_current_app_uid() && !susfs_is_current_ksu_domain())) /* ABK " + MARKER + " */\n"
)

REDIR_OLD = (
    "#define SUSFS_IS_INODE_OPEN_REDIRECT(inode) \\\n"
    "\t\tinode && inode->i_mapping && \\\n"
    "\t\tunlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_mapping->flags)) && \\\n"
    "\t\tsusfs_is_current_proc_umounted_app()\n"
)
REDIR_NEW = (
    "#define SUSFS_IS_INODE_OPEN_REDIRECT(inode) \\\n"
    "\t\tinode && inode->i_mapping && \\\n"
    "\t\tunlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_mapping->flags)) && \\\n"
    "\t\t(susfs_is_current_proc_umounted_app() || \\\n"
    "\t\t (susfs_is_current_app_uid() && !susfs_is_current_ksu_domain())) /* ABK " + MARKER + " */\n"
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
        die("usage: patch_susfs_sus_map_app_uid.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if os.path.isfile(os.path.join(candidate, REL)):
            base = candidate
            break
    if base is None:
        die("include/linux/susfs_def.h not found under " + root + " (directly or in common/)")

    path = os.path.join(base, REL)
    text = load(path)
    print("[ABK] kernel tree: " + base)

    if MARKER in text:
        print("[ABK] skip: " + path + " already carries " + MARKER)
    else:
        if "SUSFS_IS_INODE_SUS_MAP" not in text or "AS_FLAGS_SUS_MAP" not in text:
            die("susfs_def.h has no SUSFS_IS_INODE_SUS_MAP block; the SUSFS patch is missing")
        text = sub_one(text, DECL_ANCHOR, DECL_ANCHOR + DECL_ADD, path,
                       "DEFAULT_KSU_MNT_ID define")
        text = sub_one(text, MAP_OLD, MAP_NEW, path, "SUSFS_IS_INODE_SUS_MAP macro")
        text = sub_one(text, REDIR_OLD, REDIR_NEW, path,
                       "SUSFS_IS_INODE_OPEN_REDIRECT macro")
        save(path, text)
        print("[ABK] patch: " + path)

    text = load(path)
    checks = [
        ("/* ABK " + MARKER, "marker"),
        ("extern bool susfs_is_current_ksu_domain(void);", "ksu-domain declaration"),
        ("(susfs_is_current_app_uid() && !susfs_is_current_ksu_domain())", "app-uid predicate"),
    ]
    for needle, label in checks:
        if needle not in text:
            die("verification failed: " + label + " missing from " + path)
    if text.count("susfs_is_current_app_uid() && !susfs_is_current_ksu_domain()") != 2:
        die("verification failed: expected 2 app-uid predicates (sus_map + open_redirect) in " + path)
    if "\t\tsusfs_is_current_proc_umounted_app()\n" in text:
        die("verification failed: an umounted-only SUS_MAP/OPEN_REDIRECT gate is still present in " + path)

    print("[ABK] sus_map/open_redirect app-uid gate OK: " + MARKER +
          " (" + path + ", 2 macros; apps + isolated, ksu/uid<10000 unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
