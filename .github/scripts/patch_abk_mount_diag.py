#!/usr/bin/env python3
"""ABK (temporary): log who reads whose mount table and which mounts get hidden.

Usage:
    patch_abk_mount_diag.py <kernel_root>

Chunqiu's native library reads /proc/self/mountinfo, /proc/self/mounts and
/proc/<pid>/mountinfo, so its "mount gap" verdict comes from comparing two mount
tables.  Our per-uid filter is applied per *reader*, and the two tables can still
differ (different namespaces, different hidden sets), which is what we need to see.

This patcher logs, for every app reader:

    mount_diag: reader=<pid>/<comm> uid=<uid> target=<pid>/<comm> view=<kind>

and, in susfs_show_mountinfo only, every mount it hides:

    mount_diag: hidden mnt_id=<id> at '<mountpoint>' parent=<id> for <comm>

Remove this step once the verdict is explained: it prints per scan and is not
meant for a release kernel.
"""
import os
import sys

MARKER = "MOUNT_DIAG_ABK"
REL = os.path.join("fs", "proc_namespace.c")

TASK_ANCHOR = "\tstruct task_struct *task = get_proc_task(inode);\n"
INCLUDE_ANCHOR = "#include <linux/sched/task.h>\n"
INCLUDE_ADD = "#include <linux/cred.h> /* ABK " + MARKER + " */\n"
TASK_ADD = (
    "\t/* ABK " + MARKER + ": reader -> target, and which view is used */\n"
    "\tif (current_uid().val >= 10000) {\n"
    "\t\tconst char *abk_view = \"other\";\n"
    "\t\tif (show == susfs_show_mountinfo)\n"
    "\t\t\tabk_view = \"filtered-mountinfo\";\n"
    "\t\telse if (show == susfs_show_vfsmnt)\n"
    "\t\t\tabk_view = \"filtered-mounts\";\n"
    "\t\telse if (show == susfs_show_vfsstat)\n"
    "\t\t\tabk_view = \"filtered-mountstats\";\n"
    "\t\telse if (show == show_mountinfo)\n"
    "\t\t\tabk_view = \"RAW-mountinfo\";\n"
    "\t\telse if (show == show_vfsmnt)\n"
    "\t\t\tabk_view = \"RAW-mounts\";\n"
    "\t\telse if (show == show_vfsstat)\n"
    "\t\t\tabk_view = \"RAW-mountstats\";\n"
    "\t\tpr_info(\"mount_diag: reader=%d/%s uid=%u target=%d/%s view=%s\\n\",\n"
    "\t\t\t   current->pid, current->comm, current_uid().val,\n"
    "\t\t\t   task ? task->pid : -1, task ? task->comm : \"?\", abk_view);\n"
    "\t}\n"
)

HIDE_OLD = (
    "\tif (r->mnt_id >= DEFAULT_KSU_MNT_ID)\n"
    "\t\treturn 0;\n"
)
HIDE_NEW = (
    "\tif (r->mnt_id >= DEFAULT_KSU_MNT_ID) {\n"
    "\t\t/* ABK " + MARKER + " */\n"
    "\t\tif (current_uid().val >= 10000)\n"
    "\t\t\tpr_info(\"mount_diag: hidden mnt_id=%i at '%.*s' parent=%i for %s\\n\",\n"
    "\t\t\t\t   r->mnt_id, r->mnt_mountpoint->d_name.len,\n"
    "\t\t\t\t   r->mnt_mountpoint->d_name.name, r->mnt_parent->mnt_id,\n"
    "\t\t\t\t   current->comm);\n"
    "\t\treturn 0;\n"
    "\t}\n"
)


def die(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        die("usage: patch_abk_mount_diag.py <kernel_root>")
    root = sys.argv[1]
    path = None
    for base in (os.path.join(root, "common"), root):
        candidate = os.path.join(base, REL)
        if os.path.isfile(candidate):
            path = candidate
            break
    if path is None:
        die("expected file not found: " + REL)

    with open(path, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    if MARKER in text:
        print("skip (already patched): " + REL)
        return 0

    if text.count(INCLUDE_ANCHOR) != 1:
        die("proc_namespace sched/task include anchor matched %d times" % text.count(INCLUDE_ANCHOR))
    text = text.replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE_ADD, 1)

    if text.count(TASK_ANCHOR) != 1:
        die("mounts_open_common task anchor matched %d times" % text.count(TASK_ANCHOR))
    text = text.replace(TASK_ANCHOR, TASK_ANCHOR + TASK_ADD, 1)

    # only the mountinfo viewer: that is the file the check parses
    hits = text.count(HIDE_OLD)
    if hits < 1:
        die("KSU mount skip anchor matched 0 times")
    text = text.replace(HIDE_OLD, HIDE_NEW)

    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    print("patch: mount diagnostics (" + MARKER + ", %d skip sites)" % hits)
    return 0


if __name__ == "__main__":
    sys.exit(main())
