#!/usr/bin/env python3
"""ABK: stop an app-uid process from reading a su/ksu SELinux domain from
/proc/self/attr/current.

Usage:
    patch_susfs_proc_attr_app_uid.py <kernel_root>

Background: the detector's native Binder service (libcq_mount_view.so, running
in the isolated :nms process) reads /proc/self/attr/current as one of its 128
native probes.  A process that carries u:r:su:s0 or u:r:ksu:s0 is reported as a
root/hider artifact.  Normal apps are untrusted_app, but any process that
inherited the ksu domain (an isolated service forked from a spoofed parent, or
a helper that kept the domain) leaks the name verbatim.

This patcher rewrites ONLY the case that matters, at the /proc/<pid>/attr read:

    app uid (>= 10000), current task, not ksu domain,
    value starts with "u:r:su:" or "u:r:ksu:"
        -> "u:r:untrusted_app:s0"

Everything else is returned untouched, including /proc/<pid>/attr/* of other
processes and every su/ksu tool.  The replacement is allocated with kstrdup and
the LSM-allocated string is freed with kfree, matching security_getprocattr()'s
contract for SELinux (the only LSM on Android that answers this file).

Kill switch: plain bool, default on:
    abk_proc_attr_gate=0

Touched file (relative to <kernel_root>, directly or under common/):
    fs/proc/base.c

Every missing or ambiguous anchor aborts with exit code 2 and an ::error::
line.  Re-running is a no-op.
"""
import os
import sys

MARKER = "PROC_ATTR_APP_UID_SPOOF_ABK"
REL = os.path.join("fs", "proc", "base.c")

INCLUDE_ANCHOR = "#include <linux/dma-buf.h>\n"
INCLUDE_ADD = (
    "#include <linux/dma-buf.h>\n"
    "#ifdef CONFIG_KSU_SUSFS\n"
    "#include <linux/susfs_def.h> /* ABK " + MARKER + " */\n"
    "#endif\n"
)

FN_ANCHOR = (
    "static ssize_t proc_pid_attr_read(struct file *file, char __user *buf,\n"
    "\t\t\t\t  size_t count, loff_t *ppos)\n"
)

HELPER = (
    "#ifdef CONFIG_KSU_SUSFS\n"
    "/* ABK " + MARKER + ": a su/ksu domain name must never be readable by an\n"
    " * app-uid process, not even its own.  Only that exact case is rewritten;\n"
    " * /proc/<pid>/attr of other tasks and all su/ksu tools are untouched.\n"
    " * Boot-time override: abk_proc_attr_gate=0\n"
    " */\n"
    "static bool abk_proc_attr_gate __read_mostly = true;\n"
    "core_param(abk_proc_attr_gate, abk_proc_attr_gate, bool, 0644);\n"
    "\n"
    "static ssize_t abk_proc_attr_spoof(char **value, ssize_t len)\n"
    "{\n"
    "\tchar *p, *repl;\n"
    "\n"
    "\tif (!READ_ONCE(abk_proc_attr_gate) || len <= 0 || !value || !(p = *value))\n"
    "\t\treturn len;\n"
    "\tif (!susfs_is_current_app_uid() || susfs_is_current_ksu_domain())\n"
    "\t\treturn len;\n"
    "\tif (strncmp(p, \"u:r:su:\", 7) && strncmp(p, \"u:r:ksu:\", 8))\n"
    "\t\treturn len;\n"
    "\trepl = kstrdup(\"u:r:untrusted_app:s0\", GFP_KERNEL);\n"
    "\tif (!repl)\n"
    "\t\treturn len;\n"
    "\tSUSFS_LOGI(\"proc attr: replacing su/ksu domain for app uid %u\\n\",\n"
    "\t\t\tcurrent_uid().val);\n"
    "\tkfree(p);\n"
    "\t*value = repl;\n"
    "\treturn strlen(repl);\n"
    "}\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS\n"
    "\n"
)

TAIL_OLD = (
    "\tif (length > 0)\n"
    "\t\tlength = simple_read_from_buffer(buf, count, ppos, p, length);\n"
    "\tkfree(p);\n"
    "\treturn length;\n"
    "}\n"
)
TAIL_NEW = (
    "#ifdef CONFIG_KSU_SUSFS\n"
    "\tlength = abk_proc_attr_spoof(&p, length);\n"
    "#endif\n"
    "\tif (length > 0)\n"
    "\t\tlength = simple_read_from_buffer(buf, count, ppos, p, length);\n"
    "\tkfree(p);\n"
    "\treturn length;\n"
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


def main():
    if len(sys.argv) != 2:
        die("usage: patch_susfs_proc_attr_app_uid.py <kernel_root>")
    root = sys.argv[1]
    base = None
    for candidate in (os.path.join(root, "common"), root):
        if os.path.isfile(os.path.join(candidate, REL)):
            base = candidate
            break
    if base is None:
        die("fs/proc/base.c not found under " + root + " (directly or in common/)")

    path = os.path.join(base, REL)
    text = load(path)
    print("[ABK] kernel tree: " + base)

    if MARKER in text:
        print("[ABK] skip: " + path + " already carries " + MARKER)
    else:
        if "proc_pid_attr_read" not in text:
            die("fs/proc/base.c has no proc_pid_attr_read(); unexpected kernel baseline")
        if "#include <linux/moduleparam.h>" not in text:
            text = sub_one(text, INCLUDE_ANCHOR,
                           INCLUDE_ADD + "#include <linux/moduleparam.h> /* ABK " + MARKER + " */\n",
                           path, "dma-buf include")
        else:
            text = sub_one(text, INCLUDE_ANCHOR, INCLUDE_ADD, path, "dma-buf include")
        text = sub_one(text, FN_ANCHOR, HELPER + FN_ANCHOR, path,
                       "proc_pid_attr_read definition")
        text = sub_one(text, TAIL_OLD, TAIL_NEW, path, "proc_pid_attr_read tail")
        save(path, text)
        print("[ABK] patch: " + path)

    text = load(path)
    checks = [
        ("/* ABK " + MARKER, "marker"),
        ("static ssize_t abk_proc_attr_spoof(char **value, ssize_t len)", "helper"),
        ("length = abk_proc_attr_spoof(&p, length);", "call site"),
        ("core_param(abk_proc_attr_gate", "boot parameter"),
        ('kstrdup("u:r:untrusted_app:s0", GFP_KERNEL)', "replacement context"),
    ]
    for needle, label in checks:
        if needle not in text:
            die("verification failed: " + label + " missing from " + path)
    if text.count("abk_proc_attr_spoof") != 2:
        die("verification failed: abk_proc_attr_spoof referenced " +
            str(text.count("abk_proc_attr_spoof")) + " times (expected 2: definition + call)")

    print("[ABK] proc attr app-uid spoof OK: " + MARKER +
          " (fs/proc/base.c, su/ksu domain -> untrusted_app for app uids, abk_proc_attr_gate=0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
