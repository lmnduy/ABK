# 架构说明

## 三层隐藏

| 层 | 位置 | 作用域 | 命令 |
|---|---|---|---|
| 包可见性 | HMA-OSS（Zygisk/Java 钩子） | per-target | 由 HMA 配置生成 `targets.txt` |
| 路径 | SUSFS sus_path | per-target | `add_sus_path_hide_from <path> <target_uid>` (0x55554) |
| uid | SUSFS hidden uid | **全局** | `add_hidden_uid <uid>` (0x55555) |
| uid | 本仓库新增 | **per-target** | `add_hidden_uid_from <hidden_uid> <target_uid>` (0x55556) |

三者需要一致：如果包被隐藏、路径被隐藏，但 uid 仍能通过 `getpriority` 查到，
检测器就会判定"有隐藏行为"；反之如果 uid 被全局隐藏，其他应用也会看到异常。

## 内核数据结构

```c
struct st_susfs_hidden_uid_from {
    uid_t uid;          /* 被隐藏的 uid */
    uid_t target_uid;   /* 只有这个 uid 的进程看到 ESRCH */
    int   err;
};

struct st_susfs_hidden_uid_from_hlist {
    struct hlist_node node;
    uid_t uid;
    uid_t target_uid;
};
static DEFINE_HASHTABLE(ABK_HIDDEN_UID_FROM_HLIST, 8);
```

`abk_hidden_uid_from_upsert()` 按 `(uid, target_uid)` 去重插入，`hash_add_rcu` 写。
查询走 `hash_for_each_possible_rcu`，RCU 读锁，无睡眠。

## 查询钩子

`kernel/sys.c`：

```c
SYSCALL_DEFINE2(getpriority, int, which, int, who)
{
    ...
    if (which == PRIO_USER && who >= 0 &&
        (susfs_uid_is_hidden_from((uid_t)who, current_uid().val) ||
         susfs_uid_is_hidden((uid_t)who)))
        return -ESRCH;
    ...
}
```

`setpriority()` 同样处理。

## 门控（gate）

`susfs_uid_is_hidden_from()` 只在**普通应用进程**里生效：

```c
if (!READ_ONCE(abk_sus_path_app_uid_gate)) return false;  /* 总开关 */
if (susfs_is_current_ksu_domain())          return false;  /* su/ksu 保持真实 */
if (!susfs_is_current_app_uid())            return false;
if (uid < 10000 || caller < 10000)          return false;  /* 系统 uid 保持真实 */
```

因此 `adb shell su -c getpriority` 永远看到真实结果，方便调试。

## 为什么要 per-target

`add_hidden_uid` 的哈希只用 uid 做键，任何进程来查都是同一个答案。实践中的问题：

1. 检测器自己也可能出现在别的应用的隐藏名单里 → 它的 uid 被全局隐藏 →
   它自己的 uid 存在性探针失败 → 整轮检测 incomplete。
2. 全局隐藏会让**所有**应用的视图失真，其他检测器也能看出"某 uid 被抹掉了"。

per-target 表把"隐藏谁"和"对谁隐藏"解耦，既保持隐藏效果，又不破坏其它进程。

## 与路径层的关系

`sus_path` 的 per-target 实现（`0x55554`）用 `(ino, dev, target_uid)` 判权，
本仓库的 uid 层用 `(uid, target_uid)`，两者独立但语义对齐：
同一行 `targets.txt` 会同时产生路径对与 uid 对。

## 启动时序

* `boot-completed`：CE 存储未解锁，`/data/user/0/<pkg>` 可能不可读 → 检测器那组
  取不到 uid。脚本因此做两遍循环（先检测器 target），并在
  `/data/adb/service.d/` 放一个延时脚本，解锁后重跑一次幂等同步。
* 所有 `stat` / CLI 调用都带 `|| true`，避免未安装包让 `set -e` 中断整个循环。
