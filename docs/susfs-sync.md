# 同步上游 SUSFS 的操作手册

本文记录 **ABK 对上游 simonpunk/susfs4ksu 的依赖点**，每次同步上游之前/之后按这里的清单核对，可以少踩很多坑。

适用分支：`gki-android14-6.1`（BakaSU 6.1.138 构建）。

---

## 1. 怎么同步

1. 打开 `config/config`，确认 `custom=true`，把

   ```
   gki-android14-6.1=<新 commit>
   ```

   改成上游目标提交（旧的用 `#` 注释保留，方便回退）。
2. 触发 `.github/workflows/kernel-custom.yml`（`android14 / 6.1 / 138 / 2025-06 / BakaSU`）。
3. **按下面第 2 节的顺序**盯 CI 日志，任何一步报 `::error::` 就先修那一步，不要继续往下刷机。

> 上游 SUSFS 是「移动分支」（每次都取最新），所以本文的锚点会随上游漂移；
> 补丁脚本都写成「锚点不匹配就明确报错」，不会静默产出坏内核。

---

## 2. 同步后必须核对的补丁点（按 CI 执行顺序）

| # | CI 步骤 | 脚本 | 依赖上游的什么 | 失败时的典型报错 |
|---|---|---|---|---|
| 1 | 应用 per-UID sus_path 补丁 | `patches/60_add_per_uid_sus_path.patch` | `susfs.c` 的 `susfs_add_sus_path` / `susfs_add_sus_path_loop` / `susfs_run_sus_path_loop` 结构 | `Hunk #N FAILED` |
| 2 | per-target hide-from | `patch_susfs_hide_from_uid.py` | `susfs_sus_path_uid_upsert` 的**两参数**原型 | `anchor '...' matched 0 times` |
| 3 | readdir/getdents 过滤 | `patch_susfs_readdir_filter.py` | `fs/readdir.c` 里 SUSFS 的 `ilookup` 钩子（≥3 处） | `expected at least 3 SUSFS ilookup blocks` |
| 4 | app-uid 门控放宽 | `patch_susfs_app_uid_gate.py` | `if (!susfs_is_current_proc_umounted_app())` 原文 | `anchor '...' matched 0 times` |
| 5 | **SUSFS sus_type 注册** | `patch_susfs_bakasu_sus_types.py` | 上游 `susfs.c` 里有 `susfs_add_sus_type()` / `susfs_add_sus_avd_allowed_by_type()` | 自动跳过（旧版没有这两个函数） |
| 6 | **sus_path uid 表忽略 ino 0** | `patch_susfs_ino_zero_guard.py` | 无（在 #2 之后即可） | `anchor 'upsert guard (!inode || uid < 0)' missing` |
| 7 | **sus_path_loop per-uid 语义** | `patch_susfs_loop_mode.py` | `struct st_susfs_sus_path_list` 定义、`susfs_add_sus_path_hide_from()` 已由 #2 注入 | `anchor 'st_susfs_sus_path_list' missing` |
| 8 | 未使用 cred 辅助函数 | `patch_susfs_unused_creds.py` | 上游有 `susfs_switch_to_ksu_domain()` / `susfs_restore_creds()` 但 Kconfig 没有 `CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER` | 编译报 `-Werror,-Wunused-function` |

> #5～#7 是 **ABK 对上游语义的适配**（外加 #6 是踩过的坑），不是上游自带功能，详见第 3 节。

---

## 3. 上游改过、ABK 需要跟进的语义

### 3.1 SELinux 隐藏：注册表模型（a0ac906 起）

上游把 SUSFS 的 SELinux 隐藏从「简单 selinuxfs 包装」改成 **注册表模型**：

- `fs/susfs.c` 维护 `SUS_TYPE_HLIST`（要隐藏的 type）和 AVD spoof 表；
- `security/selinux/{selinuxfs,ss/services,status}.c` 查询这两张表；
- **往表里写数据的只有 KernelSU 侧**：`10_enable_susfs_for_ksu.patch` 会在 `kernel/selinux/sepolicy.c` 的 `add_type()` / `add_rule_raw()` 里调用 `susfs_add_sus_type()` / `susfs_add_sus_avd_allowed_by_type()`。

ABK 的 BakaSU 分支**不应用** `10_enable_susfs_for_ksu.patch`（`build.yml` 里写的是「BakaSU 使用内置 SUSFS 支持」），
所以必须由 `patch_susfs_bakasu_sus_types.py` 把这两个注册调用补进 BakaSU 的 `sepolicy.c`，否则：

- `u:r:ksu:s0`、`u:object_r:ksu_file:s0`、magisk/lsposed 的 type 与规则全部可见；
- 春秋/鸭子会报「可疑 SELinux 上下文」。

**同步上游后验证**：`ksu_susfs show version` 应为 `v2.3.0` 级别；检测器不应再报 ksu/magisk/lsposed 上下文。

### 3.2 `sus_path_loop` 只有「可见 uid」一种语义（历史限制）

上游 `susfs_add_sus_path_loop()` 只存 `(path, uid)`，worker 固定做
`set_bit(AS_FLAGS_SUS_PATH)` + `upsert(uid, 0)`，**无法表达 per-target（mode 1）**。

ABK 用 `patch_susfs_loop_mode.py` 补上：

- `st_susfs_sus_path_list` 增加 `mode`（内核内部结构，不动用户态 ABI）；
- `add_sus_path_loop()` 记 `mode 0`；
- `susfs_add_sus_path_hide_from()` 成功后再把 `(path, uid, 1)` 入队（带去重）；
- worker 按 `cursor->mode` 分支，mode 1 打 `AS_FLAGS_SUS_PATH_HIDE_FROM` + `upsert(uid, 1)`。

**为什么必须这样**：sus_path 是 **inode 记账**，inode 被回收或 app 数据目录重建（卸载/重装/更新）后
`AS_FLAGS*` 就随 inode 消失，隐藏失效但配置还在；loop 是**路径记账**，每次 app 进程启动都会
重新解析并重打标记，ino 怎么变都跟得上。

**同步上游后验证**：

```sh
su -c 'dmesg | grep "loop queue" | tail -3'          # hide_from 是否入队（mode 1）
su -c 'dmesg | grep "re-flag AS_FLAGS_SUS_PATH" | tail -3'  # worker 是否重放
```

### 3.3 `priority_uid_filter` 的未使用函数

a0ac906 起 `fs/susfs.c` 在**任何 guard 之外**定义 `susfs_switch_to_ksu_domain()` /
`susfs_restore_creds()`，而唯一调用点在 `#ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER` 里。
BakaSU 4.2.0-rc3 的 Kconfig 没有这个符号，于是 `-Werror,-Wunused-function` 编译失败。

`patch_susfs_unused_creds.py` 会把这两个函数包进同一个 guard；上游以后补了 guard 就自动 no-op。

### 3.4 `fs/namespace.c` 头部 hunk 打不上（6.1 LTS）

上游补丁的 hunk #1 假设存在 `#include <trace/hooks/blk.h>`，6.1.138 上没有，
`build.yml` 用 sed 兜底注入 `susfs_def.h` + `CL_COPY_MNT_NS`（**不带**上游那句
`/* used by copy_mnt_ns() */` 注释）。所以 `patch_susfs_mount_app_uid.py` 的锚点只匹配
`#define CL_COPY_MNT_NS BIT(25)` 这一行，两种结尾都兼容——改这个锚点前先看这里。

### 3.5 FUSE 的 `i_ino` 是 0，per-uid 表会退化成「通配符」（2026-11-03 教训）

**症状**：某个 app 本身正常、但读不到自己的 `/sdcard/Android/data/<pkg>`
（原神表现为「资源下载失败」）；`dmesg` 刷屏

```
susfs_is_inode_sus_path] hiding path with ino '0' from uid '10274'
```

**原因**：`/storage/emulated/0` 是 FUSE，子项在 readdir/lookup 时不会实例化 inode，
`inode->i_ino == 0`。而 per-uid 表是按 `(i_ino, s_dev, uid, mode)` 记账、查询只比
`(ino, dev)`，于是 `ino 0` 变成「所有 i_ino 为 0 的 FUSE inode」的通配条目——
**一个 app 只要同时是 target，就会把自己的 FUSE 路径一起隐藏掉**。

**修复**：`patch_susfs_ino_zero_guard.py` —— `ino == 0` 一律不写表、不查表。

**代价**：FUSE 路径无法再做 per-target 隐藏（没有稳定 inode 可记账）；
`/data/data` 这类真实文件系统不受影响。

**验证**：

```sh
dmesg | grep "uid entry set: ino '0'" | wc -l                        # 期望 0
dmesg | grep "from uid '<目标 app uid>'" | grep "ino '0'" | wc -l    # 期望 0
```

**教训（写新隐藏机制前必看）**：

- 任何「按 inode 记账」的机制，第一步都要判断 inode 是否可用：
  `!inode || inode->i_ino == 0` 在 FUSE / overlayfs / 未实例化的 dentry 上很常见；
- 记账键里出现「哨兵值」时，它就是通配符。0、-1、`DEFAULT_KSU_MNT_ID` 这类值要显式排除；
- 若需要隐藏 FUSE 路径，只能按「父目录 + 名字」或路径字符串做，不能按 inode。

---

### 3.6 重载「只增不删」：模板改小后旧条目残留到重启（2026-11-24 教训）

**现象**：在 HMA 里把几个应用加进白名单模板（隐藏集合变小）→ 同步 → 春秋报
`隐藏应用列表生效 (2)`；`policy.tsv` 完全正确（该 uid 45 条规则），`dmesg` 里
`hiding path` 计数为 0；**重启手机后自动恢复正常**。

**机制**：`susfs_load_policy_file()` 只做两件事——

```c
susfs_sus_path_uid_upsert(ino_target, uid, 1);   /* 只插入/更新 */
susfs_loop_queue_path(target, uid, 1);           /* 只追加 */
```

两张表都没有"移除"路径：

- `SUS_PATH_UID_HLIST`（(ino, dev, uid) → mode）按 upsert 语义只增不减；
- `LH_SUS_PATH_LOOP` 是去重追加的队列，且 `susfs_run_sus_path_loop()` 在**每次
  app 进程 spawn** 时会把队列条目重新置位 + 重新 upsert。

于是隐藏集合从 H1 缩小到 H2 时，H1 里被移出的行仍然留在两张表里，并在后续每次
app 启动时被 loop worker 重新强化：**PM 层已可见、磁盘层仍隐藏**，两层不再一致。
检测器（春秋）不需要 stat 被隐藏的目录就能判定"存在隐藏列表"。

**为什么 `hiding path` 日志是 0**：那句日志只在 `is_denied()` 命中的快路径打印；残留行
是由 loop worker 在进程启动阶段重新置位的，与被遮蔽目录的后续访问无关。

**当前处置（决定）**：保持"追加"模式，不引入整表重建。

- 模板修改是低频操作（本次是当天唯一一次），重启一次即可恢复，代价可接受；
- 整表重建需要「清空 → 重新解析 → 重新入队」的原子切换，涉及
  `SUS_PATH_UID_HLIST` 与 `LH_SUS_PATH_LOOP` 两把锁 + RCU grace，风险高于收益；
- 一旦重建途中解析失败，会把「原本还能用的隐藏」清成「什么都没有」。

**操作约定**：改完模板并同步后，如果检测器出现「隐藏应用列表生效」类词条，
**重启一次**再判定；重启后的状态才是磁盘层与 PM 层一致的状态。此约定已写入
`HMA-susfs/docs/SUSFS-SYNC.md`。

**如果将来要修**：在 `susfs_load_policy_file()` 解析前，按桶 `hash_del_rcu` 清空
`SUS_PATH_UID_HLIST`、按 `list_del_rcu` 清空 `LH_SUS_PATH_LOOP`，各自解锁后
`synchronize_rcu()` 再 `kfree`，然后由文件重建。实现草案见提交 `b4f903e`
（已回退，仅作参考）。
## 4. 排障速查

```sh
# 内核侧
su -c '/data/adb/hma_susfs/bin/ksu_susfs show version'
su -c '/data/adb/hma_susfs/bin/ksu_susfs show enabled_features'
su -c 'dmesg | grep -E "loop queue|re-flag|hiding name|sus_path uid entry|failed opening" | tail -20'

# 用户态同步
su -c 'sh /data/adb/hma_susfs/sync.sh; echo rc=$?'     # 期望 SUSFS_SYNC_OK / rc=0
```

常见现象对照：

| 现象 | 先看什么 |
|---|---|
| 某路径隐藏过一会又出现 | `re-flag` 是否有该路径；没有说明没入 loop（检查 sync 是否用了 loop 命令） |
| app 读不到自己的 `/sdcard/Android/data/<pkg>` | 3.5 的 ino 0 通配：`dmesg \| grep "ino '0'"` 是否有条目 |
| 重启后全部失效 | 模块是否装上；`sync.sh` 是否在开机执行 |
| 检测器报 SELinux 上下文 | 3.1 的 `sus_type` 注册是否生效（`patch_susfs_bakasu_sus_types.py` 是否被跳过） |
| 编译失败 `unused function` | 3.3 的 guard 脚本 |
| 编译失败 `anchor ... matched 0 times` | 对应脚本的锚点随上游漂移，按报错信息里的文件名/锚点名修 |

---

## 5. 变更记录

- **2026-11-24**：定位「重载只增不删」短板（改模板后旧隐藏条目残留到重启），\n  决定沿用追加模式并在文档中约定「改模板后先重启再判定」。内核回退到 490614b。\n- **2026-11-03**：修 FUSE `i_ino == 0` 导致的 per-uid 通配（原神读不到自己的
  `/sdcard/Android/data`）。新增 `patch_susfs_ino_zero_guard.py`，dev 提交 `3f26140`。
- **2026-11-02**：SUSFS 同步到 `a0ac906`；新增 sus_type 注册、loop per-uid 语义、cred guard；
  修正 mount app-uid gate 锚点。dev 提交：`c7933d2`、`99b4685`、`abc4d16`、`e039b2d`。
