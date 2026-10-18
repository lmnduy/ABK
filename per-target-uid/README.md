# SUSFS per-target UID hiding

让 **uid 隐藏与路径隐藏都只对指定的应用生效**，而不是全局生效。

面向的场景：检测器（例如春秋 Native Check）会把 PackageManager 的可见性
与 `getpriority(PRIO_USER, uid)` 这类"uid 是否存在"的探针交叉比对。
SUSFS 自带的 `add_hidden_uid` 是**全局**表，隐藏一个包会让所有进程都看不到
它的 uid —— 既会暴露"有东西被隐藏"，也可能把检测器自己的 uid 一起藏掉，
导致整个扫描以 "incomplete" 收场。

本仓库提供内核侧的 per-target 表 + 用户态工具 + 设备脚本，使：

* 隐藏 X 于 A：只有 A 看到 "uid 不存在"
* 隐藏 X 于 A 不影响 B、C
* 目标永远不会"隐藏自己"（除非显式配置）

## 组件

| 位置 | 内容 |
|---|---|
| `patches/patch_susfs_hide_from_uid.py` | sus_path per-target（`0x55554`），内核 + CLI |
| `patches/patch_hide_from_cli_only.py` | 上者的 CLI-only 变体（补 `struct st_susfs_sus_path.uid`） |
| `patches/patch_susfs_hidden_uid.py` | 全局 hidden-uid 表 + `add_hidden_uid`（`0x55555`） |
| `patches/patch_susfs_hidden_uid_from.py` | **per-target** hidden-uid 表（`0x55556`）+ sys.c 钩子重写 + dispatch 注入 |
| `cli/build-cli.sh` | 用 NDK 从 SUSFS 源码重编 `ksu_susfs` |
| `device/hmaoss.sh` | HMA-OSS zygote 资产：开机按 `targets.txt` 成对同步 |
| `device/susfs_sync.sh` | HMA-OSS app 资产：手动同步版本 |
| `device/hma_late_sync.sh` | `service.d` 延迟补跑（CE 解锁后） |
| `.github/workflows/build-ksu-susfs.yml` | CI：拉取指定 SUSFS 版本 → 打补丁 → 编 CLI → 出 artifact |

## 内核侧 ABI

```c
#define CMD_SUSFS_ADD_HIDDEN_UID        0x55555  /* 全局，慎用 */
#define CMD_SUSFS_ADD_HIDDEN_UID_FROM   0x55556  /* per-target */

struct st_susfs_hidden_uid_from { uid_t uid; uid_t target_uid; int err; };
```

`getpriority()` / `setpriority()` 的钩子改成：

```c
if (which == PRIO_USER && who >= 0 &&
    (susfs_uid_is_hidden_from((uid_t)who, current_uid().val) ||
     susfs_uid_is_hidden((uid_t)who)))
        return -ESRCH;
```

细节见 `docs/ARCHITECTURE.md`。

## 快速开始

1. **内核**：在 SUSFS 源码上依次执行

   ```sh
   python3 patches/patch_susfs_hide_from_uid.py   <susfs4ksu_dir>
   python3 patches/patch_susfs_hidden_uid.py      <susfs4ksu_dir>
   python3 patches/patch_susfs_hidden_uid_from.py <susfs4ksu_dir> <kernel_root>
   ```

   第三个脚本必须同时改 **SUSFS 模板**和**已生成的内核树**（`common/include/linux/susfs.h`、
   `common/fs/susfs.c`、`common/include/linux/susfs_def.h`），否则 `kernel/sys.c` 报
   `call to undeclared function 'susfs_uid_is_hidden_from'`。

2. **CLI**：`cli/build-cli.sh`（NDK）会以 CLI-only 模式重打三个补丁并编译
   `ksu_susfs`。**不要用 SUSFS release 里的预编译二进制**，它没有新命令。

3. **设备**：把 `device/hmaoss.sh`、`device/susfs_sync.sh` 放回 HMA-OSS 对应 assets
   重编安装；`device/hma_late_sync.sh` 放 `/data/adb/service.d/`。

4. **验证**

   ```sh
   dmesg | grep CMD_SUSFS_ADD_HIDDEN_UID_FROM | grep -c "target: '<检测器 uid>'"   # 期望 >0
   dmesg | grep -c "CMD_SUSFS_ADD_HIDDEN_UID ->"                                   # 期望 0
   ```

## 已验证环境

| 项 | 版本 |
|---|---|
| 内核 | 6.1.138-android14-11（BakaSU，SUSFS v2.3.0 基线 5192aa2d） |
| SUSFS | simonpunk/susfs4ksu `gki-android14-6.1` |
| HMA-OSS | 5c287a4+8 |
| NDK | 26.0.10792818 |

## 上游更新后

见 **[docs/UPGRADE.md](docs/UPGRADE.md)**：锚点变了会硬失败（`::error::`），按清单逐项复检即可。

## 许可

设备脚本衍生自 **HMA-OSS（AGPL-3.0）**，本仓库整体按 AGPL-3.0 发布；
出处与第三方项目见 `NOTICE.md`。
