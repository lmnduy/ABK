# 上游更新后的复检清单

本项目的补丁全部**锚点驱动**：锚点不存在会以 `::error::` 硬失败，不会静默产出半成品。
上游一变，先跑补丁看是否失败，再按下面逐项确认。

## 1. SUSFS 更新（simonpunk/susfs4ksu）

```sh
python3 patches/patch_susfs_hide_from_uid.py   <susfs>
python3 patches/patch_susfs_hidden_uid.py      <susfs>
python3 patches/patch_susfs_hidden_uid_from.py <susfs> <kernel_root>
```

检查点：

- `CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553` 仍是 hide_from/新命令的插入锚点
- `susfs_def.h` 的命令号段没被上游占用（`0x55554/0x55555/0x55556`）
- `susfs.c` 里 `static DEFINE_HASHTABLE(ABK_HIDDEN_UID_HLIST, 8);` 存在（第二、三个补丁的锚点）
- `kernel/sys.c` 的 `getpriority` / `setpriority` 原型没变（第三个补丁会改写两处调用）

## 2. 内核 / KernelSU 变体更新

- 内核树的 susfs 副本路径：`common/include/linux/susfs.h`、`common/fs/susfs.c`、
  `common/include/linux/susfs_def.h`——第三个补丁会**同时**改模板和树内副本
- BakaSU / SukiSU 的 `KernelSU/kernel/supercall/dispatch.c`：
  确认 `case CMD_SUSFS_ADD_HIDDEN_UID:` 已由前一个补丁注入（本补丁在其后插入 `0x55556`）
- `CONFIG_KSU_SUSFS_SUS_PATH` 必须开启

## 3. CLI（ksu_susfs）

**不要**使用 SUSFS release 的预编译 `ksu_susfs`：它不含 `add_hidden_uid_from`。
用 `cli/build-cli.sh`（或 CI 的 `build-ksu-susfs.yml`）重编，产物约 26 KB。

编译前必须按顺序打三个补丁（CLI-only 模式）：

1. `patch_hide_from_cli_only.py` —— 注意它会给 `struct st_susfs_sus_path` 补 `int uid;`
2. `patch_susfs_hidden_uid.py`
3. `patch_susfs_hidden_uid_from.py`（`ABK_CLI_ONLY=1`）

## 4. HMA-OSS 更新

HMA-OSS 升级会覆盖两个 asset：

- `zygote/src/main/assets/hmaoss.sh`
- `app/src/main/assets/susfs_sync.sh`

需要用本仓库 `device/` 下的版本重新替换（或把你的改动 rebase 进去），要点：

- `targets.txt` 每行 `<target>\t<hidden>\t[data]`
- 对每行调用 `add_hidden_uid_from <hidden_uid> <target_uid>`
- 两遍循环：先处理检测器 target，再处理其余
- 所有 `stat` / CLI 调用加 `|| true`
- `service.d/hma_late_sync.sh` 负责解锁后补跑

## 5. 检测器更新后

- 重新确认它对 `getpriority` / `getInstalledPackages` 的探针方式
- 若它开始用 `/proc/<pid>` 枚举或 `getpwuid`，需要评估是否补新的钩子
- 复测：`error.txt` 的 UNAVAILABLE 数量、界面"已完成 N 项"、异常项列表

## 6. 验收基线（本仓库验证过的值）

```
detector target pairs = 6
全局 hidden uid 命令计数 = 0
hide_from 条目 > 2000
检测器界面: 已完成 112 项 / 异常 1 项（USB 调试）
```
