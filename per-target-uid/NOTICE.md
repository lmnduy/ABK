# 出处与第三方项目

本项目把若干补丁、脚本与构建步骤整理在一起，其中部分衍生自以下项目：

## HMA-OSS（AGPL-3.0）

- 上游：https://github.com/frknkrc44/HMA-OSS
- 本仓库 `device/hmaoss.sh`、`device/susfs_sync.sh` 是 HMA-OSS 模块资产
  （`zygote/src/main/assets/hmaoss.sh`、`app/src/main/assets/susfs_sync.sh`）的修改版本，
  改动内容包括：per-target uid 调用、两遍循环、`stat` 容错。
- 依其许可，本仓库整体以 **AGPL-3.0** 发布（见 `LICENSE`）。

## SUSFS（GPL-2.0）

- 上游：https://gitlab.com/simonpunk/susfs4ksu
- `patches/` 中的补丁以内核源码补丁形式作用于该项目的
  `kernel_patches/` 与 `ksu_susfs/`，不包含其源码副本。

## KernelSU / BakaSU / SukiSU

- 补丁会向 `KernelSU/kernel/supercall/dispatch.c` 注入命令分发；
  这些内核侧文件属于各自项目，本仓库不附带其源码。

## 声明

本项目仅用于 Android 系统机制的研究与自有设备的环境自检，
不包含任何绕过第三方应用风控的商用方案，也不附带任何密钥、证书或个人数据。
使用风险自负。
