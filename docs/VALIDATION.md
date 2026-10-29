# 验证记录

本页分开记录 v0.2.0 基线和 v0.3.0-dev1 的有限增量检查。设备结果不代表其他 boot、内核配置或 KernelPatch loader。

## v0.3.0-dev1 有限增量检查

2026-09-30，维护者在同一 Xiaomi dagu Android 15 / Linux 4.19.157 测试设备上完成下列检查。设备序列号、boot/KPM 哈希和原始日志不随公开仓库发布。

| 范围 | 结果 | 具体边界 |
| --- | --- | --- |
| 双容器并发回归 | 通过（两轮） | 两个容器同时运行时 PID/IPC namespace identity 与同 key SysV message queue 相互隔离；分别停止、重启一方时检查另一方仍可用及旧消息不可见。仅覆盖记录的两个容器和工作负载 |
| IPC `setns()` 矩阵 | 通过（记录的路径） | 检查 host 与两个 fake namespace 间切换、同 namespace、无效 fd 和不匹配类型错误；不覆盖任意组合 |
| PID 与 IPC 连续 `setns()` | 通过（两种顺序） | 按 IPC→PID 与 PID→IPC 切换后 fork，并检查 child PID 1、namespace identity 与消息队列；不覆盖所有调用顺序 |
| PID `setns()` 目标关系 | 通过（记录的路径） | 同 namespace 与 descendant 目标可用；ancestor 与 sibling 目标被拒绝；不证明所有 namespace 拓扑和生命周期情形 |

这些检查对应 v0.3.0-dev1 开发候选的有限设备结果，不是通用兼容保证。未实现项和安全边界见[限制与未实现功能](LIMITATIONS.md)。

## v0.2.0 核心验证摘要

本页是 2026-09-29 在一台 Xiaomi dagu（Android 15、Linux `4.19.157-perf-gb57830672689`）上的维护者验证摘要。设备序列号、镜像/KPM 哈希和原始日志不随公开仓库发布；完整原始记录保存在维护者本机。下列结论只适用于记录过的设备、boot 和 KernelPatch loader。

| 范围 | 结果 | 具体边界 |
| --- | --- | --- |
| KPM 构建与 loader ELF 检查 | 通过 | ARM64 relocatable ELF、KPM sections 和 KernelPatch API imports 检查通过；不代表其他 boot ABI |
| PID namespace 核心语义 | 通过 | `unshare()` 后 PID identity 改变；新 PID namespace 的 fork child 显示 PID 1 和预期 `NSpid` 末项 |
| IPC namespace 核心语义 | 通过 | identity 改变；SysV 消息队列同 key 隔离，namespace 内消息可收发，宿主已有消息仍可读 |
| namespace 生命周期 | 通过（有限观察） | 32 轮创建/退出未观察到重启或 Oops；未做引用计数或内存泄漏仪表 |
| PID `setns()` 扩展路径 | 通过（记录的组合） | 覆盖 holder 创建 fake `pid_for_children` 后 host setns 再 fork PID 1；不覆盖任意组合 |
| Droidspaces v6.6.0 流程 | 通过（两轮串行） | MUST HAVE PID/IPC 检查通过；容器 create/run/enter/stop/destroy 两轮完成；不覆盖并发容器 |

## 2026-10-29 增量验证（clone3 与 SysV 消息队列）

测试环境为 Xiaomi dagu（Android 14，Linux `4.19.157-perf-gb57830672689`），
通过 fastboot 临时启动带本 KPM 的 boot 镜像（KPImg 0.13.14，另含 selinux KPM）。

| 范围 | 结果 | 边界 |
| --- | --- | --- |
| `clone3`（435 号） | 通过 | 空 flags / SIGCHLD / `CLONE_THREAD\|CLONE_VM` / 独立 stack / `CLONE_NEWPID\|CLONE_NEWIPC`（子进程 raw pid=1）；`size=0/4/89`、`stack_size` 未对齐、缺少 `stack` 均返回 EINVAL；15000 次混合 syscall 无异常。只覆盖 AArch64，compat 路径未测 |
| SysV 消息队列 | 通过 | `msgget`、`msgsnd`、`msgrcv`、`msgctl(STAT\|SET\|RMID)`；`ns_smoke ipc_object` 覆盖 host 与 fake IPC namespace 的同 key 隔离及跨 namespace 不可见 |
| PID/IPC namespace 回归 | 通过 | `ns_smoke pid/ipc`、`ns_advanced clone_pid/clone3/stress`、`ns_setns_pid_for_children`、`ns_setns_pid_ancestry`、`ns_setns_ipc_matrix`、`ns_setns_pid_ipc_orders` 十项全部 exit=0 |

未覆盖：SysV 信号量与共享内存、POSIX 消息队列（`semget`、`shmget`、`mq_open` 仍返回 ENOSYS）、user namespace、`devtmpfs`。

## 未实现或未验收

SysV semaphore/shared memory 与 POSIX message queue 尚未实现。`devtmpfs` 使用 tmpfs 回退，硬件访问未验证；user namespace 沙箱未启用。完整 `_patchHarmony` 对等、并发容器 namespace 唯一性和任意 `setns()` 组合不在本次通过范围。

公开复验入口见 [开发指南](DEVELOPMENT.md)。构建测试 helper 不会自动连接设备或刷写 boot；设备行为测试必须在兼容的专用测试设备上由所有者自行执行。
