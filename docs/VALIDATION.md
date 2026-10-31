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

未覆盖：SysV 信号量与共享内存、POSIX 消息队列（`semget`、`shmget`、`mq_open` 仍返回 ENOSYS）、user namespace。

### devtmpfs 文件系统类型

| 范围 | 结果 | 边界 |
| --- | --- | --- |
| 类型注册 | 通过 | 基于 `shmem_fs_type` 复制并改名后注册，`/proc/filesystems` 出现 `nodev devtmpfs` |
| 挂载 | 通过 | `mount -t devtmpfs` 返回 0，挂载点以 `devtmpfs` 类型出现在 `/proc/self/mounts` |
| 节点创建 | 通过 | 在挂载实例上按 `/sys/class/*/*/dev` 枚举创建 559 个字符设备节点，均可打开；`null`、`zero`、`random`、`kmsg`、`fuse`、`tun`、`ashmem`、`ion` 可用，`kgsl-3d0` 读出驱动标识 |
| 容器端到端 | 通过 | `droidspaces --hw-access` 启动容器后，容器内 `/dev` 以 `devtmpfs` 类型挂载，含 32 个节点；`head /dev/kgsl-3d0` 返回驱动标识，写 `/dev/null` 成功 |
| PID/IPC 回归 | 通过 | `ns_smoke pid/ipc/ipc_object`、`ns_advanced clone3` 在含 devtmpfs 的镜像上仍 exit=0 |

挂载结果为空，驱动核心的自动节点维护在未启用 `CONFIG_DEVTMPFS` 的内核中不存在。节点由消费方按 sysfs 创建：测试直接枚举 `/sys/class` 得到 559 个，Droidspaces 在 `--hw-access` 模式下为容器建立其中的 32 个。

### SysV 信号量

| 范围 | 结果 | 边界 |
| --- | --- | --- |
| 创建与属性 | 通过 | `semget` 返回集合 id；`IPC_STAT` 回写 `key`、`mode`、`sem_nsems` 正确 |
| 单个信号量操作 | 通过 | `SETVAL`、`GETVAL`、`GETPID` 按预期读写 |
| P/V 操作 | 通过 | `semop` 负值递减、正值递增，结果与余额一致 |
| 余额不足 | 通过 | 递减超过当前值返回 `EAGAIN`，值保持不变 |
| 多信号量原子性 | 通过 | 一项失败时整个操作回滚，先前项的写入不保留 |
| 批量赋值 | 通过 | `SETALL`、`GETALL` 按 `sem_nsems` 逐一读写 |
| 删除 | 通过 | `IPC_RMID` 后同一 id 的访问返回错误 |
| 稳定性 | 通过 | 连续 20 轮完整用例无失败，同轮次内 PID/IPC namespace 与 `clone3` 检查保持退出码 0 |

信号量经 `el0_svc_common` 拦截实现：该内核的四个信号量 syscall 对应 8 字节 weak stub，逐个改写表项无法在其上完成 inline hook。调用参数在 before 阶段存入 transit 局部量，after 阶段覆写 `regs->regs[0]`。

## 未实现或未验收

SysV shared memory 与 POSIX message queue 尚未实现。`devtmpfs` 文件系统类型可用，通用硬件访问未验证；user namespace 沙箱未启用。完整 `_patchHarmony` 对等、并发容器 namespace 唯一性和任意 `setns()` 组合不在本次通过范围。

公开复验入口见 [开发指南](DEVELOPMENT.md)。构建测试 helper 不会自动连接设备或刷写 boot；设备行为测试必须在兼容的专用测试设备上由所有者自行执行。

## 2026-10-31 增量验证（POSIX 消息队列）

测试环境为 Xiaomi dagu（Android 14，Linux `4.19.157-perf-gb57830672689`），
boot 镜像含 selinux KPM、本 KPM 与 IPv6 NAT KPM（KPImg 0.13.14）。

| 范围 | 结果 | 边界 |
| --- | --- | --- |
| `mq_open` / `mq_unlink` | 通过 | 创建、`O_EXCL` 冲突返回 EEXIST、缺名返回 ENOENT、重复 unlink 返回 ENOENT |
| `mq_timedsend` / `mq_timedreceive` | 通过 | 消息按优先级降序出队；`mq_getsetattr` 回读 `mq_maxmsg`/`mq_msgsize`；队列满时非阻塞返回 EAGAIN；空队列绝对超时返回 ETIMEDOUT；缓冲区小于 `mq_msgsize` 返回 EMSGSIZE |
| 描述符语义 | 通过 | 描述符为 anon-inode 文件，`close()` 释放打开计数；`O_NONBLOCK` 按描述符生效 |
| `mq_notify` | 未实现 | 返回 ENOSYS |

测试在容器内以 Python `ctypes` 直接调用系统调用完成（180–185），未覆盖
多线程阻塞唤醒与 signal 通知路径。

## 2026-10-31 增量验证（IPv6 NAT）

测试环境为 Xiaomi dagu（Android 14，Linux `4.19.157-perf-gb57830672689`），
boot 镜像只含 selinux KPM 与合并了 IPv6 NAT 的本 KPM（KPImg 0.13.14）。

| 范围 | 结果 | 边界 |
| --- | --- | --- |
| 加载时序 | 通过 | pre-kernel-init 排队，10 秒后在内核线程完成注册（`nat` 表出现） |
| `droidspaces check` | 通过 | `[✓] IPv6 NAT support` |
| 容器地址与路由 | 通过 | 容器获得 `fd64:7370::/64` 地址与 `fe80::1` 默认路由 |
| 容器出网 | 通过 | `ipv6.baidu.com` HTTP 200；conntrack 记录源地址被替换为主机公网地址 |
| 卸载 | 不适用 | KPM 的 unload 已被现有守卫拒绝 |

容器侧配置（`IPv6AcceptRA=no`、静态地址单元、`--dns`）不属于 KPM，记录在工作区的 `tools/container-net/`。

## 2026-10-31 增量验证（User namespace 核心）

测试环境为 Xiaomi dagu（Android 14，Linux `4.19.157-perf-gb57830672689`），
boot 镜像含 selinux KPM 与本 KPM（KPImg 0.13.14）。

| 范围 | 结果 | 边界 |
| --- | --- | --- |
| `unshare(CLONE_NEWUSER)` | 通过 | 凭据换成新建命名空间，`cap_effective` 全满 |
| `unshare(CLONE_NEWNS)` | 通过 | 新 mount namespace 的 owner 为该命名空间 |
| `mount -t tmpfs` | 通过 | 挂载、写文件、读回、`umount` 全部成功 |
| `mq_*` 与 IPv6 NAT | 通过 | 同一镜像内未回归；`ip6tables -t nat -L` 可用 |
| `uid_map` / `gid_map` / `setgroups` | 通过 | 新建命名空间读出恒等映射与 `deny`，初始命名空间读出 `allow`；恒等写入成功，非恒等写入返回 EPERM |
| `/proc/<pid>/ns/user` | 通过 | 初始命名空间读出 `user:[4026531837]`，新建命名空间读出独立 inode；`droidspaces check` 的 Sandboxing 项转为通过 |
| `unshare(CLONE_NEWPID)` | 通过 | 先 `unshare(CLONE_NEWUSER)`，再创建 PID namespace；`fork` 后子进程 `getpid()` 为 1，`mount -t proc` 成功 |
| `unshare(CLONE_NEWUSER \| CLONE_NEWPID \| CLONE_NEWNS)` | 通过 | 一次调用同时建立三类命名空间，`mount` 与 `umount` 正常 |
| `clone(CLONE_NEWUSER)` | 不支持 | 跨进程安装凭据的路径未实现，返回 `EOPNOTSUPP` |
| 容器内 `unshare -U -m -p -f --mount-proc` | 通过 | `allow_sandboxing=1` 后容器内可用，新 PID namespace 内 `/proc` 可挂载、可写 |

测试为宿主侧静态程序（`unshare`、`mount`、`open/write/read`、`umount`），容器侧为 `kdeanland` 内的 `unshare` 命令；未覆盖多线程形态。
