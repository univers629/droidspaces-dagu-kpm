# 限制与未实现功能

`v0.3.0-dev1` 是面向单一设备和内核配置的实验性 KPM 快照。以下条目说明当前发布范围及未关闭的工程门槛，不代表相关能力在所有环境中都不可能实现。

## 已实现

- **`clone3`：**目标内核的 `sys_call_table` 只有 435 项，`__NR_syscalls=435`，`scno >= 435` 直接走 `do_ni_syscall`，按 syscall 表项 hook 写入的是表外 rodata，回调不触发。实现改为 inline hook `el0_svc_common`，在 after 阶段调用六参数 `_do_fork` 后覆写 `regs->regs[0]`。fork、CLONE_THREAD 与参数校验路径已在设备验证。
- **`devtmpfs` 文件系统类型：**KPM 复制 `shmem_fs_type` 并改名注册，`mount -t devtmpfs` 可用。驱动核心的自动节点维护在未启用 `CONFIG_DEVTMPFS` 的内核中不存在，挂载实例为空，节点由消费方按 sysfs 创建。目标镜像上该结构实例为 0x68 字节，拷贝以此为界。通用硬件访问未验收。
- **`mqueue` 文件系统类型与 POSIX 消息队列：**目标内核没有该配置项时 `mount -t mqueue` 报 ENODEV，容器运行时在初始化阶段挂载该路径，失败即终止。文件系统类型复制 `shmem_fs_type` 改名注册，挂载实例为空，队列条目不出现在该挂载点。`mq_open`、`mq_unlink`、`mq_timedsend`、`mq_timedreceive` 与 `mq_getsetattr` 由 `mqueue_core.c` 在本模块内实现，队列对象按 fake IPC namespace 隔离，描述符是 anon-inode 文件。`mq_notify` 未实现，返回 ENOSYS。
- **IPv6 NAT：**目标内核没有 `CONFIG_IP6_NF_NAT`，也没有 IPv6 的 `MASQUERADE` 目标，容器的 NAT 网络因此停留在 IPv4。KPM 内置内核树的 `ip6table_nat`、`nf_nat_l3proto_ipv6` 与 `nf_nat_masquerade_ipv6`，并注册 `NFPROTO_IPV6` 的 `MASQUERADE`；内核符号经 `nat66/shim.c` 间接调用。注册由内核线程延迟 10 秒执行：KPM 在 pre-kernel-init 加载，此时 netfilter 表尚未分配，同步注册会阻塞启动。MASQUERADE 的接口/地址通知器为空实现（`nf_ct_iterate_cleanup_net`、`__put_net` 未导出），旧连接靠超时清理。
- **User namespace（部分）：**内核把 `create_user_ns()`、`get_user_ns()` 与 `current_user_ns()` 编译成桩，原生不支持。KPM 自建命名空间对象：`unshare(CLONE_NEWUSER)` 返回成功，凭据换成该命名空间并持有完整 capability；`unshare(CLONE_NEWNS)` 后的挂载、读写与卸载可用。`mount_nodev()` 期间凭据临时切到初始命名空间以通过 `current_user_ns()` 常量带来的检查，挂载完成后再改回，并把 superblock 的归属改为容器命名空间。`/proc/<pid>/{uid_map,gid_map,setgroups}` 由 KPM 补回：初始命名空间读出 `allow`，新建命名空间读出 `deny` 与恒等映射 `0 0 4294967295`；写入只接受恒等映射，其他映射返回 EPERM 而不是被接受后忽略。`unshare(CLONE_NEWPID)` 与 `unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS)` 可用，PID namespace 归属该用户命名空间，其中可以挂载新的 `proc`。**尚未实现：**`clone(CLONE_NEWUSER)` 返回 `EOPNOTSUPP`（只支持 `unshare` 路径）；`/proc/<pid>/ns/user` 仍没有条目，非恒等映射不会被记录；Droidspaces 的 seccomp 在 `allow_sandboxing=0` 时对 `unshare(CLONE_NEWUSER)` 返回 EPERM，容器内启用需要该选项。
- **SysV 信号量：**四个 syscall 在该内核上返回 ENOSYS，实现经 `el0_svc_common` 拦截后由 KPM 提供，集合按 fake IPC namespace 隔离。`semget`、`semop`、`semtimedop` 与 `semctl` 的创建、属性、P/V、原子多操作和删除路径已在设备验证。

## 尚未实现

- **SysV shared memory：**没有实现对应的 namespace 对象、隔离和生命周期路径，也没有设备验收；不要将 SysV message queue、semaphore 或 POSIX mqueue 的支持外推到 SysV shared memory。
- **通用硬件访问：**`devtmpfs` 类型可用后，容器节点由消费方创建；跨设备的通用硬件访问未验收。
- **User namespace 的可见性与映射：**`/proc/<pid>/ns/user` 没有条目，非恒等映射无法建立，`newuidmap` 一类工具与 rootless 容器尚不可用；合成实现的卸载生命周期也未验证。

## 验收边界

- 并发检查覆盖两个容器及记录过的 SysV message queue 场景；不证明更大规模或任意容器生命周期都正确。
- `setns()` 检查覆盖文档列出的 PID/IPC 路径；不证明所有 namespace 类型、调用顺序和错误路径均已支持。
- 与 `_patchHarmony` 的逐项功能相似不代表完整功能对等。上游模块针对不同内核 ABI 与 hook 环境，不能直接用于本项目目标内核。
- 测试设备上的结果不构成其他设备、boot、loader 或内核配置的兼容性保证。

## 运行风险

KPM 在内核态修改系统行为，错误的 ABI、符号或生命周期假设可能导致系统崩溃或无法启动。验证记录中的 loader 不允许安全的运行时卸载；在有经过验证的启动恢复路径之前，不应尝试安装到日常使用设备。构建说明和设备探针见[开发指南](DEVELOPMENT.md)与[验证记录](VALIDATION.md)。
