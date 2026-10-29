# 限制与未实现功能

`v0.3.0-dev1` 是面向单一设备和内核配置的实验性 KPM 快照。以下条目说明当前发布范围及未关闭的工程门槛，不代表相关能力在所有环境中都不可能实现。

## 已实现

- **`clone3`：**目标内核的 `sys_call_table` 只有 435 项，`__NR_syscalls=435`，`scno >= 435` 直接走 `do_ni_syscall`，按 syscall 表项 hook 写入的是表外 rodata，回调不触发。实现改为 inline hook `el0_svc_common`，在 after 阶段调用六参数 `_do_fork` 后覆写 `regs->regs[0]`。fork、CLONE_THREAD 与参数校验路径已在设备验证。
- **`devtmpfs` 文件系统类型：**KPM 复制 `shmem_fs_type` 并改名注册，`mount -t devtmpfs` 可用。驱动核心的自动节点维护在未启用 `CONFIG_DEVTMPFS` 的内核中不存在，挂载实例为空，节点由消费方按 sysfs 创建。目标镜像上该结构实例为 0x68 字节，拷贝以此为界。通用硬件访问未验收。

## 尚未实现

- **SysV semaphore/shared memory 与 POSIX message queue：**没有实现对应的 namespace 对象、隔离和生命周期路径，也没有设备验收；不要将 SysV message queue 的支持外推到其他 IPC 类型。
- **通用硬件访问：**`devtmpfs` 类型可用后，容器节点由消费方创建；跨设备的通用硬件访问未验收。
- **User namespace：**目标内核没有启用原生 user namespace。KPM 合成实现所需的 cred/user namespace ABI、权限与 capability 规则、native/compat 路径和对象引用/卸载生命周期尚未全部证明安全，因此此版本不提供 user namespace 或 Bubblewrap 沙箱。

## 验收边界

- 并发检查覆盖两个容器及记录过的 SysV message queue 场景；不证明更大规模或任意容器生命周期都正确。
- `setns()` 检查覆盖文档列出的 PID/IPC 路径；不证明所有 namespace 类型、调用顺序和错误路径均已支持。
- 与 `_patchHarmony` 的逐项功能相似不代表完整功能对等。上游模块针对不同内核 ABI 与 hook 环境，不能直接用于本项目目标内核。
- 测试设备上的结果不构成其他设备、boot、loader 或内核配置的兼容性保证。

## 运行风险

KPM 在内核态修改系统行为，错误的 ABI、符号或生命周期假设可能导致系统崩溃或无法启动。验证记录中的 loader 不允许安全的运行时卸载；在有经过验证的启动恢复路径之前，不应尝试安装到日常使用设备。构建说明和设备探针见[开发指南](DEVELOPMENT.md)与[验证记录](VALIDATION.md)。
