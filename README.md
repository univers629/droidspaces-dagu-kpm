# Droidspaces dagu KPM adapter

这是一个面向 Xiaomi dagu、Android 15 / Linux 4.19.157 的 KernelPatch Module（KPM）研究项目。目标是在不重建内核的前提下，逐项对照 `_patchHarmony` 实现其相应功能，并供 Droidspaces v6.6.0 使用。

项目采用 fake namespace 适配：KPM 会维护 PID/IPC namespace 状态，并让进程、`/proc` 与 SysV 消息队列反映该状态。项目不把 `unshare()` 空成功视为实现。代码按 GPL-2.0-only 发布，详见 [LICENSE](LICENSE)。

## 状态

当前公开版本为 `v0.3.0-dev1`，是一个实验性开发快照，不是稳定版，也没有持续维护计划。

v0.2.0 候选版本已在一台 dagu Android 15 / Linux 4.19.157 设备上完成 PID/IPC 核心语义和 Droidspaces 容器流程验证。v0.3.0-dev1 增加了 PID `setns()` 的祖先关系限制，并在同一目标设备上完成了有限的双容器并发回归和选定 `setns()` 组合检查。结果只适用于记录过的设备、boot 和 loader；范围详见[验证记录](docs/VALIDATION.md)。

当前明确限制：

- SysV shared memory 和 POSIX message queue 尚未实现。
- `devtmpfs` 文件系统类型已实现，挂载实例为空，节点由消费方按 sysfs 创建；通用硬件访问未验收。
- synthetic user namespace 未实现；本项目不提供 user namespace 沙箱。
- 任意 `setns()` 组合、无限并发规模和完整 `_patchHarmony` 功能对等尚未验证。

为什么这些能力没有包含在快照中，以及不应据此推断什么，见[限制与未实现功能](docs/LIMITATIONS.md)。此 KPM 针对特定设备、内核和 KernelPatch loader，不代表其他设备或内核可用。

## 上游参考与目标

本项目以 [Dere3046/_patchHarmony](https://github.com/Dere3046/_patchHarmony) 的固定源码版本（见 [NOTICE](NOTICE.md)）为逐项实现对照。上游是面向 Android GKI 6.x 的可加载内核模块；本项目在 dagu 的 Linux 4.19 上只使用 KPM。每项功能优先沿用上游的对象、状态转换和系统调用处理方式，并按目标内核 ABI、KernelPatch hook 与生命周期要求改写；无法直接照搬的差异会记录和验证。

参考范围包括 PID/IPC namespace、SysV IPC、POSIX mqueue、`clone3` 与 user namespace。此快照只实现并验证其中列明的部分行为；其余上游能力不能视为本项目已支持。上游的 `no_fake_ns` 诊断模式只让调用返回成功，不建立 namespace 状态，不属于功能实现。Linux 4.19 与面向 GKI 6.x 的上游实现有 ABI 和 hook 差异，不能直接装载上游模块。

## 目录

```text
src/dagu_v02/        当前 KPM 源码、ABI 检查和构建入口
tests/               ARM64 namespace 测试源码
tools/public/        可公开复用的开发辅助脚本
docs/                稳定的架构与开发说明
```

设备镜像、构建产物、原始设备日志、供应商源码检出及本机交接数据不属于 Git 跟踪内容。外部依赖获取方式见开发指南。

## 构建入口

需要 Git、Python 3 和 Android NDK r28.2.13676358；KPM 构建还需要固定版本的 KernelPatch SDK。先按 [开发指南](docs/DEVELOPMENT.md) 配置依赖，然后运行：

```sh
python src/dagu_v02/build_check.py
python src/dagu_v02/build_kpm.py
python tools/public/build_namespace_tests.py
```

这些命令在本机生成的对象文件、KPM 和测试可执行文件会留在被忽略的 `build/` 目录下。构建过程不会刷写设备。

## 设备风险

KPM 会在内核态修改系统行为。错误的 ABI、符号地址或生命周期处理可能导致内核崩溃或设备无法启动。只在你有权维护、且已有可验证恢复路径的设备上评估构建结果；不要安装未经审阅的 KPM。安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 参与项目

贡献代码前请读 [CONTRIBUTING.md](CONTRIBUTING.md)、[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) 和 [SUPPORT.md](SUPPORT.md)。项目依赖与第三方来源列在 [NOTICE.md](NOTICE.md)。
