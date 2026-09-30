# 支持范围

## 当前验证范围

- Xiaomi dagu / 22081281AC
- Android 15
- Linux `4.19.157-perf-gb57830672689`
- KernelPatch Module 路线；不重建内核
- Droidspaces v6.6.0 的 PID/IPC 核心流程

这表示项目在一台对应设备上完成了记录的核心验证，不表示每台同型号设备、每个 boot 镜像或每个 KernelPatch loader 都兼容。

## 提交问题时

请提供最小复现步骤、KPM 源码提交、内核版本、KernelPatch loader/SDK 版本、预期和实际行为，以及已经尝试的恢复方法。先对设备日志和报告做脱敏：移除序列号、账户信息、私人路径、boot/KPM 哈希和其他个人设备标识。不要上传 boot 镜像或原始用户数据。

## 明确不支持的范围

完整 `_patchHarmony` 功能对等、`clone3`、SysV semaphore/shared memory、POSIX message queue、user namespace 沙箱、devtmpfs 硬件访问和并发容器唯一性目前不属于已验证支持范围。请先查阅 README 中的限制，再提交相关问题。
