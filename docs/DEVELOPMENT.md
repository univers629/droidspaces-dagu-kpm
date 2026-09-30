# 开发与复现

## 主机依赖

- Git
- Python 3.10 或更高版本
- Android NDK `28.2.13676358`（使用其中的 LLVM 工具链）
- KernelPatch SDK，固定在 NOTICE.md 记录的 commit
- 若要运行设备探针：ADB、root 权限和已配置兼容 KPM 的专用测试设备

项目不要求安装完整 Android 内核构建环境，也不重建内核。

## 获取 KernelPatch SDK

从仓库根目录执行。先浅量获取固定提交，再只展开构建所需目录：

```sh
git clone --filter=blob:none --no-checkout https://github.com/bmax121/KernelPatch.git vendor/KernelPatch
git -C vendor/KernelPatch sparse-checkout init --cone
git -C vendor/KernelPatch sparse-checkout set \
  kernel/include \
  kernel/patch/include \
  kernel/linux/include \
  kernel/linux/arch/arm64/include \
  kernel/linux/tools/arch/arm64/include
git -C vendor/KernelPatch checkout --detach 87f4dab2da53eca64af5175c8bdd36ca046fb875
```

也可以将 `KERNELPATCH_ROOT` 指向这份检出。该路径只供本机构建使用，不会被 Git 跟踪。

## 配置 Android NDK

将 `ANDROID_NDK_ROOT` 或 `ANDROID_NDK_HOME` 设为 NDK `28.2.13676358` 的安装目录；也可用 `NDK_LLVM_BIN` 直接指定 `toolchains/llvm/prebuilt/<host>/bin`。未设置环境变量时，脚本会检查标准 Android SDK 安装位置。

PowerShell 示例：

```powershell
$env:ANDROID_NDK_ROOT = 'C:\Android\Sdk\ndk\28.2.13676358'
```

macOS/Linux 示例：

```sh
export ANDROID_NDK_ROOT="$HOME/Android/Sdk/ndk/28.2.13676358"
```

## 构建与静态检查

```sh
python src/dagu_v02/build_check.py
python src/dagu_v02/build_kpm.py
python tools/public/build_namespace_tests.py
```

- `build_check.py` 编译 ARM64 对象并检查 Android UAPI。
- `build_kpm.py` 链接可交给 KernelPatch loader 的 ARM64 KPM，并检查 ELF section 和 loader API imports。
- `build_namespace_tests.py` 编译 `tests/` 下的设备探针（包括并发 IPC 与 `setns()` 探针），不连接设备、不运行探针。

产物写入 `src/dagu_v02/build/` 与 `tests/build/`，这些目录已从 Git 忽略。

## 手动运行 namespace 探针

仅在已知兼容的测试设备上运行。探针可能调用 `unshare()`、`clone()` 和 `setns()`；它们不会刷写 boot，但会在设备内创建/退出 namespace。先构建 helper，再使用你自己的 ADB 目标：

```sh
adb push tests/build/ns_smoke /data/local/tmp/ns_smoke
adb shell chmod 755 /data/local/tmp/ns_smoke
adb shell su -c '/data/local/tmp/ns_smoke ipc'
adb shell su -c '/data/local/tmp/ns_smoke ipc_object'
adb shell su -c '/data/local/tmp/ns_smoke pid'
```

高级探针的可用模式由程序帮助文本列出。结果必须结合目标 KPM、boot ABI、系统日志和清理状态评估；单个退出码不等于完整验收。公开报告前请脱敏设备序列号、路径、boot/KPM 哈希和原始日志。

本仓库不提供自动刷写或重启流程。任何设备修改都应由设备所有者自行审阅，并提前准备经过验证的回滚镜像和恢复通道。
