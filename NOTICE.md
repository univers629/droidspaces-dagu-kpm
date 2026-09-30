# 第三方来源与依赖

本仓库当前不跟踪 `vendor/` 第三方源码树，也不分发设备镜像、闭源工具或编译产物。

| 项目 | 用途 | 来源与固定版本 | 许可/说明 |
| --- | --- | --- | --- |
| KernelPatch | KPM API 与头文件；本机构建依赖 | <https://github.com/bmax121/KernelPatch>，commit `87f4dab2da53eca64af5175c8bdd36ca046fb875` | 上游 GPL-2.0；按开发指南在本地单独检出，不复制进本仓库 |
| `_patchHarmony` | 行为对照研究，不作为构建依赖 | <https://github.com/Dere3046/_patchHarmony>，当前参考 commit `9bf12a85e1704db1db80677719bb9b6ba551913a`；历史 userns 审计固定在 `d08fd5749e3212c4333e959cdd70e8dac6c96411` | 上游 GPL-2.0；此处仅作来源引用，未随仓库分发其源码；新版 misc/userns 未构建，不能视为 dagu 4.19 KPM 兼容证明 |

本项目自有 KPM 源码标记为 `GPL-2.0-only`。若今后添加、复制或修改第三方代码，必须先核对其许可证兼容性，并更新此文件、相应 SPDX 标记和版权声明。
