"""Compile v0.3 source components without producing an installable KPM."""

# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import os
import subprocess

from build_env import llvm_tool


ROOT = Path(__file__).resolve().parents[2]
PROJECT = Path(__file__).resolve().parent
KERNELPATCH_ROOT = Path(os.environ.get("KERNELPATCH_ROOT", ROOT / "vendor/KernelPatch")).expanduser()
SDK = KERNELPATCH_ROOT / "kernel"
SOURCES = (PROJECT / "abi_compile_check.c", PROJECT / "dagu_v02.c",
           PROJECT / "proc_bridge.c",
           PROJECT / "ipc_namespace.c", PROJECT / "nsproxy_bridge.c",
           PROJECT / "msg_core.c", PROJECT / "usercopy.c",
           PROJECT / "msg_syscalls.c", PROJECT / "clone3.c",
           PROJECT / "reboot_syscalls.c",
           PROJECT / "pid_exit_guard.c",
           PROJECT / "pid_namespace.c", PROJECT / "pid_lifecycle.c",
           PROJECT / "proc_mount_refs.c", PROJECT / "proc_root_dedup.c",
           PROJECT / "status_bridge.c")
OUT = PROJECT / "build"


def main() -> None:
    if PROJECT.resolve() != (ROOT / "src/dagu_v02").resolve():
        raise RuntimeError("Unexpected project path")
    clang = llvm_tool("clang")
    llvm_readelf = llvm_tool("llvm-readelf")
    for path in (*SOURCES, PROJECT / "uapi_host_check.c", clang,
                 llvm_readelf, SDK / "include/hook.h"):
        if not path.is_file():
            raise FileNotFoundError(path)
    OUT.mkdir(exist_ok=True)
    includes = [PROJECT, SDK / "include", SDK / "patch/include", SDK / "linux/include",
                SDK / "linux/arch/arm64/include", SDK / "linux/tools/arch/arm64/include"]
    for source in SOURCES:
        obj = OUT / (source.stem + ".o")
        subprocess.run([str(clang), "-target", "aarch64-linux-gnu", "-std=gnu11",
                        "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
                        "-fno-stack-protector", "-fno-pic", "-fno-PIE", "-mno-outline-atomics",
                        *(f"-I{path}" for path in includes), "-c", str(source), "-o", str(obj)], check=True)
        symbols = subprocess.run([str(llvm_readelf), "-s", str(obj)], check=True,
                                 capture_output=True, text=True).stdout
        if "__aarch64_" in symbols:
            raise RuntimeError(f"Unexpected outlined atomic import in {obj}")
    subprocess.run([str(clang), "-target", "aarch64-linux-android35",
                    "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only",
                    f"-I{PROJECT}", str(PROJECT / "uapi_host_check.c")], check=True)
    print(f"Compiled {len(SOURCES)} v0.3 ARM64 objects and checked Android UAPI; KPM linking is separate")


if __name__ == "__main__":
    main()
