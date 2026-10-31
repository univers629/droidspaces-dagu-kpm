"""Build the installable ARM64 v0.3 development KPM and inspect its ELF."""

# SPDX-License-Identifier: GPL-2.0-only

import hashlib
import os
from pathlib import Path
import re
import subprocess

from build_env import llvm_tool


ROOT = Path(__file__).resolve().parents[2]
PROJECT = Path(__file__).resolve().parent
KERNELPATCH_ROOT = Path(os.environ.get("KERNELPATCH_ROOT", ROOT / "vendor/KernelPatch")).expanduser()
SDK = KERNELPATCH_ROOT / "kernel"
SOURCES = (
    "dagu_v02.c",
    "proc_bridge.c",
    "ipc_namespace.c",
    "nsproxy_bridge.c",
    "msg_core.c",
    "sem_core.c",
    "sem_syscalls.c",
    "usercopy.c",
    "msg_syscalls.c",
    "clone3.c",
    "devtmpfs.c",
    "mqueue.c",
    "mqueue_core.c",
    "mqueue_syscalls.c",
    "xt_addrtype.c",
    "reboot_syscalls.c",
    "pid_exit_guard.c",
    "pid_namespace.c",
    "pid_lifecycle.c",
    "proc_mount_refs.c",
    "proc_root_dedup.c",
    "status_bridge.c",
)
OUT = PROJECT / "build"
KPM = OUT / "ds_dagu_v02_v0.3.0-dev1.kpm"

# Retarget the loader ABI without editing the source:
#   KPM_DEFINES="DAGU_KP_VER=0xd0e DAGU_KP_UNLOAD_MODULE_DELTA=0x3d00" python3 build_kpm.py
EXTRA_DEFINES = [d for d in os.environ.get("KPM_DEFINES", "").split() if d]
KPM_NAME_ENV = os.environ.get("KPM_NAME")
if KPM_NAME_ENV:
    KPM = OUT / KPM_NAME_ENV


def run(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def main() -> None:
    if PROJECT.resolve() != (ROOT / "src/dagu_v02").resolve():
        raise RuntimeError("Unexpected project path")
    clang = llvm_tool("clang")
    ld_lld = llvm_tool("ld.lld")
    llvm_readelf = llvm_tool("llvm-readelf")
    for path in (SDK / "include/hook.h", SDK / "include/kpmodule.h",
                 *(PROJECT / source for source in SOURCES)):
        if not path.is_file():
            raise FileNotFoundError(path)

    OUT.mkdir(exist_ok=True)
    includes = (
        PROJECT,
        SDK / "include",
        SDK / "patch/include",
        SDK / "linux/include",
        SDK / "linux/arch/arm64/include",
        SDK / "linux/tools/arch/arm64/include",
    )
    objects = []
    for source_name in SOURCES:
        source = PROJECT / source_name
        obj = OUT / (source.stem + ".o")
        run(str(clang), "-target", "aarch64-linux-gnu",
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-fno-pic", "-fno-PIE", "-mno-outline-atomics",
            *(f"-D{d}" for d in EXTRA_DEFINES),
            *(f"-I{path}" for path in includes), "-c", str(source), "-o", str(obj))
        symbols = run(str(llvm_readelf), "-s", str(obj))
        if "__aarch64_" in symbols:
            raise RuntimeError(f"Unexpected outlined atomic import in {obj.name}")
        objects.append(obj)

    run(str(ld_lld), "-m", "aarch64elf", "-r",
        *(str(obj) for obj in objects), "-o", str(KPM))
    header = run(str(llvm_readelf), "-h", str(KPM))
    sections = run(str(llvm_readelf), "-S", str(KPM))
    symbols = run(str(llvm_readelf), "-s", str(KPM))
    if "AArch64" not in header or "REL (Relocatable file)" not in header:
        raise RuntimeError("Output is not an ARM64 relocatable ELF")
    for name in (".kpm.info", ".kpm.init", ".kpm.exit"):
        if name not in sections:
            raise RuntimeError(f"Missing KPM section {name}")
    if not re.search(r"UND\s+.*\bhook_wrap\s*$", symbols, re.MULTILINE):
        raise RuntimeError("KernelPatch hook_wrap import absent")
    if not re.search(r"UND\s+.*\bhook_unwrap_remove\s*$", symbols, re.MULTILINE):
        raise RuntimeError("KernelPatch hook_unwrap_remove import absent")
    if "__aarch64_" in symbols:
        raise RuntimeError("Unexpected outlined atomic import")
    unresolved_internal = [
        line.split()[-1] for line in symbols.splitlines()
        if " UND " in line and line.split() and line.split()[-1].startswith("dagu_")
    ]
    if unresolved_internal:
        raise RuntimeError(f"Unresolved internal symbols: {unresolved_internal}")

    digest = hashlib.sha256(KPM.read_bytes()).hexdigest()
    print(f"{KPM.resolve()} size={KPM.stat().st_size} sha256={digest}")
    print(f"linked {len(objects)} functional objects; KernelPatch API imports remain loader-resolved")


if __name__ == "__main__":
    main()
