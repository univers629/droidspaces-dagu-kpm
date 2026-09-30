#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ARM64 Android namespace test helpers without using a device."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src/dagu_v02"))
from build_env import llvm_tool  # noqa: E402


SOURCES = (
    "ns_smoke",
    "ns_advanced",
    "ns_setns_pid_for_children",
    "ns_setns_pid_ancestry",
    "ns_setns_ipc_matrix",
    "ns_setns_pid_ipc_orders",
    "ns_concurrent_ipc",
)


def main() -> None:
    clang = llvm_tool("clang")
    output_dir = ROOT / "tests/build"
    if not output_dir.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Test output directory escaped the repository")
    output_dir.mkdir(parents=True, exist_ok=True)

    for name in SOURCES:
        source = ROOT / "tests" / f"{name}.c"
        output = output_dir / name
        if not source.is_file():
            raise FileNotFoundError(source)
        subprocess.run(
            [str(clang), "--target=aarch64-linux-android29", "-std=c11",
             "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(output)],
            check=True,
        )
        if not output.is_file() or output.stat().st_size <= 0:
            raise RuntimeError(f"Build did not produce a nonempty helper: {output}")
        print(f"Built {output.relative_to(ROOT)} ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
