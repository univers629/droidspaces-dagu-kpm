# SPDX-License-Identifier: GPL-2.0-only
"""Locate the pinned Android NDK LLVM toolchain across supported hosts."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path


NDK_VERSION = "28.2.13676358"


def _host_tag() -> str:
    if sys.platform == "win32":
        return "windows-x86_64"
    if sys.platform.startswith("linux"):
        return "linux-x86_64"
    if sys.platform == "darwin":
        machine = platform.machine().lower()
        return "darwin-arm64" if machine in {"arm64", "aarch64"} else "darwin-x86_64"
    raise RuntimeError(f"Unsupported Android NDK host platform: {sys.platform}")


def _sdk_roots() -> list[Path]:
    roots: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value).expanduser())

    home = Path.home()
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        roots.append(Path(local_app_data) / "Android/Sdk" if local_app_data else
                     home / "AppData/Local/Android/Sdk")
    elif sys.platform == "darwin":
        roots.append(home / "Library/Android/sdk")
    else:
        roots.append(home / "Android/Sdk")
    return roots


def llvm_bin() -> Path:
    direct_bin = os.environ.get("NDK_LLVM_BIN")
    if direct_bin:
        result = Path(direct_bin).expanduser()
        if result.is_dir():
            return result
        raise FileNotFoundError(f"NDK_LLVM_BIN is not a directory: {result}")

    for variable in ("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"):
        value = os.environ.get(variable)
        if value:
            ndk = Path(value).expanduser()
            candidate = ndk / "toolchains/llvm/prebuilt" / _host_tag() / "bin"
            if candidate.is_dir():
                return candidate
            raise FileNotFoundError(
                f"Could not find the pinned NDK LLVM toolchain under {ndk}; "
                "set NDK_LLVM_BIN to its host bin directory"
            )

    for sdk in _sdk_roots():
        candidate = (sdk / "ndk" / NDK_VERSION / "toolchains/llvm/prebuilt" /
                     _host_tag() / "bin")
        if candidate.is_dir():
            return candidate

    raise FileNotFoundError(
        f"Android NDK {NDK_VERSION} was not found. Set ANDROID_NDK_ROOT, "
        "ANDROID_NDK_HOME, or NDK_LLVM_BIN; see docs/DEVELOPMENT.md."
    )


def llvm_tool(name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    result = llvm_bin() / f"{name}{suffix}"
    if not result.is_file():
        raise FileNotFoundError(result)
    return result
