#!/bin/sh
# Build the macvlan link type module against the device kernel tree.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
NDK_LLVM_BIN=${NDK_LLVM_BIN:-$ROOT/../android-ndk-r28c/toolchains/llvm/prebuilt/linux-x86_64/bin}
KERNEL_TREE=${KERNEL_TREE:-$ROOT/../../ref/dagu-kernel}
KERNEL_OUT=${KERNEL_OUT:-$HOME/kbuild-dagu}

make -C "$KERNEL_TREE" O="$KERNEL_OUT" M="$HERE" ARCH=arm64 \
	CROSS_COMPILE=aarch64-linux-gnu- \
	CC="$NDK_LLVM_BIN/clang --target=aarch64-linux-gnu" \
	LD="$NDK_LLVM_BIN/ld.lld" AR="$NDK_LLVM_BIN/llvm-ar" \
	NM="$NDK_LLVM_BIN/llvm-nm" OBJCOPY="$NDK_LLVM_BIN/llvm-objcopy" \
	STRIP="$NDK_LLVM_BIN/llvm-strip" modules
"$NDK_LLVM_BIN/llvm-strip" --strip-debug "$HERE/dagu_macvlan.ko" \
	-o "$HERE/dagu_macvlan.stripped.ko"
ls -l "$HERE/dagu_macvlan.stripped.ko"
