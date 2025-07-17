#!/usr/bin/env bash
# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

set -e

GNU_TOOLCHAIN_VERSION="$1"
GNU_TOOLCHAIN_DIR="$2"

ARCH=$(uname -m)

case "$ARCH" in
    x86_64)
        GNU_TOOLCHAIN_ARCH="x86_64"
        ;;
    aarch64)
        GNU_TOOLCHAIN_ARCH="aarch64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

cd /tmp
mkdir -p "$GNU_TOOLCHAIN_DIR"

GNU_TOOLCHAIN_URL="https://developer.arm.com/-/media/Files/downloads/gnu/${GNU_TOOLCHAIN_VERSION}/binrel/arm-gnu-toolchain-${GNU_TOOLCHAIN_VERSION}-${GNU_TOOLCHAIN_ARCH}-aarch64-none-elf.tar.xz"

echo "Downloading GNU Arm Toolchain from: $GNU_TOOLCHAIN_URL"
wget -q "$GNU_TOOLCHAIN_URL"
tar -xf arm-gnu-toolchain-${GNU_TOOLCHAIN_VERSION}-${GNU_TOOLCHAIN_ARCH}-aarch64-none-elf.tar.xz -C "$GNU_TOOLCHAIN_DIR"
rm arm-gnu-toolchain-${GNU_TOOLCHAIN_VERSION}-${GNU_TOOLCHAIN_ARCH}-aarch64-none-elf.tar.xz
