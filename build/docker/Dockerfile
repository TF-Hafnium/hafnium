# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

FROM ubuntu:24.04

# Install dependencies. Clear APT cache at the end to save space.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
	&& apt-get install -y \
		bc                             `# for Linux headers` \
		bison \
		build-essential \
		cpio \
		flex \
		git \
		clang \
		clangd \
		clang-tidy \
		clang-format \
		llvm \
		lld \
		libc++-dev \
		device-tree-compiler \
		wget                           `# for setup_checkpatch.sh` \
		libpixman-1-0                  `# for QEMU` \
		libsdl2-2.0-0                  `# for QEMU` \
		libglib2.0                     `# for QEMU` \
		libssl-dev                     `# for Linux headers` \
		python3                        `# for all build scripts` \
		python3-serial                 `# for hftest.py` \
		python3-pip                    `# for hftest.py` \
		strace                         `# for strace_open.sh` \
	&& pip3 install --break-system-packages fdt && rm -rf /var/lib/apt/lists/*
