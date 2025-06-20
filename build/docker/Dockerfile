# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

FROM ubuntu:24.04

# Install dependencies.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y \
		build-essential \
		cpio \
		flex \
		git \
		device-tree-compiler \
		wget                           `# for setup_checkpatch.sh` \
		libpixman-1-0                  `# for QEMU` \
		libsdl2-2.0-0                  `# for QEMU` \
		libglib2.0                     `# for QEMU` \
		libssl-dev                     `# for Linux headers` \
		python3                        `# for all build scripts` \
		python3-serial                 `# for hftest.py` \
		python3-venv                   `# for hftest.py` \
		nodejs                         `# for Commitlint` \
		npm                            `# for Commitlint`

# Install Clang and LLVM.
# Use the packages from LLVM's repository rather than the default Ubuntu
# repository so we can control the exact version.
ENV LLVM_VERSION=20
RUN wget https://apt.llvm.org/llvm-snapshot.gpg.key -O /etc/apt/keyrings/llvm-snapshot.key
RUN echo "deb [signed-by=/etc/apt/keyrings/llvm-snapshot.key] http://apt.llvm.org/noble/ llvm-toolchain-noble-$LLVM_VERSION main" > /etc/apt/sources.list.d/llvm.list
RUN echo "deb-src [signed-by=/etc/apt/keyrings/llvm-snapshot.key] http://apt.llvm.org/noble/ llvm-toolchain-noble-$LLVM_VERSION main" >> /etc/apt/sources.list.d/llvm.list
RUN apt-get update
RUN apt-get install -y \
		clang-$LLVM_VERSION \
		clangd-$LLVM_VERSION \
		clang-tidy-$LLVM_VERSION \
		clang-format-$LLVM_VERSION \
		llvm-$LLVM_VERSION \
		lld-$LLVM_VERSION \
		libc++-$LLVM_VERSION-dev

# LLVM binaries are present in `/usr/bin` as `clang-20`, `clang-tidy-20`, etc.
# But we want them to be available as `clang`, `clang-tidy`, etc.
# So we create symlinks for them.
RUN for f in /usr/lib/llvm-$LLVM_VERSION/bin/*; do ln -s "$f" /usr/local/bin; done

# Clear APT cache to save space.
RUN rm -rf /var/lib/apt/lists/*

# To use git inside the docker image.
# Create shared config and disable safe directory
ENV GIT_CONFIG_GLOBAL=/opt/shared/.gitconfig
RUN mkdir -p /opt/shared \
	&& touch $GIT_CONFIG_GLOBAL \
	&& git config --global --add safe.directory '*' \
	&& chmod 644 $GIT_CONFIG_GLOBAL

# Preparing for the python3 dependencies in a venv.
# Adding the bin folder to path, so the respective pip
# tool is used.
RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:${PATH}
RUN pip3 install fdt

ARG LOCAL_UID=1000
ARG LOCAL_GID=1000

RUN	addgroup \
		--gid "${LOCAL_GID}" \
		hafnium \
	&& adduser \
		-disabled-password \
		-gecos "" \
		--uid "${LOCAL_UID}" \
		--shell "/bin/bash" \
		--ingroup hafnium \
		hafnium
USER hafnium
