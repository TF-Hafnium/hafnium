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
		npm                            `# for Commitlint` \
                netcat-openbsd \
                telnet \
		curl

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

# Install GNU Arm Toolchain (v14.2.rel1) for AArch64
ARG GNU_TOOLCHAIN_VERSION=14.2.rel1
ARG GNU_TOOLCHAIN_DIR=/opt/gcc-arm

COPY gnu_installation.sh /tmp/gnu_installation.sh
RUN /tmp/gnu_installation.sh $GNU_TOOLCHAIN_VERSION $GNU_TOOLCHAIN_DIR

# Add GNU toolchain binaries to /usr/local/bin via symlinks for global access
RUN TOOLCHAIN_DIR=$(find ${GNU_TOOLCHAIN_DIR} -maxdepth 1 -type d -name "arm-gnu-toolchain-*") && \
    ln -s $TOOLCHAIN_DIR/bin/* /usr/local/bin

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
RUN pip3 install fdt pyyaml termcolor tuxmake click

#Poetry Installation
ENV POETRY_HOME="/tools/poetry"
ENV PATH="${POETRY_HOME}/bin:${PATH}"
RUN curl -sSL https://install.python-poetry.org | python3 -

# Ensure Poetry creates .venv inside the project directory.
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

ARG LOCAL_UID=1000
ARG LOCAL_GID=1000

# Create group if needed
RUN if ! getent group "${LOCAL_GID}" > /dev/null; then \
      addgroup --gid "${LOCAL_GID}" hafnium; \
    else \
      echo "Group with GID ${LOCAL_GID} already exists. Reusing it."; \
    fi

# Create user if needed
RUN if ! getent passwd "${LOCAL_UID}" > /dev/null; then \
      adduser --disabled-password --gecos "" \
        --uid "${LOCAL_UID}" \
        --shell "/bin/bash" \
        --gid "${LOCAL_GID}" \
        hafnium; \
    else \
      echo "User with UID ${LOCAL_UID} already exists. Skipping user creation."; \
    fi

# Explicitly switch to 'hafnium' user if it now exists
USER hafnium

# Set HOME to /tmp to ensure compatibility with Python tools like Poetry and
# virtualenv, especially during TF-A builds that invoke them (e.g., sp_mk_generator.py).
# This prevents permission errors when these tools attempt to create `.venv`
# or write to `.cache` inside /home/hafnium, which may not be writable at build or runtime.
ENV HOME=/tmp
