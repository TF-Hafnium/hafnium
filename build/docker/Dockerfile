# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

#
# Base container image to be uploaded to Google Cloud Platform as
# "eu.gcr.io/hafnium-build/hafnium_ci". Each user derives their own container
# with local user permissions from this base image. It should contain everything
# needed to build and test Hafnium.
#
FROM launcher.gcr.io/google/ubuntu1804
MAINTAINER Hafnium Team <hafnium-team+build@google.com>

# Install dependencies. Clear APT cache at the end to save space.
ENV DEBIAN_FRONTEND=noninteractive
RUN 	apt-get update \
	&& apt-get install -y \
		bc                             `# for Linux headers` \
		bison \
		build-essential \
		cpio \
		flex \
		git \
		libpixman-1-0                  `# for QEMU` \
		libsdl2-2.0-0                  `# for QEMU` \
		libglib2.0                     `# for QEMU` \
		libssl-dev                     `# for Linux headers` \
		python \
		python-git                     `# for Linux checkpatch` \
		python-ply                     `# for Linux checkpatch` \
		python3                        `# for all build scripts` \
		python3-serial                 `# for hftest.py` \
		python3-pip                    `# for hftest.py` \
		strace                         `# for strace_open.sh` \
	&& pip3 install fdt && rm -rf /var/lib/apt/lists/*
