#!/bin/bash
#
# Copyright 2020 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Fail on any error.
set -e
# Fail on any part of a pipeline failing.
set -o pipefail
# Treat unset variables as an error.
set -u
# Display commands being run.
set -x

TIMEOUT=(timeout --foreground)
# Set path to prebuilts used in the build.
UNAME_S=$(uname -s | tr '[:upper:]' '[:lower:]')
UNAME_M=$(uname -m)

if [ $UNAME_M == "x86_64" ]
then
        UNAME_M=x64
fi

export PREBUILTS="$PWD/prebuilts/${UNAME_S}-${UNAME_M}"

# Find out where libc++.so.1 resides so that LD_LIBRARY_PATH is adjusted to
# the right toolchain lib path. This is required by unit tests.
# Do an explicit search because the libs path is different from older toolchains
# (e.g. LLVM/clang 12) to newer toolchains (e.g. clang 15).
LLVM_LIB_PATH=$(clang -print-file-name="libc++.so.1")
export LD_LIBRARY_PATH=$(dirname ${LLVM_LIB_PATH})

# Set output and log directories.
PROJECT="${PROJECT:-reference}"
OUT="out/${PROJECT}"
# Use the gn args command to search the value of enable_assertions in the
# args.gn config file. Use grep to take the value from within the quotes.
ENABLE_ASSERTIONS_BUILD=$(${PREBUILTS}/gn/gn args out/reference \
				--list=enable_assertions --short \
			  | grep -oP '(?<=").*(?=")')
if [ "$ENABLE_ASSERTIONS_BUILD" == "1" ]
then
	BUILD_TYPE="debug"
else
	BUILD_TYPE="release"
fi
LOG_DIR_BASE="${OUT}/kokoro_log/${BUILD_TYPE}"
