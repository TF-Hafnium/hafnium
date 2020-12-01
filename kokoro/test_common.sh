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
PROJECT="${PROJECT:-reference}"
OUT="out/${PROJECT}"
LOG_DIR_BASE="${OUT}/kokoro_log"

export LD_LIBRARY_PATH="$PWD/prebuilts/linux-x64/clang/lib64"

