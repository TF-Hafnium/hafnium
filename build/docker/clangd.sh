#!/usr/bin/env bash
# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# This wrapper script runs `clangd` in the Docker container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname ${SCRIPT_DIR})"

# Disable tty allocation, otherwise `clangd` crashes.
exec "${BUILD_DIR}/run_in_container.sh" -i --tty false clangd "$@"
