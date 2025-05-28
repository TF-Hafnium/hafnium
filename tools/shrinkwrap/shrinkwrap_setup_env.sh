#!/usr/bin/env bash

# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.


# ------------------------------------------------------------------------------
# Note for Developers:
#
# This script sets up the Shrinkwrap environment for local standalone use.
# It is intended for local workflows where you run Shrinkwrap directly,
# outside of `hftest.py`, to build and run Hafnium along with TF-A and TF-A-Test
# projects — particularly when validating SPM-related test suites from TF-A-Test.
#
# If you are running hafnium CI tests via hftest.py, Shrinkwrap is automatically
# configured internally by the test script (hftest.py) — sourcing this script
# is optional.
#
# Usage:
#   source ./../shrinkwrap_setup_env.sh
#   shrinkwrap build ...
#   shrinkwrap run ...
#
# This script ensures the necessary PATH and SHRINKWRAP_* variables are exported
# for use in manual shell workflows.
# Note: Hafnium CI and automation rely on the Python-based setup in
# `ShrinkwrapManager.setup_env()`. If any environment paths or variables change
# here, please update the Python logic accordingly — and vice versa.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "Please source this script to retain environment changes:"
  echo "source $0"
  return 1 2>/dev/null || exit 1
fi

HAFNIUM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHRINKWRAP_DIR="$HAFNIUM_ROOT/third_party"

echo "[+] Hafnium root: $HAFNIUM_ROOT"
echo "[+] Shrinkwrap directory: $SHRINKWRAP_DIR"

# Add Shrinkwrap to PATH
export PATH="$SHRINKWRAP_DIR/shrinkwrap/shrinkwrap:$PATH"

# Set up Shrinkwrap environment variables for Build and Packaging
export SHRINKWRAP_CONFIG="${HAFNIUM_ROOT}/tools/shrinkwrap/configs"
export WORKSPACE="${HAFNIUM_ROOT}/out"
export SHRINKWRAP_BUILD="${WORKSPACE}/build"
export SHRINKWRAP_PACKAGE="${WORKSPACE}/package"

echo "[+] Environment ready. Shrinkwrap is now in PATH."

# Print Shrinkwrap version to confirm availability
echo -n "[+] Shrinkwrap version: "
shrinkwrap --version
