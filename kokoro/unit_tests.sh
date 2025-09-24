#!/bin/bash
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Host unit tests runner (standalone).

# TIMEOUT, PROJECT, OUT, LOG_DIR_BASE set in:
KOKORO_DIR="$(dirname "$0")"
source $KOKORO_DIR/test_common.sh

# Run the host unit tests.
mkdir -p "${LOG_DIR_BASE}/unit_tests"

# Short timeout for host tests; fail fast if broken
${TIMEOUT[@]} 30s "$OUT/host_fake_clang/unit_tests" \
    --gtest_output="xml:${LOG_DIR_BASE}/unit_tests/sponge_log.xml" \
    | tee "${LOG_DIR_BASE}/unit_tests/sponge_log.log"

echo "Unit tests finished. Logs at: ${LOG_DIR_BASE}/unit_tests/"
