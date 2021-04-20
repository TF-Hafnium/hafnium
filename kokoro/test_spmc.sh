#!/bin/bash
#
# Copyright 2020 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# TIMEOUT, PROJECT, OUT, LOG_DIR_BASE set in:
KOKORO_DIR="$(dirname "$0")"
source $KOKORO_DIR/test_common.sh

HFTEST=(${TIMEOUT[@]} 300s ./test/hftest/hftest.py)
SPMC_PATH="$OUT/secure_aem_v8a_fvp_clang"
HYPERVISOR_PATH="$OUT/aem_v8a_fvp_clang"

HFTEST+=(--out_partitions "$OUT/secure_aem_v8a_fvp_vm_clang")
HFTEST+=(--log "$LOG_DIR_BASE")
HFTEST+=(--spmc "$SPMC_PATH/hafnium.bin" --driver=fvp)

${HFTEST[@]} --partitions_json test/vmapi/ffa_secure_partition_only/ffa_secure_partition_only_test.json

${HFTEST[@]} --partitions_json test/vmapi/ffa_secure_partitions/ffa_secure_partitions_test.json

${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_test.json
