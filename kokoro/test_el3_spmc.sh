#!/bin/bash
#
# Copyright 2023 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# TIMEOUT, PROJECT, OUT, LOG_DIR_BASE set in:
KOKORO_DIR="$(dirname "$0")"
source $KOKORO_DIR/test_common.sh

HFTEST=(${TIMEOUT[@]} 1000s ./test/hftest/hftest.py)

HYPERVISOR_PATH="$OUT/aem_v8a_fvp_vhe_clang"

HFTEST+=(--log "$LOG_DIR_BASE/el3_spmc")
HFTEST+=(--el3_spmc  --driver=fvp)

# Test Hafnium primary VM with EL3 SPMC and services SP
${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" --out_partitions "$OUT/secure_aem_v8a_fvp_vhe_vm_clang" \
             --partitions_json test/vmapi/ffa_both_worlds_el3_spmc/ffa_both_world_partitions_test.json

#Test Hafnium primary_only_test with EL3 SPMC and TSP SP
${HFTEST[@]}  --out_initrd "$OUT/aem_v8a_fvp_vhe_vm_clang" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                    --initrd test/vmapi/primary_only/primary_only_test

#Test EL3 SPMC with S-EL1 SP based on Hafnium standalone secure SP
${HFTEST[@]} --out_partitions "$OUT/secure_aem_v8a_fvp_vhe_vm_clang" --partitions_json \
	test/vmapi/ffa_secure_partition_el3_spmc/ffa_secure_partition_only_test.json
