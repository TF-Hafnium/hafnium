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

USE_VHE=false
EL0_TEST_ONLY=false

while test $# -gt 0
do
  case "$1" in
    --vhe) USE_VHE=true
      ;;
    --el0) EL0_TEST_ONLY=true
      ;;
    *) echo "Unexpected argument $1"
      exit 1
      ;;
  esac
  shift
done

HFTEST=(${TIMEOUT[@]} 300s ./test/hftest/hftest.py)
if [ $USE_VHE == true ]
then
  SPMC_PATH="$OUT/secure_aem_v8a_fvp_vhe_clang"
  HYPERVISOR_PATH="$OUT/aem_v8a_fvp_vhe_clang"
  HFTEST+=(--out_partitions "$OUT/secure_aem_v8a_fvp_vhe_vm_clang")
else
  SPMC_PATH="$OUT/secure_aem_v8a_fvp_clang"
  HYPERVISOR_PATH="$OUT/aem_v8a_fvp_clang"
  HFTEST+=(--out_partitions "$OUT/secure_aem_v8a_fvp_vm_clang")
fi

HFTEST+=(--log "$LOG_DIR_BASE")
HFTEST+=(--spmc "$SPMC_PATH/hafnium.bin" --driver=fvp)

if [ $EL0_TEST_ONLY == false ]
then
  ${HFTEST[@]} --partitions_json test/vmapi/ffa_secure_partition_only/ffa_secure_partition_only_test.json

  ${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
               --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_test.json
fi

if [ $USE_VHE == true ]
then
  ${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
    --partitions_json test/vmapi/el0_partitions/secure_partitions/ffa_both_world_partitions_test.json
fi
