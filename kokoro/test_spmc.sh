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

HFTEST=(${TIMEOUT[@]} 600s ./test/hftest/hftest.py)

SPMC_PATH="$OUT/secure_aem_v8a_fvp_vhe_clang"
HYPERVISOR_PATH="$OUT/aem_v8a_fvp_vhe_clang"
HFTEST+=(--out_partitions $OUT/secure_aem_v8a_fvp_vhe_vm_clang)

HFTEST+=(--log "$LOG_DIR_BASE")

HFTEST+=(--spmc "$SPMC_PATH/hafnium.bin" --driver=fvp)

USE_PARITY=false
USAGE="Use --parity to run EL3 SPMC testsuite"

while test $# -gt 0
do
  case "$1" in
    --parity) USE_PARITY=true
      ;;
    -h) echo $USAGE
	exit 1
	;;
    --help) echo $USAGE
	exit 1
	;;
    *) echo "Unexpected argument $1"
	echo $USAGE
	exit 1
	;;
  esac
  shift
done

if [ $USE_PARITY == true ]
then
   ${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" --partitions_json test/vmapi/ffa_both_worlds_el3_spmc/ffa_both_world_partitions_test.json

   ${HFTEST[@]} --partitions_json test/vmapi/ffa_secure_partition_el3_spmc/ffa_secure_partition_only_test.json
fi

${HFTEST[@]} --partitions_json test/vmapi/ffa_secure_partition_only/ffa_secure_partition_only_test.json

${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_test.json

${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/primary_with_secondaries/primary_with_sp.json

${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                 --partitions_json test/vmapi/primary_with_secondaries/primary_with_sp_vhe.json

${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                 --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_vhe_test.json
