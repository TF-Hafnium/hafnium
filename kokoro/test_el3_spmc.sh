#!/bin/bash
#
# Copyright 2023 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Default log level
HFTEST_LOG_LEVEL="INFO"
WAIT_FOR_DEBUGGER=false
SUITE=""
TEST=""

# Parse script arguments
while test $# -gt 0
do
  case "$1" in
    --log-level) HFTEST_LOG_LEVEL="$2"; shift
      ;;
    --debug) WAIT_FOR_DEBUGGER=true
      ;;
    --suite) SUITE="$2"; shift
      ;;
    --test)TEST="$2"; shift
      ;;
    -h|--help)
      echo "Usage: $0 [--debug] [--log-level [DEBUG|INFO|WARNING|ERROR]] [--suite <regex>] [--test <regex>]"
      exit 0
      ;;
    *)
      echo "Unexpected argument $1"
      echo "Run with -h or --help for usage."
      exit 1
      ;;
  esac
  shift
done

case "$HFTEST_LOG_LEVEL" in
	DEBUG|INFO|WARNING|ERROR)
	  ;;
	*) echo "Unsupported hftest log level $HFTEST_LOG_LEVEL"
	exit 1
	;;
esac

# TIMEOUT, PROJECT, OUT, LOG_DIR_BASE set in:
KOKORO_DIR="$(dirname "$0")"
source $KOKORO_DIR/test_common.sh

DRIVER="fvp"

HFTEST=(${TIMEOUT[@]} 1000s ./test/hftest/drivers/hftest.py $DRIVER)

HYPERVISOR_PATH="$OUT/aem_v8a_fvp_vhe_ffa_v1_1_clang"

HFTEST+=(--log "$LOG_DIR_BASE/el3_spmc")
HFTEST+=(--el3_spmc)

if [ -n "$SUITE" ]; then
  HFTEST+=(--suite "$SUITE")
fi

if [ -n "$TEST" ]; then
  HFTEST+=(--test "$TEST")
fi

if [ $WAIT_FOR_DEBUGGER = true ]; then
	HFTEST+=(--debug)
fi

# Add hftest loglevel argument
HFTEST+=(--log-level "$HFTEST_LOG_LEVEL")

# Test Hafnium primary VM with EL3 SPMC and services SP
${HFTEST[@]} --hypervisor "$HYPERVISOR_PATH/hafnium.bin" --out_partitions "$OUT/secure_aem_v8a_fvp_vhe_vm_clang" \
             --partitions_json test/vmapi/ffa_both_worlds_el3_spmc/ffa_both_world_partitions_test.json

#Test Hafnium primary_only_test with EL3 SPMC and TSP SP
${HFTEST[@]}  --out_initrd "$OUT/aem_v8a_fvp_vhe_ffa_v1_1_vm_clang" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                    --initrd test/vmapi/primary_only/primary_only_test

#Test EL3 SPMC with S-EL1 SP based on Hafnium standalone secure SP
${HFTEST[@]} --out_partitions "$OUT/secure_aem_v8a_fvp_vhe_vm_clang" --partitions_json \
	test/vmapi/ffa_secure_partition_el3_spmc/ffa_secure_partition_only_test.json
