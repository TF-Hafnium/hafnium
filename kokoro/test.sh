#!/bin/bash
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Note: this assumes that the images have all been built and the current working
# directory is the root of the repo.

USE_FVP=false
USE_TFA=false
EL0_TEST_ONLY=false
SKIP_LONG_RUNNING_TESTS=false
SKIP_UNIT_TESTS=false
ASSERT_DISABLED_BUILD=false
DEFAULT_HFTEST_TIMEOUT="600s"

while test $# -gt 0
do
  case "$1" in
    --fvp) USE_FVP=true
      ;;
    --tfa) USE_TFA=true
      ;;
    --el0) EL0_TEST_ONLY=true
      ;;
    --skip-unit-tests) SKIP_UNIT_TESTS=true
      ;;
    --skip-long-running-tests) SKIP_LONG_RUNNING_TESTS=true
      ;;
    --assert-disabled-build) ASSERT_DISABLED_BUILD=true
      ;;
    *) echo "Unexpected argument $1"
      exit 1
      ;;
  esac
  shift
done

# TIMEOUT, PROJECT, OUT, LOG_DIR_BASE set in:
KOKORO_DIR="$(dirname "$0")"
source $KOKORO_DIR/test_common.sh

# Run the tests with a timeout so they can't loop forever.
HFTEST=(${TIMEOUT[@]} $DEFAULT_HFTEST_TIMEOUT ./test/hftest/hftest.py)
HYPERVISOR_PATH="$OUT/"
if [ $USE_FVP == true ]
then
  HYPERVISOR_PATH+="aem_v8a_fvp_vhe_clang"
  HFTEST+=(--out_initrd "$OUT/aem_v8a_fvp_vhe_vm_clang")
  HFTEST+=(--out_partitions "$OUT/aem_v8a_fvp_vhe_vm_clang")
  HFTEST+=(--driver=fvp)
else
  HYPERVISOR_PATH+="qemu_aarch64_vhe_clang"
  HFTEST+=(--out_initrd "$OUT/qemu_aarch64_vhe_vm_clang")
fi
if [ $USE_TFA == true ]
then
  HFTEST+=(--tfa)
fi
if [ $SKIP_LONG_RUNNING_TESTS == true ]
then
  HFTEST+=(--skip-long-running-tests)
fi

if [ $SKIP_UNIT_TESTS == false ]
then
# Run the host unit tests.
mkdir -p "${LOG_DIR_BASE}/unit_tests"
  ${TIMEOUT[@]} 30s "$OUT/host_fake_clang/unit_tests" \
    --gtest_output="xml:${LOG_DIR_BASE}/unit_tests/sponge_log.xml" \
    | tee "${LOG_DIR_BASE}/unit_tests/sponge_log.log"
fi

if [ $USE_FVP == false ]
then
  HFTEST+=(--cpu "max")
fi

HFTEST+=(--log "$LOG_DIR_BASE")

if [ $EL0_TEST_ONLY == false ]
then
  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/arch_test.bin"
  if [ $USE_TFA == true -o $USE_FVP == true ]
  then
    "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/aarch64_test.bin"
  fi

  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                     --initrd test/vmapi/arch/aarch64/aarch64_test

  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                     --initrd test/vmapi/arch/aarch64/gicv3/gicv3_test

  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                     --initrd test/vmapi/primary_only/primary_only_test

  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                     --initrd test/vmapi/primary_with_secondaries/primary_with_secondaries_test

  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                     --initrd test/vmapi/primary_with_secondaries/primary_with_secondaries_no_fdt
fi

  "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                     --initrd test/vmapi/primary_with_secondaries/primary_with_secondaries_el0_test

if [ $USE_TFA == true ] && [ $USE_FVP == true ]
then
   "${HFTEST[@]}" --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                      --partitions_json test/vmapi/primary_only_ffa/primary_only_ffa_test.json
fi
