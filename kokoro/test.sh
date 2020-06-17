#!/bin/bash
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Note: this assumes that the images have all been built and the current working
# directory is the root of the repo.

# Fail on any error.
set -e
# Fail on any part of a pipeline failing.
set -o pipefail
# Treat unset variables as an error.
set -u
# Display commands being run.
set -x

USE_FVP=false
USE_TFA=false
SKIP_LONG_RUNNING_TESTS=false
RUN_ALL_QEMU_CPUS=false

while test $# -gt 0
do
  case "$1" in
    --fvp) USE_FVP=true
      ;;
    --tfa) USE_TFA=true
      ;;
    --skip-long-running-tests) SKIP_LONG_RUNNING_TESTS=true
      ;;
    --run-all-qemu-cpus) RUN_ALL_QEMU_CPUS=true
      ;;
    *) echo "Unexpected argument $1"
      exit 1
      ;;
  esac
  shift
done

TIMEOUT=(timeout --foreground)
PROJECT="${PROJECT:-reference}"
OUT="out/${PROJECT}"
LOG_DIR_BASE="${OUT}/kokoro_log"

# Run the tests with a timeout so they can't loop forever.
HFTEST=(${TIMEOUT[@]} 300s ./test/hftest/hftest.py)
if [ $USE_FVP == true ]
then
  HFTEST+=(--driver=fvp)
  HFTEST+=(--out "$OUT/aem_v8a_fvp_clang")
  HFTEST+=(--out_initrd "$OUT/aem_v8a_fvp_vm_clang")
else
  HFTEST+=(--out "$OUT/qemu_aarch64_clang")
  HFTEST+=(--out_initrd "$OUT/qemu_aarch64_vm_clang")
fi
if [ $USE_TFA == true ]
then
  HFTEST+=(--tfa)
fi
if [ $SKIP_LONG_RUNNING_TESTS == true ]
then
  HFTEST+=(--skip-long-running-tests)
fi

# Add prebuilt libc++ to the path.
export LD_LIBRARY_PATH="$PWD/prebuilts/linux-x64/clang/lib64"

# Run the host unit tests.
mkdir -p "${LOG_DIR_BASE}/unit_tests"
${TIMEOUT[@]} 30s "$OUT/host_fake_clang/unit_tests" \
  --gtest_output="xml:${LOG_DIR_BASE}/unit_tests/sponge_log.xml" \
  | tee "${LOG_DIR_BASE}/unit_tests/sponge_log.log"

CPUS=("")

if [ $RUN_ALL_QEMU_CPUS == true ]
then
  CPUS=("cortex-a53" "max")
fi

for CPU in "${CPUS[@]}"
do
  HFTEST_CPU=("${HFTEST[@]}")
  if [ -n "$CPU" ]
  then
    # Per-CPU log directory to avoid filename conflicts.
    HFTEST_CPU+=(--cpu "$CPU" --log "$LOG_DIR_BASE/$CPU")
  else
    HFTEST_CPU+=(--log "$LOG_DIR_BASE")
  fi
  "${HFTEST_CPU[@]}" arch_test
  if [ $USE_TFA == true -o $USE_FVP == true ]
  then
    "${HFTEST_CPU[@]}" aarch64_test
  fi
  "${HFTEST_CPU[@]}" hafnium --initrd test/vmapi/arch/aarch64/aarch64_test
  "${HFTEST_CPU[@]}" hafnium --initrd test/vmapi/arch/aarch64/gicv3/gicv3_test
  "${HFTEST_CPU[@]}" hafnium --initrd test/vmapi/primary_only/primary_only_test
  "${HFTEST_CPU[@]}" hafnium --initrd test/vmapi/primary_with_secondaries/primary_with_secondaries_test
  "${HFTEST_CPU[@]}" hafnium --initrd test/linux/linux_test --force-long-running --vm_args "rdinit=/test_binary --"
done
