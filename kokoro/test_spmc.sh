#!/bin/bash
#
# Copyright 2020 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# TIMEOUT, PROJECT, OUT, LOG_DIR_BASE set in:
set +x

# Executes a test suite and if code coverage is enabled then the trace files
# produced by the test suite are moved to a predefined folder along with the
# elf file(s) that contains the DWARF signature to be matched to the trace
# files.
execute_test() {
  # The first argument is by reference and contains the bash command with
  # parameters to execute the test suite
  local -n runner=$1
  shift

  command="${runner[@]} $@" # The rest of arguments are extra parameters
  if [ "$CODE_COVERAGE" = true ];then
    ${command} || true
    move_log_files ${WORKSPACE} trace_folder
    # If one of the parameters of the executed command was spmc or hypervisor
    # we need to extract the path to the binary to get the elf files
    if [[ "${command}" =~ ^.+?--spmc[[:space:]]([^[:space:]]+?).+$ ]]; then
      append_elf_file "${WORKSPACE}/$(dirname ${BASH_REMATCH[1]})/hafnium.elf" $trace_folder
    fi
    if [[ "${command}" =~ ^.+?--hypervisor[[:space:]]([^[:space:]]+?).+$ ]]; then
      append_elf_file "${WORKSPACE}/$(dirname ${BASH_REMATCH[1]})/hafnium.elf" $trace_folder
    fi
  else
    ${command}
  fi

}

KOKORO_DIR="$(dirname "$0")"
source $KOKORO_DIR/test_common.sh

HFTEST=(${TIMEOUT[@]} 1200s ./test/hftest/hftest.py)

SPMC_PATH="$OUT/secure_aem_v8a_fvp_vhe_clang"
HYPERVISOR_PATH="$OUT/aem_v8a_fvp_vhe_clang"
HFTEST+=(--out_partitions $OUT/secure_aem_v8a_fvp_vhe_vm_clang)

HFTEST+=(--log "$LOG_DIR_BASE")

HFTEST+=(--spmc "$SPMC_PATH/hafnium.bin" --driver=fvp)

USE_PARITY=false
CODE_COVERAGE=false

USAGE="Use --parity to run EL3 SPMC testsuite; --code-coverage to enable code coverage"

while test $# -gt 0
do
  case "$1" in
    --parity) USE_PARITY=true
      ;;
    --code-coverage) CODE_COVERAGE=true
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

if [ "$CODE_COVERAGE" = true ]; then
  source $KOKORO_DIR/qa-code-coverage.sh
  FALLBACK_PLUGIN_URL="https://downloads.trustedfirmware.org/coverage-plugin/qa-tools/coverage-tool/coverage-plugin"
  enable_code_coverage
  HFTEST+=(--coverage_plugin "$coverage_trace_plugin")
fi

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_boot_fail_test_sp1.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_boot_fail_test_sp2.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_boot_fail_test_sp3.json

if [ $USE_PARITY == true ]
then
   execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" --partitions_json test/vmapi/ffa_both_worlds_el3_spmc/ffa_both_world_partitions_test.json

   execute_test HFTEST --partitions_json test/vmapi/ffa_secure_partition_el3_spmc/ffa_secure_partition_only_test.json
fi

execute_test HFTEST --partitions_json test/vmapi/ffa_secure_partition_only/ffa_secure_partition_only_test.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_test.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
             --partitions_json test/vmapi/primary_with_secondaries/primary_with_sp.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                 --partitions_json test/vmapi/primary_with_secondaries/primary_with_sp_vhe.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                 --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_vhe_test.json

execute_test HFTEST --hypervisor "$HYPERVISOR_PATH/hafnium.bin" \
                 --partitions_json test/vmapi/ffa_secure_partitions/ffa_both_world_partitions_sel1_up_test.json

if [ "$CODE_COVERAGE" = true ]; then
  create_configuration_file
  generate_intermediate_layer
  create_coverage_report
  generate_header "${WORKSPACE}/report.html"
  echo "Finished code coverage..."
fi
