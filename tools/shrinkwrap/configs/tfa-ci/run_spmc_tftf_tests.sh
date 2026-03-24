#!/bin/bash
set -euo pipefail

# Positional arguments:
#   $1 - base config file name under tools/shrinkwrap/configs/tfa-ci/common/
#        Example: hafnium-tftf-base.yaml
#   $2 - test group directory name under tools/shrinkwrap/configs/tfa-ci/
#        Currently used with: spmc-tftf-tests
# The selected test group must provide:
#   - a manifest.txt listing overlay file names
#   - an overlays/ directory containing those overlay YAML files
#
# Each overlay extends the common base config and is built/run independently.

#Global Definitions
# Resolve Hafnium repository root relative to this script location.
# This allows the script to be invoked from any directory.
HAFNIUM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
WORKSPACE="${HAFNIUM_ROOT}"

# Allow overriding source paths via environment (useful in CI),
# otherwise default to expected local checkout layout.
HAFNIUM_SRC="${HAFNIUM_SRC:-$(realpath "${WORKSPACE}")}"
TFA_SRC="${TFA_SRC:-$(realpath "${WORKSPACE}/../trusted-firmware-a")}"
TFTF_SRC="${TFTF_SRC:-$(realpath "${WORKSPACE}/../tf-a-tests")}"

# Base configuration and test group definition.
# Overlays listed in the manifest extend this base config.
# Allow the caller to select the base config and test group.
BASE_CFG="${1:?Usage: $0 <base-config> <test-group>}"
TEST_GROUP="${2:?Usage: $0 <base-config> <test-group>}"
MANIFEST="${WORKSPACE}/tools/shrinkwrap/configs/tfa-ci/${TEST_GROUP}/manifest.txt"

# Optional common build mode override for both TF-A and TFTF.
# When omitted, Shrinkwrap falls back to the btvar defaults(release) from the base YAML.
# Supported values: debug, release
BUILD_MODE="${3:-}"

case "${BUILD_MODE}" in
    ""|debug|release) ;;
    *)
        echo "Invalid build mode: ${BUILD_MODE}"
        echo "Usage: $0 <base-config> <test-group> [debug|release]"
        exit 1
        ;;
esac

BUILD_TYPE_ARGS=()
if [ -n "${BUILD_MODE}" ]; then
    BUILD_TYPE_ARGS+=(--btvar=TFA_BUILD="${BUILD_MODE}")
    BUILD_TYPE_ARGS+=(--btvar=TFTF_BUILD="${BUILD_MODE}")
fi

# Shared root directories for build and packaged outputs.
BUILD_ROOT="${WORKSPACE}/out/build"
PACKAGE_ROOT="${WORKSPACE}/out/package"

export PATH="${WORKSPACE}/third_party/shrinkwrap/shrinkwrap:${PATH}"
export SHRINKWRAP_CONFIG="${WORKSPACE}/tools/shrinkwrap/configs/tfa-ci"

# Set default output roots; overridden per test iteration below.
export SHRINKWRAP_BUILD="${BUILD_ROOT}"
export SHRINKWRAP_PACKAGE="${PACKAGE_ROOT}"

# Ensure execution from Hafnium root so that relative paths
# (e.g. overlay logfile locations under out/package) resolve correctly.
cd "${HAFNIUM_ROOT}"

RESULT=0
GROUP_PASSED=0
GROUP_FAILED=0

# Open manifest on a dedicated file descriptor to avoid stdin conflicts
# with shrinkwrap run (which may consume stdin).
exec 3< "${MANIFEST}"

while IFS= read -r overlay_name <&3 || [ -n "${overlay_name}" ]; do
    # Skip empty lines and comments.
    [ -z "${overlay_name}" ] && continue
    [[ "${overlay_name}" =~ ^# ]] && continue

    # Derive a stable per-test name from the overlay filename.
    # Example:
    #   overlay_name = fvp-spm-ivy-vhe.yaml
    #   test_name    = fvp-spm-ivy-vhe
    #
    # Build the overlay path relative to SHRINKWRAP_CONFIG so it can be
    # passed directly to `shrinkwrap build --overlay=...`.
    test_name="$(basename "${overlay_name}" .yaml)"
    overlay="${TEST_GROUP}/overlays/${overlay_name}"

    # Use per-test output directories to isolate artifacts.
    export SHRINKWRAP_BUILD="${BUILD_ROOT}/${TEST_GROUP}/${test_name}"
    export SHRINKWRAP_PACKAGE="${PACKAGE_ROOT}/${TEST_GROUP}/${test_name}"

    log_dir="${PACKAGE_ROOT}/${TEST_GROUP}/${test_name}/log"
    mkdir -p "${log_dir}"

    build_log="${log_dir}/build.log"
    run_log="${log_dir}/run.log"

    echo
    echo "------------------------------------------------------------"
    echo " TEST: ${test_name}"
    echo "------------------------------------------------------------"

    if shrinkwrap --runtime=null build "common/${BASE_CFG}" \
        --overlay="${overlay}" \
        --btvar=HAFNIUM_SRC="${HAFNIUM_SRC}" \
        --btvar=TFA_SRC="${TFA_SRC}" \
        --btvar=TFTF_SRC="${TFTF_SRC}" \
        "${BUILD_TYPE_ARGS[@]}" \
        --no-sync-all \
        --verbose >"${build_log}" 2>&1; then
        echo "Build: PASS"
    else
        echo "Build : FAIL"
        echo "Logs  : ${log_dir}"
        echo "Last 40 lines of build.log:"
        tail -n 40 "${build_log}" || true
        echo "Result: FAIL (build failed)"
        echo "------------------------------------------------------------"
        GROUP_FAILED=$((GROUP_FAILED + 1))
        RESULT=1
        echo
        continue
    fi

    if timeout 5m shrinkwrap --runtime=null run "${BASE_CFG}" >"${run_log}" 2>&1; then
        echo "Run: PASS"
    else
        rc=$?
        # `timeout` returns exit code 124 when the command exceeds the time limit.
        TIMEOUT_EXIT_CODE=124

        if [ "${rc}" -eq "${TIMEOUT_EXIT_CODE}" ]; then
            echo "Run   : FAIL (timeout)"
        else
            echo "Run   : FAIL"
        fi
        echo "Logs  : ${log_dir}"
        echo "Last 40 lines of run.log:"
        tail -n 40 "${run_log}" || true
        echo "Result: FAIL (run failed)"
        echo "------------------------------------------------------------"
        GROUP_FAILED=$((GROUP_FAILED + 1))
        RESULT=1
        echo
        continue
    fi

    # Determine expected behavior from overlay
    if [[ "${test_name}" == *"crash-debug"* ]]; then
        if grep -q "PANIC" "${log_dir}/uart1.log" 2>/dev/null || \
            grep -q "PANIC" "${log_dir}/uart0.log" 2>/dev/null; then
            echo "Expected panic observed -> PASS (${test_name})"
            GROUP_PASSED=$((GROUP_PASSED + 1))
        else
            echo "Expected panic NOT observed -> FAIL (${test_name})"
            GROUP_FAILED=$((GROUP_FAILED + 1))
            RESULT=1
        fi
    else
        # normal TFTF evaluation
        if grep -q "Tests Failed  : 0" "${log_dir}/uart0.log"; then
            GROUP_PASSED=$((GROUP_PASSED + 1))
        else
            GROUP_FAILED=$((GROUP_FAILED + 1))
            RESULT=1
        fi
    fi

    echo "Logs  : ${log_dir}"
    echo "------------------------------------------------------------"
    echo
done

# Close manifest file descriptor.
exec 3<&-

echo
echo "================================================================"
echo "GROUP SUMMARY: ${TEST_GROUP}"
echo "Passed   : ${GROUP_PASSED}"
echo "Failed   : ${GROUP_FAILED}"
echo "Artifacts: ${PACKAGE_ROOT}/${TEST_GROUP}"
echo "================================================================"

exit "${RESULT}"
