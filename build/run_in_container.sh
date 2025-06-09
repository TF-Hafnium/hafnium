#!/usr/bin/env bash
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname ${SCRIPT_DIR})"

source "${SCRIPT_DIR}/docker/common.inc"

if [ "${HAFNIUM_HERMETIC_BUILD:-}" == "inside" ]
then
	echo "ERROR: Invoked $0 recursively" 1>&2
	exit 1
fi

# Set up a temp directory and register a cleanup function on exit.
TMP_DIR="$(mktemp -d)"
function cleanup() {
	rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# Build local image and write its hash to a temporary file.
IID_FILE="${TMP_DIR}/imgid.txt"
"${DOCKER}" build \
	--build-arg LOCAL_UID="$(id -u)" \
	--build-arg LOCAL_GID="$(id -g)" \
	--iidfile="${IID_FILE}" \
	-f "${SCRIPT_DIR}/docker/Dockerfile" \
	"${SCRIPT_DIR}/docker"
IMAGE_ID="$(cat ${IID_FILE})"

# Parse command line arguments
INTERACTIVE=false
ALLOW_PTRACE=false
TTY=true
while true
do
	case "${1:-}" in
	--tty)
	 	TTY=${2:-}
		shift; shift
		;;
	-i)
		INTERACTIVE=true
		shift
		;;
	-p)
		ALLOW_PTRACE=true
		shift
		;;
	-*)
		echo "ERROR: Unknown command line flag: $1" 1>&2
		echo "Usage: $0 [-i] [-p] [--tty true|false] <command>"
		exit 1
		;;
	*)
		break
		;;
	esac
done

ARGS=()
# Run with a pseduo-TTY for nicer logging.
ARGS+=(--tty=${TTY})
# Run interactive if this script was invoked with '-i'.
if [ "${INTERACTIVE}" == "true" ]
then
	ARGS+=(-i)
fi
# Allow ptrace() syscall if invoked with '-p'.
if [ "${ALLOW_PTRACE}" == "true" ]
then
	echo "WARNING: Docker seccomp profile is disabled!" 1>&2
	ARGS+=(--cap-add=SYS_PTRACE --security-opt seccomp=unconfined)
fi
# Propagate "HAFNIUM_*" environment variables.
# Note: Cannot use `env | while` because the loop would run inside a child
# process and would not have any effect on variables in the parent.
while read -r ENV_LINE
do
	VAR_NAME="$(echo ${ENV_LINE} | cut -d= -f1)"
	case "${VAR_NAME}" in
	HAFNIUM_HERMETIC_BUILD)
		# Skip this one. It will be overridden below.
		;;
	HAFNIUM_*)
		ARGS+=(-e "${ENV_LINE}")
		;;
	esac
done <<< "$(env)"
# Set environment variable informing the build that we are running inside
# a container.
ARGS+=(-e HAFNIUM_HERMETIC_BUILD=inside)
# Bind-mount the Hafnium root directory and the FVP directory. We mount them at
# the same absolute location so that all paths match across the host and guest.
ARGS+=(-v "${ROOT_DIR}":"${ROOT_DIR}")
ARGS+=(-v "${ROOT_DIR}/../fvp":"${ROOT_DIR}/../fvp")
# Make all files outside of the Hafnium directory read-only to ensure that all
# generated files are written there.
ARGS+=(--read-only)
# Mount a writable /tmp folder. Required by LLVM/Clang for intermediate files.
ARGS+=(--tmpfs /tmp)
# Set working directory.
ARGS+=(-w "${ROOT_DIR}")

echo "Running in container: $*" 1>&2
${DOCKER} run \
	${ARGS[@]} \
	"${IMAGE_ID}" \
	/bin/bash -c "$*"
