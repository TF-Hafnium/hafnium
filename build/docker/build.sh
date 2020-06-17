#!/usr/bin/env bash
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.inc"

${DOCKER} build \
	--pull \
	-f "${SCRIPT_DIR}/Dockerfile" \
	-t "${CONTAINER_TAG}" \
	"${SCRIPT_DIR}"
