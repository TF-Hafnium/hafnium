#!/usr/bin/env bash
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.inc"

# Requires for the user to be an owner of the GCP 'hafnium-build' project and
# have gcloud SDK installed and authenticated.

${DOCKER} push "${CONTAINER_TAG}"
