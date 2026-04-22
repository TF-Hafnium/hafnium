#!/usr/bin/env bash
#
# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

FROM="${1:-HEAD~1}"
TO="${2:-HEAD}"

# Always run from the repository root so npm and commitlint use the
# correct package.json, package-lock.json, and commitlint config.
cd "${ROOT_DIR}"

# Use a writable npm cache location for CI environments.
export npm_config_cache=/tmp/.npm

# Print runtime versions for easier debugging in Jenkins logs.
node --version
npm --version

# Install dependencies exactly as pinned in package-lock.json (clean, reproducible CI install)
npm ci

# Execute the commitlint command.
npx commitlint --from=$FROM --to=$TO --verbose
