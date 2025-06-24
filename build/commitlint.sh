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

# Install commitlint only if not already available.
if [ ! -d "node_modules/@commitlint/cli" ]; then
  export npm_config_cache=/tmp/.npm
  npm install -D @commitlint/cli @commitlint/config-conventional
fi

# Execute the commitlint command.
npx commitlint --from=$FROM --to=$TO --verbose
