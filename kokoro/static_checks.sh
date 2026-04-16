#!/usr/bin/env bash
#
# Copyright 2024 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

source "$(dirname ${BASH_SOURCE[0]})/../build/bash/common.inc"

# Set all environment variables
init_build

#
# Make sure the code looks good.
#

make check-format
make checkpatch

#
# Make sure there's not lint.
#

# Run clang-tidy via `make tidy` and capture full output in a temporary file.
# The job fails if any clang-tidy errors are detected in the output.
# Note:
# - Analysis runs across the entire repository, so failures may be
#   unrelated to the current patch.
# - A temporary file is used to avoid polluting the git workspace.
# - Check the Jenkins console output for details and fix issues locally
#   using `make tidy`.
tidy_log=$(mktemp)
make tidy 2>&1 | tee "$tidy_log"

if grep -q "error:" "$tidy_log"; then
	echo "Static analysis errors found..."
	rm -f "$tidy_log"
	exit 1
fi

rm -f "$tidy_log"

# Still enforce auto-fixes
if is_repo_dirty
then
	echo "Run \`make tidy\' locally to fix this."
	exit 1
fi

#
# Make sure all the files have a license.
#
make license_
if is_repo_dirty
then
	echo "Run \`make license_\' locally to fix this."
	exit 1
fi
