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

make tidy
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
