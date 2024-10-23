#!/usr/bin/env bash
# Copyright 2024 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

set -euox pipefail

source "$(dirname ${BASH_SOURCE[0]})/../build/bash/common.inc"
# Initialize global variables, prepare repo for building.
init_build

OUT=$ROOT_DIR/out
# Dowloading the script from 6.11.5 stable.
LINK=https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/scripts/checkpatch.pl?h=v6.11.5

# From a fresh clone out/ folder may not have been created.
mkdir -p $OUT

# Delete the folder to avoid any conflicts if it exists.
CHECKPATCH_DIR=$OUT/checkpatch

[ -d $CHECKPATCH_DIR ] && rm -r $CHECKPATCH_DIR
mkdir $CHECKPATCH_DIR

touch ${CHECKPATCH_DIR}/download_checkpatch.log
wget --tries=3 --output-file=${CHECKPATCH_DIR}/download_checkpatch.log ${LINK} -P $CHECKPATCH_DIR

# Rename to drop the extra characters at the end of the file name.
mv $CHECKPATCH_DIR/checkpatch* $CHECKPATCH_DIR/checkpatch.pl
chmod +x $CHECKPATCH_DIR/checkpatch.pl

# File for outputting spelling mistakes and for outputting structs that
# shoud const. This is mostly to mute the warnings.
touch $CHECKPATCH_DIR/spelling.txt
touch $CHECKPATCH_DIR/const_structs.checkpatch
