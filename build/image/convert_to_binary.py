#!/usr/bin/env python3
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Convert a file to binary format.

Calls objcopy to convert a file into raw binary format.
"""

import argparse
import os
import subprocess
import sys

OBJCOPY = "llvm-objcopy"

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    subprocess.check_call([
        OBJCOPY, "-O", "binary", args.input, args.output
    ])
    return 0


if __name__ == "__main__":
    sys.exit(Main())
