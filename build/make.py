#!/usr/bin/env python3
#
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Runs make to build a target."""

import argparse
import os
import shutil
import subprocess
import sys


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--copy_out_file", nargs=2,
                        help="Copy file after building. Takes two params: <src> <dest>")
    args, make_args = parser.parse_known_args()

    os.chdir(args.directory)
    os.environ["PWD"] = args.directory
    status = subprocess.call(["make"] + make_args)
    if status != 0:
        return status

    if args.copy_out_file is not None:
        shutil.copyfile(args.copy_out_file[0], args.copy_out_file[1])
    return 0


if __name__ == "__main__":
    sys.exit(Main())
