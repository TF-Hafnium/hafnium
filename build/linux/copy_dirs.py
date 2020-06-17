#!/usr/bin/env python3
#
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Copies all files inside one folder to another, preserving subfolders."""

import argparse
import os
import shutil
import sys

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("source_folder",
	                    help="directory to be copied from")
	parser.add_argument("destination_folder",
	                    help="directory to be copied into")
	parser.add_argument("stamp_file",
	                    help="stamp file to be touched")
	args = parser.parse_args()

	# Walk the subfolders of the source directory and copy individual files.
	# Not using shutil.copytree() because it never overwrites files.
	for root, _, files in os.walk(args.source_folder):
		for f in files:
			abs_src_path = os.path.join(root, f)
			rel_path = os.path.relpath(abs_src_path, args.source_folder)
			abs_dst_path = os.path.join(args.destination_folder, rel_path)
			abs_dst_folder = os.path.dirname(abs_dst_path)
			if not os.path.isdir(abs_dst_folder):
				os.makedirs(abs_dst_folder)
			shutil.copyfile(abs_src_path, abs_dst_path)

	# Touch `stamp_file`.
	with open(args.stamp_file, "w"):
		pass

if __name__ == "__main__":
    sys.exit(main())
