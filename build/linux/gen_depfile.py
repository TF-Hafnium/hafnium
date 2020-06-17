#!/usr/bin/env python3
#
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Generate a depfile for a folder."""

import argparse
import os
import sys

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("root_dir", help="input directory")
	parser.add_argument("stamp_file", help="stamp file to be touched")
	parser.add_argument("dep_file", help="depfile to be written")
	args = parser.parse_args()

	# Compile list of all files in the folder, relative to `root_dir`.
	sources = []
	for root, _, files in os.walk(args.root_dir):
		sources.extend([ os.path.join(root, f) for f in files ])
	sources = sorted(sources)

	# Write `dep_file` as a Makefile rule for `stamp_file`.
	with open(args.dep_file, "w") as f:
		f.write(args.stamp_file)
		f.write(":")
		for source in sources:
			f.write(' ');
			f.write(source)
		f.write(os.linesep)

	# Touch `stamp_file`.
	with open(args.stamp_file, "w"):
		pass

if __name__ == "__main__":
    sys.exit(main())
