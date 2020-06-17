#!/usr/bin/env python3
#
# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Parse Repo manifest and symlink files specified in <linkfile> tags.

This is a workaround for Kokoro which does not support <linkfile>.
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("root_dir", help="root directory")
	args = parser.parse_args()

	manifest = os.path.join(args.root_dir, ".repo", "manifest.xml")
	tree = ET.parse(manifest)
	root = tree.getroot()
	assert(root.tag == "manifest");

	for proj in root:
		if proj.tag != "project":
			continue

		proj_name = proj.attrib["name"]
		proj_path = proj.attrib["path"]

		for linkfile in proj:
			if linkfile.tag != "linkfile":
				continue

			linkfile_src = linkfile.attrib["src"]
			linkfile_dest = linkfile.attrib["dest"]
			src_path = os.path.join(
				args.root_dir, proj_path, linkfile_src)
			dest_path = os.path.join(args.root_dir, linkfile_dest)

			os.symlink(src_path, dest_path)

if __name__ == "__main__":
    sys.exit(main())
