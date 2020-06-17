#!/usr/bin/env python3
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Add license header to source files.

If the file doesn't have the license header, add it with the appropriate comment
style.
"""

import argparse
import datetime
import re
import sys


bsd = """{comment} Copyright {year} The Hafnium Authors.
{comment}
{comment} Use of this source code is governed by a BSD-style
{comment} license that can be found in the LICENSE file or at
{comment} https://opensource.org/licenses/BSD-3-Clause."""

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--style", choices=["c", "hash"], required=True)
    args = parser.parse_args()
    header = "/*\n" if args.style == "c" else ""
    year = str(datetime.datetime.now().year)
    header += bsd.format(comment=" *" if args.style == "c" else "#", year=year)
    header += "\n */" if args.style == "c" else ""
    header += "\n\n"
    header_regex = re.escape(header).replace(year, r"\d\d\d\d")
    with open(args.file, "r") as f:
        contents = f.read()
        if re.search(header_regex, contents):
            return
    with open(args.file, "w") as f:
        f.write(header)
        f.write(contents)

if __name__ == "__main__":
    sys.exit(Main())
