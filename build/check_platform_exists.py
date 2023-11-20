#!/usr/bin/env python3
#
# Copyright 2024 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Check a list of platforms are defined in a project.

First argument is the project name (e.g. reference).
The script returns a zero error code if the list of platform names given as
arguments (following the project name) are available for building.
If one platform supplied in arguments doesn't exist, the script prints the
list of supported platforms and returns 1 as an exit code.
If the script is called with only the project name, it prints the list of
available platforms and returns 0.
"""

import sys
import re
import os

def Main():
    project = sys.argv[1]

    platforms = []
    reg = re.compile('aarch64_toolchains\("(\w*)')
    with open("project/" + project + "/BUILD.gn") as project_file:
        for line in project_file:
            platforms += reg.findall(line)

    if len(sys.argv) < 3:
        print("Supported platforms: ", platforms)
        return 0

    platform_list = sys.argv[2:]

    if not set(platform_list).issubset(platforms):
        print("Supported platforms: ", platforms)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(Main())
