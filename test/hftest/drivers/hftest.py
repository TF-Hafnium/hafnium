#!/usr/bin/env python3
#
# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Script which drives invocation of tests and parsing their output to produce
a results report.
"""

import click
import sys

from fvp_driver import FvpDriver
from qemu_driver import QemuDriver

@click.group()
def hftest():
    pass

hftest.add_command(FvpDriver.fvp)
hftest.add_command(QemuDriver.qemu)

if __name__ == "__main__":
    sys.exit(hftest())
