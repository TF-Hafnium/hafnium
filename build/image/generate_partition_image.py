#!/usr/bin/env python3
#
# Copyright 2020 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Script which generates a Secure Partition package.
https://trustedfirmware-a.readthedocs.io/en/latest/components/secure-partition-manager.html#secure-partition-packages
"""

import argparse
import sys
from shutil import copyfileobj
import os

HF_PAGE_SIZE = 0x1000
HEADER_ELEMENT_BYTES = 4 # bytes
HEADER_LEN = 6

MANIFEST_IMAGE_SPLITTER=':'
def split_dtb_bin(i : str):
    return i.split(MANIFEST_IMAGE_SPLITTER)

def align_to_page(n):
    return HF_PAGE_SIZE * \
          (round(n / HF_PAGE_SIZE) + \
           (1 if n % HF_PAGE_SIZE else 0))

def to_bytes(value):
    return int(value).to_bytes(4, 'little')

class sp_pkg_info:
    def __init__(self, manifest_path : str, image_path : str, include_header = True):
        if not os.path.isfile(manifest_path) or not os.path.isfile(image_path):
            raise Exception(f"Parameters should be path.  \
                              manifest: {manifest_path}; image: {image_path}")
        self.manifest_path = manifest_path
        self.image_path = image_path
        self.include_header = include_header

    def __str__(self):
        return \
        f'''-------------------SP package Info------------------------
        header:{self.header}
        manifest: {self.manifest_path}
        image: {self.image_path}
        '''

    @property
    def magic(self):
        return "SPKG".encode()

    @property
    def version(self):
        return 1

    @property
    def manifest_offset(self):
        return self.header_size if self.include_header else 0

    @property
    def manifest_size(self):
        return os.path.getsize(self.manifest_path)

    @property
    def image_offset(self):
        return align_to_page(self.manifest_offset + self.manifest_size)

    @property
    def image_size(self):
        return os.path.getsize(self.image_path)

    @property
    def header(self):
        return [self.magic,
                self.version,
                self.manifest_offset,
                self.manifest_size,
                self.image_offset,
                self.image_size]

    @property
    def header_size(self):
        return (HEADER_ELEMENT_BYTES * HEADER_LEN)

    def generate_package(self, f_out : str):
        with open(f_out, "wb+") as output:
            if self.include_header is True:
                for h in self.header:
                    to_write = h if type(h) is bytes else to_bytes(h)
                    output.write(to_write)
            with open(self.manifest_path, "rb") as manifest:
                copyfileobj(manifest, output)
            output.seek(self.image_offset, 0)
            with open(self.image_path, "rb") as image:
                copyfileobj(image, output)

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", required=True,
                        help="Add Secure Partition image and Manifest blob "
                             "(specified in two paths) separated by a colon).")
    parser.add_argument("-o", required=True, help="Set output file path.")
    parser.add_argument("-n", required=False, action="store_true", default=False,
                        help="Generate package without header.")
    args = parser.parse_args()

    if not os.path.exists(os.path.dirname(args.o)):
        raise Exception("Provide a valid output file path!\n")

    image_path, manifest_path = split_dtb_bin(args.i)
    pkg = sp_pkg_info(manifest_path, image_path, not args.n)
    pkg.generate_package(args.o)

    return 0

if __name__ == "__main__":
    sys.exit(Main())
