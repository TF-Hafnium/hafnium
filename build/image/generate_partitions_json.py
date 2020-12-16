#!/usr/bin/env python3
#
# Copyright 2020 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

import argparse
import sys
import os
import json

"""
This script aims at generating a json file that contains the artifacts of
partitions that will execute alongside in the same test setup.
A partition can be:
 - Virtual Machine (VM) - to execute in EL1;
 - Secure Partition (SP) - to execute in S-EL1.

A setup can have multiple VMs and multiple SPs executing alongside.
The json file shall list the VMs and SPs, such as:
{
    "SPs" : [ <SP information>, ... , <SPx Information>],
    "VMs" : [ <VM information>, ... , <VMx Information>]
}

Where the information of each partition shall obey the following format:
{
     "img" : <path to partition package>.img,
     "dts" : <path to manifest>.dts
}

In the arguments of this script provide the path to partition's artifacts
separated by the character defined as 'ARG_SPLITTER'. Example:
--sp <path to img>,<path to dts>
--vm <path to img>,<path to dts>
"""

ARG_SPLITTER = ','
ARG_FORMAT = f"<img>{ARG_SPLITTER}<dts>"

def split_partition_arg(sp_arg : str):
    ret = sp_arg.split(ARG_SPLITTER)
    if len(ret) != 2:
        raise Exception(f"Argument should follow format {ARG_FORMAT}")
    return ret

def partition_info(img, dts):
    return {"img": img, "dts": dts}

def list_of_partitions(partitions : list):
    return [partition_info(*split_partition_arg(p)) for p in partitions]

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sp", action="append")
    parser.add_argument("--vm", action="append")
    parser.add_argument("--out", action="store", required=True)
    args = parser.parse_args()

    #Arguments sanity check:
    if args.vm is None and args.sp is None:
        raise Exception("Specify at least one VM (--vm) or one SP (--sp)")

    partitions = dict()
    if args.sp is not None:
        partitions["SPs"] = list_of_partitions(args.sp)
    if args.vm is not None:
        partitions["VMs"] = list_of_partitions(args.vm)

    json.dump(partitions, open(args.out, "w+"))
    return 0

if __name__ == "__main__":
    sys.exit(Main())
