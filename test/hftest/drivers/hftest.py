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

from __future__ import print_function
import argparse
import json
import os
import sys

from common import ArtifactsManager, TestRunner
from driver import DriverArgs
from fvp_driver import (
    FvpDriverBothWorlds,
    FvpDriverEL3SPMC,
    FvpDriverEL3SPMCBothWorlds,
    FvpDriverHypervisor,
    FvpDriverSPMC,
    FVP_BINARY
)
from qemu_driver import QemuDriver
from serial_driver import SerialDriver

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hypervisor")
    parser.add_argument("--spmc")
    parser.add_argument("--el3_spmc", action="store_true")
    parser.add_argument("--log", required=True)
    parser.add_argument("--out_initrd")
    parser.add_argument("--out_partitions")
    parser.add_argument("--initrd")
    parser.add_argument("--partitions_json")
    parser.add_argument("--suite")
    parser.add_argument("--test")
    parser.add_argument("--vm_args")
    parser.add_argument("--driver", default="qemu")
    parser.add_argument("--serial-dev", default="/dev/ttyUSB0")
    parser.add_argument("--serial-baudrate", type=int, default=115200)
    parser.add_argument("--serial-no-init-wait", action="store_true")
    parser.add_argument("--skip-long-running-tests", action="store_true")
    parser.add_argument("--force-long-running", action="store_true")
    parser.add_argument("--debug", action="store_true",
        help="Makes platforms stall waiting for debugger connection.")
    parser.add_argument("--show-output", action="store_true")
    parser.add_argument("--cpu",
        help="Selects the CPU configuration for the run environment.")
    parser.add_argument("--tfa", action="store_true")
    parser.add_argument("--coverage_plugin", default="")
    parser.add_argument("--disable_visualisation", action="store_true")
    parser.add_argument("--log-level", default=None,
    help="Set the log level (DEBUG=10, INFO=20, WARNING=30, ERROR=40)")
    args = parser.parse_args()

    # Create class which will manage all test artifacts.
    if args.hypervisor and args.spmc:
        test_set_up = "hypervisor_and_spmc"
    elif args.hypervisor:
        test_set_up = "hypervisor"
    elif args.spmc:
        test_set_up = "spmc"
    elif args.el3_spmc:
        test_set_up = "el3_spmc"
    else:
        raise Exception("No Hafnium image provided!\n")

    initrd = None
    if args.hypervisor and args.initrd:
        initrd_dir = os.path.join(args.out_initrd, "obj", args.initrd)
        initrd = os.path.join(initrd_dir, "initrd.img")
        test_set_up += "_" + args.initrd
    vm_args = args.vm_args or ""

    partitions = None
    global_run_name = "arch"
    if args.driver == "fvp":
        if not os.path.isfile(FVP_BINARY):
            raise Exception("Cannot find FVP binary.")
        if args.partitions_json is not None:
            partitions_dir = os.path.join(
                args.out_partitions, "obj", args.partitions_json)
            partitions = json.load(open(partitions_dir, "r"))
            global_run_name = os.path.basename(args.partitions_json).split(".")[0]
        elif args.hypervisor:
            if args.initrd:
                global_run_name = os.path.basename(args.initrd)
            else:
                global_run_name = os.path.basename(args.hypervisor).split(".")[0]

    # Create class which will manage all test artifacts.
    log_dir = os.path.join(os.path.join(args.log, test_set_up), global_run_name)
    artifacts = ArtifactsManager(log_dir)

    # Create a driver for the platform we want to test on.
    driver_args = DriverArgs(artifacts, args.hypervisor, args.spmc, initrd,
                             vm_args, args.cpu, partitions, global_run_name,
                             args.coverage_plugin, args.disable_visualisation)

    if args.el3_spmc:
        # So far only FVP supports tests for SPMC.
        if args.driver != "fvp":
            raise Exception("Secure tests can only run with fvp driver")
        if args.hypervisor:
           driver = FvpDriverEL3SPMCBothWorlds(driver_args)
        else:
           driver = FvpDriverEL3SPMC(driver_args)
    elif args.spmc:
        # So far only FVP supports tests for SPMC.
        if args.driver != "fvp":
            raise Exception("Secure tests can only run with fvp driver")
        if args.hypervisor:
            driver = FvpDriverBothWorlds(driver_args)
        else:
            driver = FvpDriverSPMC(driver_args)
    elif args.hypervisor:
        if args.driver == "qemu":
            out = os.path.dirname(args.hypervisor)
            driver = QemuDriver(driver_args, out, args.tfa)
        elif args.driver == "fvp":
            driver = FvpDriverHypervisor(driver_args)
        elif args.driver == "serial":
            driver = SerialDriver(driver_args, args.serial_dev,
                    args.serial_baudrate, not args.serial_no_init_wait)
        else:
            raise Exception("Unknown driver name: {}".format(args.driver))
    else:
        raise Exception("No Hafnium image provided!\n")

    # Create class which will drive test execution.
    runner = TestRunner(artifacts, driver, test_set_up, args.suite, args.test,
        args.skip_long_running_tests, args.force_long_running, args.debug, args.show_output)

    # Run tests.
    runner_result = runner.run_tests()

    # Print error message if no tests were run as this is probably unexpected.
    # Return suitable error code.
    if runner_result.tests_run == 0:
        print("Error: no tests match")
        return 10
    elif runner_result.tests_failed > 0:
        return 1
    else:
        return 0

if __name__ == "__main__":
    sys.exit(Main())
