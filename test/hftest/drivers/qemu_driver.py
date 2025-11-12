# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

import click
import logging
import os

from common import (
    ArtifactsManager,
    TestRunner,
    join_if_not_None,
    shared_options,
    HF_PREBUILTS,
    MACHINE,
)
from driver import Driver, DriverArgs, DriverRunException

QEMU_CPU_MAX = "max,pauth-impdef=true"
QEMU_PREBUILTS = os.path.join(HF_PREBUILTS,
         "linux-" + ("x64" if MACHINE == "x86_64" else MACHINE),
         "qemu", "qemu-system-aarch64")

class QemuDriver(Driver):
    """Driver which runs tests in QEMU."""

    def __init__(self, args, qemu_wd, tfa):
        Driver.__init__(self, args)
        self.qemu_wd = qemu_wd
        self.tfa = tfa

    def gen_exec_args(self, test_args, is_long_running):
        """Generate command line arguments for QEMU."""
        time_limit = "120s" if is_long_running else "30s"
        # If no CPU configuration is selected, then test against the maximum
        # configuration, "max", supported by QEMU.
        if not self.args.cpu or self.args.cpu == "max":
            cpu = QEMU_CPU_MAX
        else:
            cpu = self.args.cpu

        exec_args = [
            "timeout", "--foreground", time_limit,
            QEMU_PREBUILTS,
            "-no-reboot", "-machine", "virt-6.2,virtualization=on,gic-version=3",
            "-cpu", cpu, "-smp", "8", "-m", "1G",
            "-nographic", "-nodefaults", "-serial", "stdio",
            "-d", "unimp", "-kernel", os.path.abspath(self.args.hypervisor),
        ]

        if self.tfa:
            bl1_path = os.path.join(
                HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a",
                "qemu", "bl1.bin")
            exec_args += ["-bios",
                os.path.abspath(bl1_path),
                "-machine", "secure=on", "-semihosting-config",
                "enable=on,target=native"]

        if self.args.initrd:
            exec_args += ["-initrd", os.path.abspath(self.args.initrd)]

        vm_args = join_if_not_None(self.args.vm_args, test_args)
        if vm_args:
            exec_args += ["-append", vm_args]

        return exec_args

    def run(self, run_name, test_args, is_long_running, debug = False,
            show_output = False):
        """Run test given by `test_args` in QEMU."""
        # TODO: use 'debug' and 'show_output' flags.
        run_state = self.start_run(run_name)

        try:
            # Execute test in QEMU..
            exec_args = self.gen_exec_args(test_args, is_long_running)
            self.exec_logged(run_state, exec_args,
                cwd=self.qemu_wd)
        except DriverRunException:
            pass

        return self.finish_run(run_state)

    def finish(self):
        """Clean up after running tests."""
        pass

    def qemu_options(f):
        f = click.option("--cpu", help="Selects the CPU configuration for the run environment.")(f)
        f = click.option("--tfa", is_flag=True)(f)
        return f

    @click.command()
    @shared_options
    @qemu_options
    def qemu(**options):
        QemuDriver.process_options(**options)

    def process_options(**options):
        if options.get("hypervisor") and options.get("spmc"):
            test_set_up = "hypervisor_and_spmc"
        elif options.get("hypervisor"):
            test_set_up = "hypervisor"
        elif options.get("spmc"):
            test_set_up = "spmc"
        elif options.get("el3_spmc"):
            test_set_up = "el3_spmc"
        else:
            raise Exception("No Hafnium image provided!\n")

        initrd = None

        if options.get("hypervisor") and options.get("initrd"):
            initrd_dir = os.path.join(options.get("out_initrd"), "obj", options.get("initrd"))
            initrd = os.path.join(initrd_dir, "initrd.img")
            test_set_up += "_" + options.get("initrd")
        vm_args = options.get("vm_args") or ""

        # Create class which will manage all test artifacts.
        global_run_name = "arch"
        log_dir = os.path.join(os.path.join(options.get("log"), test_set_up), global_run_name)
        artifacts = ArtifactsManager(log_dir)

        # driver_args setup
        partitions = None
        driver_args = DriverArgs(artifacts, options.get("hypervisor"), options.get("spmc"), initrd,
                                vm_args, options.get("cpu"), partitions, global_run_name,
                                options.get("coverage_plugin"), options.get("disable_visualisation"))
        if options.get("hypervisor"):
            out = os.path.dirname(options.get("hypervisor"))
            driver = QemuDriver(driver_args, out, options.get("tfa"))
        else:
            raise Exception("No Hafnium image provided!\n")

        # LoggingPriority: CLI > ENV > Default
        logging_level_str = options.get("log_level") or os.getenv("HFTEST_LOG_LEVEL", "INFO")
        if logging_level_str.isdigit():
            numeric_level = int(logging_level_str)
        else:
            numeric_level = logging.__dict__.get(logging_level_str.upper())

        if type(numeric_level) != int:
            raise ValueError(f"Error: Invalid log level '{logging_level_str}'")

        logging.basicConfig(level=numeric_level, format="[%(levelname)s] %(message)s")
        logging.info(f"Logging initialized with level: {logging.getLevelName(numeric_level)}")

        # Create class which will drive test execution.
        runner = TestRunner(artifacts, driver, test_set_up, options.get("suite"), options.get("test"),
            options.get("skip_long_running_tests"), options.get("force_long_running"), options.get("debug"), options.get("show_output"))

        # Run tests.
        runner_result = runner.run_tests()

        # Print warning message if no tests were run as this is probably unexpected.
        # Return suitable error code.
        if runner_result.tests_run == 0:
            print("Warning: no tests match")
        elif runner_result.tests_failed > 0:
            raise click.ClickException(f"Error: tests {runner_result.tests_failed} failed")
