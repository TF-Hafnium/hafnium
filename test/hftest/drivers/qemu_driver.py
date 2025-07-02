# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

import os

from common import (
    join_if_not_None,
    HF_PREBUILTS,
    MACHINE,
)
from driver import Driver, DriverRunException

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
