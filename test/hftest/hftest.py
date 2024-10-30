#!/usr/bin/env python3
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""Script which drives invocation of tests and parsing their output to produce
a results report.
"""

from __future__ import print_function

import xml.etree.ElementTree as ET

import argparse
from abc import ABC, abstractmethod
import collections
import datetime
import importlib
import json
import os
import re
import subprocess
import sys
import time
import fdt
import platform
import tempfile

MACHINE = platform.machine()

HFTEST_LOG_PREFIX = "[hftest] "
HFTEST_LOG_FAILURE_PREFIX = "Failure:"
HFTEST_LOG_FINISHED = "FINISHED"

HFTEST_CTRL_JSON_START = "[hftest_ctrl:json_start]"
HFTEST_CTRL_JSON_END = "[hftest_ctrl:json_end]"

HFTEST_CTRL_GET_COMMAND_LINE = "[hftest_ctrl:get_command_line]"
HFTEST_CTRL_FINISHED = "[hftest_ctrl:finished]"

HFTEST_CTRL_JSON_REGEX = re.compile("^\\[[0-9a-fA-F]+ [0-9a-fA-F]+\\] ")

HF_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
DTC_SCRIPT = os.path.join(HF_ROOT, "build", "image", "dtc.py")
FVP_BINARY = os.path.join(
    os.path.dirname(HF_ROOT), "fvp", "Base_RevC_AEMvA_pkg", "models",
    "Linux64_armv8l_GCC-9.3" if MACHINE == "aarch64" else "Linux64_GCC-9.3",
    "FVP_Base_RevC-2xAEMvA")
HF_PREBUILTS = os.path.join(HF_ROOT, "prebuilts")
QEMU_PREBUILTS = os.path.join(HF_PREBUILTS,
         "linux-" + ("x64" if MACHINE == "x86_64" else MACHINE),
         "qemu", "qemu-system-aarch64")
FVP_PREBUILTS_TFA_ROOT = os.path.join(
    HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a", "fvp")
FVP_PREBUILT_DTS = os.path.join(
    FVP_PREBUILTS_TFA_ROOT, "fvp-base-gicv3-psci-1t.dts")

FVP_PREBUILT_TFA_SPMD_ROOT = os.path.join(
    HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a-spmd", "fvp")

FVP_PREBUILTS_TFA_EL3_SPMC_ROOT = os.path.join(
    HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a-el3-spmc")
VM_NODE_REGEX = "vm[1-9]"

QEMU_CPU_MAX = "max,pauth-impdef=true"

def read_file(path):
    with open(path, "r") as f:
        return f.read()

def write_file(path, to_write, append=False):
    with open(path, "a" if append else "w") as f:
        f.write(to_write)

def append_file(path, to_write):
    write_file(path, to_write, append=True)

def join_if_not_None(*args):
    return " ".join(filter(lambda x: x, args))

def get_vm_node_from_manifest(dts : str):
    """ Get VM node string from Partition's extension to Partition Manager's
    manifest."""
    match = re.search(VM_NODE_REGEX, dts)
    if not match:
        raise Exception("Partition's node is not defined in its manifest.")
    return match.group()

def correct_vm_node(dts: str, node_index : int):
    """ The vm node is being appended to the Partition Manager manifests.
    Ideally, these files would be reused accross various test set-ups."""
    return dts.replace(get_vm_node_from_manifest(dts), f"vm{node_index}")

DT = collections.namedtuple("DT", ["dts", "dtb"])

class ArtifactsManager:
    """Class which manages folder with test artifacts."""

    def __init__(self, log_dir):
        self.created_files = []
        self.log_dir = log_dir

        # Create directory.
        try:
            os.makedirs(self.log_dir)
        except OSError:
            if not os.path.isdir(self.log_dir):
                raise
        print("Logs saved under", log_dir)

        # Create files expected by the Sponge test result parser.
        self.sponge_log_path = self.create_file("sponge_log", ".log")
        self.sponge_xml_path = self.create_file("sponge_log", ".xml")

    def gen_file_path(self, basename, extension):
        """Generate path to a file in the log directory."""
        return os.path.join(self.log_dir, basename + extension)

    def create_file(self, basename, extension):
        """Create and touch a new file in the log folder. Ensure that no other
        file of the same name was created by this instance of ArtifactsManager.
        """
        # Determine the path of the file.
        path = self.gen_file_path(basename, extension)

        # Check that the path is unique.
        assert(path not in self.created_files)
        self.created_files += [ path ]

        # Touch file.
        with open(path, "w") as f:
            pass

        return path

    def get_file(self, basename, extension):
        """Return path to a file in the log folder. Assert that it was created
        by this instance of ArtifactsManager."""
        path = self.gen_file_path(basename, extension)
        assert(path in self.created_files)
        return path


# Tuple holding the arguments common to all driver constructors.
# This is to avoid having to pass arguments from subclasses to superclasses.
DriverArgs = collections.namedtuple("DriverArgs", [
        "artifacts",
        "hypervisor",
        "spmc",
        "initrd",
        "vm_args",
        "cpu",
        "partitions",
        "global_run_name",
        "coverage_plugin",
        "disable_visualisation"
    ])

# State shared between the common Driver class and its subclasses during
# a single invocation of the target platform.
class DriverRunState:
    def __init__(self, log_path):
        self.log_path = log_path
        self.ret_code = 0

    def set_ret_code(self, ret_code):
        self.ret_code = ret_code

class DriverRunException(Exception):
    """Exception thrown if subprocess invoked by a driver returned non-zero
    status code. Used to fast-exit from a driver command sequence."""
    pass


class Driver:
    """Parent class of drivers for all testable platforms."""

    def __init__(self, args):
        self.args = args

    def get_run_log(self, run_name):
        """Return path to the main log of a given test run."""
        return self.args.artifacts.get_file(run_name, ".log")

    def start_run(self, run_name):
        """Hook called by Driver subclasses before they invoke the target
        platform."""
        return DriverRunState(self.args.artifacts.create_file(run_name, ".log"))

    def exec_logged(self, run_state, exec_args, cwd=None):
        """Run a subprocess on behalf of a Driver subclass and append its
        stdout and stderr to the main log."""
        assert(run_state.ret_code == 0)
        with open(run_state.log_path, "a") as f:
            f.write("$ {}\r\n".format(" ".join(exec_args)))
            f.flush()
            ret_code = subprocess.call(exec_args, stdout=f, stderr=f, cwd=cwd)
            if ret_code != 0:
                run_state.set_ret_code(ret_code)
                raise DriverRunException()

    def finish_run(self, run_state):
        """Hook called by Driver subclasses after they finished running the
        target platform. `ret_code` argument is the return code of the main
        command run by the driver. A corresponding log message is printed."""
        # Decode return code and add a message to the log.
        with open(run_state.log_path, "a") as f:
            if run_state.ret_code == 124:
                f.write("\r\n{}{} timed out\r\n".format(
                    HFTEST_LOG_PREFIX, HFTEST_LOG_FAILURE_PREFIX))
            elif run_state.ret_code != 0:
                f.write("\r\n{}{} process return code {}\r\n".format(
                    HFTEST_LOG_PREFIX, HFTEST_LOG_FAILURE_PREFIX,
                    run_state.ret_code))

        # Append log of this run to full test log.
        log_content = read_file(run_state.log_path)
        append_file(
            self.args.artifacts.sponge_log_path,
            log_content + "\r\n\r\n")
        return log_content

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

class FvpDriver(Driver, ABC):
    """Base class for driver which runs tests in Arm FVP emulator."""

    def __init__(self, args, cpu_start_address, fvp_prebuilt_bl31):
        self.cov_plugin = args.coverage_plugin or None
        if args.cpu:
            raise ValueError("FVP emulator does not support the --cpu option.")
        super().__init__(args)
        self._cpu_start_address = cpu_start_address
        self._fvp_prebuilt_bl31 = fvp_prebuilt_bl31

    def create_dt(self, run_name : str):
        """Create DT related files, and return respective paths in a tuple
           (dts,dtb)"""
        return DT(self.args.artifacts.create_file(run_name, ".dts"),
                  self.args.artifacts.create_file(run_name, ".dtb"))

    def compile_dt(self, run_state, dt : DT):
        """Compile DT calling dtc."""
        dtc_args = [
            DTC_SCRIPT, "compile", "-i", dt.dts, "-o", dt.dtb,
        ]
        self.exec_logged(run_state, dtc_args)

    def create_uart_log(self, run_name : str, file_name : str):
        """Create uart log file, and return path"""
        return self.args.artifacts.create_file(run_name, file_name)

    def get_img_and_ldadd(self, partitions : dict):
        ret = []
        for i, p in enumerate(partitions):
            with open(p["dts"], "r") as dt:
                dts = dt.read()
                manifest = fdt.parse_dts(dts)
                vm_node = get_vm_node_from_manifest(dts)
                load_address = manifest.get_property("load_address",
                                          f"/hypervisor/{vm_node}").value
                ret.append((p["img"], load_address))
        return ret

    def get_manifests_from_json(self, partitions : list):
        manifests = ""
        if partitions is not None:
            for i, p in enumerate(partitions):
                manifests += correct_vm_node(read_file(p["dts"]), i + 1)
        return manifests

    @abstractmethod
    def gen_dts(self, dt, test_args):
        """Abstract method to generate dts file. This specific to the use case
           so should be implemented within derived driver"""
        pass

    @abstractmethod
    def gen_fvp_args(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug = False, show_output = False):
        """Generate command line arguments for FVP."""
        show_output = debug or show_output
        disable_visualisation = self.args.disable_visualisation is True
        time_limit = "150s" if is_long_running else "40s"
        fvp_args = []

        if not show_output:
            fvp_args = [
                "timeout", "--foreground", time_limit,
            ]

        fvp_args += [
            FVP_BINARY,
            "-C", "pci.pci_smmuv3.mmu.SMMU_AIDR=2",
            "-C", "pci.pci_smmuv3.mmu.SMMU_IDR0=0x0046123B",
            "-C", "pci.pci_smmuv3.mmu.SMMU_IDR1=0x00600002",
            "-C", "pci.pci_smmuv3.mmu.SMMU_IDR3=0x1714",
            "-C", "pci.pci_smmuv3.mmu.SMMU_IDR5=0xFFFF0472",
            "-C", "pci.pci_smmuv3.mmu.SMMU_S_IDR1=0xA0000002",
            "-C", "pci.pci_smmuv3.mmu.SMMU_S_IDR2=0",
            "-C", "pci.pci_smmuv3.mmu.SMMU_S_IDR3=0",
            "-C", "pctl.startup=0.0.0.0",
            "-C", "bp.secure_memory=1",
            "-C", "cluster0.NUM_CORES=4",
            "-C", "cluster1.NUM_CORES=4",
            "-C", "cache_state_modelled=0",
            "-C", "bp.vis.rate_limit-enable=false",
            "-C", "bp.pl011_uart0.untimed_fifos=1",
            "-C", "bp.pl011_uart0.unbuffered_output=1",
            "-C", f"cluster0.cpu0.RVBAR={self._cpu_start_address}",
            "-C", f"cluster0.cpu1.RVBAR={self._cpu_start_address}",
            "-C", f"cluster0.cpu2.RVBAR={self._cpu_start_address}",
            "-C", f"cluster0.cpu3.RVBAR={self._cpu_start_address}",
            "-C", f"cluster1.cpu0.RVBAR={self._cpu_start_address}",
            "-C", f"cluster1.cpu1.RVBAR={self._cpu_start_address}",
            "-C", f"cluster1.cpu2.RVBAR={self._cpu_start_address}",
            "-C", f"cluster1.cpu3.RVBAR={self._cpu_start_address}",
            "--data",
            f"cluster0.cpu0={self._fvp_prebuilt_bl31}@{self._cpu_start_address}",
            "-C", "bp.ve_sysregs.mmbSiteDefault=0",
            "-C", "cluster0.has_arm_v8-5=1",
            "-C", "cluster1.has_arm_v8-5=1",
            "-C", "cluster0.has_branch_target_exception=1",
            "-C", "cluster1.has_branch_target_exception=1",
            "-C", "cluster0.memory_tagging_support_level=2",
            "-C", "cluster1.memory_tagging_support_level=2",
            "-C", "bp.dram_metadata.is_enabled=1",
            "-C", "cluster0.gicv3.extended-interrupt-range-support=1",
            "-C", "cluster1.gicv3.extended-interrupt-range-support=1",
            "-C", "gic_distributor.extended-ppi-count=64",
            "-C", "gic_distributor.extended-spi-count=1024",
            "-C", "gic_distributor.ARE-fixed-to-one=1",
        ]

        if uart0_log_path and uart1_log_path:
            fvp_args += [
                "-C", f"bp.pl011_uart0.out_file={uart0_log_path}",
                "-C", f"bp.pl011_uart1.out_file={uart1_log_path}",
            ]

        if not show_output:
            fvp_args += [
                "-C", "bp.terminal_0.start_telnet=false",
                "-C", "bp.terminal_1.start_telnet=false",
                "-C", "bp.terminal_2.start_telnet=false",
                "-C", "bp.terminal_3.start_telnet=false",
                "-C", "bp.ve_sysregs.exit_on_shutdown=1",
            ]
            disable_visualisation = True

        if disable_visualisation:
            fvp_args += [
                "-C", "bp.vis.disable_visualisation=true"
            ]

        if debug:
            fvp_args += [
                    "--iris-connect", "tcpserver,allowRemote",
                    "-p",
                    ]

        if self.cov_plugin is not None:
            fvp_args += [
                "--plugin", self.cov_plugin
            ]
        return fvp_args

    def run(self, run_name, test_args, is_long_running, debug = False,
            show_output = False):
        """ Run test """
        run_state = self.start_run(run_name)
        dt = self.create_dt(run_name)
        uart0_log_path = self.create_uart_log(run_name, ".uart0.log")
        uart1_log_path = self.create_uart_log(run_name, ".uart1.log")

        try:
            self.gen_dts(dt, test_args)
            self.compile_dt(run_state, dt)
            fvp_args = self.gen_fvp_args(is_long_running, uart0_log_path,
                                         uart1_log_path, dt, debug=debug,
                                         show_output=show_output)
            self.exec_logged(run_state, fvp_args)
        except DriverRunException:
            pass

        # Append UART0 output to main log.
        append_file(run_state.log_path, read_file(uart0_log_path))
        return self.finish_run(run_state)

    def finish(self):
        """Clean up after running tests."""
        pass

class FvpDriverHypervisor(FvpDriver):
    """
    Driver which runs tests in Arm FVP emulator, with hafnium as hypervisor
    """
    INITRD_START= 0x84000000
    INITRD_END = 0x86000000 #Default value, however may change if initrd in args

    def __init__(self, args, hypervisor_address=0x80000000, hypervisor_dtb_address=0x82000000):
        fvp_prebuilt_bl31 = os.path.join(FVP_PREBUILTS_TFA_ROOT, "bl31.bin")
        FvpDriver.__init__(self, args, 0x04020000, fvp_prebuilt_bl31)
        self.vms_in_partitions_json = args.partitions and args.partitions["VMs"]
        self._hypervisor_address = hypervisor_address
        self._hypervisor_dtb_address = hypervisor_dtb_address

    def gen_dts(self, dt, test_args):
        """Create a DeviceTree source which will be compiled into a DTB and
        passed to FVP for a test run."""

        vm_args = join_if_not_None(self.args.vm_args, test_args)
        write_file(dt.dts, read_file(FVP_PREBUILT_DTS))

        # Write the vm arguments to the partition manifest
        to_append = f"""
/ {{
    chosen {{
        bootargs = "{vm_args}";
        stdout-path = "serial0:115200n8";
        linux,initrd-start = <{self.INITRD_START if self.args.initrd else 0}>;
        linux,initrd-end = <{self.INITRD_END if self.args.initrd else 0}>;
    }};
}};"""
        if self.vms_in_partitions_json:
            to_append += self.get_manifests_from_json(self.args.partitions["VMs"])

        append_file(dt.dts, to_append)

    def gen_fvp_args(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug = False, show_output = False):
        """Generate command line arguments for FVP."""
        common_args = (self, is_long_running, uart0_log_path, uart1_log_path, dt,
                       debug, show_output)
        fvp_args = FvpDriver.gen_fvp_args(*common_args)

        fvp_args += [
            "--data", f"cluster0.cpu0={dt.dtb}@{self._hypervisor_dtb_address}",
            "--data", f"cluster0.cpu0={self.args.hypervisor}@{self._hypervisor_address}",
        ]

        if self.vms_in_partitions_json:
            img_ldadd = self.get_img_and_ldadd(self.args.partitions["VMs"])
            for img, ldadd in img_ldadd:
                fvp_args += ["--data", f"cluster0.cpu0={img}@{hex(ldadd)}"]

        if self.args.initrd:
            fvp_args += [
                "--data",
                f"cluster0.cpu0={self.args.initrd}@{self.INITRD_START}"
            ]
        return fvp_args

class FvpDriverSPMC(FvpDriver):
    """
    Driver which runs tests in Arm FVP emulator, with hafnium as SPMC
    """
    FVP_PREBUILT_SECURE_DTS = os.path.join(
        HF_ROOT, "test", "vmapi", "fvp-base-spmc.dts")
    hftest_cmd_file = tempfile.NamedTemporaryFile(mode="w+")

    def __init__(self, args, cpu_start_address=0x04010000, fvp_prebuilt_bl31=None):
        fvp_prebuilt_bl31 = os.path.join(FVP_PREBUILT_TFA_SPMD_ROOT, "bl31.bin") if fvp_prebuilt_bl31 is None else fvp_prebuilt_bl31
        super().__init__(args, cpu_start_address, fvp_prebuilt_bl31)

        self._spmc_address = 0x6000000
        self._spmc_dtb_address = 0x0403f000

    def gen_dts(self, dt, test_args):
        """Create a DeviceTree source which will be compiled into a DTB and
        passed to FVP for a test run."""
        to_append = self.get_manifests_from_json(self.args.partitions["SPs"])
        write_file(dt.dts, read_file(FvpDriverSPMC.FVP_PREBUILT_SECURE_DTS))
        append_file(dt.dts, to_append)

    def secure_ctrl_fvp_args(self, secure_ctrl):
        fvp_args = ""
        if secure_ctrl:
            fvp_args = [
                "-C", f"bp.pl011_uart0.in_file={FvpDriverSPMC.hftest_cmd_file.name}",
                "-C", f"bp.pl011_uart0.shutdown_tag=\"{HFTEST_CTRL_FINISHED}\"",
            ]
        return fvp_args

    def gen_fvp_args(
        self, is_long_running, uart0_log_path, uart1_log_path, dt,
        call_super = True, secure_ctrl = True, debug = False, show_output = False):
        """Generate command line arguments for FVP."""
        common_args = (self, is_long_running, uart0_log_path, uart1_log_path, dt.dtb,
                       debug, show_output)
        fvp_args = FvpDriver.gen_fvp_args(*common_args) if call_super else []

        fvp_args += [
            "--data", f"cluster0.cpu0={dt.dtb}@{self._spmc_dtb_address}",
            "--data", f"cluster0.cpu0={self.args.spmc}@{self._spmc_address}",
        ]

        fvp_args += FvpDriverSPMC.secure_ctrl_fvp_args(self, secure_ctrl)

        img_ldadd = self.get_img_and_ldadd(self.args.partitions["SPs"])
        for img, ldadd in img_ldadd:
            fvp_args += ["--data", f"cluster0.cpu0={img}@{hex(ldadd)}"]

        return fvp_args

    def run(self, run_name, test_args, is_long_running, debug = False, show_output = False):
        vm_args = join_if_not_None(self.args.vm_args, test_args)
        FvpDriverSPMC.hftest_cmd_file.write(f"{vm_args}\n")
        FvpDriverSPMC.hftest_cmd_file.seek(0)
        return super().run(run_name, test_args, is_long_running, debug, show_output)

    def finish(self):
        """Clean up after running tests."""
        FvpDriverSPMC.hftest_cmd_file.close()

class FvpDriverBothWorlds(FvpDriverHypervisor, FvpDriverSPMC):
    def __init__(self, args):
        FvpDriverHypervisor.__init__(self, args, hypervisor_address=0x88000000)
        FvpDriverSPMC.__init__(self, args)

    def create_dt(self, run_name):
        dt = dict()
        dt["hypervisor"] = FvpDriver.create_dt(self, run_name + "_hypervisor")
        dt["spmc"] = FvpDriver.create_dt(self, run_name + "_spmc")
        return dt

    def compile_dt(self, run_state, dt):
        FvpDriver.compile_dt(self, run_state, dt["hypervisor"])
        FvpDriver.compile_dt(self, run_state, dt["spmc"])

    def gen_dts(self, dt, test_args):
        FvpDriverHypervisor.gen_dts(self, dt["hypervisor"], test_args)
        FvpDriverSPMC.gen_dts(self, dt["spmc"], test_args)

    def gen_fvp_args(self, is_long_running, uart0_log_path, uart1_log_path, dt,
                     debug = False, show_output = False):
        """Generate command line arguments for FVP."""
        common_args = (self, is_long_running, uart0_log_path, uart1_log_path)
        fvp_args = FvpDriverHypervisor.gen_fvp_args(*common_args, dt["hypervisor"],
                                                    debug, show_output)
        fvp_args += FvpDriverSPMC.gen_fvp_args(*common_args, dt["spmc"], False,
                                               False)
        return fvp_args

    def run(self, run_name, test_args, is_long_running, debug = False,
            show_output = False):

        return FvpDriver.run(self, run_name, test_args, is_long_running,
               debug, show_output)

    def finish(self):
        """Clean up after running tests."""
        FvpDriver.finish(self)

class FvpDriverEL3SPMC(FvpDriverSPMC):
    """
    Driver which runs tests in Arm FVP emulator, with EL3 as SPMC
    """

    def __init__(self, args):
        FvpDriverSPMC.__init__(
                self, args, cpu_start_address=0x04003000,
                fvp_prebuilt_bl31=os.path.join(FVP_PREBUILTS_TFA_EL3_SPMC_ROOT, "bl31.bin"))
        self.vms_in_partitions_json = args.partitions and args.partitions["SPs"]
        self._sp_dtb_address = 0x0403f000

    def sp_partition_manifest_fvp_args(self):
        img_ldadd = self.get_img_and_ldadd(self.args.partitions["SPs"])

        # Expect only one tuple with img and load address, as EL3 SPMC only supports
        # one SP.
        assert(len(img_ldadd) == 1)
        img, ldadd = img_ldadd[0]
        fvp_args = ["--data", f"cluster0.cpu0={img}@{ldadd}"]

        # Even though FF-A manifest is part of the SP PKG we need to load at a specific
        # location. Fetch the respective dtb file and load at the following address.
        output_path = os.path.dirname(os.path.dirname(img))
        partition_manifest = f"{output_path}/partition-manifest.dtb"
        fvp_args += ["--data", f"cluster0.cpu0={partition_manifest}@{self._sp_dtb_address}"]
        return fvp_args

    def gen_fvp_args(
        self, is_long_running, uart0_log_path, uart1_log_path, dt,
        call_super = True, secure_ctrl = True, debug = False, show_output = False):
        """Generate command line arguments for FVP."""
        common_args = (self, is_long_running, uart0_log_path, uart1_log_path, dt.dtb,
                       debug, show_output)
        fvp_args = FvpDriver.gen_fvp_args(*common_args) if call_super else []

        fvp_args += FvpDriverSPMC.secure_ctrl_fvp_args(self, secure_ctrl)

        fvp_args += self.sp_partition_manifest_fvp_args()

        return fvp_args

class FvpDriverEL3SPMCBothWorlds(FvpDriverHypervisor, FvpDriverEL3SPMC):
    """
    Driver which runs tests in Arm FVP emulator, with EL3 as SPMC
    """

    def __init__(self, args):
        FvpDriverHypervisor.__init__(self, args)
        FvpDriverEL3SPMC.__init__(self, args)

        self._fvp_prebuilt_bl32 = os.path.join(FVP_PREBUILTS_TFA_EL3_SPMC_ROOT, "bl32.bin")
        self._fvp_prebuilt_dtb = os.path.join(FVP_PREBUILTS_TFA_EL3_SPMC_ROOT, "fdts/fvp_tsp_sp_manifest.dtb")

    def gen_fvp_args(
        self, is_long_running, uart0_log_path, uart1_log_path, dt,
        call_super = True, secure_ctrl = True, debug = False, show_output = False):
        """Generate command line arguments for FVP."""

        fvp_args = FvpDriverHypervisor.gen_fvp_args(self, is_long_running, uart0_log_path, uart1_log_path, dt,
        debug, show_output)

        fvp_args += FvpDriverSPMC.secure_ctrl_fvp_args(self, secure_ctrl)

        if self.args.partitions is not None and self.args.partitions["SPs"] is not None:
            fvp_args += FvpDriverEL3SPMC.sp_partition_manifest_fvp_args(self)
        else :
            # Use prebuilt TSP and TSP manifest if build does not specify SP
            # EL3 SPMC expects SP to be loaded at 0xFF200000 and SP manifest at 0x0403F000
            fvp_args += ["--data", f"cluster0.cpu0={self._fvp_prebuilt_bl32}@0xff200000"]
            fvp_args += ["--data", f"cluster0.cpu0={self._fvp_prebuilt_dtb}@{self._sp_dtb_address}"]

        return fvp_args

class SerialDriver(Driver):
    """Driver which communicates with a device over the serial port."""

    def __init__(self, args, tty_file, baudrate, init_wait):
        Driver.__init__(self, args)
        self.tty_file = tty_file
        self.baudrate = baudrate
        self.pyserial = importlib.import_module("serial")

        if init_wait:
            input("Press ENTER and then reset the device...")

    def connect(self):
        return self.pyserial.Serial(self.tty_file, self.baudrate, timeout=10)

    def run(self, run_name, test_args, is_long_running):
        """Communicate `test_args` to the device over the serial port."""
        run_state = self.start_run(run_name)

        with self.connect() as ser:
            with open(run_state.log_path, "a") as f:
                while True:
                    # Read one line from the serial port.
                    line = ser.readline().decode('utf-8')
                    if len(line) == 0:
                        # Timeout
                        run_state.set_ret_code(124)
                        input("Timeout. " +
                            "Press ENTER and then reset the device...")
                        break
                    # Write the line to the log file.
                    f.write(line)
                    if HFTEST_CTRL_GET_COMMAND_LINE in line:
                        # Device is waiting for `test_args`.
                        ser.write(test_args.encode('ascii'))
                        ser.write(b'\r')
                    elif HFTEST_CTRL_FINISHED in line:
                        # Device has finished running this test and will reboot.
                        break

        return self.finish_run(run_state)

    def finish(self):
        """Clean up after running tests."""
        with self.connect() as ser:
            while True:
                line = ser.readline().decode('utf-8')
                if len(line) == 0:
                    input("Timeout. Press ENTER and then reset the device...")
                elif HFTEST_CTRL_GET_COMMAND_LINE in line:
                    # Device is waiting for a command. Instruct it to exit
                    # the test environment.
                    ser.write("exit".encode('ascii'))
                    ser.write(b'\r')
                    break

# Tuple used to return information about the results of running a set of tests.
TestRunnerResult = collections.namedtuple("TestRunnerResult", [
        "tests_run",
        "tests_failed",
        "tests_skipped",
    ])

class TestRunner:
    """Class which communicates with a test platform to obtain a list of
    available tests and driving their execution."""

    def __init__(self, artifacts, driver, test_set_up, suite_regex, test_regex,
            skip_long_running_tests, force_long_running, debug, show_output):
        self.artifacts = artifacts
        self.driver = driver
        self.test_set_up = test_set_up
        self.skip_long_running_tests = skip_long_running_tests
        self.force_long_running = force_long_running
        self.debug = debug
        self.show_output = show_output

        self.suite_re = re.compile(suite_regex or ".*")
        self.test_re = re.compile(test_regex or ".*")

    def extract_hftest_lines(self, raw):
        """Extract hftest-specific lines from a raw output from an invocation
        of the test platform."""
        lines = []
        lines_to_process = raw.splitlines()

        try:
            # If logs have logs of more than one VM, the loop below to extract
            # lines won't work. Thus, extracting between starting and ending
            # logs: HFTEST_CTRL_GET_COMMAND_LINE and HFTEST_CTRL_FINISHED.
            hftest_start = lines_to_process.index(HFTEST_CTRL_GET_COMMAND_LINE) + 1
            hftest_end = lines_to_process.index(HFTEST_CTRL_FINISHED)
        except ValueError:
            hftest_start = 0
            hftest_end = len(lines_to_process)

        lines_to_process = lines_to_process[hftest_start : hftest_end]

        for line in lines_to_process:
            match = HFTEST_CTRL_JSON_REGEX.search(line)
            if match is not None:
                line = line[match.end():]
            if line.startswith(HFTEST_LOG_PREFIX):
                lines.append(line[len(HFTEST_LOG_PREFIX):])
        return lines

    def get_test_json(self):
        """Invoke the test platform and request a JSON of available test and
        test suites."""
        out = self.driver.run("json", "json", self.force_long_running)
        hf_out = self.extract_hftest_lines(out)
        try:
            hf_out = hf_out[hf_out.index(HFTEST_CTRL_JSON_START) + 1
                        :hf_out.index(HFTEST_CTRL_JSON_END)];
        except ValueError as e:
            print("Unable to find JSON control string:")
            print(f"out={out}")
            print(f"hf_out={hf_out}")
            raise e

        hf_out = "\n".join(hf_out)
        try:
            return json.loads(hf_out)
        except ValueError as e:
            print("Unable to parse JSON:")
            print(f"out={out}")
            print(f"hf_out={hf_outout}")
            print(out)
            raise e

    def collect_results(self, fn, it, xml_node):
        """Run `fn` on every entry in `it` and collect their TestRunnerResults.
        Insert "tests" and "failures" nodes to `xml_node`."""
        tests_run = 0
        tests_failed = 0
        tests_skipped = 0
        start_time = time.perf_counter()
        for i in it:
            sub_result = fn(i)
            assert(sub_result.tests_run >= sub_result.tests_failed)
            tests_run += sub_result.tests_run
            tests_failed += sub_result.tests_failed
            tests_skipped += sub_result.tests_skipped
        elapsed_time = time.perf_counter() - start_time

        xml_node.set("tests", str(tests_run + tests_skipped))
        xml_node.set("failures", str(tests_failed))
        xml_node.set("skipped", str(tests_skipped))
        xml_node.set("time", str(elapsed_time))
        return TestRunnerResult(tests_run, tests_failed, tests_skipped)

    def is_passed_test(self, test_out):
        """Parse the output of a test and return True if it passed."""
        return \
            len(test_out) > 0 and \
            test_out[-1] == HFTEST_LOG_FINISHED and \
            not any(l.startswith(HFTEST_LOG_FAILURE_PREFIX) for l in test_out)

    def get_failure_message(self, test_out):
        """Parse the output of a test and return the message of the first
        assertion failure."""
        for i, line in enumerate(test_out):
            if line.startswith(HFTEST_LOG_FAILURE_PREFIX) and i + 1 < len(test_out):
                # The assertion message is on the line after the 'Failure:'
                return test_out[i + 1].strip()

        return None

    def get_log_name(self, suite, test):
        """Returns a string with a generated log name for the test."""
        log_name = ""

        cpu = self.driver.args.cpu
        if cpu:
            log_name += cpu + "."

        log_name += suite["name"] + "." + test["name"]

        return log_name

    def run_test(self, suite, test, suite_xml):
        """Invoke the test platform and request to run a given `test` in given
        `suite`. Create a new XML node with results under `suite_xml`.
        Test only invoked if it matches the regex given to constructor."""
        if not self.test_re.match(test["name"]):
            return TestRunnerResult(tests_run=0, tests_failed=0, tests_skipped=0)

        test_xml = ET.SubElement(suite_xml, "testcase")
        test_xml.set("name", test["name"])
        test_xml.set("classname", suite["name"])

        if (self.skip_long_running_tests and test["is_long_running"]) or test["skip_test"]:
            print("      SKIP", test["name"])
            test_xml.set("status", "notrun")
            skipped_xml = ET.SubElement(test_xml, "skipped")
            skipped_xml.set("message", "Long running")
            return TestRunnerResult(tests_run=0, tests_failed=0, tests_skipped=1)

        action_log = "DEBUG" if self.debug else "RUN"
        print(f"      {action_log}", test["name"])
        log_name = self.get_log_name(suite, test)

        test_xml.set("status", "run")

        start_time = time.perf_counter()
        out = self.driver.run(
            log_name, "run {} {}".format(suite["name"], test["name"]),
            test["is_long_running"] or self.force_long_running,
            self.debug, self.show_output)

        hftest_out = self.extract_hftest_lines(out)
        elapsed_time = time.perf_counter() - start_time

        test_xml.set("time", str(elapsed_time))

        system_out_xml = ET.SubElement(test_xml, "system-out")
        system_out_xml.text = out

        if self.is_passed_test(hftest_out):
            print("        PASS")
            return TestRunnerResult(tests_run=1, tests_failed=0, tests_skipped=0)
        else:
            print("[x]     FAIL --", self.driver.get_run_log(log_name))
            failure_xml = ET.SubElement(test_xml, "failure")
            failure_message = self.get_failure_message(hftest_out) or "Test failed"
            failure_xml.set("message", failure_message)
            failure_xml.text = '\n'.join(hftest_out)
            return TestRunnerResult(tests_run=1, tests_failed=1, tests_skipped=0)

    def run_suite(self, suite, xml):
        """Invoke the test platform and request to run all matching tests in
        `suite`. Create new XML nodes with results under `xml`.
        Suite skipped if it does not match the regex given to constructor."""
        if not self.suite_re.match(suite["name"]):
            return TestRunnerResult(tests_run=0, tests_failed=0, tests_skipped=0)

        print("    SUITE", suite["name"])
        suite_xml = ET.SubElement(xml, "testsuite")
        suite_xml.set("name", suite["name"])
        properties_xml = ET.SubElement(suite_xml, "properties")

        property_xml = ET.SubElement(properties_xml, "property")
        property_xml.set("name", "driver")
        property_xml.set("value", type(self.driver).__name__)

        if self.driver.args.cpu:
            property_xml = ET.SubElement(properties_xml, "property")
            property_xml.set("name", "cpu")
            property_xml.set("value", self.driver.args.cpu)

        return self.collect_results(
            lambda test: self.run_test(suite, test, suite_xml),
            suite["tests"],
            suite_xml)

    def run_tests(self):
        """Run all suites and tests matching regexes given to constructor.
        Write results to sponge log XML. Return the number of run and failed
        tests."""

        test_spec = self.get_test_json()
        timestamp = datetime.datetime.now().replace(microsecond=0).isoformat()

        xml = ET.Element("testsuites")
        xml.set("name", self.test_set_up)
        xml.set("timestamp", timestamp)

        result = self.collect_results(
            lambda suite: self.run_suite(suite, xml),
            test_spec["suites"],
            xml)

        # Write XML to file.
        ET.ElementTree(xml).write(self.artifacts.sponge_xml_path,
            encoding='utf-8', xml_declaration=True)

        if result.tests_failed > 0:
            print("[x] FAIL:", result.tests_failed, "of", result.tests_run,
                    "tests failed")
        elif result.tests_run > 0:
            print("    PASS: all", result.tests_run, "tests passed")

        # Let the driver clean up.
        self.driver.finish()

        return result

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
