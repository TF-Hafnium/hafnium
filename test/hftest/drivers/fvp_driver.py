# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

from abc import ABC, abstractmethod
import shrinkwrap_utils as sw_util
import click
import fdt
import json
import logging
import os
import tempfile

from common import (
    ArtifactsManager,
    DT,
    TestRunner,
    append_file,
    correct_vm_node,
    get_vm_node_from_manifest,
    join_if_not_None,
    read_file,
    shared_options,
    write_file,
    HF_PREBUILTS,
    HF_ROOT,
    HFTEST_CTRL_FINISHED,
    MACHINE
)
from driver import Driver, DriverArgs, DriverRunException

DTC_SCRIPT = os.path.join(HF_ROOT, "build", "image", "dtc.py")

try:
    FVP_BINARY = os.environ['HAFNIUM_FVP']
    print(f"Setting environment FVP: {FVP_BINARY}")
except KeyError:
    FVP_BINARY = os.path.join(
        os.path.dirname(HF_ROOT), "fvp", "Base_RevC_AEMvA_pkg", "models",
        "Linux64_armv8l_GCC-9.3" if MACHINE == "aarch64" else "Linux64_GCC-9.3",
        "FVP_Base_RevC-2xAEMvA")

FVP_PREBUILTS_TFA_ROOT = os.path.join(
    HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a", "fvp")
FVP_PREBUILT_DTS = os.path.join(
    FVP_PREBUILTS_TFA_ROOT, "fvp-base-gicv3-psci-1t.dts")

FVP_PREBUILT_TFA_SPMD_ROOT = os.path.join(
    HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a-spmd", "fvp")

FVP_PREBUILTS_TFA_EL3_SPMC_ROOT = os.path.join(
    HF_PREBUILTS, "linux-aarch64", "trusted-firmware-a-el3-spmc")

class FvpDriver(Driver, ABC):
    """Base class for driver which runs tests in Arm FVP emulator."""
    shrinkwrap_static_overlay_key = None  # default, overriden in subclasses

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

    def get_shrinkwrap_static_overlay(self):
        key = self.shrinkwrap_static_overlay_key
        if key is None:
            raise ValueError(f"{type(self).__name__} did not define a shrinkwrap_overlay_key.")
        try:
            return sw_util.SHRINKWRAP_STATIC_OVERLAY_MAP[key]
        except KeyError:
            valid_keys = list(sw_util.SHRINKWRAP_STATIC_OVERLAY_MAP.keys())
            raise ValueError(
                f"No static overlays found for the key: '{key}' in SHRINKWRAP_STATIC_OVERLAY_MAP.\n"
                f"Supported keys are: {valid_keys}"
            )

    @abstractmethod
    def gen_dts(self, dt, test_args):
        """Abstract method to generate dts file. This specific to the use case
           so should be implemented within derived driver"""
        pass

    @abstractmethod
    def get_shrinkwrap_runtime_overlay_config(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug=False, show_output=False):
        """
        Constructs and returns the runtime overlay configuration for Shrinkwrap.

        Returns:
            Tuple[dict, dict]: A pair of (params, rtvars) dictionaries representing
            FVP runtime arguments and variable bindings for Shrinkwrap overlays.
        """
        disable_visualisation = self.args.disable_visualisation is True
        show_output = debug or show_output
        if not show_output:
            disable_visualisation = True

        params = {}

        rtvars = {
            "UART0_LOG" : {
                "type": "path",
                "value": str(uart0_log_path)
            },

            "UART1_LOG" : {
                "type": "path",
                "value": str(uart1_log_path)
            },

            "TELNET" : {
                "type": "string",
                "value": "false" if not show_output else "true"
            },

            "EXIT_ON_SHUTDOWN" : {
                "type": "string",
                "value": "1" if not show_output else "0"
            },

            "DISABLE_VISUALISATION" : {
                "type": "string",
                "value": "true" if disable_visualisation else "false"
            }
        }

        if self.cov_plugin is not None:
            rtvars.update ({
                "COV_PLUGIN" : {
                "type": "path",
                "value": str(self.cov_plugin)
                }
            })
        return params, rtvars

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
            # Setup Shrinkwrap Environment via ShrinkwrapManager helper
            shrinkwrap = sw_util.ShrinkwrapManager(HF_ROOT)

            # Perform the Shrinkwrap build (fvp_package) only once per test session
            # This constructs the Shrinkwrap build command using:
            # - The base FVP configuration
            # - Static overlays for the selected driver setup (e.g.: Hypervisor/SPMC)
            # - Optional overlays for debug mode and coverage plugins, if enabled
            driver_overlays = self.get_shrinkwrap_static_overlay()
            shrinkwrap.build_fvp_package_once(driver_overlays)

            # Generate runtime configuration (rtvars and params)
            params, rtvars = self.get_shrinkwrap_runtime_overlay_config(
                                is_long_running, uart0_log_path, uart1_log_path,
                                dt, debug=debug, show_output=show_output)

            # Construct the dynamic runtime overlay
            dynamic_overlay_path = shrinkwrap.get_dynamic_overlay_path()
            shrinkwrap.write_overlay_yaml(dynamic_overlay_path, rtvars,
                                        new_params=params, fvp_name=str(FVP_BINARY))

            # Shrinkwrap_Run phase: Launch FVP through Shrinkwrap for each test.
            # Invoke Shrinkwrap run phase using the combined overlays:
            # - FVP package built thorough Static overlay.
            # - Dynamic runtime overlay with resolved rtvars and test-specific data
            # This completes FVP model construction and launches the test instance.
            shrinkwrap.run_fvp(run_state, self.exec_logged, is_long_running,
                               debug, show_output, cov_plugin=self.cov_plugin)
        except DriverRunException:
            pass

        # Append UART outputs to the main run log with clear labels.
        append_file(run_state.log_path, "\n===== UART0 Output =====\n")
        append_file(run_state.log_path, read_file(uart0_log_path))
        append_file(run_state.log_path, "\n===== UART1 Output =====\n")
        append_file(run_state.log_path, read_file(uart1_log_path))
        return self.finish_run(run_state)

    def finish(self):
        """Clean up after running tests."""
        pass

    def fvp_options(f):
        f = click.option("--spmc")(f)
        f = click.option("--partitions_json")(f)
        f = click.option("--out_partitions")(f)
        f = click.option("--coverage_plugin")(f)
        f = click.option("--el3_spmc", is_flag=True)(f)
        return f

    @click.command()
    @shared_options
    @fvp_options
    def fvp(**options):
        FvpDriver.process_options(**options)

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
        if not os.path.isfile(FVP_BINARY):
            raise Exception("Cannot find FVP binary.")
        if options.get("partitions_json") is not None:
            partitions_dir = os.path.join(
                options.get("out_partitions"), "obj", options.get("partitions_json"))
            partitions = json.load(open(partitions_dir, "r"))
            global_run_name = os.path.basename(options.get("partitions_json")).split(".")[0]
        elif options.get("hypervisor"):
            if options.get("initrd"):
                global_run_name = os.path.basename(options.get("initrd"))
            else:
                global_run_name = os.path.basename(options.get("hypervisor")).split(".")[0]

        driver_args = DriverArgs(artifacts, options.get("hypervisor"), options.get("spmc"), initrd,
                                vm_args, options.get("cpu"), partitions, global_run_name,
                                options.get("coverage_plugin"), options.get("disable_visualisation"))

        if options.get("el3_spmc"):
            if options.get("hypervisor"):
                driver = FvpDriverEL3SPMCBothWorlds(driver_args)
            else:
                driver = FvpDriverEL3SPMC(driver_args)
        elif options.get("spmc"):
            if options.get("hypervisor"):
                driver = FvpDriverBothWorlds(driver_args)
            else:
                driver = FvpDriverSPMC(driver_args)
        elif options.get("hypervisor"):
            driver = FvpDriverHypervisor(driver_args)
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

class FvpDriverHypervisor(FvpDriver):
    """
    Driver which runs tests in Arm FVP emulator, with hafnium as hypervisor
    """
    INITRD_START= 0x84000000
    INITRD_END = 0x86000000 #Default value, however may change if initrd in args
    shrinkwrap_static_overlay_key = "hypervisor"

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

    def get_shrinkwrap_runtime_overlay_config(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug=False, show_output=False, call_base=True):
        """Construct Shrinkwrap-compatible rtvars and params dictionaries."""
        params = {}
        rtvars = {}

        # Include shared FVP configuration
        if call_base:
            params_base, rtvars_base = FvpDriver.get_shrinkwrap_runtime_overlay_config(
                                            self, is_long_running, uart0_log_path,
                                            uart1_log_path, dt, debug, show_output)
            params.update(params_base)
            rtvars.update(rtvars_base)

        # Add VMs image and load address variables
        data_entries = []
        if self.vms_in_partitions_json:
            img_ldadd = self.get_img_and_ldadd(self.args.partitions["VMs"])

            # Collect rtvars and param values for all VMs
            for i, (img, ldadd) in enumerate(img_ldadd):
                vm_name = f"VM{i+1}"
                img_var = f"{vm_name}_IMG"
                addr_var = f"{vm_name}_ADDR"
                rtvars.update({
                    img_var: {
                        "type": "path",
                        "value": str(img)
                    },
                    addr_var: {
                        "type": "string",
                        "value": hex(ldadd)
                    }
                })
                data_entries.append(f"${{rtvar:{img_var}}}@${{rtvar:{addr_var}}}")

            # Add --data cluster0.cpu0 spaced param entries for VMs starting from offset=5
            params.update(sw_util.ShrinkwrapManager.add_multi_param_with_spacing(
                "--data cluster0.cpu0", data_entries, offset=sw_util.VM_PARAM_OFFSET))

        # Add initrd data if specified
        if self.args.initrd:
            params.update(sw_util.ShrinkwrapManager.add_multi_param_with_spacing(
                "--data cluster0.cpu0",
                ["${rtvar:INITRD}@${rtvar:INITRD_START}"],
                offset=sw_util.INITRD_PARAM_OFFSET  # Ensures offset doesn't overlap with VMs
            ))

        # Add rtvars referenced by static preloaded YAML overlays
        static_rtvars = {
            "HYPERVISOR": {
                "type": "string",
                "value": str(self.args.hypervisor)
            },
            "HYPERVISOR_DTB": {
                "type": "string",
                "value": str(dt.dtb)
            },
            "INITRD": {
                "type": "path",
                "value": str(self.args.initrd)
            },
            "INITRD_START": {
                "type": "string",
                "value": str(self.INITRD_START)
            }
        }
        rtvars.update(static_rtvars)
        return params, rtvars

class FvpDriverSPMC(FvpDriver):
    """
    Driver which runs tests in Arm FVP emulator, with hafnium as SPMC
    """
    FVP_PREBUILT_SECURE_DTS = os.path.join(
        HF_ROOT, "test", "vmapi", "fvp-base-spmc.dts")
    hftest_cmd_file = tempfile.NamedTemporaryFile(mode="w+")
    shrinkwrap_static_overlay_key = "spmc"

    def __init__(self, args, cpu_start_address=0x04010000, fvp_prebuilt_bl31=None):
        fvp_prebuilt_bl31 = os.path.join(FVP_PREBUILT_TFA_SPMD_ROOT, "bl31.bin") if fvp_prebuilt_bl31 is None else fvp_prebuilt_bl31
        super().__init__(args, cpu_start_address, fvp_prebuilt_bl31)
        self.sps_in_partitions_json = args.partitions and args.partitions["SPs"]
        self._spmc_address = 0x6000000
        self._spmc_dtb_address = 0x0403f000

    def gen_dts(self, dt, test_args):
        """Create a DeviceTree source which will be compiled into a DTB and
        passed to FVP for a test run."""
        to_append = self.get_manifests_from_json(self.args.partitions["SPs"])
        write_file(dt.dts, read_file(FvpDriverSPMC.FVP_PREBUILT_SECURE_DTS))
        append_file(dt.dts, to_append)

    def secure_ctrl_fvp_args(self, secure_ctrl):
        params = {}
        if secure_ctrl:
            params.update({
                "-C bp.pl011_uart0.in_file": FvpDriverSPMC.hftest_cmd_file.name,
                "-C bp.pl011_uart0.shutdown_tag": HFTEST_CTRL_FINISHED
            })
        return params

    def get_shrinkwrap_runtime_overlay_config(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug=False, show_output=False, secure_ctrl=True, call_base=True):
        """Construct Shrinkwrap-compatible rtvars and params dictionaries."""
        params = {}
        rtvars = {}

        # Add Base Class settings
        if call_base:
            params_base, rtvars_base = FvpDriver.get_shrinkwrap_runtime_overlay_config(
                                            self, is_long_running,
                                            uart0_log_path, uart1_log_path, dt,
                                            debug, show_output)
            params.update(params_base)
            rtvars.update(rtvars_base)

        # Add SP images and load address variables
        sp_entries = []
        if self.sps_in_partitions_json:
            img_ldadd = self.get_img_and_ldadd(self.args.partitions["SPs"])
            for i, (img, ldadd) in enumerate(img_ldadd):
                sp_name = f"SP{i + 1}"
                img_var = f"{sp_name}_IMG"
                addr_var = f"{sp_name}_ADDR"

                # Create rtvars
                rtvars.update({
                    img_var: {
                        "type": "path",
                        "value": str(img)
                    },
                    addr_var: {
                        "type": "string",
                        "value": hex(ldadd)
                    }
                })
                # Construct value for --data cluster0.cpu0
                sp_entries.append(f"${{rtvar:{img_var}}}@${{rtvar:{addr_var}}}")

        # Generate a unique param key (YAML requires unique keys)
        # Add --data cluster0.cpu0 spaced entries for SPs (offset=10)
        if sp_entries:
            params.update(sw_util.ShrinkwrapManager.add_multi_param_with_spacing(
                "--data cluster0.cpu0", sp_entries, offset=sw_util.SP_PARAM_OFFSET))

        # Add static rtvars like SPMC_DTB
        rtvars["SPMC_DTB"] = {
            "type": "string",
            "value": str(dt.dtb)
        }

        # Add secure control UART parameters
        secure_params = FvpDriverSPMC.secure_ctrl_fvp_args(self, secure_ctrl)
        params.update(secure_params)
        return params, rtvars

    def run(self, run_name, test_args, is_long_running, debug = False, show_output = False):
        vm_args = join_if_not_None(self.args.vm_args, test_args)
        FvpDriverSPMC.hftest_cmd_file.write(f"{vm_args}\n")
        FvpDriverSPMC.hftest_cmd_file.seek(0)
        return super().run(run_name, test_args, is_long_running, debug, show_output)

    def finish(self):
        """Clean up after running tests."""
        FvpDriverSPMC.hftest_cmd_file.close()

class FvpDriverBothWorlds(FvpDriverHypervisor, FvpDriverSPMC):
    shrinkwrap_static_overlay_key = "hypervisor_and_spmc"

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

    def get_shrinkwrap_runtime_overlay_config(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug=False, show_output=False):
        """Generate command line arguments for FVP."""
        # Get base FVP arguments
        params_base, rtvars_base = FvpDriver.get_shrinkwrap_runtime_overlay_config(
                                        self, is_long_running, uart0_log_path,
                                        uart1_log_path, dt, debug, show_output)
        # Get hypervisor-specific arguments
        params_h, rtvars_h = FvpDriverHypervisor.get_shrinkwrap_runtime_overlay_config(
                                        self, is_long_running, uart0_log_path,
                                        uart1_log_path, dt["hypervisor"],
                                        debug, show_output, call_base=False)
        # Get SPMC-specific arguments
        params_s, rtvars_s = FvpDriverSPMC.get_shrinkwrap_runtime_overlay_config(
                                        self, is_long_running, uart0_log_path,
                                        uart1_log_path, dt["spmc"],
                                        debug, show_output, call_base=False)
        # Merge all the rtvars and params
        params = {**params_base, **params_h, **params_s}
        rtvars = {**rtvars_base, **rtvars_h, **rtvars_s}
        return params, rtvars

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
    shrinkwrap_static_overlay_key = "el3_spmc"

    def __init__(self, args):
        FvpDriverSPMC.__init__(
                self, args, cpu_start_address=0x04003000,
                fvp_prebuilt_bl31=os.path.join(FVP_PREBUILTS_TFA_EL3_SPMC_ROOT, "bl31.bin"))
        self.vms_in_partitions_json = args.partitions and args.partitions["SPs"]
        self._sp_dtb_address = 0x0403f000

    def sp_partition_manifest_fvp_args(self):
        """Generate rtvars and params for SP image and manifest loading."""

        img_ldadd = self.get_img_and_ldadd(self.args.partitions["SPs"])

        # Expect only one tuple with img and load address,
        # as EL3 SPMC only supports only one SP.
        assert(len(img_ldadd) == 1)
        img, ldadd = img_ldadd[0]

        # Even though FF-A manifest is part of the SP PKG we need to load at a specific
        # location. Fetch the respective dtb file and load at the following address.
        output_path = os.path.dirname(os.path.dirname(img))
        partition_manifest = os.path.join(output_path, "partition-manifest.dtb")

        # Runtime variables
        rtvars = {
            "SP_IMG": {
                "type": "path",
                "value": str(img)
            },
            "SP_ADDR": {
                "type": "string",
                "value": hex(ldadd)
            },
            "SP_DTB": {
                "type": "path",
                "value": str(partition_manifest)
            },
            "SP_DTB_ADDR": {
                "type": "string",
                "value": hex(self._sp_dtb_address)
            }
        }

        param_values = [
            "${rtvar:SP_IMG}@${rtvar:SP_ADDR}",
            "${rtvar:SP_DTB}@${rtvar:SP_DTB_ADDR}"
        ]
        params = sw_util.ShrinkwrapManager.add_multi_param_with_spacing(
                    "--data cluster0.cpu0", param_values, offset=sw_util.SP_PARAM_OFFSET)
        return params, rtvars

    def get_shrinkwrap_runtime_overlay_config(
                self, is_long_running, uart0_log_path, uart1_log_path, dt,
                secure_ctrl=True, debug=False, show_output=False,
                call_base=True):
        """Construct Shrinkwrap-compatible rtvars and params dictionaries."""
        params = {}
        rtvars = {}
        # Add Base Class settings
        if call_base:
            params_base, rtvars_base = FvpDriver.get_shrinkwrap_runtime_overlay_config(
                                            self, is_long_running,uart0_log_path,
                                            uart1_log_path, dt, debug, show_output)
            params.update(params_base)
            rtvars.update(rtvars_base)
        # Add secure control UART parameters
        secure_params = FvpDriverSPMC.secure_ctrl_fvp_args(self, secure_ctrl)
        params.update(secure_params)

        # SP image + manifest DTB
        params_m, rtvars_m = self.sp_partition_manifest_fvp_args()

        params.update(params_m)
        rtvars.update(rtvars_m)
        return params, rtvars

class FvpDriverEL3SPMCBothWorlds(FvpDriverHypervisor, FvpDriverEL3SPMC):
    """
    Driver which runs tests in Arm FVP emulator, with EL3 as SPMC
    """
    shrinkwrap_static_overlay_key = "hypervisor_el3_spmc"

    def __init__(self, args):
        FvpDriverHypervisor.__init__(self, args)
        FvpDriverEL3SPMC.__init__(self, args)

        self._fvp_prebuilt_bl32 = os.path.join(FVP_PREBUILTS_TFA_EL3_SPMC_ROOT, "bl32.bin")
        self._fvp_prebuilt_dtb = os.path.join(FVP_PREBUILTS_TFA_EL3_SPMC_ROOT, "fdts/fvp_tsp_sp_manifest.dtb")

    def get_shrinkwrap_runtime_overlay_config(
            self, is_long_running, uart0_log_path, uart1_log_path, dt,
            debug=False, show_output=False, secure_ctrl=True, call_base=True):
        """Generate command line arguments for FVP."""
        params = {}
        rtvars = {}
        # Add Base Class settings
        params_base, rtvars_base = FvpDriver.get_shrinkwrap_runtime_overlay_config(
                                        self, is_long_running,
                                        uart0_log_path, uart1_log_path, dt,
                                        debug, show_output)

        params_h, rtvars_h = FvpDriverHypervisor.get_shrinkwrap_runtime_overlay_config(
                                self, is_long_running, uart0_log_path,
                                uart1_log_path, dt, debug, show_output, call_base=False)
        # Merge all the rtvars and params
        params = {**params_base, **params_h}
        rtvars = {**rtvars_base, **rtvars_h}

        # Add secure control UART parameters
        secure_params = FvpDriverSPMC.secure_ctrl_fvp_args(self, secure_ctrl)
        params.update(secure_params)

        if self.args.partitions is not None and self.args.partitions["SPs"] is not None:
            # Step: SP image + manifest DTB
            params_sp, rtvars_sp = FvpDriverEL3SPMC.sp_partition_manifest_fvp_args(self)
            params.update(params_sp)
            rtvars.update(rtvars_sp)
        else:
            # Use prebuilt TSP and TSP manifest if build does not specify SP
            # EL3 SPMC expects SP to be loaded at 0xFF200000 and SP manifest at 0x0403F000
            # Case: Fallback to prebuilt TSP image and manifest
            rtvars.update ({
                "PREBUILT_BL32": {
                    "type": "path",
                    "value": str(self._fvp_prebuilt_bl32)
                },
                "TSP_ADDR": {
                    "type": "string",
                    "value": "0xff200000"
                },
                "PREBUILT_DTB": {
                    "type": "path",
                    "value": str(self._fvp_prebuilt_dtb)
                },
                "SP_DTB_ADDR": {
                    "type": "string",
                    "value": hex(self._sp_dtb_address)
                }
            })
            param_vals = [
                "${rtvar:PREBUILT_BL32}@${rtvar:TSP_ADDR}",
                "${rtvar:PREBUILT_DTB}@${rtvar:SP_DTB_ADDR}"
            ]
            params.update(sw_util.ShrinkwrapManager.add_multi_param_with_spacing(
                "--data cluster0.cpu0", param_vals, offset=sw_util.SP_PARAM_OFFSET))
        return params, rtvars
