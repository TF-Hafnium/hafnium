#!/usr/bin/env python3
#
# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

"""
shrinkwrap_utils.py

Helper class for managing Shrinkwrap integration within the Hafnium test framework.

This module provides the `ShrinkwrapManager` class, which handles:
  - Setting up the Shrinkwrap environment.
  - Generating dynamic YAML overlay from runtime-evaluated `rtvars` and `params`
  - Invoking Shrinkwrap `build` once per test session
  - Running Shrinkwrap for each test using the generated dynamic overlay.

Used by FVP-based drivers (e.g. FvpDriver, FvpDriverSPMC, etc.) to simplify
and reuse Shrinkwrap logic.
"""

import os
import subprocess
import yaml
import shutil
import logging
import re

# Inherits the config settings from global logger in hftest.py
logger = logging.getLogger(__name__)

VM_PARAM_OFFSET = 5
INITRD_PARAM_OFFSET = 8
SP_PARAM_OFFSET = 10

# Maps FVP driver configuration keys to their corresponding static Shrinkwrap overlays
SHRINKWRAP_STATIC_OVERLAY_MAP = {
    "hypervisor": ["fvp_hf_hypervisor_preloaded.yaml"],
    "spmc": ["fvp_hf_spmc_preloaded.yaml"],
    "hypervisor_and_spmc": ["fvp_hf_hypervisor_and_spmc_preloaded.yaml"],
    "el3_spmc": ["fvp_hf_el3spmc_preloaded.yaml"],
    "hypervisor_el3_spmc": ["fvp_hf_hypervisor_el3spmc_preloaded.yaml"]
}

class ShrinkwrapManager:

    CONFIG_SUBDIR = os.path.join("tools", "shrinkwrap", "configs", "kokoro")
    FVP_BASE_PACKAGE = "FVP_Base_RevC-2xAEMvA-hafnium.yaml"
    DEFAULT_DYNAMIC_OVERLAY = "fvp_hf_dynamic_overlay.yaml"
    _fvp_package_built = False

    def __init__(self, hafnium_root):
        self.hafnium_root = hafnium_root
        self.env = self.setup_env()

    def _get_config_dir(self):
        """Returns the absolute path to Shrinkwrap yaml configs directory."""
        return os.path.join(self.hafnium_root, self.CONFIG_SUBDIR)

    def setup_env(self):
        """
        Sets up and returns the environment required for Shrinkwrap.
        Returns:
            dict: Updated environment dictionary for Shrinkwrap use.
        """
        env = os.environ.copy()

        # Specify explicit environment variables (e.g., CI, Docker), fallback to /src/out
        default_workspace = os.path.join(self.hafnium_root, "out")
        default_config_dir = self._get_config_dir()

        # Set Shrinkwrap-specific environment variables.
        env["SHRINKWRAP_CONFIG"] = env.get("SHRINKWRAP_CONFIG", default_config_dir)
        env["SHRINKWRAP_BUILD"] = env.get("SHRINKWRAP_BUILD", os.path.join(default_workspace, "build"))
        env["SHRINKWRAP_PACKAGE"] = env.get("SHRINKWRAP_PACKAGE", os.path.join(default_workspace, "package"))

        # Validate output directories exist (skip errors if in read-only FS)
        try:
            os.makedirs(env["SHRINKWRAP_BUILD"], exist_ok=True)
            os.makedirs(env["SHRINKWRAP_PACKAGE"], exist_ok=True)
        except OSError:
            pass # Likely running in read-only root filesystem

        # Add Shrinkwrap's CLI path to PATH if not already present
        shrinkwrap_binary = os.path.join(self.hafnium_root, "third_party", "shrinkwrap", "shrinkwrap")
        if shrinkwrap_binary not in env.get("PATH", ""):
            env["PATH"] = shrinkwrap_binary + os.pathsep + env.get("PATH", "")

        # Validate shrinkwrap CLI exists
        try:
            resolved_path = self.get_shrinkwrap_cmd(env)
        except RuntimeError:
            raise

        # Print the Shrinkwrap environment variables once for every test session(DEBUG only)
        if not getattr(ShrinkwrapManager.setup_env, "_has_printed", False):
            logger.debug("Shrinkwrap environment variables set:")
            for key in ["SHRINKWRAP_CONFIG", "SHRINKWRAP_BUILD", "SHRINKWRAP_PACKAGE", "PATH"]:
                logger.debug("  %s = %s", key, env[key])
            ShrinkwrapManager.setup_env._has_printed = True
        return env

    @staticmethod
    def add_multi_param_with_spacing(base_key, values, offset=5):
        """
        Generate Shrinkwrap-compliant spaced param keys for duplicate base keys.
        """
        return {(" " * (i + offset)) + base_key: val for i, val in enumerate(values)}

    def ensure_config_dir(self):
        """Ensure the Shrinkwrap kokoro config directory exists."""
        os.makedirs(self._get_config_dir(), exist_ok=True)

    def get_dynamic_overlay_path(self, filename="fvp_hf_dynamic_overlay.yaml"):
        """Return the absolute path to the overlay YAML file in the kokoro config directory."""
        self.ensure_config_dir()
        return os.path.join(self._get_config_dir(), filename or self.DEFAULT_DYNAMIC_OVERLAY)

    def write_overlay_yaml(self, overlay_path, rtvars, new_params=None, fvp_name=None):
        """
        Write rtvars and optional params to a YAML overlay file.
        Args:
            overlay_path (str): Full path to the overlay YAML file.
            rtvars (dict): Dictionary of runtime variables.
            params (dict, optional): Optional FVP parameters.
            run_name (str, optional): Optional value for run.name.
        """
        overlay = {"run": {"rtvars": rtvars}}
        if new_params:
            overlay["run"]["params"] = new_params
        if fvp_name:
            overlay["run"]["name"] = fvp_name

        with open(overlay_path, "w") as f:
            yaml.safe_dump(overlay, f, sort_keys=False)

    def get_shrinkwrap_cmd(self, env):
        """Check for Shrinkwrap CLI availability and return its path."""
        path = shutil.which("shrinkwrap", path=env.get("PATH", ""))
        if not path:
            raise RuntimeError(
                "'shrinkwrap' CLI not found in PATH. "
                "Please ensure it's built and available at out/shrinkwrap/shrinkwrap."
            )
        return path

    def build_fvp_package_once(self, overlays):
        """
        Builds the Shrinkwrap FVP package using static YAML overlays,
        if not already built.
        This is a one-time setup performed per test session (i.e., per hftest.py invocation),
        and combines the base FVP model with test-specific static configuration overlays.
        """
        if getattr(self.__class__, "_fvp_package_built", False):
            return

        config_dir = self._get_config_dir()

        # NOTE: Do NOT move or modify the build_cmd initialization block below.
        # The base command (with FVP package) MUST be passed first,
        # followed by all --overlay options (including loop-based and conditional ones).
        # Changing this order may break Shrinkwrap's build semantics.
        build_cmd = [
            "shrinkwrap", "--runtime", "null", "build",
            os.path.join(config_dir, "FVP_Base_RevC-2xAEMvA-hafnium.yaml")
        ]
        for overlay in overlays:
            build_cmd += ["--overlay",  os.path.join(config_dir, overlay)]

        logger.debug("Shrinkwrap BUILD CMD:\n%s", " ".join(build_cmd))
        self.__class__._fvp_package_built = True

        try:
            subprocess.run(build_cmd, env=self.env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.debug("\u2705 Shrinkwrap build succeeded")
        except subprocess.CalledProcessError as e:
            raise RuntimeError("\u274C Shrinkwrap build step failed") from e

    def run_fvp(self, run_state, execute_logged_fn, is_long_running, debug,
                show_output, cov_plugin, dynamic_overlay=None):
        """
        Executes Shrinkwrap 'run' using the prebuilt FVP package,
        overlaying the dynamically generated runtime YAML  and timeouts.
        """
        config_dir = self._get_config_dir()
        show_output = debug or show_output
        dynamic_overlay = dynamic_overlay or self.DEFAULT_DYNAMIC_OVERLAY

        time_limit = "40s"
        if cov_plugin is None:
            time_limit = "150s" if is_long_running else time_limit
        else:
            time_limit = "300s" if is_long_running else "80s"

        # NOTE: Keep this order — timeout first (if enabled), then Shrinkwrap
        # run with FVP base package and dynamic overlay.
        # Reordering may break execution or cause config issues.
        run_cmd = []
        if not show_output:
            run_cmd += ["timeout", "--foreground", time_limit]

        run_cmd += [
            "shrinkwrap", "--runtime", "null", "run", "FVP_Base_RevC-2xAEMvA-hafnium.yaml"
        ]
        if debug:
            run_cmd += ["--overlay", os.path.join(config_dir, "fvp_hf_debug.yaml")]
        if cov_plugin is not None:
            run_cmd += ["--overlay", os.path.join(config_dir, "fvp_hf_cov_plugin.yaml")]
        if dynamic_overlay:
            run_cmd += ["--overlay", os.path.join(config_dir, dynamic_overlay)]

        logger.debug("Shrinkwrap RUN CMD:\n%s", " ".join(run_cmd))

        self.log_resolved_fvp_command(run_cmd, run_state.log_path)

        try:
            execute_logged_fn(run_state, run_cmd, env=self.env)
            logger.debug("\u2705 Shrinkwrap run successful")
        except subprocess.CalledProcessError as e:
            raise RuntimeError("\u274C Shrinkwrap run failed") from e

    def log_resolved_fvp_command(self, run_cmd, log_path):
        """
        Extracts the actual FVP execution command line from Shrinkwrap's --dry-run
        output and appends it to the test's UART log for traceability.

        Note:
        Shrinkwrap's `--dry-run` output includes more than just the FVP command-
        it may contain shell boilerplate, git operations etc.
        This function filters that output to extract only the actual FVP model
        command for logging.
        """
        dry_run_cmd = run_cmd + ["--dry-run"]

        try:
            result = subprocess.run(dry_run_cmd, env=self.env, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output_lines = result.stdout.decode().splitlines()
            fvp_cmd = []
            capture_fvp_cmd = False

            for line in output_lines:
                trimmed_line = line.strip()

                # Regex Logic:
                # ^/ : Line start with a ( / )
                #.*/FVP_   : Somewhere in the path, it must include 'FVP_' (e.g., FVP_Base_RevC...)
                # .*  : can have additionl data after that FVP name
                if re.match(r"^/.*/FVP_.*", trimmed_line):
                    capture_fvp_cmd = True  # Start capturing

                if capture_fvp_cmd:
                    # Stop capturing if we hit an unrelated command or blank (optional)
                    if (trimmed_line.startswith("#") or
                        trimmed_line.startswith("git ") or
                        trimmed_line == ""):
                        break
                    fvp_cmd.append(line)

            if fvp_cmd:
                with open(log_path, "a") as f:
                    f.write("\n # SHRINKWRAP Resolved FVP Command:\n")
                    for line in fvp_cmd:
                        f.write(line + "\n")
                    f.write("\n")
            else:
                logger.warning("No FVP command found in Shrinkwrap --dry-run output.")

        except subprocess.CalledProcessError as e:
            logger.warning("Shrinkwrap dry-run failed while logging FVP command: %s", e)
