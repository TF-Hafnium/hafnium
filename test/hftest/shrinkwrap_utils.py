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

        # Validate shrinkwrap CLI exists and log its resolved path
        try:
            resolved_path = self.get_shrinkwrap_cmd(env)
            print (f"Shrinkwrap CLI found at: {resolved_path}")
        except RuntimeError:
            raise

        # Print the Shrinkwrap environment variables once for every test session(DEBUG only)
        if not getattr(ShrinkwrapManager.setup_env, "_has_printed", False):
            print("Shrinkwrap environment variables set:")
            for key in ["SHRINKWRAP_CONFIG", "SHRINKWRAP_BUILD", "SHRINKWRAP_PACKAGE", "PATH"]:
                print("  %s = %s", key, env[key])
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

    def get_dynamic_overlay_path(self, filename):
        """Return the absolute path to the overlay YAML file in the kokoro config directory."""
        self.ensure_config_dir()
        return os.path.join(self._get_config_dir(), filename or self.DEFAULT_DYNAMIC_OVERLAY)

    def write_overlay_yaml(self, overlay_path, rtvars, new_params=None, run_name=None):
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
        if run_name:
            overlay["run"]["name"] = run_name

        with open(overlay_path, "w") as f:
            yaml.safe_dump(overlay, f, sort_keys=False)

    def get_shrinkwrap_cmd(self, env):
        path = shutil.which("shrinkwrap", path=env.get("PATH", ""))
        if not path:
            raise RuntimeError(
                "'shrinkwrap' CLI not found in PATH. "
                "Please ensure it's built and available at out/shrinkwrap/shrinkwrap."
            )
        return path

    def build_fvp_package_once(self):
        """
        Builds the Shrinkwrap FVP package using static YAML overlays,
        if not already built.
        This is a one-time setup performed per test session (i.e., per hftest.py invocation),
        and combines the base FVP model with test-specific static configuration overlays.
        """
        pass

    def run_fvp(self):
        """
        Executes Shrinkwrap 'run' using the prebuilt FVP package,
        overlaying the dynamically generated runtime YAML  and timeouts.
        """
        pass
