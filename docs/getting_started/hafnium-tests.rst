Hafnium Tests
=============

This guide explains how to build and run Hafnium tests on the Arm |FVP|, including
all necessary other firmware images, by using `Shrinkwrap`_.
These tests include Hafnium itself, as well as supporting components like TF-A,
secure partitions, and test payloads such as TFTF.

Overview of Shrinkwrap for Hafnium Testing
------------------------------------------

Shrinkwrap is a tool that makes it easier to build and run firmware on Arm FVP.
It provides a user-friendly command-line interface and, by default, uses a
container-based backend to manage the build environment.
It uses YAML-based configuration files to describe platform topology, firmware
components, and runtime parameters. These configurations can be easily customized
and extended through a built-in layering system.

For further detailed information on the Shrinkwrap tool, including its design and usage,
refer to the `Quick Start Guide`_.

Shrinkwrap Integration in hftest.py
-----------------------------------

Shrinkwrap is included in the Hafnium repository as a Git submodule at
``third_party/shrinkwrap``.

For test execution, all Shrinkwrap setup is handled internally by the
Hafnium test framework. The `hftest.py` script uses a helper class
(``ShrinkwrapManager``) to configure paths, generate overlays, and run
Shrinkwrap commands for each test.

Manual configuration of environment variables or setup scripts is not
required. The `hftest.py` framework handles Shrinkwrap setup automatically in all
environments, including local development, Docker, and CI.

To run Hafnium tests configured through the ``kokoro/`` test scripts, use the
following predefined Makefile targets:

.. code:: shell

   make test_spmc        # Runs the SPMC test suite
   make test_el3_spmc    # Runs the EL3 SPMC test suite

These workflows are supported across local development, CI pipelines, and the
Hafnium Docker container provided under ``build/docker/``.

These targets invoke test scripts under `kokoro/` directory, which then invokes
`hftest.py` with the appropriate configuration. Shrinkwrap is used under the
hood to build the FVP package and launch tests using both static and dynamic overlays.

For example:
- ``kokoro/test_spmc.sh`` runs tests for Secure Partition Manager Component (SPMC) at S-EL1.
- ``kokoro/test_el3_spmc.sh`` runs tests for EL3-based SPMC setups (e.g., Hafnium at EL3).


Manual Shrinkwrap Environment Setup
-----------------------------------

If you intend to use Shrinkwrap manually, outside of `hftest.py` framework, you
can configure the environment using the following script:

.. code:: shell

   source ./tools/shrinkwrap/shrinkwrap_setup_env.sh

This script prepares the environment by:

- Adding the Shrinkwrap CLI binary to your ``PATH``
- Setting ``SHRINKWRAP_CONFIG`` to point to Hafnium’s overlay configs
- Setting ``SHRINKWRAP_BUILD`` and ``SHRINKWRAP_PACKAGE`` as the output directories for build artifacts

.. note::

   By default, if ${SHRINKWRAP_BUILD} and ${SHRINKWRAP_PACKAGE} are not set,
   Shrinkwrap uses ``${HOME}/.shrinkwrap`` as its default output directory.
   However, the provided setup script ``shrinkwrap_setup_env.sh`` overrides that
   and places the build/package outputs under ``out/`` folder in the Hafnium
   repository. You can modify these paths if needed.

Shrinkwrap at the Core of the hftest Framework
----------------------------------------------

The ``hftest`` Python framework now leverages `Shrinkwrap`_ to handle model
configuration and runtime arguments for FVP-based Hafnium tests.
This integration replaces manual argument generation with modular and declarative
YAML configurations, enhancing both clarity and maintainability.

All Shrinkwrap-related functionality is handled internally by the
``ShrinkwrapManager`` utility, which abstracts away the complexity of manual
setup and execution.

The ``ShrinkwrapManager`` utility is responsible for:

* Setting up the Shrinkwrap environment (e.g., config paths, build directories)
* Generating the dynamic overlay.
* Running the Shrinkwrap build phase once, using static overlays.
* Running the Shrinkwrap run phase individually for each test, with the appropriate dynamic overlay.

Overlay Structure
~~~~~~~~~~~~~~~~~

Overlays are an important concept in Shrinkwrap. They are configuration fragments
(typically YAML files) that are layered on top of a base configuration—either
during the build or run phase to compose, reuse, or override configuration logic
without duplicating YAML files. Overlays are always applied as the topmost layer
in the configuration stack, and can also be passed dynamically at runtime using
the ``--overlay`` command-line flag to selectively modify or extend existing setups
without altering the original configuration.

In the context of Hafnium's ``hftest.py`` integration with Shrinkwrap, overlays
are applied in the following way:

- **Static Overlays**:

  - Define reusable FVP-related configurations such as hypervisor preloading,
    SPMC artifact addresses, debug flags, etc.
  - Each test driver (e.g., `FvpDriverHypervisor`, `FvpDriverSPMC`, `FvpDriverEL3SPMC`)
    contributes one or more static overlays.
  - These are applied during the Shrinkwrap build phase and reside under:
    ``tools/shrinkwrap/configs/kokoro/``

  - Example overlays:

    - ``fvp_hf_hypervisor_preloaded.yaml``
    - ``fvp_hf_spmc_preloaded.yaml``
    - ``fvp_hf_debug.yaml`` (conditionally applied)

- **Dynamic Overlay**:

  - Automatically generated by ``hftest.py`` at runtime.
  - Applied during the **Shrinkwrap run phase** using: ``fvp_hf_dynamic_overlay.yaml``

- **Overlay Layering in Practice**:

  - Common FVP platform settings are defined in the base YAML:
    ``FVP_Base_RevC-2xAEMvA-hafnium.yaml``
  - Static overlays provided by the test driver are layered **on top** of this
    base during the ``shrinkwrap build`` phase.
  - The dynamic overlay is layered **last**, during the ``shrinkwrap run`` phase,
    and contains runtime values such as UART log paths, memory load addresses,
    or test-specific artifacts.

This overlay-based design promotes clean separation between reusable
infrastructure setup and per-test dynamic inputs. It improves configurability,
test maintenance, and makes it easy to add new test targets without repeating
model configuration.

Testing Hafnium with TFTF
-------------------------

Outside of the Hafnium test framework (`hftest.py`), developers can use a standalone
Shrinkwrap configuration ``hafnium-tftf.yaml`` to build and run the full
Hafnium software stack. This configuration is designed to support day-to-day
integration testing of Hafnium alongside `TF-A`_ and `TF-A-Tests`_.

The primary test payload from TF-A-Tests is the TFTF (Trusted Firmware Test
Framework) binary. The test setup also deploys the Cactus and Ivy secure partitions
to validate FF-A-based SPM functionality.

In this setup:

- TF-A runs at EL3
- Hafnium runs at Secure EL2
- Cactus and Ivy SPs (Secure Partitions) run at S-EL1
- TFTF runs in the Normal World

This configuration is ideal for validating SPMC behavior, FF-A interface support,
and overall system integration.

Hafnium provides dedicated Makefile targets to build and run the ``hafnium-tftf.yaml``
configuration using Shrinkwrap:

.. code:: shell

  make test_tftf         # Builds and runs the full configuration
  make test_tftf_build   # Only performs the Shrinkwrap build phase
  make test_tftf_run     # Runs the configuration on FVP after building
  make test_tftf_clean   # Cleans previously built Shrinkwrap artifacts

When ``HAFNIUM_HERMETIC_BUILD=true`` is set, the above targets are executed inside
the Hafnium developer Docker container (``build/docker/``), with all dependencies
and the runtime environment preconfigured.

These targets invoke corresponding rules from the ``kokoro.mk`` which run
``shrinkwrap build`` and ``shrinkwrap run`` using the ``hafnium-tftf.yaml``
configuration and its associated overlays.

The build and run commands are also documented in detail within the corresponding
YAML configuration file. When you run the build command, Shrinkwrap stores external
repositories under the ``${SHRINKWRAP_BUILD}/sources/<CONFIG_NAME>`` directory.

By using the ``hafnium-tftf.yaml`` custom configuration file, developers can
easily build and run SPM-related test suites through Shrinkwrap.

*Copyright (c) 2025, Arm Limited. All rights reserved.*

.. _Shrinkwrap: https://shrinkwrap.docs.arm.com
.. _Quick Start Guide: https://shrinkwrap.docs.arm.com/en/latest/userguide/quickstart.html#quick-start-guide
.. _TF-A: https://trustedfirmware-a.readthedocs.io/en/latest/
.. _TF-A-Tests: https://trustedfirmware-a-tests.readthedocs.io/en/latest/index.html
