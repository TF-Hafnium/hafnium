Project Structure
=================

The Hafnium repository contains Hafnium source code, along with testing code related to integration
tests, and unit tests.
To aid with the integration tests, the repository also contains a small client library
for partitions and prebuilt binaries of tools needed for the  build and running the tests.
The build system is supported by `gn`_.

Each platform has a single associated architecture.

The source tree is organised as follows:

::

    ├── build
    ├── docs
    ├── inc
    │   ├── hf
    │   │   ├── arch
    │   │   ├── plat
    │   │   └── ffa
    │   └── vmapi
    │       └── hf
    ├── kokoro
    ├── prebuilts
    ├── project
    ├── src
    │   ├── arch
    │   └── ffa
    ├── test
    │   ├── arch
    │   ├── hftest
    │   ├── inc
    │   ├── linux
    │   └── vmapi
    ├── third_party
    ├── tools
    ├── vmlib
    └── out

- `build`: Common GN configuration, build scripts, and linker script.

- `docs`: Documentation.

- `inc`: Header files.

   - `hf`: internal to Hafnium.

      - `arch`: Architecture-dependent modules, which have a common interface
        but separate implementations per architecture. This includes details
        of CPU initialisation, exception handling, timers, page table management,
        and other system registers.

      - `plat`: Platform-dependent modules, which have a common interface but
        separate implementations per platform. This includes details of the boot
        flow, and a UART driver for the debug log console.

      - `ffa`: Interface for FF-A features.

   - `vmapi/hf`: for the interface exposed to partitions.

- `kokoro`: Scripts and configuration for continuous integration and presubmit checks.

- `prebuilts`: Prebuilt binaries needed for building Hafnium or running tests.

- `project`: Configuration and extra code for each project.
  A project is a set of one or more platforms (see above) that are built
  together. Hafnium comes with the `reference` project
  for running it on some common emulators and development boards. To port
  Hafnium to a new board, you can create a new project under this directory
  with the platform or platforms you want to add, without affecting the core
  Hafnium code.

- `src`: Source code for Hafnium itself in C and assembly, and unit tests in C++.

  - `arch`: Implementation of architecture-dependent modules.

  - `ffa`: Abstraction over SPMC/hypervisor specific implementation details of FF-A features.
    This includes the maintained SPMC implementation as well as legacy normal-world
    hypervisor code paths kept for test coverage.

- `test`: Integration tests

   - `arch`: Tests for components of Hafnium that need to be run on a real architecture.

   - `hftest`: A simple test framework that supports running tests standalone on bare
     metal, in partitions under Hafnium. Also as user-space binaries under Linux, but these are
     not yet integrated with system where Hafnium is the SPMC.

   - `vmapi`: Tests which are run in minimal test partitions under Hafnium.

      - `arch`: Tests which are rely on specific architectural details such as the GIC version.

      - `primary_only`: Tests which run only a single (primary) partition.

      - `primary_with_secondaries`: Test which run with a primary partition and one
        or more secondary partitions to test how they interact.

- `third_party`: Third party code needed for building Hafnium.

- `vmlib`: A small client library for partitions running under Hafnium.

- `out`: Output directory for the build artifacts.

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*

.. _gn: https://gn.googlesource.com/gn/
