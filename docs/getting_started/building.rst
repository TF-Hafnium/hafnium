Building
========

This page assumes the :ref:`Prerequisites` have been followed to install all project dependencies.

Hafnium
^^^^^^^

Most common options
~~~~~~~~~~~~~~~~~~~

By default, Hafnium builds all target platforms along with tests with clang.
From Hafnium top level directory, use:

.. code:: shell

   make

The resulting Hafnium images are located in `out/reference/<platform>/hafnium.bin`.

It is possible to build Hafnium for a single platform target omitting tests,
resulting in faster builds when the test suite is not required.
For example to build the SPMC targeting FVP:

.. code:: shell

   make PLATFORM=secure_aem_v8a_fvp_vhe

The resulting FVP image is located in
`out/reference/secure_aem_v8a_fvp_vhe_clang/hafnium.bin`.

Multiple platform names can be provided for building e.g.:

.. code:: shell

   make PLATFORM="secure_aem_v8a_fvp_vhe,secure_tc"

To get a list of available platforms, you may use:

.. code:: shell

    make list

resulting in:

.. code:: shell

    Supported platforms:  ['secure_rd_fremont', 'secure_rd_fremont_cfg1', 'secure_aem_v8a_fvp_vhe', 'aem_v8a_fvp_vhe', 'aem_v8a_fvp_vhe_ffa_v1_1', 'qemu_aarch64_vhe', 'secure_qemu_aarch64', 'rpi4', 'secure_tc']

Additional options
~~~~~~~~~~~~~~~~~~

The presence of assertions in the final build can be set using the `ENABLE_ASSERTIONS`
make variable, by default this is set to `true`, meaning asserts are included in the build.

.. code:: shell

   make ENABLE_ASSERTIONS=<true|false>

Each project in the `project` directory specifies a root configurations of the
build. Adding a project is the preferred way to extend support to new platforms.
The target project that is built is selected by the `PROJECT` make variable, the
default project is 'reference'.

.. code:: shell

   make PROJECT=<project_name>

If you wish to change the value of the make variables you may need to first use:

.. code:: shell

   make clobber

So the `args.gn` file will be regenerated with the new values.

Troubleshoot(Clean Up Artifacts)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Before building Hafnium, ensure the Clang toolchain is installed and available
in your `PATH`. This is usually sufficient for a successful build.

If you encounter errors related to missing or incompatible C library headers
(e.g., after a failed build or toolchain update), clean up stale artifacts by running:

.. code:: shell

   make clobber

This command removes previously generated build outputs, which can help resolve
issues caused by outdated intermediate files. It's a useful troubleshooting step
but not required for a fresh setup.

.. _Using_Docker:

Using Docker
^^^^^^^^^^^^

We provide a Docker container to ensure a consistent development environment.
Build the container with `./build/docker/build.sh`. You can run commands in the
container with `./build/run_in_container.sh -i bash`:

.. code:: shell

   ./build/docker/build.sh
   ./build/run_in_container.sh -i bash
   make

Alternatively, the Makefile will automatically use the Docker container
if the environment variable `HAFNIUM_HERMETIC_BUILD` is set to `true`:

.. code:: shell

   ./build/docker/build.sh
   HAFNIUM_HERMETIC_BUILD=true make

Hafnium Documentation
^^^^^^^^^^^^^^^^^^^^^

If you have already sourced a virtual environment, Poetry will respect this and
install dependencies there.

.. code:: shell

   poetry run make doc


Output from the build process will be placed in: ``docs/build/html``.

To build the documentation in PDF format, additionally ensure that the following
packages are installed:

- FreeSerif font
- latexmk
- librsvg2-bin
- xelatex
- xindy

Below is an example set of instructions to install the required packages
(tested on Ubuntu):

.. code:: shell

   sudo apt install fonts-freefont-otf latexmk librsvg2-bin texlive-xetex xindy

Once all the dependencies are installed, the ``pdf`` can be built using:

.. code:: shell

   poetry run make -C docs latexpdf

The generated PDF (``hafnium.pdf``) can be found in: ``docs/build/latex``.

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*
