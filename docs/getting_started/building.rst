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

    Supported platforms:  ['secure_rd_fremont', 'secure_rd_fremont_cfg1', 'secure_aem_v8a_fvp_vhe', 'aem_v8a_fvp_vhe', 'qemu_aarch64_vhe', 'secure_qemu_aarch64', 'rpi4', 'secure_tc']

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

Hafnium Documentation
^^^^^^^^^^^^^^^^^^^^^

If you have already sourced a virtual environment, Poetry will respect this and
install dependencies there.

.. code:: shell

   poetry run make doc

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*
