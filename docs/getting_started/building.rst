Building
========

This page assumes the :ref:`Prerequisites` have been followed to install all project dependencies.

Hafnium
^^^^^^^

By default, the Hafnium SPMC is built with clang for a few target platforms along
with tests. From Hafnium top level directory, simply type:

.. code:: shell

   make

The resulting FVP image is located in
`out/reference/secure_aem_v8a_fvp_vhe_clang/hafnium.bin`.

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
