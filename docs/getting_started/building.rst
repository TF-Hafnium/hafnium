Building Hafnium
================

Prerequisites
-------------

Build Host
^^^^^^^^^^

A relatively recent Linux distribution is recommended.
CI runs are done using Ubuntu 22.04 LTS (64-bit).

Toolchain
^^^^^^^^^

The following toolchain is recommended for building Hafnium and the test
infrastructure:

- For a x86_64 Ubuntu host,

.. code:: shell

   https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.6/clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04.tar.xz

- For a AArch64 Ubuntu host,

.. code:: shell

   https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.6/clang+llvm-15.0.6-aarch64-linux-gnu.tar.xz

.. note::

   Use of a native toolchain installed on the host (e.g. /usr/bin/clang) is
   not supported.

.. note::

   Using a toolchain version greater, or significantly lesser than the one
   specified is not guaranteed to work.

.. _prerequisites_software_and_libraries:

Dependencies
^^^^^^^^^^^^

If you are using the recommended Ubuntu distribution then you can install the
required packages with the following command:

.. code:: shell

   sudo apt install make libssl-dev flex bison python3 python3-serial
   python3-pip device-tree-compiler

   pip3 install fdt

.. _prerequisites_get_source:

Getting the sources
^^^^^^^^^^^^^^^^^^^

Hafnium source code is maintained in a Git repository hosted on
trustedfirmware.org.
To clone this repository from the server, run the following
in your shell:

.. code:: shell

    git clone --recurse-submodules https://git.trustedfirmware.org/hafnium/hafnium.git

In order to import gerrit hooks useful to add a Change-Id footer in commit messages,
it is recommended to use:

.. code:: shell

   git clone --recurse-submodules https://git.trustedfirmware.org/hafnium/hafnium.git && { cd hafnium && f="$(git rev-parse --git-dir)"; curl -Lo "$f/hooks/commit-msg" https://review.trustedfirmware.org/tools/hooks/commit-msg && { chmod +x "$f/hooks/commit-msg"; git submodule --quiet foreach "cp \"\$toplevel/$f/hooks/commit-msg\" \"\$toplevel/$f/modules/\$path/hooks/commit-msg\""; }; }

Building
--------

The PATH environment variable shall be adjusted to the LLVM/clang directory, prior to building e.g.:

.. code:: shell

   PATH=<toolchain_dir>/clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04/bin:$PATH

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

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*
