Prerequisites
=============

Build Host
----------

A relatively recent Linux distribution is recommended.
CI runs are done using Ubuntu 22.04 LTS (64-bit).

Toolchain
---------

The following toolchain is recommended for building Hafnium and the test
infrastructure:

- For a x86_64 Ubuntu host,

.. code:: shell

   https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz

- For a AArch64 Ubuntu host,

.. code:: shell

   https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang+llvm-18.1.8-aarch64-linux-gnu.tar.xz

.. note::

   Use of a native toolchain installed on the host (e.g. /usr/bin/clang) is
   not supported.

.. note::

   Using a toolchain version greater, or significantly lesser than the one
   specified is not guaranteed to work.

The PATH environment variable shall be adjusted to contain the LLVM/clang directory, e.g.:

.. code:: shell

   PATH=<toolchain_dir>/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04/bin:$PATH

Dependencies
------------

Build
^^^^^

The following command install the dependencies for the Hafnium build:

.. code:: shell

   sudo apt install make libssl-dev flex bison python3 python3-serial python3-pip device-tree-compiler

In addion, install the following python lib using `pip`_:

.. code:: shell

   pip3 install fdt

The file kokoro/static_checks.sh runs a series of static code checks into Hafnium's codebase.
Hafnium follows the linux kernel coding guidelines. As such, the static code checks using the
'checkpatch.pl' script from linux source tree. To setup and download 'checkpatch.pl':

.. code:: shell

   ./build/setup_checkpatch.sh

Then test it works with:

.. code:: shell

   make checkpatch

Documentation
^^^^^^^^^^^^^

To create a rendered copy of this documentation locally you can use the
`Sphinx`_ tool to build and package the plain-text documents into HTML-formatted
pages.

For building a local copy of the documentation you will need:

- Python 3 (3.8 or later)
- PlantUML (1.2017.15 or later)
- `Poetry`_ (Python dependency manager)

Below is an example set of instructions to get a working environment (tested on
Ubuntu):

.. code:: shell

    sudo apt install python3 python3-pip plantuml
    curl -sSL https://install.python-poetry.org | python3 -

Run the command below to install using Poetry, Python dependencies to build the documentation:

.. code:: shell

    poetry install --with docs

Poetry will create a new virtual environment and install all dependencies listed
in ``pyproject.toml``. You can get information about this environment, such as
its location and the Python version, with the command:

.. code:: shell

    poetry env info

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*

.. _Sphinx: http://www.sphinx-doc.org/en/master/
.. _Poetry: https://python-poetry.org/docs/
.. _pip: https://pip.pypa.io/en/stable/
