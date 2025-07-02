Prerequisites
=============

Build Host
----------

A relatively recent Linux distribution is recommended.
CI runs are done using Ubuntu 22.04 LTS (64-bit).

Toolchain
---------

The clang-20 toolchain is recommended for building Hafnium and the test
infrastructure. On Ubuntu, the toolchain can be installed from the LLVM apt
repository (https://apt.llvm.org/).

.. note::

   Using a toolchain version greater than, or significantly lesser than the one
   specified is not guaranteed to work.

.. note::

   You may also use the Docker container if you are unable to install the
   toolchain on your host machine, see the :ref:`Using_Docker` section.

Dependencies
------------

Build
^^^^^

The following command install the dependencies for the Hafnium build:

.. code:: shell

   sudo apt install make libssl-dev flex bison python3 python3-serial python3-pip device-tree-compiler

In addition, install the following python libraries using `pip`_:

.. code:: shell

   pip3 install fdt click

The file kokoro/static_checks.sh runs a series of static code checks into Hafnium's codebase.
Hafnium follows the linux kernel coding guidelines. As such, the static code checks using the
'checkpatch.pl' script from linux source tree. To setup and download 'checkpatch.pl':

.. code:: shell

   ./build/setup_checkpatch.sh

Then test it works with:

.. code:: shell

   make checkpatch

System and Python Packages for test infrastructure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The `Shrinkwrap`_ tool is a core component of the hftest scripts and is included
as a submodule. It relies on the following system packages to function correctly:

.. code:: shell

   sudo apt-get install -y git netcat-openbsd python3 python3-pip telnet

Further, install the required Python packages:

.. code:: shell

   pip3 install --user fdt pyyaml termcolor tuxmake

.. note::

   These manual installation steps are not required if you're using the Docker
   based test environment. All necessary dependencies—system packages,
   Python modules, and Shrinkwrap environment configuration—are already
   pre-installed and automated inside the Docker image provided by the
   Hafnium repository (see :ref:`Using_Docker`).

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

*Copyright (c) 2023-2025, Arm Limited. All rights reserved.*

.. _Shrinkwrap: https://shrinkwrap.docs.arm.com
.. _Sphinx: http://www.sphinx-doc.org/en/master/
.. _Poetry: https://python-poetry.org/docs/
.. _pip: https://pip.pypa.io/en/stable/
