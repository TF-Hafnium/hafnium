Building Documentation
======================

To create a rendered copy of this documentation locally you can use the
`Sphinx`_ tool to build and package the plain-text documents into HTML-formatted
pages.

If you are building the documentation for the first time then you will need to
check that you have the required software packages, as described in the
*Prerequisites* section that follows.

.. note::
   An online copy of the documentation is available at
   https://hafnium.readthedocs.io/, if you want to view a rendered
   copy without doing a local build.

Prerequisites
-------------

For building a local copy of the documentation you will need:

- Python 3 (3.8 or later)
- PlantUML (1.2017.15 or later)
- `Poetry`_ (Python dependency manager)

Below is an example set of instructions to get a working environment (tested on
Ubuntu):

.. code:: shell

    sudo apt install python3 python3-pip plantuml
    curl -sSL https://install.python-poetry.org | python3 -

Building rendered documentation
-------------------------------

To install Python dependencies using Poetry:

.. code:: shell

    poetry install

Poetry will create a new virtual environment and install all dependencies listed
in ``pyproject.toml``. You can get information about this environment, such as
its location and the Python version, with the command:

.. code:: shell

    poetry env info

If you have already sourced a virtual environment, Poetry will respect this and
install dependencies there.

Once all dependencies are installed, the documentation can be compiled into
HTML-formatted pages from the project root directory by running:

.. code:: shell

   poetry run make doc

Output from the build process will be placed in: ``docs/build/html``.

Other Output Formats
~~~~~~~~~~~~~~~~~~~~

We also support building documentation in other formats. From the ``docs``
directory of the project, run the following command to see the supported
formats.

.. code:: shell

   poetry run make -C docs help

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*

.. _Sphinx: http://www.sphinx-doc.org/en/master/
.. _Poetry: https://python-poetry.org/docs/
.. _pip homepage: https://pip.pypa.io/en/stable/
