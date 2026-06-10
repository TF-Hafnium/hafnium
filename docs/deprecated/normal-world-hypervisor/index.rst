Deprecated Normal-World Hypervisor
==================================

.. warning::

   The following pages describe Hafnium's legacy normal-world hypervisor.
   This implementation is retained only as historical reference and test
   infrastructure. It is not a supported product target, and current Hafnium
   documentation should be read as SPMC-first.

Relevant maintained guidance lives in:

- :doc:`../../getting_started/prerequisites` for toolchain and FVP setup.
- :doc:`../../getting_started/building` for supported build flows.
- :doc:`../../getting_started/hafnium-tests` for current test execution.
- :doc:`../../getting_started/project-structure` for the current source tree.

These pages are kept because some tests, drivers, overlays, and FF-A
compatibility paths still rely on the legacy hypervisor code. Treat the content
below as deprecated reference material, not current guidance.

.. toctree::
   :maxdepth: 1

   GetStarted
   Architecture
   CodeStructure
   FVP
   HafniumRamDisk
   HermeticBuild
   Manifest
   PreparingLinux
   SchedulerExpectations
   StyleGuide
   Testing
   VmInterface
