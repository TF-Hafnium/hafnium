Advisory HFV-1 (CVE-2025-10263)
================================

+----------------+-----------------------------------------------------------------+
| Title          | Completion of affected memory accesses may not be guaranteed    |
|                | by the completion of a TLBI                                     |
+================+=================================================================+
| CVE ID         | `CVE-2025-10263`_                                               |
+----------------+-----------------------------------------------------------------+
| Date           | Reported on 13 August 2025                                      |
+----------------+-----------------------------------------------------------------+
| Versions       | All Hafnium versions up to and including v2.15                  |
| Affected       |                                                                 |
+----------------+-----------------------------------------------------------------+
| Configurations | All platforms containing any of the following affected CPU      |
| Affected       | implementations (if even a single affected core is present,     |
|                | the the workaround must be enabled):                            |
|                | - Cortex-A76                                                    |
|                | - Cortex-A76AE                                                  |
|                | - Cortex-A77                                                    |
|                | - Cortex-A78                                                    |
|                | - Cortex-A78C                                                   |
|                | - Cortex-A78AE                                                  |
|                | - Cortex-A710                                                   |
|                | - Cortex-X1                                                     |
|                | - Cortex-X1C                                                    |
|                | - Cortex-X2                                                     |
|                | - Cortex-X3                                                     |
|                | - Cortex-X4                                                     |
|                | - Cortex-X925                                                   |
|                | - Neoverse-N1                                                   |
|                | - Neoverse-N2                                                   |
|                | - Neoverse-V1                                                   |
|                | - Neoverse-V2                                                   |
|                | - Neoverse-V3                                                   |
|                | - Neoverse-V3AE                                                 |
|                | - C1-Ultra                                                      |
|                | - C1-Premium                                                    |
+----------------+-----------------------------------------------------------------+
| Impact         | Potential privilege escalation within the same security state   |
+----------------+-----------------------------------------------------------------+
| Fix Version    | `Gerrit Patches #cve_2025_10263`_                               |
|                | Also see mitigation guidance in the `Official Arm Advisory`_    |
+----------------+-----------------------------------------------------------------+
| Credit         | Arm                                                             |
+----------------+-----------------------------------------------------------------+

Description
-----------

CVE-2025-10263 describes an implementation erratum affecting the ordering
of TLBI and DSB instructions under multi-core concurrency. Under certain
conditions, a TLBI followed by a DSB may complete before store operations
from another processing element are globally observed.

This issue is specific to certain CPU implementations as described in the
`Official Arm Advisory`_. It is not an architectural vulnerability.

For full technical details of the erratum, refer to the Official Arm Advisory.

Impact on Hafnium
-----------------

Hafnium executes TLBI operations when modifying translation tables or updating
memory permissions. On affected CPU implementations, a TLBI followed by a DSB
may not guarantee that concurrent store operations from another processing
element have completed. This could allow memory accesses to be observed after
permission changes, potentially resulting in privilege escalation within the
same security state.

Mitigation in Hafnium
---------------------

Hafnium mitigates this erratum by issuing the additional TLBI + DSB sequence
required by the erratum after completion of TLBI maintenance affecting
Stage-1 translation information.

The mitigation is controlled via the build-time flag:

::

    WORKAROUND_CVE_2025_10263

This flag is disabled by default. Integrators must enable it when targeting
platforms that include affected CPU implementations.

.. _CVE-2025-10263: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-10263
.. _Gerrit Patches #cve_2025_10263: https://review.trustedfirmware.org/q/topic:%22jc/cve_2025_10263%22
.. _Official Arm Advisory: https://developer.arm.com/documentation/112137/1-0/
