Advisory HFV-2 (CVE-2026-73092)
===============================

+----------------+-----------------------------------------------------------------+
| Title          | FFA_NS_RES_INFO_GET may read beyond fragmented memory-send      |
|                | descriptors                                                     |
+================+=================================================================+
| CVE ID         | CVE-2026-73092                                                  |
+----------------+-----------------------------------------------------------------+
| Date           | Reported on July 8th 2026                                       |
+----------------+-----------------------------------------------------------------+
| Versions       | Hafnium v2.14 through v2.15                                     |
| Affected       |                                                                 |
+----------------+-----------------------------------------------------------------+
| Configurations | Hafnium running as the S-EL2 SPMC with FF-A v1.3                |
| Affected       | FFA_NS_RES_INFO_GET enabled.                                    |
+----------------+-----------------------------------------------------------------+
| Impact         | Disclosure of S-EL2 secure-pool contents to the Normal World    |
|                | and denial of service to the Secure World                       |
+----------------+-----------------------------------------------------------------+
| Severity       | CVSS v3.1 7.9 (High)                                            |
|                | CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:H                    |
+----------------+-----------------------------------------------------------------+
| Fix Version    | `Skip incomplete memory-send transactions`_ and                 |
|                | `traverse constituents across all fragments`_                   |
+----------------+-----------------------------------------------------------------+
| Credit         | Minwoo Ra                                                       |
+----------------+-----------------------------------------------------------------+

Description
-----------

Hafnium retains an FF-A memory-send transaction in a share-state entry while
its fragments are being received. The composite memory-region header in the
initial fragment declares the total number of constituents in the transaction,
whereas the share state records the constituents actually received in each
fragment.

FFA_NS_RES_INFO_GET enumerated allocated Normal World share states without
first requiring the memory-send transaction to be complete. It then used the
declared total constituent count as the bound for indexing the constituent
array following the composite header in the initial fragment. A malicious
Normal World endpoint could submit an initial FFA_MEM_SHARE fragment containing
fewer constituents than declared and leave the transaction incomplete. A
subsequent FFA_NS_RES_INFO_GET call would read beyond the received constituents
and interpret adjacent S-EL2 secure-pool memory as constituent records.

Completed fragmented transactions also retain continuation fragments in
separate allocations. Although completion verifies that the declared count
matches the total received across all fragments, it does not make those
allocations contiguous with the constituent array in the initial descriptor.
FFA_NS_RES_INFO_GET therefore must resolve each constituent through the share
state's fragment array rather than index every constituent from the initial
fragment.

Exploitability Details
----------------------

Exploitation requires control of privileged Normal World software, such as an
NS-EL1 operating system or NS-EL2 hypervisor, that can issue crafted FF-A calls.
Hafnium must be operating as the S-EL2 SPMC, FFA_NS_RES_INFO_GET must be
enabled, and the caller must be able to initiate fragmented memory-send
transactions.

When the receiver endpoint can be resolved, out-of-bounds values may be
interpreted as memory constituents and returned to the Normal World as FF-A
address-map descriptors. This can disclose values derived from adjacent S-EL2
secure-pool objects, including address-like values, endpoint metadata,
permissions, and in-flight descriptor contents.

When the receiver endpoint cannot be resolved, no address-map descriptor is
emitted and the response-page budget does not terminate constituent traversal.
An incomplete transaction with a large attacker-controlled constituent count
can consequently cause a long-running loop in S-EL2, preventing the FF-A call
from returning and starving Secure World execution.

No out-of-bounds write, control-flow corruption, or integrity impact has been
identified.

Mitigation and Recommendations
------------------------------

The fixes prevent FFA_NS_RES_INFO_GET from traversing incomplete memory-send
transactions and resolve constituent indices through the allocations recorded
in the share state's fragment array. Together, these changes ensure that only
fully received transactions are reported and that every constituent is read
from the fragment that stores it.

Users of affected configurations should apply both fixes. If the fixes cannot
be applied immediately, integrators should prevent untrusted Normal World
software from invoking FFA_NS_RES_INFO_GET or initiating fragmented
memory-send transactions.

.. _Skip incomplete memory-send transactions: https://review.trustedfirmware.org/q/I4daf28e0a47d32f1176caa5228038e961176b967
.. _traverse constituents across all fragments: https://review.trustedfirmware.org/q/I9dbb5df7f0cfbd0540df1886353ac038f44ecd1c
