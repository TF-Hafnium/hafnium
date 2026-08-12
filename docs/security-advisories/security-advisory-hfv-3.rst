Advisory HFV-3 (CVE-2026-73093)
===============================

+----------------+-----------------------------------------------------------------+
| Title          | Integer overflow in FF-A receiver array bounds check can cause  |
|                | an out-of-bounds access                                         |
+================+=================================================================+
| CVE ID         | CVE-2026-73093                                                  |
+----------------+-----------------------------------------------------------------+
| Date           | Reported on 6th July 2026                                       |
+----------------+-----------------------------------------------------------------+
| Versions       | Hafnium v2.15                                                   |
| Affected       |                                                                 |
+----------------+-----------------------------------------------------------------+
| Configurations | Hafnium configurations that accept FF-A v1.1 or later memory    |
| Affected       | send requests from an untrusted caller                          |
+----------------+-----------------------------------------------------------------+
| Impact         | Denial of service (Hafnium panic)                               |
+----------------+-----------------------------------------------------------------+
| Fix Version    | `Receiver array bound check`_                                   |
+----------------+-----------------------------------------------------------------+
| Credit         | Minwoo Ra                                                       |
+----------------+-----------------------------------------------------------------+

Description
-----------

Hafnium validates the receiver array in an FF-A memory transaction descriptor
before accessing its entries. The end of the array was calculated from the
``receivers_offset``, ``memory_access_desc_size``, and ``receiver_count``
fields using 32-bit unsigned arithmetic.

An attacker can supply a large ``receivers_offset`` that causes this
calculation to wrap around. The wrapped value can pass the fragment bounds
check, while the original offset is subsequently used to form a pointer
outside the copied memory transaction descriptor. Dereferencing this pointer
can cause an out-of-bounds access and panic Hafnium.

Exploitability Details
----------------------

The issue affects FF-A v1.1 and later memory send requests, for which the
caller supplies the receiver array offset. The caller must be able to invoke
``FFA_MEM_SHARE``, ``FFA_MEM_LEND``, or ``FFA_MEM_DONATE`` and control the
memory transaction descriptor in its TX buffer.

When Hafnium runs as an SPMC, a compromised Normal World component can submit
the malformed descriptor and cause an S-EL2 panic. The resulting availability
impact is a denial of service.

Mitigation and Recommendations
------------------------------

The issue is fixed by calculating the end of the receiver array using 64-bit
arithmetic and rejecting the descriptor when the result exceeds the initial
fragment length. This validation occurs before a receiver pointer is formed.

Users should apply the fix referenced below. There is no known configuration
workaround other than preventing untrusted callers from issuing FF-A memory
send requests.

.. _Receiver array bound check: https://review.trustedfirmware.org/q/Ic54bbc09f7ff604f93d35e7ab5f3523c4250133a
