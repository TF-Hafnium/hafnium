Threat Model
************

.. contents::

************
Introduction
************
This document provides a threat model for the TF-A :ref:`Secure Partition Manager`
(SPM) implementation or more generally the S-EL2 reference firmware running on
systems implementing the FEAT_SEL2 (formerly Armv8.4 Secure EL2) architecture
extension. The SPM implementation is based on the `Arm Firmware Framework for
Arm A-profile`_ specification.

In brief, the broad FF-A specification and S-EL2 firmware implementation
provide:

- Isolation of mutually mistrusting SW components, or endpoints in the FF-A
  terminology.
- Distinct sandboxes in the secure world called secure partitions. This permits
  isolation of services from multiple vendors.
- A standard protocol for communication and memory sharing between FF-A
  endpoints.
- Mutual isolation of the normal world and the secure world (e.g. a Trusted OS
  is prevented to map an arbitrary NS physical memory region such as the kernel
  or the Hypervisor).

********************
Target of Evaluation
********************
In this threat model, the target of evaluation is the S-EL2 firmware or the
``Secure Partition Manager Core`` component (SPMC).
The monitor and SPMD at EL3 are covered by the `Generic TF-A threat model`_.

The scope for this threat model is:

- The TF-A implementation for the S-EL2 SPMC based on the Hafnium hypervisor
  running in the secure world of TrustZone (at S-EL2 exception level).
  The threat model is not related to the normal world Hypervisor or VMs.
  The S-EL1 and EL3 SPMC solutions are not covered.
- The implementation complies with the FF-A v1.0 specification, and a few
  features of FF-A v1.1 specification.
- Secure partitions are statically provisioned at boot time.
- Focus on the run-time part of the life-cycle (no specific emphasis on boot
  time, factory firmware provisioning, firmware udpate etc.)
- Not covering advanced or invasive physical attacks such as decapsulation,
  FIB etc.
- Assumes secure boot or in particular TF-A trusted boot (TBBR or dual CoT) is
  enabled. An attacker cannot boot arbitrary images that are not approved by the
  SiP or platform providers.

Data Flow Diagram
=================
Figure 1 shows a high-level data flow diagram for the SPM split into an SPMD
component at EL3 and an SPMC component at S-EL2. The SPMD mostly acts as a
relayer/pass-through between the normal world and the secure world. It is
assumed to expose small attack surface.

A description of each diagram element is given in Table 1. In the diagram, the
red broken lines indicate trust boundaries.

Components outside of the broken lines are considered untrusted.

.. uml:: resources/diagrams/plantuml/spm_dfd.puml
  :caption: Figure 1: SPMC Data Flow Diagram

.. table:: Table 1: SPMC Data Flow Diagram Description

  +---------------------+--------------------------------------------------------+
  | Diagram Element     | Description                                            |
  +=====================+========================================================+
  | ``DF1``             | SP to SPMC communication. FF-A function invocation or  |
  |                     | implementation-defined Hypervisor call.                |
  +---------------------+--------------------------------------------------------+
  | ``DF2``             | SPMC to SPMD FF-A call.                                |
  +---------------------+--------------------------------------------------------+
  | ``DF3``             | SPMD to NS forwarding.                                 |
  +---------------------+--------------------------------------------------------+
  | ``DF4``             | SP to SP FF-A direct message request/response.         |
  |                     | Note as a matter of simplifying the diagram            |
  |                     | the SP to SP communication happens through the SPMC    |
  |                     | (SP1 performs a direct message request to the          |
  |                     | SPMC targeting SP2 as destination. And similarly for   |
  |                     | the direct message response from SP2 to SP1).          |
  +---------------------+--------------------------------------------------------+
  | ``DF5``             | HW control.                                            |
  +---------------------+--------------------------------------------------------+
  | ``DF6``             | Bootloader image loading.                              |
  +---------------------+--------------------------------------------------------+
  | ``DF7``             | External memory access.                                |
  +---------------------+--------------------------------------------------------+

***************
Threat Analysis
***************

This threat model follows a similar methodology to the `Generic TF-A threat model`_.
The following sections define:

- Trust boundaries
- Assets
- Threat agents
- Threat types

Trust boundaries
================

- Normal world is untrusted.
- Secure world and normal world are separate trust boundaries.
- EL3 monitor, SPMD and SPMC are trusted.
- Bootloaders (in particular BL1/BL2 if using TF-A) and run-time BL31 are
  implicitely trusted by the usage of secure boot.
- EL3 monitor, SPMD, SPMC do not trust SPs.

.. figure:: resources/diagrams/spm-threat-model-trust-boundaries.png

    Figure 2: Trust boundaries

Assets
======

The following assets are identified:

- SPMC state.
- SP state.
- Information exchange between endpoints (partition messages).
- SPMC secrets (e.g. pointer authentication key when enabled)
- SP secrets (e.g. application keys).
- Scheduling cycles.
- Shared memory.

Threat Agents
=============

The following threat agents are identified:

- NS-Endpoint identifies a non-secure endpoint: normal world client at NS-EL2
  (Hypervisor) or NS-EL1 (VM or OS kernel).
- S-Endpoint identifies a secure endpoint typically a secure partition.
- Hardware attacks (non-invasive) requiring a physical access to the device,
  such as bus probing or DRAM stress.

Threat types
============

The following threat categories as exposed in the `Generic TF-A threat model`_
are re-used:

- Spoofing
- Tampering
- Repudiation
- Information disclosure
- Denial of service
- Elevation of privileges

Similarly this threat model re-uses the same threat risk ratings. The risk
analysis is evaluated based on the environment being ``Server`` or ``Mobile``.

Threat Assessment
=================

The following threats are identified by applying STRIDE analysis on each diagram
element of the data flow diagram.

+------------------------+----------------------------------------------------+
| ID                     | 01                                                 |
+========================+====================================================+
| ``Threat``             | **An endpoint impersonates the sender or receiver  |
|                        | FF-A ID in a direct request/response invocation.** |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF4                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMD, SPMC                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP state                                           |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Spoofing                                           |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------++----------------+---------------+
| ``Impact``             | Critical(5)      | Critical(5)     |               |
+------------------------+------------------++----------------+---------------+
| ``Likelihood``         | Critical(5)      | Critical(5)     |               |
+------------------------+------------------++----------------+---------------+
| ``Total Risk Rating``  | Critical(25)     | Critical(25)    |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not mitigate this threat.       |
|                        | The guidance below is left for a system integrator |
|                        | to implemented as necessary.                       |
|                        | The SPMC must enforce checks in the direct message |
|                        | request/response interfaces such an endpoint cannot|
|                        | spoof the origin and destination worlds (e.g. a NWd|
|                        | originated message directed to the SWd cannot use a|
|                        | SWd ID as the sender ID).                          |
|                        | Additionally a software component residing in the  |
|                        | SPMC can be added for the purpose of direct        |
|                        | request/response filtering.                        |
|                        | It can be configured with the list of known IDs    |
|                        | and about which interaction can occur between one  |
|                        | and another endpoint (e.g. which NWd endpoint ID   |
|                        | sends a direct request to which SWd endpoint ID).  |
|                        | This component checks the sender/receiver fields   |
|                        | for a legitimate communication between endpoints.  |
|                        | A similar component can exist in the OS kernel     |
|                        | driver, or Hypervisor although it remains untrusted|
|                        | by the SPMD/SPMC.                                  |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 02                                                 |
+========================+====================================================+
| ``Threat``             | **Tampering with memory shared between an endpoint |
|                        | and the SPMC.**                                    |
|                        | A malicious endpoint may attempt tampering with its|
|                        | RX/TX buffer contents while the SPMC is processing |
|                        | it (TOCTOU).                                       |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF3, DF4, DF7                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | Shared memory, Information exchange                |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering                                          |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (16)        | High (16)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | In context of FF-A v1.0 and v1.1 this is the case  |
|                        | of sharing the RX/TX buffer pair and usage in the  |
|                        | PARTITION_INFO_GET or mem sharing primitives.      |
|                        | The SPMC must copy the contents of the TX buffer   |
|                        | to an internal temporary buffer before processing  |
|                        | its contents. The SPMC must implement hardened     |
|                        | input validation on data transmitted through the TX|
|                        | buffer by an untrusted endpoint.                   |
|                        | The TF-A SPMC mitigates this threat by enforcing   |
|                        | checks on data transmitted through RX/TX buffers.  |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 03                                                 |
+========================+====================================================+
| ``Threat``             | **An endpoint may tamper with its own state or the |
|                        | state of another endpoint.**                       |
|                        | A malicious endpoint may attempt violating:        |
|                        | - its own or another SP state by using an unusual  |
|                        | combination (or out-of-order) FF-A function        |
|                        | invocations.                                       |
|                        | This can also be an endpoint emitting              |
|                        | FF-A function invocations to another endpoint while|
|                        | the latter is not in a state to receive it (e.g. a |
|                        | SP sends a direct request to the normal world early|
|                        | while the normal world is not booted yet).         |
|                        | - the SPMC state itself by employing unexpected    |
|                        | transitions in FF-A memory sharing, direct requests|
|                        | and responses, or handling of interrupts.          |
|                        | This can be led by random stimuli injection or     |
|                        | fuzzing.                                           |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF4                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMD, SPMC                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP state, SPMC state                               |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering                                          |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (12)        | High (12)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC provides mitigation against such     |
|                        | threat by following the guidance for partition     |
|                        | runtime models as described in FF-A v1.1 EAC0 spec.|
|                        | The SPMC performs numerous checks in runtime to    |
|                        | prevent illegal state transitions by adhering to   |
|                        | the partition runtime model.                       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 04                                                 |
+========================+====================================================+
| ``Threat``             | *An attacker may attempt injecting errors by the   |
|                        | use of external DRAM stress techniques.**          |
|                        | A malicious agent may attempt toggling an SP       |
|                        | Stage-2 MMU descriptor bit within the page tables  |
|                        | that the SPMC manages. This can happen in Rowhammer|
|                        | types of attack.                                   |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF7                                                |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP or SPMC state                                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | Hardware attack                                    |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering                                          |
+------------------------+------------------+---------------+-----------------+
| ``Application``        |   ``Server``     |  ``Mobile``   |                 |
+------------------------+------------------+---------------+-----------------+
| ``Impact``             | High (4)         | High (4)	    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Likelihood``         | Low (2)          | Medium (3)    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Total Risk Rating``  | Medium (8)       | High (12)	    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Mitigations``        | The TF-A SPMC does not provide mitigations to this |
|                        | type of attack. It can be addressed by the use of  |
|                        | dedicated HW circuity or hardening at the chipset  |
|                        | or platform level left to the integrator.          |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 05                                                 |
+========================+====================================================+
| ``Threat``             | **Protection of the SPMC from a DMA capable device |
|                        | upstream to an SMMU.**                             |
|                        | A device may attempt to tamper with the internal   |
|                        | SPMC code/data sections.                           |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF5                                                |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC or SP state                                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Elevation of privileges                 |
+------------------------+------------------+---------------+-----------------+
| ``Application``        |   ``Server``     |  ``Mobile``   |                 |
+------------------------+------------------+---------------+-----------------+
| ``Impact``             | High (4)         | High (4)      |                 |
+------------------------+------------------+---------------+-----------------+
| ``Likelihood``         | Medium (3)       | Medium (3)    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Total Risk Rating``  | High (12)        | High (12)     |                 |
+------------------------+------------------+---------------+-----------------+
| ``Mitigations``        | Hafnium SPMC mitigates this threat by enforcing    |
|                        | static dma isolation. Under this model, every      |
|                        | partition uses its manifest to specify the memory  |
|                        | regions in its physical address space that it      |
|                        | intends to make visible to each DMA device with    |
|                        | specific memory attributes.                        |
|                        | The SPMC enforces access control to make sure a DMA|
|                        | device cannot access a memory region unless        |
|                        | explicitly specified in partition manifest.        |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 06                                                 |
+========================+====================================================+
| ``Threat``             | **Replay fragments of past communication between   |
|                        | endpoints.**                                       |
|                        | A malicious endpoint may replay a message exchange |
|                        | that occured between two legitimate endpoint as    |
|                        | a matter of triggering a malfunction or extracting |
|                        | secrets from the receiving endpoint. In particular |
|                        | the memory sharing operation with fragmented       |
|                        | messages between an endpoint and the SPMC may be   |
|                        | replayed by a malicious agent as a matter of       |
|                        | getting access or gaining permissions to a memory  |
|                        | region which does not belong to this agent.        |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF2, DF3                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | Information exchange                               |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Repdudiation                                       |
+------------------------+------------------+---------------+-----------------+
| ``Application``        |   ``Server``     |  ``Mobile``   |                 |
+------------------------+------------------+---------------+-----------------+
| ``Impact``             | Medium (3)       | Medium (3)    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Likelihood``         | High (4)         | High (4)	    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Total Risk Rating``  | High (12)        | High (12)     |                 |
+------------------------+------------------+---------------+-----------------+
| ``Mitigations``        | The TF-A SPMC does not mitigate this threat.       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 07                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint may attempt to extract data |
|                        | or state information by the use of invalid or      |
|                        | incorrect input arguments.**                       |
|                        | Lack of input parameter validation or side effects |
|                        | of maliciously forged input parameters might affect|
|                        | the SPMC.                                          |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF4                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMD, SPMC                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP secrets, SPMC secrets, SP state, SPMC state     |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Information discolure                              |
+------------------------+------------------+---------------+-----------------+
| ``Application``        |   ``Server``     |  ``Mobile``   |                 |
+------------------------+------------------+---------------+-----------------+
| ``Impact``             | High (4)         | High (4)      |                 |
+------------------------+------------------+---------------+-----------------+
| ``Likelihood``         | Medium (3)       | Medium (3)    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Total Risk Rating``  | High (12)        | High (12)     |                 |
+------------------------+------------------+---------------+-----------------+
| ``Mitigations``        | Secure Partitions must follow security standards   |
|                        | and best practises as a way to mitigate the risk   |
|                        | of common vulnerabilities to be exploited.         |
|                        | The use of software (canaries) or hardware         |
|                        | hardening techniques (XN, WXN, BTI, pointer        |
|                        | authentication, MTE) helps detecting and stopping  |
|                        | an exploitation early.                             |
|                        | The TF-A SPMC mitigates this threat by implementing|
|                        | stack protector, pointer authentication, BTI, XN,  |
|                        | WXN, security hardening techniques.                |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 08                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint may forge a direct message  |
|                        | request such that it reveals the internal state of |
|                        | another endpoint through the direct message        |
|                        | response.**                                        |
|                        | The secure partition or SPMC replies to a partition|
|                        | message by a direct message response with          |
|                        | information which may reveal its internal state    |
|                        | (.e.g. partition message response outside of       |
|                        | allowed bounds).                                   |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF4                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC or SP state                                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Information discolure                              |
+------------------------+------------------+---------------+-----------------+
| ``Application``        |   ``Server``     |  ``Mobile``   |                 |
+------------------------+------------------+---------------+-----------------+
| ``Impact``             | Medium (3)       | Medium (3)    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Likelihood``         | Low (2)          | Low (2)	    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Total Risk Rating``  | Medium (6)       | Medium (6)    |                 |
+------------------------+------------------+---------------+-----------------+
| ``Mitigations``        | For the specific case of direct requests targeting |
|                        | the SPMC, the latter is hardened to prevent        |
|                        | its internal state or the state of an SP to be     |
|                        | revealed through a direct message response.        |
|                        | Further, SPMC performs numerous checks in runtime  |
|                        | on the basis of the rules established by partition |
|                        | runtime models to stop  any malicious attempts by  |
|                        | an endpoint to extract internal state of another   |
|                        | endpoint.                                          |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 09                                                 |
+========================+====================================================+
| ``Threat``             | **Probing the FF-A communication between           |
|                        | endpoints.**                                       |
|                        | SPMC and SPs are typically loaded to external      |
|                        | memory (protected by a TrustZone memory            |
|                        | controller). A malicious agent may use non invasive|
|                        | methods to probe the external memory bus and       |
|                        | extract the traffic between an SP and the SPMC or  |
|                        | among SPs when shared buffers are held in external |
|                        | memory.                                            |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF7                                                |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP/SPMC state, SP/SPMC secrets                     |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | Hardware attack                                    |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Information disclosure                             |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Low (2)          | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (6)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | It is expected the platform or chipset provides    |
|                        | guarantees in protecting the DRAM contents.        |
|                        | The TF-A SPMC does not mitigate this class of      |
|                        | attack and this is left to the integrator.         |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 10                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious agent may attempt revealing the SPMC |
|                        | state or secrets by the use of software-based cache|
|                        | side-channel attack techniques.**                  |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF7                                                |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP or SPMC state                                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Information disclosure                             |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Low (2)          | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (6)       | Medium (6)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | From an integration perspective it is assumed      |
|                        | platforms consuming the SPMC component at S-EL2    |
|                        | (hence implementing the Armv8.4 FEAT_SEL2          |
|                        | architecture extension) implement mitigations to   |
|                        | Spectre, Meltdown or other cache timing            |
|                        | side-channel type of attacks.                      |
|                        | The TF-A SPMC implements one mitigation (barrier   |
|                        | preventing speculation past exeception returns).   |
|                        | The SPMC may be hardened further with SW           |
|                        | mitigations (e.g. speculation barriers) for the    |
|                        | cases not covered in HW. Usage of hardened         |
|                        | compilers and appropriate options, code inspection |
|                        | are recommended ways to mitigate Spectre types of  |
|                        | attacks. For non-hardened cores, the usage of      |
|                        | techniques such a kernel page table isolation can  |
|                        | help mitigating Meltdown type of attacks.          |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 11                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint may attempt flooding the    |
|                        | SPMC with requests targeting a service within an   |
|                        | endpoint such that it denies another endpoint to   |
|                        | access this service.**                             |
|                        | Similarly, the malicious endpoint may target a     |
|                        | a service within an endpoint such that the latter  |
|                        | is unable to request services from another         |
|                        | endpoint.                                          |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF4                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not mitigate this threat.       |
|                        | Bounding the time for operations to complete can   |
|                        | be achieved by the usage of a trusted watchdog.    |
|                        | Other quality of service monitoring can be achieved|
|                        | in the SPMC such as counting a number of operations|
|                        | in a limited timeframe.                            |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 12                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint may attempt to allocate     |
|                        | notifications bitmaps in the SPMC, through the     |
|                        | FFA_NOTIFICATION_BITMAP_CREATE.**                  |
|                        | This might be an attempt to exhaust SPMC's memory, |
|                        | or to allocate a bitmap for a VM that was not      |
|                        | intended to receive notifications from SPs. Thus   |
|                        | creating the possibility for a channel that was not|
|                        | meant to exist.                                    |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of service, Spoofing                        |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium(3)        | Medium(3)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium(3)        | Medium(3)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium(9)        | Medium(9)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this threat by defining a  |
|                        | a fixed size pool for bitmap allocation.           |
|                        | It also limits the designated FF-A calls to be used|
|                        | from NWd endpoints.                                |
|                        | In the NWd the hypervisor is supposed to limit the |
|                        | access to the designated FF-A call.                |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 13                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint may attempt to destroy the  |
|                        | notifications bitmaps in the SPMC, through the     |
|                        | FFA_NOTIFICATION_BITMAP_DESTROY.**                 |
|                        | This might be an attempt to tamper with the SPMC   |
|                        | state such that a partition isn't able to receive  |
|                        | notifications.                                     |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering                                          |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Low(4)           | Low(4)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this issue by limiting the |
|                        | designated FF-A call to be issued by the NWd.      |
|                        | Also, the notifications bitmap can't be destroyed  |
|                        | if there are pending notifications.                |
|                        | In the NWd, the hypervisor must restrict the       |
|                        | NS-endpoints that can issue the designated call.   |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 14                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint might attempt to give       |
|                        | permissions to an unintended sender to set         |
|                        | notifications targeting another receiver using the |
|                        | FF-A call FFA_NOTIFICATION_BIND.**                 |
|                        | This might be an attempt to tamper with the SPMC   |
|                        | state such that an unintended, and possibly        |
|                        | malicious, communication channel is established.   |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Spoofing                                |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium(3)        | Medium(3)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium(6)        | Medium(6)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this by restricting        |
|                        | designated FFA_NOTIFICATION_BIND call to be issued |
|                        | by the receiver only. The receiver is responsible  |
|                        | for allocating the notifications IDs to one        |
|                        | specific partition.                                |
|                        | Also, receivers that are not meant to receive      |
|                        | notifications, must have notifications receipt     |
|                        | disabled in the respective partition's manifest.   |
|                        | As for calls coming from NWd, if the NWd VM has had|
|                        | its bitmap allocated at initialization, the TF-A   |
|                        | SPMC can't guarantee this threat won't happen.     |
|                        | The Hypervisor must mitigate in the NWd, similarly |
|                        | to SPMC for calls in SWd. Though, if the Hypervisor|
|                        | has been compromised, the SPMC won't be able to    |
|                        | mitigate it for calls forwarded from NWd.          |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 15                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious partition endpoint might attempt to  |
|                        | set notifications that are not bound to it.**      |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Spoofing                                           |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Low(4)           | Low(4)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this by checking the       |
|                        | sender's ID provided in the input to the call      |
|                        | FFA_NOTIFICATION_SET. The SPMC keeps track of which|
|                        | notifications are bound to which sender, for a     |
|                        | given receiver. If the sender is an SP, the        |
|                        | provided sender ID must match the ID of the        |
|                        | currently running partition.                       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 16                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious partition endpoint might attempt to  |
|                        | get notifications that are not targeted to it.**   |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Spoofing                                           |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Informational(1) | Informational(1)|               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this by checking the       |
|                        | receiver's ID provided in the input to the call    |
|                        | FFA_NOTIFICATION_GET. The SPMC keeps track of which|
|                        | notifications are pending for each receiver.       |
|                        | The provided receiver ID must match the ID of the  |
|                        | currently running partition, if it is an SP.       |
|                        | For calls forwarded from NWd, the SPMC will return |
|                        | the pending notifications if the receiver had its  |
|                        | bitmap created, and has pending notifications.     |
|                        | If Hypervisor or OS kernel are compromised, the    |
|                        | SPMC won't be able to mitigate calls from rogue NWd|
|                        | endpoints.                                         |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 17                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious partition endpoint might attempt to  |
|                        | get the information about pending notifications,   |
|                        | through the FFA_NOTIFICATION_INFO_GET call.**      |
|                        | This call is meant to be used by the NWd FF-A      |
|                        | driver.                                            |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Information disclosure                             |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium(3)        | Medium(3)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium(6)        | Medium(6)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this by returning error to |
|                        | calls made by SPs to FFA_NOTIFICATION_INFO_GET.    |
|                        | If Hypervisor or OS kernel are compromised, the    |
|                        | SPMC won't be able mitigate calls from rogue NWd   |
|                        | endpoints.                                         |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 18                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious partition endpoint might attempt to  |
|                        | flood another partition endpoint with notifications|
|                        | hindering its operation.**                         |
|                        | The intent of the malicious endpoint could be to   |
|                        | interfere with both the receiver's and/or primary  |
|                        | endpoint execution, as they can both be preempted  |
|                        | by the NPI and SRI, respectively.                  |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF4                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, CPU cycles                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | DoS                                                |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Low(2)           | Low(2)          |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium(3)        | Medium(3)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium(6)        | Medium(6)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not mitigate this threat.       |
|                        | However, the impact is limited due to the          |
|                        | architecture:                                      |
|                        | - Notifications are not queued, one that has been  |
|                        | signaled needs to be retrieved by the receiver,    |
|                        | until it can be sent again.                        |
|                        | - Both SRI and NPI can't be pended until handled   |
|                        | which limits the amount of spurious interrupts.    |
|                        | - A given receiver could only bind a maximum number|
|                        | of notifications to a given sender, within a given |
|                        | execution context.                                 |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 19                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint may abuse FFA_RUN call to   |
|                        | resume or turn on other endpoint execution         |
|                        | contexts, attempting to alter the internal state of|
|                        | SPMC and SPs, potentially leading to illegal state |
|                        | transitions and deadlocks.**                       |
|                        | An endpoint can call into another endpoint         |
|                        | execution context using FFA_MSG_SEND_DIRECT_REQ (or|
|                        | FFA_MSG_SEND_DIRECT_REQ2) ABI to create a call     |
|                        | chain. A malicious endpoint could abuse this to    |
|                        | form loops in a call chain that could lead to      |
|                        | potential deadlocks.                               |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF4                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, SPMD                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC provides mitigation against such     |
|                        | threats by following the guidance for partition    |
|                        | runtime models as described in FF-A v1.1 EAC0 spec.|
|                        | The SPMC performs numerous checks in runtime to    |
|                        | prevent illegal state transitions by adhering to   |
|                        | the partition runtime model. Further, if the       |
|                        | receiver endpoint is a predecessor of current      |
|                        | endpoint in the present call chain, the SPMC denies|
|                        | any attempts to form loops by returning FFA_DENIED |
|                        | error code. Only the primary scheduler is allowed  |
|                        | to turn on execution contexts of other partitions  |
|                        | though SPMC does not have the ability to           |
|                        | scrutinize its identity. Secure partitions have    |
|                        | limited ability to resume execution contexts of    |
|                        | other partitions based on the runtime model. Such  |
|                        | attempts cannot compromise the integrity of the    |
|                        | SPMC.                                              |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 20                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint can perform a               |
|                        | denial-of-service attack by using FFA_INTERRUPT    |
|                        | call that could attempt to cause the system to     |
|                        | crash or enter into an unknown state as no physical|
|                        | interrupt could be pending for it to be handled in |
|                        | the SPMC.**                                        |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF5                                      |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, SPMD                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC provides mitigation against such     |
|                        | attack by detecting invocations from partitions    |
|                        | and simply returning FFA_ERROR status interface.   |
|                        | SPMC only allows SPMD to use FFA_INTERRUPT ABI to  |
|                        | communicate a pending secure interrupt triggered   |
|                        | while execution was in normal world.               |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 21                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious secure endpoint might deactivate a   |
|                        | (virtual) secure interrupt that was not originally |
|                        | signaled by SPMC, thereby attempting to alter the  |
|                        | state of the SPMC and potentially lead to system   |
|                        | crash.**                                           |
|                        | SPMC maps the virtual interrupt ids to the physical|
|                        | interrupt ids to keep the implementation of virtual|
|                        | interrupt driver simple.                           |
|                        | Similarly, a malicious secure endpoint might invoke|
|                        | the deactivation ABI more than once for a secure   |
|                        | interrupt. Moreover, a malicious secure endpoint   |
|                        | might attempt to deactivate a (virtual) secure     |
|                        | interrupt that was signaled to another endpoint    |
|                        | execution context by the SPMC even before secure   |
|                        | interrupt was handled.                             |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state                               |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering                                          |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | At initialization, the TF-A SPMC parses the        |
|                        | partition manifests to find the target execution   |
|                        | context responsible for handling the various       |
|                        | secure physical interrupts. The TF-A SPMC provides |
|                        | mitigation against above mentioned threats by:     |
|                        |                                                    |
|                        | - Keeping track of each pending virtual interrupt  |
|                        |   signaled to an execution context of a secure     |
|                        |   secure partition.                                |
|                        | - Denying any deactivation call from SP if there is|
|                        |   no pending physical interrupt  mapped to the     |
|                        |   given virtual interrupt.                         |
|                        | - Denying any deactivation call from SP if the     |
|                        |   virtual interrupt has not been signaled to the   |
|                        |   current execution context.                       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 22                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious secure endpoint might not deactivate |
|                        | a virtual interrupt signaled to it by the SPMC but |
|                        | perform secure interrupt signal completion. This   |
|                        | attempt to corrupt the internal state of the SPMC  |
|                        | could lead to an unknown state and further lead to |
|                        | system crash.**                                    |
|                        | Similarly, a malicious secure endpoint could       |
|                        | deliberately not perform either interrupt          |
|                        | deactivation or interrupt completion signal. Since,|
|                        | the SPMC can only process one secure interrupt at a|
|                        | time, this could choke the system where all        |
|                        | interrupts are indefinitely masked which could     |
|                        | potentially lead to system crash or reboot.        |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not provide mitigation against  |
|                        | such threat. This is a limitation of the current   |
|                        | SPMC implementation and needs to be handled in the |
|                        | future releases.                                   |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 23                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint could leverage non-secure   |
|                        | interrupts to preempt a secure endpoint, thereby   |
|                        | attempting to render it unable to handle a secure  |
|                        | virtual interrupt targetted for it. This could lead|
|                        | to priority inversion as secure virtual interrupts |
|                        | are kept pending while non-secure interrupts are   |
|                        | handled by normal world VMs.**                     |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF5                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, SPMD                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint                                        |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC alone does not provide mitigation    |
|                        | against such threats. System integrators must take |
|                        | necessary high level design decisions that takes   |
|                        | care of interrupt prioritization. The SPMC performs|
|                        | its role of enabling SPs to specify appropriate    |
|                        | action towards non-secure interrupt with the help  |
|                        | of partition manifest based on the guidance in the |
|                        | FF-A v1.1 EAC0 specification.                      |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 24                                                 |
+========================+====================================================+
| ``Threat``             | **A secure endpoint depends on primary scheduler   |
|                        | for CPU cycles. A malicious endpoint could delay   |
|                        | the secure endpoint from being scheduled. Secure   |
|                        | interrupts, if not handled timely, could compromise|
|                        | the state of SP and SPMC, thereby rendering the    |
|                        | system unresponsive.**                             |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2, DF3, DF5                                 |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, SPMD                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint                                        |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not provide full mitigation     |
|                        | against such threats. However, based on the        |
|                        | guidance provided in the FF-A v1.1 EAC0 spec, SPMC |
|                        | provisions CPU cycles to run a secure endpoint     |
|                        | execution context in SPMC schedule mode which      |
|                        | cannot be preempted by a non-secure interrupt.     |
|                        | This reduces the dependency on primary scheduler   |
|                        | for cycle allocation. Moreover, all further        |
|                        | interrupts are masked until pending secure virtual |
|                        | interrupt on current CPU is handled. This allows SP|
|                        | execution context to make progress even upon being |
|                        | interrupted.                                       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 25                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue FF-A endpoint can use memory sharing     |
|                        | calls to exhaust SPMC resources.**                 |
|                        | For each on-going operation that involves an SP,   |
|                        | the SPMC allocates resources to track its state.   |
|                        | If the operation is never concluded, the resources |
|                        | are never freed.                                   |
|                        | In the worst scenario, multiple operations that    |
|                        | never conclude may exhaust the SPMC resources to a |
|                        | point in which renders memory sharing operations   |
|                        | impossible. This could affect other, non-harmful   |
|                        | FF-A endpoints, from legitimately using memory     |
|                        | share functionality. The intent might even be      |
|                        | to cause the SPMC to consume excessive CPU cycles, |
|                        | attempting to make it deny its service to the NWd. |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, SPMD                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state                                         |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | High (4)         | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (16)        | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC uses a statically allocated pool of  |
|                        | memory to keep track of on-going memory sharing    |
|                        | operations. After a possible attack, this could    |
|                        | fail due to insufficient memory, and return an     |
|                        | error to the caller. At this point, any other      |
|                        | endpoint that requires use of memory sharing for   |
|                        | its operation could get itself in an unusable      |
|                        | state.                                             |
|                        | Regarding CPU cycles starving threat, the SPMC     |
|                        | doesn't provide any mitigation for this, as any    |
|                        | FF-A endpoint, at the virtual FF-A instance is     |
|                        | allowed to invoke memory share/lend/donate.        |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 26                                                 |
+========================+====================================================+
| ``Threat``             | **A borrower may interfere with lender's           |
|                        | operation, if it terminates due to a fatal error   |
|                        | condition without releasing the memory             |
|                        | shared/lent.**                                     |
|                        | Such scenario may render the lender inoperable.    |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP state                                           |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (12)        | Medium(6)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not provide mitigation for such |
|                        | scenario. The FF-A endpoints must attempt to       |
|                        | relinquish memory shared/lent themselves in        |
|                        | case of failure. The memory used to track the      |
|                        | operation in the SPMC will also remain usuable.    |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 27                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue FF-A endpoint may attempt to tamper with |
|                        | the content of the memory shared/lent, whilst      |
|                        | being accessed by other FF-A endpoints.**          |
|                        | It might attempt to do so: using one of the clear  |
|                        | flags, when either retrieving or relinquishing     |
|                        | access to the memory via the respective FF-A       |
|                        | calls; or directly accessing memory without        |
|                        | respecting the synchronization protocol between    |
|                        | all involved endpoints.                            |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, FF-A endpoint                                |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP state                                           |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service, Tampering                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Low (2)          | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (6)       | Medium(6)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The first case defined in the threat, the TF-A     |
|                        | SPMC mitigates it, by ensuring a memory is cleared |
|                        | only when all borrowers have relinquished access   |
|                        | to the memory, in a scenario involving multiple    |
|                        | borrowers. Also, if the receiver is granted RO,    |
|                        | permissions, the SPMC will reject any request      |
|                        | to clear memory on behalf of the borrower, by      |
|                        | returning an error to the respective FF-A call.    |
|                        | The second case defined in the threat can't be     |
|                        | mitigated by the SPMC. It is up to the NS/S FF-A   |
|                        | endpoints to establish a robust protocol for using |
|                        | the shared memory.                                 |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 28                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue FF-A endpoint may attempt to share       |
|                        | memory that is not in its translation regime, or   |
|                        | attempt to specify attributes more permissive than |
|                        | those it possesses at a given time.**              |
|                        | Both ways could be an attempt for escalating its   |
|                        | privileges.                                        |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, FF-A endpoint                                |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP state                                           |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service, Tampering                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (12)        | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC mitigates this threat by performing  |
|                        | sanity checks to the provided memory region        |
|                        | descriptor.                                        |
|                        | For operations at the virtual FF-A instance, and   |
|                        | once the full memory descriptor is provided,       |
|                        | the SPMC validates that the memory is part of the  |
|                        | caller's translation regime. The SPMC also checks  |
|                        | that the memory attributes provided are within     |
|                        | those the owner possesses, in terms of             |
|                        | permissiveness. If more permissive attributes are  |
|                        | specified, the SPMC returns an error               |
|                        | FFA_INVALID_PARAMETERS. The permissiveness rules   |
|                        | are enforced in any call to share/lend or donate   |
|                        | the memory, and in retrieve requests.              |
|                        | Security state attributes are provided by the SPMC |
|                        | as set in the S2 translation regime, without       |
|                        | requiring the configuration of the lender.         |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 29                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue NS FF-A endpoint may attempt to share    |
|                        | memory that belongs to another system component.** |
|                        | E.g. the secure memory belonging to the monitor,   |
|                        | or the SPMC, as well as other SPs.                 |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, FF-A endpoint                                |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SP state                                           |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | NS-Endpoint, S-Endpoint                            |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service, Tampering                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (12)        | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The system integrator shall configure memory       |
|                        | ranges in the SPMC manifest, which limit the       |
|                        | memory that can be used by SPs in their address    |
|                        | space. This includes both secure and non-secure    |
|                        | memory. All non-secure memory that is not          |
|                        | assigned to SPs is used to create a page table     |
|                        | that the SPMC relates to the NWd, which is used to |
|                        | contain the memory sharing operations from the     |
|                        | NWd to SPs. I.e. if the SPMC handles a request     |
|                        | from the NWd to lend or donate memory that is not  |
|                        | mapped in the referred page table, the operation   |
|                        | will fail with FFA_ERROR. No secure memory shall   |
|                        | be mapped, thus mitigating the possibility of      |
|                        | an NWd component circumventing the sandboxing      |
|                        | enforced by the SPMC.                              |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 30                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious secure endpoint might attempt to     |
|                        | reconfigure a physical secure interrupt belonging  |
|                        | to another endpoint using the                      |
|                        | HF_INTERRUPT_RECONFIGURE interface.**              |
|                        | Through this interface, the malicious secure       |
|                        | endpoint could reroute or disable or even change   |
|                        | security state of the physical interrupt.          |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state                               |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering                                          |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | At initialization, the TF-A SPMC parses the        |
|                        | partition manifests to identify various physical   |
|                        | interrupts associated with an SP. The SPMC         |
|                        | provides mitigation against above mentioned threat |
|                        | by denying any such attempts if the interrupt does |
|                        | not belong to the caller SP.                       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 31                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious endpoint could leverage the          |
|                        | HF_INTERRUPT_RECONFIGURE interface to change the   |
|                        | security state of a physical interrupt it owns     |
|                        | without coordinating with its normal world driver  |
|                        | to register an appropriate non-secure handler. This|
|                        | could lead to preemption of an endpoint when this  |
|                        | interrupt gets triggered. Since there is no handler|
|                        | to triage this interrupt in the normal world, it   |
|                        | could render the system unresponsive.**            |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (16)        | High (16)       |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not provide mitigation against  |
|                        | against such threats. System integrators must take |
|                        | necessary high level design decisions that takes   |
|                        | care of rogue interrupts.                          |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 32                                                 |
+========================+====================================================+
| ``Threat``             | **A malicious secure endpoint may tamper with the  |
|                        | system resources allocated to it, such as memory   |
|                        | regions, interrupts, timers, etc., in an attempt to|
|                        | corrupt the internal state of the SPMC, there by   |
|                        | leading to system crash.**                         |
|                        | For example, such an endpoint can configure a      |
|                        | secure virtual interrupt to be fired after driving |
|                        | itself to an aborted state without handling the    |
|                        | virtual interrupt. This attempt to corrupt the     |
|                        | internal state of the SPMC and further lead to     |
|                        | system crash.                                      |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, Scheduling cycles            |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (9)       | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC provides mitigation against such     |
|                        | threat by freeing all resources belonging to an    |
|                        | aborted partition. Specifically, all the interrupts|
|                        | belonging to the partition are disabled as soon as |
|                        | any execution context of the partition is aborted. |
|                        | Also, any pending interrupt targeting the aborted  |
|                        | partition is deactivated as soon as it triggers.   |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 33                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue NWd FF-A endpoint could provide an RXTX  |
|                        | buffer pair from a wrong physical address space.** |
|                        | The NWd FF-A endpoint is expected to provide RXTX  |
|                        | buffers in the non-secure physical address space.  |
|                        | The SPMC maps them as non-secure memory in its S1  |
|                        | page tables.                                       |
|                        | In an attempt to attack the state of the SPMC or   |
|                        | other SPs, the NWd FF-A endpoint could provide     |
|                        | an address in the secure PAS. In this case, an     |
|                        | access to the secure memory results in a           |
|                        | synchronous data abort.                            |
|                        | In Armv9 platforms, the NWd FF-A endpoint could    |
|                        | also provide root memory or realm memory. In this  |
|                        | case an access from the SPMC would result in a     |
|                        | Granule Protection Fault.                          |
|                        | In all cases, there could be an explicit attempt   |
|                        | from the NWd FF-A endpoint to tamper with SPMC     |
|                        | execution.                                         |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state                               |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (12)      | Medium (12)     |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The non-secure memory that the SWd is expected to  |
|                        | use should be configured in the SPMC's manifest.   |
|                        | The SPMC can't validate the physical address       |
|                        | of the provided ranges. That responsibility is     |
|                        | reserved to the EL3 monitor of the system. The     |
|                        | ranges are provided by the system integrator in the|
|                        | SPMC manifest. The contents of the manifest are    |
|                        | integral due to the secure boot process.           |
|                        | In an Armv8 platform, if there is a                |
|                        | misconfiguration and any access results in a data  |
|                        | abort, the TF-A SPMC has no way to recover from    |
|                        | this. In an Armv9 platform, if there is a          |
|                        | misconfiguration or the addresses get updated in   |
|                        | runtime by using the RME system architecture       |
|                        | features, the SPMC's access originates a Granule   |
|                        | Protection Fault.                                  |
|                        | In this case, the threat is mitigated by using     |
|                        | a special function whose access is conceived for   |
|                        | possibly getting trapped and to return error.      |
|                        | The scenarios in which the SPMC is prone to such   |
|                        | attacks are:                                       |
|                        | - Indirect messaging targetting or from a VM.      |
|                        | - Memory sharing when exchanging memory regions    |
|                        | descriptors with the hypervisor/OS Kernel.         |
|                        | - FFA_PARTITION_INFO_GET via buffers.              |
|                        | In these scenarios, the SPMC is able to detect the |
|                        | fault, recover, and relinquish smoothly, returning |
|                        | error FFA_ABORTED back to the caller FF-A endpoint.|
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 34                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue NWd FF-A endpoint could attempt to       |
|                        | share/lend/donate a memory region with the wrong   |
|                        | security state attribute.**                        |
|                        | The attacker could attempt to corrupt the state of |
|                        | the SP.                                            |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF5                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC                                               |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, CPU cycles                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (12)      | Medium (12)     |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The platform owner must configure the NS/S regions |
|                        | that the secure world is allowed to use during     |
|                        | runtime in the SPMC's manifest.                    |
|                        | This configuration must be coherent with that of   |
|                        | platform's memory map, and its PAS setup.          |
|                        | The EL3 monitor can configure the PAS:             |
|                        | - In Armv8-A platforms, e.g. by leveraging the     |
|                        | TZC.                                               |
|                        | - In Armv9-A platforms, by configuring the GPT     |
|                        | following the `RME system architecture`_.          |
|                        | The SPMC doesn't allow the NWd to share/lend/donate|
|                        | NS memory outside of the ranges specified in the   |
|                        | manifest.                                          |
|                        | If the operation is a lend/donate from the NWd to  |
|                        | an SP or multiple SPs, the platform can leverage   |
|                        | the ability to change the PAS in runtime to        |
|                        | enforce the semantics of the lend/donate operation.|
|                        | The SPMC implementation, for the FVP platform      |
|                        | leverages the RME architecture to dynamically      |
|                        | change the PAS from NS to S. In case the update    |
|                        | fails because the region is not on NS PAS, the     |
|                        | SPMC returns error back to the NWd caller.         |
|                        | For the share operation, the SPMC will check that  |
|                        | is within the NS ranges from the manifest, but     |
|                        | won't attest that the PAS is correctly set by      |
|                        | EL3 monitor. The impact of a GPF in a partition    |
|                        | depends on its EL:                                 |
|                        | * S-EL1: the SP should handle the GPF, recover     |
|                        | and relinquish access to the memory.               |
|                        | * S-EL0: the GPF would trap onto SPMC, which sets  |
|                        | the SP in an aborted state.                        |
|                        | Platform owners are encouraged to implement a      |
|                        | similar interface for the SPMC to leverage,        |
|                        | equivalent to that detailed for the FVP platform.  |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 35                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue SP could try use IPIs to steal cycles    |
|                        | from other SPs.**                                  |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1,                                               |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, FF-A Endpoint                                |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, CPU cycles                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | High (4)         | High (4)        |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (12)      | Medium (12)     |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | When an IPI is received, if the target vCPU is     |
|                        | in the RUNNING state, since the vCPU               |
|                        | already has cycles it can use to handle the        |
|                        | interrupt, the virtual interrupt is injected       |
|                        | straight away.                                     |
|                        | In the case the target vCPU is in the              |
|                        | PREEMPTED/BLOCKED state, the IPI virtual interrupt |
|                        | is simply pended. In both cases, it is implicit    |
|                        | with the states that the vCPU will be resumed      |
|                        | eventually. The virtual interrupt is injected and  |
|                        | handled then.                                      |
|                        | If the vCPU is in the WAITING state, it needs the  |
|                        | scheduler to provide CPU cycles to it. To mitigate |
|                        | the threat described above, the SPMC sends the SRI |
|                        | SGI to inform the Normal World that the target     |
|                        | vCPU has a pending IPI. It can then schedule time  |
|                        | for the vCPU to handle the IPI virtual interrupt.  |
|                        | This means the SP is unable to take cycles without |
|                        | the knowledge of the Normal World Scheduler.       |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 36                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue SP could try use IPIs to interrupt       |
|                        | another SP.**                                      |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1                                                |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, FF-A Endpoint                                |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, SP state, CPU cycles                   |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Denial of Service                                  |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (3)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | Low (2)          | Low (2)         |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | Medium (6)       | Medium (6)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | This is not possible. The ABI only allows an SP to |
|                        | specify the target vCPU ID. Hafnium then directs   |
|                        | the IPI to the vCPU with that ID, that belongs to  |
|                        | the SP currently running on the source CPU. As     |
|                        | such it is impossible for an SP to target another  |
|                        | SP for an IPI.                                     |
+------------------------+----------------------------------------------------+

+------------------------+----------------------------------------------------+
| ID                     | 37                                                 |
+========================+====================================================+
| ``Threat``             | **A rogue Secure Partition, that subscribes to     |
|                        | CPU_OFF power management message, could hog CPU    |
|                        | cycles or deny the power management operation when |
|                        | the SPMC resumes it to process PSCI CPU_OFF event, |
|                        | thereby compromising the state of SPMC and         |
|                        | rendering the system unresponsive.**               |
+------------------------+----------------------------------------------------+
| ``Diagram Elements``   | DF1, DF2                                           |
+------------------------+----------------------------------------------------+
| ``Affected TF-A        | SPMC, SPMD                                         |
| Components``           |                                                    |
+------------------------+----------------------------------------------------+
| ``Assets``             | SPMC state, CPU cycles                             |
+------------------------+----------------------------------------------------+
| ``Threat Agent``       | S-Endpoint                                         |
+------------------------+----------------------------------------------------+
| ``Threat Type``        | Tampering, Denial of Service                       |
+------------------------+------------------+-----------------+---------------+
| ``Application``        |   ``Server``     |   ``Mobile``    |               |
+------------------------+------------------+-----------------+---------------+
| ``Impact``             | Medium (4)       | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Likelihood``         | High (4)         | Medium (3)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Total Risk Rating``  | High (16)        | Medium (9)      |               |
+------------------------+------------------+-----------------+---------------+
| ``Mitigations``        | The TF-A SPMC does not provide full mitigation     |
|                        | against such threats in order to keep the current  |
|                        | implementation simple. When an SP sends DENIED     |
|                        | status to SPMC in response to power management     |
|                        | message, SPMC forwards the status to SPMD and      |
|                        | panics, thereby causing a hard reset as the        |
|                        | integrity of Secure World is no more guaranteed.   |
+------------------------+----------------------------------------------------+

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*

.. _Arm Firmware Framework for Arm A-profile: https://developer.arm.com/docs/den0077/latest
.. _Generic TF-A threat model: https://trustedfirmware-a.readthedocs.io/en/latest/threat_model/threat_model.html
.. _FF-A ACS: https://github.com/ARM-software/ff-a-acs/releases
.. _RME system architecture: https://developer.arm.com/documentation/den0129/latest/
