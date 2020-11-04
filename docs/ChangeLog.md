# Change log

## v2.4

This is the first drop to implement the TrustZone secure side S-EL2 firmware
(SPM Core component) complying with FF-A v1.0.
It is a companion to the broader TF-A v2.4 release.
The normal world Hypervisor is maintained functional along with the
Hafnium CI test suite.

* FF-A v1.0 Setup and discovery interface
    * Hypervisor implementation re-used and extended to the SPMC and SPs.
    * Added partition info get ABI and appropriate properties response depending
      on partition capabilities (PVM, Secondary VM or Secure Partitions).
    * FF-A device-tree manifest parsing.
    * FF-A partitions can declare memory/device regions, and RX/TX buffers that
      the SPMC sets up in the SP EL1&0 Stage-2 translation regime at boot time.
    * FF-A IDs normal and secure world split ranges.
    * The SPMC maps the Hypervisor (or OS kernel) RX/TX buffers as non-secure
      buffers in its EL2 Stage-1 translation regime on FFA_RXTX_MAP ABI
      invocation from the non-secure physical FF-A instance.
* FF-A v1.0 Direct message interface
    * Added implementation for the normal world Hypervisor and test cases.
    * Implementation extended to the SPMC and SPs.
    * Direct message requests emitted from the PVM to a Secondary VM or a
      Secure Partition (or OS Kernel to a Secure Partition). Direct message
      responses emitted from Secondary VMs and Secure Partitions to the PVM.
    * The secure world represents the "other world" (normal world Hypervisor
      or OS kernel) vCPUs in an abstract "Hypervisor VM".
* FF-A v1.0 memory sharing
    * Hypervisor implementation re-used and extended to the SPMC and SPs.
    * A NS buffer can be shared/lent/donated by a VM to a SP (or OS Kernel
      to a SP).
    * The secure world configures Stage-1 NS IPA output to access the NS PA
      space.
    * The secure world represents the "other world" (normal world Hypervisor
      or OS kernel) memory pages in an abstract "Hypervisor VM" and tracks
      memory sharing permissions from incoming normal world requests.
* Secure world enablement
    * Secure Partitions booted in sequence on their primary execution context,
      according to the boot order field in their partition manifest.
      This happens during the secure boot process before the normal world
      actually runs.
    * The SPMC implements the logic to receive FF-A messages through the EL3
      SPMD, process them, and either return to the SPMD (and normal world) or
      resume a Secure Partition.
    * Extract NS bit from HPFAR_EL2 on Stage-2 page fault.
    * Prevent setup of LOR regions in SWd.
    * Avoid direct PSCI calls down to EL3.
* Platforms
    * Added Arm FVP secure Hafnium build support.
    * Added Arm TC0 "Total Compute" secure Hafnium build support.
* Other improvements
    * Re-hosting to trustedfirmware.org
    * busy_secondary timer increased to improve CI stability.
    * Removed legacy Hypervisor calls.
    * Fix CPTR_EL2 TTA bit position.
    * Report FAR_EL2 on injecting EL1 exception.
* Known limitations:
    * Not all fields of the FF-A manifest are actually processed by the Hafnium
      device-tree parser.
    * SP to SP communication not supported.
    * SP to SP memory sharing not supported.
    * S-EL1 and SIMD contexts shall be saved/restored by EL3.
    * Multi-endpoint memory sharing not supported.
    * Interrupt management limited to trapping physical interrupts to
      the first S-EL1 SP. Physical interrupt trapping at S-EL2 planned as
      next release improvement.
    * Validation mostly performed using first SP Execution Context (vCPU0). More
      comprehensive multicore enablement planned as next release improvement.
