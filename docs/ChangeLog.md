# Change log

## v2.6
#### Highlights
* FF-A Setup and discovery
    * FF-A build time version updated to v1.1.
    * Managed exit and notifications feature support enabled in SP manifests.
    * Updated FFA_FEATURES to permit discovery of managed exit, schedule receiver,
      and notification pending interrupt IDs.
    * FFA_PARTITION_INFO_GET updated to permit managed exit and notification
      support discovery.
    * FFA_SPM_ID_GET added to permit discovering the SPMC endpoint ID (or the
      SPMD ID at the secure physical FF-A instance).
    * FFA_RXTX_UNMAP implementation added.
* FF-A v1.1 notifications
    * Added ABIs permitting VM (or OS kernel) to SP, and SP to SP asynchronous
      signaling.
    * Added generation of scheduler receiver (NS physical) and notification
      pending (secure virtual) interrupts.
    * The schedule receiver interrupt is donated from the secure world SGI
      interrupt ID range.
* FF-A v1.1 interrupt handling
    * Added a GIC driver at S-EL2 permitting to trap and handle non-secure and
      secure interrupts while the secure world runs.
    * Added forwarding and handling of a secure interrupt while the normal world
      runs.
    * Added secure interrupt forwarding to the secure partition that had the
      interrupt registered in its partition manifest.
    * The interrupt deactivation happens through the Hafnium para-virtualized
      interrupt controller interface.
    * vCPU states, run time models and SP scheduling model are revisited as per
      FF-A v1.1 Beta0 specification (see 'Known limitations' section below).
* S-EL0 partitions support
    * Added support for VHE architecture extension in the secure world (through
      a build option).
    * A partition bootstraps as an S-EL0 partition based on the exception-level
      field in the FF-A manifest.
    * It permits the implementation of applications on top of Hafnium without
      relying on an operating system at S-EL1.
    * It leverages the EL2&0 Stage-1 translation regime. Apps use FF-A
      ABIs through the SVC conduit.
    * Added FF-A v1.1 FFA_MEM_PERM_GET/SET ABIs permitting run-time update of
      memory region permissions.
    * It supersedes the existing S-EL1 shim architecture (without removing its
      support).
    * S-EL1 SP, S-EL0 SP or former S-EL0 SP+shim can all co-exist in the same
      system.
* SVE
    * Support for saving/restoring the SVE live state such that S-EL2/Hafnium
      preserves the normal world state on world switches.
    * Secure partitions are permitted to use FP/SIMD while normal world uses
      SVE/SIMD/FP on the same core.
    * The SVE NS live state comprises FPCR/FPSR/FFR/p[16]/Z[32] registers.
* LLVM/Clang 12
    * The toolchain stored in prebuilts submodule is updated to LLVM 12.0.5.
    * Build/static analyzer fixes done in the top and third party projects.
    * Linux sources (used by the test infrastructure) are updated to 5.4.148.
      The linux test kernel module build is updated to only depend on LLVM
      toolchain.
* Hafnium CI improvements
    * Added two configurations permitting Hafnium testing in the secure world.
    * First configuration launches both the Hypervisor in the normal world
      and the SPMC in the secure world. This permits thorough FF-A ABI testing
      among normal and secure world endpoints.
    * The second configuration launches the SPMC alone for component testing
      or SP to SP ABI testing.
    * Hafnium CI Qemu version updated to v6.0.0 (implements VHE and FEAT_SEL2
      extensions).
* FF-A compliance fixes
    * Added checks for valid memory permissions values in manifest memory and
      device regions declarations.
    * FFA_FEATURES fixed to state indirect messages are not supported by
      the SPMC.
    * Limit an SP to emit a direct request to another SP only.
    * Memory sharing: fixed input validation and return values.
    * FFA_RXTX_MAP fixed returned error codes.
    * FFA_MSG_WAIT input parameters check hardened.

#### Known limitations:
* S-EL0 partitions/VHE: the feature is in an experimental stage and not all use
  cases have been implemented or tested. Normal world to SP and SP to SP memory
  sharing is not tested. Interrupt handling is not tested.
* The current implementation does not support handling a secure interrupt that
  is triggered while currently handling a secure interrupt. This restricts to
  scenarios described in Table 8.13 and Table 8.14 of the FF-A v1.1 Beta0
  specification. Priority Mask Register is not saved/restored during context
  switching while handling secure interrupt.
* Hafnium CI: scenarios involving the Hypervisor are left as test harness
  purposes only, not meant for production use cases.

## v2.5
#### Highlights
* BTI/Pointer authentication support
    * Add branch protection build option for FEAT_PAuth and FEAT_BTI to the
      clang command line. This only affects the S-EL2 image.
    * Enable pointer authentication by supplying a platform defined pseudo
      random key.
    * Enable BTI by setting the guarded page bit in MMU descriptors for
      executable pages.
* SMMUv3.2 S-EL2 support
    * Add support for SMMUv3 driver to perform stage 2 translation, protection
      and isolation of upstream peripheral device's DMA transactions.
* FF-A v1.0 Non-secure interrupt handling
    * Trap physical interrupts to S-EL2 when running a SP.
    * Handle non secure interrupts that occur while an SP is executing,
      performing managed exit if supported.
    * Add basic support for the GICv3 interrupt controller for the AArch64
      platform.
* FF-A power management support at boot time
    * Provide platform-independent power management implementations for the
      Hypervisor and SPMC.
    * Implement the FFA_SECONDARY_EP_REGISTER interface for an MP SP or SPMC
      to register the secondary core cold boot entry point for each of their
      execution contexts.
    * Introduce a generic "SPMD handler" to process the power management events
      that may be conveyed from SPMD to SPMC, such as core off.
* FF-A Direct message interfaces
    * Introduce SP to SP direct messaging.
    * Fix bug in the MP SP to UP SP direct response handling.
* FF-A Memory sharing interfaces
    * Introduce SP to SP memory sharing.
    * When a sender of a memory management operation reclaims memory, set the
      memory regions permissions back to it's original configuration.
    * Require default permissions to be supplied to the function
      'ffa_memory_permissions_to_mode', so in the case where no permissions are
      specified for a memory operation, the data and instruction permissions can
      be set to the default.
    * Encode Bit[63] of the memory region handle according to if the handle is
      allocated by the Hypervisor or SPMC.
* FF-A v1.0 spec compliance
    * Return INVALID_PARAMETER error code instead of NOT_SUPPORTED for direct
      messaging interfaces when an invalid sender or receiver id is given.
    * Check that reserved parameter registers are 0 when invoking direct
      messaging ABI interfaces.
    * For SMC32 compliant direct message interfaces, only copy 32-bits
      parameter values.
    * Change the FF-A error codes to 32-bit to match the FF-A specification.
    * Fix consistency with maintaining the calling convention bit of the
      func id between the ffa_handler and the FFA_FEATURES function.
* Remove primary VM dependencies in the SPMC
    * Treat normal world as primary VM when running in the secure world.
    * Create an SPMC boot flow.
* Hafnium CI
    * Enable Hafnium CI to include tests for Hafnium SPMC.
    * Add basic exception handler to service VM's.
* SIMD support
    * Add saving/restoring of other world FP/NEON/SIMD state when entering and
      exiting the SPMC.
* SPMC early boot cache fix
    * Import data cache clean and invalidation helpers from TF-A project and
      provide an arch module for cache operations.
    * Invalidate the SPMC image in the data cache at boot time to prevent
      potential access to stale cache entries left by earlier boots stages.
* Misc and bug fixes
    * Complete vCPU state save prior to normal world exit.
    * Update S-EL2 Stage-1 page table shareability from outer to inner.
    * Add PL011 UART initialization code to set the IDRD and FBRD registers
      according to the UART clock and baud rate specified at build time.
    * License script checker fixes.

#### Known limitations:
* Secure interrupts not supported.
* FF-A indirect message interface not supported in the secure world.
* Only supporting models of MultiProcessor SP (vCPUs pinned to physical
  CPUs) or UniProcessor SP (single vCPU).
* The first secure partition booted must be a MP SP.
* FFA_RXTX_UNMAP not implemented.
* Use of an alternate caller provided buffer from RX/TX buffers for memory
  sharing operations is not implemented.
* A memory retrieve request to SPMC does not support the caller endpoint to
  provide the range of IPA addresses to map the region to.

## v2.4

This is the first drop to implement the TrustZone secure side S-EL2 firmware
(SPM Core component) complying with FF-A v1.0.
It is a companion to the broader TF-A v2.4 release.
The normal world Hypervisor is maintained functional along with the
Hafnium CI test suite.

#### Highlights
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
#### Known limitations:
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
