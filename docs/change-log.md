# Change Log

## v2.12
### Highlights

* FF-A v1.2 (continued adoption):
    * Restrict use of the `FFA_VERSION` ABI: FF-A endpoint version is locked from the first
      FF-A ABI call handled in the SPMC.
    * `FFA_MSG_WAIT` ABI update:
        * Transfer the ownership of RX buffer from consumer to producer.
        * Bypass the mentioned transfer of ownership via dedicated flag.
    * Support for VM availibility messages:
        * Subscription through the FF-A manifest.
        * Discovery through `FFA_PARTITION_INFO_GET` only at the NS FF-A instance.
        * Relay the framework message to the subscribed partition.

* Runtime support:
    * `FFA_CONSOLE_LOG` ABI:
       * SPMC adds the string `[<SP ID> <vCPU ID>]` to line logs from SPs.
       * Console log for each partition is tracked per vCPU, to avoid corrupting the buffer
         from concurrent logging from the same partition.
    * Exceptions related to synchronous tag faults in S-EL2 are now logged.
    * FF-A memory management:
        * Support of the SMC64 ABI version of all FF-A memory management interfaces.
        * Handle GPF exception caused by accessing non-secure RX/TX buffers in the handling
          of FF-A memory management ABIs.
        * Support for sharing and lending device memory.
    * Allocate the boot parameters for Hafnium's initialisation functions in the memory
      pool.
    * Paravirtualized interface for sending IPI (`HF_INTERRUPT_SEND_IPI`).
        * IPI injected straight away to target vCPUs in the running state.
        * Sending `SRI` interrupt to the NWd, when the target vCPU is in the waiting state.
        * Report the partitions and vCPUs which require CPU cycles to handle IPI through
          `FFA_NOTIFICATION_INFO_GET`.
        * If target vCPU is in blocked/preempted state, then pend/queue the virtual
          interrupt.
    * Secure Interrupt handling:
        * Support for queueing secure interrupts.
        * Support for S-EL1 UP SPs to handle interrupts.
        * Support interrupts sent during runtime model for intialisation (`RTM_INIT`).
    * Always eret `FFA_RUN` to the target SP, regardless of if it has pending messages,
      secure interrupts or notifications.

* Hardware architecture support:
    * Architectural physical timer emulation for SPs.
    * TC platform enabled branch protection feature.
    * Support for platforms with non-linear GIC redistributor frames.
    * Enabled S-EL0 partitions Pointer Authentication feature.

* Tests, scripts, testing framework and build:
    * Improved readability of the error messages for failed assertions.
    * Enabled the build flags '-Wextra' and '-Wsign-compare'.
    * Definition of assertion helpers to check content of strings.
    * Using enum types for the FF-A ABIs, FF-A errors, and test SP service commands.
    * Toolchain upgrade to clang-18.
    * Improved performance of `clang-tidy`.
    * Always expand the `assert` macro, to make sure arguments are type checked even
      when `ENABLE_ASSERTIONS` is not enabled.
    * Adopted `FFA_CONSOLE_LOG` ABI on `dlog` instances from SPs.
    * Restricted the functions defined with `SERVICE_SETUP` macros to run on the primary
      core.
    * Support for using the generic timer in the test partitions.
    * Support for using a watchdog timer from NWd test VMs.
    * Added new system setup, loading S-EL1 UP partitions on top of SPMC.

* Bug fixes:
    * Incorrect calculation of number of FF-A boot information descriptors.
    * FF-A memory management:
        * Drop unnecessary check to instruction permissions in the handling of
         `FFA_MEM_RELINQUISH`.
        * Sender with no Write access to a given memory region is prevented from using
          the clear/zero memory flags, in the descriptor to `FFA_MEM_LEND`, `FFA_MEM_SHARE`
          or `FFA_MEM_DONATE`.
        * Checks to the `impdef` field in the FF-A memory access descriptor done in accordance
          to FF-A version.
        * Consider the memory region descriptor format according to FF-A version, when
          processing an hypervisor retrieve request.
    * Platform build options:
        * Attest the option `enable_mte` can only have legal values 0 or 1, to enable
          and disable MTE feature use, respectively.
        * Attest the options `gic_version` and `gic_enable_espi` are configured with
          correct values, according to what is supported in Hafnium.
        * Attest the option `branch_protection` can only be configured with values
          `standard`, `pac-ret`, `pac-ret+leaf` and `bti`.
    * FF-A Notifications:
        * Set framework notifications only when recipient supports notifications.
        * Delay SRI flag can only be used on `FFA_NOTIFICATION_SET` from SPs. Return
          `FFA_ERROR(FFA_INVALID_PARAMETERS)` in invocations from the NWd that use it.
        * Allow for a caller to invoke`FFA_NOTIFICATION_GET` specifying a vCPU ID different
          than the calling vCPU.
    * `FFA_FEATURES` ABI:
        * Reports `FFA_YIELD` only to SPs.
        * Reports `ME` and `NPI` VI Id to S-EL1 partitions only.
        * Reports `FFA_SECONDARY_EP_REGISTER` to MP partitions only.
        * Reports `FFA_MEM_PERM_SET/GET` to S-EL0 partitions only.
    * The `FFA_PARTITION_INFO_GET(_REGS)` ABI reports the support of indirect message and direct
      message request/response 2, considering the version of the caller.
    * Prevent secure interrupt from preempting an SP in `SPMC` scheduled mode.
    * Ensure the FF-A error codes are be 32-bit unsigned values.
    * The error return for `FFA_FEATURES` ABI is restricted to `FFA_ERROR(FFA_NOT_SUPPORTED)`
      according to the FF-A v1.2 specification.
    * Ensure that accesses to `GICD_CTLR` register are complete by checking the state of
      the bit RWP.
    * Add check that manifest declared memory regions shouldn't overlap with SPMC address
      space.
    * First vCPU to boot ever from any SP was booting with the wrong vCPU state, fixed to
      `VCPU_STATE_RUNNING`.
    * Correctly define stack for the test SPs.
    * Report error when there are too many UUIDs defined in the partition's FF-A manifest.
    * Fix out of tree buid: use of `OUT` make argument such that the output directory can point
      to another location other than out/project/reference.
    * Memory regions specified with offset relative to partition's image position, rather than
      partition package load-address.
    * The SPMC enables a physical interrupt when the SP enables the respective virtual interrupt,
      instead of enabling by default during load of owner SP.

* Miscellaneous:
    * Improved `dlog` functions with compile time type checking to the arguments of
      logged strings.
    * Reduced complexity of utility functions defined in `std.h`.
    * The documentation of FF-A manifest bindings now refer to TF-A documentation as the common
      resource for all reference SPMC implementations.
    * Simplified the code for handling the preemption of `FFA_MSG_WAIT`/`FFA_MSG_SEND_DIRECT_RESP`
      due to a pending interrupt.
    * Dropped legacy code/tests:
        * Legacy hypervisor tests for timer support in NWd VMs.
        * Legacy hypervisor interface `HF_INTERRUPT_INJECT` and respective tests.
        * Legacy hypervisor waiting list concept.
        * The linux kernel tests in the Hafnium tests scripts. Hafnium driver code supports the
          hypervisor runtime model not the SPMC.
        * The linux kernel and hafnium driver submodules.
        * Legacy hypervisor `FFA_RUN` ABI tests.
    * Refactored the code enforcing the `boot-order` according to FF-A boot protocol to use
      `list.h` header.
    * Refactored the UUID packing/unpacking functions.
    * Dropped the SRI state tracking within the SPMC, to simplify notifications code.

## v2.11
### Highlights

* FF-A v1.2 (continued adoption):
    * Direct messaging:
        * New ABIs `FFA_MSG_SEND_DIRECT_REQ2` and `FFA_MSG_SEND_DIRECT_RESP2`.
        * Support extended register set and use of service UUID.
    * Memory management:
        * ABIs support the impdef field in memory access descriptor.
        * Lend device memory from an SP to another SP, and from a VM to an SP.
    * Setup and discovery:
        * Support multiple UUIDs per SP, both in manifest parsing and
          `FFA_PARTITION_INFO_GET`.
        * The `FFA_FEATURES` ABI reports RX/TX buffer max size.
    * Support extended set of registers with `FFA_CONSOLE_LOG` for v1.2 SPs.

* Runtime support:
    * Trap SP access to AMU counters.
    * SIMD context:
	* Refactored Advanced SIMD/SVE save and restore operations.
        * Introduce context save and restore of SME registers.
        * Leverage the SMCCC SVE hint bit mask.
        * Trap SP access to SVE/SME registers.
    * Realm Management Extension support:
        * On `FFA_MEM_DONATE` or `FFA_MEM_LEND` from VM/OS Kernel to SPs, change the physical
          address space of the memory regions from non-secure to secure.
        * On `FFA_MEM_RECLAIM`, if memory's address space was changed from non-secure to secure
          address space, revert physical address space change (from secure to non-secure).
        * The SPMC can handle a Granule Protection Fault: exception handler refactored
          to trap the new `memcpy_trapped` function, which returns error if copy failed due to GPF.
        * FFA_PARTITION_INFO_GET and FFA_MSG_SEND2 interfaces return FFA_ERROR(FFA_ABORTED) in case
          of hitting a Granule Protection Fault.
    * SMMUv3:
        * Support for static DMA isolation of upstream devices.
        * Access from DMA capable devices are only permitted to specific memory regions
          via dedicated DMA properties in the memory region node of an partition manifest.
    * SPMC saves and restores the NS-EL1 system registers context, to help reduce memory from
      EL3 monitor.
    * GICv3 driver to support two security states for interrupts.

* Hardware architecture support:
    * New platform build for RD fremont.
    * TC platform remapped the UART devices.

* Tests, scripts and testing framework:
    * TF-A prebuilt image used in Hafnium tests updated to support v1.2 interfaces.
    * S-EL0 partitions bumped to FF-A v1.2 version in general functionality tests.
    * The `SERVICE_SELECT_MP` macro was added to allow for tests to target a different vCPU
      than the primary vCPU.
    * Various new tests added to cover the newly added functionalities.

* Bug fixes:
    * FF-A memory management:
        * `FFA_MEM_RELINQUISH` returns `FFA_ERROR(FFA_DENIED)`, if clear memory flag is used
          when borrower's permission is RO.
        * `FFA_MEM_RETRIEVE_REQ` returns `FFA_ERROR(FFA_DENIED)` if sender ID is not correct in
          memory region descriptor.
        * Hypervisor retrieve request updated to support FF-A v1.2 descriptors and avoid
          conflicting checks with normal retrieve requests from FF-A endpoints.
        * `FFA_MEM_RETRIEVE_REQ` returns `FFA_ERROR(FFA_INVALID_PARAMETERS)` if receiver count
          is zero in memory region descriptor.
    * Interrupt handling:
        * Secure interrupt implicit completion flag reset in the runtime model for `FFA_RUN`.
        * Intercept `FFA_MSG_SEND_DIRECT_RESP/FFA_MSG_SEND_DIRECT_RESP2` and `FFA_MSG_WAIT` if SP
          relinquishes CPU cycles with pending secure interrupts.
        * Ignore spurious interrupt 1023 when SP is executing.
        * Unwind call chain when intercepting a direct response, to avoid SPs crashing.
    * Check that platform exists before building.
    * `FFA_FEATURES` interface:
        * SPMC returns `FFA_ERROR(FFA_NOT_SUPPORTED)` if func ID is `FFA_EL3_INTR_HANDLE`, and
          call is from hyperviosr/OS kernel.
        * SPMC returns `FFA_ERROR(FFA_NOT_SUPPORTED)` if feature ID is `SRI`, and call is from SP.
        * SPMC returns `FFA_ERROR(FFA_NOT_SUPPORTED)` if feature ID is `NPI` or `ME`, and call is
          from Hypervisor/OS Kernel.
    * FF-A notifications:
        * Return error code `FFA_INVALID_PARAMETERS` when provided invalid partition IDs
          in `FFA_NOTIFICATION_BITMAP_CREATE/DESTROY` and `FFA_NOTIFICATION_BIND/UNBIND`.
        * Return error `FFA_INVALID_PARAMETERS` to `FFA_NOTIFICATION_SET` if flags that
          Must Be Zero are not.
        * The vCPU argument must be zero in `FFA_NOTIFICATION_SET` for global notifications,
          else return error `FFA_INVALID_PARAMETERS`.
    * FF-A Indirect messaging:
        * Fix the checks to messages offset and total size.
        * Validate that SPMC has mapped the hypervisor/OS Kernel RX/TX buffers before
          accessing the buffers.
    * The handling of `FFA_MSG_WAIT` shall not change the SPMC's internal state of the
      RX buffer.
    * The interfaces `FFA_MEM_PERM_SET/GET` return error `FFA_DENIED` if used after
      SP's initializing.
    * The `kokoro/test_spmc.sh` terminates when hitting a failure for runs that are not
      collecting coverage data.
    * Device memory regions are mapped with attributes nGnRnE.

* Misc:
    * Building multiple targets with a single command with PLATFORM variable, providing
      multiple targets separated by ','.
    * Dropped the clang toolchain from the 'prebuilts' submodule to save repository space.
    * Dropped implementation of `HF_INTERRUPT_INJECT` out of SPMC implementation, as it was
      designed for Hypervisor and has no use in the SPMC.
    * Code static checks were separated into a dedicated script.
    * The interfaces `FFA_RXTX_MAP` and `FFA_RXTX_UNMAP` are restricted to NS memory provided
      in the SPMC manifest.
    * Improved handling of device region nodes in SP manifest:
        * The ranges specified were restricted to those specified in the designated nodes of
          the SPMC manifest.
        * Check overlaps with other memory regions in the system, such as partitions address
          space.
    * Avoid tracking the sender ID and descriptor size for memory management ABIs, in
      Hafnium's mailbox internal structures.
    * Helpers to log the names of FF-A ABIs and FF-A error codes.
    * Increase timeout for tests in `kokoro/test_spmc.sh` to cater for CI speed.
    * Use bitfield structures for permissions and attributes from the FF-A memory access
      descriptors.

## v2.10
### Highlights

* FF-A v1.2 (continued adoption):
    * `FFA_YIELD` interface:
        * Allow to be invoked while endpoint's partition runtime model is
          either direct message request or secure interrupt handling.
        * Allow an endpoint to specify an optional timeout such that it can be
          rescheduled after appropriate time to avoid busy wait.
    * Handle the `FFA_ERROR` interface at the SPs initialisation runtime model
      to put the SP in an aborted state.
    * Support for Logical Secure Partitions at EL3, managed by the SPMD:
        * Direct messaging request from LSPs to SPs at the virtual FF-A instance.
        * Discovery of LSPs via `FFA_PARTITION_INFO_GET(_REGS)` interfaces.
    * Support flag to bypass multiple borrower checks as part of `FFA_MEM_RETRIEVE_REQ`
      handling.
    * Memory region nodes support addresses relative to partition's load address.
* Hardware architecture support:
    * Fix to SMCCC use on Hafnium, to support use of extended register set as per
      SMCCCv1.2 for FF-A v1.2 and above.
    * GICv3: Enable platforms to leverage Shared Peripheral Interrupts extended ranges.
    * New paravirtualized interfaces to reconfigure a physical interrupt at runtime:
      target CPU, disabling/enabling the secure interrupt, and changing interrupt's
      security state.
    * Leverage support of secure and non-secure set of page tables for SMMUv3 streams.
    * Platform description of secure and non-secure memory is mandatory in the  SPMC
      manifest.
    * Use security state information in the S2 page tables to invalidate SP's TLB.
* Tests, scripts and testing framework:
    * Test framework improved to add tests into the SP's intialisation, via means of
      a helper macro.
    * Removed duplicated set of tests that were used to enable support of EL0
      partitions.
    * Hypervisor build refactored to track the state of memory sharing operations.
    * Few memory sharing related tests to run on EL3 SPMC, and serve as an indicator
      about feature parity.
    * Added ability to perform test coverage analysis, via Hafnium's testing scripts.
    * Increased test coverage of memory sharing functionality.
* Bug fixes:
    * Various fixes to memory sharing functionality:
        * Clear memory operations retrieve security state from S2 translation
          attributes.
        * Validation to page count field in the composite memory descriptor.
        * No overlapping of memory constituents.
        * Restrict SP from doing lend/share/donate targeting a normal world borrower.
        * Processing of instruction permissions specified in the lend/share/donate
          and by the borrower in the memory retrieve operation.
        * Use the NS bit in the `FFA_MEM_RETRIEVE_RESP` from SPMC to SP.
    * Force uniqueness of boot order field in the partition's manifest.
    * Added `FFA_RUN` interface restriction towards vCPU cores migration.
    * Refactor use of locked vCPU structures in few identified scenarios, that
      were prone to creating deadlocks.
    * Fixed the version compatibility rules in handling of the `FFA_VERSION`
      interface.
* Misc:
    * Migration of Hafnium documentation as the reference Secure Partition Manager
      into its own pages, leveraging the sphinx documentation framework.
    * Free resources allocated to SP if it gets to an aborted state, including
      disabling any physical interrupts that might trigger.
    * Deprecation of legacy hypervisor calls `HF_MAILBOX_*_GET`.
    * Simplified code path in the handling of secure interrupts.
    * Added build option to specify build target, which allows for faster builds,
      e.g. `make PLATFORM=secure_aem_v8a_fvp_vhe`.

## v2.9
### Highlights

* FF-A v1.2 (early adoption)
    * Implemented `FFA_PARTITION_INFO_GET_REGS` ABI permitting discovery of
      secure partitions by the use of general purpose registers instead of RX/TX
      buffers.
    * `FFA_CONSOLE_LOG` ABI support is improved from earlier release. It permits
      handling multiple characters passed through general purpose registers.
      The intent is to deprecate the legacy `HF_DEBUG_LOG` hypercall in a next
      release.
    * Introduced `FFA_EL3_INTR_HANDLE` ABI permitting the delegation of Group0
      physical secure interrupt handling to EL3. A G0 interrupt triggered while
      an SP is running traps to S-EL2 and is routed to the SPMD by the use of
      this ABI. Conversely, a G0 interrupt triggered while the normal world runs
      traps to EL3.
* FF-A v1.1 interrupt handling
    * Added support for secure interrupt signalling to S-EL0 partitions.
    * Increased the maximum number of virtual interrupts supported by an SP to a
      platform defined value (default 1024). This lifts a limitation in which
      SPs were allowed to declare only the first 64 physical interrupt IDs.
    * Added the impdef 'other-s-interrupts-action' field to SP manifests
      specifying the action to be taken (queued or signaled) in response to a
      secure interrupt targetted to an SP that is not the currently running SP.
    * For S-EL1 SP vCPUs, enable the notification pending and managed exit
      virtual interrupts if requested in the manifest.
      For S-EL0 SP vCPUs, enable virtual interrupts IDs matching the secure
      physical interrupt IDs declared in device regions.
    * Allow a physical interrupt declared in a SP manifest device region to be
      routed to any PE specified by its MPIDR. Introduce the 'interrupts-target'
      manifest field for this purpose.
* FF-A v1.1 memory sharing
    * Implemented changes to memory sharing structures to support FF-A backwards
      compatibility updates in the specification. The SPMC implementation caters
      for the case of existing FF-A v1.0 endpoints on top of the FF-A v1.1 SPMC.
      The latter performs the necessary conversions in the memory sharing
      structures.
    * Implemented capability to share/lend/donate memory to multiple borrowers
      including VMs or SPs.
    * Fragmented memory sharing is supported between normal world and secure
      world endpoints.
* FF-A v1.1 power management
    * Added the impdef 'power-management-messages' field to SP manifests
      specifying the type of power management events relayed to the SPMC.
    * Removed the limitation in which the first SP must be a MP SP.
      The configuration where all deployed SPs are S-EL0 SPs is now supported.
* FF-A v1.1 Indirect messaging
    * Updated mailbox internal state structures to align with RX/TX buffer
      synchronization rules (buffer state and ownership transfer).
* Misc and bug fixes
    * Introduced SPMC manifest memory region nodes specifying the system address
      ranges for secure and non-secure memory. This permits further hardening in
      which the SPMC needs to know the security state of a memory range. This
      helps boot time validation of SP manifests, and run-time checks in the
      memory sharing protocol.
    * SP manifest memory regions validation is hardened such that one SP cannot
      declare a memory region overlapping another SP's memory region.
    * Drop dynamic allocation of memory region base address. The option for
      declaring a memory region without its base address (and let the SPMC
      choose it) is removed.
    * Fixed handling of FEAT_LPA/FEAT_LPA2.
    * SMMUv3: fix SIDSIZE field usage.
    * GIC: fixed interrupt type configuration (edge/level).
* CI and test infrastructure
    * Migration to LLVM/clang 15.0.6
    * Removal of non-VHE configurations. Keep only configurations assuming
      Armv8.1 Virtualization Host Extensions is implemented. This implies
      HCR_EL2.E2H is always set. This change is transparent for the end user as
      configurations supported with VHE enabled are a superset of legacy non-VHE
      configurations.
    * EL3 SPMC: added test configurations to permit testing TF-A's EL3 SPMC
      by the use of Hafnium's CI test and infrastructure. The goal is to improve
      the test coverage for this alternative SPMC configuration and maintain a
      feature set parity with the S-EL2 SPMC.
    * Added debug capabilities to hftest script.

### Known limitations:
* Power management support limits to cpu on and cpu off events. Only S-EL1
  partitions can opt in for power management events. A power management
  event is forwarded from the SPMD to the SPMC and isn't forwarded to a SP.

## v2.8
### Highlights

* FF-A v1.1 partition runtime model and CPU cycle allocation modes
    * Implemented partition runtime models for secure partitions entered at
      initialization, processing a secure interrupt or as a result of allocation
      of CPU cycles by `FFA_RUN` and `FFA_MSG_SEND_DIRECT_REQ` ABIs invocations.
    * Added state machine checks related to above, in which a partition has a
      set of allowed transitions to enter and exit a partition runtime model.
    * Implemented CPU cycle allocation modes and winding/unwinding of call
      chains.
    * Refactored managed exit field in manifests to use one of the possible
      "Action for a non-secure interrupt" defined by the specification.
    * Added support for preferred managed exit signal (among vIRQ or vFIQ).
    * Support for precedence of the NS interrupt action in unwinding a normal
      world scheduled call chain.
* FF-A v1.1 memory sharing
    * Preparation changes for multiple borrowers and fragmented memory
      sharing support.
    * Fixed memory attributes checks as they are passed to memory sharing
      primitives (`FFA_MEM_SHARE/LEND/DONATE` and `FFA_MEM_RETRIEVE_REQ`).
    * Memory sharing support for S-EL0 partitions.
* FF-A v1.1 notifications
    * Added framework notifications support.
      The supported use case is for indirect messaging to notify a partition
      about a message pending in its RX buffer (or 'RX buffer full' framework
      notification).
    * Added support for notification pending interrupt injection on a RX buffer
      full event.
* FF-A v1.1 Indirect messaging
    * Added support for VM-VM, VM-SP, SP-SP indirect messaging scenarios.
    * Added partition message header structures.
    * Implemented `FFA_MSG_SEND2` and `FFA_RX_ACQUIRE` ABIs.
    * Refactored VM internal state tracking in the SPMC to support forwarding
      of RX/TX buffer mapping/unmapping, notifications creation/destruction,
      RX buffer acquire/release.
    * Refactored VM mailbox states to support the RX buffer full event.
* FF-A console log ABI
    * Added the `FFA_CONSOLE_LOG` ABI as a simple and standardized means to print
      characters without depending on an MMIO device mapped into the VM.
      This allows a VM to print debug or information strings through an
      hypervisor call service using general-purpose registers rather than a
      shared buffer. Multiple VMs can use the ABI concurrently as the SPMC
      buffers data per VM and serializes output to the physical serial device.
* FF-A v1.1 Setup & Discovery
    * Updated the `PARTITION_INFO_GET` ABI to return the partition UUID in the
      partition information descriptors. Additionaly the partition information
      descriptor size is returned as part of the response.
    * Added `FFA_MEM_FRAG_RX/TX` as supported interface in `FFA_FEATURE` response.
* Image footprint optimization
    * The following updates were made with the general idea of reducing the
      flash and RAM footprints. They are also means to adjust the memory
      utilization based on the target market segment.
        * Added platform defines to state the per-VM maximum number of memory and
          device regions, interrupts and SMMU streams per device.
        * Dynamically allocate per vCPU notifications.
        * Allocate vCPU structures from heap.
        * Manifest data allocation from page pool.
        * Fixed core stacks section with noload attribute.
* GIC
    * Added support for GICv3.1 extended SPI / PPI INTID ranges.
    * Add build options to extend the number of supported virtual interrupt IDs.
* SVE
    * Detect the platform supported SVE vector length or set the limit for the
      lower ELs.
    * Increased the SVE NS context to support the maximum vector length
      permitted by the architecture.
    * Above changes lift the limit about a fixed sized SVE vector length (of
      512 bits) used in earlier releases.
* Misc
    * Partition manifest parsing:
        * Added checks forbidding SPs to declare overlapping memory regions and
	  conflicting device interrupt ID resources.
        * Add ability to specify the security state of a memory region
	  for S-EL0 partitions.
    * Fixed system register trap exception injection.
    * Removed hypervisor tables defragmentation.
    * Add ability to define a log level per platform.
    * Disable alignment check for EL0 partitions (when VHE is enabled).

### Known limitations:
* S-EL0 partitions interrupt handling is work in progress.
* Normal world to secure world fragmented memory sharing and sharing to multiple
  borrowers is work in progress.

## v2.7
### Highlights

* Boot protocol (FF-A v1.1 EAC0)
    * The SPMC primarily supports passing the SP manifest address at boot time.
    * In a secure partition package, partition manifest and image offsets are
      configurable.
      * Allows for larger partition manifest sizes.
* Setup and discovery (FF-A v1.1 EAC0)
    * `FFA_VERSION` is forwarded from SPMD to SPMC. SPMC records the version of
      a normal world endpoint.
    * Added UUID to partition info descriptors.
    * Introduced count flag to `FFA_PARTITION_INFO_GET`.
* Interrupt handling (FF-A v1.1 Beta0)
    * Physical GIC registers trapped when accessed from secure partitions.
    * Priority mask register saved/restored on world switches.
    * Interrupts masked before resuming a pre-empted vCPU.
    * Implemented implicit secure interrupt completion signal.
    * Allow unused GICR frame for non-existent PEs.
* Notifications (FF-A v1.1 EAC0)
    * Implemented notification pending interrupt and additional test coverage.
* MTE stack tagging
    * Implemented `FEAT_MTE2` stack tagging support at S-EL2.
    * Core stacks marked as normal tagged memory. A synchronous abort triggers
      on a load/store tag check failure.
    * This permits detection of wrong operations affecting buffers allocated
      from the stack.
* FF-A v1.0 compliance
    * Check composite memory region offset is defined in FF-A memory sharing.
    * Check sender and receiver memory attributes in a FF-A memory sharing
      operation match the attributes expected in the Hafnium implementation.
    * Fix clear memory bit use in FF-A memory sharing from NWd to SWd.
    * Prevent FF-A memory sharing from a SP to a NS endpoint.
    * Reject a FF-A memory retrieve operation with the 'Address Range Alignment
      Hint' bit set (not supported by the implementation).
    * Refine usage of FF-A memory sharing 'clear memory flag'.
* Misc
    * Improved extended memory address ranges support:
        * 52 bits PA (`FEAT_LPA`/`FEAT_LPA2`) architecture extension detected
	  results in limiting the EL2 Stage-1 physical address range to 48 bits.
        * In the FF-A memory sharing operations, harden address width checks on
	  buffer mapping.
    * Improved MP SP and S-EL0 partitions support
      * The physical core index is passed to a SP vCPU0 on booting.
      * Added MP SP and S-EL0 partitions boot test coverage.
    * Emulate SMCCC VERSION to the primary VM.
    * Memory config registers (non-secure and secure virtualization control and
      translation table base) moved to the vCPU context.
    * EL2 stage 1 mapping extended to 1TB to support systems with physical
      address space larger than 512GB.
    * `FFA_RUN` ABI hardened to check the vCPU index matches the PE index onto
      which a vCPU is requested to run.
    * Fixed missing ISB after `CPTR_EL2` update upon PE initialization.
    * Fixed stage 2 default shareability to inner shareable (from non-shareable)
      to better support vCPU migration.
    * Fixed manifest structure allocation from BSS rather than stack
      at initialization.
    * Fixed an issue with FF-A memory reclaim executed after memory donate
      resulting in a returned error code.
* Build and test environment
    * Add the ability to use an out-of-tree toolchain.
      * Primary intent is to permit building Hafnium on Aarch64 hosts.
      * CI runs using the toolchain versioned in prebuilts submodule.
        A developer can still use this version as well.
    * Introduce an assert macro enabled by a build option on the command line.
      Assertions are checked by default. Production builds can optionally
      disable assertions.
    * Added manifest options to permit loading VMs using an FF-A manifest.
* CI
    * Added job running the Hypervisor + SPMC configuration on patch
      submissions.
    * FVP
      * Enable secure memory option.
      * Remove restriction on speculative execution options.
      * Updated to use model version 11.17 build 21.
    * Updated linux submodule to v5.10.
    * VHE EL0 partitions tests automated through jenkins.

### Known limitations:
* FF-A v1.1 EAC0 implementation is partial mainly on interrupt handling and
  memory sharing.
* Hafnium limits physical interrupt IDs to 64. The legacy virtual interrupt
  controller driver limits to 64. The recent addition of physical interrupt
  handling in the SPMC through the GIC assumes a 1:1 mapping of a physical
  interrupt ID to a virtual interrupt ID.
* Secure timer virtualization is not supported.
* The security state of memory or device region cannot be specified in a SP
  manifest.

## v2.6
### Highlights
* FF-A Setup and discovery
    * FF-A build time version updated to v1.1.
    * Managed exit and notifications feature support enabled in SP manifests.
    * Updated `FFA_FEATURES` to permit discovery of managed exit, schedule receiver,
      and notification pending interrupt IDs.
    * `FFA_PARTITION_INFO_GET` updated to permit managed exit and notification
      support discovery.
    * `FFA_SPM_ID_GET` added to permit discovering the SPMC endpoint ID (or the
      SPMD ID at the secure physical FF-A instance).
    * `FFA_RXTX_UNMAP` implementation added.
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
    * Added FF-A v1.1 `FFA_MEM_PERM_GET/SET` ABIs permitting run-time update of
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
    * Hafnium CI Qemu version updated to v6.0.0 (implements VHE and `FEAT_SEL2`
      extensions).
* FF-A compliance fixes
    * Added checks for valid memory permissions values in manifest memory and
      device regions declarations.
    * `FFA_FEATURES` fixed to state indirect messages are not supported by
      the SPMC.
    * Limit an SP to emit a direct request to another SP only.
    * Memory sharing: fixed input validation and return values.
    * `FFA_RXTX_MAP` fixed returned error codes.
    * `FFA_MSG_WAIT` input parameters check hardened.

### Known limitations:
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
### Highlights
* BTI/Pointer authentication support
    * Add branch protection build option for `FEAT_PAuth` and `FEAT_BTI` to the
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
    * Implement the `FFA_SECONDARY_EP_REGISTER` interface for an MP SP or SPMC
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
      `ffa_memory_permissions_to_mode`, so in the case where no permissions are
      specified for a memory operation, the data and instruction permissions can
      be set to the default.
    * Encode Bit[63] of the memory region handle according to if the handle is
      allocated by the Hypervisor or SPMC.
* FF-A v1.0 spec compliance
    * Return `INVALID_PARAMETER` error code instead of `NOT_SUPPORTED` for direct
      messaging interfaces when an invalid sender or receiver id is given.
    * Check that reserved parameter registers are 0 when invoking direct
      messaging ABI interfaces.
    * For SMC32 compliant direct message interfaces, only copy 32-bits
      parameter values.
    * Change the FF-A error codes to 32-bit to match the FF-A specification.
    * Fix consistency with maintaining the calling convention bit of the
      func id between the `ffa_handler` and the `FFA_FEATURES` function.
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

### Known limitations:
* Secure interrupts not supported.
* FF-A indirect message interface not supported in the secure world.
* Only supporting models of MultiProcessor SP (vCPUs pinned to physical
  CPUs) or UniProcessor SP (single vCPU).
* The first secure partition booted must be a MP SP.
* `FFA_RXTX_UNMAP` not implemented.
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

### Highlights
* FF-A v1.0 Setup and discovery interface
    * Hypervisor implementation re-used and extended to the SPMC and SPs.
    * Added partition info get ABI and appropriate properties response depending
      on partition capabilities (PVM, Secondary VM or Secure Partitions).
    * FF-A device-tree manifest parsing.
    * FF-A partitions can declare memory/device regions, and RX/TX buffers that
      the SPMC sets up in the SP EL1&0 Stage-2 translation regime at boot time.
    * FF-A IDs normal and secure world split ranges.
    * The SPMC maps the Hypervisor (or OS kernel) RX/TX buffers as non-secure
      buffers in its EL2 Stage-1 translation regime on `FFA_RXTX_MAP` ABI
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
    * Extract NS bit from `HPFAR_EL2` on Stage-2 page fault.
    * Prevent setup of LOR regions in SWd.
    * Avoid direct PSCI calls down to EL3.
* Platforms
    * Added Arm FVP secure Hafnium build support.
    * Added Arm TC0 "Total Compute" secure Hafnium build support.
* Other improvements
    * Re-hosting to trustedfirmware.org
    * `busy_secondary` timer increased to improve CI stability.
    * Removed legacy Hypervisor calls.
    * Fix `CPTR_EL2` TTA bit position.
    * Report `FAR_EL2` on injecting EL1 exception.
### Known limitations:
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
