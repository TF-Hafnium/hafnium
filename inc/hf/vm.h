/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdatomic.h>

#include "hf/arch/vm/vm.h"

#include "hf/cpu.h"
#include "hf/ffa_partition_manifest.h"
#include "hf/interrupt_desc.h"
#include "hf/list.h"
#include "hf/mm.h"
#include "hf/mpool.h"

#include "vmapi/hf/ffa.h"

#define MAX_SMCS 32
#define VM_MANIFEST_MAX_INTERRUPTS 32

/** Action for Other-Secure interrupts by SPMC. */
#define OTHER_S_INT_ACTION_QUEUED 0
#define OTHER_S_INT_ACTION_SIGNALED 1

/**
 * Power management bifields stating which messages a VM is willing to be
 * notified about.
 */
#define VM_POWER_MANAGEMENT_CPU_OFF_SHIFT (0)
#define VM_POWER_MANAGEMENT_CPU_ON_SHIFT (3)

/**
 * The state of an RX buffer, as defined by FF-A v1.1 EAC0 specification.
 * It is used to implement ownership rules, as defined in the section 6.2.2.4.2.
 *
 * EMPTY is the initial state. It is set by default to the endpoints at the
 * virtual instance.
 * The follow state transitions are possible:
 * * EMPTY => FULL: message sent to a partition. Ownership given to the
 * partition.
 * * EMPTY => OTHER_WORLD_OWNED: This state transition only applies to NWd VMs.
 * Used by the SPMC or Hypervisor to track that ownership of the RX buffer
 * belong to the other world:
 * - The Hypervisor does this state transition after forwarding
 * FFA_RXTX_MAP call to the SPMC, for it to map a VM's RXTX buffers into SPMC's
 * translation regime.
 * - SPMC was previously given ownership of the VM's RX buffer, after the
 * FFA_RXTX_MAP interface has been successfully forwarded to it. The SPMC does
 * this state transition, when handling a successful FFA_RX_ACQUIRE, assigning
 * ownership to the hypervisor.
 * * FULL => EMPTY: Partition received an RX buffer full notification, consumed
 * the content of buffers, and called FFA_RX_RELEASE or FFA_MSG_WAIT. SPMC or
 * Hypervisor's ownership reestablished.
 * * OTHER_WORLD_OWNED => EMPTY: VM called FFA_RX_RELEASE, the hypervisor
 * forwarded it to the SPMC, which reestablishes ownership of the VM's buffer.
 * SPs should never have their buffers state set to OTHER_WORLD_OWNED.
 */
enum mailbox_state {
	/** There is no message in the mailbox. */
	MAILBOX_STATE_EMPTY,

	/** There is a message in the mailbox that is waiting for a reader. */
	MAILBOX_STATE_FULL,

	/**
	 * In the SPMC, it means the Hypervisor/OS Kernel owns the RX buffer.
	 * In the Hypervisor, it means the SPMC owns the Rx buffer.
	 */
	MAILBOX_STATE_OTHER_WORLD_OWNED,
};

struct mailbox {
	enum mailbox_state state;
	void *recv;
	const void *send;

	/** The ID of the VM which sent the message currently in `recv`. */
	ffa_id_t recv_sender;

	/** The size of the message currently in `recv`. */
	uint32_t recv_size;

	/**
	 * The FF-A function ID to use to deliver the message currently in
	 * `recv`.
	 */
	uint32_t recv_func;
};

struct notifications_state {
	/**
	 * To keep track of the notifications pending.
	 * Set on call to FFA_NOTIFICATION_SET, and cleared on call to
	 * FFA_NOTIFICATION_GET.
	 */
	ffa_notifications_bitmap_t pending;

	/**
	 * Set on FFA_NOTIFICATION_INFO_GET to keep track of the notifications
	 * whose information has been retrieved by the referred ABI.
	 * Cleared on call to FFA_NOTIFICATION_GET.
	 */
	ffa_notifications_bitmap_t info_get_retrieved;
};

struct notifications {
	/**
	 * The following array maps the notifications to the bound FF-A
	 * endpoint.
	 * The index in the bindings array relates to the notification
	 * ID, and bit position in 'ffa_notifications_bitmap_t'.
	 */
	ffa_id_t bindings_sender_id[MAX_FFA_NOTIFICATIONS];
	ffa_notifications_bitmap_t bindings_per_vcpu;

	/* The index of the array below relates to the ID of the VCPU.
	 * This is a dynamically allocated array of struct
	 * notifications_state and has as many entries as vcpu_count.
	 */
	struct notifications_state *per_vcpu;
	struct notifications_state global;
};

/**
 * The following enum relates to a state machine to guide the insertion of
 * IDs in the respective list as a result of a FFA_NOTIFICATION_INFO_GET call.
 * As per the FF-A v1.1 specification, the return of the interface
 * FFA_NOTIFICATION_INFO_GET, is a list of 16-bit values, regarding the VM ID
 * and VCPU IDs of those with pending notifications.
 * The overall list, is composed of "sub-lists", that starts with the VM ID, and
 * can follow with up to 3 more VCPU IDs. A VM can have multiple 'sub-lists'.
 * The states are traversed on a per VM basis, and should help with filling the
 * list of IDs.
 *
 * INIT is the initial state. The following state transitions are possible:
 * * INIT => INSERTING: no list has been created for the VM prior. There are
 * notifications pending and VM ID should be inserted first. If it regards to
 * a per VCPU notification the VCPU ID should follow. Only VCPU IDs should be
 * inserted from this point, until reaching "sub-list" size limit.
 * * INIT => FULL: There is no space in the ID list to insert IDs.
 * * INSERTING => STARTING_NEW: list has been created. Adding only VCPU IDs,
 * however "sub-list" limit has been reached. If there are more pending per VCPU
 * notifications pending for the VM, a new list should be created starting with
 * VM ID.
 * * INSERTING => FULL: There is no space in the ID list to insert IDs.
 * * STARTING_NEW => INSERTING: Started a new 'sub-list' for the given VM, for
 * the remaining pending per VCPU notifications, only the VCPU ID should be
 * inserted.
 * * STARTING_NEW => FULL: There is no space in the ID list to insert IDs.
 */
enum notifications_info_get_state {
	INIT,
	INSERTING,
	STARTING_NEW,
	FULL,
};

struct smc_whitelist {
	uint32_t smcs[MAX_SMCS];
	uint16_t smc_count;
	bool permissive;
};

/* NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding) */
struct vm {
	ffa_id_t id;
	struct ffa_uuid uuids[PARTITION_MAX_UUIDS];
	enum ffa_version ffa_version;

	/*
	 * Whether this FF-A instance has negotiated an FF-A version through a
	 * call to FFA_VERSION. Once the version has been negotiated, it is an
	 * error to attempt to change it through another call to FFA_VERSION.
	 */
	bool ffa_version_negotiated;

	struct smc_whitelist smc_whitelist;

	/** See api.c for the partial ordering on locks. */
	struct spinlock lock;
	ffa_vcpu_count_t vcpu_count;
	struct vcpu *vcpus;
	struct mm_ptable ptable;

	/**
	 * Set of page tables used for defining the peripheral's secure
	 * IPA space, in the context of SPMC.
	 */
	struct mm_ptable iommu_ptables[PARTITION_MAX_DMA_DEVICES];
	/** Count of DMA devices assigned to this VM. */
	uint8_t dma_device_count;
	struct mailbox mailbox;

	struct {
		/**
		 * State structures for notifications coming from VMs or coming
		 * from SPs. Both fields are maintained by the SPMC.
		 * The hypervisor ignores the 'from_sp' field, given VM
		 * notifications from SPs are managed by the SPMC.
		 */
		struct notifications from_vm;
		struct notifications from_sp;
		struct notifications_state framework;
		bool enabled;
		bool npi_injected;
	} notifications;

	/**
	 * Whether this partition is subscribed to receiving VM created/VM
	 * destroyed messages.
	 */
	struct {
		bool vm_created;
		bool vm_destroyed;
	} vm_availability_messages;

	atomic_bool aborting;

	/**
	 * Booting parameters (FF-A SP partitions).
	 */
	uint16_t boot_order;

	/** Entries to pass boot data to the VM. */
	struct {
		uint32_t gp_register_num;
		ipaddr_t blob_addr;
	} boot_info;

	uint16_t messaging_method;

	/**
	 * Action specified by a Partition through the manifest in response to
	 * non secure interrupt.
	 */
	uint8_t ns_interrupts_action;

	/**
	 * Action specified by a Partition through the manifest in response to
	 * Other-S-Int.
	 */
	uint8_t other_s_interrupts_action;
	bool me_signal_virq;

	/**
	 * Bitmask reporting the power management events that a partition
	 * requests to the signaled about.
	 */
	uint32_t power_management;

	/**
	 * Secondary entry point supplied by FFA_SECONDARY_EP_REGISTER used
	 * for cold and warm boot of SP execution contexts.
	 */
	ipaddr_t secondary_ep;

	/** Arch-specific VM information. */
	struct arch_vm arch;
	bool el0_partition;

	/** Interrupt descriptor */
	struct interrupt_descriptor interrupt_desc[VM_MANIFEST_MAX_INTERRUPTS];
};

/** Encapsulates a VM whose lock is held. */
struct vm_locked {
	struct vm *vm;
};

/** Container for two vm_locked structures */
struct two_vm_locked {
	struct vm_locked vm1;
	struct vm_locked vm2;
};

struct vm *vm_init(ffa_id_t id, ffa_vcpu_count_t vcpu_count,
		   struct mpool *ppool, bool el0_partition,
		   uint8_t dma_device_count);
bool vm_init_next(ffa_vcpu_count_t vcpu_count, struct mpool *ppool,
		  struct vm **new_vm, bool el0_partition,
		  uint8_t dma_device_count);
ffa_vm_count_t vm_get_count(void);
struct vm *vm_find(ffa_id_t id);
struct vm_locked vm_find_locked(ffa_id_t id);
struct vm *vm_find_index(uint16_t index);
struct vm_locked vm_lock(struct vm *vm);
struct two_vm_locked vm_lock_both(struct vm *vm1, struct vm *vm2);
void vm_unlock(struct vm_locked *locked);
struct two_vm_locked vm_lock_both_in_order(struct vm_locked vm1,
					   struct vm *vm2);
struct vcpu *vm_get_vcpu(struct vm *vm, ffa_vcpu_index_t vcpu_index);
bool vm_id_is_current_world(ffa_id_t vm_id);
bool vm_is_mailbox_busy(struct vm_locked to);
bool vm_is_mailbox_other_world_owned(struct vm_locked to);
bool vm_identity_map(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
		     uint32_t mode, struct mpool *ppool, ipaddr_t *ipa);
bool vm_identity_prepare(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			 uint32_t mode, struct mpool *ppool);
void vm_identity_commit(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			uint32_t mode, struct mpool *ppool, ipaddr_t *ipa);
bool vm_unmap(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
	      struct mpool *ppool);
void vm_ptable_defrag(struct vm_locked vm_locked, struct mpool *ppool);
bool vm_unmap_hypervisor(struct vm_locked vm_locked, struct mpool *ppool);

bool vm_mem_get_mode(struct vm_locked vm_locked, ipaddr_t begin, ipaddr_t end,
		     uint32_t *mode);
bool vm_iommu_mm_identity_map(struct vm_locked vm_locked, paddr_t begin,
			      paddr_t end, uint32_t mode, struct mpool *ppool,
			      ipaddr_t *ipa, uint8_t dma_device_id);

void vm_notifications_init(struct vm *vm, ffa_vcpu_count_t vcpu_count,
			   struct mpool *ppool);
bool vm_mailbox_state_busy(struct vm_locked vm_locked);
bool vm_are_notifications_pending(struct vm_locked vm_locked, bool from_vm,
				  ffa_notifications_bitmap_t notifications);
bool vm_are_fwk_notifications_pending(struct vm_locked vm_locked);
bool vm_are_global_notifications_pending(struct vm_locked vm_locked);
bool vm_are_per_vcpu_notifications_pending(struct vm_locked vm_locked,
					   ffa_vcpu_index_t vcpu_id);
bool vm_are_notifications_enabled(struct vm *vm);
bool vm_locked_are_notifications_enabled(struct vm_locked vm_locked);
bool vm_notifications_validate_per_vcpu(struct vm_locked vm_locked,
					bool is_from_vm, bool is_per_vcpu,
					ffa_notifications_bitmap_t notif);
bool vm_notifications_validate_bound_sender(
	struct vm_locked vm_locked, bool is_from_vm, ffa_id_t sender_id,
	ffa_notifications_bitmap_t notifications);
bool vm_notifications_validate_binding(struct vm_locked vm_locked,
				       bool is_from_vm, ffa_id_t sender_id,
				       ffa_notifications_bitmap_t notifications,
				       bool is_per_vcpu);
void vm_notifications_update_bindings(struct vm_locked vm_locked,
				      bool is_from_vm, ffa_id_t sender_id,
				      ffa_notifications_bitmap_t notifications,
				      bool is_per_vcpu);
void vm_notifications_partition_set_pending(
	struct vm_locked vm_locked, bool is_from_vm,
	ffa_notifications_bitmap_t notifications, ffa_vcpu_index_t vcpu_id,
	bool is_per_vcpu);
ffa_notifications_bitmap_t vm_notifications_partition_get_pending(
	struct vm_locked vm_locked, bool is_from_vm, ffa_vcpu_index_t vcpu_id);
void vm_notifications_framework_set_pending(
	struct vm_locked vm_locked, ffa_notifications_bitmap_t notifications);
ffa_notifications_bitmap_t vm_notifications_framework_get_pending(
	struct vm_locked vm_locked);
void vm_notifications_info_get_pending(
	struct vm_locked vm_locked, bool is_from_vm, uint16_t *ids,
	uint32_t *ids_count, uint32_t *lists_sizes, uint32_t *lists_count,
	uint32_t ids_max_count,
	enum notifications_info_get_state *info_get_state);
bool vm_notifications_pending_not_retrieved_by_scheduler(void);
bool vm_is_notifications_pending_count_zero(void);
bool vm_notifications_info_get(struct vm_locked vm_locked, uint16_t *ids,
			       uint32_t *ids_count, uint32_t *lists_sizes,
			       uint32_t *lists_count, uint32_t ids_max_count);
bool vm_supports_messaging_method(struct vm *vm, uint16_t messaging_method);
void vm_notifications_set_npi_injected(struct vm_locked vm_locked,
				       bool npi_injected);
bool vm_notifications_is_npi_injected(struct vm_locked vm_locked);
void vm_set_boot_info_gp_reg(struct vm *vm, struct vcpu *vcpu);

/**
 * Returns true if the VM requested to receive cpu on power management
 * events.
 */
static inline bool vm_power_management_cpu_on_requested(struct vm *vm)
{
	return (vm->power_management &
		(UINT32_C(1) << VM_POWER_MANAGEMENT_CPU_ON_SHIFT)) != 0;
}

/**
 * Returns true if the VM requested to receive cpu off power management
 * events.
 */
static inline bool vm_power_management_cpu_off_requested(struct vm *vm)
{
	return (vm->power_management &
		(UINT32_C(1) << VM_POWER_MANAGEMENT_CPU_OFF_SHIFT)) != 0;
}

/* Return true if `vm` is a UP. */
static inline bool vm_is_up(const struct vm *vm)
{
	return vm->vcpu_count == 1;
}

/* Return true if `vm` is a MP. */
static inline bool vm_is_mp(const struct vm *vm)
{
	return vm->vcpu_count > 1;
}

/* Return true if `vm` is the primary VM. */
static inline bool vm_is_primary(const struct vm *vm)
{
	return vm->id == HF_PRIMARY_VM_ID;
}

/**
 * Convert a CPU ID for a secondary VM to the corresponding vCPU index.
 */
static inline ffa_vcpu_index_t vcpu_id_to_index(cpu_id_t vcpu_id)
{
	/* For now we use indices as IDs. */
	return vcpu_id;
}

struct interrupt_descriptor *vm_interrupt_set_target_mpidr(
	struct vm_locked vm_locked, uint32_t id, uint32_t target_mpidr);
struct interrupt_descriptor *vm_interrupt_set_sec_state(
	struct vm_locked vm_locked, uint32_t id, uint32_t sec_state);
struct interrupt_descriptor *vm_interrupt_set_enable(struct vm_locked vm_locked,
						     uint32_t id, bool enable);
