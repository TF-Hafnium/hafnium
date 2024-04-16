/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/fpu.h"
#include "hf/arch/sme.h"
#include "hf/arch/sve.h"

#include "hf/types.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "smc.h"
#include "sysregs.h"

/**
 * Other world SIMD SVE/SME context.
 * By design the VM struct stores FPU/Adv. SIMD contexts but no SIMD context
 * for newer extensions. The structure below supplements the VM struct with
 * SVE/SME contexts just for the other world VM usage.
 * Restricting to the other world VM limits the required memory footprint when
 * compared to a design where the VM struct holds the full FPU/Adv. SIMD/SVE/SME
 * contexts. There is no immediate requirement to extend the VM struct provided
 * SVE/SME are not enabled for secure partitions (or secondary VMs).
 */
static struct {
	/** SMCCCv1.3 FID[16] hint bit state recorded on SPMC entry from NWd. */
	bool hint;

	/** SVE context. */
	uint64_t zcr_el2;
	struct sve_context sve_context;

	/** SME context. */
	uint64_t svcr;
	uint64_t smcr_el2;
} ns_simd_ctx[MAX_CPUS];

/**
 * Restore FPU/Adv. SIMD/SVE/SME 'Other world' context when exiting the SPMC.
 * Called from exceptions.S: other_world_loop.
 */
void plat_restore_ns_simd_context(struct vcpu *vcpu)
{
	bool sve = is_arch_feat_sve_supported();
	bool sme = is_arch_feat_sme_supported();
	bool fa64 = is_arch_feat_sme_fa64_supported();
	bool streaming_mode = false;
	bool hint;
	uint32_t cpu_id;

	assert(vcpu->vm->id == HF_HYPERVISOR_VM_ID);
	cpu_id = cpu_index(vcpu->cpu);
	hint = ns_simd_ctx[cpu_id].hint;

	if (sme) {
		/* Disable SME EL2 and lower traps. */
		arch_sme_disable_traps();

		/* Assert ZA array did not change state. */
		assert((arch_sme_svcr_get() & MSR_SVCR_ZA) ==
		       (ns_simd_ctx[cpu_id].svcr & MSR_SVCR_ZA));

		/*
		 * Restore SVCR, in particular (re)enable SSVE if it was enabled
		 * at entry.
		 * NOTE: a PSTATE.SM transition resets Z0-Z31, P0-P15,
		 * FFR and FPSR registers to an architecturally defined
		 * constant.
		 */
		arch_sme_svcr_set(ns_simd_ctx[cpu_id].svcr);

		streaming_mode =
			(ns_simd_ctx[cpu_id].svcr & MSR_SVCR_SM) == MSR_SVCR_SM;

		/*
		 * Streaming SVE vector length is determined by SMCR_EL2.LEN
		 * that was set earlier during the save operation.
		 */
	}

	if (sve) {
		/* Disable SVE EL2 and lower traps. */
		arch_sve_disable_traps();

		/*
		 * SVE vector length is determined by ZCR_EL2.LEN
		 * that was set earlier during the save operation.
		 */
	}

	/* Restore FPCR/FPSR common to FPU/Adv. SIMD./SVE/SME. */
	arch_fpu_state_restore_from_vcpu(vcpu);

	/*
	 * If SVE or SME is implemented and SVE hint is false as it was
	 * passed by the normal world caller when entering the SPMC, then
	 * restore the SVE (or Streaming SVE) state.
	 * Omit restoring the SVE state, if only SME is implemented (and
	 * SVE is not implemented) and Streaming SVE is disabled.
	 */
	if ((sve || sme) && !hint && !(!sve && sme && !streaming_mode)) {
		/*
		 * Restore FFR register before predicates,
		 * if SVE only is implemented, or both SVE and SME are
		 * implemented and Streaming SVE is disabled,
		 * or both SME and FEAT_SME_FA64 are implemented and
		 * Streaming SVE is enabled.
		 */
		if ((sve && !sme) || (sve && sme && !streaming_mode) ||
		    (sme && fa64 && streaming_mode)) {
			__asm__ volatile(
				".arch_extension sve;"
				"ldr p0, [%0];"
				"wrffr p0.b;"
				".arch_extension nosve"
				:
				: "r"(&ns_simd_ctx[cpu_id].sve_context.ffr));
		}

		/*
		 * Restore predicates if SVE only is implemented,
		 * or both SME and SVE are implemented and Streaming SVE
		 * is disabled,
		 * or SME is implemented and Streaming SVE is enabled.
		 */
		if ((sve && !sme) || (sve && sme && !streaming_mode) ||
		    (sme && streaming_mode)) {
			/* Restore predicate registers. */
			__asm__ volatile(
				".arch_extension sve;"
				"ldr p0, [%0, #0, MUL VL];"
				"ldr p1, [%0, #1, MUL VL];"
				"ldr p2, [%0, #2, MUL VL];"
				"ldr p3, [%0, #3, MUL VL];"
				"ldr p4, [%0, #4, MUL VL];"
				"ldr p5, [%0, #5, MUL VL];"
				"ldr p6, [%0, #6, MUL VL];"
				"ldr p7, [%0, #7, MUL VL];"
				"ldr p8, [%0, #8, MUL VL];"
				"ldr p9, [%0, #9, MUL VL];"
				"ldr p10, [%0, #10, MUL VL];"
				"ldr p11, [%0, #11, MUL VL];"
				"ldr p12, [%0, #12, MUL VL];"
				"ldr p13, [%0, #13, MUL VL];"
				"ldr p14, [%0, #14, MUL VL];"
				"ldr p15, [%0, #15, MUL VL];"
				".arch_extension nosve"
				:
				: "r"(&ns_simd_ctx[cpu_id]
					       .sve_context.predicates));

			/* Restore SVE/Streaming SVE vectors. */
			__asm__ volatile(
				".arch_extension sve;"
				"ldr z0, [%0, #0, MUL VL];"
				"ldr z1, [%0, #1, MUL VL];"
				"ldr z2, [%0, #2, MUL VL];"
				"ldr z3, [%0, #3, MUL VL];"
				"ldr z4, [%0, #4, MUL VL];"
				"ldr z5, [%0, #5, MUL VL];"
				"ldr z6, [%0, #6, MUL VL];"
				"ldr z7, [%0, #7, MUL VL];"
				"ldr z8, [%0, #8, MUL VL];"
				"ldr z9, [%0, #9, MUL VL];"
				"ldr z10, [%0, #10, MUL VL];"
				"ldr z11, [%0, #11, MUL VL];"
				"ldr z12, [%0, #12, MUL VL];"
				"ldr z13, [%0, #13, MUL VL];"
				"ldr z14, [%0, #14, MUL VL];"
				"ldr z15, [%0, #15, MUL VL];"
				"ldr z16, [%0, #16, MUL VL];"
				"ldr z17, [%0, #17, MUL VL];"
				"ldr z18, [%0, #18, MUL VL];"
				"ldr z19, [%0, #19, MUL VL];"
				"ldr z20, [%0, #20, MUL VL];"
				"ldr z21, [%0, #21, MUL VL];"
				"ldr z22, [%0, #22, MUL VL];"
				"ldr z23, [%0, #23, MUL VL];"
				"ldr z24, [%0, #24, MUL VL];"
				"ldr z25, [%0, #25, MUL VL];"
				"ldr z26, [%0, #26, MUL VL];"
				"ldr z27, [%0, #27, MUL VL];"
				"ldr z28, [%0, #28, MUL VL];"
				"ldr z29, [%0, #29, MUL VL];"
				"ldr z30, [%0, #30, MUL VL];"
				"ldr z31, [%0, #31, MUL VL];"
				".arch_extension nosve"
				:
				: "r"(&ns_simd_ctx[cpu_id]
					       .sve_context.vectors));
		}
	} else {
		/* Restore FPU/Adv. SIMD vectors. */
		arch_fpu_regs_restore_from_vcpu(vcpu);

		if ((sve || sme) && hint) {
			/* TODO: clear predicates and ffr */
		}
	}

	if (sve) {
		/*
		 * Restore normal world ZCR_EL2.
		 * ZCR_EL1 is untouched as SVE is not enabled for SPs.
		 */
		write_msr(MSR_ZCR_EL2, ns_simd_ctx[cpu_id].zcr_el2);
		isb();

		arch_sve_enable_traps();
	}

	if (sme) {
		/* Restore SSVE vector length if enabled. */
		write_msr(MSR_SMCR_EL2, ns_simd_ctx[cpu_id].smcr_el2);
		isb();

		arch_sme_enable_traps();
	}
}

/**
 * Save FPU/Adv SIMD/SVE/SME 'Other world' context when entering the SPMC.
 * Called from handler.c: smc_handler_from_nwd.
 */
void plat_save_ns_simd_context(struct vcpu *vcpu)
{
	uint32_t cpu_id;
	uint64_t smc_fid;
	bool sve = is_arch_feat_sve_supported();
	bool sme = is_arch_feat_sme_supported();
	bool fa64 = is_arch_feat_sme_fa64_supported();
	bool streaming_mode = false;
	bool hint;

	assert(vcpu->vm->id == HF_HYPERVISOR_VM_ID);
	cpu_id = cpu_index(vcpu->cpu);

	/* Get SMCCCv1.3 SMC FID[16] SVE hint, and clear it from vCPU r0. */
	smc_fid = vcpu->regs.r[0];
	hint = ns_simd_ctx[cpu_id].hint = (smc_fid & SMCCC_SVE_HINT_MASK) != 0;

	if (sme) {
		/* Disable SME EL2 and lower traps. */
		arch_sme_disable_traps();

		/*
		 * Save current SMCR_EL2 value, in particular to preserve
		 * NS context SSVE vector length.
		 */
		ns_simd_ctx[cpu_id].smcr_el2 = read_msr(MSR_SMCR_EL2);

		/* Configure EL2 SSVE vector length. */
		arch_sme_configure_svl();

		/* Save ZA array and SSVE enable state. */
		ns_simd_ctx[cpu_id].svcr = arch_sme_svcr_get();

		streaming_mode =
			(ns_simd_ctx[cpu_id].svcr & MSR_SVCR_SM) == MSR_SVCR_SM;
	}

	if (sve) {
		/* Disable SVE EL2 and lower traps. */
		arch_sve_disable_traps();

		/*
		 * Save current ZCR_EL2 value, in particular to preserve
		 * NS context SVE Vector Length.
		 */
		ns_simd_ctx[cpu_id].zcr_el2 = read_msr(MSR_ZCR_EL2);

		/* Configure EL2 SVE Vector Length. */
		arch_sve_configure_vector_length();
	}

	/* Save FPCR/FPSR common to FPU/Adv. SIMD/SVE/SME. */
	arch_fpu_state_save_to_vcpu(vcpu);

	/*
	 * If SVE or SME is implemented and SVE hint is false as passed by
	 * the normal world caller, then save the SVE (or Streaming SVE) state.
	 * Omit saving the SVE state, if only SME is implemented (and SVE is not
	 * implemented) and Streaming SVE is disabled.
	 */
	if ((sve || sme) && !hint && !(!sve && sme && !streaming_mode)) {
		/*
		 * Save predicates if SVE only is implemented,
		 * or both SME and SVE are implemented and Streaming SVE
		 * is disabled,
		 * or SME is implemented and Streaming SVE is enabled.
		 */
		if ((sve && !sme) || (sve && sme && !streaming_mode) ||
		    (sme && streaming_mode)) {
			/* Save predicate registers. */
			__asm__ volatile(
				".arch_extension sve;"
				"str p0, [%0, #0, MUL VL];"
				"str p1, [%0, #1, MUL VL];"
				"str p2, [%0, #2, MUL VL];"
				"str p3, [%0, #3, MUL VL];"
				"str p4, [%0, #4, MUL VL];"
				"str p5, [%0, #5, MUL VL];"
				"str p6, [%0, #6, MUL VL];"
				"str p7, [%0, #7, MUL VL];"
				"str p8, [%0, #8, MUL VL];"
				"str p9, [%0, #9, MUL VL];"
				"str p10, [%0, #10, MUL VL];"
				"str p11, [%0, #11, MUL VL];"
				"str p12, [%0, #12, MUL VL];"
				"str p13, [%0, #13, MUL VL];"
				"str p14, [%0, #14, MUL VL];"
				"str p15, [%0, #15, MUL VL];"
				".arch_extension nosve"
				:
				: "r"(&ns_simd_ctx[cpu_id]
					       .sve_context.predicates));
		}

		/*
		 * Save FFR register if SVE only is implemented,
		 * or both SVE and SME are implemented and Streaming SVE
		 * is disabled, or both SME and FEAT_SME_FA64 are implemented
		 * and Streaming SVE is enabled.
		 */
		if ((sve && !sme) || (sve && sme && !streaming_mode) ||
		    (sme && fa64 && streaming_mode)) {
			__asm__ volatile(
				".arch_extension sve;"
				"rdffr p0.b;"
				"str p0, [%0];"
				".arch_extension nosve"
				:
				: "r"(&ns_simd_ctx[cpu_id].sve_context.ffr));
		}

		/*
		 * Save SVE/Streaming SVE vectors (similar conditions as
		 * predicates above).
		 */
		if ((sve && !sme) || (sve && sme && !streaming_mode) ||
		    (sme && streaming_mode)) {
			__asm__ volatile(
				".arch_extension sve;"
				"str z0, [%0, #0, MUL VL];"
				"str z1, [%0, #1, MUL VL];"
				"str z2, [%0, #2, MUL VL];"
				"str z3, [%0, #3, MUL VL];"
				"str z4, [%0, #4, MUL VL];"
				"str z5, [%0, #5, MUL VL];"
				"str z6, [%0, #6, MUL VL];"
				"str z7, [%0, #7, MUL VL];"
				"str z8, [%0, #8, MUL VL];"
				"str z9, [%0, #9, MUL VL];"
				"str z10, [%0, #10, MUL VL];"
				"str z11, [%0, #11, MUL VL];"
				"str z12, [%0, #12, MUL VL];"
				"str z13, [%0, #13, MUL VL];"
				"str z14, [%0, #14, MUL VL];"
				"str z15, [%0, #15, MUL VL];"
				"str z16, [%0, #16, MUL VL];"
				"str z17, [%0, #17, MUL VL];"
				"str z18, [%0, #18, MUL VL];"
				"str z19, [%0, #19, MUL VL];"
				"str z20, [%0, #20, MUL VL];"
				"str z21, [%0, #21, MUL VL];"
				"str z22, [%0, #22, MUL VL];"
				"str z23, [%0, #23, MUL VL];"
				"str z24, [%0, #24, MUL VL];"
				"str z25, [%0, #25, MUL VL];"
				"str z26, [%0, #26, MUL VL];"
				"str z27, [%0, #27, MUL VL];"
				"str z28, [%0, #28, MUL VL];"
				"str z29, [%0, #29, MUL VL];"
				"str z30, [%0, #30, MUL VL];"
				"str z31, [%0, #31, MUL VL];"
				".arch_extension nosve"
				:
				: "r"(&ns_simd_ctx[cpu_id]
					       .sve_context.vectors));
		}
	} else {
		/* Save FPU/Adv. SIMD vectors. */
		arch_fpu_regs_save_to_vcpu(vcpu);
	}

	if (sve) {
		arch_sve_enable_traps();
	}

	/*
	 * SVCR.ZA=1 indicates the ZA array is live.
	 * We deliberately choose to leave the ZA array enabled, knowing
	 * that S-EL2 and lower won't make use of SME.
	 * S-EL1 and lower are prevented SME registers access. There is
	 * a probable performance impact but this avoids us saving/restoring
	 * the ZA array contents. SME2 ZT0 isn't touched by EL2 and lower ELs
	 * hence no need to save/restore it.
	 */

	if (sme) {
		if (streaming_mode) {
			/*
			 * SVCR.SM=1 indicates active Streaming SVE mode.
			 * It is preferable to disable it to save power.
			 * The overall NS SIMD state has been saved above.
			 * Disabling SSVE destroys the live state. Change
			 * to this field doesn't impact the ZA storage.
			 */
			arch_sme_svcr_set(ns_simd_ctx[cpu_id].svcr &
					  ~MSR_SVCR_SM);
		}

		arch_sme_enable_traps();
	}
}
