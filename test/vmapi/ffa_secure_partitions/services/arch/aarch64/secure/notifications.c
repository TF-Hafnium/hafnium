/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"

/**
 * Return a notification2 service result through FFA_MSG_SEND_DIRECT_RESP2.
 *
 * x4 contains SP_SUCCESS or SP_ERROR.
 * On success x5-x10 contain the returned partition bitmap.
 * On failure x5 contains the FF-A error code.
 */
static struct ffa_value sp_notif2_resp(ffa_id_t test_source, ffa_id_t own_id,
				       struct ffa_value res,
				       ffa_notifications_bitmap_t bitmap)
{
	uint64_t msg[7] = {SP_SUCCESS};

	if (res.func == FFA_ERROR_32) {
		msg[0] = (uint64_t)(int64_t)SP_ERROR;
		msg[1] = (uint32_t)ffa_error_code(res);
		return ffa_msg_send_direct_resp2(own_id, test_source, msg, 2);
	}

	ffa_notification_bitmap_to_regs(bitmap, &msg[1], &msg[2], &msg[3],
					&msg[4], &msg[5], &msg[6]);
	return ffa_msg_send_direct_resp2(own_id, test_source, msg,
					 sizeof(msg) / sizeof(msg[0]));
}

/**
 * Convert a notification2 ABI success or error into a service response when
 * the operation does not return a notification bitmap.
 */
static struct ffa_value sp_notif2_ffa_resp(ffa_id_t test_source,
					   ffa_id_t own_id,
					   struct ffa_value res)
{
	ffa_notifications_bitmap_t empty;

	ffa_notification_bitmap_init(&empty);
	return sp_notif2_resp(test_source, own_id, res, empty);
}

struct ffa_value sp_notif_set_cmd(ffa_id_t test_source, ffa_id_t notif_receiver,
				  uint32_t flags,
				  ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_notification_set(own_id, notif_receiver, flags, bitmap);
	return sp_check_ffa_return_resp(test_source, own_id, res);
}

struct ffa_value sp_notif_get_cmd(ffa_id_t test_source, uint16_t vcpu_id,
				  uint32_t flags)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_notification_get(own_id, vcpu_id, flags);
	if (res.func == FFA_ERROR_32) {
		dlog_error("Failed to get pending notifications SP");
		return sp_error(own_id, test_source, ffa_error_code(res));
	}

	return sp_notif_get_success(own_id, test_source,
				    ffa_notification_get_from_sp(res),
				    ffa_notification_get_from_vm(res));
}

struct ffa_value sp_notif_bind_cmd(ffa_id_t test_source, ffa_id_t notif_sender,
				   uint32_t flags,
				   ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_notification_bind(notif_sender, own_id, flags, bitmap);

	/*
	 * Register handler to log when notification pending interrupts are
	 * thrown.
	 */
	exception_setup(check_npi, NULL);

	return sp_check_ffa_return_resp(test_source, own_id, res);
}

struct ffa_value sp_notif_unbind_cmd(ffa_id_t test_source,
				     ffa_id_t notif_sender,
				     ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	dlog_verbose("Unbind notifications %lx, from sender: %x\n",
		     ffa_notification_bitmap_low64(bitmap), notif_sender);

	res = ffa_notification_unbind(notif_sender, own_id, bitmap);
	return sp_check_ffa_return_resp(test_source, own_id, res);
}

/**
 * Invoke FFA_NOTIFICATION_SET2 as the sending SP service.
 */
struct ffa_value sp_notif_set2_cmd(ffa_id_t test_source,
				   ffa_id_t notif_receiver, uint64_t flags,
				   ffa_notifications_bitmap_t bitmap)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res =
		ffa_notification_set2(own_id, notif_receiver, flags, bitmap);

	return sp_notif2_ffa_resp(test_source, own_id, res);
}

/**
 * Invoke FFA_NOTIFICATION_GET2 and return the requested SP or VM partition
 * bitmap to the test endpoint.
 */
struct ffa_value sp_notif_get2_cmd(ffa_id_t test_source,
				   ffa_vcpu_index_t vcpu_id, uint64_t flags,
				   ffa_notifications_bitmap_t mask)
{
	ffa_notifications_bitmap_t empty;
	ffa_notifications_bitmap_t sp_mask;
	ffa_notifications_bitmap_t vm_mask;
	ffa_notifications_bitmap_t notifications;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	ffa_notification_bitmap_init(&empty);

	/*
	 * The service protocol returns one partition bitmap per request. This
	 * is sufficient for the SP and VM sender paths exercised by these
	 * tests.
	 */
	if (flags != FFA_NOTIFICATION_FLAG_BITMAP_SP &&
	    flags != FFA_NOTIFICATION_FLAG_BITMAP_VM) {
		uint64_t msg[] = {(uint64_t)(int64_t)SP_ERROR,
				  FFA_INVALID_PARAMETERS};

		return ffa_msg_send_direct_resp2(own_id, test_source, msg,
						 sizeof(msg) / sizeof(msg[0]));
	}

	sp_mask = flags == FFA_NOTIFICATION_FLAG_BITMAP_SP ? mask : empty;
	vm_mask = flags == FFA_NOTIFICATION_FLAG_BITMAP_VM ? mask : empty;

	res = ffa_notification_get2(own_id, vcpu_id, flags, sp_mask, vm_mask,
				    0U, 0U);
	if (res.func == FFA_ERROR_32) {
		return sp_notif2_resp(test_source, own_id, res, empty);
	}

	notifications = flags == FFA_NOTIFICATION_FLAG_BITMAP_SP
				? ffa_notification_bitmap_from_get2_sp(res)
				: ffa_notification_bitmap_from_get2_vm(res);

	return sp_notif2_resp(test_source, own_id, res, notifications);
}

/**
 * Invoke FFA_NOTIFICATION_BIND2 as the receiving SP service.
 */
struct ffa_value sp_notif_bind2_cmd(ffa_id_t test_source, ffa_id_t notif_sender,
				    uint64_t flags,
				    ffa_notifications_bitmap_t bitmap)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res =
		ffa_notification_bind2(notif_sender, own_id, flags, bitmap);

	/*
	 * Register the handler which logs notification-pending interrupts.
	 */
	exception_setup(check_npi, NULL);

	return sp_notif2_ffa_resp(test_source, own_id, res);
}

/**
 * Invoke FFA_NOTIFICATION_UNBIND2 as the receiving SP service.
 */
struct ffa_value sp_notif_unbind2_cmd(ffa_id_t test_source,
				      ffa_id_t notif_sender,
				      ffa_notifications_bitmap_t bitmap)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res =
		ffa_notification_unbind2(notif_sender, own_id, bitmap);

	return sp_notif2_ffa_resp(test_source, own_id, res);
}
