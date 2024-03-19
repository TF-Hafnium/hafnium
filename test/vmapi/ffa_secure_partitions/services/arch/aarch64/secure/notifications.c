/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"

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

	return sp_check_ffa_return_resp(test_source, own_id, res);
}

struct ffa_value sp_notif_unbind_cmd(ffa_id_t test_source,
				     ffa_id_t notif_sender,
				     ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	dlog_verbose("Unbind notifications %lx, from sender: %x\n", bitmap,
		     notif_sender);

	res = ffa_notification_unbind(notif_sender, own_id, bitmap);
	return sp_check_ffa_return_resp(test_source, own_id, res);
}
