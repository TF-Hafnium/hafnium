/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "ffa_secure_partitions.h"

SERVICE_PARTITION_INFO_GET(service1, SERVICE1)
SERVICE_PARTITION_INFO_GET(service2, SERVICE2)
SERVICE_PARTITION_INFO_GET(service3, SERVICE3)

/**
 * Helper to setup mailbox for precondition functions.
 */
static struct mailbox_buffers get_precondition_mailbox(void)
{
	static struct mailbox_buffers mb = {.recv = NULL, .send = NULL};

	if (mb.send == NULL && mb.recv == NULL) {
		mb = set_up_mailbox();
	}

	return mb;
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an UP SP.
 */
bool service2_is_up_sp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return (service2_info->vcpu_count == 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an MP SP.
 */
bool service2_is_mp_sp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return (service2_info->vcpu_count > 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an S-EL0 SP.
 */
bool service2_is_el0(void)
{
	return (SP2_EL == 0);
}
