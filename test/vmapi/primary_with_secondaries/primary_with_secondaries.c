/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

SERVICE_PARTITION_INFO_GET(service1, SERVICE1)
SERVICE_PARTITION_INFO_GET(service2, SERVICE2)
SERVICE_PARTITION_INFO_GET(service3, SERVICE3)

/*
 * The following is a precondition function, for the current system set-up.
 * This is currently being used to skip memory sharing tests, when
 * the service is an SP.
 */
bool service1_is_vm(void)
{
	struct ffa_partition_info *service1_info = service1();
	return IS_VM_ID(service1_info->vm_id);
}
