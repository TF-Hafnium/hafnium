/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/*
 * FF-A UUID of the SP First. Named as it is the first SP to boot.
 */
#define SP_SERVICE_FIRST_UUID {0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc}

/*
 * FF-A UUID of the SP Service Second. Named as it is the second service to
 * boot. UUID To be shared between S-EL1 and S-EL0 partition.
 */
#define SP_SERVICE_SECOND_UUID {0xa609f132, 0x6b4f, 0x4c14, 0x9489}

/*
 * FF-A UUID of the SP Service Third. Named as it is the third service to
 * boot.
 */
#define SP_SERVICE_THIRD_UUID {0x1df938ef, 0xe8b94490, 0x84967204, 0xab77f4a5}
