/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/sve.h"

#include "hf/api.h"
#include "hf/bits.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa/vm.h"
#include "hf/ffa_internal.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

#include "./spmc/vm.h"
