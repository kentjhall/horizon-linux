// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#include <uapi/linux/futex.h>
#include <linux/sched.h>

#define HANDLE_WAIT_MASK ((u32)(1u << 30))

#undef FUTEX_WAITERS
#define FUTEX_WAITERS HANDLE_WAIT_MASK

#undef FUTEX_OWNER_DIED
#define FUTEX_OWNER_DIED 0

#undef FUTEX_TID_MASK
#define FUTEX_TID_MASK (0xFFFFFFFF - HANDLE_WAIT_MASK)

#define exit_pi_state_list horizon_exit_pi_state_list
#define handle_futex_death horizon_handle_futex_death
#define exit_robust_list horizon_exit_robust_list
#define do_futex do_horizon_futex

#define HORIZON_FUTEX

#include "futex.c"
