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

#define futex_exit_recursive horizon_futex_exit_recursive
#define futex_exit_release horizon_futex_exit_release
#define do_futex do_horizon_futex

#define HORIZON_FUTEX

#include "futex.c"
