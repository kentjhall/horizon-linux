// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef _LINUX_SCHED_HORIZON_H
#define _LINUX_SCHED_HORIZON_H

#include <linux/types.h>

#define HZN_LOWEST_THREAD_PRIORITY 63
#define HZN_HIGHEST_THREAD_PRIORITY 0

enum hzn_yield_type {
	HZN_YIELD_TYPE_WITHOUT_CORE_MIGRATION = -2,
	HZN_YIELD_TYPE_WITH_CORE_MIGRATION = -1,
	HZN_YIELD_TYPE_TO_ANY_THREAD = 0,

	HZN_YIELD_NONE = 1,
};

struct task_struct;

extern int get_hzn_priority(struct task_struct *p);

extern bool set_hzn_priority(struct task_struct *p, int priority);

#endif
