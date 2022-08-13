/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _MEMWATCH_H
#define _MEMWATCH_H

#include <linux/sched.h>
#include <linux/types.h>

/* memwatch operations */
#define MEMWATCH_SD_GET			0x1
#define MEMWATCH_SD_CLEAR		0x2
#define MEMWATCH_SD_NO_REUSED_REGIONS	0x4

long do_process_memwatch(struct task_struct *task, unsigned long start, int len,
			unsigned int flags, loff_t __user *vec, int vec_len);

#endif

