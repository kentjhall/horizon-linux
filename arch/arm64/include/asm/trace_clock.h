/*
 * Copyright (c) 2018, NVIDIA CORPORATION.  All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _ASM_ARM64_TRACE_CLOCK_H
#define _ASM_ARM64_TRACE_CLOCK_H

#ifdef CONFIG_ARM_ARCH_TIMER

extern u64 trace_arm64_tsc(void);

#define ARCH_TRACE_CLOCKS { trace_arm64_tsc, "arm64-tsc", .in_ns = 0 },

#else

#define ARCH_TRACE_CLOCKS

#endif

#endif
