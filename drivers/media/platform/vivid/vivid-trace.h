/*
 * vivid-trace.h - Add trace to resolve performance issues
 *
 * Copyright (c) 2017, NVIDIA CORPORATION, All rights reserved.
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

#ifndef __VIVID_TRACE_H_
#define __VIVID_TRACE_H_

void vivid_trace_single_msg(const char *devname,
				const char *message, int index);
void vivid_trace_dual_msg(const char *devname, const char *msg1, int index1,
			const char *msg2, int index2);
void vivid_trace_double_index(const char *devname, const char *msg1,
				int index1, int index2);
#endif
