/*
 * vivid-trace.c - Add trace to resolve performance issues
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

#define CREATE_TRACE_POINTS
#include <trace/events/vivid.h>


void vivid_trace_single_msg(const char *devname,
				const char *message, int index)
{
	trace_vivid_buffer_flow(devname, message, index);
}

void vivid_trace_dual_msg(const char *devname, const char *msg1, int index1,
			const char *msg2, int index2)
{
	trace_vivid_copybuf(devname, msg1, index1, msg2, index2);
}

void vivid_trace_double_index(const char *devname, const char *msg1,
				int index1, int index2)
{
	trace_vivid_timer(devname, msg1, index1, index2);
}
