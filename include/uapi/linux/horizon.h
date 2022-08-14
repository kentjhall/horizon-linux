// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef _UAPI_LINUX_HORIZON_H__
#define _UAPI_LINUX_HORIZON_H__

#include <linux/types.h>

enum {
	HZN_SCTL_REGISTER_NAMED_SERVICE = 0,
	HZN_SCTL_GET_CMD,
	HZN_SCTL_PUT_CMD,
	HZN_SCTL_CREATE_SESSION_HANDLE,
	HZN_SCTL_CREATE_COPY_HANDLE,
	HZN_SCTL_GET_PROCESS_ID,
	HZN_SCTL_GET_TITLE_ID,
	HZN_SCTL_WRITE_BUFFER,
	HZN_SCTL_READ_BUFFER,
	HZN_SCTL_MAP_MEMORY,
	HZN_SCTL_WRITE_BUFFER_TO,
	HZN_SCTL_READ_BUFFER_FROM,
	HZN_SCTL_MEMWATCH_GET_CLEAR,
};

/*
 * Executable format stuff
 */

struct horizon_codeset_hdr {
	/// A single segment within a code set.
	struct {
		/// The byte offset that this segment is located at.
		__u64 offset;

		/// The address to map this segment to.
		__u64 addr;

		/// The size of this segment in bytes.
		__u32 size;
	}
	/// The segments that comprise this code set.
	segments[3];

	/// The size of the overall data that backs this code set.
	__u64 memory_size;
};

struct horizon_hdr {
	__u32 magic;
	__u64 title_id;
	__u8 ideal_core;
	__u8 is_64bit;
	__u8 address_space_type;
	__u32 system_resource_size;
	__s32 main_thread_priority;
	__u32 num_codesets;
	struct horizon_codeset_hdr codesets[];
};

#define HORIZON_MAGIC 0x70417020

#endif
