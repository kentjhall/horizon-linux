// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef _LINUX_HORIZON_TYPES_H
#define _LINUX_HORIZON_TYPES_H

enum hzn_memory_attribute {
	HZN_MEMORY_ATTRIBUTE_LOCKED = (1 << 0),
	HZN_MEMORY_ATTRIBUTE_IPC_LOCKED = (1 << 1),
	HZN_MEMORY_ATTRIBUTE_DEVICE_SHARED = (1 << 2),
	HZN_MEMORY_ATTRIBUTE_UNCACHED = (1 << 3),
};

enum hzn_memory_state {
	HZN_MEMORY_STATE_FREE = 0x00,
	HZN_MEMORY_STATE_IO = 0x01,
	HZN_MEMORY_STATE_STATIC = 0x02,
	HZN_MEMORY_STATE_CODE = 0x03,
	HZN_MEMORY_STATE_CODE_DATA = 0x04,
	HZN_MEMORY_STATE_NORMAL = 0x05,
	HZN_MEMORY_STATE_SHARED = 0x06,
	HZN_MEMORY_STATE_ALIAS = 0x07,
	HZN_MEMORY_STATE_ALIAS_CODE = 0x08,
	HZN_MEMORY_STATE_ALIAS_CODE_DATA = 0x09,
	HZN_MEMORY_STATE_IPC = 0x0A,
	HZN_MEMORY_STATE_STACK = 0x0B,
	HZN_MEMORY_STATE_THREAD_LOCAL = 0x0C,
	HZN_MEMORY_STATE_TRANSFERRED = 0x0D,
	HZN_MEMORY_STATE_SHARED_TRANSFERRED = 0x0E,
	HZN_MEMORY_STATE_SHARED_CODE = 0x0F,
	HZN_MEMORY_STATE_INACCESSIBLE = 0x10,
	HZN_MEMORY_STATE_NON_SECURE_IPC = 0x11,
	HZN_MEMORY_STATE_NON_DEVICE_IPC = 0x12,
	HZN_MEMORY_STATE_KERNEL = 0x13,
	HZN_MEMORY_STATE_GENERATED_CODE = 0x14,
	HZN_MEMORY_STATE_CODE_OUT = 0x15,
};

enum hzn_memory_permission {
	HZN_MEMORY_PERMISSION_NONE = (0 << 0),
	HZN_MEMORY_PERMISSION_READ = (1 << 0),
	HZN_MEMORY_PERMISSION_WRITE = (1 << 1),
	HZN_MEMORY_PERMISSION_EXECUTE = (1 << 2),
	HZN_MEMORY_PERMISSION_READ_WRITE = HZN_MEMORY_PERMISSION_READ | HZN_MEMORY_PERMISSION_WRITE,
	HZN_MEMORY_PERMISSION_READ_EXECUTE = HZN_MEMORY_PERMISSION_READ | HZN_MEMORY_PERMISSION_EXECUTE,
	HZN_MEMORY_PERMISSION_DONT_CARE = (1 << 28),
};

struct hzn_memory_info {
	u64 addr;
	u64 size;
	enum hzn_memory_state state;
	enum hzn_memory_attribute attr;
	enum hzn_memory_permission perm;
	u32 ipc_refcount;
	u32 device_refcount;
	u32 padding;
};

enum hzn_thread_activity {
	HZN_THREAD_ACTIVITY_RUNNABLE = 0,
	HZN_THREAD_ACTIVITY_PAUSED = 1,
};

struct hzn_thread_context_64 {
	u64 cpu_registers[31];
	u64 sp;
	u64 pc;
	u32 pstate;
	u8 padding[4];
	__uint128_t vector_registers[32];
	u32 fpcr;
	u32 fpsr;
	u64 tpidr;
};
// Internally within the kernel, it expects the AArch64 version of the
// thread context to be 800 bytes in size.
__used static void ___hzn_thread_context_64_assert(void)
{
	BUILD_BUG_ON(sizeof(struct hzn_thread_context_64) != 0x320);
}

#endif
