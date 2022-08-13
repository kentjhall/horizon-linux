// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef _LINUX_HORIZON_RESULT_H
#define _LINUX_HORIZON_RESULT_H

#include <linux/types.h>
#include <linux/limits.h>

#ifdef CONFIG_CPU_BIG_ENDIAN
#error "Doesn't support big-endian"
#endif

#define HZN_ERROR_MODULE_KERNEL	1
#define HZN_ERROR_MODULE_HIPC	11

union hzn_result_code {
	u32 raw;

	struct {
		u32 module : 9;
		u32 description : 13;
	} bf;
};

#define HZN_RESULT_SUCCESS ((u32)0)
#define HZN_RESULT_UNKNOWN ((u32)U32_MAX)

// Switch kernel error codes (from yuzu)

#define HZN_RESULT_OUT_OF_SESSIONS (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 7}}).raw)
#define HZN_RESULT_INVALID_ARGUMENT (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 14}}).raw)
#define HZN_RESULT_NO_SYNCHRONIZATION_OBJECT (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 57}}).raw)
#define HZN_RESULT_TERMINATION_REQUESTED (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 59}}).raw)
#define HZN_RESULT_INVALID_SIZE (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 101}}).raw)
#define HZN_RESULT_INVALID_ADDRESS (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 102}}).raw)
#define HZN_RESULT_OUT_OF_RESOURCE (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 103}}).raw)
#define HZN_RESULT_OUT_OF_MEMORY (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 104}}).raw)
#define HZN_RESULT_OUT_OF_HANDLES (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 105}}).raw)
#define HZN_RESULT_INVALID_CURRENT_MEMORY (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 106}}).raw)
#define HZN_RESULT_INVALID_NEW_MEMORY_PERMISSION (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 108}}).raw)
#define HZN_RESULT_INVALID_MEMORY_REGION (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 110}}).raw)
#define HZN_RESULT_INVALID_PRIORITY (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 112}}).raw)
#define HZN_RESULT_INVALID_CORE_ID (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 113}}).raw)
#define HZN_RESULT_INVALID_HANDLE (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 114}}).raw)
#define HZN_RESULT_INVALID_POINTER (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 115}}).raw)
#define HZN_RESULT_INVALID_COMBINATION (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 116}}).raw)
#define HZN_RESULT_TIMED_OUT (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 117}}).raw)
#define HZN_RESULT_CANCELLED (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 118}}).raw)
#define HZN_RESULT_OUT_OF_RANGE (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 119}}).raw)
#define HZN_RESULT_INVALID_ENUM_VALUE (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 120}}).raw)
#define HZN_RESULT_NOT_FOUND (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 121}}).raw)
#define HZN_RESULT_BUSY (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 122}}).raw)
#define HZN_RESULT_SESSION_CLOSED (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 123}}).raw)
#define HZN_RESULT_INVALID_STATE (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 125}}).raw)
#define HZN_RESULT_RESERVED_USED (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 126}}).raw)
#define HZN_RESULT_PORT_CLOSED (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 131}}).raw)
#define HZN_RESULT_LIMIT_REACHED (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 132}}).raw)
#define HZN_RESULT_INVALID_ID (((union hzn_result_code){.bf={HZN_ERROR_MODULE_KERNEL, 519}}).raw)

#endif
