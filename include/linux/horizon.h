// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef _LINUX_HORIZON_H
#define _LINUX_HORIZON_H

#include <linux/sizes.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <asm/processor.h>
#include <uapi/linux/horizon.h>

enum hzn_address_space_type {
	HZN_IS_32_BIT = 0,
	HZN_IS_36_BIT = 1,
	HZN_IS_32_BIT_NO_MAP = 2,
	HZN_IS_39_BIT = 3,
};

#define HZN_HEAP_REGION_SIZE(tsk)						\
	((tsk)->hzn_address_space_type == HZN_IS_39_BIT ? (SZ_4G + SZ_2G) :	\
	((tsk)->hzn_address_space_type == HZN_IS_36_BIT ? (SZ_4G + SZ_2G) : SZ_1G))
#define HZN_ALIAS_CODE_REGION_SIZE(tsk)						\
	((tsk)->hzn_address_space_type == HZN_IS_39_BIT ? (SZ_512G - SZ_128M) :	\
	((tsk)->hzn_address_space_type == HZN_IS_36_BIT ? (SZ_64G - SZ_2G) : (SZ_4G - SZ_1G)))
#define HZN_ALIAS_REGION_SIZE(tsk)					\
	((tsk)->hzn_address_space_type == HZN_IS_39_BIT ? SZ_64G :	\
	((tsk)->hzn_address_space_type == HZN_IS_36_BIT ? (SZ_4G + SZ_2G) : SZ_1G))
#define HZN_STACK_REGION_SIZE(tsk)					\
	((tsk)->hzn_address_space_type == HZN_IS_39_BIT ? SZ_2G : 0)	\

#define HZN_TLS_AREA_START(tsk) \
	((tsk)->thread.uw.tp_value)
#define HZN_TLS_AREA_END(tsk) \
	(HZN_TLS_AREA_START(tsk) + PAGE_SIZE)
#define HZN_ALIAS_CODE_REGION_START(tsk) \
	((tsk)->mm->hzn_alias_code_start)
#define HZN_ALIAS_CODE_REGION_END(tsk) \
	(HZN_ALIAS_CODE_REGION_START(tsk) + HZN_ALIAS_CODE_REGION_SIZE(tsk))
#define HZN_ALIAS_REGION_START(tsk) \
	((tsk)->mm->hzn_alias_start)
#define HZN_ALIAS_REGION_END(tsk) \
	(HZN_ALIAS_REGION_START(tsk) + HZN_ALIAS_REGION_SIZE(tsk))

#define HZN_ADDRESS_SPACE_START 0
#define HZN_ADDRESS_SPACE_END(tsk) TASK_SIZE_OF(tsk)

struct task_struct;
struct page;

struct hzn_session_handler {
	struct pid *service;
	unsigned long id;
	bool is_domain;
};

struct hzn_session_request {
	union {
		struct task_struct *requester;
		unsigned long close_session_id;
	};
	struct page *cmd;
	struct file *handler_file;
	struct list_head entry;
};

#define hzn_session_request_free(req)				\
do {								\
	if ((req)->cmd) { /* not a close command */		\
		put_page((req)->cmd);				\
		fput((req)->handler_file);			\
		put_task_struct((req)->requester);		\
	}							\
	kfree(req);						\
} while(0)

#define HZN_SESSION_REQUEST_PENDING 0
#define HZN_SESSION_REQUEST_HANDLED 1
#define HZN_SESSION_REQUEST_FAILED  2

#define HZN_PORT_NAME_MAX_LENGTH 11

struct hzn_named_service {
	char name[HZN_PORT_NAME_MAX_LENGTH + 1];
	struct task_struct *service;
	struct list_head entry;
};

extern struct list_head hzn_named_services;
extern spinlock_t hzn_named_services_lock;

/*
 * Executable format stuff
 */

#define horizon_hdr_check_arch(hdr) \
	((hdr)->is_64bit)

#define horizon_set_personality()					\
({									\
	clear_thread_flag(TIF_32BIT);					\
	current->personality &= ~READ_IMPLIES_EXEC;			\
})

#endif
