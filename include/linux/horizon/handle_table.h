// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef _LINUX_HORIZON_HANDLE_TABLE_H
#define _LINUX_HORIZON_HANDLE_TABLE_H

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/anon_inodes.h>

#define HZN_INVALID_HANDLE ((u32)0)

#define HZN_PSEUDO_HANDLE_CURRENT_THREAD  0xFFFF8000
#define HZN_PSEUDO_HANDLE_CURRENT_PROCESS 0xFFFF8001

#define hzn_is_pseudo_handle(handle)			\
    (handle == HZN_PSEUDO_HANDLE_CURRENT_THREAD ||	\
     handle == HZN_PSEUDO_HANDLE_CURRENT_PROCESS)

#define hzn_handle_to_fd(handle) ((handle)-1) // handle decremented for HZN_INVALID_HANDLE offset

/*
 * To use this interface: 'files' must either be from current, or it must have
 * been grabbed by get_files_struct().
 */

// must be released later by fput()
#define __hzn_handle_table_get(handle) \
	fget_raw(hzn_handle_to_fd(handle)) 

#define hzn_handle_table_get(handle, expected_fops)		\
({								\
	struct file *__file = __hzn_handle_table_get(handle);	\
	if (__file && __file->f_op != (expected_fops)) {	\
		fput(__file);					\
		__file = NULL;					\
	}							\
	__file;							\
})

#define hzn_handle_table_remove(files, handle) \
	({ __close_fd((files), hzn_handle_to_fd(handle)) < 0; })

// This consumes the file reference, so its reference count should be bumped.
static inline u32 __hzn_handle_table_add(struct files_struct *files, struct file *file)
{
	int fd;

	fd = __alloc_fd(files, 0, rlimit(RLIMIT_NOFILE), 0);
	if (fd < 0) {
		pr_err("horizon KHandleTable: __alloc_fd failed\n");
		return HZN_INVALID_HANDLE;
	}

	__fd_install(files, fd, file);
	return fd + 1; // handle incremented for HZN_INVALID_HANDLE offset
}

static inline u32 hzn_handle_table_add(struct files_struct *files,
                                      void *obj, const struct file_operations *fops)
{
	struct file *file;
	u32 handle;

	file = anon_inode_getfile("[horizon handle]", fops, obj, 0);
	if (IS_ERR(file)) {
		pr_err("horizon KHandleTable: anon_inode_getfile failed\n");
		return HZN_INVALID_HANDLE;
	}

	if ((handle = __hzn_handle_table_add(files, file)) == HZN_INVALID_HANDLE)
		fput(file);

	return handle;
}

extern const struct file_operations hzn_thread_fops;
extern const struct file_operations hzn_session_fops;

#endif
