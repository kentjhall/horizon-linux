// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sizes.h>
#include <linux/limits.h>
#include <linux/sched/mm.h>
#include <linux/build_bug.h>
#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/hrtimer.h>
#include <linux/random.h>
#include <linux/shmem_fs.h>
#include <linux/poll.h>
#include <linux/futex.h>
#include <linux/memwatch.h>
#include <asm/futex.h>
#include <linux/horizon.h>
#include <linux/horizon/handle_table.h>
#include <linux/horizon/result.h>

#define REQUEST_HANDLER(req) \
	((struct hzn_session_handler *)req->handler_file->private_data)

/*
 * horizon_servctl is actually set up as a normal Linux system call (not for horizon
 * tasks), so it needs to return negative values on error, but these values are
 * result codes that horizon tasks recognize rather than typical errno values (for
 * convenience, since these will often be relayed back to horizon tasks by the
 * service).
 *
 * HZN_SCTL_REGISTER_NAMED_SERVICE (const char *name)
 * 	- registers current task as named service for horizon task to connect to
 * 	- returns 0 on success
 *
 * HZN_SCTL_GET_CMD (unsigned long *session_id)
 * 	- session id is set based on next request in the queue
 * 	- sets horizon task for subsequent operations in session
 * 	  (until HZN_SCTL_PUT_CMD)
 * 	- returns command buffer, or 0 in case of close request, on success
 *
 * HZN_SCTL_PUT_CMD (unsigned long session_id, bool is_domain)
 * 	- sets kernel's session status based on arguments
 * 	- notifies requesting thread and cleans up request
 * 	- returns 0 on success
 *
 * HZN_SCTL_CREATE_SESSION_HANDLE (pid_t pid, unsigned long session_id)
 * 	- pid = -1 means session is created without handler
 * 	- pid = 0 means session is created with current handler process
 * 	- pid > 0 means session is created with handler at specified pid
 * 	- session id is set as specified; may be 0, in which case the
 * 	  service will fill it later
 * 	- returns session handle (for horizon task) on success
 *
 * HZN_SCTL_CREATE_COPY_HANDLE (int fd)
 * 	- creates handle for horizon task from passed fd
 * 	- returns newly created handle on success
 *
 * HZN_SCTL_GET_PROCESS_ID ()
 * 	- returns pid of horizon task
 *
 * HZN_SCTL_GET_TITLE_ID () 
 * 	- returns title id of horizon task
 *
 * HZN_SCTL_READ_BUFFER 
   HZN_SCTL_WRITE_BUFFER (unsigned long there, void __user *here, size_t len)
 *	- reads/writes len bytes from/to horizon task
 *	- returns 0 on success
 *
 * HZN_SCTL_READ_BUFFER_FROM
   HZN_SCTL_WRITE_BUFFER_TO (unsigned long there, void __user *here,
   			     size_t len, pid_t pid)
 *	- reads/writes len bytes from/to task at specified pid
 *	- returns 0 on success
 *
 * HZN_SCTL_MAP_MEMORY (unsigned long there, unsigned long here, size_t len)
 * 	- maps len byte region from horizon task
 * 	- returns 0 on success
 *
 * HZN_SCTL_MEMWATCH_GET_CLEAR (pid_t pid, unsigned long addr, size_t len,
 * 				loff_t __user *vec, size_t vec_len)
 * 	- checks / clears soft dirty for memory of task at specified pid
 * 	- copies out offsets of dirty pages to vec
 * 	- returns number of dirty pages on success
 */

#define SERVCTL_RET(result) \
	(-(long)(result))

SYSCALL_DEFINE6(horizon_servctl, unsigned int, cmd,
	        unsigned long, arg1, unsigned long, arg2,
	        unsigned long, arg3, unsigned long, arg4,
	        unsigned long, arg5)
{
	switch (cmd) {
	case HZN_SCTL_REGISTER_NAMED_SERVICE:
	{
		struct hzn_named_service *iter, *new;
		char portname[HZN_PORT_NAME_MAX_LENGTH + 1];

		if (strncpy_from_user(portname, (const char *)arg1,
				      sizeof(portname)) < 0)
			return SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
		portname[sizeof(portname)-1] = 0;

		// allocated in case new entry is needed
		new = kmalloc(sizeof(struct hzn_named_service), GFP_KERNEL);
		if (new == NULL)
			return SERVCTL_RET(HZN_RESULT_OUT_OF_MEMORY);

		spin_lock(&hzn_named_services_lock);

		// If already in the list, replace existing entry
		list_for_each_entry(iter, &hzn_named_services, entry) {
			if (strcmp(iter->name, portname) == 0) {
				kfree(new);
				new = NULL;
				put_task_struct(iter->service);
				iter->service = get_task_struct(current);
				break;
			}
		}

		// Otherwise add to list
		if (new) {
			strncpy(new->name, portname, sizeof(new->name));
			new->name[sizeof(new->name)-1] = 0;
			new->service = get_task_struct(current);
			list_add_tail(&new->entry, &hzn_named_services);
		}

		spin_unlock(&hzn_named_services_lock);

		return 0;
	}
	case HZN_SCTL_GET_CMD:
	{
		unsigned long cmd_addr;
		struct hzn_session_request *request;

		// shouldn't already be handling a command
		if (current->hzn_cmd_addr)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		// wait for request
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock(&current->hzn_requests_lock);
		while (list_empty(&current->hzn_requests)) {
			spin_unlock(&current->hzn_requests_lock);
			if (signal_pending(current)) {
				__set_current_state(TASK_RUNNING);
				return SERVCTL_RET(HZN_RESULT_CANCELLED);
			}
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);
			spin_lock(&current->hzn_requests_lock);
		}
		__set_current_state(TASK_RUNNING);

		// next request in the queue
		request = list_first_entry(&current->hzn_requests,
		                           struct hzn_session_request,
					   entry);

		// if this is a close command, we just cleanup and return 0
		// (no future HZN_SCTL_PUT_CMD is expected)
		if (request->cmd == NULL) {
			list_del(&request->entry);
			spin_unlock(&current->hzn_requests_lock);
			if (put_user(request->close_session_id, (unsigned long *)arg1))
				return SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
			hzn_session_request_free(request);
			return 0;
		}
		spin_unlock(&current->hzn_requests_lock);

		// put session handler id to argument pointer
		if (put_user(REQUEST_HANDLER(request)->id, (unsigned long *)arg1))
			return SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);

		// map for command
		cmd_addr = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
		if (IS_ERR_VALUE(cmd_addr)) {
			pr_err("horizon_servctl HZN_SCTL_GET_CMD: vm_mmap failed\n");
			return SERVCTL_RET(HZN_RESULT_OUT_OF_MEMORY);
		}

		// copy to command page
		if (copy_to_user((void *)cmd_addr, page_to_virt(request->cmd), PAGE_SIZE)) {
			vm_munmap(cmd_addr, PAGE_SIZE);
			return SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
		}

		current->hzn_cmd_addr = cmd_addr;

		// just a convenience pointer so that we don't need to grab
		// hzn_requests_lock to get the current request
		current->hzn_session_request = request;

		return cmd_addr;
	}
	case HZN_SCTL_PUT_CMD:
	{
		if (!current->hzn_cmd_addr)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		// these should always be set when hzn_cmd_addr is set
		BUG_ON(!current->hzn_session_request);
		BUG_ON(!current->hzn_session_request->cmd);

		// copy out the command page
		if (copy_from_user(page_to_virt(current->hzn_session_request->cmd),
		                   (void *)current->hzn_cmd_addr, PAGE_SIZE))
			return SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);

		// unmap the command
		vm_munmap(current->hzn_cmd_addr, PAGE_SIZE);
		current->hzn_cmd_addr = 0;

		// pull the handled request out of the queue
		spin_lock(&current->hzn_requests_lock);
		list_del(&current->hzn_session_request->entry);
		spin_unlock(&current->hzn_requests_lock);

		// update handler status
		// (handler pointer should be valid until subsequent
		// put_files_struct call by hzn_session_request_free)
		REQUEST_HANDLER(current->hzn_session_request)->id = arg1;
		REQUEST_HANDLER(current->hzn_session_request)->is_domain = arg2;

		// notify the requesting thread
		atomic_set(&current->hzn_session_request->requester->hzn_request_state,
		           HZN_SESSION_REQUEST_HANDLED);
		wake_up_process(current->hzn_session_request->requester);

		// cleanup the request
		hzn_session_request_free(current->hzn_session_request);
		current->hzn_session_request = NULL;

		return 0;
	}
	case HZN_SCTL_CREATE_SESSION_HANDLE:
	{
		struct files_struct *requester_files;
		struct hzn_session_handler *handler;
		u32 handle;

		if (!current->hzn_session_request)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		// allocate for session
		handler = kmalloc(sizeof(struct hzn_session_handler), GFP_KERNEL);
		if (handler == NULL)
			return SERVCTL_RET(HZN_RESULT_OUT_OF_MEMORY);

		// set session fields based on arguments
		switch (arg1) {
		case -1:
			handler->service = NULL;
			break;
		case 0:
			handler->service = get_task_pid(current, PIDTYPE_PID);
			break;
		default:
			if (!(handler->service = find_get_pid(arg1))) {
				kfree(handler);
				return SERVCTL_RET(HZN_RESULT_NOT_FOUND);
			}
		}
		handler->id = arg2;
		handler->is_domain = false;

		if (!(requester_files = get_files_struct(current->hzn_session_request->requester))) {
			if (handler->service)
				put_pid(handler->service);
			kfree(handler);
			return SERVCTL_RET(HZN_RESULT_SESSION_CLOSED);
		}

		// add to the handle table of the requesting thread
		handle = hzn_handle_table_add(requester_files, handler, &hzn_session_fops);
		put_files_struct(requester_files);
		if (handle == HZN_INVALID_HANDLE) {
			if (handler->service)
				put_pid(handler->service);
			kfree(handler);
			return SERVCTL_RET(HZN_RESULT_OUT_OF_HANDLES);
		}

		return handle;
	}
	case HZN_SCTL_CREATE_COPY_HANDLE:
	{
		struct files_struct *requester_files;
		struct file *file;
		u32 handle;

		if (!current->hzn_session_request)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		file = fget_raw(arg1);
		if (file == NULL)
			return SERVCTL_RET(HZN_RESULT_INVALID_HANDLE);

		if (!(requester_files = get_files_struct(current->hzn_session_request->requester))) {
			fput(file);
			return SERVCTL_RET(HZN_RESULT_SESSION_CLOSED);
		}

		// add to the handle table of the requesting thread
		handle = __hzn_handle_table_add(requester_files, file);
		put_files_struct(requester_files);
		if (handle == HZN_INVALID_HANDLE) {
			fput(file);
			return SERVCTL_RET(HZN_RESULT_OUT_OF_HANDLES);
		}

		return handle;

	}
	case HZN_SCTL_GET_PROCESS_ID:
	{
		if (!current->hzn_session_request)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		return task_pid_nr(current->hzn_session_request->requester);
	}
	case HZN_SCTL_GET_TITLE_ID:
	{
		if (!current->hzn_session_request)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		return current->hzn_session_request->requester->hzn_title_id;
	}
	case HZN_SCTL_READ_BUFFER:
	case HZN_SCTL_WRITE_BUFFER:
	case HZN_SCTL_READ_BUFFER_FROM:
	case HZN_SCTL_WRITE_BUFFER_TO:
	{
		struct task_struct *tsk;
		struct pid *pid;
		struct page **pages;
		struct mm_struct *requester_mm;
		void *user_ptr;
		size_t i;
		size_t page_off = arg1 & ~PAGE_MASK;
		unsigned long nr_pages = (page_off + arg3 + PAGE_SIZE - 1) / PAGE_SIZE;
		int locked = 1;
		long ret = 0;

		switch (cmd) {
		case HZN_SCTL_READ_BUFFER_FROM:
		case HZN_SCTL_WRITE_BUFFER_TO:
			pid = find_get_pid(arg4);
			tsk = get_pid_task(pid, PIDTYPE_PID);
			put_pid(pid);
			if (!tsk)
				return SERVCTL_RET(HZN_RESULT_INVALID_ID);
			break;
		default:
			if (!current->hzn_session_request)
				return SERVCTL_RET(HZN_RESULT_INVALID_STATE);
			tsk = current->hzn_session_request->requester;
		}

		if (arg3 == 0)
			goto out;

		pages = kmalloc(sizeof(struct page *) * nr_pages, GFP_KERNEL);
		if (pages == NULL) {
			ret = SERVCTL_RET(HZN_RESULT_OUT_OF_MEMORY);
			goto out;
		}

		// get the requester's mm
		requester_mm = get_task_mm(tsk);
		if (requester_mm == NULL) {
			kfree(pages);
			ret = SERVCTL_RET(HZN_RESULT_SESSION_CLOSED);
			goto out;
		}

		// get the requester's pages
		mmap_read_lock(requester_mm);
		ret = get_user_pages_remote(requester_mm, arg1, nr_pages,
				            cmd == HZN_SCTL_WRITE_BUFFER ? FOLL_WRITE : 0,
					    pages, NULL, &locked);
		if (locked)
			mmap_read_unlock(requester_mm);
		mmput(requester_mm);

		if (ret != nr_pages) {
			for (i = 0; (long)i < ret; ++i)
				put_page(pages[i]);
			kfree(pages);
			ret = SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
			goto out;
		}

		// copy to/from pages to/from the service's specified address
		ret = 0;
		user_ptr = (void *)arg2;
		for (i = 0; i < nr_pages; ++i) {
			size_t to_copy = min((unsigned long)arg3 - (user_ptr - (void *)arg2), PAGE_SIZE - page_off);
			if (cmd == HZN_SCTL_WRITE_BUFFER || cmd == HZN_SCTL_WRITE_BUFFER_TO) {
				if (copy_from_user(kmap(pages[i]) + page_off, user_ptr, to_copy)) {
					ret = SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
					kunmap(pages[i]);
					break;
				}
				kunmap(pages[i]);
				set_page_dirty_lock(pages[i]);
			}
			else {
				if (copy_to_user(user_ptr, kmap(pages[i]) + page_off, to_copy)) {
					ret = SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
					kunmap(pages[i]);
					break;
				}
				kunmap(pages[i]);
			}
			page_off = 0;
			user_ptr += to_copy;
		}
		WARN_ON(!ret && user_ptr - (void *)arg2 != arg3);

		for (i = 0; i < nr_pages; ++i)
			put_page(pages[i]);
		kfree(pages);

out:
		switch (cmd) {
		case HZN_SCTL_WRITE_BUFFER_TO:
		case HZN_SCTL_READ_BUFFER_FROM:
			put_task_struct(tsk);
		}
		return ret;
	}
	case HZN_SCTL_MAP_MEMORY:
	{
		struct file *file = NULL;
		struct page **pages;
		struct vm_area_struct *vma;
		struct mm_struct *requester_mm, *current_mm;
		struct task_rss_stat current_rss_stat;
		size_t i;
		size_t page_off = arg1 & ~PAGE_MASK;
		unsigned long nr_pages = (page_off + arg3 + PAGE_SIZE - 1) / PAGE_SIZE;
		bool succ = true;
		unsigned long existing_off = 0;
		int locked = 1;
		loff_t pos =  0;
		long ret = 0;

		if (!current->hzn_session_request)
			return SERVCTL_RET(HZN_RESULT_INVALID_STATE);

		if (arg3 == 0)
			return SERVCTL_RET(HZN_RESULT_INVALID_SIZE);

		pages = kmalloc(sizeof(struct page *) * nr_pages, GFP_KERNEL);
		if (pages == NULL)
			return SERVCTL_RET(HZN_RESULT_OUT_OF_MEMORY);

		// get the requester's mm
		requester_mm = get_task_mm(current->hzn_session_request->requester);
		if (requester_mm == NULL) {
			kfree(pages);
			return SERVCTL_RET(HZN_RESULT_SESSION_CLOSED);
		}

		mmap_read_lock(requester_mm);

		// check for existing shared mapping that we can take
		vma = find_vma(requester_mm, arg1);
		if (vma && arg1 >= vma->vm_start && (vma->vm_flags & VM_SHARED) && vma->vm_file) {
			// we have enough, just steal what's there
			file = get_file(vma->vm_file);
			existing_off = (vma->vm_pgoff * PAGE_SIZE) + arg1 - vma->vm_start;
			if (arg1 + arg3 > vma->vm_end) {
				WARN_ON(vfs_truncate(&file->f_path, existing_off + arg3) < 0);
				pos = existing_off;
			}
			else {
				mmap_read_unlock(requester_mm);
				mmput(requester_mm);
				kfree(pages);
				goto map_service;
			}
		}

		// get the requester's pages
		ret = get_user_pages_remote(requester_mm, arg1, nr_pages, 0,
					    pages, NULL, &locked);
		if (locked)
			mmap_read_unlock(requester_mm);

		if (ret != nr_pages) {
			for (i = 0; (long)i < ret; ++i)
				put_page(pages[i]);
			kfree(pages);
			mmput(requester_mm);
			return SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
		}

		if (!file) {
			// open shared memory file
			file = shmem_file_setup("horizon_servctl_shared_mem", arg3, 0);
			if (IS_ERR(file)) {
				for (i = 0; i < nr_pages; ++i)
					put_page(pages[i]);
				kfree(pages);
				mmput(requester_mm);
				return SERVCTL_RET(HZN_RESULT_OUT_OF_MEMORY);
			}
		}

		// write out requester's existing memory to shared mem
		ret = 0;
		for (i = 0; i < nr_pages; ++i) {
			size_t to_copy = min((unsigned long)(arg3 - (pos - existing_off)), PAGE_SIZE - page_off);
			ssize_t w;
			WARN(!(page_off + to_copy <= PAGE_SIZE),
			     "page_off=%zu, nr_pages=%lu, arg3=0x%lx, offset=%zu, to_copy=%zu\n",
			     page_off, nr_pages, arg3, page_off, to_copy);
			w = kernel_write(file, kmap(pages[i]) + page_off, to_copy, &pos);
			kunmap(pages[i]);
			if (w == -1) {
				ret = SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS);
				break;
			}
			page_off = 0;
		}
		WARN_ON(!ret && pos - existing_off != arg3);

		for (i = 0; i < nr_pages; ++i)
			put_page(pages[i]);
		kfree(pages);
		if (ret != 0) {
			mmput(requester_mm);
			fput(file);
			return ret;
		}

		// a hack to map to requester's space, by saving/restoring the
		// necessary state to trick vm_mmap into thinking we're them
		//
		// NOTE: messing with rss_stat unprotected seems suss, but in
		// *theory* it's fine since the requester should just be
		// sleeping while we process its synchronous request
		current_rss_stat = current->rss_stat;
		current->rss_stat = current->hzn_session_request->requester->rss_stat;
		task_lock(current);
		current_mm = current->mm;
		current->mm = requester_mm;
		task_unlock(current);
		// get_task_mm() is modified to (hopefully) ensure we don't
		// accidentally expose the wrong mm
		succ = vm_mmap(file, arg1, arg3, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, existing_off) == arg1;
		task_lock(current);
		WARN_ON(!current->mm); // pretty sure this is impossible since we don't exit
		current->mm = current_mm;
		task_unlock(current);
		current->hzn_session_request->requester->rss_stat = current->rss_stat;
		current->rss_stat = current_rss_stat;

		mmput(requester_mm);

map_service:
		// map into service's space
		succ = succ &&
		       vm_mmap(file, arg2, arg3, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, existing_off) == arg2;
		fput(file);
		return SERVCTL_RET(succ ? 0 : HZN_RESULT_INVALID_ADDRESS);
	}
	case HZN_SCTL_MEMWATCH_GET_CLEAR:
	{
		struct pid *pid;
		struct task_struct *tsk;
		long ret;

		pid = find_get_pid(arg1);
		tsk = get_pid_task(pid, PIDTYPE_PID);
		put_pid(pid);
		if (!tsk)
			return SERVCTL_RET(HZN_RESULT_INVALID_ID);

		ret = do_process_memwatch(tsk, arg2, arg3,
					  MEMWATCH_SD_NO_REUSED_REGIONS | 
					  MEMWATCH_SD_GET | MEMWATCH_SD_CLEAR,
					  (loff_t __user *)arg4, arg5);

		put_task_struct(tsk);
		return ret < 0 ? SERVCTL_RET(HZN_RESULT_INVALID_ADDRESS) : ret;
	}
	}

	return SERVCTL_RET(HZN_RESULT_INVALID_ARGUMENT);
}
