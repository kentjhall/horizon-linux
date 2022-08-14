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
#include <asm/futex.h>
#include <linux/sched/horizon.h>
#include <linux/horizon.h>
#include <linux/horizon/handle_table.h>
#include <linux/horizon/result.h>
#include <linux/horizon/types.h>

static inline struct task_struct *get_handle_task(u32 thread_handle)
{
	struct file *thread_file =
		hzn_handle_table_get(thread_handle, &hzn_thread_fops);
	struct task_struct *tsk;
	if (!thread_file)
		return NULL;
	tsk = get_pid_task(thread_file->private_data, PIDTYPE_PID);
	fput(thread_file);
	return tsk;
}

HSYSCALL_DEFINE2(set_heap_size, long, __unused, u64, size)
{
	unsigned long start_brk;
	unsigned long new_brk;
	// Size must be a multiple of 0x200000 (2MB).
	if ((size % 0x200000) != 0 || size > HZN_HEAP_REGION_SIZE(current))
		return HZN_RESULT_INVALID_SIZE;

	BUG_ON(!(current->mm));

	spin_lock(&current->mm->arg_lock);
	start_brk = current->mm->start_brk;
	spin_unlock(&current->mm->arg_lock);
	new_brk = start_brk + size;
	if (do_brk(new_brk) != new_brk)
		return HZN_RESULT_OUT_OF_MEMORY;

	HSYSCALL_OUT(start_brk);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE4(set_memory_attribute, unsigned long, addr, u64, size,
		 u32, mask, u32, value)
{
	enum memory_attribute attributes = mask | value;

	// must be page-aligned
	if (addr & ~PAGE_MASK)
		return HZN_RESULT_INVALID_ADDRESS;

	// size must be non-zero and page-aligned
	if (size == 0 || size % PAGE_SIZE != 0)
		return HZN_RESULT_INVALID_ADDRESS;

	// mask/attribute must match, and must be to set uncached
	if (attributes != mask ||
	    (attributes | HZN_MEMORY_ATTRIBUTE_UNCACHED) != HZN_MEMORY_ATTRIBUTE_UNCACHED)
		return HZN_RESULT_INVALID_COMBINATION;

	pr_warn("horizon set_memory_attribute: stubbed\n");
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE3(map_memory, unsigned long, dst_addr, unsigned long, src_addr,
		 u64, size)
{
	unsigned long flags = MREMAP_FIXED | MREMAP_MAYMOVE;
	unsigned long end_code;

	if (!PAGE_ALIGNED(dst_addr) || !PAGE_ALIGNED(src_addr))
		return HZN_RESULT_INVALID_ADDRESS;
	if (size == 0)
		return HZN_RESULT_INVALID_SIZE;

	spin_lock(&current->mm->arg_lock);
	end_code = current->mm->end_code;
	spin_unlock(&current->mm->arg_lock);
	// Mapping from code is an exception because
	// MREMAP_DONTUNMAP doesn't work for
	// non-anonymous regions; hopefully not
	// unmapping isn't an issue since we don't
	// expect anything to get mapped over code
	// anyway
	if (!(src_addr < end_code))
		flags |= MREMAP_DONTUNMAP;

	if (vm_mremap(src_addr, size, size, flags, dst_addr) != dst_addr)
		return HZN_RESULT_INVALID_ADDRESS;
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE3(unmap_memory, unsigned long, dst_addr, unsigned long, src_addr,
		 u64, size)
{
	unsigned long flags = MREMAP_FIXED | MREMAP_MAYMOVE;

	if (!PAGE_ALIGNED(dst_addr) || !PAGE_ALIGNED(src_addr))
		return HZN_RESULT_INVALID_ADDRESS;
	if (size == 0)
		return HZN_RESULT_INVALID_SIZE;

	if (vm_mremap(dst_addr, size, size, flags, src_addr) != src_addr)
		return HZN_RESULT_INVALID_ADDRESS;
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE3(query_memory, void __user *, memory_info, long, __unused,
		 unsigned long, addr)
{
	struct vm_area_struct *vma, *prev_vma;
	struct memory_info mi;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;

	BUG_ON(!(current->mm));

	spin_lock(&current->mm->arg_lock);
	start_code = current->mm->start_code;
	end_code = current->mm->end_code;
	start_data = current->mm->start_data;
	end_data = current->mm->end_data;
	start_brk = current->mm->start_brk;
	start_stack = current->mm->start_stack;
	spin_unlock(&current->mm->arg_lock);

	if (addr < HZN_ADDRESS_SPACE_START || addr >= HZN_ADDRESS_SPACE_END(current)) {
		mi.addr = HZN_ADDRESS_SPACE_END(current);
		mi.size = 0 - HZN_ADDRESS_SPACE_END(current);
		mi.state = HZN_MEMORY_STATE_INACCESSIBLE;
		mi.attr = 0;
		mi.perm = HZN_MEMORY_PERMISSION_NONE;
		mi.ipc_refcount = 0;
		mi.device_refcount = 0;
		pr_debug("horizon query_memory: 0x%lx out-of-range, max is 0x%lx\n", addr, HZN_ADDRESS_SPACE_END(current));
	}
	else {
		mmap_read_lock(current->mm);
		brk = current->mm->brk;
		if (!(vma = find_vma_prev(current->mm, addr, &prev_vma)) || vma->vm_start > addr) {
			if (likely(prev_vma)) 
				mi.addr = prev_vma->vm_end;
			else // no previous VMA, use earliest address
				mi.addr = start_code;
			if (likely(vma))
				mi.size = vma->vm_start - mi.addr;
			else  // no next VMA, go to end
				mi.size = start_stack+1 - mi.addr;
			WARN_ON(!vma);
			mmap_read_unlock(current->mm);
			mi.state = HZN_MEMORY_STATE_FREE;
			mi.attr = 0;
			mi.perm = HZN_MEMORY_PERMISSION_NONE;
			mi.ipc_refcount = 0;
			mi.device_refcount = 0;
			pr_debug("horizon query_memory: 0x%lx no mapping addr=0x%llx, size=0x%llx\n", addr, mi.addr, mi.size);
		}
		else {
			mi.addr = vma->vm_start;
			mi.size = vma->vm_end - vma->vm_start;
			// Note: these values are the same as VM_* from the Linux kernel, so we'll just
			// use vm_flags directly. Still not sure how Dont_Care is used though.
			BUILD_BUG_ON(VM_NONE  != HZN_MEMORY_PERMISSION_NONE ||
				     VM_READ  != HZN_MEMORY_PERMISSION_READ ||
				     VM_WRITE != HZN_MEMORY_PERMISSION_WRITE ||
				     VM_EXEC  != HZN_MEMORY_PERMISSION_EXECUTE);
			mi.perm =
				(vma->vm_flags & (HZN_MEMORY_PERMISSION_NONE |
						  HZN_MEMORY_PERMISSION_READ |
						  HZN_MEMORY_PERMISSION_WRITE |
						  HZN_MEMORY_PERMISSION_EXECUTE));
			mmap_read_unlock(current->mm);
			// TODO handle other regions as they're implemented
			if (addr >= HZN_TLS_AREA_START(current) &&
			    addr < HZN_TLS_AREA_END(current))
				mi.state = HZN_MEMORY_STATE_THREAD_LOCAL;
			else if (addr >= start_code && addr < end_code &&
				 (mi.perm & HZN_MEMORY_PERMISSION_EXECUTE))
				mi.state = HZN_MEMORY_STATE_CODE;
			else if (addr >= start_data && addr < end_data) {
				if (mi.perm & HZN_MEMORY_PERMISSION_WRITE)
					mi.state = HZN_MEMORY_STATE_CODE_DATA;
				else
					mi.state = HZN_MEMORY_STATE_CODE;
			}
			else if (addr >= start_brk && addr < brk)
				mi.state = HZN_MEMORY_STATE_NORMAL;
			else if (addr >= HZN_ALIAS_REGION_START(current) &&
				 addr < HZN_ALIAS_REGION_END(current))
				mi.state = HZN_MEMORY_STATE_ALIAS;
			else if (addr >= HZN_ALIAS_CODE_REGION_START(current) &&
				 addr < HZN_ALIAS_CODE_REGION_END(current))
				mi.state = HZN_MEMORY_STATE_ALIAS_CODE;
			else // have to assume it's the stack otherwise
				mi.state = HZN_MEMORY_STATE_STACK;
			mi.attr = 0; // TODO when we start dealing with attributes
			mi.ipc_refcount = 0; // TODO probably
			mi.device_refcount = 0; // TODO probably
			pr_debug("horizon query_memory: 0x%lx addr=0x%llx, size=0x%llx, perm=0x%x, state=0x%x\n", addr, mi.addr, mi.size, mi.perm, mi.state);
		}
	}

	if (put_user(mi.addr, (u64 *)(memory_info + 0x00)) ||
	    put_user(mi.size, (u64 *)(memory_info + 0x08)) ||
	    put_user((u32)mi.state & 0xff, (u32 *)(memory_info + 0x10)) ||
	    put_user((u32)mi.attr, (u32 *)(memory_info + 0x14)) ||
	    put_user((u32)mi.perm, (u32 *)(memory_info + 0x18)) ||
	    put_user(mi.ipc_refcount, (u32 *)(memory_info + 0x1c)) ||
	    put_user(mi.device_refcount, (u32 *)(memory_info + 0x20)) ||
	    put_user(0, (u32 *)(memory_info + 0x24)))
		return HZN_RESULT_INVALID_ADDRESS;

	// Page info appears to be currently unused by the kernel and is always set to zero.
	HSYSCALL_OUT(0);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE0(exit_process)
{
	do_group_exit(0);
	return HZN_RESULT_SUCCESS;
}

#define IDEAL_CORE_DONT_CARE ((s32)-1)
#define IDEAL_CORE_USE_PROCESS_VALUE ((s32)-2)
#define IDEAL_CORE_NO_UPDATE ((s32)-3)

HSYSCALL_DEFINE6(create_thread, long, __unused, unsigned long, entry,
		 unsigned long, thread_context, unsigned long, stack_top,
		 s32, priority, s32, processor_id)
{
	struct kernel_clone_args args = {
		.flags		= CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
				  CLONE_THREAD | CLONE_SYSVSEM,
		.exit_signal	= 0,
		.stack		= stack_top,
	};
	int cpu = processor_id;
	struct task_struct *p;
	long tls_addr;
	size_t off;
	u32 handle;

	if (cpu == IDEAL_CORE_USE_PROCESS_VALUE)
		cpu = current->hzn_ideal_core;

	if (cpu < 0 || cpu >= (int)num_online_cpus())
		return HZN_RESULT_INVALID_CORE_ID;

	// TLS past current TLS
	off = 1;
	do {
		tls_addr = vm_mmap(NULL, current->thread.uw.tp_value + (PAGE_SIZE * off),
				   PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0);
		++off;
	} while (tls_addr == -EEXIST);
	if (IS_ERR_VALUE(tls_addr))
		return HZN_RESULT_OUT_OF_MEMORY;
	if (unlikely(copy_to_user((void *)tls_addr, empty_zero_page, PAGE_SIZE))) {
		vm_munmap(tls_addr, PAGE_SIZE);
		return HZN_RESULT_INVALID_ADDRESS;
	}

	p = copy_process(NULL, 0, cpu_to_node(cpu), &args);
	if (IS_ERR(p)) {
		vm_munmap(tls_addr, PAGE_SIZE);
		return HZN_RESULT_OUT_OF_MEMORY; // for lack of a better reason
	}

	if (set_cpus_allowed_ptr(p, cpumask_of(cpu)) < 0)
		return HZN_RESULT_INVALID_CORE_ID;
	if (!set_hzn_priority(p, priority))
		return HZN_RESULT_INVALID_PRIORITY;

	p->hzn_title_id = current->hzn_title_id;
	p->hzn_ideal_core = current->hzn_ideal_core;
	p->hzn_system_resource_size = current->hzn_system_resource_size;
	p->hzn_address_space_type = current->hzn_address_space_type;

	if (is_compat_thread(task_thread_info(p)))
		compat_start_thread(task_pt_regs(p), entry, stack_top);
	else
		start_thread(task_pt_regs(p), entry, stack_top);
	task_pt_regs(p)->regs[0] = thread_context;
	p->thread.uw.tp_value = tls_addr;

	handle = hzn_handle_table_add(current->files, get_task_pid(p, PIDTYPE_PID), &hzn_thread_fops);
	if (handle == HZN_INVALID_HANDLE) {
		put_task_struct(p);
		vm_munmap(tls_addr, PAGE_SIZE);
		send_sig(SIGKILL, p, 1);
		wake_up_new_task(p);
		return HZN_RESULT_OUT_OF_HANDLES;
	}
	p->hzn_thread_handle = handle;

	HSYSCALL_OUT(handle);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE1(start_thread, u32, thread_handle)
{
	struct task_struct *tsk = get_handle_task(thread_handle);
	if (!tsk)
		return HZN_RESULT_INVALID_HANDLE;
	wake_up_new_task(tsk);
	put_task_struct(tsk);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE0(exit_thread)
{
	do_exit(0);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE1(sleep_thread, u64, ns)
{
	long ret;
	s64 yield_type = ns;

	switch (yield_type) {
	case HZN_YIELD_TYPE_WITHOUT_CORE_MIGRATION:
	case HZN_YIELD_TYPE_WITH_CORE_MIGRATION:
	case HZN_YIELD_TYPE_TO_ANY_THREAD:
		__yield(yield_type);
		return HZN_RESULT_SUCCESS;
	}
	current->restart_block.nanosleep.type = TT_NONE;
	current->restart_block.nanosleep.rmtp = NULL;
	set_current_hzn_state(HZN_SWITCHABLE);
	ret = hrtimer_nanosleep((ktime_t)ns, HRTIMER_MODE_REL, CLOCK_MONOTONIC);
	set_current_hzn_state(HZN_FIXED);
	if (ret != 0)
		return HZN_RESULT_CANCELLED;
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE2(get_thread_priority, long, __unused, u32, thread_handle)
{
	struct task_struct *tsk = get_handle_task(thread_handle);
	if (!tsk)
		return HZN_RESULT_INVALID_HANDLE;
	HSYSCALL_OUT(get_hzn_priority(tsk));
	put_task_struct(tsk);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE2(set_thread_priority, u32, thread_handle, s32, priority)
{
	struct task_struct *tsk = get_handle_task(thread_handle);
	bool succ;
	if (!tsk)
		return HZN_RESULT_INVALID_HANDLE;
	succ = set_hzn_priority(tsk, priority);
	put_task_struct(tsk);
	return succ ? HZN_RESULT_SUCCESS : HZN_RESULT_INVALID_PRIORITY;
}

HSYSCALL_DEFINE3(set_thread_core_mask, u32, thread_handle, s32, core_mask_0,
		 u64, core_mask_1)
{
	struct task_struct *tsk = get_handle_task(thread_handle);
	if (!tsk)
		return HZN_RESULT_INVALID_HANDLE;
	set_hzn_state(tsk, HZN_SWITCHABLE);
	if (core_mask_0 == IDEAL_CORE_USE_PROCESS_VALUE)
		set_cpus_allowed_ptr(tsk, cpumask_of(current->hzn_ideal_core));
	else {
		int cpu;
		DECLARE_BITMAP(core_mask_bits, NR_CPUS) = { 0 };
		for (cpu = 0; cpu < NR_CPUS; ++cpu)
			if (core_mask_1 & (1ULL << cpu))
				bitmap_set(core_mask_bits, cpu, 1);
		set_cpus_allowed_ptr(tsk, to_cpumask(core_mask_bits));
	}
	set_hzn_state(tsk, HZN_FIXED);
	put_task_struct(tsk);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE0(get_current_processor_number)
{
	return raw_smp_processor_id();
}

static inline long do_clear_event(struct file *file)
{
	struct eventfd_ctx *ctx;

	ctx = eventfd_ctx_fileget(file);
	fput(file);
	if (!ctx)
		return HZN_RESULT_INVALID_HANDLE;

	spin_lock_irq(&ctx->wqh.lock);
	ctx->count = 0;
	spin_unlock_irq(&ctx->wqh.lock);

	eventfd_ctx_put(ctx);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE1(clear_event, u32, event_handle)
{
	struct file *file = __hzn_handle_table_get(event_handle);

	if (!file)
		return HZN_RESULT_INVALID_HANDLE;

	return do_clear_event(file);
}

HSYSCALL_DEFINE1(reset_signal, u32, handle)
{
	struct file *file = __hzn_handle_table_get(handle);

	if (!file)
		return HZN_RESULT_INVALID_HANDLE;

	if (file->f_op == &hzn_thread_fops) {
		// TODO process handles
		pr_err("horizon reset_signal: unhandled process\n");
		fput(file);
		return HZN_RESULT_INVALID_HANDLE;
	}

	return do_clear_event(file);
}

HSYSCALL_DEFINE4(map_shared_memory, u32, shared_mem_handle,
		 unsigned long, addr, u64, size,
		 enum memory_permission, memory_perm)
{
	struct file *file = __hzn_handle_table_get(shared_mem_handle);
	unsigned long ret;
	if (!file)
		return HZN_RESULT_INVALID_HANDLE;

	// these are all the same, so should be able to use the
	// permission flags as-is (except Dont_Care)
	BUILD_BUG_ON(PROT_NONE  != HZN_MEMORY_PERMISSION_NONE ||
		     PROT_READ  != HZN_MEMORY_PERMISSION_READ ||
		     PROT_WRITE != HZN_MEMORY_PERMISSION_WRITE ||
		     PROT_EXEC  != HZN_MEMORY_PERMISSION_EXECUTE);
	ret = vm_mmap(file, addr, size, memory_perm & ~HZN_MEMORY_PERMISSION_DONT_CARE, MAP_SHARED | MAP_FIXED, 0);
	fput(file);

	if (ret != addr)
		return HZN_RESULT_INVALID_ADDRESS;
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE3(unmap_shared_memory, u32, shared_mem_handle,
		 unsigned long, addr, u64, size)
{
	struct vm_area_struct *vma;
	struct file *file = __hzn_handle_table_get(shared_mem_handle);
	unsigned long ret = HZN_RESULT_SUCCESS;
	if (!file)
		return HZN_RESULT_INVALID_HANDLE;

	mmap_read_lock(current->mm);
	if (!(vma = find_vma(current->mm, addr)) ||
	    vma->vm_start > addr ||
	    vma->vm_end < addr + size ||
	    vma->vm_file != file)
		ret = HZN_RESULT_INVALID_MEMORY_REGION;
	mmap_read_unlock(current->mm);

	if (ret == HZN_RESULT_SUCCESS)
		vm_munmap(addr, size);
	return ret;
}

HSYSCALL_DEFINE4(create_transfer_memory, long, __unused, unsigned long, addr,
		 u64, size, enum memory_permission, memory_perm)
{
	u32 handle;
	struct page **pages;
	struct file *file;
	size_t page_off = addr & ~PAGE_MASK;
	unsigned long nr_pages = (page_off + size + PAGE_SIZE - 1) / PAGE_SIZE;
	size_t i;
	long ret;
	loff_t pos =  0;

	switch (memory_perm) {
	case HZN_MEMORY_PERMISSION_NONE:
	case HZN_MEMORY_PERMISSION_READ:
	case HZN_MEMORY_PERMISSION_READ_WRITE:
		break;
	default:
		return HZN_RESULT_INVALID_NEW_MEMORY_PERMISSION;
	}

	if (size == 0)
		return HZN_RESULT_INVALID_SIZE;

	file = shmem_file_setup("horizon_tmem", size, 0);
	if (IS_ERR(file))
		return HZN_RESULT_OUT_OF_MEMORY;

	pages = kmalloc(sizeof(struct page *) * nr_pages, GFP_KERNEL);
	if (pages == NULL) {
		fput(file);
		return HZN_RESULT_OUT_OF_MEMORY;
	}

	// get the transfer pages
	if ((ret = get_user_pages_fast(addr, nr_pages, 0, pages)) != nr_pages) {
		fput(file);
		for (i = 0; (long)i < ret; ++i)
			put_page(pages[i]);
		kfree(pages);
		return HZN_RESULT_INVALID_ADDRESS;
	}

	// write out to shared memory file
	ret = HZN_RESULT_SUCCESS;
	for (i = 0; i < nr_pages; ++i) {
		size_t to_copy = min(size - pos, (u64)PAGE_SIZE - page_off);
		ssize_t w = kernel_write(file, kmap(pages[i]) + page_off, to_copy, &pos);
		kunmap(pages[i]);
		if (w == -1) {
			ret = HZN_RESULT_INVALID_ADDRESS;
			break;
		}
		page_off = 0;
	}
	WARN_ON(pos != size);

	for (i = 0; i < nr_pages; ++i)
		put_page(pages[i]);
	kfree(pages);
	if (ret != HZN_RESULT_SUCCESS)
		return ret;

	// relying on previous BUILD_BUG_ON that Memory_Permission
	// corresponds to PROT_*
	if (vm_mmap(file, addr, size, memory_perm, MAP_SHARED | MAP_FIXED, 0) != addr) {
		fput(file);
		return HZN_RESULT_INVALID_ADDRESS;
	}

	// add transfer mem to handle table
	if ((handle = __hzn_handle_table_add(current->files, file)) == HZN_INVALID_HANDLE) {
		fput(file);
		return HZN_RESULT_OUT_OF_HANDLES;
	}

	HSYSCALL_OUT(handle);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE1(close_handle, u32, handle)
{
	if (!hzn_is_pseudo_handle(handle))
		hzn_handle_table_remove(current->files, handle);
	return HZN_RESULT_SUCCESS;
}

#define ARGUMENT_HANDLE_COUNT_MAX ((s32)0x40)

HSYSCALL_DEFINE4(wait_synchronization, long, __unused,
		 u32 __user *, handles_ptr, s32, handles_num, s64, timeout)
{
	u32 handles[ARGUMENT_HANDLE_COUNT_MAX];
	struct file *files[ARGUMENT_HANDLE_COUNT_MAX];
	size_t i;
	struct poll_wqueues table;
	struct timespec64 timeout_time, *end_time = NULL;
	size_t polled_index = -1;
	ktime_t expire, *to = NULL;
	u64 slack = 0;
	u32 err = HZN_RESULT_SUCCESS;

	if (handles_num > ARGUMENT_HANDLE_COUNT_MAX)
		return HZN_RESULT_OUT_OF_RANGE;

	// copy in array of handles
	if (copy_from_user(handles, handles_ptr, handles_num * sizeof(u32)))
		return HZN_RESULT_INVALID_ADDRESS;

	// populate files array from handles
	for (i = 0; i < handles_num; ++i) {
		if (!(files[i] = __hzn_handle_table_get(handles[i])) ||
		    !file_can_poll(files[i])) {
			if (hzn_is_pseudo_handle(handles[i]) || (files[i] && files[i]->f_op == &hzn_thread_fops)) // TODO process handles
				pr_err("horizon wait_synchronization: unhandled thread: %u\n", handles[i]);
			else if (files[i] && files[i]->f_op == &hzn_session_fops) // TODO session handles
				pr_err("horizon wait_synchronization: unhandled session\n");
			else // TODO something else?
				pr_err("horizon WAIT_SYNCHRONIZATION: unhandled unknown\n");
			if (files[i])
				fput(files[i]);
			while (i)
				fput(files[--i]);
			return HZN_RESULT_INVALID_HANDLE;
		}
	}

	/*
	 * This is all basically do_poll() from fs/select.c, but with the
	 * unnecessary stuff stripped out.
	 */

	poll_initwait(&table);

	// set timeout
	if (timeout >= 0) {
		end_time = &timeout_time;
		poll_select_set_timeout(end_time, timeout / NSEC_PER_SEC,
						  timeout % NSEC_PER_SEC);
	}

	// in case of zero timeout
	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		table.pt._qproc = NULL; // won't be necessary to wait
		err = HZN_RESULT_TIMED_OUT;
	}

	if (end_time && err != HZN_RESULT_TIMED_OUT)
		slack = select_estimate_accuracy(end_time);

	for (;;) {
		for (i = 0; i < handles_num; ++i) {
			if (vfs_poll(files[i], &table.pt) & EPOLLIN) {
				polled_index = i;
				break;
			}
		}
		table.pt._qproc = NULL; // everyone registered in wait queue now
		if (polled_index == -1) {
			if (signal_pending(current))
				err = HZN_RESULT_CANCELLED;
			// I've only seen this set for ENOMEM, so let's just assume
			else if (table.error) 
				err = HZN_RESULT_OUT_OF_MEMORY;
		}
		if (polled_index != -1 || err != HZN_RESULT_SUCCESS)
			break;
		if (end_time && !to) {
			expire = timespec64_to_ktime(*end_time);
			to = &expire;
		}
		set_current_hzn_state(HZN_SWITCHABLE);
		if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE, to, slack))
			err = HZN_RESULT_TIMED_OUT;
		set_current_hzn_state(HZN_FIXED);
	};
	poll_freewait(&table);

	if (polled_index == -1)
		return err;
	HSYSCALL_OUT(polled_index);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE3(arbitrate_lock, u32, thread_handle, u32 __user *, addr,
		 u32, tag)
{
	long ret;

	if (tag != current->hzn_thread_handle) {
		// I don't understand why this is even a possibility (to
		// grab the lock for another thread), so I'm just not
		// gonna support it until it's necessary
		pr_err("horizon arbitrate_lock: attempted to set non-current thread handle; TODO\n");
		return HZN_RESULT_INVALID_HANDLE;
	}

	// Also not sure if I need to use the given thread handle?  I'm
	// not really sure why it's necessary to only consider the given
	// thread holding the lock, but might be worth looking into

	set_current_hzn_state(HZN_SWITCHABLE);
	ret = do_horizon_futex(addr, FUTEX_LOCK_PI_PRIVATE, 0, NULL, NULL, 0, 0);
	set_current_hzn_state(HZN_FIXED);
	if (ret != 0) {
		if (ret == -ERESTARTNOINTR || ret == -EWOULDBLOCK)
			return HZN_RESULT_CANCELLED;
		return HZN_RESULT_INVALID_ADDRESS;
	}
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE1(arbitrate_unlock, u32 __user *, addr)
{
	long ret;
	if ((ret = do_horizon_futex(addr, FUTEX_UNLOCK_PI_PRIVATE, 0, NULL, NULL, 0, 0)) != 0) {
		if (ret == -EFAULT)
			return HZN_RESULT_INVALID_ADDRESS;
	}
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE4(wait_process_wide_key_atomic, u32 __user *, key_addr,
		 u32 __user *, tag_addr, u32, tag, s64, timeout)
{
	long ret;
	ktime_t ktimeout = (ktime_t)timeout;

	if (tag != current->hzn_thread_handle) {
		// see HNR_ARBITRATE_LOCK comment
		pr_err("horizon wait_process_wide_key_atomic: attempted to set non-current thread handle; TODO\n");
		return HZN_RESULT_INVALID_HANDLE;
	}

	set_current_hzn_state(HZN_SWITCHABLE);
	do_horizon_futex(tag_addr, FUTEX_WAIT_REQUEUE_PI_PRIVATE, 0,
			timeout < 0 ? NULL : &ktimeout, key_addr, 0, 0);
	set_current_hzn_state(HZN_FIXED);
	if (ret != 0) {
		if (ret == -ERESTARTNOINTR || ret == -EWOULDBLOCK)
			return HZN_RESULT_CANCELLED;
		if (ret == -ETIMEDOUT)
			return HZN_RESULT_TIMED_OUT;
		return HZN_RESULT_INVALID_ADDRESS;
	}
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE2(signal_process_wide_key, u32 __user *, addr, s32, val)
{
	if (do_horizon_futex(addr, FUTEX_CMP_REQUEUE_PI_PRIVATE, 1,
			  NULL, NULL, val <= 0 ? INT_MAX : val, 0) < 0)
		return HZN_RESULT_INVALID_ADDRESS;
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE0(get_system_tick)
{
	return read_sysreg(cntpct_el0);
}

LIST_HEAD(hzn_named_services);
DEFINE_SPINLOCK(hzn_named_services_lock);

HSYSCALL_DEFINE2(connect_to_named_port, long, __unused,
		 char __user *, port_name)
{
	struct hzn_named_service *iter;
	struct pid *service;
	struct hzn_session_handler *handler;
	char portname[HZN_PORT_NAME_MAX_LENGTH + 1];
	u32 handle;

	if (strncpy_from_user(portname, port_name, HZN_PORT_NAME_MAX_LENGTH) < 0)
		return HZN_RESULT_INVALID_ADDRESS;
	portname[sizeof(portname)-1] = 0;

	spin_lock(&hzn_named_services_lock);

	service = NULL;
	list_for_each_entry(iter, &hzn_named_services, entry) {
		if (strcmp(iter->name, portname) == 0) {
			service = get_task_pid(iter->service, PIDTYPE_PID);
			break;
		}
	}

	spin_unlock(&hzn_named_services_lock);

	if (!service)
		return HZN_RESULT_NOT_FOUND;

	handler = kmalloc(sizeof(struct hzn_session_handler), GFP_KERNEL);
	if (handler == NULL) {
		put_pid(service);
		return HZN_RESULT_OUT_OF_MEMORY;
	}

	handler->service = service;
	handler->id = 0;
	handler->is_domain = false;

	if ((handle = hzn_handle_table_add(current->files, handler, &hzn_session_fops)) ==
	    HZN_INVALID_HANDLE) {
		put_pid(service);
		kfree(handler);
		return HZN_RESULT_OUT_OF_HANDLES;
	}

	HSYSCALL_OUT(handle);
	return HZN_RESULT_SUCCESS;
}

#ifdef CONFIG_CPU_BIG_ENDIAN
#error "Doesn't support big-endian"
#endif

#define COMMAND_BUFFER_LENGTH (0x100 / sizeof(u32))

enum command_type {
	COMMAND_TYPE_CLOSE = 2,
	COMMAND_TYPE_REQUEST = 4,
	COMMAND_TYPE_REQUEST_WITH_CONTEXT = 6,
	COMMAND_TYPE_TIPC_CLOSE = 15,
	COMMAND_TYPE_TIPC_COMMAND_REGION = 16,
};

struct command_header {
	union {
		u32 : 32;
		struct {
			enum command_type type : 16;
			u32 : 4;
			u32 : 4;
			u32 : 4;
			u32 : 4;
		};
	};

	union {
		u32 : 32;
		struct {
			u32 data_size : 10;
			u32 : 4;
			u32 : 17;
			u32 : 1;
		};
	};
};
__used static void __command_header_assert(void)
{
	BUILD_BUG_ON(sizeof(struct command_header) != 8);
}


struct data_payload_header {
	u32 magic;
	u32 : 32;
};
__used static void __data_payload_header_assert(void)
{
	BUILD_BUG_ON(sizeof(struct data_payload_header) != 8);
}

struct domain_message_header {
	union {
		struct {
			u32 num_objects;
			u32 : 32;
			u32 : 32;
			u32 : 32;
		};

		struct {
			u32 : 8;
			u32 : 8;
			u32 : 16;

			u32 : 32;
			u32 : 32;
			u32 : 32;
		};

		u32 raw[4];
	};
};

__used static void __domain_message_header_assert(void)
{
	BUILD_BUG_ON(sizeof(struct domain_message_header) != 16);
}

#define IPC_ERR_REMOTE_PROCESS_DEAD (((union hzn_result_code){.bf={HZN_ERROR_MODULE_HIPC, 301}}).raw)

// Adapted from yuzu's ipc_helpers.h (Response_Builder)
static inline void build_result_response(void *cmdbuf, bool is_domain,
                                         u32 result)
{
	u32 raw_data_size;
	void *iter;
	struct command_header *cmdhdr = cmdbuf;
	bool is_tipc = cmdhdr->type >= COMMAND_TYPE_TIPC_COMMAND_REGION;
	bool is_request = cmdhdr->type == COMMAND_TYPE_REQUEST ||
	                  cmdhdr->type == COMMAND_TYPE_REQUEST_WITH_CONTEXT;

	iter = cmdbuf;

	memset(iter, 0, sizeof(u32) * COMMAND_BUFFER_LENGTH);

	// normal_params_size = 2 in subsequent logic

	// The entire size of the raw data section in u32 units, including the 16 bytes of mandatory
	// padding.
	raw_data_size = is_tipc ? 2 - 1 : 2;

	if (is_domain)
		raw_data_size +=
			(u32)(sizeof(struct domain_message_header) / sizeof(u32));

	if (!is_tipc)
		raw_data_size += (u32)(sizeof(struct data_payload_header) /
		                       sizeof(u32) + 4 + 2);

	cmdhdr->data_size = raw_data_size;
	iter += sizeof(struct command_header);

	if (!is_tipc) {
		// Padding to align to 16 bytes
		size_t index_words = (iter - cmdbuf) / sizeof(u32);	
		if (index_words & 3) {
			size_t padsize = sizeof(u32) * (4 - (index_words & 3));
			memset(iter, 0, padsize);
			iter += padsize;
		}

		if (is_domain && is_request) {
			((struct domain_message_header *)iter)->num_objects = 0;
			iter += sizeof(struct domain_message_header);
		}

		((struct data_payload_header *)iter)->magic =
			((u32)'S' | (u32)'F' << 8 | (u32)'C' << 16 | (u32)'O' << 24);
		iter += sizeof(struct data_payload_header);
	}

	// Push result with trailing 0
	*(u32 *)iter = result;
	iter += sizeof(u32);
	*(u32 *)iter = 0;
	iter += sizeof(u32);
}

HSYSCALL_DEFINE1(send_sync_request, u32, session_handle)
{
	struct page *tls_page;
	void *cmdbuf;
	struct file *handler_file;
	struct hzn_session_handler *handler;
	struct hzn_session_request *request;
	struct task_struct *service_task;
	bool session_is_domain;
	bool interrupted = false;

	if (session_handle == HZN_INVALID_HANDLE ||
	    !(handler_file = hzn_handle_table_get(session_handle, &hzn_session_fops)))
		return HZN_RESULT_INVALID_HANDLE;
	handler = handler_file->private_data;
	session_is_domain = handler->is_domain;

	if (unlikely(get_user_pages_fast(HZN_TLS_AREA_START(current), 1, FOLL_WRITE, &tls_page) != 1)) {
		pr_err("horizon send_sync_request: "
		       "unexpectedly failed to get TLS area page\n");
		fput(handler_file);
		return HZN_RESULT_INVALID_ADDRESS;
	}

	cmdbuf = page_to_virt(tls_page);

	// close command is handled here
	if (((struct command_header *)cmdbuf)->type == COMMAND_TYPE_CLOSE ||
	    ((struct command_header *)cmdbuf)->type == COMMAND_TYPE_TIPC_CLOSE) {
		// service will be notified when the handle is closed
		build_result_response(cmdbuf, session_is_domain, HZN_RESULT_SUCCESS);
		fput(handler_file);
		put_page(tls_page);
		return IPC_ERR_REMOTE_PROCESS_DEAD;
	}

	// not sure why but yuzu supports this case of a session without
	// a handler, so I'll just handle it similarly
	if (!handler->service) {
		pr_err("horizon send_sync_request: "
		       "Session handler is invalid, stubbing response!\n");
		build_result_response(cmdbuf, session_is_domain, HZN_RESULT_SUCCESS);
		fput(handler_file);
		put_page(tls_page);
		return HZN_RESULT_SUCCESS;
	}

	// the service is gone, report the session closed
	if (!(service_task = get_pid_task(handler->service, PIDTYPE_PID))) {
		fput(handler_file);
		put_page(tls_page);
		return HZN_RESULT_SESSION_CLOSED;
	}

	// construct the request
	request = kmalloc(sizeof(struct hzn_session_request), GFP_KERNEL);
	if (request == NULL) {
		fput(handler_file);
		put_page(tls_page);
		put_task_struct(service_task);
		return HZN_RESULT_OUT_OF_MEMORY;
	}
	request->requester = get_task_struct(current);
	request->cmd = tls_page;
	request->handler_file = handler_file;

	// set state for pending request
	atomic_set(&current->hzn_request_state, HZN_SESSION_REQUEST_PENDING);

	// put it on the service's queue and wake the service
	spin_lock(&service_task->hzn_requests_lock);
	if (service_task->hzn_requests_stop) {
		// the service is not taking any more requests
		spin_unlock(&service_task->hzn_requests_lock);
		put_task_struct(service_task);
		hzn_session_request_free(request);
		return HZN_RESULT_SESSION_CLOSED;
	}
	list_add_tail(&request->entry, &service_task->hzn_requests);
	spin_unlock(&service_task->hzn_requests_lock);
	wake_up_process(service_task);
	put_task_struct(service_task);

	set_current_hzn_state(HZN_SWITCHABLE);

	// wait for service to handle the request
	set_current_state(TASK_INTERRUPTIBLE);
	while (atomic_read(&current->hzn_request_state) == HZN_SESSION_REQUEST_PENDING) {
		if (signal_pending(current)) {
			interrupted = true;
			break;
		}
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);

	set_current_hzn_state(HZN_FIXED);

	// check in case interrupted or the service exited before handling
	if (atomic_read(&current->hzn_request_state) != HZN_SESSION_REQUEST_HANDLED)
		return interrupted ? HZN_RESULT_CANCELLED :
				     HZN_RESULT_SESSION_CLOSED;

	// service task should free up the request, so no need here
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE2(get_thread_id, long, __unused, u32, thread_handle)
{
	struct file *thread_file = NULL;

	if (hzn_is_pseudo_handle(thread_handle))
		HSYSCALL_OUT(task_pid_nr(current));
	else {
		thread_file = hzn_handle_table_get(thread_handle, &hzn_thread_fops);
		if (!thread_file)
			return HZN_RESULT_INVALID_HANDLE;
		HSYSCALL_OUT(pid_nr(thread_file->private_data));
		fput(thread_file);
	}

	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE3(break, u32, break_reason, u64, info1, u64, info2)
{
	pr_info("horizon (pid=%d) break: reason=0x%x, info1=0x%llx, info2=0x%llx\n",
		task_pid_nr(current), break_reason, info1, info2);
	do_exit(1 << 8);
	return HZN_RESULT_UNKNOWN; // shouldn't get here obv
}

HSYSCALL_DEFINE2(output_debug_string, char __user *, str, u64, size)
{
	char *debug_msg = kmalloc(size+1, GFP_KERNEL);
	if (debug_msg == NULL)
		return HZN_RESULT_OUT_OF_MEMORY;
	if (copy_from_user(debug_msg, str, size)) {
		kfree(debug_msg);
		return HZN_RESULT_INVALID_ADDRESS;
	}
	debug_msg[size] = 0;
	pr_info("horizon output_debug_string: %s\n", debug_msg);
	kfree(debug_msg);
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE4(get_info, long, __unused, u32, info_type, u32, handle,
		 u64, info_sub_type)
{
	struct file *thread_file = NULL;
	struct task_struct *process;
	struct mm_struct *mm;
	u32 err = HZN_RESULT_SUCCESS;

	// from yuzu
	enum {
		// 1.0.0+
		ALLOWED_CPU_CORE_MASK = 0,
		ALLOWED_THREAD_PRIORITY_MASK = 1,
		MAP_REGION_BASE_ADDR = 2,
		MAP_REGION_SIZE = 3,
		HEAP_REGION_BASE_ADDR = 4,
		HEAP_REGION_SIZE = 5,
		TOTAL_PHYSICAL_MEMORY_AVAILABLE = 6,
		TOTAL_PHYSICAL_MEMORY_USED = 7,
		IS_CURRENT_PROCESS_BEING_DEBUGGED = 8,
		REGISTER_RESOURCE_LIMIT = 9,
		IDLE_TICK_COUNT = 10,
		RANDOM_ENTROPY = 11,
		THREAD_TICK_COUNT = 0xF0000002,
		// 2.0.0+
		ASLR_REGION_BASE_ADDR = 12,
		ASLR_REGION_SIZE = 13,
		STACK_REGION_BASE_ADDR = 14,
		STACK_REGION_SIZE = 15,
		// 3.0.0+
		SYSTEM_RESOURCE_SIZE = 16,
		SYSTEM_RESOURCE_USAGE = 17,
		TITLE_ID = 18,
		// 4.0.0+
		PRIVILEGED_PROCESS_ID = 19,
		// 5.0.0+
		USER_EXCEPTION_CONTEXT_ADDR = 20,
		// 6.0.0+
		TOTAL_PHYSICAL_MEMORY_AVAILABLE_WITHOUT_SYSTEM_RESOURCE = 21,
		TOTAL_PHYSICAL_MEMORY_USED_WITHOUT_SYSTEM_RESOURCE = 22,
	};

	switch (info_type) {
	case IS_CURRENT_PROCESS_BEING_DEBUGGED:
	{
		HSYSCALL_OUT(0);
		return HZN_RESULT_SUCCESS;
	}
	case RANDOM_ENTROPY:
	{
		u64 rand;
		get_random_bytes(&rand, sizeof(rand));
		HSYSCALL_OUT(rand);
		return HZN_RESULT_SUCCESS;
	}
	}

	if (hzn_is_pseudo_handle(handle))
		process = current;
	else {
		thread_file = hzn_handle_table_get(handle, &hzn_thread_fops);
		if (!thread_file)
			return HZN_RESULT_INVALID_HANDLE;
		process = get_pid_task(thread_file->private_data, PIDTYPE_PID);
		fput(thread_file);
		if (!process)
			return HZN_RESULT_INVALID_HANDLE;
	}

	// TODO handle other info requests
	switch (info_type) {
	case ALLOWED_CPU_CORE_MASK:
		// just allow all cores always, whatever
		HSYSCALL_OUT(0xF);
		break;
	case MAP_REGION_BASE_ADDR:
		HSYSCALL_OUT(HZN_ALIAS_REGION_START(process));
		break;
	case MAP_REGION_SIZE:
		HSYSCALL_OUT(HZN_ALIAS_REGION_SIZE(process));
		break;
	case HEAP_REGION_BASE_ADDR:
		if (!(mm = get_task_mm(process))) {
			err = HZN_RESULT_INVALID_HANDLE;
			break;
		}
		spin_lock(&mm->arg_lock);
		HSYSCALL_OUT(mm->start_brk);
		spin_unlock(&mm->arg_lock);
		mmput(mm);
		break;
	case HEAP_REGION_SIZE:
		HSYSCALL_OUT(HZN_HEAP_REGION_SIZE(process));
		break;
	/*
	 * TOTAL_PHYSICAL_MEMORY_AVAILABLE/TOTAL_PHYSICAL_MEMORY_USED seem to
	 * be used to determine heap size, just hard-coding values for
	 * now that seem to work for TETRIS :P
	 */
	case TOTAL_PHYSICAL_MEMORY_AVAILABLE:
		HSYSCALL_OUT(0x60000000);
		break;
	case TOTAL_PHYSICAL_MEMORY_USED:
		HSYSCALL_OUT(0);
		break;
	case ASLR_REGION_BASE_ADDR:
		HSYSCALL_OUT(HZN_ALIAS_CODE_REGION_START(process));
		break;
	case ASLR_REGION_SIZE:
		HSYSCALL_OUT(HZN_ALIAS_CODE_REGION_SIZE(process));
		break;
	case STACK_REGION_BASE_ADDR:
	{
		unsigned long start_stack;
		if (!(mm = get_task_mm(process))) {
			err = HZN_RESULT_INVALID_HANDLE;
			break;
		}
		spin_lock(&mm->arg_lock);
		start_stack = mm->start_stack;
		spin_unlock(&mm->arg_lock);
		mmput(mm);
		HSYSCALL_OUT(PAGE_ALIGN(start_stack+1) - HZN_STACK_REGION_SIZE(process));
		break;
	}
	case STACK_REGION_SIZE:
		HSYSCALL_OUT(HZN_STACK_REGION_SIZE(process));
		break;
	case SYSTEM_RESOURCE_SIZE:
		HSYSCALL_OUT(process->hzn_system_resource_size);
		break;
	/*
	 * Same deal as
	 * TOTAL_PHYSICAL_MEMORY_AVAILABLE/TOTAL_PHYSICAL_MEMORY_USED for now.
	 */
	case TOTAL_PHYSICAL_MEMORY_AVAILABLE_WITHOUT_SYSTEM_RESOURCE:
		HSYSCALL_OUT(0x60000000);
		break;
	case TOTAL_PHYSICAL_MEMORY_USED_WITHOUT_SYSTEM_RESOURCE:
		HSYSCALL_OUT(0);
		break;
	default:
		pr_err("horizon get_info: unhandled info id=%u, sub id=%llu\n", info_type, info_sub_type);
		err = HZN_RESULT_UNKNOWN;
	}

	if (!hzn_is_pseudo_handle(handle))
		put_task_struct(process);

	return err;
}

HSYSCALL_DEFINE2(map_physical_memory, unsigned long, addr, u64, size)
{
	if (!PAGE_ALIGNED(addr))
		return HZN_RESULT_INVALID_ADDRESS;
	if (size == 0 || !PAGE_ALIGNED(size))
		return HZN_RESULT_INVALID_SIZE;
	if (!(addr < addr + size) ||
	    addr < HZN_ALIAS_REGION_START(current) ||
	    addr + size >= HZN_ALIAS_REGION_END(current))
		return HZN_RESULT_INVALID_MEMORY_REGION;
	if (current->hzn_system_resource_size == 0)
		return HZN_RESULT_INVALID_STATE;

	if (vm_mmap(NULL, addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0) != addr)
		return HZN_RESULT_OUT_OF_MEMORY;
	return HZN_RESULT_SUCCESS;
}

HSYSCALL_DEFINE2(unmap_physical_memory, unsigned long, addr, u64, size)
{
	if (!PAGE_ALIGNED(addr))
		return HZN_RESULT_INVALID_ADDRESS;
	if (size == 0 || !PAGE_ALIGNED(size))
		return HZN_RESULT_INVALID_SIZE;
	if (!(addr < addr + size) ||
	    addr < HZN_ALIAS_REGION_START(current) ||
	    addr + size >= HZN_ALIAS_REGION_END(current))
		return HZN_RESULT_INVALID_MEMORY_REGION;
	if (current->hzn_system_resource_size == 0)
		return HZN_RESULT_INVALID_STATE;

	vm_munmap(addr, size);
	return HZN_RESULT_SUCCESS;
}
