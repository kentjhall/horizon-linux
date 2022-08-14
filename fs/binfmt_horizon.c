// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#include <linux/horizon.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/binfmts.h>
#include <linux/personality.h>
#include <linux/init.h>
#include <linux/coredump.h>
#include <linux/slab.h>
#include <linux/sched/task_stack.h>

#include <linux/uaccess.h>
#include <asm/cacheflush.h>

static int load_horizon_binary(struct linux_binprm *);

static struct linux_binfmt horizon_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_horizon_binary,
};

#define HORIZON_TXTADDR(hdr) \
	((hdr)->is_64bit ? SZ_128M : SZ_2M)

static int set_brk(unsigned long start, unsigned long end)
{
	start = PAGE_ALIGN(start);
	end = PAGE_ALIGN(end);
	if (end > start)
		return vm_brk(start, end - start);
	return 0;
}

static int load_horizon_binary(struct linux_binprm * bprm)
{
	struct pt_regs *regs = current_pt_regs();
	struct horizon_hdr *hdr = (struct horizon_hdr *)bprm->buf;
	size_t hdr_size =
		sizeof(*hdr) + (hdr->num_codesets * sizeof(*hdr->codesets));
	unsigned long error;
	unsigned long rlim;
	unsigned long data_size, total_size;
	unsigned long file_pos, vm_pos;
	int i, j;
	int retval;

	if (!test_thread_flag(TIF_HORIZON) || hdr->magic != HORIZON_MAGIC ||
	    !horizon_hdr_check_arch(hdr) || hdr->num_codesets == 0) {
		return -ENOEXEC;
	}

	current->hzn_title_id = hdr->title_id;
	current->hzn_ideal_core = hdr->ideal_core;
	current->hzn_address_space_type = hdr->address_space_type;
	current->hzn_system_resource_size = hdr->system_resource_size;

	if (!set_hzn_priority(current, hdr->main_thread_priority))
		return -EINVAL;

	/*
	 * Requires a mmap handler.
	 */
	if (!bprm->file->f_op->mmap)
		return -ENOEXEC;

	retval = -ENOEXEC;

	if (hdr_size > BINPRM_BUF_SIZE) {
		hdr = kmalloc(hdr_size, GFP_KERNEL);
		if (hdr == NULL)
			return -ENOMEM;
		error = kernel_read(bprm->file, hdr, hdr_size, NULL);
		if (error != hdr_size)
			goto out;
	}

	data_size = total_size = 0;
	for (i = 0; i < hdr->num_codesets; ++i) {
		data_size += hdr->codesets[i].segments[1].size +
		             hdr->codesets[i].segments[2].size;
		total_size += hdr->codesets[i].memory_size;
	}

	/* Check initial limits. This avoids letting people circumvent
	 * size limits imposed on them by creating programs with large
	 * arrays in the data or bss.
	 */
	rlim = rlimit(RLIMIT_DATA);
	if (rlim >= RLIM_INFINITY)
		rlim = ~0;
	if (data_size > rlim)
		goto out;

	/* Flush all traces of the currently running executable */
	retval = begin_new_exec(bprm);
	if (retval)
		goto out;

	/* OK, This is the point of no return */
	horizon_set_personality();
	setup_new_exec(bprm);

	/* These regions will be overlapping since the code/data regions aren't
	 * contiguous when there are multiple codesets, but start/end points
	 * will be correct. Segments within these ranges can be differentiated
	 * by checking permissions.
	 */
	current->mm->end_code = total_size -
		(hdr->codesets[hdr->num_codesets-1].segments[1].size +
		 hdr->codesets[hdr->num_codesets-1].segments[2].size) +
		(current->mm->start_code = HORIZON_TXTADDR(hdr));
	current->mm->end_data = total_size - hdr->codesets[0].segments[0].size +
		(current->mm->start_data =
		 HORIZON_TXTADDR(hdr) + hdr->codesets[0].segments[0].size);
	current->mm->brk = 0 +
		(current->mm->start_brk = HORIZON_TXTADDR(hdr) + total_size +
		 HZN_ALIAS_REGION_SIZE(current));

	retval = setup_arg_pages(bprm, STACK_TOP, EXSTACK_DEFAULT);
	if (retval < 0)
		goto out;

	vm_pos = HORIZON_TXTADDR(hdr);
	file_pos = PAGE_ALIGN(hdr_size);
	for (i = 0; i < hdr->num_codesets; ++i) {
		for (j = 0; j < ARRAY_SIZE(hdr->codesets[i].segments); ++j) {
			error = vm_mmap(bprm->file, vm_pos + hdr->codesets[i].segments[j].addr,
				hdr->codesets[i].segments[j].size,
				PROT_READ | (j == 0 ? PROT_EXEC : (j == 2 ? PROT_WRITE : 0)),
				MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE,
				file_pos + hdr->codesets[i].segments[j].addr);
			if (error != vm_pos + hdr->codesets[i].segments[j].addr) {
				retval = error;
				goto out;
			}
		}
		vm_pos += hdr->codesets[i].memory_size;
		file_pos += hdr->codesets[i].memory_size;
	}

	set_binfmt(&horizon_format);

	retval = set_brk(current->mm->start_brk, current->mm->brk);
	if (retval < 0)
		goto out;

	current->mm->start_stack = arch_align_stack(bprm->p);

	finalize_exec(bprm);
	start_thread(regs, current->mm->start_code, current->mm->start_stack);
out:
	if (hdr != (struct horizon_hdr *)bprm->buf)
		kfree(hdr);
	return retval;
}

static int __init init_horizon_binfmt(void)
{
	register_binfmt(&horizon_format);
	return 0;
}

static void __exit exit_horizon_binfmt(void)
{
	unregister_binfmt(&horizon_format);
}

core_initcall(init_horizon_binfmt);
module_exit(exit_horizon_binfmt);
MODULE_LICENSE("GPL");
