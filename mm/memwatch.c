/*
 * Adapted from the following patch series:
 * https://www.spinics.net/lists/kernel/msg4452239.html
 */
// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Collabora Ltd.
 */
#include <linux/pagewalk.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <linux/sched/mm.h>
#include <uapi/asm-generic/errno-base.h>
#include <linux/compat.h>
#include <linux/minmax.h>
#include <linux/swapops.h>
#include <linux/memwatch.h>

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

static inline bool pte_is_pinned(struct vm_area_struct *vma, unsigned long addr, pte_t pte)
{
	struct page *page;

	if (!pte_write(pte))
		return false;
	if (!is_cow_mapping(vma->vm_flags))
		return false;
	page = vm_normal_page(vma, addr, pte);
	if (!page)
		return false;
	return page_maybe_dma_pinned(page);
}

static inline bool check_soft_dirty(struct vm_area_struct *vma,
				    unsigned long addr, pte_t *pte, bool clear)
{
	/*
	 * The soft-dirty tracker uses #PF-s to catch writes
	 * to pages, so write-protect the pte as well. See the
	 * Documentation/admin-guide/mm/soft-dirty.rst for full description
	 * of how soft-dirty works.
	 */
	pte_t ptent = *pte;
	int dirty = 0;

	if (pte_present(ptent)) {
		pte_t old_pte;

		dirty = pte_soft_dirty(ptent);

		if (dirty && clear && !pte_is_pinned(vma, addr, ptent)) {
			old_pte = ptep_modify_prot_start(vma, addr, pte);
			ptent = pte_wrprotect(old_pte);
			ptent = pte_clear_soft_dirty(ptent);
			ptep_modify_prot_commit(vma, addr, pte, old_pte, ptent);
		}
	} else if (is_swap_pte(ptent)) {
		dirty = pte_swp_soft_dirty(ptent);

		if (dirty && clear) {
			ptent = pte_swp_clear_soft_dirty(ptent);
			set_pte_at(vma->vm_mm, addr, pte, ptent);
		}
	}

	return !!dirty;
}

#define MEMWATCH_SD_OPS_MASK (MEMWATCH_SD_GET | MEMWATCH_SD_CLEAR | \
			      MEMWATCH_SD_NO_REUSED_REGIONS)

struct memwatch_sd_private {
	unsigned long start;
	unsigned int flags;
	unsigned int index;
	unsigned int vec_len;
	unsigned long *vec;
};

static int memwatch_pmd_entry(pmd_t *pmd, unsigned long addr,
			      unsigned long end, struct mm_walk *walk)
{
	struct memwatch_sd_private *p = walk->private;
	struct vm_area_struct *vma = walk->vma;
	unsigned long start = addr;
	spinlock_t *ptl;
	pte_t *pte;
	int dirty;

	end = min(end, walk->vma->vm_end);
	split_huge_pmd(vma, pmd, addr);

	if (pmd_trans_unstable(pmd))
		return 0;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		dirty = check_soft_dirty(vma, addr, pte, p->flags & MEMWATCH_SD_CLEAR);

		if ((p->flags & MEMWATCH_SD_GET) && dirty && p->index < p->vec_len)
			p->vec[p->index++] = addr - p->start;
	}
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();

	if (p->flags & MEMWATCH_SD_CLEAR)
		flush_tlb_range(vma, start, end);

	return 0;
}

static int memwatch_pte_hole(unsigned long addr, unsigned long end, int depth,
			     struct mm_walk *walk)
{
	struct memwatch_sd_private *p = walk->private;
	struct vm_area_struct *vma = walk->vma;

	if (p->flags & MEMWATCH_SD_NO_REUSED_REGIONS)
		return 0;

	if (vma && (vma->vm_flags & VM_SOFTDIRTY) && (p->flags & MEMWATCH_SD_GET)) {
		for (; addr != end && p->index < p->vec_len; addr += PAGE_SIZE)
			p->vec[p->index++] = addr - p->start;
	}

	return 0;
}

static int memwatch_pre_vma(unsigned long start, unsigned long end, struct mm_walk *walk)
{
	struct memwatch_sd_private *p = walk->private;
	struct vm_area_struct *vma = walk->vma;
	int ret;
	unsigned long end_cut = end;

	if (p->flags & MEMWATCH_SD_NO_REUSED_REGIONS)
		return 0;

	if ((p->flags & MEMWATCH_SD_CLEAR) && (vma->vm_flags & VM_SOFTDIRTY)) {
		if (vma->vm_start < start) {
			ret = split_vma(vma->vm_mm, vma, start, 1);
			if (ret)
				return ret;
		}

		if (p->flags & MEMWATCH_SD_GET)
			end_cut = min(start + p->vec_len * PAGE_SIZE, end);

		if (vma->vm_end > end_cut) {
			ret = split_vma(vma->vm_mm, vma, end_cut, 0);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static void memwatch_post_vma(struct mm_walk *walk)
{
	struct memwatch_sd_private *p = walk->private;
	struct vm_area_struct *vma = walk->vma;

	if (p->flags & MEMWATCH_SD_NO_REUSED_REGIONS)
		return;

	if ((p->flags & MEMWATCH_SD_CLEAR) && (vma->vm_flags & VM_SOFTDIRTY)) {
		vma->vm_flags &= ~VM_SOFTDIRTY;
		vma_set_page_prot(vma);
	}
}

static int memwatch_pmd_test_walk(unsigned long start, unsigned long end,
				  struct mm_walk *walk)
{
	struct memwatch_sd_private *p = walk->private;
	struct vm_area_struct *vma = walk->vma;

	if ((p->flags & MEMWATCH_SD_GET) && (p->index == p->vec_len))
		return -1;

	if (vma->vm_flags & VM_PFNMAP)
		return 1;

	return 0;
}

static const struct mm_walk_ops memwatch_ops = {
	.test_walk = memwatch_pmd_test_walk,
	.pre_vma = memwatch_pre_vma,
	.pmd_entry = memwatch_pmd_entry,
	.pte_hole = memwatch_pte_hole,
	.post_vma = memwatch_post_vma,
};

long do_process_memwatch(struct task_struct *task, unsigned long start, int len,
			unsigned int flags, loff_t __user *vec, int vec_len)
{
	struct memwatch_sd_private watch;
	struct mmu_notifier_range range;
	unsigned long end;
	struct mm_struct *mm;
	int ret;

	if ((!IS_ALIGNED(start, PAGE_SIZE)) || !access_ok((void __user *)start, len))
		return -EINVAL;

	if ((flags == 0) || (flags == MEMWATCH_SD_NO_REUSED_REGIONS) ||
	    (flags & ~MEMWATCH_SD_OPS_MASK))
		return -EINVAL;

	if ((flags & MEMWATCH_SD_GET) && ((vec_len == 0) || (!vec) ||
	    !access_ok(vec, vec_len)))
		return -EINVAL;

	end = start + len;
	watch.start = start;
	watch.flags = flags;
	watch.index = 0;
	watch.vec_len = vec_len;

	if (flags & MEMWATCH_SD_GET) {
		watch.vec = vzalloc(vec_len * sizeof(loff_t));
		if (!watch.vec)
			return -ENOMEM;
	}

	mm = mm_access(task, PTRACE_MODE_ATTACH_FSCREDS);
	if (IS_ERR_OR_NULL(mm)) {
		ret = mm ? PTR_ERR(mm) : -ESRCH;
		goto free_watch;
	}

	if (flags & MEMWATCH_SD_CLEAR) {
		mmap_write_lock(mm);

		mmu_notifier_range_init(&range, MMU_NOTIFY_SOFT_DIRTY, 0, NULL,
					mm, start, end);
		mmu_notifier_invalidate_range_start(&range);
		inc_tlb_flush_pending(mm);
	} else {
		mmap_read_lock(mm);
	}

	ret = walk_page_range(mm, start, end, &memwatch_ops, &watch);

	if (flags & MEMWATCH_SD_CLEAR) {
		mmu_notifier_invalidate_range_end(&range);
		dec_tlb_flush_pending(mm);

		mmap_write_unlock(mm);
	} else {
		mmap_read_unlock(mm);
	}

	mmput(mm);

	if (ret < 0)
		goto free_watch;

	if (flags & MEMWATCH_SD_GET) {
		ret = copy_to_user(vec, watch.vec, watch.index * sizeof(loff_t));
		if (ret) {
			ret = -EIO;
			goto free_watch;
		}
		ret = watch.index;
	} else {
		ret = 0;
	}

free_watch:
	if (flags & MEMWATCH_SD_GET)
		vfree(watch.vec);

	return ret;
}
