/*
 * SWIOTLB-based DMA API implementation
 * Copyright (c) 2017-2018, NVIDIA CORPORATION.  All rights reserved.
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt)	"%s():%d: " fmt, __func__, __LINE__

#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#include <linux/vmalloc.h>
#include <linux/swiotlb.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/memblock.h>
#include <linux/iommu.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/cma.h>
#include <linux/dma-attrs.h>

#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/tlbflush.h>
#include <asm/dma-iommu.h>
#include <linux/dma-iommu.h>
#include <asm/dma-contiguous.h>

#include "mm.h"

#define CREATE_TRACE_POINTS
#include <trace/events/dmadebug.h>

#define ENABLE_IOMMU_DMA_OPS 0
#define ENABLE_IOMMU_DMA_OPS_NOTIFIER 0
#define ENABLE_IOMMU_SETUP_DMA_OPS 0

#ifndef CONFIG_DMA_API_DEBUG
char *__weak debug_dma_platformdata(struct device *dev)
{
	/* empty string by default */
	static char buf[1];

	return buf;
}
#endif

static int dma_get_ioprot(unsigned long attrs,
		enum dma_data_direction dir, bool coherent);

struct iommu_dma_cookie {
	struct iova_domain	iovad;
	struct list_head	msi_page_list;
	spinlock_t		msi_lock;
};

inline struct iova_domain *cookie_iovad(struct iommu_domain *domain)
{
	return &((struct iommu_dma_cookie *)domain->iova_cookie)->iovad;
}

dma_addr_t __iommu_dma_alloc_iova(struct iommu_domain *domain, size_t size,
		dma_addr_t dma_limit, bool size_aligned);

void __iommu_dma_free_iova(struct iova_domain *iovad,
		dma_addr_t iova, size_t size);

static void arm__free_iova(struct device *dev,
			       dma_addr_t addr, size_t size)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	struct iommu_domain *domain = mapping->domain;
	struct iova_domain *iovad = cookie_iovad(domain);

	__iommu_dma_free_iova(iovad, addr, size);
}


dma_addr_t arm__alloc_iova_at(struct device *dev, dma_addr_t dma_handle,
				size_t size)
{
	dma_addr_t dma_addr;
	struct iommu_domain *domain;
	struct iova_domain *iovad;
	size_t len = PAGE_ALIGN(size);
	dma_addr_t limit_addr;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		struct dma_iommu_mapping *mapping = dev->archdata.mapping;

		domain = mapping->domain;
		if (!domain)
			return DMA_ERROR_CODE;
	}

	iovad = domain->iova_cookie;
	if (!iovad)
		return DMA_ERROR_CODE;

	/* limit addr is inclusive. */
	limit_addr = dma_handle + iova_align(iovad, size) -
				iovad->granule;

	dma_addr = __iommu_dma_alloc_iova(domain, len, limit_addr, false);

	if (!dma_addr)
		return DMA_ERROR_CODE;

	if (dma_addr != dma_handle) {
		pr_err("iova alloc don't match, dh=%pad, da=%pad\n",
			&dma_handle, &dma_addr);
		__iommu_dma_free_iova(iovad, dma_addr, len);
		return DMA_ERROR_CODE;
	}

	return dma_addr;
}

struct dma_map_ops arm_dma_ops;

enum dma_operation {
	ALLOC_OR_FREE = 1,
	ATOMIC_ALLOC_OR_FREE,
	MAP_OR_UNMAP,
	CPU_MAP_OR_UNMAP
};

#ifdef CONFIG_DMA_API_DEBUG
#define NULL_DEV "null_dev"
struct iommu_usage {
	struct device		*dev;
	struct list_head	recordlist;
};

struct null_device {
	char const	*dev_name;
	atomic64_t	map_size;
	atomic64_t	atomic_alloc_size;
	atomic64_t	alloc_size;
	atomic64_t	cpu_map_size;
};

static struct null_device *dev_is_null;
static LIST_HEAD(iommu_rlist_head);
static size_t dmastats_alloc_or_map(struct device *dev, size_t size,
	const int type);
static size_t dmastats_free_or_unmap(struct device *dev, size_t size,
	const int type);
static void add_value(struct dma_iommu_mapping *iu, size_t size,
	const int type);
static void sub_value(struct dma_iommu_mapping *device_ref, size_t size,
	const int type);
#else
#define dmastats_alloc_or_map(dev, size, type)
#define dmastats_free_or_unmap(dev, size, type)
#endif

static struct page **__alloc_buffer_pages(struct device *dev, size_t size,
					  gfp_t gfp, unsigned long attrs);
static int __free_buffer_pages(struct device *dev, struct page **pages,
			       size_t size, unsigned long attrs);
static struct page **__get_pages(void *cpu_addr, unsigned long attrs);

struct dma_map_ops *dma_ops;
EXPORT_SYMBOL(dma_ops);

static pgprot_t __get_dma_pgprot(unsigned long attrs, pgprot_t prot,
				 bool coherent)
{
	if (!coherent || dma_get_attr(DMA_ATTR_WRITE_COMBINE, attrs))
		return pgprot_writecombine(prot);
	return prot;
}

static struct gen_pool *atomic_pool;
static struct page **atomic_pool_pages;

static size_t atomic_pool_size = SZ_1M;

static int __init early_coherent_pool(char *p)
{
	atomic_pool_size = memparse(p, &p);
	return 0;
}
early_param("coherent_pool", early_coherent_pool);

static void *__alloc_from_pool(size_t size, struct page **ret_page, gfp_t flags)
{
	unsigned long val;
	void *ptr = NULL;

	if (!atomic_pool) {
		WARN(1, "coherent pool not initialised!\n");
		return NULL;
	}

	val = gen_pool_alloc(atomic_pool, size);
	if (val) {
		phys_addr_t phys = gen_pool_virt_to_phys(atomic_pool, val);

		*ret_page = phys_to_page(phys);
		ptr = (void *)val;
		memset(ptr, 0, size);
	}

	return ptr;
}

static bool __in_atomic_pool(void *start, size_t size)
{
	if (!atomic_pool)
		return false;

	return addr_in_gen_pool(atomic_pool, (unsigned long)start, size);
}

static int __free_from_pool(void *start, size_t size)
{
	if (!__in_atomic_pool(start, size))
		return 0;

	gen_pool_free(atomic_pool, (unsigned long)start, size);

	return 1;
}

#ifdef CONFIG_DMA_API_DEBUG
static void *___alloc_from_pool(struct device *dev, size_t size,
				struct page **ret_page, gfp_t flags)
{
	struct dma_iommu_mapping *mapping;
	void *ptr = __alloc_from_pool(size, ret_page, flags);

	mapping = to_dma_iommu_mapping(dev);
	if (ptr && mapping)
		dmastats_alloc_or_map(dev, size, ATOMIC_ALLOC_OR_FREE);

	return ptr;
}

static int ___free_from_pool(struct device *dev, void *start, size_t size)
{
	int ret = __free_from_pool(start, size);

	if (ret)
		dmastats_free_or_unmap(dev, size, ATOMIC_ALLOC_OR_FREE);

	return ret;
}

#define __free_from_pool(start, size)	\
	___free_from_pool(dev, start, size)

#define __alloc_from_pool(size, ret_page, flags) \
	___alloc_from_pool(dev, size, ret_page, flags)
#endif

#ifdef CONFIG_SWIOTLB
static void *__dma_alloc_coherent(struct device *dev, size_t size,
				  dma_addr_t *dma_handle, gfp_t flags,
				  unsigned long attrs)
{
	if (dev == NULL) {
		WARN_ONCE(1, "Use an actual device structure for DMA allocation\n");
		return NULL;
	}

	if (IS_ENABLED(CONFIG_ZONE_DMA) &&
	    dev->coherent_dma_mask <= DMA_BIT_MASK(32))
		flags |= GFP_DMA;
	if (IS_ENABLED(CONFIG_DMA_CMA) && (gfpflags_allow_blocking(flags))) {
		struct page *page;
		void *addr;

		size = PAGE_ALIGN(size);
		page = dma_alloc_from_contiguous(dev, size >> PAGE_SHIFT,
							get_order(size));
		if (!page)
			return NULL;

		*dma_handle = phys_to_dma(dev, page_to_phys(page));
		addr = page_address(page);
		memset(addr, 0, size);
		return addr;
	}
	return swiotlb_alloc_coherent(dev, size, dma_handle, flags);
}

static void __dma_free_coherent(struct device *dev, size_t size,
				void *vaddr, dma_addr_t dma_handle,
				unsigned long attrs)
{
	bool freed;
	phys_addr_t paddr = dma_to_phys(dev, dma_handle);

	if (dev == NULL) {
		WARN_ONCE(1, "Use an actual device structure for DMA allocation\n");
		return;
	}

	freed = dma_release_from_contiguous(dev,
					phys_to_page(paddr),
					size >> PAGE_SHIFT);
	if (!freed)
		swiotlb_free_coherent(dev, size, vaddr, dma_handle);
}

static void *__dma_alloc_noncoherent(struct device *dev, size_t size,
				     dma_addr_t *dma_handle, gfp_t flags,
				     unsigned long attrs)
{
	struct page *page;
	void *ptr, *coherent_ptr;

	size = PAGE_ALIGN(size);

	if (!gfpflags_allow_blocking(flags)) {
		struct page *page = NULL;
		void *addr = __alloc_from_pool(size, &page, flags);

		if (addr)
			*dma_handle = phys_to_dma(dev, page_to_phys(page));

		return addr;

	}

	ptr = __dma_alloc_coherent(dev, size, dma_handle, flags, attrs);
	if (!ptr)
		goto no_mem;

	/* remove any dirty cache lines on the kernel alias */
	__dma_flush_area(ptr, size);

	/* create a coherent mapping */
	page = virt_to_page(ptr);
	coherent_ptr = dma_common_contiguous_remap(page, size, VM_USERMAP,
				__get_dma_pgprot(attrs,
					__pgprot(PROT_NORMAL_NC), false),
					NULL);
	if (!coherent_ptr)
		goto no_map;

	return coherent_ptr;

no_map:
	__dma_free_coherent(dev, size, ptr, *dma_handle, attrs);
no_mem:
	*dma_handle = DMA_ERROR_CODE;
	return NULL;
}

static void __dma_free_noncoherent(struct device *dev, size_t size,
				   void *vaddr, dma_addr_t dma_handle,
				   unsigned long attrs)
{
	void *swiotlb_addr = phys_to_virt(dma_to_phys(dev, dma_handle));

	if (__free_from_pool(vaddr, size))
		return;
	vunmap(vaddr);
	__dma_free_coherent(dev, size, swiotlb_addr, dma_handle, attrs);
}

static dma_addr_t __swiotlb_map_page(struct device *dev, struct page *page,
				     unsigned long offset, size_t size,
				     enum dma_data_direction dir,
				     unsigned long attrs)
{
	dma_addr_t dev_addr;

	dev_addr = swiotlb_map_page(dev, page, offset, size, dir, attrs);
	__dma_map_area(phys_to_virt(dma_to_phys(dev, dev_addr)), size, dir);

	return dev_addr;
}


static void __swiotlb_unmap_page(struct device *dev, dma_addr_t dev_addr,
				 size_t size, enum dma_data_direction dir,
				 unsigned long attrs)
{
	__dma_unmap_area(phys_to_virt(dma_to_phys(dev, dev_addr)), size, dir);
	swiotlb_unmap_page(dev, dev_addr, size, dir, attrs);
}

static int __swiotlb_map_sg_attrs(struct device *dev, struct scatterlist *sgl,
				  int nelems, enum dma_data_direction dir,
				  unsigned long attrs)
{
	struct scatterlist *sg;
	int i, ret;

	ret = swiotlb_map_sg_attrs(dev, sgl, nelems, dir, attrs);
	for_each_sg(sgl, sg, ret, i)
		__dma_map_area_no_dsb(phys_to_virt(dma_to_phys(dev, sg->dma_address)),
			       sg->length, dir);
	dsb(sy);

	return ret;
}

static void __swiotlb_unmap_sg_attrs(struct device *dev,
				     struct scatterlist *sgl, int nelems,
				     enum dma_data_direction dir,
				     unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nelems, i)
		__dma_unmap_area_no_dsb(
				phys_to_virt(dma_to_phys(dev, sg->dma_address)),
				sg->length, dir);
	dsb(sy);
	swiotlb_unmap_sg_attrs(dev, sgl, nelems, dir, attrs);
}

static void __swiotlb_sync_single_for_cpu(struct device *dev,
					  dma_addr_t dev_addr, size_t size,
					  enum dma_data_direction dir)
{
	__dma_unmap_area(phys_to_virt(dma_to_phys(dev, dev_addr)), size, dir);
	swiotlb_sync_single_for_cpu(dev, dev_addr, size, dir);
}

static void __swiotlb_sync_single_for_device(struct device *dev,
					     dma_addr_t dev_addr, size_t size,
					     enum dma_data_direction dir)
{
	swiotlb_sync_single_for_device(dev, dev_addr, size, dir);
	__dma_map_area(phys_to_virt(dma_to_phys(dev, dev_addr)), size, dir);
}

static void __swiotlb_sync_sg_for_cpu(struct device *dev,
				      struct scatterlist *sgl, int nelems,
				      enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nelems, i)
		__dma_unmap_area_no_dsb(
				phys_to_virt(dma_to_phys(dev, sg->dma_address)),
				sg->length, dir);
	dsb(sy);
	swiotlb_sync_sg_for_cpu(dev, sgl, nelems, dir);
}

static void __swiotlb_sync_sg_for_device(struct device *dev,
					 struct scatterlist *sgl, int nelems,
					 enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	swiotlb_sync_sg_for_device(dev, sgl, nelems, dir);
	for_each_sg(sgl, sg, nelems, i)
		__dma_map_area_no_dsb(phys_to_virt(dma_to_phys(dev, sg->dma_address)),
			       sg->length, dir);
	dsb(sy);
}

/* vma->vm_page_prot must be set appropriately before calling this function */
static int __dma_common_mmap(struct device *dev, struct vm_area_struct *vma,
			     void *cpu_addr, dma_addr_t dma_addr, size_t size)
{
	int ret = -ENXIO;
	unsigned long nr_vma_pages = (vma->vm_end - vma->vm_start) >>
					PAGE_SHIFT;
	unsigned long nr_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long pfn = dma_to_phys(dev, dma_addr) >> PAGE_SHIFT;
	unsigned long off = vma->vm_pgoff;

	if (dma_mmap_from_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;

	if (off < nr_pages && nr_vma_pages <= (nr_pages - off)) {
		ret = remap_pfn_range(vma, vma->vm_start,
				      pfn + off,
				      vma->vm_end - vma->vm_start,
				      vma->vm_page_prot);
	}

	return ret;
}

static int __swiotlb_mmap_noncoherent(struct device *dev,
		struct vm_area_struct *vma,
		void *cpu_addr, dma_addr_t dma_addr, size_t size,
		unsigned long attrs)
{
	vma->vm_page_prot = __get_dma_pgprot(attrs, vma->vm_page_prot, false);
	return __dma_common_mmap(dev, vma, cpu_addr, dma_addr, size);
}

static int __swiotlb_mmap_coherent(struct device *dev,
		struct vm_area_struct *vma,
		void *cpu_addr, dma_addr_t dma_addr, size_t size,
		unsigned long attrs)
{
	/* Just use whatever page_prot attributes were specified */
	return __dma_common_mmap(dev, vma, cpu_addr, dma_addr, size);
}

struct dma_map_ops noncoherent_swiotlb_dma_ops = {
	.alloc = __dma_alloc_noncoherent,
	.free = __dma_free_noncoherent,
	.mmap = __swiotlb_mmap_noncoherent,
	.map_page = __swiotlb_map_page,
	.unmap_page = __swiotlb_unmap_page,
	.map_sg = __swiotlb_map_sg_attrs,
	.unmap_sg = __swiotlb_unmap_sg_attrs,
	.sync_single_for_cpu = __swiotlb_sync_single_for_cpu,
	.sync_single_for_device = __swiotlb_sync_single_for_device,
	.sync_sg_for_cpu = __swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = __swiotlb_sync_sg_for_device,
	.dma_supported = swiotlb_dma_supported,
	.mapping_error = swiotlb_dma_mapping_error,
};
EXPORT_SYMBOL(noncoherent_swiotlb_dma_ops);

struct dma_map_ops coherent_swiotlb_dma_ops = {
	.alloc = __dma_alloc_coherent,
	.free = __dma_free_coherent,
	.mmap = __swiotlb_mmap_coherent,
	.map_page = swiotlb_map_page,
	.unmap_page = swiotlb_unmap_page,
	.map_sg = swiotlb_map_sg_attrs,
	.unmap_sg = swiotlb_unmap_sg_attrs,
	.sync_single_for_cpu = swiotlb_sync_single_for_cpu,
	.sync_single_for_device = swiotlb_sync_single_for_device,
	.sync_sg_for_cpu = swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = swiotlb_sync_sg_for_device,
	.dma_supported = swiotlb_dma_supported,
	.mapping_error = swiotlb_dma_mapping_error,
};
EXPORT_SYMBOL(coherent_swiotlb_dma_ops);

extern int swiotlb_late_init_with_default_size(size_t default_size);

#endif /* CONFIG_SWIOTLB */

static int __init atomic_pool_init(void)
{
	pgprot_t prot = __pgprot(PROT_NORMAL_NC);
	unsigned long nr_pages = atomic_pool_size >> PAGE_SHIFT;
	struct page *page;
	struct page **pages = NULL;
	void *addr;
	unsigned int pool_size_order = get_order(atomic_pool_size);

	if (dev_get_cma_area(NULL))
		page = dma_alloc_from_contiguous(NULL, nr_pages,
							pool_size_order);
	else
		page = alloc_pages(GFP_DMA, pool_size_order);

	if (page) {
		int ret, i = 0;
		void *page_addr = page_address(page);

		memset(page_addr, 0, atomic_pool_size);
		__dma_flush_area(page_addr, atomic_pool_size);

		atomic_pool = gen_pool_create(PAGE_SHIFT, -1);
		if (!atomic_pool)
			goto free_page;

		pages = kmalloc(sizeof(struct page *) << pool_size_order,
				GFP_KERNEL);
		if (!pages)
			goto free_page;

		for (; i < nr_pages; i++)
			pages[i] = page + i;

		addr = dma_common_pages_remap(pages, atomic_pool_size,
					VM_USERMAP,
					prot, atomic_pool_init);

		if (!addr)
			goto destroy_genpool;

		ret = gen_pool_add_virt(atomic_pool, (unsigned long)addr,
					page_to_phys(page),
					atomic_pool_size, -1);
		if (ret)
			goto remove_mapping;

		atomic_pool_pages = pages;
		gen_pool_set_algo(atomic_pool,
				  gen_pool_first_fit_order_align,
				  (void *)PAGE_SHIFT);

		pr_info("DMA: preallocated %zu KiB pool for atomic allocations\n",
			atomic_pool_size / 1024);
		return 0;
	}
	goto out;

remove_mapping:
	dma_common_free_remap(addr, atomic_pool_size,
			      VM_USERMAP);
destroy_genpool:
	gen_pool_destroy(atomic_pool);
	atomic_pool = NULL;
	kfree(pages);
free_page:
	if (!dma_release_from_contiguous(NULL, page, nr_pages))
		__free_pages(page, pool_size_order);
out:
	pr_err("DMA: failed to allocate %zu KiB pool for atomic coherent allocation\n",
		atomic_pool_size / 1024);
	return -ENOMEM;
}

/********************************************
 * The following APIs are for dummy DMA ops *
 ********************************************/

static void *__dummy_alloc(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, gfp_t flags,
			   unsigned long attrs)
{
	return NULL;
}

static void __dummy_free(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle,
			 unsigned long attrs)
{
}

static int __dummy_mmap(struct device *dev,
			struct vm_area_struct *vma,
			void *cpu_addr, dma_addr_t dma_addr, size_t size,
			unsigned long attrs)
{
	return -ENXIO;
}

static dma_addr_t __dummy_map_page(struct device *dev, struct page *page,
				   unsigned long offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	return DMA_ERROR_CODE;
}

static void __dummy_unmap_page(struct device *dev, dma_addr_t dev_addr,
			       size_t size, enum dma_data_direction dir,
			       unsigned long attrs)
{
}

static int __dummy_map_sg(struct device *dev, struct scatterlist *sgl,
			  int nelems, enum dma_data_direction dir,
			  unsigned long attrs)
{
	return 0;
}

static void __dummy_unmap_sg(struct device *dev,
			     struct scatterlist *sgl, int nelems,
			     enum dma_data_direction dir,
			     unsigned long attrs)
{
}

static void __dummy_sync_single(struct device *dev,
				dma_addr_t dev_addr, size_t size,
				enum dma_data_direction dir)
{
}

static void __dummy_sync_sg(struct device *dev,
			    struct scatterlist *sgl, int nelems,
			    enum dma_data_direction dir)
{
}

static int __dummy_mapping_error(struct device *hwdev, dma_addr_t dma_addr)
{
	return 1;
}

static int __dummy_dma_supported(struct device *hwdev, u64 mask)
{
	return 0;
}

struct dma_map_ops dummy_dma_ops = {
	.alloc                  = __dummy_alloc,
	.free                   = __dummy_free,
	.mmap                   = __dummy_mmap,
	.map_page               = __dummy_map_page,
	.unmap_page             = __dummy_unmap_page,
	.map_sg                 = __dummy_map_sg,
	.unmap_sg               = __dummy_unmap_sg,
	.sync_single_for_cpu    = __dummy_sync_single,
	.sync_single_for_device = __dummy_sync_single,
	.sync_sg_for_cpu        = __dummy_sync_sg,
	.sync_sg_for_device     = __dummy_sync_sg,
	.mapping_error          = __dummy_mapping_error,
	.dma_supported          = __dummy_dma_supported,
};
EXPORT_SYMBOL(dummy_dma_ops);

#ifdef CONFIG_SWIOTLB
static int __init swiotlb_late_init(void)
{
	size_t swiotlb_size = min(SZ_64M, MAX_ORDER_NR_PAGES << PAGE_SHIFT);

	dma_ops = &noncoherent_swiotlb_dma_ops;

	return swiotlb_late_init_with_default_size(swiotlb_size);
}
#endif /* CONFIG_SWIOTLB */

static int __init arm64_dma_init(void)
{
	int ret = 0;

	dma_ops = &arm_dma_ops;
#ifdef CONFIG_SWIOTLB
	ret |= swiotlb_late_init();
#endif /* CONFIG_SWIOTLB */
	ret |= atomic_pool_init();

	return ret;
}
arch_initcall(arm64_dma_init);


#ifdef CONFIG_IOMMU_DMA
#include <linux/dma-iommu.h>
#include <linux/platform_device.h>
#include <linux/amba/bus.h>

#define UL_ATR(a) (a)

static void flush_sg(struct device *dev, struct sg_table *sgt)
{
	struct scatterlist *s;
	int i = 0;
	int nents = sgt->orig_nents;

	for_each_sg(sgt->sgl, s, nents, i) {
		__dma_flush_area(sg_virt(s), s->length);
	}
}

static void *__iommu_alloc_attrs(struct device *dev, size_t size,
				 dma_addr_t *handle, gfp_t gfp,
				 unsigned long attrs)
{
	bool coherent = is_device_dma_coherent(dev);
	int ioprot = dma_get_ioprot(attrs, DMA_BIDIRECTIONAL, coherent);
	size_t iosize = size;
	void *addr;

	/* Following is a work-around (a.k.a. hack) to prevent pages
	 * with __GFP_COMP being passed to split_page() which cannot
	 * handle them.  The real problem is that this flag probably
	 * should be 0 on ARM as it is not supported on this
	 * platform--see CONFIG_HUGETLB_PAGE.
	 */
	gfp &= ~(__GFP_COMP);

	if (WARN(!dev, "cannot create IOMMU mapping for unknown device\n"))
		return NULL;

	size = PAGE_ALIGN(size);

	if (gfpflags_allow_blocking(gfp)) {
		struct page **pages;
		pgprot_t prot = __get_dma_pgprot(attrs, PAGE_KERNEL, coherent);

		pages = iommu_dma_alloc(dev, iosize, gfp, UL_ATR(attrs),
					ioprot, handle, flush_sg);
		if (!pages)
			return NULL;

		trace_dmadebug_alloc_attrs(dev, *handle, size, pages[0]);

		if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs))
			return pages;

		addr = dma_common_pages_remap(pages, size, VM_USERMAP, prot,
					      __builtin_return_address(0));
		if (!addr)
			iommu_dma_free(dev, pages, iosize, handle, attrs);
	} else {
		struct page *page;
		/*
		 * In atomic context we can't remap anything, so we'll only
		 * get the virtually contiguous buffer we need by way of a
		 * physically contiguous allocation.
		 */
		if (coherent) {
			page = alloc_pages(gfp, get_order(size));
			addr = page ? page_address(page) : NULL;
		} else {
			addr = __alloc_from_pool(size, &page, gfp);
		}
		if (!addr)
			return NULL;

		*handle = iommu_dma_map_page(dev, page, 0, iosize, ioprot);
		if (iommu_dma_mapping_error(dev, *handle)) {
			if (coherent)
				__free_pages(page, get_order(size));
			else
				__free_from_pool(addr, size);
			addr = NULL;
		} else
			trace_dmadebug_alloc_attrs(dev, *handle, size, page);
	}
	return addr;
}

static void __iommu_free_attrs(struct device *dev, size_t size, void *cpu_addr,
			       dma_addr_t handle, unsigned long attrs)
{
	size_t iosize = size;

	size = PAGE_ALIGN(size);

	trace_dmadebug_free_attrs(dev, handle, size, NULL);

	/*
	 * @cpu_addr will be one of 3 things depending on how it was allocated:
	 * - A remapped array of pages from iommu_dma_alloc(), for all
	 *   non-atomic allocations.
	 * - A non-cacheable alias from the atomic pool, for atomic
	 *   allocations by non-coherent devices.
	 * - A normal lowmem address, for atomic allocations by
	 *   coherent devices.
	 * Hence how dodgy the below logic looks...
	 */
	if (__in_atomic_pool(cpu_addr, size)) {
		iommu_dma_unmap_page(dev, handle, iosize, 0, 0);
		__free_from_pool(cpu_addr, size);
	} else if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs)) {
		iommu_dma_free(dev, (struct page **)cpu_addr, iosize,
			       &handle, attrs);
	} else if (is_vmalloc_addr(cpu_addr)){
		struct vm_struct *area = find_vm_area(cpu_addr);

		if (WARN_ON(!area || !area->pages))
			return;
		iommu_dma_free(dev, area->pages, iosize, &handle, attrs);
		dma_common_free_remap(cpu_addr, size, VM_USERMAP);
	} else {
		iommu_dma_unmap_page(dev, handle, iosize, 0, 0);
		__free_pages(virt_to_page(cpu_addr), get_order(size));
	}
}

static int __iommu_mmap_attrs(struct device *dev, struct vm_area_struct *vma,
			      void *cpu_addr, dma_addr_t dma_addr, size_t size,
			      unsigned long attrs)
{
	struct vm_struct *area;
	int ret;

	vma->vm_page_prot = __get_dma_pgprot(attrs, vma->vm_page_prot,
					     is_device_dma_coherent(dev));

	if (dma_mmap_from_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;

	area = find_vm_area(cpu_addr);
	if (WARN_ON(!area || !area->pages))
		return -ENXIO;

	return iommu_dma_mmap(area->pages, size, vma);
}

static int __iommu_get_sgtable(struct device *dev, struct sg_table *sgt,
			       void *cpu_addr, dma_addr_t dma_addr,
			       size_t size, unsigned long attrs)
{
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct vm_struct *area = find_vm_area(cpu_addr);

	if (WARN_ON(!area || !area->pages))
		return -ENXIO;

	return sg_alloc_table_from_pages(sgt, area->pages, count, 0, size,
					 GFP_KERNEL);
}

static void __iommu_sync_single_for_cpu(struct device *dev,
					dma_addr_t dev_addr, size_t size,
					enum dma_data_direction dir)
{
	phys_addr_t phys;

	if (is_device_dma_coherent(dev))
		return;

	phys = iommu_iova_to_phys(iommu_get_domain_for_dev(dev), dev_addr);
	__dma_unmap_area(phys_to_virt(phys), size, dir);
}

static void __iommu_sync_single_for_device(struct device *dev,
					   dma_addr_t dev_addr, size_t size,
					   enum dma_data_direction dir)
{
	phys_addr_t phys;

	if (is_device_dma_coherent(dev))
		return;

	phys = iommu_iova_to_phys(iommu_get_domain_for_dev(dev), dev_addr);
	__dma_map_area(phys_to_virt(phys), size, dir);
}

static dma_addr_t __iommu_map_page(struct device *dev, struct page *page,
				   unsigned long offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	bool coherent = is_device_dma_coherent(dev);
	int prot = dma_get_ioprot(attrs, dir, coherent);
	dma_addr_t dev_addr = iommu_dma_map_page(dev, page, offset, size, prot);

	if (!iommu_dma_mapping_error(dev, dev_addr) &&
	    (UL_ATR(attrs) & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		__iommu_sync_single_for_device(dev, dev_addr, size, dir);

	trace_dmadebug_map_page(dev, dev_addr + offset, size, page);
	return dev_addr;
}

static dma_addr_t arm_iommu_map_at(struct device *dev, dma_addr_t dma_addr,
				       phys_addr_t phys, size_t size,
				       enum dma_data_direction dir,
				       unsigned long attrs);

#if ENABLE_IOMMU_DMA_OPS
static dma_addr_t __iommu_map_at(struct device *dev, dma_addr_t dma_addr,
				 phys_addr_t phys, size_t size,
				 enum dma_data_direction dir,
				 unsigned long attrs)
{
	bool coherent = is_device_dma_coherent(dev);
	int prot = dma_get_ioprot(attrs, dir, coherent);

	return iommu_dma_map_at(dev, dma_addr, phys, size, prot);
}
#endif


static void __iommu_unmap_page(struct device *dev, dma_addr_t dev_addr,
			       size_t size, enum dma_data_direction dir,
			       unsigned long attrs)
{
	if ((UL_ATR(attrs) & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		__iommu_sync_single_for_cpu(dev, dev_addr, size, dir);

	trace_dmadebug_unmap_page(dev, dev_addr, size,
		  phys_to_page(iommu_iova_to_phys(iommu_get_domain_for_dev(dev),
				 dev_addr)));
	iommu_dma_unmap_page(dev, dev_addr, size, dir, UL_ATR(attrs));
}

static void __iommu_sync_sg_for_cpu(struct device *dev,
				    struct scatterlist *sgl, int nelems,
				    enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	if (is_device_dma_coherent(dev))
		return;

	for_each_sg(sgl, sg, nelems, i)
		__dma_unmap_area_no_dsb(sg_virt(sg), sg->length, dir);
	dsb(sy);
}

static void __iommu_sync_sg_for_device(struct device *dev,
				       struct scatterlist *sgl, int nelems,
				       enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	if (is_device_dma_coherent(dev))
		return;

	for_each_sg(sgl, sg, nelems, i)
		__dma_map_area_no_dsb(sg_virt(sg), sg->length, dir);
	dsb(sy);
}

static int __iommu_map_sg_attrs(struct device *dev, struct scatterlist *sgl,
				int nelems, enum dma_data_direction dir,
				unsigned long attrs)
{
	bool coherent = is_device_dma_coherent(dev);

	if ((UL_ATR(attrs) & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		__iommu_sync_sg_for_device(dev, sgl, nelems, dir);

	return iommu_dma_map_sg(dev, sgl, nelems,
			dma_get_ioprot(attrs, dir, coherent));
}

static void __iommu_unmap_sg_attrs(struct device *dev,
				   struct scatterlist *sgl, int nelems,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	if ((UL_ATR(attrs) & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		__iommu_sync_sg_for_cpu(dev, sgl, nelems, dir);

	iommu_dma_unmap_sg(dev, sgl, nelems, dir, UL_ATR(attrs));
}

static struct dma_map_ops iommu_dma_ops = {
	.alloc = __iommu_alloc_attrs,
	.free = __iommu_free_attrs,
	.mmap = __iommu_mmap_attrs,
	.get_sgtable = __iommu_get_sgtable,
	.map_page = __iommu_map_page,
	.unmap_page = __iommu_unmap_page,
	.map_sg = __iommu_map_sg_attrs,
	.unmap_sg = __iommu_unmap_sg_attrs,
	.sync_single_for_cpu = __iommu_sync_single_for_cpu,
	.sync_single_for_device = __iommu_sync_single_for_device,
	.sync_sg_for_cpu = __iommu_sync_sg_for_cpu,
	.sync_sg_for_device = __iommu_sync_sg_for_device,
	.dma_supported = iommu_dma_supported,
	.mapping_error = iommu_dma_mapping_error,

	.map_at = arm_iommu_map_at,
};

#if ENABLE_IOMMU_DMA_OPS_NOTIFIER
/*
 * TODO: Right now __iommu_setup_dma_ops() gets called too early to do
 * everything it needs to - the device is only partially created and the
 * IOMMU driver hasn't seen it yet, so it can't have a group. Thus we
 * need this delayed attachment dance. Once IOMMU probe ordering is sorted
 * to move the arch_setup_dma_ops() call later, all the notifier bits below
 * become unnecessary, and will go away.
 */
struct iommu_dma_notifier_data {
	struct list_head list;
	struct device *dev;
	const struct iommu_ops *ops;
	u64 dma_base;
	u64 size;
};
static LIST_HEAD(iommu_dma_masters);
static DEFINE_MUTEX(iommu_dma_notifier_lock);

/*
 * Temporarily "borrow" a domain feature flag to to tell if we had to resort
 * to creating our own domain here, in case we need to clean it up again.
 */
#define __IOMMU_DOMAIN_FAKE_DEFAULT		(1U << 31)

static bool do_iommu_attach(struct device *dev, const struct iommu_ops *ops,
			   u64 dma_base, u64 size)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	/*
	 * Best case: The device is either part of a group which was
	 * already attached to a domain in a previous call, or it's
	 * been put in a default DMA domain by the IOMMU core.
	 */
	if (!domain) {
		/*
		 * Urgh. The IOMMU core isn't going to do default domains
		 * for non-PCI devices anyway, until it has some means of
		 * abstracting the entirely implementation-specific
		 * sideband data/SoC topology/unicorn dust that may or
		 * may not differentiate upstream masters.
		 * So until then, HORRIBLE HACKS!
		 */
		domain = ops->domain_alloc(IOMMU_DOMAIN_DMA);
		if (!domain)
			goto out_no_domain;

		domain->ops = ops;
		domain->type = IOMMU_DOMAIN_DMA | __IOMMU_DOMAIN_FAKE_DEFAULT;

		if (iommu_attach_device(domain, dev))
			goto out_put_domain;
	}

	if (iommu_dma_init_domain(domain, dma_base, size, dev))
		goto out_detach;

	dev->archdata.dma_ops = &iommu_dma_ops;
	return true;

out_detach:
	iommu_detach_device(domain, dev);
out_put_domain:
	if (domain->type & __IOMMU_DOMAIN_FAKE_DEFAULT)
		iommu_domain_free(domain);
out_no_domain:
	pr_warn("Failed to set up IOMMU for device %s; retaining platform DMA ops\n",
		dev_name(dev));
	return false;
}

static void queue_iommu_attach(struct device *dev, const struct iommu_ops *ops,
			      u64 dma_base, u64 size)
{
	struct iommu_dma_notifier_data *iommudata;

	iommudata = kzalloc(sizeof(*iommudata), GFP_KERNEL);
	if (!iommudata)
		return;

	iommudata->dev = dev;
	iommudata->ops = ops;
	iommudata->dma_base = dma_base;
	iommudata->size = size;

	mutex_lock(&iommu_dma_notifier_lock);
	list_add(&iommudata->list, &iommu_dma_masters);
	mutex_unlock(&iommu_dma_notifier_lock);
}

static int __iommu_attach_notifier(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	struct iommu_dma_notifier_data *master, *tmp;

	if (action != BUS_NOTIFY_ADD_DEVICE)
		return 0;

	mutex_lock(&iommu_dma_notifier_lock);
	list_for_each_entry_safe(master, tmp, &iommu_dma_masters, list) {
		if (do_iommu_attach(master->dev, master->ops,
				master->dma_base, master->size)) {
			list_del(&master->list);
			kfree(master);
		}
	}
	mutex_unlock(&iommu_dma_notifier_lock);
	return 0;
}

int register_iommu_dma_ops_notifier(struct bus_type *bus)
{
	struct notifier_block *nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	int ret;

	if (!nb)
		return -ENOMEM;
	/*
	 * The device must be attached to a domain before the driver probe
	 * routine gets a chance to start allocating DMA buffers. However,
	 * the IOMMU driver also needs a chance to configure the iommu_group
	 * via its add_device callback first, so we need to make the attach
	 * happen between those two points. Since the IOMMU core uses a bus
	 * notifier with default priority for add_device, do the same but
	 * with a lower priority to ensure the appropriate ordering.
	 */
	nb->notifier_call = __iommu_attach_notifier;
	nb->priority = -100;

	ret = bus_register_notifier(bus, nb);
	if (ret) {
		pr_warn("Failed to register DMA domain notifier; IOMMU DMA ops unavailable on bus '%s'\n",
			bus->name);
		kfree(nb);
	}
	return ret;
}

#endif /* ENABLE_IOMMU_DMA_OPS_NOTIFIER */

static int __init __iommu_dma_init(void)
{
	int ret = 0;

	ret = iommu_dma_init();
#if ENABLE_IOMMU_DMA_OPS_NOTIFIER
	if (!ret)
		ret = register_iommu_dma_ops_notifier(&platform_bus_type);
	if (!ret)
		ret = register_iommu_dma_ops_notifier(&amba_bustype);
#endif
	return ret;
}
arch_initcall(__iommu_dma_init);

void __iommu_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
				  const struct iommu_ops *ops)
{
#if ENABLE_IOMMU_DMA_OPS_NOTIFIER
	struct iommu_group *group;

	if (!ops)
		return;
	/*
	 * TODO: As a concession to the future, we're ready to handle being
	 * called both early and late (i.e. after bus_add_device). Once all
	 * the platform bus code is reworked to call us late and the notifier
	 * junk above goes away, move the body of do_iommu_attach here.
	 */
	group = iommu_group_get(dev);
	if (group) {
		do_iommu_attach(dev, ops, dma_base, size);
		iommu_group_put(group);
	} else {
		queue_iommu_attach(dev, ops, dma_base, size);
	}
#endif
}

#else

void __iommu_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
				  struct iommu_ops *iommu)
{ }

#endif  /* CONFIG_IOMMU_DMA */

struct dma_map_ops arm_coherent_dma_ops;
void arch_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
			const struct iommu_ops *iommu, bool coherent)
{
	if (!dev->archdata.dma_ops) {
		if (!coherent)
			dev->archdata.dma_ops = &arm_dma_ops;
		else
			dev->archdata.dma_ops = &arm_coherent_dma_ops;
	}
	dev->archdata.dma_coherent = coherent;
	dev->archdata.dma_noncontig =
		of_property_read_bool(dev->of_node, "dma-noncontig");

#if ENABLE_IOMMU_SETUP_DMA_OPS
	if (!dev->archdata.dma_ops)
		dev->archdata.dma_ops = &swiotlb_dma_ops;

	__iommu_setup_dma_ops(dev, dma_base, size, iommu);
#endif
}

#ifdef CONFIG_IOMMU_DMA
void arch_teardown_dma_ops(struct device *dev)
{
#if ENABLE_IOMMU_SETUP_DMA_OPS
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (domain) {
		iommu_detach_device(domain, dev);
		if (domain->type & __IOMMU_DOMAIN_FAKE_DEFAULT)
			iommu_domain_free(domain);
	}

	dev->archdata.dma_ops = NULL;
#endif
}
#endif

/*
 *FIXME: from arm
 */
/*
 * The DMA API is built upon the notion of "buffer ownership".  A buffer
 * is either exclusively owned by the CPU (and therefore may be accessed
 * by it) or exclusively owned by the DMA device.  These helper functions
 * represent the transitions between these two ownership states.
 *
 * Note, however, that on later ARMs, this notion does not work due to
 * speculative prefetches.  We model our approach on the assumption that
 * the CPU does do speculative prefetches, which means we clean caches
 * before transfers and delay cache invalidation until transfer completion.
 *
 */
static void __dma_page_cpu_to_dev(struct page *, unsigned long,
		size_t, enum dma_data_direction);
static void __dma_page_dev_to_cpu(struct page *, unsigned long,
		size_t, enum dma_data_direction);

__weak void dma_qualify_ioprot(enum dma_data_direction dir,
	unsigned long *ioprot) {}
__weak void dma_marshal_handle(enum dma_data_direction dir, dma_addr_t *handle) {}
__weak void dma_unmarshal_handle(enum dma_data_direction dir, dma_addr_t *handle) {}

/**
 * arm_dma_map_page - map a portion of a page for streaming DMA
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @page: page that buffer resides in
 * @offset: offset into page for start of buffer
 * @size: size of buffer to map
 * @dir: DMA transfer direction
 *
 * Ensure that any data held in the cache is appropriately discarded
 * or written back.
 *
 * The device owns this memory once this call has completed.  The CPU
 * can regain ownership by calling dma_unmap_page().
 */
static dma_addr_t arm_dma_map_page(struct device *dev, struct page *page,
	     unsigned long offset, size_t size, enum dma_data_direction dir,
	     unsigned long attrs)
{
	dma_addr_t handle;

	if (!dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
		__dma_page_cpu_to_dev(page, offset, size, dir & DMA_NONE);

	handle = __pfn_to_phys(page_to_pfn(page)) + offset;

	dma_marshal_handle(dir, &handle);

	return handle;
}

static dma_addr_t arm_coherent_dma_map_page(struct device *dev,
		struct page *page, unsigned long offset, size_t size,
		enum dma_data_direction dir, unsigned long attrs)
{
	dma_addr_t handle =  __pfn_to_phys(page_to_pfn(page)) + offset;

	dma_marshal_handle(dir, &handle);

	return handle;
}

/**
 * arm_dma_unmap_page - unmap a buffer previously mapped through dma_map_page()
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @handle: DMA address of buffer
 * @size: size of buffer (same as passed to dma_map_page)
 * @dir: DMA transfer direction (same as passed to dma_map_page)
 *
 * Unmap a page streaming mode DMA translation.  The handle and size
 * must match what was provided in the previous dma_map_page() call.
 * All other usages are undefined.
 *
 * After this call, reads by the CPU to the buffer are guaranteed to see
 * whatever the device wrote there.
 */
static void arm_dma_unmap_page(struct device *dev, dma_addr_t handle,
		size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
	dma_unmarshal_handle(dir, &handle);

	if (!dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
		__dma_page_dev_to_cpu(pfn_to_page(__phys_to_pfn(handle)),
				      handle & ~PAGE_MASK, size, dir & DMA_NONE);
}

static void arm_dma_sync_single_for_cpu(struct device *dev,
		dma_addr_t handle, size_t size, enum dma_data_direction dir)
{
	unsigned int offset = handle & (PAGE_SIZE - 1);
	struct page *page = pfn_to_page(__phys_to_pfn(handle-offset));

	__dma_page_dev_to_cpu(page, offset, size, dir);
}

static void arm_dma_sync_single_for_device(struct device *dev,
		dma_addr_t handle, size_t size, enum dma_data_direction dir)
{
	unsigned int offset = handle & (PAGE_SIZE - 1);
	struct page *page = pfn_to_page(__phys_to_pfn(handle-offset));

	__dma_page_cpu_to_dev(page, offset, size, dir);
}

struct dma_map_ops arm_dma_ops = {
	.alloc			= arm_dma_alloc,
	.free			= arm_dma_free,
	.mmap			= arm_dma_mmap,
	.get_sgtable		= arm_dma_get_sgtable,
	.map_page		= arm_dma_map_page,
	.unmap_page		= arm_dma_unmap_page,
	.map_sg			= arm_dma_map_sg,
	.unmap_sg		= arm_dma_unmap_sg,
	.sync_single_for_cpu	= arm_dma_sync_single_for_cpu,
	.sync_single_for_device	= arm_dma_sync_single_for_device,
	.sync_sg_for_cpu	= arm_dma_sync_sg_for_cpu,
	.sync_sg_for_device	= arm_dma_sync_sg_for_device,
	.set_dma_mask		= arm_dma_set_mask,
	.mapping_error		= arm_dma_mapping_error,
	.dma_supported		= arm_dma_supported,
};
EXPORT_SYMBOL(arm_dma_ops);

static void *arm_coherent_dma_alloc(struct device *dev, size_t size,
	dma_addr_t *handle, gfp_t gfp, unsigned long attrs);
static void arm_coherent_dma_free(struct device *dev, size_t size,
	void *cpu_addr, dma_addr_t handle, unsigned long attrs);

struct dma_map_ops arm_coherent_dma_ops = {
	.alloc			= arm_coherent_dma_alloc,
	.free			= arm_coherent_dma_free,
	.mmap			= arm_dma_mmap,
	.get_sgtable		= arm_dma_get_sgtable,
	.map_page		= arm_coherent_dma_map_page,
	.map_sg			= arm_dma_map_sg,
	.set_dma_mask		= arm_dma_set_mask,
	.mapping_error		= arm_dma_mapping_error,
	.dma_supported		= arm_dma_supported,
};
EXPORT_SYMBOL(arm_coherent_dma_ops);

static u64 get_coherent_dma_mask(struct device *dev)
{
	u64 mask = (u64)arm_dma_limit;

	if (dev) {
		mask = dev->coherent_dma_mask;

		/*
		 * Sanity check the DMA mask - it must be non-zero, and
		 * must be able to be satisfied by a DMA allocation.
		 */
		if (mask == 0) {
			dev_dbg(dev, "coherent DMA mask is unset\n");
			return 0;
		}

		if ((~mask) & (u64)arm_dma_limit) {
			dev_warn(dev, "coherent DMA mask %#llx is smaller "
				 "than system GFP_DMA mask %#llx\n",
				 mask, (u64)arm_dma_limit);
			return 0;
		}
	}

	return mask;
}

static void __dma_clear_buffer(struct page *page, size_t size, bool coherent)
{
	void *ptr;
	/*
	 * Ensure that the allocated pages are zeroed, and that any data
	 * lurking in the kernel direct-mapped region is invalidated.
	 */
	ptr = page_address(page);
	if (ptr) {
		memset(ptr, 0, size);
		if (!coherent)
			__dma_flush_area(ptr, size);
	}
}

/*
 * Allocate a DMA buffer for 'dev' of size 'size' using the
 * specified gfp mask.  Note that 'size' must be page aligned.
 */
static struct page *__dma_alloc_buffer(struct device *dev,
					size_t size, gfp_t gfp)
{
	unsigned long order = get_order(size);
	struct page *page, *p, *e;
	bool coherent = is_device_dma_coherent(dev);

	page = alloc_pages(gfp, order);
	if (!page)
		return NULL;

	/*
	 * Now split the huge page and free the excess pages
	 */
	split_page(page, order);
	for (p = page + (size >> PAGE_SHIFT), e = page + (1 << order);
			p < e; p++)
		__free_page(p);

	__dma_clear_buffer(page, size, coherent);

	return page;
}

/*
 * Free a DMA buffer.  'size' must be page aligned.
 */
static void __dma_free_buffer(struct page *page, size_t size)
{
	struct page *e = page + (size >> PAGE_SHIFT);

	while (page < e) {
		__free_page(page);
		page++;
	}
}

#ifdef CONFIG_MMU

static void *__alloc_from_contiguous(struct device *dev, size_t size,
				     pgprot_t prot, struct page **ret_page);

static void *__alloc_remap_buffer(struct device *dev, size_t size, gfp_t gfp,
				 pgprot_t prot, struct page **ret_page,
				 const void *caller);

static void *
__dma_alloc_remap(struct page *page, size_t size, gfp_t gfp, pgprot_t prot,
	const void *caller)
{
	struct vm_struct *area;
	unsigned long addr;

	/*
	 * DMA allocation can be mapped to user space, so lets
	 * set VM_USERMAP flags too.
	 */
	area = get_vm_area_caller(size, VM_USERMAP,
				  caller);
	if (!area)
		return NULL;
	addr = (unsigned long)area->addr;
	area->phys_addr = __pfn_to_phys(page_to_pfn(page));

	if (ioremap_page_range(addr, addr + size, area->phys_addr, prot)) {
		vunmap((void *)addr);
		return NULL;
	}
	return (void *)addr;
}

static void __dma_free_remap(void *cpu_addr, size_t size)
{
	unsigned int flags = VM_USERMAP;
	struct vm_struct *area = find_vm_area(cpu_addr);

	if (!area || (area->flags & flags) != flags) {
		WARN(1, "trying to free invalid coherent area: %p\n", cpu_addr);
		return;
	}
	unmap_kernel_range((unsigned long)cpu_addr, size);
	vunmap(cpu_addr);
}

struct dma_contig_early_reserve {
	phys_addr_t base;
	unsigned long size;
};

static struct dma_contig_early_reserve dma_mmu_remap[MAX_CMA_AREAS] __initdata;

static int dma_mmu_remap_num __initdata;

void __init dma_contiguous_early_fixup(phys_addr_t base, unsigned long size)
{
	dma_mmu_remap[dma_mmu_remap_num].base = base;
	dma_mmu_remap[dma_mmu_remap_num].size = size;
	dma_mmu_remap_num++;
}

void __init create_mapping_noalloc(phys_addr_t phys, unsigned long virt,
				  phys_addr_t size, pgprot_t prot);

void __init dma_contiguous_remap(void)
{
	int i;

	for (i = 0; i < dma_mmu_remap_num; i++) {
		unsigned long addr;
		phys_addr_t start = dma_mmu_remap[i].base;
		phys_addr_t end = start + dma_mmu_remap[i].size;

		if (start >= end)
			continue;

		for (addr = start; addr < end; addr += PAGE_SIZE)
			create_mapping_noalloc(addr, __phys_to_virt(addr),
				       PAGE_SIZE, PAGE_KERNEL);
	}
}

static void *__alloc_remap_buffer(struct device *dev, size_t size, gfp_t gfp,
				 pgprot_t prot, struct page **ret_page,
				 const void *caller)
{
	struct page *page;
	void *ptr;

	page = __dma_alloc_buffer(dev, size, gfp);
	if (!page)
		return NULL;

	ptr = __dma_alloc_remap(page, size, gfp, prot, caller);
	if (!ptr) {
		__dma_free_buffer(page, size);
		return NULL;
	}

	*ret_page = page;
	return ptr;
}

static void *__alloc_from_contiguous(struct device *dev, size_t size,
				     pgprot_t prot, struct page **ret_page)
{
	unsigned long order = get_order(size);
	size_t count = size >> PAGE_SHIFT;
	struct page *page;

	page = dma_alloc_from_contiguous(dev, count, order);
	if (!page)
		return NULL;

	*ret_page = page;
	return page_address(page);
}

static void __free_from_contiguous(struct device *dev, struct page *page,
				   size_t size)
{
	dma_release_from_contiguous(dev, page, size >> PAGE_SHIFT);
}

#define nommu() 0

#else	/* !CONFIG_MMU */

#define nommu() 1

#define __alloc_remap_buffer(dev, size, gfp, prot, ret, c)	NULL
#define __alloc_from_pool(size, ret_page)			NULL
#define __alloc_from_contiguous(dev, size, prot, ret)		NULL
#define __free_from_pool(cpu_addr, size)			0
#define __free_from_contiguous(dev, page, size)			do { } while (0)
#define __dma_free_remap(cpu_addr, size)			do { } while (0)

#endif	/* CONFIG_MMU */

static void *__alloc_simple_buffer(struct device *dev, size_t size, gfp_t gfp,
				   struct page **ret_page)
{
	struct page *page;

	page = __dma_alloc_buffer(dev, size, gfp);
	if (!page)
		return NULL;

	*ret_page = page;
	return page_address(page);
}

static void *__dma_alloc(struct device *dev, size_t size, dma_addr_t *handle,
			 gfp_t gfp, pgprot_t prot, bool is_coherent,
			 unsigned long attrs, const void *caller)
{
	u64 mask = get_coherent_dma_mask(dev);
	struct page *page = NULL;
	struct page **pages = NULL;
	void *addr = NULL;
	bool noncontig = is_device_dma_noncontig(dev) &&
			!dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs) &&
			gfpflags_allow_blocking(gfp);

#ifdef CONFIG_DMA_API_DEBUG
	u64 limit = (mask + 1) & ~mask;

	if (limit && size >= limit) {
		dev_warn(dev, "coherent allocation too big (requested %#zx mask %#llx)\n",
			size, mask);
		return NULL;
	}
#endif

	if (!mask)
		return NULL;

#ifdef CONFIG_ZONE_DMA
	if (mask == (u64)arm_dma_limit) {
		if ((gfp & GFP_ZONEMASK) != GFP_DMA &&
		    (gfp & GFP_ZONEMASK) != 0) {
			dev_warn(dev, "Invalid GFP flags(%x) passed. "
				"GFP_DMA should only be set.",
				 gfp & GFP_ZONEMASK);
			return NULL;
		}
		gfp |= GFP_DMA;
	}
#endif

	/*
	 * Following is a work-around (a.k.a. hack) to prevent pages
	 * with __GFP_COMP being passed to split_page() which cannot
	 * handle them.  The real problem is that this flag probably
	 * should be 0 on ARM as it is not supported on this
	 * platform; see CONFIG_HUGETLBFS.
	 */
	gfp &= ~(__GFP_COMP);

	size = PAGE_ALIGN(size);

	if (noncontig)
		pages = __alloc_buffer_pages(dev, size, gfp, attrs);
	else if (nommu())
		addr = __alloc_simple_buffer(dev, size, gfp, &page);
	else if (!gfpflags_allow_blocking(gfp))
		addr = __alloc_from_pool(size, &page, gfp);
	else if (size == PAGE_SIZE || !IS_ENABLED(CONFIG_CMA))
		addr = __alloc_remap_buffer(dev, size, gfp, prot,
						&page, caller);
	else
		addr = __alloc_from_contiguous(dev, size, prot, &page);

	if (noncontig && !pages)
		return NULL;
	if (!noncontig && !addr)
		return NULL;

	*handle = __pfn_to_phys(page_to_pfn(page));

	if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs)) {
		if (noncontig) {
			return pages;
		} else {
			int i;
			int count = (size >> PAGE_SHIFT);
			int array_size = count * sizeof(struct page *);
			struct page **pages;

			if (array_size <= PAGE_SIZE)
				pages = kzalloc(array_size, GFP_KERNEL);
			else
				pages = vzalloc(array_size);
			for (i = 0; i < count; i++)
				pages[i] = page + i;
			return pages;
		}
	} else {
		if (noncontig) {
			addr = dma_common_pages_remap(pages, size, VM_USERMAP,
					prot, __builtin_return_address(0));
			if (!addr)
				__free_buffer_pages(dev, pages, size, attrs);
		}
		return addr;
	}
}

/*
 * Allocate DMA-coherent memory space and return both the kernel remapped
 * virtual and bus address for that space.
 */
void *arm_dma_alloc(struct device *dev, size_t size, dma_addr_t *handle,
		    gfp_t gfp, unsigned long attrs)
{
	pgprot_t prot = __get_dma_pgprot(attrs, PG_PROT_KERNEL, false);
	void *memory;

	if (dma_alloc_from_coherent_attr(dev, size, handle, &memory, attrs))
		return memory;

	return __dma_alloc(dev, size, handle, gfp, prot, false,
			   attrs, __builtin_return_address(0));
}

static void *arm_coherent_dma_alloc(struct device *dev, size_t size,
	dma_addr_t *handle, gfp_t gfp, unsigned long attrs)
{
	pgprot_t prot = __get_dma_pgprot(attrs, PG_PROT_KERNEL, true);
	void *memory;

	if (dma_alloc_from_coherent_attr(dev, size, handle, &memory, attrs))
		return memory;

	return __dma_alloc(dev, size, handle, gfp, prot, true,
			   attrs, __builtin_return_address(0));
}

/*
 * Create userspace mapping for the DMA-coherent memory.
 */
int arm_dma_mmap(struct device *dev, struct vm_area_struct *vma,
		 void *cpu_addr, dma_addr_t dma_addr, size_t size,
		 unsigned long attrs)
{
	int ret = -ENXIO;
#ifdef CONFIG_MMU
	unsigned long nr_vma_pages =
		(vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	unsigned long nr_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long pfn = __phys_to_pfn(dma_addr);
	unsigned long off = vma->vm_pgoff;

	vma->vm_page_prot = __get_dma_pgprot(attrs, vma->vm_page_prot, false);

	if (dma_mmap_from_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;

	if (off < nr_pages && nr_vma_pages <= (nr_pages - off)) {
		ret = remap_pfn_range(vma, vma->vm_start,
				      pfn + off,
				      vma->vm_end - vma->vm_start,
				      vma->vm_page_prot);
	}
#endif	/* CONFIG_MMU */

	return ret;
}

/*
 * Free a buffer as defined by the above mapping.
 */
static void __arm_dma_free(struct device *dev, size_t size, void *cpu_addr,
			   dma_addr_t handle, unsigned long attrs,
			   bool is_coherent)
{
	struct page *page = pfn_to_page(__phys_to_pfn(handle));
	bool noncontig = is_device_dma_noncontig(dev) &&
				!dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs);

	if (dma_release_from_coherent_attr(dev, size, cpu_addr,
		attrs, handle))
		return;

	if (noncontig) {
		struct page **pages = __get_pages(cpu_addr, attrs);
		size = PAGE_ALIGN(size);
		if (__free_from_pool(cpu_addr, size))
			return;
		if (!dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs)) {
			unmap_kernel_range((unsigned long)cpu_addr, size);
			vunmap(cpu_addr);
		}
		__free_buffer_pages(dev, pages, size, attrs);
		return;
	}

	if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs)) {
		int count = size >> PAGE_SHIFT;
		int array_size = count * sizeof(struct page *);
		struct page **pages = (struct page **)cpu_addr;

		cpu_addr = (void *)page_address(pages[0]);
		if (array_size <= PAGE_SIZE)
			kfree(pages);
		else
			vfree(pages);
	}

	size = PAGE_ALIGN(size);

	if (nommu()) {
		__dma_free_buffer(page, size);
	} else if (__free_from_pool(cpu_addr, size)) {
		return;
	} else if (size == PAGE_SIZE || !IS_ENABLED(CONFIG_CMA)) {
		__dma_free_remap(cpu_addr, size);
		__dma_free_buffer(page, size);
	} else {
		/*
		 * Non-atomic allocations cannot be freed with IRQs disabled
		 */
		WARN_ON(irqs_disabled());
		__free_from_contiguous(dev, page, size);
	}
}

void arm_dma_free(struct device *dev, size_t size, void *cpu_addr,
		  dma_addr_t handle, unsigned long attrs)
{
	__arm_dma_free(dev, size, cpu_addr, handle, attrs, false);
}

static void arm_coherent_dma_free(struct device *dev, size_t size,
					void *cpu_addr, dma_addr_t handle,
					unsigned long attrs)
{
	__arm_dma_free(dev, size, cpu_addr, handle, attrs, true);
}

int arm_dma_get_sgtable(struct device *dev, struct sg_table *sgt,
		 void *cpu_addr, dma_addr_t handle, size_t size,
		 unsigned long attrs)
{
	bool noncontig = is_device_dma_noncontig(dev) &&
				!dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs);
	if (noncontig) {
		unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
		struct page **pages = __get_pages(cpu_addr, attrs);

		if (!pages) {
			dump_stack();
			pr_warn("No pages\n");
			return -ENXIO;
		}

		return sg_alloc_table_from_pages(sgt, pages, count, 0, size,
				GFP_KERNEL);
	} else {
		struct page *page = pfn_to_page(__phys_to_pfn(handle));
		int ret;

		ret = sg_alloc_table(sgt, 1, GFP_KERNEL);
		if (unlikely(ret)) {
			pr_warn("sg_alloc_table failed\n");
			return ret;
		}

		sg_set_page(sgt->sgl, page, PAGE_ALIGN(size), 0);
		return 0;
	}
}

static void dma_cache_maint_page(struct page *page, unsigned long offset,
	size_t size, enum dma_data_direction dir,
	void (*op)(const void *, size_t, int))
{
	op(page_address(page) + offset, size, dir);
}

/*
 * Make an area consistent for devices.
 * Note: Drivers should NOT use this function directly, as it will break
 * platforms with CONFIG_DMABOUNCE.
 * Use the driver DMA support - see dma-mapping.h (dma_sync_*)
 */
static void __dma_page_cpu_to_dev(struct page *page, unsigned long off,
	size_t size, enum dma_data_direction dir)
{
	dma_cache_maint_page(page, off, size, dir, __dma_map_area);
}

static void __dma_page_dev_to_cpu(struct page *page, unsigned long off,
	size_t size, enum dma_data_direction dir)
{
	dma_cache_maint_page(page, off, size, dir, __dma_unmap_area);

	/*
	 * Mark the D-cache clean for this page to avoid extra flushing.
	 */
	if (dir != DMA_TO_DEVICE && off == 0 && size >= PAGE_SIZE)
		set_bit(PG_dcache_clean, &page->flags);
}

/**
 * arm_dma_map_sg - map a set of SG buffers for streaming mode DMA
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to map
 * @dir: DMA transfer direction
 *
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * This is the scatter-gather version of the dma_map_single interface.
 * Here the scatter gather list elements are each tagged with the
 * appropriate dma address and length.  They are obtained via
 * sg_dma_{address,length}.
 *
 * Device ownership issues as mentioned for dma_map_single are the same
 * here.
 */
int arm_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction dir, unsigned long attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	struct scatterlist *s;
	int i, j;

	for_each_sg(sg, s, nents, i) {
#ifdef CONFIG_NEED_SG_DMA_LENGTH
		s->dma_length = s->length;
#endif
		s->dma_address = ops->map_page(dev, sg_page(s), s->offset,
						s->length, dir, attrs);
		if (dma_mapping_error(dev, s->dma_address))
			goto bad_mapping;
	}
	return nents;

 bad_mapping:
	for_each_sg(sg, s, i, j)
		ops->unmap_page(dev, sg_dma_address(s), sg_dma_len(s),
				dir, attrs);
	return 0;
}

/**
 * arm_dma_unmap_sg - unmap a set of SG buffers mapped by dma_map_sg
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to unmap (same as was passed to dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 *
 * Unmap a set of streaming mode DMA translations.  Again, CPU access
 * rules concerning calls here are the same as for dma_unmap_single().
 */
void arm_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction dir, unsigned long attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	struct scatterlist *s;

	int i;

	for_each_sg(sg, s, nents, i)
		ops->unmap_page(dev, sg_dma_address(s), sg_dma_len(s),
				dir, attrs);
}

/**
 * arm_dma_sync_sg_for_cpu
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to map (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 */
void arm_dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg,
			int nents, enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		ops->sync_single_for_cpu(dev, sg_dma_address(s), s->length,
					 dir);
}

/**
 * arm_dma_sync_sg_for_device
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to map (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 */
void arm_dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
			int nents, enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		ops->sync_single_for_device(dev, sg_dma_address(s), s->length,
					    dir);
}

int arm_dma_supported(struct device *dev, u64 mask)
{
	if (mask < (u64)arm_dma_limit)
		return 0;
	return 1;
}

int arm_dma_set_mask(struct device *dev, u64 dma_mask)
{
	if (!dev->dma_mask || !dma_supported(dev, dma_mask))
		return -EIO;

	*dev->dma_mask = dma_mask;

	return 0;
}

int arm_dma_mapping_error(struct device *dev, dma_addr_t dev_addr)
{
	return dev_addr == DMA_ERROR_CODE;
}

#if defined(CONFIG_ARM_DMA_USE_IOMMU)

static LIST_HEAD(iommu_mapping_list);
static DEFINE_SPINLOCK(iommu_mapping_list_lock);

#if defined(CONFIG_DMA_API_DEBUG)
#if defined(CONFIG_DEBUG_FS)
static dma_addr_t bit_to_addr(size_t pos, dma_addr_t base)
{
	return base + pos * (1 << PAGE_SHIFT);
}

static void seq_print_dma_areas(struct seq_file *s, void *bitmap,
				dma_addr_t base, size_t bits)
{
	/* one bit = one (page + order) sized block */
	size_t pos = find_first_bit(bitmap, bits), end;

	for (; pos < bits; pos = find_next_bit(bitmap, bits, end + 1)) {
		dma_addr_t start_addr, end_addr;

		end = find_next_zero_bit(bitmap, bits, pos);
		start_addr = bit_to_addr(pos, base);
		end_addr = bit_to_addr(end, base) - 1;
		seq_printf(s, "    %pa-%pa pages=%zu\n",
			   &start_addr, &end_addr, end - pos);
	}
}

static void seq_print_mapping(struct seq_file *s,
			      struct dma_iommu_mapping *mapping)
{
	int i;
	size_t mapping_size = mapping->bits << PAGE_SHIFT;

	seq_printf(s, "  memory map: base=%pa size=%zu domain=%p\n",
		   &mapping->base, (size_t)(mapping->end - mapping->base),
		   mapping->domain);

	for (i = 0; i < mapping->nr_bitmaps; i++)
		seq_print_dma_areas(s, mapping->bitmaps[i],
			mapping->base + mapping_size * i, mapping->bits);
}

static void debug_dma_seq_print_mappings(struct seq_file *s)
{
	struct dma_iommu_mapping *mapping;
	int i = 0;

	list_for_each_entry(mapping, &iommu_mapping_list, list) {
		seq_printf(s, "Map %d (%p):\n", i, mapping);
		seq_print_mapping(s, mapping);
		i++;
	}
}

static int dump_iommu_mappings(struct seq_file *s, void *data)
{
	debug_dma_seq_print_mappings(s);
	return 0;
}

static int dump_iommu_mappings_open(struct inode *inode, struct file *file)
{
	return single_open(file, dump_iommu_mappings, NULL);
}

static const struct file_operations dump_iommu_mappings_fops = {
	.open           = dump_iommu_mappings_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

#endif /* CONFIG_DEBUG_FS */
#endif /* CONFIG_DMA_API_DEBUG */

void dma_debugfs_platform_info(struct dentry *dent)
{
#ifdef CONFIG_DEBUG_FS
#ifdef CONFIG_DMA_API_DEBUG
	debugfs_create_file("dump_mappings", S_IRUGO, dent, NULL,
			    &dump_iommu_mappings_fops);
#endif
#endif
}

#else /* !CONFIG_ARM_DMA_USE_IOMMU */
static inline void dma_debugfs_platform_info(struct dentry *dent)
{
}
#endif /* !CONFIG_ARM_DMA_USE_IOMMU */

#if defined(CONFIG_DMA_API_DEBUG)
static inline void dma_debug_platform(void)
{
	struct dentry *dent;

	dent = debugfs_create_dir("dma-api", NULL);
	if (dent)
		dma_debugfs_platform_info(dent);
}
#else /* !CONFIG_DMA_API_DEBUG */
static void dma_debug_platform(void)
{
}
#endif /* !CONFIG_DMA_API_DEBUG */


#define PREALLOC_DMA_DEBUG_ENTRIES	4096

static int __init dma_debug_do_init(void)
{
	dma_debug_init(PREALLOC_DMA_DEBUG_ENTRIES);
	dma_debug_platform();
	return 0;
}
fs_initcall(dma_debug_do_init);

#ifdef CONFIG_ARM_DMA_USE_IOMMU

/* IOMMU */

static unsigned int prefetch_page_count = 1;
static unsigned int gap_page_count = 1;

#define PF_PAGES_SIZE (prefetch_page_count << PAGE_SHIFT)
#define PG_PAGES (prefetch_page_count + gap_page_count)

static struct page *iova_gap_pages;
static phys_addr_t iova_gap_phys;

static int __init iova_gap_pages_init(void)
{
	unsigned long order = get_order(PF_PAGES_SIZE);

	iova_gap_pages = alloc_pages(GFP_KERNEL, order);
	if (WARN_ON(!iova_gap_pages)) {
		prefetch_page_count = 0;
		return 0;
	}

	__dma_clear_buffer(iova_gap_pages, PAGE_SIZE << order, false);
	iova_gap_phys = page_to_phys(iova_gap_pages);
	return 0;
}
core_initcall(iova_gap_pages_init);

static void iommu_mapping_list_add(struct dma_iommu_mapping *mapping)
{
	unsigned long flags;

	spin_lock_irqsave(&iommu_mapping_list_lock, flags);
	list_add_tail(&mapping->list, &iommu_mapping_list);
	spin_unlock_irqrestore(&iommu_mapping_list_lock, flags);
}

static void iommu_mapping_list_del(struct dma_iommu_mapping *mapping)
{
	unsigned long flags;

	spin_lock_irqsave(&iommu_mapping_list_lock, flags);
	list_del(&mapping->list);
	spin_unlock_irqrestore(&iommu_mapping_list_lock, flags);
}

static inline int iommu_get_num_pf_pages(struct dma_iommu_mapping *mapping,
					 unsigned long attrs)
{
	/* XXX: give priority to DMA_ATTR_SKIP_IOVA_GAP */
	if (dma_get_attr(DMA_ATTR_SKIP_IOVA_GAP, attrs))
		return 0;

	/* XXX: currently we support only 1 prefetch page */
	WARN_ON(mapping->num_pf_page > prefetch_page_count);

	return mapping->num_pf_page;
}

static inline size_t iommu_get_size_pf_pages(struct dma_iommu_mapping *mapping,
					 unsigned long attrs)
{
	return iommu_get_num_pf_pages(mapping, attrs) << PAGE_SHIFT;
}

static inline int iommu_gap_pg_count(struct dma_iommu_mapping *mapping,
				     unsigned long attrs)
{
	if (dma_get_attr(DMA_ATTR_SKIP_IOVA_GAP, attrs))
		return 0;

	return mapping->gap_page ? gap_page_count : 0;
}

#ifdef CONFIG_DMA_API_DEBUG
static size_t _iommu_unmap(struct dma_iommu_mapping *mapping,
		unsigned long iova, size_t bytes)
{
	unsigned long start, offs, end;
	u32 bitmap_index, bitmap_last_index;
	dma_addr_t bitmap_base;
	size_t mapping_size = mapping->bits << PAGE_SHIFT;
	int i;

	bitmap_index = (u32)((iova - mapping->base) / mapping_size);
	bitmap_last_index = DIV_ROUND_UP(iova + bytes - mapping->base,
				mapping_size);
	bitmap_base = mapping->base + mapping_size * bitmap_index;

	if ((iova < mapping->base) || bitmap_index > mapping->extensions ||
			bitmap_last_index > mapping->extensions) {
		WARN(1, "trying to unmap invalid iova\n");
		return -EINVAL;
	}

	offs = (iova - bitmap_base) >> PAGE_SHIFT;
	end = offs + (PAGE_ALIGN(bytes) >> PAGE_SHIFT);
	/*
	 * [offs, end) is the portion of the requested region for unmap
	 * that falls into current bitmap.
	 * NOTE: This logic can't guarantee detection at the first faulty unmap
	 * unless the page 'end' is free. IOW this will work always when you
	 * enable gap pages.
	 */
	for (i = bitmap_index; i < bitmap_last_index;
	     i++, offs = 0, end -= mapping->bits) {
		start = find_next_zero_bit(mapping->bitmaps[i],
					   min_t(u32, mapping->bits, end),
					   offs);
		if ((start >= offs) && (start < end)) {
			WARN(1, "trying to unmap already unmapped area\n");
			return -EINVAL;
		}
	}

	return iommu_unmap(mapping->domain, iova, bytes);
}
#else
#define _iommu_unmap(mapping, iova, bytes) \
		iommu_unmap(mapping->domain, iova, bytes)
#endif

static int dma_get_ioprot(unsigned long attrs,
		enum dma_data_direction dir, bool coherent)
{
	unsigned long ioprot;

#if ENABLE_IOMMU_DMA_OPS
	ioprot = dma_direction_to_prot(dir, coherent);
#else
	ioprot = IOMMU_READ | IOMMU_WRITE;
	if (dma_get_attr(DMA_ATTR_READ_ONLY, (unsigned long)attrs))
		ioprot &= ~IOMMU_WRITE;
	else if (dma_get_attr(DMA_ATTR_WRITE_ONLY, (unsigned long)attrs))
		ioprot &= ~IOMMU_READ;

	if (coherent)
		ioprot |= IOMMU_CACHE;
#endif
	dma_qualify_ioprot(dir, &ioprot);

	return ioprot;
}

static int pg_iommu_map(struct dma_iommu_mapping *mapping, unsigned long iova,
			phys_addr_t phys, size_t len, unsigned long prot,
			enum dma_data_direction dir, bool coherent)
{
	int err;
	unsigned long attrs = (unsigned long)prot;
	struct iommu_domain *domain = mapping->domain;
	bool need_prefetch_page = !!iommu_get_num_pf_pages(mapping, attrs);
	unsigned long ioprot = dma_get_ioprot(attrs, dir, coherent);

	if (need_prefetch_page) {
		err = iommu_map(domain, iova + len, iova_gap_phys,
				PF_PAGES_SIZE, ioprot);
		if (err)
			return err;
	}

	err = iommu_map(domain, iova, phys, len, ioprot);
	if (err && need_prefetch_page)
		_iommu_unmap(mapping, iova + len, PF_PAGES_SIZE);

	return err;
}

/*
 * __alloc_buffer_pages - Allocates a buffer of pages to be mapped into
 *	IOVA space. Used by IOVA alloc for all allocations or DMA alloc
 *	when non-contiguous memory is needed.
 */
static struct page **__alloc_buffer_pages(struct device *dev, size_t size,
					  gfp_t gfp, unsigned long attrs)
{
	struct page **pages;
	bool coherent = is_device_dma_coherent(dev);
	int count = size >> PAGE_SHIFT;
	int array_size = count * sizeof(struct page *);
	int i = 0;

	if (array_size <= PAGE_SIZE)
		pages = kzalloc(array_size, GFP_KERNEL);
	else
		pages = vzalloc(array_size);
	if (!pages)
		return NULL;

	if (dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs))
	{
		unsigned long order = get_order(size);
		struct page *page;

		page = dma_alloc_from_contiguous(dev, count, order);
		if (!page)
			goto error;

		for (i = 0; i < count; i++)
			pages[i] = page + i;

		dmastats_alloc_or_map(dev, size, ALLOC_OR_FREE);
		return pages;
	}

	/*
	 * IOMMU can map any pages, so himem can also be used here
	 */
	if (!(gfp & GFP_DMA) && !(gfp & GFP_DMA32))
		gfp |= __GFP_HIGHMEM;

	gfp |= __GFP_NOWARN;

	while (count) {
		int j, order = __fls(count);

		pages[i] = alloc_pages(gfp, order);
		while (!pages[i] && order)
			pages[i] = alloc_pages(gfp, --order);
		if (!pages[i])
			goto error;

		if (order) {
			split_page(pages[i], order);
			j = 1 << order;
			while (--j)
				pages[i + j] = pages[i] + j;
		}

		__dma_clear_buffer(pages[i], PAGE_SIZE << order, coherent);
		i += 1 << order;
		count -= 1 << order;
	}

	dmastats_alloc_or_map(dev, size, ALLOC_OR_FREE);
	return pages;
error:
	while (i--)
		if (pages[i])
			__free_pages(pages[i], 0);
	if (array_size <= PAGE_SIZE)
		kfree(pages);
	else
		vfree(pages);
	return NULL;
}

/*
 * __free_buffer_pages: frees the buffer previously allocated  by
 * 			__alloc_buffer_pages
 */
static int __free_buffer_pages(struct device *dev, struct page **pages,
			       size_t size, unsigned long attrs)
{
	int count = size >> PAGE_SHIFT;
	int array_size = count * sizeof(struct page *);
	int i;

	if (dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs)) {
		dma_release_from_contiguous(dev, pages[0], count);
	} else {
		for (i = 0; i < count; i++)
			if (pages[i])
				__free_pages(pages[i], 0);
	}

	if (array_size <= PAGE_SIZE)
		kfree(pages);
	else
		vfree(pages);

	dmastats_free_or_unmap(dev, size, ALLOC_OR_FREE);
	return 0;
}


#ifdef CONFIG_DMA_API_DEBUG
#define  __iommu_alloc_remap(pages, size, gfp, prot, caller)	\
	 ___iommu_alloc_remap(dev, pages, size, gfp, prot, caller)
static void *
___iommu_alloc_remap(struct device *dev, struct page **pages, size_t size,
		    gfp_t gfp, pgprot_t prot, const void *caller)
{
	void *ptr = __iommu_alloc_remap(pages, size, gfp, prot, caller);

	if (ptr)
		dmastats_alloc_or_map(dev, size, CPU_MAP_OR_UNMAP);
	return ptr;
}
#endif

/*
 * __get_pages: returns the list of pages associated with a given address
 * 		that had previously been allocated by __alloc_buffer_pages
 */
static struct page **__get_pages(void *cpu_addr, unsigned long attrs)
{
	struct vm_struct *area;
	int offset = 0;

	if (__in_atomic_pool(cpu_addr, PAGE_SIZE)) {
		phys_addr_t phys = gen_pool_virt_to_phys(atomic_pool,
						(unsigned long)cpu_addr);
		struct gen_pool_chunk *chunk;

		rcu_read_lock();
		/* NOTE: this works as only a single chunk is present
		 * for atomic pool
		 */
		chunk = list_first_or_null_rcu(&atomic_pool->chunks,
					       struct gen_pool_chunk,
					       next_chunk);
		phys -= chunk->phys_addr;
		rcu_read_unlock();
		offset = phys >> PAGE_SHIFT;
		return atomic_pool_pages + offset;
	}

	if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs))
		return cpu_addr;

	area = find_vm_area(cpu_addr);
	if (area)
		return &area->pages[offset];
	return NULL;
}

static dma_addr_t arm_iommu_map_page_at(struct device *dev, struct page *page,
		 dma_addr_t dma_addr, unsigned long offset, size_t size,
		 enum dma_data_direction dir, unsigned long attrs)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	int ret, len = PAGE_ALIGN(size + offset);
	bool coherent = is_device_dma_coherent(dev);

	if (!coherent && !dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
		__dma_page_cpu_to_dev(page, offset, size, dir);

	ret = pg_iommu_map(mapping, dma_addr,
			   page_to_phys(page), len, (ulong)attrs,
			   dir, coherent);
	if (ret < 0)
		return DMA_ERROR_CODE;

	trace_dmadebug_map_page(dev, dma_addr, size, page);
	return dma_addr + offset;
}

static dma_addr_t arm_iommu_map_at(struct device *dev, dma_addr_t dma_addr,
				       phys_addr_t phys, size_t size,
				       enum dma_data_direction dir,
				       unsigned long attrs)
{
	dma_addr_t iova, ret;

	iova = dma_addr;
	ret = arm__alloc_iova_at(dev, iova, size);

	if (iova == -ENXIO) {
		/* Linear map request is out side iova window.
		 * It usually happens when an SMMU client need to
		 * access physcial memory and IOVA range is not overlapping
		 * with it. The client would need mapping to be able to access
		 * desired phys memory. Map request should be carried out even
		 * without successful IOVA allocation.
		 */
		iova = dma_addr;
	} else if (ret == DMA_ERROR_CODE) {
		return ret;
	} else if (iova != dma_addr) {
		arm__free_iova(dev, ret, size);
		return DMA_ERROR_CODE;
	}

	return arm_iommu_map_page_at(dev, phys_to_page(phys), iova,
				     0, size, dir, attrs);
}


bool device_is_iommuable(struct device *dev)
{
	return (dev->archdata.dma_ops == &iommu_dma_ops);
}
EXPORT_SYMBOL(device_is_iommuable);

/* __alloc_iova_at() is broken with extensions enabled.
 * Disable the extensions till it is fixed.
 */
#define DISABLE_EXTENSIONS 1

/**
 * arm_iommu_create_mapping
 * @bus: pointer to the bus holding the client device (for IOMMU calls)
 * @base: start address of the valid IO address space
 * @size: maximum size of the valid IO address space
 *
 * Creates a mapping structure which holds information about used/unused
 * IO address ranges, which is required to perform memory allocation and
 * mapping with IOMMU aware functions.
 *
 * The client device need to be attached to the mapping with
 * arm_iommu_attach_device function.
 */
struct dma_iommu_mapping *
arm_iommu_create_mapping(struct bus_type *bus, dma_addr_t base, size_t size)
{
	struct dma_iommu_mapping *mapping;
	struct iommu_domain *domain;
	int err = -ENOMEM;

	mapping = kzalloc(sizeof(struct dma_iommu_mapping), GFP_KERNEL);
	if (!mapping)
		goto err;

	mapping->base = base;
	mapping->end = base + size;

	spin_lock_init(&mapping->lock);

	mapping->domain = iommu_domain_alloc(bus);
	if (!mapping->domain)
		goto err4;

	domain = mapping->domain;
	domain->geometry.aperture_start = base;
	domain->geometry.aperture_end   = base + size;
	domain->geometry.force_aperture = 1;

	kref_init(&mapping->kref);

	iommu_mapping_list_add(mapping);
	return mapping;
err4:
	kfree(mapping);
err:
	return ERR_PTR(err);
}

static void release_iommu_mapping(struct kref *kref)
{
	struct dma_iommu_mapping *mapping =
		container_of(kref, struct dma_iommu_mapping, kref);

	iommu_mapping_list_del(mapping);
	iommu_domain_free(mapping->domain);
	kfree(mapping);
}

void arm_iommu_release_mapping(struct dma_iommu_mapping *mapping)
{
	if (mapping)
		kref_put(&mapping->kref, release_iommu_mapping);
}

/**
 * arm_iommu_attach_device
 * @dev: valid struct device pointer
 * @mapping: io address space mapping structure (returned from
 *	arm_iommu_create_mapping)
 *
 * Attaches specified io address space mapping to the provided device,
 * this replaces the dma operations (dma_map_ops pointer) with the
 * IOMMU aware version. More than one client might be attached to
 * the same io address space mapping.
 */
int arm_iommu_attach_device(struct device *dev,
			    struct dma_iommu_mapping *mapping)
{
	int err;
	struct dma_map_ops *org_ops;
	struct dma_iommu_mapping *org_map;
	struct iommu_domain *domain;

#ifdef CONFIG_DMA_API_DEBUG
	struct iommu_usage *device_ref;

	device_ref = kzalloc(sizeof(*device_ref), GFP_KERNEL);
	if (!device_ref)
		return -ENOMEM;

	device_ref->dev = dev;
	list_add(&device_ref->recordlist, &iommu_rlist_head);
#endif

	org_ops = get_dma_ops(dev);
	set_dma_ops(dev, &iommu_dma_ops);

	org_map = dev->archdata.mapping;
	dev->archdata.mapping = mapping;

	err = iommu_attach_device(mapping->domain, dev);
	if (err) {
		set_dma_ops(dev, org_ops);
		dev->archdata.mapping = org_map;
#ifdef CONFIG_DMA_API_DEBUG
		list_del(&device_ref->recordlist);
		kfree(device_ref);
#endif
		return err;
	}

	domain = mapping->domain;
	if (!iommu_get_dma_cookie(domain)) {
		if (iommu_dma_init_domain(domain,
					  domain->geometry.aperture_start,
					  domain->geometry.aperture_end -
					  domain->geometry.aperture_start, dev))
			pr_err("iommu_dma_init_domain failed, %s\n",
				dev_name(dev));
	}


	kref_get(&mapping->kref);

	pr_debug("Attached IOMMU controller to %s device.\n", dev_name(dev));
	return 0;
}

/**
 * arm_iommu_detach_device
 * @dev: valid struct device pointer
 *
 * Detaches the provided device from a previously attached map.
 * This voids the dma operations (dma_map_ops pointer)
 */
void arm_iommu_detach_device(struct device *dev)
{
	struct dma_iommu_mapping *mapping;
#ifdef CONFIG_DMA_API_DEBUG
	struct iommu_usage *device_ref, *tmp;
#endif

	mapping = to_dma_iommu_mapping(dev);
	if (!mapping) {
		dev_warn(dev, "Not attached\n");
		return;
	}

#ifdef CONFIG_DMA_API_DEBUG
	list_for_each_entry_safe(device_ref, tmp, &iommu_rlist_head,
		recordlist) {
		if (dev == device_ref->dev) {
			list_del(&device_ref->recordlist);
			kfree(device_ref);
			break;
		}
	}
#endif

	iommu_detach_device(mapping->domain, dev);
	kref_put(&mapping->kref, release_iommu_mapping);
	mapping = NULL;
	set_dma_ops(dev, NULL);

	pr_debug("Detached IOMMU controller from %s device.\n", dev_name(dev));
}

#endif

#ifdef CONFIG_DMA_API_DEBUG
static void
add_value(struct dma_iommu_mapping *device_ref, size_t size, const int type)
{
	switch (type) {
	case ALLOC_OR_FREE:
		atomic64_add(size, &device_ref->alloc_size);
		break;
	case ATOMIC_ALLOC_OR_FREE:
		atomic64_add(size, &device_ref->atomic_alloc_size);
		break;
	case MAP_OR_UNMAP:
		atomic64_add(size, &device_ref->map_size);
		break;
	case CPU_MAP_OR_UNMAP:
		atomic64_add(size, &device_ref->cpu_map_size);
		break;
	default:
		pr_info("Invalid argument in function %s\n", __func__);
	}
}

static void
sub_value(struct dma_iommu_mapping *device_ref, size_t size, const int type)
{
	switch (type) {
	case ALLOC_OR_FREE:
		atomic64_sub(size, &device_ref->alloc_size);
		break;
	case ATOMIC_ALLOC_OR_FREE:
		atomic64_sub(size, &device_ref->atomic_alloc_size);
		break;
	case MAP_OR_UNMAP:
		atomic64_sub(size, &device_ref->map_size);
		break;
	case CPU_MAP_OR_UNMAP:
		atomic64_sub(size, &device_ref->cpu_map_size);
		break;
	default:
		pr_info("Invalid argument in function %s\n", __func__);
	}
}

static size_t
dmastats_alloc_or_map(struct device *dev, size_t size, const int type)
{
	struct dma_iommu_mapping *mapping;

	mapping = to_dma_iommu_mapping(dev);
	if (mapping)
		add_value(mapping, size, type);
	else
		atomic64_add(size, &dev_is_null->alloc_size);
	return 0;
}

static size_t dmastats_free_or_unmap(struct device *dev, size_t size,
	const int type)
{
	struct dma_iommu_mapping *mapping;

	mapping = to_dma_iommu_mapping(dev);
	if (mapping)
		sub_value(mapping, size, type);
	else
		atomic64_sub(size, &dev_is_null->alloc_size);
	return 0;
}

static int dmastats_debug_show(struct seq_file *s, void *data)
{
	struct iommu_usage *device_ref = NULL, *tmp;
	size_t alloc_size = 0, map_size = 0;
	size_t atomic_alloc_size = 0, cpu_map_size = 0;
	struct dma_iommu_mapping *mapping;

	seq_printf(s, "%-24s %18s %18s %18s %18s\n", "DEV_NAME", "ALLOCATED",
			"ATOMIC_ALLOCATED", "MAPPED", "CPU_MAPPED");
	list_for_each_entry_safe(device_ref, tmp, &iommu_rlist_head,
		recordlist) {
		mapping = to_dma_iommu_mapping(device_ref->dev);
		alloc_size += atomic64_read(&mapping->alloc_size);
		map_size += atomic64_read(&mapping->map_size);
		atomic_alloc_size += atomic64_read(&mapping->atomic_alloc_size);
		cpu_map_size += atomic64_read(&mapping->cpu_map_size);

		seq_printf(s, "%-24s %18ld %18ld %18ld %18ld\n",
			dev_name(device_ref->dev),
			atomic64_read(&mapping->alloc_size),
			atomic64_read(&mapping->atomic_alloc_size),
			atomic64_read(&mapping->map_size),
			atomic64_read(&mapping->cpu_map_size));
	}

	alloc_size += atomic64_read(&dev_is_null->alloc_size);
	map_size += atomic64_read(&dev_is_null->map_size);
	atomic_alloc_size += atomic64_read(&dev_is_null->atomic_alloc_size);
	cpu_map_size += atomic64_read(&dev_is_null->cpu_map_size);

	seq_printf(s, "%-24s %18ld %18ld %18ld %18ld\n",
		dev_is_null->dev_name,
		atomic64_read(&dev_is_null->alloc_size),
		atomic64_read(&dev_is_null->atomic_alloc_size),
		atomic64_read(&dev_is_null->map_size),
		atomic64_read(&dev_is_null->cpu_map_size));

	seq_printf(s, "\n%-24s %18zu %18zu %18zu %18zu\n", "Total",
		alloc_size, atomic_alloc_size, map_size, cpu_map_size);
	return 0;
}

static int dmastats_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, dmastats_debug_show, NULL);
}

static const struct file_operations debug_dmastats_fops = {
	.open		= dmastats_debug_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init dmastats_debug_init(void)
{
	struct dentry *rootdir, *ret;

	rootdir = debugfs_create_dir("dma", NULL);
	if (!rootdir) {
		pr_err("Failed to create dma directory!\n");
		return -ENOMEM;
	}

	ret = debugfs_create_file("usage", S_IRUGO, rootdir, NULL,
		&debug_dmastats_fops);
	if (!ret) {
		pr_err("Failed to create usage debug file!\n");
		return -ENOMEM;
	}

	dev_is_null = kzalloc(sizeof(*dev_is_null), GFP_KERNEL);
	if (!dev_is_null)
		return -ENOMEM;

	dev_is_null->dev_name = NULL_DEV;
	return 0;
}

static void __exit dmastats_debug_exit(void)
{
	struct iommu_usage *device_ref = NULL, *tmp;

	list_for_each_entry_safe(device_ref, tmp, &iommu_rlist_head,
		recordlist) {
		list_del(&device_ref->recordlist);
		kfree(device_ref);
	}

	kfree(dev_is_null);
}

late_initcall(dmastats_debug_init);
module_exit(dmastats_debug_exit);
#endif
