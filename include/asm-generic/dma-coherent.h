#ifndef DMA_COHERENT_H
#define DMA_COHERENT_H

#ifdef CONFIG_HAVE_GENERIC_DMA_COHERENT
/*
 * These three functions are only for dma allocator.
 * Don't use them in device drivers.
 */
int dma_alloc_from_coherent_attr(struct device *dev, ssize_t size,
				       dma_addr_t *dma_handle, void **ret,
				       unsigned long attrs);
int dma_release_from_coherent_attr(struct device *dev, size_t size, void *vaddr,
				       unsigned long attrs, dma_addr_t dma_handle);
#define dma_alloc_from_coherent(d, s, h, r) \
	 dma_alloc_from_coherent_attr(d, s, h, r, 0)
#define dma_release_from_coherent(d, s, v) \
	 dma_release_from_coherent_attr(d, s, v, 0, 0)

int dma_mmap_from_coherent(struct device *dev, struct vm_area_struct *vma,
			    void *cpu_addr, size_t size, int *ret);
/*
 * Standard interface
 */
#define ARCH_HAS_DMA_DECLARE_COHERENT_MEMORY
struct dma_declare_info;
struct dma_coherent_stats;

extern int
dma_declare_coherent_resizable_cma_memory(struct device *dev,
				struct dma_declare_info *dma_info);

extern int
dma_set_resizable_heap_floor_size(struct device *dev, size_t floor_size);

int dma_declare_coherent_memory(struct device *dev, phys_addr_t phys_addr,
				dma_addr_t device_addr, size_t size, int flags);

int _dma_declare_coherent_memory(struct device *dev, phys_addr_t phys_addr,
				dma_addr_t device_addr, size_t size,
				unsigned long alloc_shift, int flags);
unsigned long dma_get_coherent_memory_alloc_shift(struct device *dev);

void dma_release_declared_memory(struct device *dev);

bool dma_is_coherent_dev(struct device *dev);

extern int
dma_get_coherent_stats(struct device *dev,
			struct dma_coherent_stats *stats);

#else
#define dma_alloc_from_coherent_attr(dev, size, handle, ret, attr) (0)
#define dma_release_from_coherent_attr(dev, size, vaddr, attr, dma_handle) (0)
#define dma_alloc_from_coherent(dev, size, handle, ret) (0)
#define dma_release_from_coherent(dev, order, vaddr) (0)
#define dma_mmap_from_coherent(dev, vma, vaddr, order, ret) (0)
#define dma_declare_coherent_resizable_cma_memory(dev, dma_info) (0)
#define dma_is_coherent_dev(dev) (0)
#define dma_get_coherent_stats(dev, dma_stats) (0)
#endif

#endif
