#ifndef _ASM_ARM64_DMA_CONTIGUOUS_H
#define _ASM_ARM64_DMA_CONTIGUOUS_H

#include <linux/types.h>

void dma_contiguous_early_fixup(phys_addr_t base, unsigned long size);

#endif
