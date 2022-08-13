extern void __init bootmem_init(void);

#ifdef CONFIG_ZONE_DMA
#define arm_dma_limit (0xffffffff)
#else
#define arm_dma_limit ((phys_addr_t)~0)
#endif
