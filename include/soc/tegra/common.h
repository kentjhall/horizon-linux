/*
 * Copyright (C) 2014-2017 NVIDIA Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __SOC_TEGRA_COMMON_H__
#define __SOC_TEGRA_COMMON_H__

#include <linux/platform_device.h>

#define PMC_RST_STATUS		0x1b4
#define PMC_SCRATCH0		0x50
#define PMC_SCRATCH1		0x54
#define PMC_SCRATCH4		0x60
#define PMC_SCRATCH203		0x84c

struct board_info {
	u16 board_id;
	u16 sku;
	u8  fab;
	u8  major_revision;
	u8  minor_revision;
};

extern phys_addr_t tegra_bootloader_fb_start;
extern phys_addr_t tegra_bootloader_fb_size;
extern phys_addr_t tegra_bootloader_fb2_start;
extern phys_addr_t tegra_bootloader_fb2_size;
extern phys_addr_t tegra_bootloader_fb3_start;
extern phys_addr_t tegra_bootloader_fb3_size;
extern phys_addr_t tegra_bootloader_lut_start;
extern phys_addr_t tegra_bootloader_lut_size;
extern phys_addr_t tegra_bootloader_lut2_start;
extern phys_addr_t tegra_bootloader_lut2_size;
extern phys_addr_t tegra_bootloader_lut3_start;
extern phys_addr_t tegra_bootloader_lut3_size;
extern phys_addr_t tegra_fb_start;
extern phys_addr_t tegra_fb_size;
extern phys_addr_t tegra_fb2_start;
extern phys_addr_t tegra_fb2_size;
extern phys_addr_t tegra_fb3_start;
extern phys_addr_t tegra_fb3_size;
extern phys_addr_t tegra_lut_start;
extern phys_addr_t tegra_lut_size;
extern phys_addr_t tegra_lut2_start;
extern phys_addr_t tegra_lut2_size;
extern phys_addr_t tegra_lut3_start;
extern phys_addr_t tegra_lut3_size;

#ifdef CONFIG_ARCH_TEGRA
bool soc_is_tegra210_n_before(void);
bool soc_is_tegra186_n_later(void);
#else
static inline bool soc_is_tegra210_n_before(void)
{
	return false;
}
static inline bool soc_is_tegra186_n_later(void)
{
	return false;
}
#endif

static inline bool soc_is_tegra(void)
{
	return soc_is_tegra210_n_before() || soc_is_tegra186_n_later();
}

int tegra_get_usb_port_owner_info(void);
void tegra_get_display_board_info(struct board_info *bi);
int tegra_get_board_panel_id(void);
void __tegra_move_framebuffer(struct platform_device *pdev,
				phys_addr_t to, phys_addr_t from, size_t size);
void __tegra_clear_framebuffer(struct platform_device *pdev,
				unsigned long to, unsigned long size);


#endif /* __SOC_TEGRA_COMMON_H__ */
