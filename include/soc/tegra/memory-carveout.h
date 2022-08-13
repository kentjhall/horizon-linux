/*
 * Copyright (c) 2016, NVIDIA Corporation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __SOC_TEGRA_MEMORY_CARVEOUT_H__
#define __SOC_TEGRA_MEMORY_CARVEOUT_H__

#include <linux/types.h>

extern phys_addr_t tegra_carveout_start;
extern phys_addr_t tegra_carveout_size;
extern phys_addr_t tegra_vpr_start;
extern phys_addr_t tegra_vpr_size;
extern bool tegra_vpr_resize;

#endif /* __SOC_TEGRA_MEMORY_CARVEOUT_H__ */
