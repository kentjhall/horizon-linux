/*
 * Copyright (c) 2012-2017, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __SOC_TEGRA_AHB_H__
#define __SOC_TEGRA_AHB_H__

extern int tegra_ahb_enable_smmu(struct device_node *ahb);

int tegra_ahb_get_master_id(struct device *dev);

bool tegra_ahb_is_mem_wrque_busy(u32 mst_id);

#endif /* __SOC_TEGRA_AHB_H__ */
