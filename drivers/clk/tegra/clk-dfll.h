/*
 * clk-dfll.h - prototypes and macros for the Tegra DFLL clocksource driver
 * Copyright (C) 2013 NVIDIA Corporation.  All rights reserved.
 *
 * Aleksandr Frid <afrid@nvidia.com>
 * Paul Walmsley <pwalmsley@nvidia.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __DRIVERS_CLK_TEGRA_CLK_DFLL_H
#define __DRIVERS_CLK_TEGRA_CLK_DFLL_H

#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/types.h>
#include <soc/tegra/cvb.h>
#include <soc/tegra/tegra-dfll.h>

struct thermal_tv;

/**
 * struct tegra_dfll_soc_data - SoC-specific hooks/integration for the DFLL driver
 * @dev: struct device * that holds the OPP table for the DFLL
 * @max_freq: maximum frequency supported on this SoC
 * @cvb: CPU frequency table for this SoC
 * @set_clock_trimmers_low: callback to tune clock trimmers for low voltage
 * @tune0_low: DFLL tuning register 0 (low voltage range)
 * @tune0_high: DFLL tuning register 0 (high voltage range)
 * @tune1: DFLL tuning register 1
 * @set_clock_trimmers_high: fn ptr to tune clock trimmers for high voltage
 * @set_clock_trimmers_low: fn ptr to tune clock trimmers for low voltage
 * @thermal_floor_table: table mapping a given temperature to a minimum voltage
 * @thermal_cap_table: table mapping a given temperature to a maximum voltage
 * @thermal_floor_table_size: size of thermal_floor_table
 * @thermal_cap_table_size: size of thermal_cap_table
 */
struct tegra_dfll_soc_data {
	struct device *dev;
	unsigned long max_freq;
	const struct cvb_table *cvb;
	struct rail_alignment alignment;
	unsigned int min_millivolts;
	unsigned int tune_high_min_millivolts;
	u32 tune0_low;
	u32 tune0_high;
	u32 tune1_low;
	u32 tune1_high;
	unsigned int tune_high_margin_millivolts;
	void (*init_clock_trimmers)(void);
	void (*set_clock_trimmers_high)(void);
	void (*set_clock_trimmers_low)(void);
	const struct thermal_tv *thermal_floor_table;
	const struct thermal_tv *thermal_cap_table;
	unsigned int thermal_floor_table_size;
	unsigned int thermal_cap_table_size;
};


/*
 * These thermal boundaries are not set in thermal zone as trip-points, but
 * must be below/above all other actually set DFLL thermal trip-points.
 */
#define DFLL_THERMAL_CAP_NOCAP		0
#define DFLL_THERMAL_FLOOR_NOFLOOR	125000

int tegra_dfll_register(struct platform_device *pdev,
			struct tegra_dfll_soc_data *soc);
struct tegra_dfll_soc_data *tegra_dfll_unregister(struct platform_device *pdev);
void tegra_dfll_suspend(struct platform_device *pdev);
void tegra_dfll_resume(struct platform_device *pdev, bool on_dfll);
int tegra_dfll_resume_tuning(struct device *dev);
int tegra_dfll_runtime_suspend(struct device *dev);
int tegra_dfll_runtime_resume(struct device *dev);
#endif /* __DRIVERS_CLK_TEGRA_CLK_DFLL_H */
