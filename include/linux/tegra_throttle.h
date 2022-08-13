/*
 * include/linux/tegra_throttle.h
 *
 * Copyright (c) 2010-2017 NVIDIA CORPORATION. All rights reserved.
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

#ifndef __TEGRA_THROTTLE_H
#define __TEGRA_THROTTLE_H

#include <linux/therm_est.h>
#include <linux/thermal.h>

struct tegra_cooling_device {
	char *cdev_type;
	int *trip_temperatures;
	int trip_temperatures_num;
	const char *compatible;
	struct device_node *cdev_dn;
};

#define MAX_THROT_TABLE_SIZE	(64)
#define NO_CAP			(ULONG_MAX) /* no cap */
#define CPU_THROT_LOW		0 /* lowest throttle freq. only used for CPU */

#ifdef CONFIG_TEGRA_THERMAL_THROTTLE
bool tegra_is_throttling(int *count);
#else
static inline bool tegra_is_throttling(int *count)
{ return false; }
#endif /* CONFIG_TEGRA_THERMAL_THROTTLE */

#endif	/* __TEGRA_THROTTLE_H */
