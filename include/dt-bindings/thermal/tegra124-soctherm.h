/*
 * Copyright (c) 2014 - 2017, NVIDIA CORPORATION.  All rights reserved.
 *
 * Author:
 *	Mikko Perttunen <mperttunen@nvidia.com>
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
 * This header provides constants for binding nvidia,tegra124-soctherm.
 */

#ifndef _DT_BINDINGS_THERMAL_TEGRA124_SOCTHERM_H
#define _DT_BINDINGS_THERMAL_TEGRA124_SOCTHERM_H

#define TEGRA124_SOCTHERM_SENSOR_CPU 0
#define TEGRA124_SOCTHERM_SENSOR_MEM 1
#define TEGRA124_SOCTHERM_SENSOR_GPU 2
#define TEGRA124_SOCTHERM_SENSOR_PLLX 3
#define TEGRA124_SOCTHERM_SENSOR_NUM 4

#define TEGRA_SOCTHERM_THROT_LEVEL_NONE 0
#define TEGRA_SOCTHERM_THROT_LEVEL_LOW  1
#define TEGRA_SOCTHERM_THROT_LEVEL_MED  2
#define TEGRA_SOCTHERM_THROT_LEVEL_HIGH 3

#endif
