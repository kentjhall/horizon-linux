/*
 * Copyright (c) 2014-2017, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef __DRIVERS_THERMAL_TEGRA_SOCTHERM_H
#define __DRIVERS_THERMAL_TEGRA_SOCTHERM_H

#include <linux/tsensor-fuse.h>

#define THERMCTL_LEVEL0_GROUP_CPU               0x0
#define THERMCTL_LEVEL0_GROUP_GPU		0x4
#define THERMCTL_LEVEL0_GROUP_MEM		0x8
#define THERMCTL_LEVEL0_GROUP_TSENSE		0xc

#define SENSOR_CONFIG2                          8
#define SENSOR_CONFIG2_THERMA_MASK		(0xffff << 16)
#define SENSOR_CONFIG2_THERMA_SHIFT		16
#define SENSOR_CONFIG2_THERMB_MASK		0xffff
#define SENSOR_CONFIG2_THERMB_SHIFT		0

#define THERMCTL_THERMTRIP_CTL			0x80
/* BITs are defined in device file */

#define SENSOR_PDIV				0x1c0
#define SENSOR_PDIV_CPU_MASK			(0xf << 12)
#define SENSOR_PDIV_GPU_MASK			(0xf << 8)
#define SENSOR_PDIV_MEM_MASK			(0xf << 4)
#define SENSOR_PDIV_PLLX_MASK			(0xf << 0)

#define SENSOR_HOTSPOT_OFF			0x1c4
#define SENSOR_HOTSPOT_CPU_MASK			(0xff << 16)
#define SENSOR_HOTSPOT_GPU_MASK			(0xff << 8)
#define SENSOR_HOTSPOT_MEM_MASK			(0xff << 0)

#define SENSOR_HW_PLLX_OFFSET_EN		0x1e4
#define SENSOR_HW_PLLX_OFFSET_MEM_EN_MASK	BIT(2)
#define SENSOR_HW_PLLX_OFFSET_CPU_EN_MASK	BIT(1)
#define SENSOR_HW_PLLX_OFFSET_GPU_EN_MASK	BIT(0)

#define SENSOR_HW_PLLX_OFFSET_MIN		0x1e8
#define SENSOR_HW_PLLX_OFFSET_MAX		0x1ec
#define SENSOR_HW_PLLX_OFFSET_MEM_MASK		(0xff << 16)
#define SENSOR_HW_PLLX_OFFSET_GPU_MASK		(0xff << 8)
#define SENSOR_HW_PLLX_OFFSET_CPU_MASK		(0xff << 0)

#define SENSOR_TEMP1				0x1c8
#define SENSOR_TEMP1_CPU_TEMP_MASK		(0xffff << 16)
#define SENSOR_TEMP1_GPU_TEMP_MASK		0xffff
#define SENSOR_TEMP2				0x1cc
#define SENSOR_TEMP2_MEM_TEMP_MASK		(0xffff << 16)
#define SENSOR_TEMP2_PLLX_TEMP_MASK		0xffff

#define SENSOR_VALID			0x1e0
#define SENSOR_GPU_VALID_MASK		BIT(9)
#define SENSOR_CPU_VALID_MASK		0xf
#define SENSOR_MEM_VALID_MASK		(0x3 << 10)

/**
 * struct tegra_tsensor_group - SOC_THERM sensor group data
 * @name: short name of the temperature sensor group
 * @id: numeric ID of the temperature sensor group
 * @sensor_temp_offset: offset of the SENSOR_TEMP* register
 * @sensor_temp_mask: bit mask for this sensor group in SENSOR_TEMP* register
 * @pdiv: the sensor count post-divider to use during runtime
 * @pdiv_ate: the sensor count post-divider used during automated test
 * @pdiv_mask: register bitfield mask for the PDIV field for this sensor
 * @pllx_hotspot_diff: hotspot offset from the PLLX sensor, must be 0 for
    PLLX sensor group
 * @pllx_hotspot_mask: register bitfield mask for the HOTSPOT field
 */
struct tegra_tsensor_group {
	const char *name;
	u8 id;
	u16 sensor_temp_offset;
	u32 sensor_temp_mask;
	u32 pdiv_mask;
	u32 pllx_hotspot_diff;
	u32 pllx_hotspot_mask;
	u32 hw_pllx_offset_mask;
	u32 hw_pllx_offset_en_mask;
	u32 thermtrip_enable_mask;
	u32 thermtrip_any_en_mask;
	u32 thermtrip_threshold_mask;
	u16 thermctl_lvl0_offset;
	u32 thermctl_isr_mask;
	u32 thermctl_lvl0_up_thresh_mask;
	u32 thermctl_lvl0_dn_thresh_mask;
};

struct tegra_tsensor {
	const char *name;
	const u32 base;
	const struct tegra_tsensor_configuration *config;
	const u32 calib_fuse_offset;
	/*
	 * Correction values used to modify values read from
	 * calibration fuses
	 */
	const struct fuse_corr_coeff fuse_corr;
	const struct tegra_tsensor_group *group;
};

struct tsensor_group_offsets {
	u32 max;
	u32 min;
	u32 hw_offsetting_en;
	const struct tegra_tsensor_group *ttg;
};

struct tsensor_group_thermtrips {
	u8 id;
	u32 temp;
};

struct tegra_soctherm_soc {
	const struct tegra_tsensor *tsensors;
	const unsigned int num_tsensors;
	const struct tegra_tsensor_group **ttgs;
	struct tsensor_group_offsets *toffs;
	const unsigned int num_ttgs;
	const struct tegra_tsensor_fuse *tfuse;
	const int thresh_grain;
	const unsigned int bptt;
	const bool use_ccroc;
	struct tsensor_group_thermtrips *thermtrips;
};

#ifdef CONFIG_ARCH_TEGRA_124_SOC
extern const struct tegra_soctherm_soc tegra124_soctherm;
#endif

#ifdef CONFIG_ARCH_TEGRA_132_SOC
extern const struct tegra_soctherm_soc tegra132_soctherm;
#endif

#ifdef CONFIG_ARCH_TEGRA_210_SOC
extern const struct tegra_soctherm_soc tegra210_soctherm;
extern const struct tegra_soctherm_soc tegra210b01_soctherm;
#endif

#endif

