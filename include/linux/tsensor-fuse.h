/*
 * Copyright (c) 2016, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef __DRIVERS_THERMAL_TEGRA_TSOSC_FUSE_H
#define __DRIVERS_THERMAL_TEGRA_TSOSC_FUSE_H

struct tegra_tsensor_configuration {
	u32 tall;
	u32 tiddq_en;
	u32 ten_count;
	u32 pdiv;
	u32 pdiv_ate;
	u32 tsample;
	u32 tsample_ate;
};

struct tegra_tsensor_fuse {
	u32 fuse_base_cp_mask;
	u32 fuse_base_cp_shift;
	u32 fuse_base_ft_mask;
	u32 fuse_base_ft_shift;
	u32 fuse_shift_ft_mask;
	u32 fuse_shift_ft_shift;
	u32 fuse_spare_realignment;
};

struct tsensor_shared_calib {
	u32 base_cp;
	u32 base_ft;
	u32 actual_temp_cp;
	u32 actual_temp_ft;
};

struct fuse_corr_coeff {
	s32 alpha;
	s32 beta;
};

int tegra_calc_shared_calib(const struct tegra_tsensor_fuse *tfuse,
			    struct tsensor_shared_calib *shared);
int tegra_calc_tsensor_calib(const struct tegra_tsensor_configuration *cfg,
			     const struct tsensor_shared_calib *shared,
			     const struct fuse_corr_coeff *corr,
			     u32 *calibration, u32 offset);

#endif
