/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2016-2018, NVIDIA Corporation.  All rights reserved.
 *
 * Author:
 *	Colin Cross <ccross@android.com>
 *	Olof Johansson <olof@lixom.net>
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

#ifndef __TEGRA_EMC_H_
#define __TEGRA_EMC_H_

#define TEGRA_EMC_NUM_REGS 46

enum {
	TEGRA_DRAM_OVER_TEMP_NONE = 0,
	TEGRA_DRAM_OVER_TEMP_REFRESH_X2,
	TEGRA_DRAM_OVER_TEMP_REFRESH_X4,
	TEGRA_DRAM_OVER_TEMP_THROTTLE, /* 4x Refresh + derating. */
	TEGRA_DRAM_OVER_TEMP_MAX,
};

enum emc_user_id {
	EMC_USER_DC1 = 0,
	EMC_USER_DC2,
	EMC_USER_VI,
	EMC_USER_MSENC,
	EMC_USER_2D,
	EMC_USER_3D,
	EMC_USER_BB,
	EMC_USER_VDE,
	EMC_USER_VI2,
	EMC_USER_ISPA,
	EMC_USER_ISPB,
	EMC_USER_NVDEC,
	EMC_USER_NVJPG,
	EMC_USER_NUM,
};

struct tegra_emc_table {
	unsigned long rate;
	u32 regs[TEGRA_EMC_NUM_REGS];
};

struct tegra_emc_pdata {
	int num_tables;
	struct tegra_emc_table *tables;
};

struct emc_clk_ops {
	long		(*emc_round_rate)(unsigned long);
	int		(*emc_set_rate)(unsigned long);
	unsigned long	(*emc_get_rate)(void);
	struct clk *	(*emc_predict_parent)(unsigned long, unsigned long *);
	void		(*emc_get_backup_parent)(struct clk **,
							unsigned long *);
};

struct emc_iso_usage {
	u32 emc_usage_flags;
	u8 iso_usage_share;
	u8 (*iso_share_calculator)(unsigned long iso_bw);
};

#ifdef CONFIG_TEGRA124_EMC
void tegra124_emc_timing_invalidate(void);
bool tegra124_emc_is_ready(void);
unsigned long tegra124_predict_emc_rate(int millivolts);
const struct emc_clk_ops *tegra124_emc_get_ops(void);
#else
static inline void tegra124_emc_timing_invalidate(void) { return; };
static inline bool tegra124_emc_is_ready(void) { return true; };
static inline unsigned long tegra124_predict_emc_rate(int millivolts)
{ return -ENODEV; }
static inline const struct emc_clk_ops *tegra124_emc_get_ops(void)
{ return NULL; }
#endif

#ifdef CONFIG_TEGRA210_EMC
void tegra210_emc_timing_invalidate(void);
bool tegra210_emc_is_ready(void);
unsigned long tegra210_predict_emc_rate(int millivolts);
const struct emc_clk_ops *tegra210_emc_get_ops(void);
int tegra210_emc_get_dram_temp(void);
int tegra210_emc_set_over_temp_state(unsigned long state);
void tegra210_emc_mr4_set_freq_thresh(unsigned long thresh);
#else
static inline void tegra210_emc_timing_invalidate(void) { return; }
static inline bool tegra210_emc_is_ready(void) { return true; }
static inline unsigned long tegra210_predict_emc_rate(int millivolts)
{ return -ENODEV; }
static inline const struct emc_clk_ops *tegra210_emc_get_ops(void)
{ return NULL; }
static inline int tegra210_emc_get_dram_temp(void) {return -ENODEV; }
static inline int tegra210_emc_set_over_temp_state(unsigned long state)
{ return -ENODEV; }
static inline void tegra210_emc_mr4_set_freq_thresh(unsigned long thresh) { }
#endif

#endif
