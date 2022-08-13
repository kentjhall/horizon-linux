/*
 * pinctrl configuration definitions for the NVIDIA Tegra pinmux
 *
 * Copyright (c) 2011-2017, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef __PINCONF_TEGRA_H__
#define __PINCONF_TEGRA_H__

struct device;

#ifdef CONFIG_PINCTRL_TEGRA
extern int tegra_pinctrl_config_prod(struct device *dev,
		const char *prod_name);
#else
static inline int tegra_pinctrl_config_prod(struct device *dev,
		const char *prod_name)
{
	return 0;
}
#endif

#endif
