/*
 * Copyright (C) 2016 NVIDIA Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __SOC_TEGRA_PWM_TEGRA_DFLL_H__
#define __SOC_TEGRA_PWM_TEGRA_DFLL_H__

#ifdef CONFIG_PWM_TEGRA_DFLL
int tegra_dfll_pwm_output_enable(void);
int tegra_dfll_pwm_output_disable(void);
#else
static inline int tegra_dfll_pwm_output_enable(void)
{
	return -ENOTSUPP;
}

static inline int tegra_dfll_pwm_output_disable(void)
{
	return -ENOTSUPP;
}
#endif

#endif /* __SOC_TEGRA_PWM_TEGRA_DFLL_H__ */
