/*
 * include/linux/irqchip/tegra-agic.h
 *
 * Header file for managing AGIC interrupt controller
 *
 * Copyright (C) 2014-2017 NVIDIA Corporation. All rights reserved.
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

#ifndef _TEGRA_AGIC_H_
#define _TEGRA_AGIC_H_

#include <linux/irqchip/tegra-t18x-agic.h>
#include <linux/irqchip/tegra-t210-agic.h>

enum tegra_agic_cpu {
	TEGRA_AGIC_T210_APE_HOST = 0,
	TEGRA_AGIC_T210_ADSP = 1,
	MAX_AGIC_T210_INTERFACES = 2,
	TEGRA_AGIC_T18x_APE_HOST0 = 0,
	TEGRA_AGIC_T18x_APE_HOST1 = 1,
	TEGRA_AGIC_T18x_APE_HOST2 = 2,
	TEGRA_AGIC_T18x_APE_HOST3 = 3,
	TEGRA_AGIC_T18x_ADSP = 4,
	MAX_AGIC_T18x_INTERFACES = 5,
};

extern int tegra_agic_route_interrupt(int irq, enum tegra_agic_cpu cpu);
extern bool tegra_agic_irq_is_active(int irq);
extern bool tegra_agic_irq_is_pending(int irq);
extern void tegra_agic_clear_pending(int irq);
extern void tegra_agic_clear_active(int irq);
#endif /* _TEGRA_AGIC_H_ */
