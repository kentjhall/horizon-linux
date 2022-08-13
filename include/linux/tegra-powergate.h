/*
 * Copyright (c) 2010 Google, Inc
 * Copyright (C) 2011-2017, NVIDIA Corporation. All rights reserved.
 *
 * Author:
 *	Colin Cross <ccross@google.com>
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

#ifndef _LINUX_TEGRA_POWERGATE_H_
#define _LINUX_TEGRA_POWERGATE_H_

#include <linux/init.h>
#include <linux/notifier.h>

#define TEGRA_CPU_POWERGATE_ID(cpu)					\
		tegra_powergate_cpuid_to_powergate_id(cpu)

#ifdef CONFIG_TEGRA_POWERGATE
int tegra_cpu_powergate_id(int cpuid);
int tegra_powergate_is_powered(int id);
int tegra_powergate_mc_disable(int id);
int tegra_powergate_mc_enable(int id);
int tegra_powergate_mc_flush(int id);
int tegra_powergate_mc_flush_done(int id);
bool tegra_powergate_check_clamping(int id);
int tegra_powergate_remove_clamping(int id);
const char *tegra_powergate_get_name(int id);

/*
 * Functions to powergate un-powergate partitions.
 * Drivers are responsible for clk enable-disable
 *
 * tegra_powergate_partition() should be called with all
 * required clks OFF. Drivers should disable clks BEFORE
 * calling this fucntion
 *
 * tegra_unpowergate_partition should be called with all
 * required clks OFF. Returns with all clks OFF. Drivers
 * should enable all clks AFTER this function
 */
int tegra_powergate_partition(int id);
int tegra_unpowergate_partition(int id);
int slcg_register_notifier(int id, struct notifier_block *nb);
int slcg_unregister_notifier(int id, struct notifier_block *nb);
int tegra_powergate_cpuid_to_powergate_id(int cpu);
#else
static inline int tegra_powergate_is_powered(int id)
{
	return 1;
}

static inline int tegra_powergate_partition(int id)
{
	return -ENOSYS;
}

static inline int tegra_unpowergate_partition(int id)
{
	return -ENOSYS;
}

static inline bool tegra_powergate_check_clamping(int id)
{
	return false;
}
static inline int tegra_powergate_remove_clamping(int id)
{
	return -EOPNOTSUPP;
}

static inline int slcg_register_notifier(int id, struct notifier_block *nb)
{
	return 0;
}
static inline int slcg_unregister_notifier(int id, struct notifier_block *nb)
{
	return 0;
}
static inline int tegra_powergate_cpuid_to_powergate_id(int cpu)
{
	return -1;
}
#endif

#endif /* _LINUX_TEGRA_POWERGATE_H_ */
