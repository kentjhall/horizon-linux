/*
 * Copyright (c) 2017, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef _SOC_TEGRA_POWERGATE_DRIVER_H_
#define _SOC_TEGRA_POWERGATE_DRIVER_H_

struct tegra_powergate_driver_ops {
	const char *soc_name;

	int num_powerdomains;
	int num_cpu_domains;
	u8 *cpu_domains;

	spinlock_t *(*get_powergate_lock)(void);

	const char *(*get_powergate_domain_name)(int id);

	bool (*powergate_id_is_soc_valid)(int id);
	int (*powergate_cpuid_to_powergate_id)(int cpu);

	int (*powergate_partition)(int);
	int (*unpowergate_partition)(int id);

	int (*powergate_mc_enable)(int id);
	int (*powergate_mc_disable)(int id);

	int (*powergate_mc_flush)(int id);
	int (*powergate_mc_flush_done)(int id);

	int (*powergate_init_refcount)(void);

	bool (*powergate_check_clamping)(int id);

	bool (*powergate_skip)(int id);

	bool (*powergate_is_powered)(int id);

	int (*powergate_remove_clamping)(int id);

	int (*slcg_register_notifier)(int id, struct notifier_block *nb);

	int (*slcg_unregister_notifier)(int id, struct notifier_block *nb);
};

/* INIT APIs: New SoC needs to add its support here */
#if defined(CONFIG_ARCH_TEGRA_210_SOC)
struct tegra_powergate_driver_ops *tegra210_powergate_init_chip_support(void);
#else
static inline
struct tegra_powergate_driver_ops *tegra210_powergate_init_chip_support(void)
{
	return NULL;
}
#endif

#if defined(CONFIG_ARCH_TEGRA_18x_SOC)
struct tegra_powergate_driver_ops *tegra186_powergate_init_chip_support(void);
#else
static inline
struct tegra_powergate_driver_ops *tegra186_powergate_init_chip_support(void)
{
	return NULL;
}
#endif

struct tegra_powergate_driver_ops *tegra194_powergate_init_chip_support(void);

#endif /* _SOC_TEGRA_POWERGATE_DRIVER_H_ */
