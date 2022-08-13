/*
 * drivers/platform/tegra/pm_domains.c
 *
 * Copyright (c) 2012-2018, NVIDIA CORPORATION. All rights reserved.
 *
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

#include <linux/module.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/pm_domain.h>
#include <linux/tegra_pm_domains.h>
#include <linux/tegra-powergate.h>
#include <linux/slab.h>

typedef int (*of_tegra_pd_init_cb_t)(struct generic_pm_domain *);

static int tegra_legacy_power_off(struct generic_pm_domain *genpd)
{
	struct tegra_pm_domain *pd = to_tegra_pd(genpd);

	return tegra_powergate_partition(pd->partition_id);
}

static int tegra_legacy_power_on(struct generic_pm_domain *genpd)
{
	struct tegra_pm_domain *pd = to_tegra_pd(genpd);

	return tegra_unpowergate_partition(pd->partition_id);
}

static int __init tegra_init_legacy_ops(struct generic_pm_domain *pd)
{
	struct tegra_pm_domain *tpd = to_tegra_pd(pd);

	if (tpd->partition_id == -1)
		return -EINVAL;

	pd->power_off = tegra_legacy_power_off;
	pd->power_on = tegra_legacy_power_on;
	return 0;
}

/* Do not add to this list */
static const struct of_device_id tegra_pd_match[] __initconst = {
	{.compatible = "nvidia,tegra210-ape-pd", .data = NULL},
	{.compatible = "nvidia,tegra210-pcie-pd", .data = tegra_init_legacy_ops},
	{},
};

/* node: device tree node of the child power domain */
static int attach_subdomain(struct device_node *node)
{
	int ret;
	struct of_phandle_args master_phandle, child_phandle;

	child_phandle.np = node;
	child_phandle.args_count = 0;

	ret = of_parse_phandle_with_args(node, "power-domains",
					 "#power-domain-cells", 0,
					 &master_phandle);

	if (ret < 0)
		return ret;

	pr_info("Adding domain %s to PM domain %s\n",
		node->name, master_phandle.np->name);
	of_genpd_add_subdomain(&master_phandle, &child_phandle);

	return 0;
}

static int __init tegra_init_pd(struct device_node *np)
{
	struct tegra_pm_domain *tpd;
	struct generic_pm_domain *gpd;
	of_tegra_pd_init_cb_t tpd_init_cb;
	const struct of_device_id *match = of_match_node(tegra_pd_match, np);
	bool is_off = false;

	tpd = (struct tegra_pm_domain *)kzalloc
			(sizeof(struct tegra_pm_domain), GFP_KERNEL);
	if (!tpd) {
		pr_err("Failed to allocate memory for %s domain\n",
					of_node_full_name(np));
		return -ENOMEM;
	}

	gpd = &tpd->gpd;
	gpd->name = (char *)np->name;
	tpd_init_cb = match->data;

	if (tpd_init_cb)
		tpd_init_cb(gpd);

	if (of_property_read_u32(np, "partition-id", &tpd->partition_id))
		tpd->partition_id = -1;

	is_off = !tegra_powergate_is_powered(tpd->partition_id);

	pm_genpd_init(gpd, &simple_qos_governor, is_off);

	of_genpd_add_provider_simple(np, gpd);

	attach_subdomain(np);
	return 0;
}

static int __init tegra_init_pm_domain(void)
{
	struct device_node *np;
	int ret = 0;

	for_each_matching_node(np, tegra_pd_match) {
		ret = tegra_init_pd(np);
		if (ret)
			return ret;
	}

	return ret;
}
core_initcall(tegra_init_pm_domain);

int tegra_pd_get_powergate_id(const struct of_device_id *dev_id)
{
	struct device_node *dn = NULL;
	u32 partition_id;
	int ret = -EINVAL;

	for_each_matching_node(dn, dev_id) {
		ret = of_property_read_u32(dn, "partition-id", &partition_id);
		break;
	}

	if (ret) {
		pr_err("Reading powergate-id failed\n");
		return ret;
	}

	return partition_id;
}
EXPORT_SYMBOL(tegra_pd_get_powergate_id);
