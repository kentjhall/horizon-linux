/*
 * arch/arm/mach-tegra/powergate.c
 *
 * Copyright (c) 2010 Google, Inc
 * Copyright (c) 2011 - 2017, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <soc/tegra/fuse.h>
#include <soc/tegra/tegra_powergate.h>
#include <soc/tegra/tegra-powergate-driver.h>
#include <trace/events/power.h>
#include <asm/atomic.h>

int TEGRA_POWERGATE_DISA;
EXPORT_SYMBOL(TEGRA_POWERGATE_DISA);

int TEGRA_POWERGATE_SOR;
EXPORT_SYMBOL(TEGRA_POWERGATE_SOR);

static struct tegra_powergate_driver_ops *pg_ops;

static inline bool tegra_powergate_check_skip_list(int id)
{
	return pg_ops->powergate_skip ?
		pg_ops->powergate_skip(id) : false;
}

/* EXTERNALY VISIBLE APIS */
int slcg_register_notifier(int id, struct notifier_block *nb)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->slcg_register_notifier)
		return pg_ops->slcg_register_notifier(id, nb);

	return 0;
}
EXPORT_SYMBOL(slcg_register_notifier);

int slcg_unregister_notifier(int id, struct notifier_block *nb)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->slcg_unregister_notifier)
		return pg_ops->slcg_unregister_notifier(id, nb);

	return 0;
}
EXPORT_SYMBOL(slcg_unregister_notifier);

bool tegra_powergate_check_clamping(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return false;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return false;
	}

	if (pg_ops->powergate_check_clamping)
		return pg_ops->powergate_check_clamping(id);

	return 0;
}
EXPORT_SYMBOL(tegra_powergate_check_clamping);

int tegra_powergate_remove_clamping(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->powergate_remove_clamping)
		return pg_ops->powergate_remove_clamping(id);

	return 0;
}
EXPORT_SYMBOL(tegra_powergate_remove_clamping);

int tegra_powergate_is_powered(int id)
{
	if (!pg_ops) {
		pr_debug("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->powergate_is_powered)
		return pg_ops->powergate_is_powered(id);

	return true;
}
EXPORT_SYMBOL(tegra_powergate_is_powered);

int tegra_cpu_powergate_id(int cpuid)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (cpuid < 0 || cpuid >= pg_ops->num_cpu_domains) {
		pr_info("%s: invalid powergate id\n", __func__);
		return -EINVAL;
	}

	if (pg_ops->cpu_domains)
		return pg_ops->cpu_domains[cpuid];
	else
		WARN_ON_ONCE("This SOC does not support CPU powergate\n");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_cpu_powergate_id);

int tegra_powergate_partition(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (tegra_powergate_check_skip_list(id))
		printk_once("%s: %s is in powergate skip list\n", __func__,
			tegra_powergate_get_name(id));

	if (pg_ops->powergate_partition)
		return pg_ops->powergate_partition(id);
	else
		WARN_ON_ONCE("This SOC doesn't support powergating");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_powergate_partition);

int tegra_unpowergate_partition(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support un-powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (tegra_powergate_check_skip_list(id))
		printk_once("%s: %s is in powergate skip list\n", __func__,
			tegra_powergate_get_name(id));

	if (pg_ops->unpowergate_partition)
		return pg_ops->unpowergate_partition(id);
	else
		WARN_ON_ONCE("This SOC doesn't support un-powergating");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_unpowergate_partition);

int tegra_powergate_mc_enable(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->powergate_mc_enable)
		return pg_ops->powergate_mc_enable(id);
	else
		WARN_ON_ONCE("This SOC does not support powergate mc enable");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_powergate_mc_enable);

int tegra_powergate_mc_disable(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->powergate_mc_disable)
		return pg_ops->powergate_mc_disable(id);
	else
		WARN_ON_ONCE("This SOC does not support powergate mc disable");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_powergate_mc_disable);

int tegra_powergate_mc_flush(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->powergate_mc_flush)
		return pg_ops->powergate_mc_flush(id);
	else
		WARN_ON_ONCE("This SOC does not support powergate mc flush");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_powergate_mc_flush);

int tegra_powergate_mc_flush_done(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return -EINVAL;
	}

	if (pg_ops->powergate_mc_flush_done)
		return pg_ops->powergate_mc_flush_done(id);
	else
		WARN_ON_ONCE("This SOC does not support powergate mc flush done");

	return -EINVAL;
}
EXPORT_SYMBOL(tegra_powergate_mc_flush_done);

const char *tegra_powergate_get_name(int id)
{
	if (!pg_ops) {
		WARN_ON_ONCE("This SOC doesn't support powergating\n");
		return NULL;
	}

	if (!pg_ops->powergate_id_is_soc_valid(id)) {
		pr_info("%s: invalid powergate id %d\n", __func__, id);
		return NULL;
	}

	if (pg_ops->get_powergate_domain_name)
		return pg_ops->get_powergate_domain_name(id);
	else
		WARN_ON_ONCE("This SOC does not support CPU powergate");

	return NULL;
}
EXPORT_SYMBOL(tegra_powergate_get_name);

int tegra_powergate_cpuid_to_powergate_id(int cpu)
{
	if (pg_ops->powergate_cpuid_to_powergate_id)
		return pg_ops->powergate_cpuid_to_powergate_id(cpu);

	return -1;
}
EXPORT_SYMBOL(tegra_powergate_cpuid_to_powergate_id);

static int tegra_powergate_init_refcount(void)
{
	if ((!pg_ops) || (!pg_ops->powergate_init_refcount))
		return 0;

	return pg_ops->powergate_init_refcount();
}

struct tegra_powergate_driver_ops
__weak *tegra194_powergate_init_chip_support(void)
{
	return NULL;
}

static int __init tegra_powergate_init(void)
{
	switch (tegra_get_chip_id()) {
	case TEGRA210:
		pg_ops = tegra210_powergate_init_chip_support();
		TEGRA_POWERGATE_DISA = TEGRA210_POWER_DOMAIN_DISA;
		TEGRA_POWERGATE_SOR = TEGRA210_POWER_DOMAIN_SOR;
		break;

	case TEGRA186:
		pg_ops = tegra186_powergate_init_chip_support();
		TEGRA_POWERGATE_DISA = TEGRA186_POWER_DOMAIN_DISP;
		TEGRA_POWERGATE_SOR = TEGRA186_POWER_DOMAIN_DISP;
		break;

	case TEGRA234:
	case TEGRA194:
		pg_ops = tegra194_powergate_init_chip_support();
		break;

	default:
		pg_ops = NULL;
		pr_info("%s: Unknown Tegra variant. Disabling powergate\n", __func__);
		break;
	}

	tegra_powergate_init_refcount();

	pr_info("%s: DONE\n", __func__);

	return (pg_ops ? 0 : -EINVAL);
}
arch_initcall(tegra_powergate_init);

#ifdef CONFIG_DEBUG_FS

static int powergate_show(struct seq_file *s, void *data)
{
	int i;
	const char *name;
	bool is_pg_skip;

	if (!pg_ops) {
		seq_printf(s, "This SOC doesn't support powergating\n");
		return -EINVAL;
	}

	seq_printf(s, " powergate powered\n");
	seq_printf(s, "------------------\n");

	for (i = 0; i < pg_ops->num_powerdomains; i++) {
		name = tegra_powergate_get_name(i);
		if (name) {
			is_pg_skip = tegra_powergate_check_skip_list(i);
			seq_printf(s, " %9s %7s\n", name,
				(is_pg_skip ? "skip" : \
				(tegra_powergate_is_powered(i) ? \
				"yes" : "no")));
		}
	}

	return 0;
}

static int powergate_open(struct inode *inode, struct file *file)
{
	return single_open(file, powergate_show, inode->i_private);
}

static const struct file_operations powergate_fops = {
	.open		= powergate_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct dentry *pg_debugfs_root;

static int state_set(void *data, u64 val)
{
	int ret;
	unsigned long id = (unsigned long)data;

	if (val)
		ret = tegra_unpowergate_partition(id);
	else
		ret = tegra_powergate_partition(id);

	return ret;
}

static int state_get(void *data, u64 *val)
{
	unsigned long id = (unsigned long)data;

	if (tegra_powergate_is_powered(id))
		*val = 1;
	else
		*val = 0;

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(state_fops, state_get, state_set, "%llu\n");

static int powergate_debugfs_register_one(unsigned long id, const char *name)
{
	struct dentry *dir, *d;

	dir = debugfs_create_dir(name, pg_debugfs_root);
	if (!dir)
		return -ENOMEM;

	d = debugfs_create_file("state", S_IRUGO | S_IWUSR, dir, (void *)id, &state_fops);
	if (!d) {
		debugfs_remove_recursive(dir);
		return -ENOMEM;
	}

	return 0;
}

int __init tegra_powergate_debugfs_init(void)
{
	struct dentry *d;
	int i, ret;
	const char *name;

	if (!pg_ops)
		return -ENOMEM;

	d = debugfs_create_file("powergate", S_IRUGO, NULL, NULL,
		&powergate_fops);
	if (!d)
		return -ENOMEM;

	d = debugfs_create_dir("pg_domains", NULL);
	if (!d)
		return -ENOMEM;

	pg_debugfs_root = d;

	for (i = 0; i < pg_ops->num_powerdomains; i++) {
		if (!pg_ops->powergate_id_is_soc_valid(i))
			continue;

		name = tegra_powergate_get_name(i);
		if (name) {
			ret = powergate_debugfs_register_one(i, name);

			/* Continue even if error is there */
			if (ret) {
				pr_info("powerdomain debugfs not created for %s(%d): %d\n",
					name, i, ret);
				continue;
			}
		}
	}

	return 0;
}
late_initcall(tegra_powergate_debugfs_init);

#endif
