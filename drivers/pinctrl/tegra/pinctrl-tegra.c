/*
 * Driver for the NVIDIA Tegra pinmux
 *
 * Copyright (c) 2011-2019, NVIDIA CORPORATION.  All rights reserved.
 *
 * Derived from code:
 * Copyright (C) 2010 Google, Inc.
 * Copyright (C) 2010 NVIDIA Corporation
 * Copyright (C) 2009-2011 ST-Ericsson AB
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

#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-tegra.h>
#include <linux/slab.h>
#include <linux/syscore_ops.h>
#include <linux/tegra_prod.h>

#include <soc/tegra/fuse.h>

#include "../core.h"
#include "../pinctrl-utils.h"
#include "pinctrl-tegra.h"

#define EMMC2_PAD_CFGPADCTRL_OFFSET	0x1C8
#define EMMC4_PAD_CFGPADCTRL_OFFSET	0x1E0

#define EMMC_PARKING_BIT		0xE
#define EMMC_DPD_PARKING(x)		(x << EMMC_PARKING_BIT)
#define EMMC_PARKING_SET		0x1FFF

struct tegra_pmx {
	struct device *dev;
	struct pinctrl_dev *pctl;

	const struct tegra_pinctrl_soc_data *soc;
	const char **group_pins;

	int nbanks;
	void __iomem **regs;
	unsigned int *reg_base;
	u32 *gpio_conf;
	struct tegra_prod *prod_list;

	int *reg_bank_size;
	u32 *pg_data;
};

static struct tegra_pmx *pmx;

static int tegra_pinconf_group_set(struct pinctrl_dev *pctldev,
		   unsigned group, unsigned long *configs,
		   unsigned num_configs);

static inline u32 pmx_readl(struct tegra_pmx *pmx, u32 bank, u32 reg)
{
	return readl(pmx->regs[bank] + reg);
}

static inline void pmx_writel(struct tegra_pmx *pmx, u32 val, u32 bank, u32 reg)
{
	writel_relaxed(val, pmx->regs[bank] + reg);
	/* make sure pinmux register write completed */
	pmx_readl(pmx, bank, reg);
}

static int tegra_pinctrl_get_groups_count(struct pinctrl_dev *pctldev)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);

	return pmx->soc->ngroups;
}

static const char *tegra_pinctrl_get_group_name(struct pinctrl_dev *pctldev,
						unsigned group)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);

	return pmx->soc->groups[group].name;
}

static int tegra_pinctrl_get_group_pins(struct pinctrl_dev *pctldev,
					unsigned group,
					const unsigned **pins,
					unsigned *num_pins)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);

	*pins = pmx->soc->groups[group].pins;
	*num_pins = pmx->soc->groups[group].npins;

	return 0;
}

#ifdef CONFIG_DEBUG_FS
static void tegra_pinctrl_pin_dbg_show(struct pinctrl_dev *pctldev,
				       struct seq_file *s,
				       unsigned offset)
{
	seq_printf(s, " %s", dev_name(pctldev->dev));
}
#endif

static const struct cfg_param {
	const char *property;
	enum tegra_pinconf_param param;
} cfg_params[] = {
	{"nvidia,pull",			TEGRA_PINCONF_PARAM_PULL},
	{"nvidia,tristate",		TEGRA_PINCONF_PARAM_TRISTATE},
	{"nvidia,enable-input",		TEGRA_PINCONF_PARAM_ENABLE_INPUT},
	{"nvidia,open-drain",		TEGRA_PINCONF_PARAM_OPEN_DRAIN},
	{"nvidia,lock",			TEGRA_PINCONF_PARAM_LOCK},
	{"nvidia,io-reset",		TEGRA_PINCONF_PARAM_IORESET},
	{"nvidia,rcv-sel",		TEGRA_PINCONF_PARAM_RCV_SEL},
	{"nvidia,io-hv",		TEGRA_PINCONF_PARAM_RCV_SEL},
	{"nvidia,io-high-voltage",	TEGRA_PINCONF_PARAM_E_IO_HV},
	{"nvidia,loopback",		TEGRA_PINCONF_PARAM_LOOPBACK},
	{"nvidia,high-speed-mode",	TEGRA_PINCONF_PARAM_HIGH_SPEED_MODE},
	{"nvidia,schmitt",		TEGRA_PINCONF_PARAM_SCHMITT},
	{"nvidia,low-power-mode",	TEGRA_PINCONF_PARAM_LOW_POWER_MODE},
	{"nvidia,pull-down-strength",	TEGRA_PINCONF_PARAM_DRIVE_DOWN_STRENGTH},
	{"nvidia,pull-up-strength",	TEGRA_PINCONF_PARAM_DRIVE_UP_STRENGTH},
	{"nvidia,slew-rate-falling",	TEGRA_PINCONF_PARAM_SLEW_RATE_FALLING},
	{"nvidia,slew-rate-rising",	TEGRA_PINCONF_PARAM_SLEW_RATE_RISING},
	{"nvidia,drive-type",		TEGRA_PINCONF_PARAM_DRIVE_TYPE},
	{"nvidia,lpdr",			TEGRA_PINCONF_PARAM_LPDR},
	{"nvidia,pbias-buf",		TEGRA_PINCONF_PARAM_PBIAS_BUF},
	{"nvidia,preemp",		TEGRA_PINCONF_PARAM_PREEMP},
	{"nvidia,rfu-in",		TEGRA_PINCONF_PARAM_RFU_IN},
	{"nvidia,special-function",	TEGRA_PINCONF_PARAM_GPIO_MODE},
	{"nvidia,pad-power",		TEGRA_PINCONF_PARAM_PAD_POWER},
	{"nvidia,func",			TEGRA_PINCONF_PARAM_FUNCTION},
};

static int tegra_pinctrl_dt_subnode_to_map(struct pinctrl_dev *pctldev,
					   struct device_node *np,
					   struct pinctrl_map **map,
					   unsigned *reserved_maps,
					   unsigned *num_maps)
{
	struct device *dev = pctldev->dev;
	int ret, i;
	const char *function;
	u32 val;
	unsigned long config;
	unsigned long *configs = NULL;
	unsigned num_configs = 0;
	unsigned reserve;
	struct property *prop;
	const char *group;

	ret = of_property_read_string(np, "nvidia,function", &function);
	if (ret < 0) {
		/* EINVAL=missing, which is fine since it's optional */
		if (ret != -EINVAL)
			dev_err(dev,
				"could not parse property nvidia,function\n");
		function = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(cfg_params); i++) {
		ret = of_property_read_u32(np, cfg_params[i].property, &val);
		if (!ret) {
			config = TEGRA_PINCONF_PACK(cfg_params[i].param, val);
			ret = pinctrl_utils_add_config(pctldev, &configs,
					&num_configs, config);
			if (ret < 0)
				goto exit;
		/* EINVAL=missing, which is fine since it's optional */
		} else if (ret != -EINVAL) {
			dev_err(dev, "could not parse property %s\n",
				cfg_params[i].property);
		}
	}

	reserve = 0;
	if (function != NULL)
		reserve++;
	if (num_configs)
		reserve++;
	ret = of_property_count_strings(np, "nvidia,pins");
	if (ret < 0) {
		dev_err(dev, "could not parse property nvidia,pins\n");
		goto exit;
	}
	reserve *= ret;

	ret = pinctrl_utils_reserve_map(pctldev, map, reserved_maps,
					num_maps, reserve);
	if (ret < 0)
		goto exit;

	of_property_for_each_string(np, "nvidia,pins", prop, group) {
		if (function) {
			ret = pinctrl_utils_add_map_mux(pctldev, map,
					reserved_maps, num_maps, group,
					function);
			if (ret < 0)
				goto exit;
		}

		if (num_configs) {
			ret = pinctrl_utils_add_map_configs(pctldev, map,
					reserved_maps, num_maps, group,
					configs, num_configs,
					PIN_MAP_TYPE_CONFIGS_GROUP);
			if (ret < 0)
				goto exit;
		}
	}

	ret = 0;

exit:
	kfree(configs);
	return ret;
}

static int tegra_pinctrl_dt_node_to_map(struct pinctrl_dev *pctldev,
					struct device_node *np_config,
					struct pinctrl_map **map,
					unsigned *num_maps)
{
	unsigned reserved_maps;
	struct device_node *np;
	int ret;

	reserved_maps = 0;
	*map = NULL;
	*num_maps = 0;

	for_each_child_of_node(np_config, np) {
		ret = tegra_pinctrl_dt_subnode_to_map(pctldev, np, map,
						      &reserved_maps, num_maps);
		if (ret < 0) {
			pinctrl_utils_free_map(pctldev, *map,
				*num_maps);
			of_node_put(np);
			return ret;
		}
	}

	return 0;
}

static const struct pinctrl_ops tegra_pinctrl_ops = {
	.get_groups_count = tegra_pinctrl_get_groups_count,
	.get_group_name = tegra_pinctrl_get_group_name,
	.get_group_pins = tegra_pinctrl_get_group_pins,
#ifdef CONFIG_DEBUG_FS
	.pin_dbg_show = tegra_pinctrl_pin_dbg_show,
#endif
	.dt_node_to_map = tegra_pinctrl_dt_node_to_map,
	.dt_free_map = pinctrl_utils_free_map,
};

static int tegra_pinctrl_get_funcs_count(struct pinctrl_dev *pctldev)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);

	return pmx->soc->nfunctions;
}

static const char *tegra_pinctrl_get_func_name(struct pinctrl_dev *pctldev,
					       unsigned function)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);

	return pmx->soc->functions[function].name;
}

static int tegra_pinctrl_get_func_groups(struct pinctrl_dev *pctldev,
					 unsigned function,
					 const char * const **groups,
					 unsigned * const num_groups)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);

	*groups = pmx->soc->functions[function].groups;
	*num_groups = pmx->soc->functions[function].ngroups;

	return 0;
}

static int tegra_pinconfig_group_set(struct pinctrl_dev *pctldev,
		unsigned group, unsigned long param, unsigned long arg)
{
	unsigned long config;
	int ret;

	config = TEGRA_PINCONF_PACK(param, arg);
	ret = tegra_pinconf_group_set(pctldev, group, &config, 1);
	if (ret < 0)
		dev_err(pctldev->dev,
			"Pinctrl group %u tristate config failed: %d\n",
			group, ret);
	return ret;
}

static int tegra_pinctrl_set_mux(struct pinctrl_dev *pctldev,
				 unsigned function,
				 unsigned group)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	const struct tegra_pingroup *g;
	int i;
	u32 val;

	g = &pmx->soc->groups[group];

	if (WARN_ON(g->mux_reg < 0))
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(g->funcs); i++) {
		if (g->funcs[i] == function)
			break;
	}
	if (WARN_ON(i == ARRAY_SIZE(g->funcs)))
		return -EINVAL;

	val = pmx_readl(pmx, g->mux_bank, g->mux_reg);
	val &= ~(0x3 << g->mux_bit);
	val |= i << g->mux_bit;
	/* Set the SFIO/GPIO selection to SFIO when under pinmux control*/
	if (pmx->soc->is_gpio_reg_support)
		val |= (1 << g->gpio_bit);
	pmx_writel(pmx, val, g->mux_bank, g->mux_reg);

	return 0;
}

static int tegra_pinctrl_gpio_set_direction(struct pinctrl_dev *pctldev,
	struct pinctrl_gpio_range *range, unsigned offset, bool input)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	unsigned  group;
	const unsigned *pins;
	unsigned num_pins;
	int ret;

	for (group = 0; group < pmx->soc->ngroups; ++group) {
		ret = tegra_pinctrl_get_group_pins(pctldev, group,
				&pins, &num_pins);
		if (ret < 0 || num_pins != 1)
			continue;
		if (offset ==  pins[0])
			break;
	}

	if (group == pmx->soc->ngroups) {
		dev_err(pctldev->dev,
			"Pingroup not found for pin %u\n", offset);
		return -EINVAL;
	}

	/*
	 * Set input = 1 for the input direction and
	 * tristate = 0 for output direction.
	 */
	if (input) {
		ret = tegra_pinconfig_group_set(pctldev, group,
					TEGRA_PINCONF_PARAM_ENABLE_INPUT, 1);
		if (!ret && pmx->soc->input_tristate_enable)
			ret = tegra_pinconfig_group_set(pctldev, group,
					TEGRA_PINCONF_PARAM_TRISTATE, 1);
	 } else {
		ret = tegra_pinconfig_group_set(pctldev, group,
					TEGRA_PINCONF_PARAM_TRISTATE, 0);
		if (!ret && pmx->soc->output_input_disable)
			ret = tegra_pinconfig_group_set(pctldev, group,
					TEGRA_PINCONF_PARAM_ENABLE_INPUT, 0);
	}

	if (pmx->soc->is_gpio_reg_support)
		ret = tegra_pinconfig_group_set(pctldev, group,
					TEGRA_PINCONF_PARAM_GPIO_MODE, 0);
	return ret;
}

static int tegra_pinctrl_gpio_save_config(struct pinctrl_dev *pctldev,
					  struct pinctrl_gpio_range *range,
					  unsigned offset)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	const struct tegra_pingroup *g;
	unsigned  group;
	const unsigned *pins;
	unsigned num_pins;
	int ret;

	for (group = 0; group < pmx->soc->ngroups; ++group) {
		ret = tegra_pinctrl_get_group_pins(pctldev, group,
				&pins, &num_pins);
		if (ret < 0 || num_pins != 1)
			continue;
		if (offset ==  pins[0])
			break;
	}

	if (group == pmx->soc->ngroups) {
		dev_err(pctldev->dev,
			"Pingroup not found for pin %u\n", offset);
		return -EINVAL;
	}

	g = &pmx->soc->groups[group];
	if (g->mux_reg >= 0)
		pmx->gpio_conf[offset] = pmx_readl(pmx, g->mux_bank, g->mux_reg);

	return 0;
}

static int tegra_pinctrl_gpio_restore_config(struct pinctrl_dev *pctldev,
					     struct pinctrl_gpio_range *range,
					     unsigned offset)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	const struct tegra_pingroup *g;
	unsigned  group;
	const unsigned *pins;
	unsigned num_pins;
	int ret;

	for (group = 0; group < pmx->soc->ngroups; ++group) {
		ret = tegra_pinctrl_get_group_pins(pctldev, group,
				&pins, &num_pins);
		if (ret < 0 || num_pins != 1)
			continue;
		if (offset ==  pins[0])
			break;
	}

	if (group == pmx->soc->ngroups) {
		dev_err(pctldev->dev,
			"Pingroup not found for pin %u\n", offset);
		return -EINVAL;
	}

	g = &pmx->soc->groups[group];
	if (g->mux_reg >= 0)
		pmx_writel(pmx, pmx->gpio_conf[offset], g->mux_bank, g->mux_reg);

	return 0;
}

static int tegra_pinctrl_gpio_request_enable(struct pinctrl_dev *pctldev,
					     struct pinctrl_gpio_range *range,
					     unsigned offset)
{
	return tegra_pinctrl_gpio_save_config(pctldev, range, offset);
}

static void tegra_pinctrl_gpio_disable_free(struct pinctrl_dev *pctldev,
					    struct pinctrl_gpio_range *range,
					    unsigned offset)
{
	tegra_pinctrl_gpio_restore_config(pctldev, range, offset);
}

static const struct pinmux_ops tegra_pinmux_ops = {
	.get_functions_count = tegra_pinctrl_get_funcs_count,
	.get_function_name = tegra_pinctrl_get_func_name,
	.get_function_groups = tegra_pinctrl_get_func_groups,
	.set_mux = tegra_pinctrl_set_mux,
	.gpio_request_enable = tegra_pinctrl_gpio_request_enable,
	.gpio_disable_free = tegra_pinctrl_gpio_disable_free,
	.gpio_set_direction = tegra_pinctrl_gpio_set_direction,
	.gpio_save_config = tegra_pinctrl_gpio_save_config,
	.gpio_restore_config = tegra_pinctrl_gpio_restore_config,
};

static int tegra_pinconf_reg(struct tegra_pmx *pmx,
			     const struct tegra_pingroup *g,
			     enum tegra_pinconf_param param,
			     bool report_err,
			     s8 *bank, s32 *reg, s8 *bit, s8 *width)
{
	switch (param) {
	case TEGRA_PINCONF_PARAM_PULL:
		*bank = g->pupd_bank;
		*reg = g->pupd_reg;
		*bit = g->pupd_bit;
		*width = 2;
		break;
	case TEGRA_PINCONF_PARAM_TRISTATE:
		*bank = g->tri_bank;
		*reg = g->tri_reg;
		*bit = g->tri_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_ENABLE_INPUT:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->einput_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_OPEN_DRAIN:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->odrain_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_LOCK:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->lock_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_IORESET:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->ioreset_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_RCV_SEL:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->rcv_sel_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_LOOPBACK:
		*bank = g->lpbk_bank;
		*reg = g->lpbk_reg;
		*bit = g->lpbk_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_E_IO_HV:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->e_io_hv_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_HIGH_SPEED_MODE:
		if (pmx->soc->hsm_in_mux) {
			*bank = g->mux_bank;
			*reg = g->mux_reg;
		} else {
			*bank = g->drv_bank;
			*reg = g->drv_reg;
		}
		*bit = g->hsm_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_SCHMITT:
		if (pmx->soc->schmitt_in_mux) {
			*bank = g->mux_bank;
			*reg = g->mux_reg;
		} else {
			*bank = g->drv_bank;
			*reg = g->drv_reg;
		}
		*bit = g->schmitt_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_LOW_POWER_MODE:
		*bank = g->drv_bank;
		*reg = g->drv_reg;
		*bit = g->lpmd_bit;
		*width = 2;
		break;
	case TEGRA_PINCONF_PARAM_DRIVE_DOWN_STRENGTH:
		*bank = g->drv_bank;
		*reg = g->drv_reg;
		*bit = g->drvdn_bit;
		*width = g->drvdn_width;
		break;
	case TEGRA_PINCONF_PARAM_DRIVE_UP_STRENGTH:
		*bank = g->drv_bank;
		*reg = g->drv_reg;
		*bit = g->drvup_bit;
		*width = g->drvup_width;
		break;
	case TEGRA_PINCONF_PARAM_SLEW_RATE_FALLING:
		*bank = g->drv_bank;
		*reg = g->drv_reg;
		*bit = g->slwf_bit;
		*width = g->slwf_width;
		break;
	case TEGRA_PINCONF_PARAM_SLEW_RATE_RISING:
		*bank = g->drv_bank;
		*reg = g->drv_reg;
		*bit = g->slwr_bit;
		*width = g->slwr_width;
		break;
	case TEGRA_PINCONF_PARAM_DRIVE_TYPE:
		if (pmx->soc->drvtype_in_mux) {
			*bank = g->mux_bank;
			*reg = g->mux_reg;
		} else {
			*bank = g->drv_bank;
			*reg = g->drv_reg;
		}
		*bit = g->drvtype_bit;
		*width = 2;
		break;
	case TEGRA_PINCONF_PARAM_GPIO_MODE:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->gpio_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_LPDR:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->lpdr_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_PBIAS_BUF:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->pbias_buf_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_PREEMP:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->preemp_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_RFU_IN:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->rfu_in_bit;
		*width = 4;
		break;
	case TEGRA_PINCONF_PARAM_PAD_POWER:
		*bank = g->pad_bank;
		*reg = g->pad_reg;
		*bit = g->pad_bit;
		*width = 1;
		break;
	case TEGRA_PINCONF_PARAM_FUNCTION:
		*bank = g->mux_bank;
		*reg = g->mux_reg;
		*bit = g->mux_bit;
		*width = 2;
		break;
	default:
		dev_err(pmx->dev, "Invalid config param %04x\n", param);
		return -ENOTSUPP;
	}

	if (*reg < 0 || *bit < 0)  {
		if (report_err) {
			const char *prop = "unknown";
			int i;

			for (i = 0; i < ARRAY_SIZE(cfg_params); i++) {
				if (cfg_params[i].param == param) {
					prop = cfg_params[i].property;
					break;
				}
			}

			dev_err(pmx->dev,
				"Config param %04x (%s) not supported on group %s\n",
				param, prop, g->name);
		}
		return -ENOTSUPP;
	}

	return 0;
}

static int tegra_pinconf_get(struct pinctrl_dev *pctldev,
			     unsigned pin, unsigned long *config)
{
	dev_err(pctldev->dev, "pin_config_get op not supported\n");
	return -ENOTSUPP;
}

static int tegra_pinconf_set(struct pinctrl_dev *pctldev,
			     unsigned pin, unsigned long *configs,
			     unsigned num_configs)
{
	dev_err(pctldev->dev, "pin_config_set op not supported\n");
	return -ENOTSUPP;
}

static int tegra_pinconf_group_get(struct pinctrl_dev *pctldev,
				   unsigned group, unsigned long *config)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	enum tegra_pinconf_param param = TEGRA_PINCONF_UNPACK_PARAM(*config);
	u16 arg;
	const struct tegra_pingroup *g;
	int ret;
	s8 bank, bit, width;
	s32 reg;
	u32 val, mask;

	g = &pmx->soc->groups[group];

	ret = tegra_pinconf_reg(pmx, g, param, true, &bank, &reg, &bit,
				&width);
	if (ret < 0)
		return ret;

	val = pmx_readl(pmx, bank, reg);
	mask = (1 << width) - 1;
	arg = (val >> bit) & mask;

	/* Inverted bit value for Pad power */
	if (param == TEGRA_PINCONF_PARAM_PAD_POWER)
		arg = !arg;

	*config = TEGRA_PINCONF_PACK(param, arg);

	return 0;
}

static int tegra_pinconf_group_set(struct pinctrl_dev *pctldev,
				   unsigned group, unsigned long *configs,
				   unsigned num_configs)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	enum tegra_pinconf_param param;
	u16 arg;
	const struct tegra_pingroup *g;
	int ret, i;
	s8 bank, bit, width;
	s32 reg;
	u32 val, mask;

	g = &pmx->soc->groups[group];

	for (i = 0; i < num_configs; i++) {
		param = TEGRA_PINCONF_UNPACK_PARAM(configs[i]);
		arg = TEGRA_PINCONF_UNPACK_ARG(configs[i]);

		/* Inverted bit value for Pad power */
		if (param == TEGRA_PINCONF_PARAM_PAD_POWER)
			arg = !arg;

		ret = tegra_pinconf_reg(pmx, g, param, true, &bank, &reg, &bit,
					&width);
		if (ret < 0)
			return ret;

		val = pmx_readl(pmx, bank, reg);

		/* LOCK can't be cleared */
		if (param == TEGRA_PINCONF_PARAM_LOCK) {
			if ((val & BIT(bit)) && !arg) {
				dev_err(pctldev->dev, "LOCK bit cannot be cleared\n");
				return -EINVAL;
			}
		}

		/* Special-case Boolean values; allow any non-zero as true */
		if (width == 1)
			arg = !!arg;

		/* Range-check user-supplied value */
		mask = (1 << width) - 1;
		if (arg & ~mask) {
			dev_err(pctldev->dev,
				"config %lx: %x too big for %d bit register\n",
				configs[i], arg, width);
			return -EINVAL;
		}

		/* Update register */
		val &= ~(mask << bit);
		val |= arg << bit;
		pmx_writel(pmx, val, bank, reg);
	} /* for each config */

	return 0;
}

#ifdef CONFIG_DEBUG_FS
static void tegra_pinconf_dbg_show(struct pinctrl_dev *pctldev,
				   struct seq_file *s, unsigned offset)
{
}

static const char *strip_prefix(const char *s)
{
	const char *comma = strchr(s, ',');
	if (!comma)
		return s;

	return comma + 1;
}

static void tegra_pinconf_group_dbg_show(struct pinctrl_dev *pctldev,
					 struct seq_file *s, unsigned group)
{
	struct tegra_pmx *pmx = pinctrl_dev_get_drvdata(pctldev);
	const struct tegra_pingroup *g;
	int i, ret;
	s8 bank, bit, width;
	s32 reg;
	u32 val;
	u8 idx;

	g = &pmx->soc->groups[group];

	for (i = 0; i < ARRAY_SIZE(cfg_params); i++) {
		ret = tegra_pinconf_reg(pmx, g, cfg_params[i].param, false,
					&bank, &reg, &bit, &width);
		if (ret < 0)
			continue;

		val = pmx_readl(pmx, bank, reg);
		val >>= bit;
		val &= (1 << width) - 1;
		if (cfg_params[i].param == TEGRA_PINCONF_PARAM_FUNCTION) {
			idx = pmx->soc->groups[group].funcs[val];
			seq_printf(s, "\n\t%s=%s",
			   strip_prefix(cfg_params[i].property),
					 pmx->soc->functions[idx].name);
		} else {
			seq_printf(s, "\n\t%s=%u",
			   strip_prefix(cfg_params[i].property), val);
		}
	}
}

static void tegra_pinconf_config_dbg_show(struct pinctrl_dev *pctldev,
					  struct seq_file *s,
					  unsigned long config)
{
	enum tegra_pinconf_param param = TEGRA_PINCONF_UNPACK_PARAM(config);
	u16 arg = TEGRA_PINCONF_UNPACK_ARG(config);
	const char *pname = "unknown";
	int i;

	for (i = 0; i < ARRAY_SIZE(cfg_params); i++) {
		if (cfg_params[i].param == param) {
			pname = cfg_params[i].property;
			break;
		}
	}

	seq_printf(s, "%s=%d", strip_prefix(pname), arg);
}
#endif

static const struct pinconf_ops tegra_pinconf_ops = {
	.pin_config_get = tegra_pinconf_get,
	.pin_config_set = tegra_pinconf_set,
	.pin_config_group_get = tegra_pinconf_group_get,
	.pin_config_group_set = tegra_pinconf_group_set,
#ifdef CONFIG_DEBUG_FS
	.pin_config_dbg_show = tegra_pinconf_dbg_show,
	.pin_config_group_dbg_show = tegra_pinconf_group_dbg_show,
	.pin_config_config_dbg_show = tegra_pinconf_config_dbg_show,
#endif
};

static struct pinctrl_gpio_range tegra_pinctrl_gpio_range = {
	.name = "Tegra GPIOs",
	.id = 0,
	.base = 0,
};

static struct pinctrl_desc tegra_pinctrl_desc = {
	.pctlops = &tegra_pinctrl_ops,
	.pmxops = &tegra_pinmux_ops,
	.confops = &tegra_pinconf_ops,
	.owner = THIS_MODULE,
};

static void tegra_pinctrl_clear_parked_bits(struct tegra_pmx *pmx)
{
	int i = 0;
	const struct tegra_pingroup *g;
	u32 val;

	for (i = 0; i < pmx->soc->ngroups; ++i) {
		g = &pmx->soc->groups[i];
		if (g->parked_bit >= 0) {
			val = pmx_readl(pmx, g->mux_bank, g->mux_reg);
			val &= ~(1 << g->parked_bit);
			pmx_writel(pmx, val, g->mux_bank, g->mux_reg);
		}
	}
}

#ifdef CONFIG_PM_SLEEP
static int tegra_pinctrl_suspend(void)
{
	int i, j;
	u32 *pg_data = pmx->pg_data;
	void __iomem *regs;

	switch (tegra_get_chip_id()) {
	case TEGRA114:
	case TEGRA124:
	case TEGRA132:
	case TEGRA210:
		break;
	default:
		return 0;
	}

	for (i = 0; i < pmx->nbanks; i++) {
		regs = pmx->regs[i];
		for (j = 0; j < pmx->reg_bank_size[i] / 4; j++, regs += 4)
			*pg_data++ = readl(regs);
	}

	return pinctrl_force_sleep(pmx->pctl);
}

static void tegra_pinctrl_resume(void)
{
	int i, j;
	u8 chip_id;
	u32 *pg_data = pmx->pg_data;
	void __iomem *regs;
	u32 val;

	chip_id = tegra_get_chip_id();

	switch (chip_id) {
	case TEGRA114:
	case TEGRA124:
	case TEGRA132:
	case TEGRA210:
		break;
	default:
		return;
	}

	for (i = 0; i < pmx->nbanks; i++) {
		regs = pmx->regs[i];
		for (j = 0; j < pmx->reg_bank_size[i] / 4; j++, regs += 4)
			writel(*pg_data++, regs);
	}

	if (chip_id == TEGRA210) {
		/* Clear parking bit for EMMC IO brick pads */
		val = pmx_readl(pmx, 0, EMMC2_PAD_CFGPADCTRL_OFFSET);
		val &= ~(EMMC_DPD_PARKING(EMMC_PARKING_SET));
		pmx_writel(pmx, val, 0, EMMC2_PAD_CFGPADCTRL_OFFSET);

		val = pmx_readl(pmx, 0, EMMC4_PAD_CFGPADCTRL_OFFSET);
		val &= ~(EMMC_DPD_PARKING(EMMC_PARKING_SET));
		pmx_writel(pmx, val, 0, EMMC4_PAD_CFGPADCTRL_OFFSET);
	}
}
#else
#define tegra_pinctrl_suspend   NULL
#define tegra_pinctrl_resume    NULL
#endif

static struct syscore_ops pinctrl_syscore_ops = {
	.suspend = tegra_pinctrl_suspend,
	.resume = tegra_pinctrl_resume,
	.save = tegra_pinctrl_suspend,
	.restore = tegra_pinctrl_resume,
};

static bool gpio_node_has_range(struct device *dev)
{
	struct device_node *np;
	bool has_prop = false;

	if (of_property_read_bool(dev->of_node, "#gpio-range-cells"))
		return true;

	np = of_find_compatible_node(NULL, NULL, "nvidia,tegra30-gpio");
	if (!np)
		return has_prop;

	has_prop = of_find_property(np, "gpio-ranges", NULL);

	of_node_put(np);

	return has_prop;
}

int tegra_pinctrl_probe(struct platform_device *pdev,
			const struct tegra_pinctrl_soc_data *soc_data)
{
	struct resource *res;
	int i, ret;
	const char **group_pins;
	int fn, gn, gfn;
	int pg_data_size = 0;

	pmx = devm_kzalloc(&pdev->dev, sizeof(*pmx), GFP_KERNEL);
	if (!pmx) {
		dev_err(&pdev->dev, "Can't alloc tegra_pmx\n");
		return -ENOMEM;
	}
	pmx->dev = &pdev->dev;
	pmx->soc = soc_data;

	/*
	 * Each mux group will appear in 4 functions' list of groups.
	 * This over-allocates slightly, since not all groups are mux groups.
	 */
	pmx->group_pins = devm_kzalloc(&pdev->dev,
		soc_data->ngroups * 4 * sizeof(*pmx->group_pins),
		GFP_KERNEL);
	if (!pmx->group_pins)
		return -ENOMEM;

	group_pins = pmx->group_pins;
	for (fn = 0; fn < soc_data->nfunctions; fn++) {
		struct tegra_function *func = &soc_data->functions[fn];

		func->groups = group_pins;

		for (gn = 0; gn < soc_data->ngroups; gn++) {
			const struct tegra_pingroup *g = &soc_data->groups[gn];

			if (g->mux_reg == -1)
				continue;

			for (gfn = 0; gfn < 4; gfn++)
				if (g->funcs[gfn] == fn)
					break;
			if (gfn == 4)
				continue;

			BUG_ON(group_pins - pmx->group_pins >=
				soc_data->ngroups * 4);
			*group_pins++ = g->name;
			func->ngroups++;
		}
	}

	tegra_pinctrl_gpio_range.npins = pmx->soc->ngpios;
	tegra_pinctrl_desc.name = dev_name(&pdev->dev);
	tegra_pinctrl_desc.pins = pmx->soc->pins;
	tegra_pinctrl_desc.npins = pmx->soc->npins;

	for (i = 0; ; i++) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, i);
		if (!res)
			break;
		pg_data_size += resource_size(res);
	}
	pmx->nbanks = i;

	pmx->regs = devm_kzalloc(&pdev->dev, pmx->nbanks * sizeof(*pmx->regs),
				 GFP_KERNEL);
	if (!pmx->regs) {
		dev_err(&pdev->dev, "Can't alloc regs pointer\n");
		return -ENOMEM;
	}

	pmx->reg_base = devm_kzalloc(&pdev->dev,
			pmx->nbanks * sizeof(*pmx->reg_base), GFP_KERNEL);
	if (!pmx->reg_base) {
		dev_err(&pdev->dev, "Can't alloc reg_base pointer\n");
		return -ENOMEM;
	}

	pmx->gpio_conf = devm_kzalloc(&pdev->dev, pg_data_size, GFP_KERNEL);
	if (!pmx->gpio_conf) {
		dev_err(&pdev->dev, "Can't alloc gpio_conf data pointer\n");
		return -ENOMEM;
	}

#ifdef CONFIG_PM_SLEEP
	pmx->reg_bank_size = devm_kzalloc(&pdev->dev,
				pmx->nbanks * sizeof(*(pmx->reg_bank_size)),
				GFP_KERNEL);
	if (!pmx->reg_bank_size) {
		dev_err(&pdev->dev, "Can't alloc reg_bank_size pointer\n");
		return -ENOMEM;
	}

	pmx->pg_data = devm_kzalloc(&pdev->dev, pg_data_size, GFP_KERNEL);
	if (!pmx->pg_data) {
		dev_err(&pdev->dev, "Can't alloc pingroup data pointer\n");
		return -ENOMEM;
	}
#endif

	for (i = 0; i < pmx->nbanks; i++) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, i);
		pmx->reg_base[i] = res->start;
		pmx->regs[i] = devm_ioremap_resource(&pdev->dev, res);
		if (IS_ERR(pmx->regs[i]))
			return PTR_ERR(pmx->regs[i]);
#ifdef CONFIG_PM_SLEEP
		pmx->reg_bank_size[i] = resource_size(res);
#endif
	}

	pmx->pctl = devm_pinctrl_register(&pdev->dev, &tegra_pinctrl_desc, pmx);
	if (IS_ERR(pmx->pctl)) {
		dev_err(&pdev->dev, "Couldn't register pinctrl driver\n");
		return PTR_ERR(pmx->pctl);
	}

	tegra_pinctrl_clear_parked_bits(pmx);

	pmx->prod_list = devm_tegra_prod_get(&pdev->dev);
	if (IS_ERR(pmx->prod_list)) {
		dev_dbg(&pdev->dev, "Prod-settngs not available\n");
		pmx->prod_list = NULL;
	} else {
		ret = tegra_prod_set_boot_init(pmx->regs, pmx->prod_list);
		if (ret < 0) {
			dev_err(&pdev->dev, "Prod config failed: %d\n", ret);
			return ret;
		}
	}


	if (!gpio_node_has_range(&pdev->dev))
		pinctrl_add_gpio_range(pmx->pctl, &tegra_pinctrl_gpio_range);

	platform_set_drvdata(pdev, pmx);

	register_syscore_ops(&pinctrl_syscore_ops);

	dev_dbg(&pdev->dev, "Probed Tegra pinctrl driver\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tegra_pinctrl_probe);

int tegra_pinctrl_config_prod(struct device *dev, const char *prod_name)
{
	int ret;

	if (!pmx) {
		dev_err(dev, "Pincontrol driver is not initialised yet\n");
		return -EIO;
	}

	ret = tegra_prod_set_by_name(pmx->regs, prod_name, pmx->prod_list);
	if (ret < 0) {
		dev_err(pmx->dev, "Prod config %s for device %s failed: %d\n",
			prod_name, dev_name(dev), ret);
		return ret;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tegra_pinctrl_config_prod);

#ifdef	CONFIG_DEBUG_FS

#include <linux/debugfs.h>
#include <linux/seq_file.h>

static int dbg_reg_pinmux_show(struct seq_file *s, void *unused)
{
	int i;
	u32 offset;
	u32 reg;
	int bank;

	for (i = 0; i < pmx->soc->ngroups; i++) {
		if (pmx->soc->groups[i].mux_reg >= 0) {
			bank = pmx->soc->groups[i].mux_bank;
			offset = pmx->soc->groups[i].mux_reg;
		} else if (pmx->soc->groups[i].drv_reg >= 0) {
			bank = pmx->soc->groups[i].drv_bank;
			offset = pmx->soc->groups[i].drv_reg;
		} else {
			continue;
		}
		reg = pmx_readl(pmx, bank, offset);
		seq_printf(s, "Bank: %d Reg: 0x%08x Val: 0x%08x -> %s\n",
			bank, pmx->reg_base[bank] + offset, reg,
			pmx->soc->groups[i].name);
	}
	return 0;
}

static int dbg_reg_pinmux_open(struct inode *inode, struct file *file)
{
	return single_open(file, dbg_reg_pinmux_show, &inode->i_private);
}

static const struct file_operations debug_reg_fops = {
	.open		= dbg_reg_pinmux_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init tegra_pinctrl_debuginit(void)
{
	if (!pmx)
		return 0;

	(void) debugfs_create_file("tegra_pinctrl_reg", 0444,
					NULL, NULL, &debug_reg_fops);
	return 0;
}
late_initcall(tegra_pinctrl_debuginit);
#endif
