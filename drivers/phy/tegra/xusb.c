/*
 * Copyright (c) 2014-2021, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/phy/phy.h>
#include <linux/phy/tegra/xusb.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <soc/tegra/fuse.h>

#include "xusb.h"

static struct phy *tegra_xusb_pad_of_xlate(struct device *dev,
					   struct of_phandle_args *args)
{
	struct tegra_xusb_pad *pad = dev_get_drvdata(dev);
	struct phy *phy = NULL;
	unsigned int i;

	if (args->args_count != 0)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < pad->soc->num_lanes; i++) {
		if (!pad->lanes[i])
			continue;

		if (pad->lanes[i]->dev.of_node == args->np) {
			phy = pad->lanes[i];
			break;
		}
	}

	if (phy == NULL)
		phy = ERR_PTR(-ENODEV);

	return phy;
}

static const struct of_device_id tegra_xusb_padctl_of_match[] = {
#if defined(CONFIG_ARCH_TEGRA_124_SOC) || defined(CONFIG_ARCH_TEGRA_132_SOC)
	{
		.compatible = "nvidia,tegra124-xusb-padctl",
		.data = &tegra124_xusb_padctl_soc,
	},
#endif
#if defined(CONFIG_ARCH_TEGRA_210_SOC)
	{
		.compatible = "nvidia,tegra210-xusb-padctl",
		.data = &tegra210_xusb_padctl_soc,
	},
#endif
#if defined(CONFIG_ARCH_TEGRA_210_SOC)
	{
		.compatible = "nvidia,tegra210b01-xusb-padctl",
		.data = &tegra210b01_xusb_padctl_soc,
	},
#endif
#if defined(CONFIG_ARCH_TEGRA_18x_SOC)
	{
		.compatible = "nvidia,tegra18x-xusb-padctl",
		.data = &tegra186_xusb_padctl_soc,
	},
#endif
#if defined(CONFIG_ARCH_TEGRA_19x_SOC)
	{
		.compatible = "nvidia,tegra19x-xusb-padctl",
		.data = &tegra194_xusb_padctl_soc,
	},
#endif
	{ }
};
MODULE_DEVICE_TABLE(of, tegra_xusb_padctl_of_match);

static struct device_node *
tegra_xusb_find_pad_node(struct tegra_xusb_padctl *padctl, const char *name)
{
	/*
	 * of_find_node_by_name() drops a reference, so make sure to grab one.
	 */
	struct device_node *np = of_node_get(padctl->dev->of_node);

	np = of_find_node_by_name(np, "pads");
	if (np)
		np = of_find_node_by_name(np, name);

	return np;
}

static struct device_node *
tegra_xusb_pad_find_phy_node(struct tegra_xusb_pad *pad, unsigned int index)
{
	/*
	 * of_find_node_by_name() drops a reference, so make sure to grab one.
	 */
	struct device_node *np = of_node_get(pad->dev.of_node);

	np = of_find_node_by_name(np, "lanes");
	if (!np)
		return NULL;

	return of_find_node_by_name(np, pad->soc->lanes[index].name);
}

static int
tegra_xusb_lane_lookup_function(struct tegra_xusb_lane *lane,
				    const char *function)
{
	unsigned int i;

	for (i = 0; i < lane->soc->num_funcs; i++)
		if (strcmp(function, lane->soc->funcs[i]) == 0)
			return i;

	return -EINVAL;
}

int tegra_xusb_lane_parse_dt(struct tegra_xusb_lane *lane,
			     struct device_node *np)
{
	struct tegra_xusb_usb2_lane *usb2 = to_usb2_lane(lane);
	struct device *dev = &lane->pad->dev;
	const char *function;
	s32 offset;
	int err;

	err = of_property_read_string(np, "nvidia,function", &function);
	if (err < 0)
		return err;

	err = tegra_xusb_lane_lookup_function(lane, function);
	if (err < 0) {
		dev_err(dev, "invalid function \"%s\" for lane \"%s\"\n",
			function, np->name);
		return err;
	}

	lane->function = err;

	err = of_property_read_s32(np, "nvidia,hs_curr_level_offset", &offset);
	if (err == 0)
		usb2->hs_curr_level_offset = offset;

	/* this property is optional, ignore -EINVAL error */
	if (err == -EINVAL)
		err = 0;

	return 0;
}

static void tegra_xusb_lane_destroy(struct phy *phy)
{
	if (phy) {
		struct tegra_xusb_lane *lane = phy_get_drvdata(phy);

		lane->pad->ops->remove(lane);
		phy_destroy(phy);
	}
}

static void tegra_xusb_pad_release(struct device *dev)
{
	struct tegra_xusb_pad *pad = to_tegra_xusb_pad(dev);

	pad->soc->ops->remove(pad);
}

static struct device_type tegra_xusb_pad_type = {
	.release = tegra_xusb_pad_release,
};

int tegra_xusb_pad_init(struct tegra_xusb_pad *pad,
			struct tegra_xusb_padctl *padctl,
			struct device_node *np)
{
	int err;

	device_initialize(&pad->dev);
	INIT_LIST_HEAD(&pad->list);
	pad->dev.parent = padctl->dev;
	pad->dev.type = &tegra_xusb_pad_type;
	pad->dev.of_node = np;
	pad->padctl = padctl;

	err = dev_set_name(&pad->dev, "%s", pad->soc->name);
	if (err < 0)
		goto unregister;

	err = device_add(&pad->dev);
	if (err < 0)
		goto unregister;

	return 0;

unregister:
	device_unregister(&pad->dev);
	return err;
}

int tegra_xusb_pad_register(struct tegra_xusb_pad *pad,
			    const struct phy_ops *ops)
{
	struct device_node *children;
	struct phy *lane;
	unsigned int i;
	int err;

	children = of_find_node_by_name(pad->dev.of_node, "lanes");
	if (!children)
		return -ENODEV;

	pad->lanes = devm_kcalloc(&pad->dev, pad->soc->num_lanes, sizeof(lane),
				  GFP_KERNEL);
	if (!pad->lanes) {
		of_node_put(children);
		return -ENOMEM;
	}

	for (i = 0; i < pad->soc->num_lanes; i++) {
		struct device_node *np = tegra_xusb_pad_find_phy_node(pad, i);
		struct tegra_xusb_lane *lane;

		/* skip disabled lanes */
		if (!np || !of_device_is_available(np)) {
			of_node_put(np);
			continue;
		}

		pad->lanes[i] = phy_create(&pad->dev, np, ops);
		if (IS_ERR(pad->lanes[i])) {
			err = PTR_ERR(pad->lanes[i]);
			of_node_put(np);
			goto remove;
		}

		lane = pad->ops->probe(pad, np, i);
		if (IS_ERR(lane)) {
			phy_destroy(pad->lanes[i]);
			err = PTR_ERR(lane);
			goto remove;
		}

		list_add_tail(&lane->list, &pad->padctl->lanes);
		phy_set_drvdata(pad->lanes[i], lane);
	}

	pad->provider = of_phy_provider_register_full(&pad->dev, children,
						      tegra_xusb_pad_of_xlate);
	if (IS_ERR(pad->provider)) {
		err = PTR_ERR(pad->provider);
		goto remove;
	}

	return 0;

remove:
	while (i--)
		tegra_xusb_lane_destroy(pad->lanes[i]);

	of_node_put(children);

	return err;
}

void tegra_xusb_pad_unregister(struct tegra_xusb_pad *pad)
{
	unsigned int i = pad->soc->num_lanes;

	of_phy_provider_unregister(pad->provider);

	while (i--)
		tegra_xusb_lane_destroy(pad->lanes[i]);

	device_unregister(&pad->dev);
}

static struct tegra_xusb_pad *
tegra_xusb_pad_create(struct tegra_xusb_padctl *padctl,
		      const struct tegra_xusb_pad_soc *soc)
{
	struct tegra_xusb_pad *pad;
	struct device_node *np;
	int err;

	np = tegra_xusb_find_pad_node(padctl, soc->name);
	if (!np || !of_device_is_available(np))
		return NULL;

	pad = soc->ops->probe(padctl, soc, np);
	if (IS_ERR(pad)) {
		err = PTR_ERR(pad);
		dev_err(padctl->dev, "failed to create pad %s: %d\n",
			soc->name, err);
		return ERR_PTR(err);
	}

	/* XXX move this into ->probe() to avoid string comparison */
	if (strcmp(soc->name, "pcie") == 0)
		padctl->pcie = pad;

	if (strcmp(soc->name, "sata") == 0)
		padctl->sata = pad;

	if (strcmp(soc->name, "usb2") == 0)
		padctl->usb2 = pad;

	if (strcmp(soc->name, "ulpi") == 0)
		padctl->ulpi = pad;

	if (strcmp(soc->name, "hsic") == 0)
		padctl->hsic = pad;

	return pad;
}

static void __tegra_xusb_remove_pads(struct tegra_xusb_padctl *padctl)
{
	struct tegra_xusb_pad *pad, *tmp;

	list_for_each_entry_safe_reverse(pad, tmp, &padctl->pads, list) {
		list_del(&pad->list);
		tegra_xusb_pad_unregister(pad);
	}
}

static void tegra_xusb_remove_pads(struct tegra_xusb_padctl *padctl)
{
	mutex_lock(&padctl->lock);
	__tegra_xusb_remove_pads(padctl);
	mutex_unlock(&padctl->lock);
}

static void tegra_xusb_lane_program(struct tegra_xusb_lane *lane)
{
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	const struct tegra_xusb_lane_soc *soc = lane->soc;
	u32 value;

	/* skip single function lanes */
	if (soc->num_funcs < 2)
		return;

	/* choose function */
	value = padctl_readl(padctl, soc->offset);
	value &= ~(soc->mask << soc->shift);
	value |= lane->function << soc->shift;
	padctl_writel(padctl, value, soc->offset);
}

static void tegra_xusb_pad_program(struct tegra_xusb_pad *pad)
{
	unsigned int i;

	for (i = 0; i < pad->soc->num_lanes; i++) {
		struct tegra_xusb_lane *lane;

		if (pad->lanes[i]) {
			lane = phy_get_drvdata(pad->lanes[i]);
			tegra_xusb_lane_program(lane);
		}
	}
}

static int tegra_xusb_setup_pads(struct tegra_xusb_padctl *padctl)
{
	struct tegra_xusb_pad *pad;
	unsigned int i;

	mutex_lock(&padctl->lock);

	for (i = 0; i < padctl->soc->num_pads; i++) {
		const struct tegra_xusb_pad_soc *soc = padctl->soc->pads[i];
		int err;

		pad = tegra_xusb_pad_create(padctl, soc);
		if (IS_ERR(pad)) {
			err = PTR_ERR(pad);
			dev_err(padctl->dev, "failed to create pad %s: %d\n",
				soc->name, err);
			__tegra_xusb_remove_pads(padctl);
			mutex_unlock(&padctl->lock);
			return err;
		}

		if (!pad)
			continue;

		list_add_tail(&pad->list, &padctl->pads);
	}

	list_for_each_entry(pad, &padctl->pads, list)
		tegra_xusb_pad_program(pad);

	mutex_unlock(&padctl->lock);
	return 0;
}

bool tegra_xusb_lane_check(struct tegra_xusb_lane *lane,
				  const char *function)
{
	const char *func = lane->soc->funcs[lane->function];

	return strcmp(function, func) == 0;
}

struct tegra_xusb_lane *tegra_xusb_find_lane(struct tegra_xusb_padctl *padctl,
					     const char *type,
					     unsigned int index)
{
	struct tegra_xusb_lane *lane, *hit = ERR_PTR(-ENODEV);
	char *name;

	name = kasprintf(GFP_KERNEL, "%s-%u", type, index);
	if (!name)
		return ERR_PTR(-ENOMEM);

	list_for_each_entry(lane, &padctl->lanes, list) {
		if (strcmp(lane->soc->name, name) == 0) {
			hit = lane;
			break;
		}
	}

	kfree(name);
	return hit;
}

struct tegra_xusb_lane *
tegra_xusb_port_find_lane(struct tegra_xusb_port *port,
			  const struct tegra_xusb_lane_map *map,
			  const char *function)
{
	struct tegra_xusb_lane *lane, *match = ERR_PTR(-ENODEV);

	for (; map->type; map++) {
		if (port->index != map->port)
			continue;

		lane = tegra_xusb_find_lane(port->padctl, map->type,
					    map->index);
		if (IS_ERR(lane))
			continue;

		if (!tegra_xusb_lane_check(lane, function))
			continue;

		if (!IS_ERR(match))
			dev_err(&port->dev, "conflicting match: %s-%u / %s\n",
				map->type, map->index, match->soc->name);
		else
			match = lane;
	}

	return match;
}

static struct device_node *
tegra_xusb_find_port_node(struct tegra_xusb_padctl *padctl, const char *type,
			  unsigned int index)
{
	/*
	 * of_find_node_by_name() drops a reference, so make sure to grab one.
	 */
	struct device_node *np = of_node_get(padctl->dev->of_node);

	np = of_find_node_by_name(np, "ports");
	if (np) {
		char *name;

		name = kasprintf(GFP_KERNEL, "%s-%u", type, index);
		np = of_find_node_by_name(np, name);
		kfree(name);
	}

	return np;
}

struct tegra_xusb_port *
tegra_xusb_find_port(struct tegra_xusb_padctl *padctl, const char *type,
		     unsigned int index)
{
	struct tegra_xusb_port *port;
	struct device_node *np;

	np = tegra_xusb_find_port_node(padctl, type, index);
	if (!np)
		return NULL;

	list_for_each_entry(port, &padctl->ports, list) {
		if (np == port->dev.of_node) {
			of_node_put(np);
			return port;
		}
	}

	of_node_put(np);

	return NULL;
}

struct tegra_xusb_usb2_port *
tegra_xusb_find_usb2_port(struct tegra_xusb_padctl *padctl, unsigned int index)
{
	struct tegra_xusb_port *port;

	port = tegra_xusb_find_port(padctl, "usb2", index);
	if (port)
		return to_usb2_port(port);

	return NULL;
}

struct tegra_xusb_hsic_port *
tegra_xusb_find_hsic_port(struct tegra_xusb_padctl *padctl, unsigned int index)
{
	struct tegra_xusb_port *port;

	port = tegra_xusb_find_port(padctl, "hsic", index);
	if (port)
		return to_hsic_port(port);

	return NULL;
}

struct tegra_xusb_usb3_port *
tegra_xusb_find_usb3_port(struct tegra_xusb_padctl *padctl, unsigned int index)
{
	struct tegra_xusb_port *port;

	port = tegra_xusb_find_port(padctl, "usb3", index);
	if (port)
		return to_usb3_port(port);

	return NULL;
}

static void tegra_xusb_port_release(struct device *dev)
{
}

static struct device_type tegra_xusb_port_type = {
	.release = tegra_xusb_port_release,
};

static int tegra_xusb_port_init(struct tegra_xusb_port *port,
				struct tegra_xusb_padctl *padctl,
				struct device_node *np,
				const char *name,
				unsigned int index)
{
	int err;

	INIT_LIST_HEAD(&port->list);
	port->padctl = padctl;
	port->index = index;

	device_initialize(&port->dev);
	port->dev.type = &tegra_xusb_port_type;
	port->dev.of_node = of_node_get(np);
	port->dev.parent = padctl->dev;

	err = dev_set_name(&port->dev, "%s-%u", name, index);
	if (err < 0)
		goto unregister;

	err = device_add(&port->dev);
	if (err < 0)
		goto unregister;

	return 0;

unregister:
	device_unregister(&port->dev);
	return err;
}

static void tegra_xusb_port_unregister(struct tegra_xusb_port *port)
{
	device_unregister(&port->dev);
}

static int tegra_xusb_usb2_port_parse_dt(struct tegra_xusb_usb2_port *usb2)
{
	struct tegra_xusb_port *port = &usb2->base;
	struct device_node *np = port->dev.of_node;
	const char *prop_string;
	int err = 0;
	u32 value;

	usb2->internal = of_property_read_bool(np, "nvidia,internal");

	usb2->port_cap = USB_PORT_DISABLED; /* default */
	if (!of_property_read_string(np, "mode", &prop_string)) {
		if (!strcmp("host", prop_string))
			usb2->port_cap = USB_HOST_CAP;
		else if (!strcmp("device", prop_string))
			usb2->port_cap = USB_DEVICE_CAP;
		else if (!strcmp("otg", prop_string))
			usb2->port_cap = USB_OTG_CAP;
	}

	if (usb2->port_cap == USB_OTG_CAP || usb2->port_cap == USB_DEVICE_CAP) {
		usb2->vbus_id = 0;
		err = of_property_read_u32(np, "vbus-id", &value);
		if (!err)
			usb2->vbus_id = value;
	}

	usb2->supply = devm_regulator_get(&port->dev, "vbus");
	if (IS_ERR(usb2->supply))
		return PTR_ERR(usb2->supply);

	err = of_property_read_u32(np, "nvidia,oc-pin", &value);
	if (!err)
		usb2->oc_pin = value;

	if (!of_property_read_u32(np, "nvidia,usb3-port-fake", &value))
		usb2->usb3_port_fake = value;
	else
		usb2->usb3_port_fake = -1; /* default */

	return 0;
}

static int tegra_xusb_add_usb2_port(struct tegra_xusb_padctl *padctl,
				    unsigned int index)
{
	struct tegra_xusb_usb2_port *usb2;
	struct device_node *np;
	int err = 0;

	/*
	 * USB2 ports don't require additional properties, but if the port is
	 * marked as disabled there is no reason to register it.
	 */
	np = tegra_xusb_find_port_node(padctl, "usb2", index);
	if (!np || !of_device_is_available(np))
		goto out;

	usb2 = devm_kzalloc(padctl->dev, sizeof(*usb2), GFP_KERNEL);
	if (!usb2) {
		err = -ENOMEM;
		goto out;
	}

	err = tegra_xusb_port_init(&usb2->base, padctl, np, "usb2", index);
	if (err < 0)
		goto out;

	/* overcurrent disabled by default */
	usb2->oc_pin = -1;
	usb2->hs_txeq = -1;

	usb2->base.ops = padctl->soc->ports.usb2.ops;

	usb2->base.lane = usb2->base.ops->map(&usb2->base);
	if (IS_ERR(usb2->base.lane)) {
		err = PTR_ERR(usb2->base.lane);
		goto out;
	}

	err = tegra_xusb_usb2_port_parse_dt(usb2);
	if (err < 0) {
		tegra_xusb_port_unregister(&usb2->base);
		goto out;
	}
	if (usb2->port_cap == USB_OTG_CAP || usb2->port_cap == USB_DEVICE_CAP) {
		padctl->otg_vbus_usb2_port_base_1[usb2->vbus_id] = index + 1;
		dev_dbg(padctl->dev, "vbus_id %d => usb2 %d\n", usb2->vbus_id,
			padctl->otg_vbus_usb2_port_base_1[usb2->vbus_id]);
		padctl->otg_port_num++;
	}

	if (usb2->oc_pin > 0 && usb2->oc_pin >= padctl->soc->num_oc_pins) {
		dev_err(padctl->dev, "Invalid OC pin: %d\n", usb2->oc_pin);
		usb2->oc_pin = -1;
	} else
		dev_dbg(padctl->dev,
			"USB2 port %d OC pin %d\n", index, usb2->oc_pin);

	list_add_tail(&usb2->base.list, &padctl->ports);

out:
	of_node_put(np);
	return err;
}

static int tegra_xusb_ulpi_port_parse_dt(struct tegra_xusb_ulpi_port *ulpi)
{
	struct tegra_xusb_port *port = &ulpi->base;
	struct device_node *np = port->dev.of_node;

	ulpi->internal = of_property_read_bool(np, "nvidia,internal");

	return 0;
}

static int tegra_xusb_add_ulpi_port(struct tegra_xusb_padctl *padctl,
				    unsigned int index)
{
	struct tegra_xusb_ulpi_port *ulpi;
	struct device_node *np;
	int err = 0;

	np = tegra_xusb_find_port_node(padctl, "ulpi", index);
	if (!np || !of_device_is_available(np))
		goto out;

	ulpi = devm_kzalloc(padctl->dev, sizeof(*ulpi), GFP_KERNEL);
	if (!ulpi) {
		err = -ENOMEM;
		goto out;
	}

	err = tegra_xusb_port_init(&ulpi->base, padctl, np, "ulpi", index);
	if (err < 0)
		goto out;

	ulpi->base.ops = padctl->soc->ports.ulpi.ops;

	ulpi->base.lane = ulpi->base.ops->map(&ulpi->base);
	if (IS_ERR(ulpi->base.lane)) {
		err = PTR_ERR(ulpi->base.lane);
		goto out;
	}

	err = tegra_xusb_ulpi_port_parse_dt(ulpi);
	if (err < 0) {
		tegra_xusb_port_unregister(&ulpi->base);
		goto out;
	}

	list_add_tail(&ulpi->base.list, &padctl->ports);

out:
	of_node_put(np);
	return err;
}

static int tegra_xusb_hsic_port_parse_dt(struct tegra_xusb_hsic_port *hsic)
{
	/* XXX */
	return 0;
}

static int tegra_xusb_add_hsic_port(struct tegra_xusb_padctl *padctl,
				    unsigned int index)
{
	struct tegra_xusb_hsic_port *hsic;
	struct device_node *np;
	int err = 0;

	np = tegra_xusb_find_port_node(padctl, "hsic", index);
	if (!np || !of_device_is_available(np))
		goto out;

	hsic = devm_kzalloc(padctl->dev, sizeof(*hsic), GFP_KERNEL);
	if (!hsic) {
		err = -ENOMEM;
		goto out;
	}

	err = tegra_xusb_port_init(&hsic->base, padctl, np, "hsic", index);
	if (err < 0)
		goto out;

	hsic->base.ops = padctl->soc->ports.hsic.ops;

	hsic->base.lane = hsic->base.ops->map(&hsic->base);
	if (IS_ERR(hsic->base.lane)) {
		err = PTR_ERR(hsic->base.lane);
		goto out;
	}

	err = tegra_xusb_hsic_port_parse_dt(hsic);
	if (err < 0) {
		tegra_xusb_port_unregister(&hsic->base);
		goto out;
	}

	list_add_tail(&hsic->base.list, &padctl->ports);

out:
	of_node_put(np);
	return err;
}

static int tegra_xusb_usb3_port_parse_dt(struct tegra_xusb_usb3_port *usb3)
{
	struct tegra_xusb_port *port = &usb3->base;
	struct device_node *np = port->dev.of_node;
	u32 value;
	int err;

	err = of_property_read_u32(np, "nvidia,usb2-companion", &value);
	if (err < 0) {
		dev_err(&port->dev, "failed to read port: %d\n", err);
		return err;
	}
	usb3->port = value;

	err = of_property_read_u32(np, "nvidia,usb3-gen1-only", &value);
	if (!err && value == 1)
		usb3->gen1_only = true;
	else
		usb3->gen1_only = false;

	usb3->internal = of_property_read_bool(np, "nvidia,internal");

	return 0;
}

static int tegra_xusb_add_usb3_port(struct tegra_xusb_padctl *padctl,
				    unsigned int index)
{
	struct tegra_xusb_usb3_port *usb3;
	struct tegra_xusb_usb2_port *usb2;
	struct device_node *np;
	int err = 0;

	/*
	 * If there is no supplemental configuration in the device tree the
	 * port is unusable. But it is valid to configure only a single port,
	 * hence return 0 instead of an error to allow ports to be optional.
	 */
	np = tegra_xusb_find_port_node(padctl, "usb3", index);
	if (!np || !of_device_is_available(np))
		goto out;

	usb3 = devm_kzalloc(padctl->dev, sizeof(*usb3), GFP_KERNEL);
	if (!usb3) {
		err = -ENOMEM;
		goto out;
	}

	err = tegra_xusb_port_init(&usb3->base, padctl, np, "usb3", index);
	if (err < 0)
		goto out;

	/* overcurrent disabled by default */
	usb3->oc_pin = -1;

	usb3->base.ops = padctl->soc->ports.usb3.ops;

	usb3->base.lane = usb3->base.ops->map(&usb3->base);
	if (IS_ERR(usb3->base.lane)) {
		err = PTR_ERR(usb3->base.lane);
		goto out;
	}

	err = tegra_xusb_usb3_port_parse_dt(usb3);
	if (err < 0) {
		tegra_xusb_port_unregister(&usb3->base);
		goto out;
	}

	usb2 = tegra_xusb_find_usb2_port(padctl, usb3->port);
	if (!usb2) {
		tegra_xusb_port_unregister(&usb3->base);
		goto out;
	}
	if (usb2->port_cap == USB_OTG_CAP || usb2->port_cap == USB_DEVICE_CAP) {
		padctl->otg_vbus_usb3_port_base_1[usb2->vbus_id] = index + 1;
		dev_dbg(padctl->dev, "vbus_id %d => usb3 %d\n", usb2->vbus_id,
			padctl->otg_vbus_usb3_port_base_1[usb2->vbus_id]);
	}

	list_add_tail(&usb3->base.list, &padctl->ports);

out:
	of_node_put(np);
	return err;
}

static void __tegra_xusb_remove_ports(struct tegra_xusb_padctl *padctl)
{
	struct tegra_xusb_port *port, *tmp;

	list_for_each_entry_safe_reverse(port, tmp, &padctl->ports, list) {
		list_del(&port->list);
		tegra_xusb_port_unregister(port);
	}
}

static int tegra_xusb_setup_ports(struct tegra_xusb_padctl *padctl)
{
	struct tegra_xusb_port *port;
	unsigned int i;
	int err = 0;

	mutex_lock(&padctl->lock);

	for (i = 0; i < padctl->soc->ports.usb2.count; i++) {
		err = tegra_xusb_add_usb2_port(padctl, i);
		if (err < 0)
			goto remove_ports;
	}

	for (i = 0; i < padctl->soc->ports.ulpi.count; i++) {
		err = tegra_xusb_add_ulpi_port(padctl, i);
		if (err < 0)
			goto remove_ports;
	}

	for (i = 0; i < padctl->soc->ports.hsic.count; i++) {
		err = tegra_xusb_add_hsic_port(padctl, i);
		if (err < 0)
			goto remove_ports;
	}

	for (i = 0; i < padctl->soc->ports.usb3.count; i++) {
		err = tegra_xusb_add_usb3_port(padctl, i);
		if (err < 0)
			goto remove_ports;
	}

	list_for_each_entry(port, &padctl->ports, list) {
		err = port->ops->enable(port);
		if (err < 0)
			dev_err(padctl->dev, "failed to enable port %s: %d\n",
				dev_name(&port->dev), err);
	}

	goto unlock;

remove_ports:
	__tegra_xusb_remove_ports(padctl);
unlock:
	mutex_unlock(&padctl->lock);
	return err;
}

static void tegra_xusb_remove_ports(struct tegra_xusb_padctl *padctl)
{
	mutex_lock(&padctl->lock);
	__tegra_xusb_remove_ports(padctl);
	mutex_unlock(&padctl->lock);
}

static int tegra_xusb_padctl_suspend_noirq(struct device *dev)
{
	struct tegra_xusb_padctl *padctl = dev_get_drvdata(dev);

	dev_dbg(dev, "%s\n", __func__);

	if (padctl->soc->ops->suspend_noirq)
		return padctl->soc->ops->suspend_noirq(padctl);

	return 0;
}

static int tegra_xusb_padctl_resume_noirq(struct device *dev)
{
	struct tegra_xusb_padctl *padctl = dev_get_drvdata(dev);

	dev_dbg(dev, "%s\n", __func__);

	if (padctl->soc->ops->resume_noirq)
		return padctl->soc->ops->resume_noirq(padctl);

	return 0;
}

static const struct dev_pm_ops tegra_xusb_padctl_pm_ops = {
	SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(tegra_xusb_padctl_suspend_noirq,
				      tegra_xusb_padctl_resume_noirq)
};

static void tegra_xusb_otg_vbus_work(struct work_struct *work)
{
	struct tegra_xusb_padctl *padctl =
		container_of(work, struct tegra_xusb_padctl, otg_vbus_work);

	int i, port;

	for (i = 0; i < XUSB_MAX_OTG_PORT_NUM; i++) {
		if (!padctl->otg_vbus_updating[i])
			continue;

		port = padctl->otg_vbus_usb2_port_base_1[i];
		if (!port)
			continue;

		padctl->soc->ops->otg_vbus_handle(padctl, i, port - 1);
		padctl->otg_vbus_updating[i] = false;
	}
}

static ssize_t otg_vbus_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb_padctl *padctl = platform_get_drvdata(pdev);
	int index = padctl->otg_vbus_usb2_port_base_1[0] - 1;

	if (!padctl->otg_vbus_usb2_port_base_1[0])
		return sprintf(buf, "No UTMI OTG port\n");

	return sprintf(buf, "OTG port %d vbus always-on: %s\n",
			index, padctl->otg_vbus_alwayson ? "yes" : "no");
}

static ssize_t otg_vbus_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb_padctl *padctl = platform_get_drvdata(pdev);
	int index = padctl->otg_vbus_usb2_port_base_1[0] - 1;
	unsigned int on;
	int err = 0;

	if (kstrtouint(buf, 10, &on))
		return -EINVAL;

	if (!padctl->otg_vbus_usb2_port_base_1[0]) {
		dev_err(dev, "No UTMI OTG port\n");
		return -EINVAL;
	}

	if (on && !padctl->otg_vbus_alwayson) {
		err = padctl->soc->ops->vbus_power_on(padctl, index);
		if (!err)
			padctl->otg_vbus_alwayson = true;
	} else if (!on && padctl->otg_vbus_alwayson) {
		/* pre-set this to make vbus power off really work */
		padctl->otg_vbus_alwayson = false;
		err = padctl->soc->ops->vbus_power_off(padctl, index);
		if (!err)
			padctl->otg_vbus_alwayson = false;
		else
			padctl->otg_vbus_alwayson = true;
	}

	if (err)
		dev_err(dev, "failed to %s OTG port %d vbus always-on: %d\n",
				on ? "enable" : "disable", index, err);

	return n;
}

static DEVICE_ATTR(otg_vbus, 0644, otg_vbus_show, otg_vbus_store);

static struct attribute *padctl_attrs[] = {
	&dev_attr_otg_vbus.attr,
	NULL,
};
static struct attribute_group padctl_attr_group = {
	.attrs = padctl_attrs,
};

int tegra_xusb_select_vbus_en_state(struct tegra_xusb_padctl *padctl,
			int pin, bool tristate)
{
	int err;

	if (tristate)
		err = pinctrl_select_state(
				padctl->oc_pinctrl,
				padctl->oc_tristate_enable[pin]);
	else
		err = pinctrl_select_state(
				padctl->oc_pinctrl,
				padctl->oc_passthrough_enable[pin]);

	if (err < 0) {
		dev_err(padctl->dev,
			"setting pin %d OC state failed: %d\n", pin, err);
	}
	return err;
}

static int tegra_xusb_setup_oc(struct tegra_xusb_padctl *padctl)
{
	struct tegra_xusb_usb2_port *usb2_port;
	int i, err = 0;
	bool oc_enabled = false;
	bool isotg = false;

	/* check oc_pin properties from USB2 phy */
	for (i = 0; i < padctl->soc->ports.usb2.count; i++) {
		usb2_port = tegra_xusb_find_usb2_port(padctl, i);
		if (usb2_port && usb2_port->oc_pin >= 0) {
			oc_enabled = true;
			break;
		}
	}
	if (!oc_enabled) {
		dev_dbg(padctl->dev, "No OC pin defined for USB2/USB3 phys\n");
		return -EINVAL;
	}

	/* getting pinctrl for controlling OC pins */
	padctl->oc_pinctrl = devm_pinctrl_get(padctl->dev);
	if (IS_ERR_OR_NULL(padctl->oc_pinctrl)) {
		dev_info(padctl->dev, "Missing OC pinctrl device: %ld\n",
			PTR_ERR(padctl->oc_pinctrl));
		return PTR_ERR(padctl->oc_pinctrl);
	}

	/* OC enable state */
	padctl->oc_tristate_enable = devm_kcalloc(padctl->dev,
			padctl->soc->num_oc_pins,
			sizeof(struct pinctrl_state *), GFP_KERNEL);
	if (!padctl->oc_tristate_enable)
		return -ENOMEM;
	for (i = 0; i < padctl->soc->num_oc_pins; i++) {
		char state_name[sizeof("vbus_enX_sfio_tristate")];

		sprintf(state_name, "vbus_en%d_sfio_tristate", i);
		padctl->oc_tristate_enable[i] = pinctrl_lookup_state(
			padctl->oc_pinctrl, state_name);
		if (IS_ERR(padctl->oc_tristate_enable[i])) {
			dev_info(padctl->dev,
				"Missing OC pin %d pinctrl state %s: %ld\n",
				 i, state_name,
				 PTR_ERR(padctl->oc_tristate_enable[i]));
			return PTR_ERR(padctl->oc_tristate_enable[i]);
		}
	}

	/* OC enable passthrough state */
	padctl->oc_passthrough_enable = devm_kcalloc(padctl->dev,
			padctl->soc->num_oc_pins,
			sizeof(struct pinctrl_state *), GFP_KERNEL);
	if (!padctl->oc_passthrough_enable)
		return -ENOMEM;
	for (i = 0; i < padctl->soc->num_oc_pins; i++) {
		char state_name[sizeof("vbus_enX_sfio_passthrough")];

		sprintf(state_name, "vbus_en%d_sfio_passthrough", i);
		padctl->oc_passthrough_enable[i] = pinctrl_lookup_state(
				padctl->oc_pinctrl, state_name);
		if (IS_ERR(padctl->oc_passthrough_enable[i])) {
			dev_info(padctl->dev,
				"Missing OC pin %d pinctrl state %s: %ld\n",
				 i, state_name,
				 PTR_ERR(padctl->oc_passthrough_enable[i]));
			return PTR_ERR(padctl->oc_passthrough_enable[i]);
		}
	}

	/* OC disable state */
	padctl->oc_disable = devm_kcalloc(padctl->dev,
			padctl->soc->num_oc_pins,
			sizeof(struct pinctrl_state *), GFP_KERNEL);
	if (!padctl->oc_disable)
		return -ENOMEM;
	for (i = 0; i < padctl->soc->num_oc_pins; i++) {
		char state_name[sizeof("vbus_enX_default")];

		sprintf(state_name, "vbus_en%d_default", i);
		padctl->oc_disable[i] = pinctrl_lookup_state(
				padctl->oc_pinctrl, state_name);
		if (IS_ERR(padctl->oc_disable[i])) {
			dev_info(padctl->dev,
				"Missing OC pin %d pinctrl state %s: %ld\n",
				 i, state_name,
				 PTR_ERR(padctl->oc_disable[i]));
			return PTR_ERR(padctl->oc_disable[i]);
		}
	}

	/* switch VBUS pin states to enable OC */
	for (i = 0; i < padctl->soc->ports.usb2.count; i++) {
		usb2_port = tegra_xusb_find_usb2_port(padctl, i);

		if (!usb2_port)
			continue;

		isotg = (usb2_port->port_cap == USB_OTG_CAP);

		if (usb2_port->oc_pin >= 0) {
			/* this OC pin is in use, enable the pin
			 * as SFIO input pin for OC detection,
			 * for OTG port, the default state is
			 * device mode and VBUS off.
			 */
			if (isotg) {
				err = tegra_xusb_select_vbus_en_state(
					padctl, usb2_port->oc_pin, false);
			}

			if (err < 0)
				return err;
		}
	}

	return 0;
}

static int
tegra_xusb_padctl_regulators_init(struct tegra_xusb_padctl *padctl)
{
	struct device *dev = padctl->dev;
	size_t size;
	int err;
	int i;

	size = padctl->soc->num_supplies * sizeof(struct regulator_bulk_data);
	padctl->supplies = devm_kzalloc(dev, size, GFP_ATOMIC);
	if (!padctl->supplies) {
		dev_err(dev, "failed to alloc memory for regulators\n");
		return -ENOMEM;
	}

	for (i = 0; i < padctl->soc->num_supplies; i++)
		padctl->supplies[i].supply = padctl->soc->supply_names[i];

	err = devm_regulator_bulk_get(dev, padctl->soc->num_supplies,
					padctl->supplies);
	if (err) {
		dev_err(dev, "failed to request regulators %d\n", err);
		return err;
	}

	return 0;
}

static int tegra_xusb_padctl_probe(struct platform_device *pdev)
{
	struct device_node *np = of_node_get(pdev->dev.of_node);
	const struct tegra_xusb_padctl_soc *soc;
	struct tegra_xusb_padctl *padctl;
	const struct of_device_id *match;
	struct resource *res;
	int err;

	/* for backwards compatibility with old device trees */
	np = of_find_node_by_name(np, "pads");
	if (!np) {
		dev_warn(&pdev->dev, "deprecated DT, using legacy driver\n");
		return tegra_xusb_padctl_legacy_probe(pdev);
	}

	of_node_put(np);

	match = of_match_node(tegra_xusb_padctl_of_match, pdev->dev.of_node);
	soc = match->data;

	padctl = soc->ops->probe(&pdev->dev, soc);
	if (IS_ERR(padctl))
		return PTR_ERR(padctl);

	np = of_node_get(pdev->dev.of_node);
	if (of_find_property(np, "is_xhci_iov", NULL))
		padctl->is_xhci_iov = true;
	else
		padctl->is_xhci_iov = false;

	of_node_put(np);

	platform_set_drvdata(pdev, padctl);
	INIT_LIST_HEAD(&padctl->ports);
	INIT_LIST_HEAD(&padctl->lanes);
	INIT_LIST_HEAD(&padctl->pads);
	mutex_init(&padctl->lock);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	padctl->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(padctl->regs)) {
		err = PTR_ERR(padctl->regs);
		goto remove;
	}

	if (!padctl->is_xhci_iov) {
		padctl->rst = devm_reset_control_get(&pdev->dev, NULL);
		if (IS_ERR(padctl->rst)) {
			err = PTR_ERR(padctl->rst);
			goto remove;
		}

		err = reset_control_deassert(padctl->rst);
		if (err < 0)
			goto remove;

		err = tegra_xusb_padctl_regulators_init(padctl);
		if (err < 0)
			goto remove;

		err = regulator_bulk_enable(padctl->soc->num_supplies,
					    padctl->supplies);
		if (err) {
			dev_err(&pdev->dev, "failed to enable regulators %d\n",
				err);
			goto remove;
		}
	}

	INIT_WORK(&padctl->otg_vbus_work, tegra_xusb_otg_vbus_work);

	err = tegra_xusb_setup_pads(padctl);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to setup pads: %d\n", err);
		goto reset;
	}

	err = tegra_xusb_setup_ports(padctl);
	if (err) {
		const char *level = KERN_ERR;

		if (err == -EPROBE_DEFER)
			level = KERN_DEBUG;

		dev_printk(level, &pdev->dev,
			   "failed to setup XUSB ports: %d\n", err);
		goto remove_pads;
	}

	err = sysfs_create_group(&pdev->dev.kobj, &padctl_attr_group);
	if (err) {
		dev_err(&pdev->dev, "cannot create sysfs group: %d\n", err);
		goto remove_pads;
	}

	err = tegra_xusb_setup_oc(padctl);
	if (err)
		padctl->oc_pinctrl = NULL;
	else
		dev_info(&pdev->dev, "VBUS over-current detection enabled\n");

	return 0;

remove_pads:
	tegra_xusb_remove_pads(padctl);
reset:
	if (!padctl->is_xhci_iov)
		reset_control_assert(padctl->rst);
remove:
	platform_set_drvdata(pdev, NULL);
	soc->ops->remove(padctl);
	return err;
}

static int tegra_xusb_padctl_remove(struct platform_device *pdev)
{
	struct tegra_xusb_padctl *padctl = platform_get_drvdata(pdev);
	int err = 0;

	tegra_xusb_remove_ports(padctl);
	tegra_xusb_remove_pads(padctl);

	if (!padctl->is_xhci_iov) {
		err = reset_control_assert(padctl->rst);
		if (err < 0)
			dev_err(&pdev->dev, "failed to assert reset: %d\n",
				err);
	}

	padctl->soc->ops->remove(padctl);

	return err;
}

static struct platform_driver tegra_xusb_padctl_driver = {
	.driver = {
		.name = "tegra-xusb-padctl",
		.of_match_table = tegra_xusb_padctl_of_match,
		.pm = &tegra_xusb_padctl_pm_ops,
	},
	.probe = tegra_xusb_padctl_probe,
	.remove = tegra_xusb_padctl_remove,
};
module_platform_driver(tegra_xusb_padctl_driver);

struct tegra_xusb_padctl *tegra_xusb_padctl_get(struct device *dev)
{
	struct tegra_xusb_padctl *padctl;
	struct platform_device *pdev;
	struct device_node *np;

	np = of_parse_phandle(dev->of_node, "nvidia,xusb-padctl", 0);
	if (!np)
		return ERR_PTR(-EINVAL);

	/*
	 * This is slightly ugly. A better implementation would be to keep a
	 * registry of pad controllers, but since there will almost certainly
	 * only ever be one per SoC that would be a little overkill.
	 */
	pdev = of_find_device_by_node(np);
	if (!pdev) {
		of_node_put(np);
		return ERR_PTR(-ENODEV);
	}

	of_node_put(np);

	padctl = platform_get_drvdata(pdev);
	if (!padctl) {
		put_device(&pdev->dev);
		return ERR_PTR(-EPROBE_DEFER);
	}

	return padctl;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_get);

void tegra_xusb_padctl_put(struct tegra_xusb_padctl *padctl)
{
	if (padctl)
		put_device(padctl->dev);
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_put);

int tegra_xusb_padctl_usb3_save_context(struct tegra_xusb_padctl *padctl,
					unsigned int port)
{
	if (padctl->soc->ops->usb3_save_context)
		return padctl->soc->ops->usb3_save_context(padctl, port);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_usb3_save_context);

int tegra_xusb_padctl_hsic_set_idle(struct tegra_xusb_padctl *padctl,
				    unsigned int port, bool idle)
{
	if (padctl->soc->ops->hsic_set_idle)
		return padctl->soc->ops->hsic_set_idle(padctl, port, idle);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_hsic_set_idle);

int tegra_xusb_padctl_hsic_reset(struct tegra_xusb_padctl *padctl,
				    unsigned int port)
{
	if (padctl->soc->ops->hsic_reset)
		return padctl->soc->ops->hsic_reset(padctl, port);

	return -ENODEV;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_hsic_reset);

int tegra_xusb_padctl_usb3_set_lfps_detect(struct tegra_xusb_padctl *padctl,
					   unsigned int port, bool enable)
{
	if (padctl->soc->ops->usb3_set_lfps_detect)
		return padctl->soc->ops->usb3_set_lfps_detect(padctl, port,
							      enable);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_usb3_set_lfps_detect);

int tegra_xusb_padctl_set_vbus_override_early(struct tegra_xusb_padctl *padctl,
		unsigned int i)
{
	if (padctl->soc->ops->vbus_override_early)
		return padctl->soc->ops->vbus_override_early(padctl, i, true);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_set_vbus_override_early);

int tegra_xusb_padctl_set_vbus_override(struct tegra_xusb_padctl *padctl,
		unsigned int i)
{
	if (padctl->soc->ops->vbus_override)
		return padctl->soc->ops->vbus_override(padctl, i, true);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_set_vbus_override);

int tegra_xusb_padctl_clear_vbus_override(struct tegra_xusb_padctl *padctl,
		unsigned int i)
{
	if (padctl->soc->ops->vbus_override)
		return padctl->soc->ops->vbus_override(padctl, i, false);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_clear_vbus_override);

int tegra_xusb_padctl_set_id_override(struct tegra_xusb_padctl *padctl,
		unsigned int i)
{
	if (padctl->soc->ops->id_override)
		return padctl->soc->ops->id_override(padctl, i, true);

	return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_set_id_override);

int tegra_xusb_padctl_clear_id_override(struct tegra_xusb_padctl *padctl,
		unsigned int i)
{
	if (padctl->soc->ops->id_override)
		return padctl->soc->ops->id_override(padctl, i, false);

	return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_clear_id_override);

bool tegra_xusb_padctl_has_otg_cap(struct tegra_xusb_padctl *padctl,
				struct phy *phy)
{
	if (padctl->soc->ops->has_otg_cap)
		return padctl->soc->ops->has_otg_cap(padctl, phy);

	return false;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_has_otg_cap);

int tegra_xusb_padctl_vbus_power_on(struct tegra_xusb_padctl *padctl,
				unsigned int port)
{
	if (padctl->soc->ops->vbus_power_on)
		return padctl->soc->ops->vbus_power_on(padctl, port);

	return false;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_vbus_power_on);

int tegra_xusb_padctl_vbus_power_off(struct tegra_xusb_padctl *padctl,
				unsigned int port)
{
	if (padctl->soc->ops->vbus_power_off)
		return padctl->soc->ops->vbus_power_off(padctl, port);

	return false;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_vbus_power_off);

int tegra_xusb_padctl_enable_phy_sleepwalk(struct tegra_xusb_padctl *padctl,
					   struct phy *phy,
					   enum usb_device_speed speed)
{
	if (padctl->soc->ops->phy_sleepwalk)
		return padctl->soc->ops->phy_sleepwalk(padctl, phy, true,
						       speed);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_enable_phy_sleepwalk);

int tegra_xusb_padctl_disable_phy_sleepwalk(struct tegra_xusb_padctl *padctl,
					    struct phy *phy)
{
	if (padctl->soc->ops->phy_sleepwalk)
		return padctl->soc->ops->phy_sleepwalk(padctl, phy, false, 0);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_disable_phy_sleepwalk);

int tegra_xusb_padctl_enable_phy_wake(struct tegra_xusb_padctl *padctl,
				      struct phy *phy)
{
	if (padctl->soc->ops->phy_wake)
		return padctl->soc->ops->phy_wake(padctl, phy, true);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_enable_phy_wake);

int tegra_xusb_padctl_disable_phy_wake(struct tegra_xusb_padctl *padctl,
				       struct phy *phy)
{
	if (padctl->soc->ops->phy_wake)
		return padctl->soc->ops->phy_wake(padctl, phy, false);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_disable_phy_wake);

int tegra_xusb_padctl_remote_wake_detected(struct tegra_xusb_padctl *padctl,
					   struct phy *phy)
{
	if (padctl->soc->ops->remote_wake_detected)
		return padctl->soc->ops->remote_wake_detected(phy);

	return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_remote_wake_detected);

int tegra_xusb_padctl_set_dcd_debounce_time(struct tegra_xusb_padctl *padctl,
					struct phy *phy, u32 val)
{
	if (padctl->soc->ops->set_debounce_time)
		return padctl->soc->ops->set_debounce_time(padctl, phy, val);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_set_dcd_debounce_time);

int tegra_xusb_padctl_utmi_pad_charger_detect_on(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->utmi_pad_charger_detect_on)
		return padctl->soc->ops->utmi_pad_charger_detect_on(padctl,
									phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_charger_detect_on);

int tegra_xusb_padctl_utmi_pad_charger_detect_off(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->utmi_pad_charger_detect_off)
		return padctl->soc->ops->utmi_pad_charger_detect_off(padctl,
									phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_charger_detect_off);

int tegra_xusb_padctl_utmi_pad_enable_detect_filters(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->detect_filters)
		return padctl->soc->ops->detect_filters(padctl, phy, true);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_enable_detect_filters);

int tegra_xusb_padctl_utmi_pad_disable_detect_filters(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->detect_filters)
		return padctl->soc->ops->detect_filters(padctl, phy, false);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_disable_detect_filters);

int tegra_xusb_padctl_utmi_pad_set_protection_level(struct tegra_xusb_padctl
		*padctl, struct phy *phy, int level, enum tegra_vbus_dir dir)
{
	if (padctl->soc->ops->utmi_pad_set_protection_level)
		return padctl->soc->ops->utmi_pad_set_protection_level
						(padctl, phy, level, dir);
	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_set_protection_level);

int tegra_xusb_padctl_utmi_pad_dcd(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->utmi_pad_dcd)
		return padctl->soc->ops->utmi_pad_dcd(padctl, phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_dcd);

int tegra_xusb_padctl_noncompliant_div_detect(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->noncompliant_div_detect)
		return padctl->soc->ops->noncompliant_div_detect(padctl, phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_noncompliant_div_detect);

int tegra_xusb_padctl_utmi_pad_primary_charger_detect(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->utmi_pad_primary_charger_detect)
		return padctl->soc->ops->utmi_pad_primary_charger_detect(padctl,
									phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_primary_charger_detect);

int tegra_xusb_padctl_utmi_pad_secondary_charger_detect(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->utmi_pad_secondary_charger_detect)
		return padctl->soc->ops->utmi_pad_secondary_charger_detect(
								padctl, phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_utmi_pad_secondary_charger_detect);


int tegra_xusb_padctl_enable_host_cdp(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->set_host_cdp)
		return padctl->soc->ops->set_host_cdp(padctl, phy, true);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_enable_host_cdp);

int tegra_xusb_padctl_disable_host_cdp(struct tegra_xusb_padctl
					*padctl, struct phy *phy)
{
	if (padctl->soc->ops->set_host_cdp)
		return padctl->soc->ops->set_host_cdp(padctl, phy, false);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_disable_host_cdp);

int tegra_xusb_padctl_overcurrent_detected(struct tegra_xusb_padctl *padctl,
					struct phy *phy)
{
	if (padctl->soc->ops->overcurrent_detected)
		return padctl->soc->ops->overcurrent_detected(phy);

	return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_overcurrent_detected);

void tegra_xusb_padctl_handle_overcurrent(struct tegra_xusb_padctl *padctl)
{
	if (padctl->soc->ops->handle_overcurrent)
		padctl->soc->ops->handle_overcurrent(padctl);
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_handle_overcurrent);

void tegra_phy_xusb_utmi_pad_power_on(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;

	if (padctl->soc->ops->utmi_pad_power_on)
		padctl->soc->ops->utmi_pad_power_on(phy);
}
EXPORT_SYMBOL_GPL(tegra_phy_xusb_utmi_pad_power_on);

void tegra_phy_xusb_utmi_pad_power_down(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;

	if (padctl->soc->ops->utmi_pad_power_down)
		padctl->soc->ops->utmi_pad_power_down(phy);
}
EXPORT_SYMBOL_GPL(tegra_phy_xusb_utmi_pad_power_down);

int tegra_phy_xusb_utmi_port_reset_quirk(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;

	if (padctl->soc->ops->utmi_port_reset_quirk)
		return padctl->soc->ops->utmi_port_reset_quirk(phy);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_phy_xusb_utmi_port_reset_quirk);

int tegra_xusb_padctl_get_vbus_id_num(struct tegra_xusb_padctl *padctl)
{
	return padctl->otg_port_num;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_get_vbus_id_num);

void tegra_xusb_padctl_get_vbus_id_ports(struct tegra_xusb_padctl *padctl,
	int i, int *usb2_port, int *usb3_port)
{
	*usb2_port = *usb3_port = -1;

	if (i < 0 || i >= padctl->otg_port_num)
		return;

	/* only check usb2 port for usb2-only otg port support */
	if (!padctl->otg_vbus_usb2_port_base_1[i])
		return;

	*usb2_port = padctl->otg_vbus_usb2_port_base_1[i] - 1;
	*usb3_port = padctl->otg_vbus_usb3_port_base_1[i] - 1;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_get_vbus_id_ports);

int tegra_xusb_padctl_usb3_port_gen1_only(struct phy *phy, bool gen1)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_padctl *padctl;

	if (!phy)
		return -ENODEV;

	lane = phy_get_drvdata(phy);
	padctl = lane->pad->padctl;

	if (padctl->soc->ops->usb3_port_gen1_only)
		return padctl->soc->ops->usb3_port_gen1_only(phy, gen1);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(tegra_xusb_padctl_usb3_port_gen1_only);

MODULE_AUTHOR("Thierry Reding <treding@nvidia.com>");
MODULE_DESCRIPTION("Tegra XUSB Pad Controller driver");
MODULE_LICENSE("GPL v2");
