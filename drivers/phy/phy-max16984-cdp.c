/*
 * phy-max16984-cdp.c -- MAXIM MAX16984 CDP PHY Driver
 *
 * This driver abstracts MAX16984 chip as a PHY which can be used
 * specifically for USB controller driver to turn on CDP (charging
 * downstream port) support of this chip.
 *
 * Copyright (c) 2016-2017, NVIDIA Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>

/* soc config for different Tegra chips */
struct max16984_tegra_soc_config {
	unsigned int num_phy;
};

/* MAX16984 control pins for each port */
struct cdp_phy_port {
	int cd0_gpio;
	int cd1_gpio; /* not used for now */
};

/* MAX16984 as a external chip for CDP */
struct max16984_cdp {
	struct device *dev;
	const struct max16984_tegra_soc_config *soc_config;
	struct phy_provider *provider;
	struct phy **cdp_phys;
	struct cdp_phy_port *cdp_ports;
};

static int phy_to_port(struct phy *phy)
{
	struct max16984_cdp *cdp = phy_get_drvdata(phy);
	unsigned int i;

	for (i = 0; i < cdp->soc_config->num_phy; i++) {
		if (phy == cdp->cdp_phys[i])
			return i;
	}
	WARN_ON(1);

	return -EINVAL;
}

static int max16984_set_cdp(struct phy *phy, bool enable)
{
	struct max16984_cdp *cdp = phy_get_drvdata(phy);
	int port = phy_to_port(phy);
	int gpio = cdp->cdp_ports[port].cd0_gpio;

	if (gpio_is_valid(gpio)) {
		dev_info(cdp->dev, "setting CD0 gpio %d of port %d = %d\n",
			 gpio, port, enable ? 1 : 0);
		gpio_set_value(gpio, enable ? 1 : 0);
	} else {
		dev_warn(cdp->dev, "CD0 gpio %d of port %d invalid\n", gpio,
			 port);
		return -EINVAL;
	}

	return 0;
}

static int max16984_cdp_phy_power_on(struct phy *phy)
{
	return max16984_set_cdp(phy, true);
}

static int max16984_cdp_phy_power_off(struct phy *phy)
{
	return max16984_set_cdp(phy, false);
}

static const struct phy_ops cdp_phy_ops = {
	.power_on = max16984_cdp_phy_power_on,
	.power_off = max16984_cdp_phy_power_off,
	.owner = THIS_MODULE,
};

static struct phy *max16984_phy_xlate(struct device *dev,
		struct of_phandle_args *args)
{
	struct max16984_cdp *cdp = dev_get_drvdata(dev);
	unsigned int index;

	if (args->args_count <= 0)
		return ERR_PTR(-EINVAL);

	index = args->args[0];
	dev_dbg(dev, "%s index %d\n", __func__, index);

	if (index < cdp->soc_config->num_phy)
		return cdp->cdp_phys[index];

	return ERR_PTR(-EINVAL);
}

static const struct max16984_tegra_soc_config tegra210_soc_config = {
	.num_phy = 4,
};

static const struct max16984_tegra_soc_config tegra186_soc_config = {
	.num_phy = 3,
};

static const struct of_device_id max16984_of_match[] = {
	{  .compatible = "maxim,max16984-tegra210-cdp-phy",
	   .data = &tegra210_soc_config },
	{  .compatible = "maxim,max16984-tegra186-cdp-phy",
	   .data = &tegra186_soc_config },
	{}
};
MODULE_DEVICE_TABLE(of, max16984_of_match);

static int max16984_probe(struct platform_device *pdev)
{
	struct max16984_cdp *cdp;
	struct device *dev = &pdev->dev;
	const struct of_device_id *match;
	struct device_node *np = dev->of_node;
	int err;
	unsigned int i;

	cdp = devm_kzalloc(dev, sizeof(*cdp), GFP_KERNEL);
	if (!cdp)
		return -ENOMEM;

	platform_set_drvdata(pdev, cdp);
	cdp->dev = dev;

	match = of_match_node(max16984_of_match, np);
	if (!match)
		return -ENODEV;
	cdp->soc_config = match->data;

	WARN_ON(cdp->soc_config->num_phy == 0);

	cdp->cdp_phys = devm_kcalloc(dev, cdp->soc_config->num_phy,
			sizeof(struct phy *), GFP_KERNEL);
	if (!cdp->cdp_phys)
		return -ENOMEM;

	cdp->cdp_ports = devm_kcalloc(dev, cdp->soc_config->num_phy,
			sizeof(struct cdp_phy_port), GFP_KERNEL);
	if (!cdp->cdp_ports)
		return -ENOMEM;

	for (i = 0; i < cdp->soc_config->num_phy; i++) {
		char prop[128];
		int gpio;

		/* get CD0 gpio */
		snprintf(prop, sizeof(prop),
			 "max,cdp-port%d-cd0-gpio", i);
		gpio = of_get_named_gpio(np, prop, 0);
		dev_dbg(dev, "max16984 port %d CD0 gpio [%s]: %d\n", i, prop,
			gpio);
		if (gpio == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		if (gpio > 0) {
			err = devm_gpio_request_one(dev, gpio,
					GPIOF_DIR_OUT | GPIOF_INIT_HIGH,
					dev_name(dev));
			if (err < 0)
				dev_err(dev, "CDP port %d CD0 gpio %d request failed: %d\n",
					i, gpio, err);
			else
				cdp->cdp_ports[i].cd0_gpio = gpio;
		}

		/* get CD1 gpio */
		snprintf(prop, sizeof(prop),
			 "max,cdp-port%d-cd1-gpio", i);
		gpio = of_get_named_gpio(np, prop, 0);
		dev_dbg(dev, "max16984 port %d CD1 gpio [%s]: %d\n", i, prop,
			gpio);
		if (gpio == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		if (gpio > 0) {
			err = devm_gpio_request_one(dev, gpio,
					GPIOF_DIR_OUT | GPIOF_INIT_HIGH,
					dev_name(dev));
			if (err < 0)
				dev_err(dev, "CDP port %d CD1 gpio %d request failed: %d\n",
					i, gpio, err);
			else
				cdp->cdp_ports[i].cd1_gpio = gpio;
		}

		/* create phy for each UTMI port */
		cdp->cdp_phys[i] = devm_phy_create(dev, NULL, &cdp_phy_ops);
		if (IS_ERR(cdp->cdp_phys[i])) {
			err = PTR_ERR(cdp->cdp_phys[i]);
			dev_err(dev, "CDP phy %d create failed: %d\n", i, err);
			return err;
		}
		phy_set_drvdata(cdp->cdp_phys[i], cdp);
	}

	/* register as phy provider */
	cdp->provider = devm_of_phy_provider_register(dev, max16984_phy_xlate);
	if (IS_ERR(cdp->provider)) {
		err = PTR_ERR(cdp->provider);
		dev_err(dev, "failed to register PHYs: %d\n", err);
		return err;
	}

	return 0;
}

static struct platform_driver max16984_cdp_phy_driver = {
	.probe = max16984_probe,
	.driver = {
		.name = "max16984-cdp-phy",
		.of_match_table = max16984_of_match,
		.owner = THIS_MODULE,
	},
};

static int __init max16984_pinctrl_init(void)
{
	return platform_driver_register(&max16984_cdp_phy_driver);
}
subsys_initcall(max16984_pinctrl_init);

static void __exit max16984_pinctrl_exit(void)
{
	platform_driver_unregister(&max16984_cdp_phy_driver);
}
module_exit(max16984_pinctrl_exit);

MODULE_DESCRIPTION("Max16984 CDP PHY driver");
MODULE_AUTHOR("Mark Kuo<mkuo@nvidia.com>");
MODULE_ALIAS("platform:max16984-cdp-phy");
MODULE_LICENSE("GPL v2");
