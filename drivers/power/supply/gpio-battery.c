/* Copyright (c) 2017, NVIDIA CORPORATION.  All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/device.h>
#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/power_supply.h>
#include <linux/slab.h>

struct gpio_gas_gauge {
	struct device *dev;
	int gpio;
	unsigned int irq;
	const char *name;
	int low_battery_signal;

	struct power_supply *supply;
	struct power_supply *charger;
};

static irqreturn_t gpio_gas_gauge_isr(int irq, void *devid)
{
	struct power_supply *supply = devid;

	power_supply_changed(supply);

	return IRQ_HANDLED;
}

static int gpio_gas_gauge_get_property(struct power_supply *psy,
				       enum power_supply_property psp,
				       union power_supply_propval *val)
{
	struct gpio_gas_gauge *gas_gauge = power_supply_get_drvdata(psy);
	int gpio_val;

	switch (psp) {
	case POWER_SUPPLY_PROP_PRESENT:
		dev_info(gas_gauge->dev, "The power supply is present.\n");
		val->intval = 1;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		gpio_val = gpio_get_value(gas_gauge->gpio);
		if (gpio_val == gas_gauge->low_battery_signal) {
			val->intval = 0;
			break;
		}
		val->intval = 100;
		break;
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = POWER_SUPPLY_STATUS_DISCHARGING;
		break;
	default:
		return 0;
	};

	return 0;
}

static enum power_supply_property gpio_gas_gauge_properties[] = {
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_STATUS,
};

static const struct power_supply_desc gpio_gas_gauge_default_desc = {
	.type		= POWER_SUPPLY_TYPE_BATTERY,
	.properties	= gpio_gas_gauge_properties,
	.num_properties	= ARRAY_SIZE(gpio_gas_gauge_properties),
	.get_property	= gpio_gas_gauge_get_property,
};

static int gpio_gas_charger_get_property(struct power_supply *psy,
		enum power_supply_property psp, union power_supply_propval *val)
{
	struct gpio_gas_gauge *gas_gauge = power_supply_get_drvdata(psy);
	int gpio_val = gpio_get_value(gas_gauge->gpio);

	if (gpio_val == gas_gauge->low_battery_signal) {
		val->intval = 0;
		return 0;
	}

	val->intval = 1;
	return 0;
}

static enum power_supply_property gpio_gas_charger_properties[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static const struct power_supply_desc gpio_gas_charger_default_desc = {
	.type		= POWER_SUPPLY_TYPE_MAINS,
	.properties	= gpio_gas_charger_properties,
	.num_properties	= ARRAY_SIZE(gpio_gas_charger_properties),
	.get_property	= gpio_gas_charger_get_property,
};

static int gpio_gas_gauge_parse_dt(struct gpio_gas_gauge *gas_gauge,
				   struct device_node *np)
{
	int err = 0;
	int len;
	char const *name = "gpio-gas-gauge";
	enum of_gpio_flags flags;

	gas_gauge->gpio = of_get_gpio_flags(np, 0, &flags);
	gas_gauge->low_battery_signal = flags & OF_GPIO_ACTIVE_LOW;

	if (of_get_property(np, "supply-name", &len))
		err = of_property_read_string(np, "supply-name",
						&gas_gauge->name);
	if (err)
		gas_gauge->name = name;

	return 0;
}

static int gpio_gas_gauge_probe(struct platform_device *pdev)
{
	struct gpio_gas_gauge *gas_gauge;
	struct power_supply_desc *psy_desc;
	struct power_supply_desc *chg_desc;
	struct power_supply_config psy_cfg = {};
	struct power_supply_config chg_cfg = {};
	int ret;
	int irq;

	if (!pdev->dev.of_node) {
		dev_err(&pdev->dev, "No DT node found, DT required\n");
		return -EINVAL;
	}

	gas_gauge = devm_kzalloc(&pdev->dev, sizeof(*gas_gauge),
					GFP_KERNEL);
	if (!gas_gauge)
		return -ENOMEM;

	psy_desc = devm_kmemdup(&pdev->dev, &gpio_gas_gauge_default_desc,
				sizeof(*psy_desc), GFP_KERNEL);
	if (!psy_desc)
		return -ENOMEM;

	chg_desc = devm_kmemdup(&pdev->dev, &gpio_gas_charger_default_desc,
				sizeof(*chg_desc), GFP_KERNEL);
	if (!chg_desc)
		return -ENOMEM;

	ret = gpio_gas_gauge_parse_dt(gas_gauge, pdev->dev.of_node);
	if (ret) {
		dev_err(&pdev->dev, "Failed to parse dt node\n");
		return -EINVAL;
	}

	gas_gauge->dev = &pdev->dev;
	psy_desc->name = gas_gauge->name;
	psy_cfg.of_node = pdev->dev.of_node;
	psy_cfg.drv_data = gas_gauge;

	chg_desc->name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "%s-charger",
					gas_gauge->name);
	chg_cfg.of_node = pdev->dev.of_node;
	chg_cfg.drv_data = gas_gauge;

	if (!gpio_is_valid(gas_gauge->gpio)) {
		dev_err(&pdev->dev, "Invalid gpio\n");
		return -EINVAL;
	}

	ret = devm_gpio_request(&pdev->dev, gas_gauge->gpio,
			"GPIO Gas Gauge");
	if (ret) {
		dev_err(&pdev->dev, "Failed requesting gpio");
		return ret;
	}

	ret = gpio_direction_input(gas_gauge->gpio);
	if (ret) {
		dev_err(&pdev->dev, "Failed setting gpio direction");
		return ret;
	}
	dev_info(&pdev->dev, "Set up gpio input");

	gas_gauge->supply = power_supply_register(&pdev->dev, psy_desc,
						  &psy_cfg);
	if (IS_ERR(gas_gauge->supply)) {
		dev_err(&pdev->dev, "Failed to register power supply: %d\n",
			ret);
		ret = PTR_ERR(gas_gauge->supply);
		return ret;
	}

	gas_gauge->charger = power_supply_register(&pdev->dev, chg_desc,
						   &chg_cfg);
	if (IS_ERR(gas_gauge->charger)) {
		dev_err(&pdev->dev, "Failed to register charger: %d\n", ret);
		ret = PTR_ERR(gas_gauge->charger);
		power_supply_unregister(gas_gauge->supply);
		return ret;
	}

	irq = gpio_to_irq(gas_gauge->gpio);
	if (irq > 0) {
		ret = request_any_context_irq(irq, gpio_gas_gauge_isr,
				IRQF_TRIGGER_FALLING | IRQF_TRIGGER_RISING,
				dev_name(&pdev->dev), gas_gauge->supply);
		if (ret < 0) {
			dev_err(&pdev->dev, "Failed to request irq: %d\n", ret);
			goto unregister_power_supplies;
		}
		gas_gauge->irq = irq;
	}
	platform_set_drvdata(pdev, gas_gauge);

	return 0;
unregister_power_supplies:
	power_supply_unregister(gas_gauge->charger);
	power_supply_unregister(gas_gauge->supply);

	return ret;
}

static int gpio_gas_gauge_remove(struct platform_device *pdev)
{
	struct gpio_gas_gauge *gas_gauge = platform_get_drvdata(pdev);

	power_supply_unregister(gas_gauge->charger);
	power_supply_unregister(gas_gauge->supply);

	return 0;
}

static const struct of_device_id gpio_gas_gauge_of_match[] = {
	{ .compatible = "gpio-gas-gauge", }, { }
};
MODULE_DEVICE_TABLE(of, gpio_gas_gauge_of_match);

static struct platform_driver gpio_gas_gauge_driver = {
	.probe			= gpio_gas_gauge_probe,
	.remove			= gpio_gas_gauge_remove,
	.driver = {
		.name		= "gpio-gas-gauge",
		.owner		= THIS_MODULE,
		.of_match_table	= of_match_ptr(gpio_gas_gauge_of_match),
	},
};
module_platform_driver(gpio_gas_gauge_driver);

MODULE_AUTHOR("Rhyland Klein <rklein@nvidia.com>");
MODULE_DESCRIPTION("Driver for gas gauges which have a gpio to signal when capacity is low enough to need to shut down");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:gpio-gas-gauge");
