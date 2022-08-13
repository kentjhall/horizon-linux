/*
 * Power off driver for Maxim MAX77620 device.
 *
 * Copyright (c) 2014-2019, NVIDIA CORPORATION.  All rights reserved.
 *
 * Author: Chaitanya Bandi <bandik@nvidia.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any kind,
 * whether express or implied; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/power/reset/system-pmic.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/mfd/max77620.h>
#include <linux/regmap.h>
#include <linux/i2c.h>

#define MAX77620_PM_RTC_AUTO_CLEAR_MASK	(1 << 1)
#define MAX77620_PM_RTC_WAKE_MASK			(1 << 3)
#define MAX77620_PM_RTC_RB_UPDATE_MASK		(1 << 4)
#define MAX77620_PM_RTC_INT1_MASK			(1 << 1)

#define GPIO_REG_ADDR(offset) (MAX77620_REG_GPIO0 + offset)
#define MAX77620_MAX_GPIO	8
#define GPIO_VAL_TO_STATE(g, v) ((g << 8) | v)
#define GPIO_STATE_TO_GPIO(gv) (gv >> 8)
#define GPIO_STATE_TO_VAL(gv) (gv & 0xFF)

struct max77620_poweroff {
	struct device *dev;
	struct regmap *rmap;
	struct i2c_client *client;
	struct max77620_chip *max77620;
	struct system_pmic_dev *system_pmic_dev;
	struct notifier_block reset_nb;
	int gpio_state[MAX77620_MAX_GPIO];
	int ngpio_states;
	int gpio_shutdown_state[MAX77620_MAX_GPIO];
	int ngpio_shutdown_states;
	bool use_power_off;
	bool use_power_reset;
	bool need_rtc_power_on;
	bool avoid_power_off_command;
};

static inline void max77620_allow_atomic_xfer(struct max77620_poweroff *max77620_poff)
{
	i2c_shutdown_clear_adapter(max77620_poff->client->adapter);
}
static int max77620_turn_off_gpio(
		struct max77620_poweroff *max77620_poweroff,
		int gpio, int value)
{
	struct device *dev = max77620_poweroff->dev;
	int val;
	int ret;

	dev_info(dev, "Turning off GPIO %d\n", gpio);

	val = (value) ? MAX77620_CNFG_GPIO_OUTPUT_VAL_HIGH :
				MAX77620_CNFG_GPIO_OUTPUT_VAL_LOW;

	ret = regmap_update_bits(max77620_poweroff->rmap,
			GPIO_REG_ADDR(gpio),
			MAX77620_CNFG_GPIO_OUTPUT_VAL_MASK, val);
	if (ret < 0) {
		dev_err(dev, "CNFG_GPIOx val update failed: %d\n", ret);
		return ret;
	}

	ret = regmap_update_bits(max77620_poweroff->rmap,
		GPIO_REG_ADDR(gpio), MAX77620_CNFG_GPIO_DIR_MASK,
				MAX77620_CNFG_GPIO_DIR_OUTPUT);
	if (ret < 0)
		dev_err(dev, "CNFG_GPIOx dir update failed: %d\n", ret);
	return ret;
}


static int max77620_configure_power_on(void *drv_data,
	enum system_pmic_power_on_event event, void *event_data)
{
	struct max77620_poweroff *max77620_poweroff = drv_data;

	switch (event) {
	case SYSTEM_PMIC_RTC_ALARM:
		max77620_poweroff->need_rtc_power_on = true;
		break;

	default:
		dev_err(max77620_poweroff->dev, "power on event does not support\n");
		break;
	}
	return 0;
}

static void _max77620_prepare_system_power_off(
		struct max77620_poweroff *max77620_poweroff)
{
	int i;
	int gpio;
	int val;

	if (!max77620_poweroff->ngpio_states)
		return;

	dev_info(max77620_poweroff->dev, "Preparing power-off from PMIC\n");

	for (i = 0; i < max77620_poweroff->ngpio_states; ++i) {
		gpio = GPIO_STATE_TO_GPIO(max77620_poweroff->gpio_state[i]);
		val = GPIO_STATE_TO_VAL(max77620_poweroff->gpio_state[i]);
		max77620_turn_off_gpio(max77620_poweroff, gpio, val);
	}
}

static void _max77620_prepare_system_shutdown_power_off(
		struct max77620_poweroff *max77620_poweroff)
{
	int i;
	int gpio;
	int val;

	if (!max77620_poweroff->ngpio_shutdown_states)
		return;

	dev_info(max77620_poweroff->dev, "Preparing power-off from PMIC\n");

	for (i = 0; i < max77620_poweroff->ngpio_shutdown_states; ++i) {
		gpio = GPIO_STATE_TO_GPIO(max77620_poweroff->gpio_shutdown_state[i]);
		val = GPIO_STATE_TO_VAL(max77620_poweroff->gpio_shutdown_state[i]);
		max77620_turn_off_gpio(max77620_poweroff, gpio, val);
	}
}

static void max77620_prepare_system_power_off(
		struct max77620_poweroff *max77620_poff)
{
	if (!max77620_poff->ngpio_states)
		return;

	max77620_allow_atomic_xfer(max77620_poff);
	_max77620_prepare_system_power_off(max77620_poff);
}

static void max77620_prepare_power_off(void *drv_data)
{
	struct max77620_poweroff *max77620_poff = drv_data;

	max77620_prepare_system_power_off(max77620_poff);
}

static void max77620_pm_power_off(void *drv_data)
{
	struct max77620_poweroff *max77620_poweroff = drv_data;
	struct max77620_chip *max77620_chip = max77620_poweroff->max77620;
	int ret;
	unsigned int reg_val;

	dev_info(max77620_poweroff->dev, "Powering off system\n");

	max77620_allow_atomic_xfer(max77620_poweroff);

	/* Clear power key interrupts */
	ret = regmap_read(max77620_poweroff->rmap,
			MAX77620_REG_ONOFFIRQ, &reg_val);
	if (ret < 0)
		dev_err(max77620_poweroff->dev,
			"Interrupt status reg 0x%x read failed: %d\n",
			MAX77620_REG_ONOFFIRQ, ret);

	/* Clear TOP interrupts */
	ret = regmap_read(max77620_poweroff->rmap,
			MAX77620_REG_IRQTOP, &reg_val);
	if (ret < 0)
		dev_err(max77620_poweroff->dev,
			"Interrupt status reg 0x%x read failed: %d\n",
			MAX77620_REG_IRQTOP, ret);

	_max77620_prepare_system_power_off(max77620_poweroff);
	_max77620_prepare_system_shutdown_power_off(max77620_poweroff);

	if (get_soc_specific_power_off())
		return;

	if (max77620_chip->chip_id == MAX20024) {
		if (max77620_poweroff->avoid_power_off_command)
			return;
		dev_err(max77620_poweroff->dev,
		    "SYSTEM PMIC MAX20024 POWER-OFF NOT SUPPORTED: SPINNING\n");
		while (1);
	}

	ret = regmap_update_bits(max77620_poweroff->rmap,
		MAX77620_REG_ONOFFCNFG2,
		MAX77620_ONOFFCNFG2_SFT_RST_WK, 0);
	if (ret < 0)
		dev_err(max77620_poweroff->dev,
			"ONOFFCNFG2 update for SFT_RST_WK failed, %d\n", ret);

	if (max77620_poweroff->avoid_power_off_command)
		return;
	ret = regmap_update_bits(max77620_poweroff->rmap,
		MAX77620_REG_ONOFFCNFG1,
		MAX77620_ONOFFCNFG1_SFT_RST, MAX77620_ONOFFCNFG1_SFT_RST);
	if (ret < 0)
		dev_err(max77620_poweroff->dev,
			"ONOFFCNFG1 update for SFT_RST failed, %d\n", ret);
}

static void max77620_pm_power_reset(void *drv_data)
{
	struct max77620_poweroff *max77620_poweroff = drv_data;
	int ret;

	dev_info(max77620_poweroff->dev, "Power resetting system\n");

	max77620_allow_atomic_xfer(max77620_poweroff);

	ret = regmap_update_bits(max77620_poweroff->rmap,
		MAX77620_REG_ONOFFCNFG2,
		MAX77620_ONOFFCNFG2_SFT_RST_WK, MAX77620_ONOFFCNFG2_SFT_RST_WK);

	_max77620_prepare_system_power_off(max77620_poweroff);

	ret = regmap_update_bits(max77620_poweroff->rmap,
		MAX77620_REG_ONOFFCNFG1,
		MAX77620_ONOFFCNFG1_SFT_RST, MAX77620_ONOFFCNFG1_SFT_RST);
	if (ret < 0)
		dev_err(max77620_poweroff->dev,
			"REG_ONOFFCNFG1 update failed, %d\n", ret);
}

static int max77620_restart_notify(struct notifier_block *nb,
			    unsigned long action, void *data)
{
	struct max77620_poweroff *max77620_poweroff;

	max77620_poweroff = container_of(nb, struct max77620_poweroff,
					reset_nb);
	max77620_prepare_system_power_off(max77620_poweroff);
	return NOTIFY_OK;
};

static struct system_pmic_ops max77620_pm_ops = {
	.power_off = max77620_pm_power_off,
	.power_reset = max77620_pm_power_reset,
	.configure_power_on = max77620_configure_power_on,
	.prepare_power_off = max77620_prepare_power_off,
};

static int max77620_poweroff_probe(struct platform_device *pdev)
{
	struct max77620_poweroff *max77620_poweroff;
	struct device_node *np = pdev->dev.parent->of_node;
	struct max77620_chip *max77620 = dev_get_drvdata(pdev->dev.parent);
	struct system_pmic_config config;
	bool use_power_off = false;
	bool use_power_reset = false;
	bool avoid_power_off_command = false;
	unsigned int poweroff_event_recorder;
	const char *prop_name = NULL;
	int count;
	int ret;

	if (np) {
		bool system_pc;

		use_power_off = of_property_read_bool(np,
				"maxim,system-pmic-power-off");
		if (!use_power_off)
			use_power_off = of_property_read_bool(np,
						"system-pmic-power-off");

		use_power_reset = of_property_read_bool(np,
				"maxim,system-pmic-power-reset");
		if (!use_power_reset)
			use_power_reset = of_property_read_bool(np,
						"system-pmic-power-reset");

		system_pc = of_property_read_bool(np,
				"maxim,system-power-controller");
		if (!system_pc)
			system_pc = of_property_read_bool(np,
						"system-power-controller");

		avoid_power_off_command = of_property_read_bool(np,
				"maxim,avoid-power-off-commands");
		if (!avoid_power_off_command)
			avoid_power_off_command = of_property_read_bool(np,
						"avoid-power-off-commands");
		if (system_pc) {
			use_power_off = true;
			use_power_reset = true;
		}
	}

	if (!use_power_off && !use_power_reset) {
		dev_warn(&pdev->dev,
			"power off and reset functionality not selected\n");
		return 0;
	}

	max77620_poweroff = devm_kzalloc(&pdev->dev, sizeof(*max77620_poweroff),
				GFP_KERNEL);
	if (!max77620_poweroff)
		return -ENOMEM;

	platform_set_drvdata(pdev, max77620_poweroff);

	if (!np)
		goto gpio_done;

	if (of_property_read_bool(np, "maxim,power-reset-gpio-states"))
		prop_name = "maxim,power-reset-gpio-states";
	else
		prop_name = "power-reset-gpio-states";

	count = of_property_count_u32_elems(np, prop_name);
	if (count == -EINVAL)
		goto gpio_reset_done;

	if (count % 2) {
		dev_warn(&pdev->dev, "Not able to parse reset-gpio-states\n");
		goto gpio_done;
	}
	max77620_poweroff->ngpio_states = count / 2;
	for (count = 0; count < max77620_poweroff->ngpio_states; ++count) {
		u32 gpio = 0;
		u32 val = 0;
		int index = count * 2;

		of_property_read_u32_index(np, prop_name, index, &gpio);
		of_property_read_u32_index(np, prop_name, index + 1, &val);
		max77620_poweroff->gpio_state[count] =
					GPIO_VAL_TO_STATE(gpio, val);
	}

gpio_reset_done:
	if (of_property_read_bool(np, "maxim,power-shutdown-gpio-states"))
		prop_name = "maxim,power-shutdown-gpio-states";
	else
		prop_name = "power-shutdown-gpio-states";

	count = of_property_count_u32_elems(np, prop_name);
	if (count == -EINVAL)
		goto gpio_done;

	if (count % 2) {
		dev_warn(&pdev->dev, "Not able to parse shutdown-gpio-states\n");
		goto gpio_done;
	}
	max77620_poweroff->ngpio_shutdown_states = count / 2;
	for (count = 0; count < max77620_poweroff->ngpio_shutdown_states; ++count) {
		u32 gpio = 0;
		u32 val = 0;
		int index = count * 2;

		of_property_read_u32_index(np, prop_name, index, &gpio);
		of_property_read_u32_index(np, prop_name, index + 1, &val);
		max77620_poweroff->gpio_shutdown_state[count] =
					GPIO_VAL_TO_STATE(gpio, val);
	}

gpio_done:
	max77620_poweroff->max77620 = max77620;
	max77620_poweroff->rmap = max77620->rmap;
	max77620_poweroff->dev = &pdev->dev;
	max77620_poweroff->use_power_off = use_power_off;
	max77620_poweroff->use_power_reset = use_power_reset;
	max77620_poweroff->avoid_power_off_command = avoid_power_off_command;

	config.allow_power_off = use_power_off;
	config.allow_power_reset = use_power_reset;
	config.avoid_power_off_command = avoid_power_off_command;

	max77620_poweroff->client = i2c_verify_client(max77620->dev);

	max77620_poweroff->system_pmic_dev = system_pmic_register(&pdev->dev,
				&max77620_pm_ops, &config, max77620_poweroff);
	if (IS_ERR(max77620_poweroff->system_pmic_dev)) {
		ret = PTR_ERR(max77620_poweroff->system_pmic_dev);

		dev_err(&pdev->dev, "System PMIC registration failed: %d\n",
			ret);
		return ret;
	}

	ret = regmap_read(max77620_poweroff->rmap,
		MAX77620_REG_NVERC, &poweroff_event_recorder);
	if (ret < 0) {
		dev_err(max77620_poweroff->dev,
			"REG_NVERC read failed, %d\n", ret);
		return ret;
	} else
		dev_info(&pdev->dev, "Event recorder REG_NVERC : 0x%x\n",
				poweroff_event_recorder);

	max77620_poweroff->reset_nb.notifier_call = max77620_restart_notify;
	max77620_poweroff->reset_nb.priority = 200;
	ret = register_restart_handler(&max77620_poweroff->reset_nb);
	if (ret < 0) {
		dev_err(&pdev->dev, "restart handler registration failed\n");
		return ret;
	}

	return 0;
}

static int max77620_poweroff_remove(struct platform_device *pdev)
{
	struct max77620_poweroff *max77620_poweroff =
					platform_get_drvdata(pdev);

	if (!max77620_poweroff)
		return 0;
	system_pmic_unregister(max77620_poweroff->system_pmic_dev);
	return 0;
}

static struct platform_device_id max77620_poweroff_devtype[] = {
	{
		.name = "max77620-power",
	},
	{
		.name = "max20024-power",
	},
	{},
};

static struct platform_driver max77620_poweroff_driver = {
	.driver = {
		.name = "max77620-power",
		.owner = THIS_MODULE,
	},
	.probe = max77620_poweroff_probe,
	.remove = max77620_poweroff_remove,
	.id_table = max77620_poweroff_devtype,
};

module_platform_driver(max77620_poweroff_driver);

MODULE_DESCRIPTION("Power off driver for MAX77620 PMIC Device");
MODULE_ALIAS("platform:max77620-power-off");
MODULE_AUTHOR("Chaitanya Bandi <bandik@nvidia.com>");
MODULE_LICENSE("GPL v2");
