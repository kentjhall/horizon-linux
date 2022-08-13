/*
 * extcon_gpio.c - Single-state GPIO extcon driver based on extcon class
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * Modified by MyungJoo Ham <myungjoo.ham@samsung.com> to support extcon
 * (originally switch class is supported)
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

#include <linux/extcon.h>
#include <linux/extcon/extcon-gpio.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

struct gpio_extcon_data {
	struct device *dev;
	struct extcon_dev *edev;
	int irq;
	struct delayed_work work;
	unsigned long debounce_jiffies;

	struct gpio_desc *id_gpiod;
	struct gpio_extcon_pdata *pdata;
};

static void gpio_extcon_work(struct work_struct *work)
{
	int state;
	int ret;
	struct gpio_extcon_data	*data =
		container_of(to_delayed_work(work), struct gpio_extcon_data,
			     work);

	if (gpio_is_valid(data->pdata->gpio)) {
		state = gpiod_get_value_cansleep(data->id_gpiod);
		if (data->pdata->gpio_active_low)
			state = !state;
	} else {
		state = data->pdata->default_state;
	}
	ret = extcon_set_state(data->edev,
			       data->pdata->supported_cable[0], state);
	if (ret < 0)
		dev_err(data->dev, "cable state update failed\n");
}

static irqreturn_t gpio_irq_handler(int irq, void *dev_id)
{
	struct gpio_extcon_data *data = dev_id;

	queue_delayed_work(system_power_efficient_wq, &data->work,
			   data->debounce_jiffies);
	return IRQ_HANDLED;
}

static int gpio_extcon_init(struct device *dev, struct gpio_extcon_data *data)
{
	struct gpio_extcon_pdata *pdata = data->pdata;
	int ret;

	ret = devm_gpio_request_one(dev, pdata->gpio, GPIOF_DIR_IN,
				    dev_name(dev));
	if (ret < 0)
		return ret;

	data->id_gpiod = gpio_to_desc(pdata->gpio);
	if (!data->id_gpiod)
		return -EINVAL;

	if (pdata->debounce) {
		ret = gpiod_set_debounce(data->id_gpiod,
					 pdata->debounce * 1000);
		if (ret < 0)
			data->debounce_jiffies =
				msecs_to_jiffies(pdata->debounce);
	}

	data->irq = gpiod_to_irq(data->id_gpiod);
	if (data->irq < 0)
		return data->irq;

	return 0;
}

static struct gpio_extcon_pdata *of_get_platform_data(
		struct platform_device *pdev)
{
	struct gpio_extcon_pdata *pdata;
	struct device_node *np = pdev->dev.of_node;
	int gpio;
	u32 pval;
	int ret;

	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	ret = of_property_read_string(np, "extcon-gpio,name", &pdata->name);
	if (ret < 0)
		pdata->name = np->name;

	ret = of_property_read_u32_array(np, "extcon-gpio,supported-cable",
					 pdata->supported_cable, 2);
	if (ret)
		return ERR_PTR(-EINVAL);

	gpio = of_get_named_gpio(np, "gpio", 0);
	if ((gpio < 0) && (gpio != -ENOENT))
		return ERR_PTR(gpio);

	if (gpio == -ENOENT)
		pdata->gpio = -1;
	else
		pdata->gpio = gpio;

	if (pdata->gpio < 0)
		pdata->default_state = of_property_read_bool(np,
					"extcon-gpio,default-connected");

	ret = of_property_read_u32(np, "extcon-gpio,irq-flags", &pval);
	if (!ret)
		pdata->irq_flags = pval;
	else
		pdata->irq_flags = IRQF_TRIGGER_RISING |
						IRQF_TRIGGER_FALLING;

	ret = of_property_read_u32(np, "extcon-gpio,debounce", &pval);
	if (!ret)
		pdata->debounce = pval;

	pdata->gpio_active_low = of_property_read_bool(np,
				"extcon-gpio,connection-state-low");

	return pdata;
}

static int gpio_extcon_probe(struct platform_device *pdev)
{
	struct gpio_extcon_pdata *pdata = dev_get_platdata(&pdev->dev);
	struct gpio_extcon_data *data;
	int ret;

	if (!pdata && pdev->dev.of_node) {
		pdata = of_get_platform_data(pdev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	}

	if (!pdata)
		return -EBUSY;
	if (!pdata->irq_flags)
		return -EINVAL;

	data = devm_kzalloc(&pdev->dev, sizeof(struct gpio_extcon_data),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	data->dev = &pdev->dev;
	data->pdata = pdata;

	/* Allocate the memory of extcon devie and register extcon device */
	data->edev = devm_extcon_dev_allocate(&pdev->dev,
					pdata->supported_cable);
	if (IS_ERR(data->edev)) {
		dev_err(&pdev->dev, "failed to allocate extcon device\n");
		return -ENOMEM;
	}

	data->edev->name = pdata->name;

	ret = devm_extcon_dev_register(&pdev->dev, data->edev);
	if (ret < 0)
		return ret;

	INIT_DELAYED_WORK(&data->work, gpio_extcon_work);

	if (!gpio_is_valid(pdata->gpio))
		goto skip_gpio;

	/* Initialize the gpio */
	ret = gpio_extcon_init(&pdev->dev, data);
	if (ret < 0)
		return ret;

	/*
	 * Request the interrupt of gpio to detect whether external connector
	 * is attached or detached.
	 */
	ret = devm_request_any_context_irq(&pdev->dev, data->irq,
					   gpio_irq_handler, pdata->irq_flags,
					   pdev->name, data);
	if (ret < 0)
		return ret;

skip_gpio:
	platform_set_drvdata(pdev, data);
	/* Perform initial detection */
	gpio_extcon_work(&data->work.work);

	return 0;
}

static int gpio_extcon_remove(struct platform_device *pdev)
{
	struct gpio_extcon_data *data = platform_get_drvdata(pdev);

	cancel_delayed_work_sync(&data->work);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int gpio_extcon_resume(struct device *dev)
{
	struct gpio_extcon_data *data;

	data = dev_get_drvdata(dev);
	if (data->pdata->check_on_resume)
		queue_delayed_work(system_power_efficient_wq,
				   &data->work, data->debounce_jiffies);

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(gpio_extcon_pm_ops, NULL, gpio_extcon_resume);

static const struct of_device_id of_extcon_gpio_tbl[] = {
	{ .compatible = "extcon-gpio", },
	{ /* end */ }
};
MODULE_DEVICE_TABLE(of, of_extcon_gpio_tbl);

static struct platform_driver gpio_extcon_driver = {
	.probe		= gpio_extcon_probe,
	.remove		= gpio_extcon_remove,
	.driver		= {
		.name	= "extcon-gpio",
		.pm	= &gpio_extcon_pm_ops,
		.of_match_table = of_extcon_gpio_tbl,
	},
};

module_platform_driver(gpio_extcon_driver);

MODULE_AUTHOR("Mike Lockwood <lockwood@android.com>");
MODULE_DESCRIPTION("GPIO extcon driver");
MODULE_LICENSE("GPL");
