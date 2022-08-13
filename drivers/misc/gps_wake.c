/*
 * Copyright (c) 2015-2016, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/interrupt.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/module.h>

struct gps_wake_data {
	int gps_enable_gpio;
	int gps_wakeup_gpio;
	int gps_wakeup_irq;
	struct class *gps_wake_class;
	struct device *gps_dev;
};

static irqreturn_t gps_hostwake_isr(int irq, void *dev_id)
{
	/* schedule a tasklet to handle the change in the host wake line */
	return IRQ_HANDLED;
}

static ssize_t gps_enable_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct gps_wake_data *gps_wake = dev_get_drvdata(dev);
	int state;

	state = gpio_get_value_cansleep(gps_wake->gps_enable_gpio);

	return sprintf(buf, "%d\n", state);
}

static ssize_t gps_enable_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct gps_wake_data *gps_wake = dev_get_drvdata(dev);
	int state;

	state = memparse(buf, NULL);
	if (state != 0 && state != 1)
		return -EINVAL;

	gpio_set_value_cansleep(gps_wake->gps_enable_gpio, state);

	return count;
}

static DEVICE_ATTR(gps_enable, S_IRUGO | S_IWUSR, gps_enable_show,
		   gps_enable_store);

static int gps_wake_probe(struct platform_device *pdev)
{
	struct gps_wake_data *gps_wake;
	struct device_node *node = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	int ret;

	gps_wake = devm_kzalloc(dev, sizeof(*gps_wake), GFP_KERNEL);
	if (!gps_wake)
		return -ENOMEM;
	dev_set_drvdata(dev, gps_wake);

	gps_wake->gps_enable_gpio = of_get_named_gpio(node,
						      "gps-enable-gpio", 0);
	gps_wake->gps_wakeup_gpio = of_get_named_gpio(node,
						      "gps-wakeup-gpio", 0);

	if ((gps_wake->gps_enable_gpio == -EPROBE_DEFER) ||
	    (gps_wake->gps_wakeup_gpio == -EPROBE_DEFER))
		return -EPROBE_DEFER;

	if (!gpio_is_valid(gps_wake->gps_enable_gpio)) {
		dev_dbg(dev, "gps_enable_gpio is not a valid\n");
		return -ENODEV;
	}
	/* Request gps_enable_gpio with output low as default direction */
	ret = devm_gpio_request_one(dev, gps_wake->gps_enable_gpio,
				    GPIOF_OUT_INIT_LOW, "gps_enable_gpio");
	if (ret) {
		dev_err(dev, "Failed to request gps_enable_gpio: %d\n", ret);
		return ret;
	}

	gps_wake->gps_wake_class = class_create(THIS_MODULE, "gps_wake");
	if (IS_ERR(gps_wake->gps_wake_class)) {
		ret = PTR_ERR(gps_wake->gps_wake_class);
		dev_err(dev, "Failed to create gps_wake class: %d\n", ret);
		goto free_res1;
	}

	gps_wake->gps_dev = device_create(gps_wake->gps_wake_class, NULL, 0,
					  gps_wake, "gps_device");
	if (IS_ERR(gps_wake->gps_dev)) {
		ret = PTR_ERR(gps_wake->gps_dev);
		dev_err(dev, "Failed to create gps_device: %d\n", ret);
		goto free_res2;
	}

	ret = device_create_file(gps_wake->gps_dev, &dev_attr_gps_enable);
	if (ret) {
		dev_err(dev, "Failed to create device file: %d\n", ret);
		goto free_res3;
	}

	if (!gpio_is_valid(gps_wake->gps_wakeup_gpio)) {
		dev_dbg(dev, "gps_wakeup_gpio is not a valid\n");
		return 0;
	}

	gps_wake->gps_wakeup_irq = gpio_to_irq(gps_wake->gps_wakeup_gpio);
	if (gps_wake->gps_wakeup_irq < 0) {
		dev_err(dev, "not a valid gps_wakeup_irq\n");
		goto free_res4;
	}

	/* configure host_wake as input */
	ret = devm_gpio_request_one(dev, gps_wake->gps_wakeup_gpio,
				    GPIOF_IN, "gps_wakeup_gpio");
	if (ret) {
		dev_err(dev, "Failed to request gps_wakeup_gpio: %d\n", ret);
		goto free_res4;
	}

	ret = devm_request_irq(dev, gps_wake->gps_wakeup_irq,
			       gps_hostwake_isr, IRQF_TRIGGER_RISING,
			       "gps_wakeup_irq", gps_wake);
	if (ret) {
		dev_err(dev, "Failed to request gps_wakeup_irq: %d\n", ret);
		goto free_res4;
	}
	ret = device_init_wakeup(dev, 1);
	if (ret) {
		dev_err(dev, "device_init_wakeup failed, ret=%d\n", ret);
		goto free_res4;
	}

	return 0;

free_res4:
	device_remove_file(gps_wake->gps_dev, &dev_attr_gps_enable);
free_res3:
	device_destroy(gps_wake->gps_wake_class, 0);
free_res2:
	class_destroy(gps_wake->gps_wake_class);
free_res1:

	return ret;
}

static int gps_wake_remove(struct platform_device *pdev)
{
	struct gps_wake_data *gps_wake = dev_get_drvdata(&pdev->dev);

	if (!gpio_is_valid(gps_wake->gps_enable_gpio))
		return 0;

	device_remove_file(&pdev->dev, &dev_attr_gps_enable);
	device_destroy(gps_wake->gps_wake_class, 0);
	class_destroy(gps_wake->gps_wake_class);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int gps_wake_suspend(struct device *dev)
{
	struct gps_wake_data *gps_wake = dev_get_drvdata(dev);

	if (device_may_wakeup(dev))
		enable_irq_wake(gps_wake->gps_wakeup_irq);
	return 0;
}

static int gps_wake_resume(struct device *dev)
{
	struct gps_wake_data *gps_wake = dev_get_drvdata(dev);

	if (device_may_wakeup(dev))
		disable_irq_wake(gps_wake->gps_wakeup_irq);

	return 0;
}
#endif

static const struct dev_pm_ops gps_wake_pm_ops = {
#ifdef CONFIG_PM_SLEEP
	SET_SYSTEM_SLEEP_PM_OPS(gps_wake_suspend, gps_wake_resume)
#endif
};

static const struct of_device_id gps_of_match[] = {
	{ .compatible = "gps-wake" },
	{ },
};
MODULE_DEVICE_TABLE(of, gps_of_match);

static struct platform_driver gps_wake_driver = {
	.probe = gps_wake_probe,
	.remove = gps_wake_remove,
	.driver = {
		.name = "gps_wake",
		.of_match_table = gps_of_match,
		.pm = &gps_wake_pm_ops,
		.owner = THIS_MODULE,
	},
};

module_platform_driver(gps_wake_driver);

MODULE_DESCRIPTION("GPS host wake driver");
MODULE_AUTHOR("NVIDIA Corporation");
MODULE_LICENSE("GPL v2");
