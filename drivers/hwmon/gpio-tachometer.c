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
 *
 */

#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/clk.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/slab.h>
#include <linux/reset.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/sysfs.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <linux/thermal.h>

/*
 * Mechanism for measuring RPM using GPIO irq
 * Enable gpio IRQ, and start a timer for 100ms.
 * In the IRQ handler, increment a static counter.
 * After the delay timeout, disable the IRQ.
 * Calculate RPM based on number of pulses per rotation.
*/

#define SECONDS_IN_MIN	60
#define MIN_SAMPLE_WIN	100	/* Minimum duration for sampling window is
				 * 100ms values lesser than this causes
				 * inconsistent measurement due to insufficient
				 *  samples
				*/
#define MAX_SAMPLE_WIN	50	/* Maximum allowed sampling window is 5 seconds
				*/

static void tach_measure_work(struct work_struct *work);

struct gpio_tachometer_device {
	/*delay work to monitor fan rpm*/
	struct delayed_work tach_work;
	struct mutex lock;
	/*work queue that schedules the delayed work*/
	struct workqueue_struct *tach_workqueue;
	u64 first_jiffy;
	u64 last_jiffy;
	u32 win_len;
	u32 pulse_per_rev;
	u32 schedule_delay;
	struct device *tach_dev;
	/*last measured rpm*/
	unsigned long rpm;
	/*number of irq reported in the time window*/
	u32 tach_counter;
	/*GPIO to which motor tach input is connected*/
	u32 tach_gpio;
	/*IRQ number to be used for measurement*/
	u32 tach_irq;
	bool is_first_jiffy;
};

static ssize_t gpio_tachometer_read_winlen(struct device *tach,
		struct device_attribute *attr, char *buf)
{
	struct gpio_tachometer_device *gpio_tachd = dev_get_drvdata(tach);

	if (gpio_tachd)
		return sprintf(buf, "%u\n", gpio_tachd->win_len);
	else
		return sprintf(buf, "%u\n", 0);
}

static ssize_t gpio_tachometer_set_winlen(struct device *tach,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct gpio_tachometer_device *gpio_tachd;

	gpio_tachd =
		(struct gpio_tachometer_device *)dev_get_drvdata(tach);
	if (kstrtouint(buf, 10, &gpio_tachd->win_len) ||
		(gpio_tachd->win_len > MAX_SAMPLE_WIN) ||
		(gpio_tachd->win_len <= 0))
		return -EINVAL;
	pr_info("gpio_tach win_len set to %d\n", gpio_tachd->win_len);

	return 0;
}

static SENSOR_DEVICE_ATTR(gpiotach_winlen, S_IRUGO | S_IWUSR,
		gpio_tachometer_read_winlen, gpio_tachometer_set_winlen, 0);

static irqreturn_t gpio_tachometer_irq_handler(int irq, void *data)
{
	struct gpio_tachometer_device *gpio_tachd =
				(struct gpio_tachometer_device *) data;

	u64 stamp = jiffies;

	if (irq != gpio_tachd->tach_irq)
		return IRQ_NONE;
	if (gpio_tachd->is_first_jiffy == 0) {
		gpio_tachd->is_first_jiffy = 1;
		gpio_tachd->first_jiffy = stamp;
	}
	gpio_tachd->last_jiffy = stamp;
	gpio_tachd->tach_counter++;
	return IRQ_HANDLED;
}

static unsigned long gpio_tachometer_read_rpm(struct device *tach)
{
	struct gpio_tachometer_device *gpio_tachd;
	u32 tach0;
	u64 time, delay;
	unsigned long denominator, numerator;
	int ret;
	unsigned long rpm;

	gpio_tachd =
		(struct gpio_tachometer_device *)dev_get_drvdata(tach);
	gpio_tachd->tach_counter = 0;
	gpio_tachd->is_first_jiffy = 0;
	gpio_tachd->first_jiffy = 0;
	gpio_tachd->last_jiffy = 0;

	/* Measurement is based on the number of IRQs reported in the given
	 * time window. Better measurement is obtained with more samples of
	 * interrupts. A multiplier of 100 makes sure that interrupts are
	 * accumulated for atleast 100ms.
	*/

	delay = ((u64)gpio_tachd->win_len * MIN_SAMPLE_WIN);

	/*Enable IRQ*/
	gpio_tachd->tach_irq = gpio_to_irq(gpio_tachd->tach_gpio);
	if (gpio_tachd->tach_irq <= 0)
		return 0;
	ret = mutex_lock_interruptible(&gpio_tachd->lock);
	if (ret != 0)
		return 0;
	ret = request_irq(gpio_tachd->tach_irq, gpio_tachometer_irq_handler,
					IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
					"gpio_tachometer", gpio_tachd);
	if (ret) {
		pr_err("%s: failed to register gpio IRQ: %d\n", __func__, ret);
		mutex_unlock(&gpio_tachd->lock);
		return 0;
	}

	mdelay(delay);

	/*Disable IRQ*/
	free_irq(gpio_tachd->tach_irq, gpio_tachd);
	mutex_unlock(&gpio_tachd->lock);
	/*Read IRQ count*/
	tach0 = gpio_tachd->tach_counter;
	time = ((int64_t)gpio_tachd->last_jiffy -
			(int64_t)gpio_tachd->first_jiffy);
	/*
	 * correct irq count to nearest multiple of pulse-per-revolution
	 * modify the time based on the adjustment
	*/
	if (tach0 % gpio_tachd->pulse_per_rev) {
		time = time +
			((gpio_tachd->pulse_per_rev -
			 (tach0 % gpio_tachd->pulse_per_rev)) *
			(time / tach0));
		tach0 = tach0 +
			(gpio_tachd->pulse_per_rev -
				(tach0 % gpio_tachd->pulse_per_rev));
	}
	/*
	 *	rpm = (irq_count * 60 * jiffy_frequency) / (time)
	*/
	numerator = SECONDS_IN_MIN *  tach0 * HZ;
	denominator = time * gpio_tachd->pulse_per_rev;
	if (denominator == 0) {
		gpio_tachd->rpm = 0;
	} else {
		rpm = numerator / denominator;
		gpio_tachd->rpm = rpm;
	}
	return gpio_tachd->rpm;
}

static ssize_t gpio_tachometer_rpm_show(struct device *tach,
			struct device_attribute *attr, char *buf)
{
	unsigned long rpm = gpio_tachometer_read_rpm(tach);

	return sprintf(buf, "%lu\n", rpm);
}

static SENSOR_DEVICE_ATTR(gpiotach_rpm, S_IRUGO,
		gpio_tachometer_rpm_show, NULL, 1);

static struct attribute *gpio_tach_attrs[] = {
	&sensor_dev_attr_gpiotach_rpm.dev_attr.attr,
	&sensor_dev_attr_gpiotach_winlen.dev_attr.attr,
	NULL,
};

ATTRIBUTE_GROUPS(gpio_tach);

static void tach_measure_work(struct work_struct *workp)
{
	struct delayed_work *work = container_of(workp, struct delayed_work,
									work);
	struct gpio_tachometer_device *gpio_tachd =
		container_of(work, struct gpio_tachometer_device, tach_work);
	struct device *tach;

	tach = gpio_tachd->tach_dev;

	(void)gpio_tachometer_read_rpm(tach);
	if (gpio_tachd->rpm == 0)
		orderly_poweroff(true);
	else
		queue_delayed_work(gpio_tachd->tach_workqueue,
			&gpio_tachd->tach_work, gpio_tachd->schedule_delay);
}

static const struct of_device_id gpio_tachometer_of_match[] = {
	{
		.compatible = "nvidia,gpio-tachometer"
	},
	{}
};
MODULE_DEVICE_TABLE(of, gpio_tachometer_of_match);

static int gpio_tachometer_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = pdev->dev.of_node;
	struct gpio_tachometer_device *gpio_tachd = NULL;
	struct device *tach_dev;
	int ret = 0, err;

	gpio_tachd = devm_kzalloc(&pdev->dev, sizeof(*gpio_tachd), GFP_KERNEL);
	if (gpio_tachd == NULL) {
		dev_err(dev, "Failed to allocate memory\n");
		return -ENOMEM;
	}
	mutex_init(&gpio_tachd->lock);

	/* If pulse-per-rev node not present or if the value
	 * is less than 1, abort.
	*/
	if (of_property_read_u32(np, "pulse-per-rev",
			&gpio_tachd->pulse_per_rev) ||
			(gpio_tachd->pulse_per_rev < 1)) {
		dev_err(dev, "pulse-per-rev field not defined\n");
		return -EINVAL;
	}

	if (of_property_read_u32(np, "win-len", &gpio_tachd->win_len))
		/*Set a minimum window length of 100ms*/
		gpio_tachd->win_len = 1;
	else {
		if (gpio_tachd->win_len > MAX_SAMPLE_WIN) {
			gpio_tachd->win_len = MAX_SAMPLE_WIN;
			pr_warn("%s: Tachometer win-len exceeds maximum allowed value.\nUsing maximum value %d\n",
				 __func__, gpio_tachd->win_len);
		}
	}

	/* If schedule-delay node not present or if the delay is less than window period
	 * then disable monitoring
	*/
	if ((of_property_read_u32(np, "schedule-delay",
					&gpio_tachd->schedule_delay)) ||
		(gpio_tachd->schedule_delay <= (gpio_tachd->win_len * MIN_SAMPLE_WIN)))
		gpio_tachd->schedule_delay = 0;

	gpio_tachd->tach_gpio = of_get_named_gpio(np, "gpio", 0);
	dev_info(dev, "Tachometer GPIO=%d, win-len=%u, schedule_delay=%u\n",
		gpio_tachd->tach_gpio, gpio_tachd->win_len, gpio_tachd->schedule_delay);
	if (gpio_is_valid(gpio_tachd->tach_gpio)) {
		err = devm_gpio_request_one(dev, gpio_tachd->tach_gpio,
						GPIOF_IN, "Tach_input");
		if (err < 0) {
			dev_err(dev, "%s: Tachometer GPIO request failed for gpio %d: error %d\n",
				__func__, gpio_tachd->tach_gpio, err);
			return -EINVAL;
		}

		tach_dev = devm_hwmon_device_register_with_groups(dev, "gpiofan",
				gpio_tachd, gpio_tach_groups);
		if (IS_ERR(tach_dev)) {
			ret = PTR_ERR(tach_dev);
			dev_err(dev, "GPIO Tachometer driver init failed, err: %d\n",
				 ret);
			return ret;
		}
		platform_set_drvdata(pdev, gpio_tachd);
		gpio_tachd->tach_dev = tach_dev;
		dev_info(dev, "Tachometer driver initialized with pulse_per_rev: %d and win_len: %d\n",
			gpio_tachd->pulse_per_rev, gpio_tachd->win_len);
		/*If schedule delay is not configured, don't monitor rpm*/
		if (gpio_tachd->schedule_delay == 0)
			return ret;
		/*Create single thread work queue*/
		gpio_tachd->tach_workqueue =
			create_singlethread_workqueue("tach_workqueue");
		INIT_DELAYED_WORK(&gpio_tachd->tach_work, tach_measure_work);
		err = queue_delayed_work(gpio_tachd->tach_workqueue,
			&gpio_tachd->tach_work, gpio_tachd->schedule_delay);
		if (err == 1)
			dev_info(dev, "tach measure work submitted successfully\n");
		else {
			dev_err(dev, "tach measure work submission failed: %d\n", err);
			destroy_workqueue(gpio_tachd->tach_workqueue);
			devm_gpio_free(dev, gpio_tachd->tach_gpio);
			ret = -EINVAL;
		}
	} else {
		dev_err(dev, "Invalid GPIO\n");
		ret = -EINVAL;
	}
	return ret;
}

static int gpio_tachometer_remove(struct platform_device *pdev)
{
	struct gpio_tachometer_device *gpio_tachd = platform_get_drvdata(pdev);

	if (!gpio_tachd)
		return 0;

	cancel_delayed_work(&gpio_tachd->tach_work);
	destroy_workqueue(gpio_tachd->tach_workqueue);
	kfree(gpio_tachd);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static struct platform_driver gpio_tachometer_driver = {
	.driver = {
		.name = "gpio-tachometer",
		.of_match_table = gpio_tachometer_of_match,
	},
	.probe = gpio_tachometer_probe,
	.remove = gpio_tachometer_remove,
};

module_platform_driver(gpio_tachometer_driver);

MODULE_DESCRIPTION("GPIO Tachometer driver");
MODULE_AUTHOR("Vishruth Jain <vishruthj@nvidia.com>");
MODULE_LICENSE("GPL v2");
