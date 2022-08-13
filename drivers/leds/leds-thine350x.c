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
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/spi/spi.h>
#include <linux/of.h>

#define THINE_350X_LEDS_COUNT				24
/*bit6-output enable, bit[5:0]-base brightness*/
#define THINE_350X_DEF_INIT_BRIGHT			127
/*slave address*/
#define THINE_350X_DEF_ADDRESS				0
/*Value of register 0: enable output, group brightness 0x3f*/
#define THINE_350X_MAX_BASE_BRIGHT			0x7f
/*No. of bytes required to control individual led*/
#define THINE_350x_LED_COM_BYTE_COUNT			3
/*No. of bytes of control information before LED brightness data for all LEDs*/
#define THINE_350x_LED_CTRL_BYTE_COUNT			3

struct thine350x_led {
	struct led_classdev	led_cdev;
	struct spi_device	*spidev;
	char			name[sizeof("thine350x_addre_id")];
	int			id;
	struct work_struct	work;
};

struct thine350xleds {
	struct thine350x_led	led[THINE_350X_LEDS_COUNT];
	struct mutex		mutex;
	unsigned int		address;
};

static enum led_brightness thine350x_get_brightness
				(struct led_classdev *ledcdev)
{
	return ledcdev->brightness;
}

static void thine350x_work(struct work_struct *work)
{
	struct thine350x_led *led = container_of(work,
					struct thine350x_led, work);
	struct spi_device *spi =
			(struct spi_device *)led->led_cdev.dev->parent;
	struct thine350xleds *leds = spi_get_drvdata(spi);
	unsigned char data[THINE_350x_LED_COM_BYTE_COUNT];
	int ret;
	/*Individual LEDs are addressed starting with index 1 in 350x chip,
	* but data structure uses LED index starting from 0.
	* So +1 is added while referring to LED index
	*/

	data[0] = (unsigned char)leds->address;
	data[1] = (unsigned char)led->id+1;
	data[2] = (unsigned char)led->led_cdev.brightness;
	ret = spi_write(spi, data, THINE_350x_LED_COM_BYTE_COUNT);
	if (ret != 0)
		dev_err(led->led_cdev.dev, "Error writing to SPI slave\n");
}

static void thine350x_set_brightness(struct led_classdev *ledcdev,
					enum led_brightness brightness)
{
	struct thine350x_led *led = container_of(ledcdev,
				struct thine350x_led, led_cdev);

	schedule_work(&led->work);
}

static int thine350x_probe(struct spi_device *spi)
{
	struct thine350xleds *leds;
	int led_i, ret, init_bright;
	unsigned char data[3+THINE_350X_LEDS_COUNT];
	struct device_node *np = spi->dev.of_node;

	leds = devm_kzalloc(&spi->dev, sizeof(struct thine350xleds),
				GFP_KERNEL);
	if (!leds)
		return -ENOMEM;
	mutex_init(&leds->mutex);

	/*If dev_address node is not present use default address*/
	if (of_property_read_u32(np, "dev_address", &leds->address))
		leds->address = THINE_350X_DEF_ADDRESS;

	if (of_property_read_u32(np, "init_brightness", &init_bright))
		init_bright = THINE_350X_DEF_INIT_BRIGHT;

	for (led_i = 0; led_i < THINE_350X_LEDS_COUNT; led_i++)	{
		leds->led[led_i].id = led_i;
		leds->led[led_i].spidev = spi;
		INIT_WORK(&leds->led[led_i].work, thine350x_work);
		/*Individual LEDs are named starting with index 1,
		* but data structure uses LED index starting from 0.
		* So +1 is added while referring to LED index
		*/
		snprintf(leds->led[led_i].name,
			sizeof("thine350x_addre_id"), "thine350x_%d_%d",
				leds->address, led_i+1);
		leds->led[led_i].led_cdev.name = leds->led[led_i].name;
		leds->led[led_i].led_cdev.max_brightness = 0xff;
		leds->led[led_i].led_cdev.brightness = LED_OFF;
		leds->led[led_i].led_cdev.brightness_get =
					thine350x_get_brightness;
		leds->led[led_i].led_cdev.brightness_set =
					thine350x_set_brightness;
		ret = led_classdev_register(&spi->dev,
					&leds->led[led_i].led_cdev);
		if (ret < 0)
			goto err;
	}
	spi_set_drvdata(spi, leds);
	/*Setup SPI bus*/
	spi->bits_per_word = 8;
	spi->mode = SPI_MODE_0;
	ret = spi_setup(spi);
	if (ret)
		return ret;

	/*Configure LED output enable without initial brightness*/
	data[0] = leds->address;/*slave address*/
	data[1] = 0;/*register address*/
	data[2] = THINE_350X_MAX_BASE_BRIGHT;
	for (led_i = 0; led_i < THINE_350X_LEDS_COUNT; led_i++)
		data[THINE_350x_LED_CTRL_BYTE_COUNT+led_i] =
					(unsigned char)init_bright;
	ret = spi_write(spi, data,
		THINE_350X_LEDS_COUNT + THINE_350x_LED_CTRL_BYTE_COUNT);
	return ret;

err:
	while (led_i--)
		led_classdev_unregister(&leds->led[led_i].led_cdev);
	return ret;
}

static int thine350x_remove(struct spi_device *spi)
{
	struct thine350xleds *leds = spi_get_drvdata(spi);
	int led_i;

	for (led_i = 0; led_i < THINE_350X_LEDS_COUNT; led_i++)
		led_classdev_unregister(&leds->led[led_i].led_cdev);
	return 0;
}

static struct spi_driver thine350x_driver = {
	.probe = thine350x_probe,
	.remove = thine350x_remove,
	.driver = {
		.name = "thine350x",
	},
};
module_spi_driver(thine350x_driver);

MODULE_AUTHOR("Vishruth Jain <vishruthj@nvidia.com");
MODULE_DESCRIPTION("THL350X LED driver");
MODULE_LICENSE("GPL v2");
