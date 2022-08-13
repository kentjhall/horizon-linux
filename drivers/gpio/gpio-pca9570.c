/*
 *  PCA9570 4 bit IO ports.
 *
 *  Copyright (C) 2017 NVIDIA CORPORATION.  All rights reserved.
 *
 *  Derived from drivers/i2c/chips/pca9539.c
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/slab.h>

struct pca9570_chip {
	struct device *dev;
	struct i2c_client *client;
	u8 current_state;
	struct gpio_chip	gpio_chip;
};

static int pca9570_gpio_read(struct i2c_client *client, u8 *val)
{
	char data;
	int ret;

	ret = i2c_master_recv(client, &data, 1);
	if (ret < 0) {
		dev_err(&client->dev, "Failed to read: %d\n", ret);
		return ret;
	};

	*val = data;

	return ret;
}

static int pca9570_gpio_write(struct i2c_client *client, u8 val)
{
	char data = val;
	int ret;

	ret = i2c_master_send(client, &data, 1);
	if (ret < 0)
		dev_err(&client->dev, "Failed to write: %d\n", ret);

	return ret;
}

static int pca9570_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct pca9570_chip *chip = gpiochip_get_data(gc);
	u8 val;
	int ret;

	ret = pca9570_gpio_read(chip->client, &val);
	if (ret < 0)
		return ret;

	return !!(val & BIT(offset));
}

static void pca9570_gpio_set(struct gpio_chip *gc, unsigned int offset,
			     int value)
{
	struct pca9570_chip *chip = gpiochip_get_data(gc);

	if (value)
		chip->current_state |= BIT(offset);
	else
		chip->current_state &= ~BIT(offset);

	pca9570_gpio_write(chip->client, chip->current_state);
}

static int pca9570_gpio_dir_input(struct gpio_chip *gc, unsigned int offset)
{
	/* No direction register to set it as input or output */
	return 0;
}

static int pca9570_gpio_dir_output(struct gpio_chip *gc, unsigned int offset,
				   int value)
{
	pca9570_gpio_set(gc, offset, value);

	return 0;
}

static int pca9570_gpio_probe(struct i2c_client *client,
			      const struct i2c_device_id *i2c_id)
{
	struct pca9570_chip *chip;
	int ret;

	chip = devm_kzalloc(&client->dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->client = client;
	chip->dev = &client->dev;

	chip->gpio_chip.label = client->name;
	chip->gpio_chip.direction_input = pca9570_gpio_dir_input;
	chip->gpio_chip.get = pca9570_gpio_get;
	chip->gpio_chip.direction_output = pca9570_gpio_dir_output;
	chip->gpio_chip.set = pca9570_gpio_set;
	chip->gpio_chip.ngpio = 4;
	chip->gpio_chip.can_sleep = 1;
	chip->gpio_chip.base = -1;
	chip->gpio_chip.of_node = client->dev.parent->of_node;

	i2c_set_clientdata(client, chip);

	ret = pca9570_gpio_read(client, &chip->current_state);
	if (ret < 0) {
		dev_err(&client->dev, "Failed to read device state: %d\n", ret);
		return ret;
	}

	ret = devm_gpiochip_add_data(chip->dev, &chip->gpio_chip, chip);
	if (ret < 0) {
		dev_err(chip->dev, "gpio_init: Failed to add PCA9570\n");
		return ret;
	}

	return 0;
}

static const struct of_device_id pca9570_dt_ids[] = {
	{ .compatible = "nxp,pca9570", },
	{ }
};
MODULE_DEVICE_TABLE(of, pca9570_dt_ids);

static const struct i2c_device_id pca9570_id[] = {
	{ "pca9570", },
	{ }
};
MODULE_DEVICE_TABLE(i2c, pca9570_id);

static struct i2c_driver pca9570_driver = {
	.driver = {
		.name	= "gpio-pca9570",
		.of_match_table = pca9570_dt_ids,

	},
	.probe		= pca9570_gpio_probe,
	.id_table	= pca9570_id,
};

module_i2c_driver(pca9570_driver);

MODULE_AUTHOR("Laxman Dewangan <ldewangan@nvidia.com");
MODULE_DESCRIPTION("GPIO expander driver for PCA9570");
MODULE_LICENSE("GPL v2");
