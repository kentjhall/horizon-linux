/*
 * TI LP88XX I2C Backlight Driver
 *
 * Copyright 2016 Texas Instruments
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/i2c.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "lp88xx.h"

#define LP88XX_SLAVE1_OFFSET		1
#define LP88XX_SLAVE2_OFFSET		2
#define LP88XX_SLAVE3_OFFSET		3
#define LP88XX_NUM_SLAVES		4

struct lp88xx_i2c {
	struct i2c_client *client[LP88XX_NUM_SLAVES];
};

static struct i2c_client *lp88xx_get_client(struct lp88xx_i2c *lpi2c,
					    unsigned int reg)
{
	switch (reg) {
	case 0 ... 0xff:
		return lpi2c->client[0];
	case 0x100 ... 0x1ff:
		return lpi2c->client[1];
	case 0x200 ... 0x2ff:
		return lpi2c->client[2];
	case 0x300 ... 0x3ff:
		return lpi2c->client[3];
	default:
		return NULL;
	}
}

static int lp88xx_reg_read(void *p, u16 reg, u16 *val)
{
	struct lp88xx_i2c *lpi2c = p;
	struct i2c_client *cl = lp88xx_get_client(lpi2c, reg);
	int ret;

	if (!cl)
		return -EINVAL;

	ret = i2c_smbus_read_word_data(cl, (u8)reg);
	if (ret < 0)
		return ret;

	*val = (u16)ret;

	return 0;
}

static int lp88xx_reg_write(void *p, u16 reg, u16 val)
{
	struct lp88xx_i2c *lpi2c = p;
	struct i2c_client *cl = lp88xx_get_client(lpi2c, reg);

	if (!cl)
		return -EINVAL;

	return i2c_smbus_write_word_data(cl, (u8)reg, val);
}

static int lp88xx_add_slave(struct i2c_client *cl)
{
	struct lp88xx_i2c *lpi2c = i2c_get_clientdata(cl);
	struct i2c_client *client;
	struct i2c_board_info info[] = {
		{
			I2C_BOARD_INFO("lp88xx-bl",
				cl->addr + LP88XX_SLAVE1_OFFSET),
		},
		{
			I2C_BOARD_INFO("lp88xx-bl",
				cl->addr + LP88XX_SLAVE2_OFFSET),
		},
		{
			I2C_BOARD_INFO("lp88xx-bl",
				cl->addr + LP88XX_SLAVE3_OFFSET),
		},
	};
	int index = 0;

	for (index = 0; index < (LP88XX_NUM_SLAVES - 1); index++) {

		client = i2c_new_device(cl->adapter, &info[index]);
		if (!client)
			return -ENODEV;

		lpi2c->client[index + LP88XX_SLAVE1_OFFSET] = client;

	}
	return 0;
}

static int lp88xx_probe(struct i2c_client *cl, const struct i2c_device_id *id)
{
	struct lp88xx *lp;
	struct lp88xx_i2c *lpi2c;
	struct device *dev = &cl->dev;
	int ret;

	if (!i2c_check_functionality(cl->adapter, I2C_FUNC_SMBUS_I2C_BLOCK))
		return -EIO;

	lp = devm_kzalloc(dev, sizeof(*lp), GFP_KERNEL);
	if (!lp)
		return -ENOMEM;

	lpi2c = devm_kzalloc(dev, sizeof(*lpi2c), GFP_KERNEL);
	if (!lpi2c)
		return -ENOMEM;

	lp->dev = &cl->dev;
	lp->priv = lpi2c;
	lp->io.write = lp88xx_reg_write;
	lp->io.read  = lp88xx_reg_read;

	i2c_set_clientdata(cl, lpi2c);

	/* LP88xx device has multiple I2C slave addresses */
	lpi2c->client[0] = cl;
	ret = lp88xx_add_slave(cl);
	if (ret) {
		dev_err(dev, "Failed to add I2C slave device: %d\n", ret);
		return ret;
	}

	return lp88xx_common_probe(dev, lp);
}

static const struct of_device_id lp88xx_dt_ids[] = {
	{ .compatible = "ti,lp8580", },
	{ .compatible = "ti,lp8863", },
	{ .compatible = "ti,lp8880", },
	{ }
};
MODULE_DEVICE_TABLE(of, lp88xx_dt_ids);

static const struct i2c_device_id lp88xx_ids[] = {
	{ "lp88xx", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, lp88xx_ids);

static struct i2c_driver lp88xx_driver = {
	.driver = {
		.name = "lp88xx",
		.of_match_table = of_match_ptr(lp88xx_dt_ids),
	},
	.probe = lp88xx_probe,
	.id_table = lp88xx_ids,
};
module_i2c_driver(lp88xx_driver);

MODULE_DESCRIPTION("Texas Instruments LP88XX I2C Backlight driver");
MODULE_AUTHOR("Milo Kim <milo.kim@ti.com>");
MODULE_LICENSE("GPL v2");
