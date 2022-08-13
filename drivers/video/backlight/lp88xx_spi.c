/*
 * TI LP88XX SPI Backlight Driver
 *
 * Copyright 2016 Texas Instruments
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>

#include "lp88xx.h"

#define LP88XX_SPI_READ(reg)		((reg << 1) & 0x7ffe)
#define LP88XX_SPI_WRITE(reg)		((reg << 1) | BIT(0))

static int lp88xx_reg_read(void *p, u16 reg, u16 *val)
{
	struct spi_device *spi = p;
	u16 cmd = LP88XX_SPI_READ(reg);

	return spi_write_then_read(spi, &cmd, 2, val, 2);
}

static int lp88xx_reg_write(void *p, u16 reg, u16 val)
{
	struct spi_device *spi = p;
	u16 cmd[2];

	cmd[0] = LP88XX_SPI_WRITE(reg);
	cmd[1] = val;

	return spi_write(spi, (const u16 *)&cmd, 4);
}

static int lp88xx_probe(struct spi_device *spi)
{
	struct lp88xx *lp;
	struct device *dev = &spi->dev;
	int ret;

	lp = devm_kzalloc(dev, sizeof(struct lp88xx), GFP_KERNEL);
	if (!lp)
		return -ENOMEM;

	lp->dev = dev;
	lp->priv = spi;
	lp->io.write = lp88xx_reg_write;
	lp->io.read  = lp88xx_reg_read;

	spi_set_drvdata(spi, lp);

	spi->bits_per_word = 16;
	ret = spi_setup(spi);
	if (ret) {
		dev_err(dev, "Failed to setup SPI: %d\n", ret);
		return ret;
	}

	return lp88xx_common_probe(dev, lp);
}

static const struct of_device_id lp88xx_dt_ids[] = {
	{ .compatible = "ti,lp8580", },
	{ .compatible = "ti,lp8880", },
	{ }
};
MODULE_DEVICE_TABLE(of, lp88xx_dt_ids);

static const struct spi_device_id lp88xx_ids[] = {
	{ "lp88xx", 0 },
	{ }
};
MODULE_DEVICE_TABLE(spi, lp88xx_ids);

static struct spi_driver lp88xx_driver = {
	.driver = {
		.name = "lp88xx",
		.of_match_table = of_match_ptr(lp88xx_dt_ids),
	},
	.probe = lp88xx_probe,
	.id_table = lp88xx_ids,
};
module_spi_driver(lp88xx_driver);

MODULE_DESCRIPTION("Texas Instruments LP88XX SPI Backlight driver");
MODULE_AUTHOR("Milo Kim <milo.kim@ti.com>");
MODULE_LICENSE("GPL v2");
