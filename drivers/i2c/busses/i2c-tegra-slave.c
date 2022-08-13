/*
 * NVIDIA tegra i2c slave driver
 *
 * Copyright (C) 2017-2019, NVIDIA CORPORATION. All rights reserved.
 *
 * Author: Shardar Shariff Md <smohammed@nvidia.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any kind,
 * whether express or implied; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/clk.h>
#include <linux/reset.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/iopoll.h>

#define I2C_SL_CNFG				0x20
#define I2C_SL_CNFG_ENABLE_SL			BIT(3)
#define I2C_SL_CNFG_NEW_SL			BIT(2)

#define I2C_SL_RCVD				0x24

#define I2C_SL_STATUS				0x28
#define I2C_SL_STATUS_END_TRANS			BIT(4)
#define I2C_SL_STATUS_SL_IRQ			BIT(3)
#define I2C_SL_STATUS_RCVD			BIT(2)
#define I2C_SL_STATUS_RNW			BIT(1)

#define I2C_SL_ADDR1				0x2c
#define I2C_SL_ADDR2				0x30
#define I2C_SL_ADDR2_MASK			0x1FFFF
#define I2C_7BIT_ADDR_MASK                      0x7F

#define I2C_TLOW_SEXT				0x34
#define I2C_SL_DELAY_COUNT			0x3c
#define I2C_SL_DELAY_COUNT_RESET		0x1e

#define I2C_SL_INT_MASK				0x40
#define I2C_SL_INT_SOURCE			0x44

#define I2C_SL_INT_SET				0x48
#define I2C_FIFO_CONTROL			0x5c

#define I2C_INTERRUPT_MASK_REGISTER		0x64
#define I2C_INTERRUPT_STATUS_REGISTER		0x68
#define I2C_INTERRUPT_SOURCE_REGISTER		0x70
#define I2C_INTERRUPT_SLV_WR2RD			BIT(26)
#define I2C_INTERRUPT_SET_REGISTER		0x74

#define I2C_CONFIG_LOAD				0x8c
#define I2C_TIMEOUT_CONFIG_LOAD			BIT(2)
#define I2C_CONFIG_LOAD_SLV			BIT(1)
#define I2C_CONFIG_LOAD_TIMEOUT			1000000

#define I2C_CLKEN_OVERRIDE			0x90
#define I2C_DEBUG_CONTROL			0xa4

struct tegra_i2cslv_dev {
	struct device *dev;
	struct i2c_adapter adap;
	struct clk *div_clk;
	struct reset_control *rstc;
	void __iomem *base;
	struct i2c_client *slave;
	raw_spinlock_t xfer_lock;
};

static inline u32 tegra_i2cslv_readl(struct tegra_i2cslv_dev *i2cslv_dev,
				     unsigned long reg)
{
	return readl(i2cslv_dev->base + reg);
}

static inline void tegra_i2cslv_writel(struct tegra_i2cslv_dev *i2cslv_dev,
				       unsigned long val, unsigned long reg)
{
	writel(val, i2cslv_dev->base + reg);
}

static void tegra_i2cslv_dump_reg(struct tegra_i2cslv_dev *i2cslv_dev)
{
	dev_warn(i2cslv_dev->dev, "I2C_I2C_SL_INT_SOURCE_0 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_SL_INT_SOURCE));
	dev_warn(i2cslv_dev->dev, "I2C_INTERRUPT_STATUS_REGISTER_0 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_INTERRUPT_STATUS_REGISTER));
	dev_warn(i2cslv_dev->dev, "I2C_I2C_SL_STATUS_0 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_SL_STATUS));
	dev_warn(i2cslv_dev->dev, "I2C_INTERRUPT_SOURCE_REGISTER 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_INTERRUPT_SOURCE_REGISTER));
	dev_warn(i2cslv_dev->dev, "I2C_I2C_SL_CNFG_0 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_SL_CNFG));
	dev_warn(i2cslv_dev->dev, "I2C_SL_ADDR1 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_SL_ADDR1));
	dev_warn(i2cslv_dev->dev, "I2C_INTERRUPT_MASK_REGISTER_0 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_INTERRUPT_MASK_REGISTER));
	dev_warn(i2cslv_dev->dev, "I2C_I2C_SL_INT_MASK_0 0x%x\n",
		 tegra_i2cslv_readl(i2cslv_dev, I2C_SL_INT_MASK));
}

static int tegra_i2cslv_load_config(struct tegra_i2cslv_dev *i2cslv_dev)
{
	u32 i2c_load_config_reg;
	u32 val;
	int ret = 0;

	i2c_load_config_reg = tegra_i2cslv_readl(i2cslv_dev, I2C_CONFIG_LOAD);
	i2c_load_config_reg |= I2C_CONFIG_LOAD_SLV;
	tegra_i2cslv_writel(i2cslv_dev, i2c_load_config_reg, I2C_CONFIG_LOAD);

	if (in_interrupt())
		ret = readl_poll_timeout_atomic(i2cslv_dev->base +
				I2C_CONFIG_LOAD, val,
				!(val & I2C_CONFIG_LOAD_SLV),
				1000, I2C_CONFIG_LOAD_TIMEOUT);
	else
		ret = readl_poll_timeout(i2cslv_dev->base + I2C_CONFIG_LOAD,
				val, !(val & I2C_CONFIG_LOAD_SLV),
				1000, I2C_CONFIG_LOAD_TIMEOUT);
	if (ret) {
		dev_err(i2cslv_dev->dev, "ERR unable to load i2cslv config\n");
		return ret;
	}

	return 0;
}

/* tegra_i2cslv_handle_rx - To get the data byte from bus and provide the
 *			    data to client driver
 */
static void tegra_i2cslv_handle_rx(struct tegra_i2cslv_dev *i2cslv_dev,
		const unsigned long i2c_int_src,
		const unsigned long i2c_slv_src)
{
	u8 value;
	struct i2c_slave_data data;

	data.buf = &value;
	data.size = sizeof(value);

	if (i2c_slv_src & I2C_SL_STATUS_END_TRANS) {
		/* clear the interrupts to release the SCL line */
		tegra_i2cslv_writel(i2cslv_dev, I2C_SL_STATUS_END_TRANS |
				    I2C_SL_STATUS_SL_IRQ, I2C_SL_STATUS);
		i2c_slave_event(i2cslv_dev->slave, I2C_SLAVE_STOP, &data);
		return;
	}

	value = (unsigned char)tegra_i2cslv_readl(i2cslv_dev, I2C_SL_RCVD);
	/* Send the received data to client driver */
	i2c_slave_event(i2cslv_dev->slave, I2C_SLAVE_WRITE_RECEIVED, &data);
	/* clear the interrupt to release the SCL line */
	tegra_i2cslv_writel(i2cslv_dev, I2C_SL_STATUS_SL_IRQ, I2C_SL_STATUS);
}

/* tegra_i2cslv_handle_tx - To get the data byte fron client driver and
 *			    send it to master over bus.
 */
static void tegra_i2cslv_handle_tx(struct tegra_i2cslv_dev *i2cslv_dev,
		const unsigned long i2c_int_src,
		const unsigned long i2c_slv_src)
{
	u8 value;
	struct i2c_slave_data data;

	data.buf = &value;
	data.size = sizeof(value);

	if (i2c_slv_src & I2C_SL_STATUS_END_TRANS) {
		/* clear the interrupt to release the SCL line */
		tegra_i2cslv_writel(i2cslv_dev, I2C_SL_STATUS_END_TRANS |
				    I2C_SL_STATUS_SL_IRQ, I2C_SL_STATUS);
		i2c_slave_event(i2cslv_dev->slave, I2C_SLAVE_STOP, &data);
		return;
	}
	/* clear the interrupt to release the SCL line */
	tegra_i2cslv_writel(i2cslv_dev, I2C_SL_STATUS_SL_IRQ, I2C_SL_STATUS);
	/* Get the data byte from client driver*/
	i2c_slave_event(i2cslv_dev->slave, I2C_SLAVE_READ_REQUESTED, &data);
	tegra_i2cslv_writel(i2cslv_dev, value, I2C_SL_RCVD);
}

static int tegra_i2cslv_init(struct tegra_i2cslv_dev *i2cslv_dev)
{
	u32 reg;

	/* Reset the controller */
	reset_control_assert(i2cslv_dev->rstc);
	udelay(2);
	reset_control_deassert(i2cslv_dev->rstc);

	/* Program the 7-bit slave address */
	tegra_i2cslv_writel(i2cslv_dev, i2cslv_dev->slave->addr &
			    I2C_7BIT_ADDR_MASK, I2C_SL_ADDR1);

	/* Specify its 7-bit address mode */
	reg = tegra_i2cslv_readl(i2cslv_dev, I2C_SL_ADDR2);
	reg &= ~(I2C_SL_ADDR2_MASK);
	tegra_i2cslv_writel(i2cslv_dev, reg, I2C_SL_ADDR2);

	/* Unmask WR2RD interrupt, just to clear it */
	tegra_i2cslv_writel(i2cslv_dev, (I2C_INTERRUPT_SLV_WR2RD),
			    I2C_INTERRUPT_MASK_REGISTER);

	tegra_i2cslv_writel(i2cslv_dev, (I2C_SL_STATUS_END_TRANS |
			    I2C_SL_STATUS_SL_IRQ | I2C_SL_STATUS_RCVD),
			    I2C_SL_INT_MASK);

	reg = tegra_i2cslv_readl(i2cslv_dev, I2C_SL_CNFG);
	reg |= (I2C_SL_CNFG_NEW_SL | I2C_SL_CNFG_ENABLE_SL);
	tegra_i2cslv_writel(i2cslv_dev, reg, I2C_SL_CNFG);

	return tegra_i2cslv_load_config(i2cslv_dev);
}

static void tegra_i2cslv_deinit(struct tegra_i2cslv_dev *i2cslv_dev)
{
	tegra_i2cslv_writel(i2cslv_dev, 0, I2C_INTERRUPT_MASK_REGISTER);
	tegra_i2cslv_writel(i2cslv_dev, 0, I2C_SL_INT_MASK);
	clk_disable(i2cslv_dev->div_clk);
}

static irqreturn_t tegra_i2cslv_isr(int irq, void *dev_id)
{
	struct tegra_i2cslv_dev *i2cslv_dev = dev_id;
	u32 i2c_int_src;
	u32 i2c_slv_int_src;
	u32 i2c_slv_sts;
	u8 value;
	unsigned long flags;
	struct i2c_slave_data data;

	data.buf = &value;
	data.size = sizeof(value);

	raw_spin_lock_irqsave(&i2cslv_dev->xfer_lock, flags);
	i2c_int_src = tegra_i2cslv_readl(i2cslv_dev,
					 I2C_INTERRUPT_SOURCE_REGISTER);
	i2c_slv_int_src = tegra_i2cslv_readl(i2cslv_dev, I2C_SL_INT_SOURCE);
	i2c_slv_sts = tegra_i2cslv_readl(i2cslv_dev, I2C_SL_STATUS);

	/* Address received */
	if ((i2c_slv_int_src & I2C_SL_STATUS_SL_IRQ) &&
			(i2c_slv_int_src & I2C_SL_STATUS_RCVD)) {
		/* End of transfer of previous transaction, just clear it */
		if (i2c_slv_int_src & I2C_SL_STATUS_END_TRANS) {
			i2c_slave_event(i2cslv_dev->slave, I2C_SLAVE_STOP,
					&data);
			tegra_i2cslv_writel(i2cslv_dev, I2C_SL_STATUS_END_TRANS,
					    I2C_SL_STATUS);
		}
		/* Clear the interrupt */
		tegra_i2cslv_writel(i2cslv_dev, I2C_SL_STATUS_SL_IRQ |
				    I2C_SL_STATUS_RCVD, I2C_SL_STATUS);
		/* if RNW, master issued read. */
		if (i2c_slv_sts & I2C_SL_STATUS_RNW) {
			i2c_slave_event(i2cslv_dev->slave,
					I2C_SLAVE_READ_REQUESTED, &data);
			tegra_i2cslv_writel(i2cslv_dev, value,
					    I2C_SL_RCVD);
		} else {
			i2c_slave_event(i2cslv_dev->slave,
					I2C_SLAVE_WRITE_REQUESTED, &data);
		}
		goto done;
	}
	if (unlikely(i2c_int_src & I2C_INTERRUPT_SLV_WR2RD)) {
		/* Clear WR2RD interrupt */
		tegra_i2cslv_writel(i2cslv_dev, I2C_INTERRUPT_SLV_WR2RD,
				    I2C_INTERRUPT_STATUS_REGISTER);
		goto done;
	}

	if ((i2c_slv_int_src & I2C_SL_STATUS_SL_IRQ)) {
		if (!(i2c_slv_sts & I2C_SL_STATUS_RNW)) {
			/* Master write and Slave receive */
			tegra_i2cslv_handle_rx(i2cslv_dev, i2c_int_src,
					i2c_slv_int_src);
			goto done;
		} else if (i2c_slv_sts & I2C_SL_STATUS_RNW) {
			/* Master read and slave write */
			tegra_i2cslv_handle_tx(i2cslv_dev, i2c_int_src,
					i2c_slv_int_src);
			goto done;
		}
	} else {
		dev_err(i2cslv_dev->dev, "Slave IRQ not set\n");
		goto err;
	}
err:
	tegra_i2cslv_dump_reg(i2cslv_dev);
	tegra_i2cslv_init(i2cslv_dev);
done:
	raw_spin_unlock_irqrestore(&i2cslv_dev->xfer_lock, flags);
	return IRQ_HANDLED;
}

static int tegra_reg_slave(struct i2c_client *slave)
{
	struct tegra_i2cslv_dev *i2cslv_dev =
		i2c_get_adapdata(slave->adapter);
	int ret;

	if (i2cslv_dev->slave)
		return -EBUSY;

	if (slave->flags & I2C_CLIENT_TEN)
		return -EAFNOSUPPORT;
	i2cslv_dev->slave = slave;

	ret = clk_enable(i2cslv_dev->div_clk);
	if (ret < 0) {
		dev_err(i2cslv_dev->dev, "Enable div-clk failed: %d\n", ret);
		return ret;
	}

	return tegra_i2cslv_init(i2cslv_dev);
}

static int tegra_unreg_slave(struct i2c_client *slave)
{
	struct tegra_i2cslv_dev *i2cslv_dev =
		i2c_get_adapdata(slave->adapter);

	WARN_ON(!i2cslv_dev->slave);
	tegra_i2cslv_deinit(i2cslv_dev);

	return 0;
}

static u32 tegra_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SLAVE;
}

static const struct i2c_algorithm tegra_i2cslv_algo = {
	.functionality  = tegra_i2c_func,
	.reg_slave      = tegra_reg_slave,
	.unreg_slave    = tegra_unreg_slave,
};

static int tegra_i2cslv_probe(struct platform_device *pdev)
{
	struct tegra_i2cslv_dev *i2cslv_dev;
	struct i2c_adapter *adap;
	struct resource *res;
	phys_addr_t phys_addr;
	void __iomem *base;
	struct clk *div_clk;
	struct reset_control *rstc;
	int irq, ret;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "No IO memory resource\n");
		return -ENODEV;
	}
	phys_addr = res->start;
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!res) {
		dev_err(&pdev->dev, "no irq resource\n");
		return -EINVAL;
	}
	irq = res->start;

	div_clk = devm_clk_get(&pdev->dev, "div-clk");
	if (IS_ERR(div_clk)) {
		dev_err(&pdev->dev, "missing controller clock");
		return PTR_ERR(div_clk);
	}

	rstc = devm_reset_control_get(&pdev->dev, "i2c");
	if (IS_ERR(rstc)) {
		ret = PTR_ERR(rstc);
		dev_err(&pdev->dev, "Reset control is not found: %d\n", ret);
		return ret;
	}

	i2cslv_dev = devm_kzalloc(&pdev->dev, sizeof(*i2cslv_dev), GFP_KERNEL);
	if (!i2cslv_dev)
		return -ENOMEM;

	i2cslv_dev->dev = &pdev->dev;
	i2cslv_dev->base = base;
	i2cslv_dev->div_clk = div_clk;
	i2cslv_dev->rstc = rstc;
	raw_spin_lock_init(&i2cslv_dev->xfer_lock);

	adap = &i2cslv_dev->adap;
	adap->algo = &tegra_i2cslv_algo;
	adap->class = I2C_CLASS_DEPRECATED;
	adap->dev.parent = &pdev->dev;
	adap->dev.of_node = pdev->dev.of_node;
	i2c_set_adapdata(adap, i2cslv_dev);
	platform_set_drvdata(pdev, i2cslv_dev);
	strlcpy(adap->name, pdev->name, sizeof(adap->name));

	ret = clk_prepare(i2cslv_dev->div_clk);
	if (ret < 0) {
		dev_err(i2cslv_dev->dev, "clock prepare failed %d\n", ret);
		return ret;
	}

	ret = devm_request_irq(&pdev->dev, irq, tegra_i2cslv_isr,
			       0, dev_name(&pdev->dev), i2cslv_dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to register ISR for IRQ %d\n", irq);
		return ret;
	}

	ret = i2c_add_adapter(&i2cslv_dev->adap);
	if (ret) {
		dev_err(&pdev->dev, "Failed to add I2C adapter\n");
		return ret;
	}

	return 0;
}

static int tegra_i2cslv_remove(struct platform_device *pdev)
{
	struct tegra_i2cslv_dev *i2cslv_dev = platform_get_drvdata(pdev);

	i2c_del_adapter(&i2cslv_dev->adap);
	return 0;
}

static int tegra_i2cslv_suspend(struct device *dev)
{
	struct tegra_i2cslv_dev *i2cslv_dev = dev_get_drvdata(dev);
	unsigned long flags;

	raw_spin_lock_irqsave(&i2cslv_dev->xfer_lock, flags);

	tegra_i2cslv_deinit(i2cslv_dev);

	raw_spin_unlock_irqrestore(&i2cslv_dev->xfer_lock, flags);

	return 0;
}

static int tegra_i2cslv_resume(struct device *dev)
{
	struct tegra_i2cslv_dev *i2cslv_dev = dev_get_drvdata(dev);
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&i2cslv_dev->xfer_lock, flags);

	ret = clk_enable(i2cslv_dev->div_clk);
	if (ret < 0) {
		dev_err(i2cslv_dev->dev, "Enable div-clk failed: %d\n", ret);
		return ret;
	}
	ret = tegra_i2cslv_init(i2cslv_dev);
	if (ret)
		return ret;

	raw_spin_unlock_irqrestore(&i2cslv_dev->xfer_lock, flags);

	return 0;
}

static const struct dev_pm_ops tegra_i2cslv_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(tegra_i2cslv_suspend, tegra_i2cslv_resume)
};

static const struct of_device_id tegra_i2cslv_of_match[] = {
	{.compatible = "nvidia,tegra210-i2c-slave",},
	{}
};

MODULE_DEVICE_TABLE(of, tegra_i2cslv_of_match);

static struct platform_driver tegra_i2cslv_driver = {
	.probe = tegra_i2cslv_probe,
	.remove = tegra_i2cslv_remove,
	.driver = {
		   .name = "tegra-i2cslv",
		   .owner = THIS_MODULE,
		   .of_match_table = of_match_ptr(tegra_i2cslv_of_match),
		   .pm = &tegra_i2cslv_pm_ops,
		   },
};

module_platform_driver(tegra_i2cslv_driver);

MODULE_AUTHOR("Shardar Shariff Md <smohammed@nvidia.com>");
MODULE_DESCRIPTION("NVIDIA Tegra I2C slave driver");
MODULE_LICENSE("GPL v2");
