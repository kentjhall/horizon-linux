/*
 * QSPI driver for NVIDIA's Tegra210 QUAD SPI Controller.
 *
 * Copyright (c) 2013-2021, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/spi/spi.h>
#include <linux/spi/qspi-tegra.h>
#include <linux/tegra_prod.h>

#define QSPI_COMMAND1				0x000
#define QSPI_BIT_LENGTH(x)			(((x) & 0x1f) << 0)
#define QSPI_PACKED				BIT(5)
#define QSPI_INTERFACE_WIDTH(x)			(((x) & 0x03) << 7)
#define QSPI_INTERFACE_WIDTH_MASK		(0x03 << 7)
#define QSPI_SDR_DDR_SEL			BIT(9)
#define QSPI_TX_EN				BIT(11)
#define QSPI_RX_EN				BIT(12)
#define QSPI_CS_SW_VAL				BIT(20)
#define QSPI_CS_SW_HW				BIT(21)
#define QSPI_CONTROL_MODE_0			(0 << 28)
#define QSPI_CONTROL_MODE_3			(3 << 28)
#define QSPI_CONTROL_MODE_MASK			(3 << 28)
#define QSPI_M_S				BIT(30)
#define QSPI_PIO				BIT(31)

#define QSPI_COMMAND2				0x004
#define QSPI_RX_TAP_DELAY(x)			(((x) & 0xFF) << 0)
#define QSPI_TX_TAP_DELAY(x)			(((x) & 0x1F) << 10)
#define QSPI_RX_EXT_TAP_DELAY(x)		(((x) & 0xFF) << 24)

#define QSPI_SETUP_HOLD(setup, hold)		\
		(((setup) << 4) | ((hold) & 0x0F))
#define QSPI_CS_SETUP_HOLD(reg, cs, val)			\
		((((val) & 0xFFu) << ((cs) * 8)) |	\
		((reg) & ~(0xFFu << ((cs) * 8))))

#define QSPI_CS_TIMING1				0x008
#define QSPI_CS_TIMING2				0x00C
#define QSPI_CS_TIMING3				0x198

#define CYCLES_BETWEEN_PACKETS_0(x)		(((x) & 0x1F) << 0)
#define CS_ACTIVE_BETWEEN_PACKETS_0             BIT(5)
#define QSPI_SET_CYCLES_BETWEEN_PACKETS(reg, cs, val)		\
		(reg = (((val) & 0xF) << ((cs) * 8)) |		\
			((reg) & ~(0xF << ((cs) * 8))))

#define QSPI_HALF_FULL_CYCLE_SAMPLE		BIT(31)

#define QSPI_TRANS_STATUS			0x010
#define QSPI_BLK_CNT(val)			(((val) >> 0) & 0xFFFF)
#define QSPI_RDY				BIT(30)

#define QSPI_FIFO_STATUS			0x014
#define QSPI_RX_FIFO_EMPTY			BIT(0)
#define QSPI_RX_FIFO_FULL			BIT(1)
#define QSPI_TX_FIFO_EMPTY			BIT(2)
#define QSPI_TX_FIFO_FULL			BIT(3)
#define QSPI_RX_FIFO_UNF			BIT(4)
#define QSPI_RX_FIFO_OVF			BIT(5)
#define QSPI_TX_FIFO_UNF			BIT(6)
#define QSPI_TX_FIFO_OVF			BIT(7)
#define QSPI_ERR				BIT(8)
#define QSPI_TX_FIFO_FLUSH			BIT(14)
#define QSPI_RX_FIFO_FLUSH			BIT(15)
#define QSPI_TX_FIFO_EMPTY_COUNT(val)		(((val) >> 16) & 0x7F)
#define QSPI_RX_FIFO_FULL_COUNT(val)		(((val) >> 23) & 0x7F)

#define QSPI_FIFO_ERROR				(QSPI_RX_FIFO_UNF | \
			QSPI_RX_FIFO_OVF | QSPI_TX_FIFO_UNF | QSPI_TX_FIFO_OVF)
#define QSPI_FIFO_EMPTY			(QSPI_RX_FIFO_EMPTY | \
						QSPI_TX_FIFO_EMPTY)

#define QSPI_TX_DATA				0x018

#define QSPI_MISC_REG                           0x194
#define QSPI_NUM_DUMMY_CYCLE(x)			(((x) & 0xFF) << 0)

#define QSPI_GLOBAL_CONFIG                      0x1a4

#define QSPI_RX_DATA				0x01C

#define QSPI_DMA_CTL				0x020
#define QSPI_TX_TRIG(n)				(((n) & 0x3) << 15)
#define QSPI_TX_TRIG_1				QSPI_TX_TRIG(0)
#define QSPI_TX_TRIG_4				QSPI_TX_TRIG(1)
#define QSPI_TX_TRIG_8				QSPI_TX_TRIG(2)
#define QSPI_TX_TRIG_16				QSPI_TX_TRIG(3)

#define QSPI_RX_TRIG(n)				(((n) & 0x3) << 19)
#define QSPI_RX_TRIG_1				QSPI_RX_TRIG(0)
#define QSPI_RX_TRIG_4				QSPI_RX_TRIG(1)
#define QSPI_RX_TRIG_8				QSPI_RX_TRIG(2)
#define QSPI_RX_TRIG_16				QSPI_RX_TRIG(3)

#define QSPI_IE_TX				BIT(28)
#define QSPI_IE_RX				BIT(29)
#define QSPI_DMA				BIT(31)
#define QSPI_DMA_EN				QSPI_DMA

#define QSPI_DMA_BLK				0x024
#define QSPI_DMA_BLK_SET(x)			(((x) & 0xFFFF) << 0)

#define QSPI_TX_FIFO				0x108
#define QSPI_RX_FIFO				0x188

#define QSPI_INTR_MASK				0x18c
#define QSPI_INTR_RX_FIFO_UNF_MASK		BIT(25)
#define QSPI_INTR_RX_FIFO_OVF_MASK		BIT(26)
#define QSPI_INTR_TX_FIFO_UNF_MASK		BIT(27)
#define QSPI_INTR_TX_FIFO_OVF_MASK		BIT(28)
#define QSPI_INTR_RDY_MASK			BIT(29)

#define QSPI_INTR_RX_TX_FIFO_ERR		(QSPI_INTR_RX_FIFO_UNF_MASK | \
						 QSPI_INTR_RX_FIFO_OVF_MASK | \
						 QSPI_INTR_TX_FIFO_UNF_MASK | \
						 QSPI_INTR_TX_FIFO_OVF_MASK)

#define QSPI_CMB_SEQ_CMD			0x19c
#define QSPI_COMMAND_VALUE_SET(X)		(((x) & 0xFF) << 0)

#define QSPI_CMB_SEQ_CMD_CFG			0x1a0
#define QSPI_COMMAND_X1_X2_X4(x)		(((x) & 0x3) << 13)
#define QSPI_COMMAND_X1_X2_X4_MASK		(0x03 << 13)
#define QSPI_COMMAND_SDR_DDR			BIT(12)
#define QSPI_COMMAND_SIZE_SET(x)		(((x) & 0xFF) << 0)

#define QSPI_GLOBAL_CONFIG			0x1a4
#define QSPI_CMB_SEQ_EN				BIT(0)

#define QSPI_CMB_SEQ_ADDR			0x1a8
#define QSPI_ADDRESS_VALUE_SET(X)		(((x) & 0xFFFF) << 0)

#define QSPI_CMB_SEQ_ADDR_CFG			0x1ac
#define QSPI_ADDRESS_X1_X2_X4(x)		(((x) & 0x3) << 13)
#define QSPI_ADDRESS_X1_X2_X4_MASK		(0x03 << 13)
#define QSPI_ADDRESS_SDR_DDR			BIT(12)
#define QSPI_ADDRESS_SIZE_SET(x)		(((x) & 0xFF) << 0)

#define DATA_DIR_TX				BIT(0)
#define DATA_DIR_RX				BIT(1)

#define QSPI_DMA_TIMEOUT			(msecs_to_jiffies(10000))
#define DEFAULT_SPI_DMA_BUF_LEN			(64 * 1024)
#define TX_FIFO_EMPTY_COUNT_MAX			SPI_TX_FIFO_EMPTY_COUNT(0x40)
#define RX_FIFO_FULL_COUNT_ZERO			SPI_RX_FIFO_FULL_COUNT(0)
#define MAX_PROD_NAME                           15
/*
 * NOTE: Actual chip has only one CS. Below is WAR to enable
 * spidev and mtd layer register same time.
 */
#define MAX_CHIP_SELECT				2
#define QSPI_FIFO_DEPTH				64
#define QSPI_FIFO_FLUSH_MAX_DELAY		2000

#define CMD_TRANSFER				0
#define ADDR_TRANSFER				1
#define DATA_TRANSFER				2

static int rx_tap_delay = -1;
module_param(rx_tap_delay, int, 0444);

static int tx_tap_delay = -1;
module_param(tx_tap_delay, int, 0444);

struct tegra_qspi_data {
	struct device				*dev;
	struct spi_master			*master;
	/* Lock fro register access */
	spinlock_t				lock;

	struct clk				*clk;
	struct clk				*sdr_ddr_clk;
	struct reset_control			*rstc;
	void __iomem				*base;
	phys_addr_t				phys;
	unsigned				irq;
	bool					enable_dma_support;
	bool					clock_always_on;
	bool					is_ddr_mode;
	u8					bus_clk_div;
	u32					qspi_max_frequency;
	u32					cur_speed;

	struct spi_device			*cur_qspi;
	unsigned				cur_pos;
	unsigned				cur_len;
	unsigned				words_per_32bit;
	unsigned				bytes_per_word;
	unsigned				curr_dma_words;
	unsigned				cur_direction;

	unsigned				cur_rx_pos;
	unsigned				cur_tx_pos;

	unsigned				dma_buf_size;
	unsigned				max_buf_size;
	bool					is_curr_dma_xfer;
	bool					is_hw_based_cs;
	bool					dcycle_non_cmbseq_mode;

	struct completion			rx_dma_complete;
	struct completion			tx_dma_complete;

	u32					tx_status;
	u32					rx_status;
	u32					status_reg;
	bool					is_packed;
	unsigned long				packed_size;

	u32					command1_reg;
	u32					dma_control_reg;
	u32					def_command1_reg;
	u32					def_command2_reg;
	u32					qspi_cs_timing;

	struct completion			xfer_completion;
	struct spi_transfer			*curr_xfer;
	struct dma_chan				*rx_dma_chan;
	u32					*rx_dma_buf;
	dma_addr_t				rx_dma_phys;
	struct dma_async_tx_descriptor		*rx_dma_desc;

	struct dma_chan				*tx_dma_chan;
	u32					*tx_dma_buf;
	dma_addr_t				tx_dma_phys;
	struct dma_async_tx_descriptor		*tx_dma_desc;
	struct tegra_prod			*prod_list;
	int					qspi_enable_cmbseq_mode;
#ifdef QSPI_BRINGUP_BUILD
	int					qspi_force_unpacked_mode;
	int					qspi_enable_prod_override;
	int					qspi_force_pio_mode;
	int					qspi_force_dma_mode;
	bool					qspi_force_bus_speed;
#endif
};

static int tegra_qspi_runtime_suspend(struct device *dev);
static int tegra_qspi_runtime_resume(struct device *dev);
static int tegra_qspi_clk_enable(struct tegra_qspi_data *tqspi);
static void tegra_qspi_clk_disable(struct tegra_qspi_data *tqspi);

static struct tegra_qspi_device_controller_data
	*tegra_qspi_get_cdata_dt(struct spi_device *spi);

static void set_best_clk_source(struct tegra_qspi_data *tqspi,
				unsigned long rate);

static unsigned long tegra_qspi_readl(struct tegra_qspi_data *tqspi,
				      unsigned long reg)
{
	return readl(tqspi->base + reg);
}

static void tegra_qspi_writel(struct tegra_qspi_data *tqspi,
			      unsigned long val, unsigned long reg)
{
	writel(val, tqspi->base + reg);

	/* Read back register to make sure that register writes completed */
	if (reg != QSPI_TX_FIFO)
		readl(tqspi->base + QSPI_COMMAND1);
}

#ifdef QSPI_BRINGUP_BUILD
static ssize_t force_unpacked_mode_set(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		tqspi->qspi_force_unpacked_mode = ((buf[0] - '0')  > 0);
		return count;
	}

	return -ENODEV;
}

static ssize_t force_unpacked_mode_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	return sprintf(buf, "%d", tqspi->qspi_force_unpacked_mode);
}

static DEVICE_ATTR(qspi_force_unpacked_mode, 0644, force_unpacked_mode_show,
						force_unpacked_mode_set);

static ssize_t force_cmbseq_mode_set(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		tqspi->qspi_enable_cmbseq_mode = ((buf[0] - '0')  > 0);
		return count;
	}

	return -ENODEV;
}

static ssize_t force_cmbseq_mode_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	return sprintf(buf, "%d", tqspi->qspi_enable_cmbseq_mode);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_enable_cmbseq_mode, 0644, force_cmbseq_mode_show,
						force_cmbseq_mode_set);

static ssize_t enable_prod_override_set(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		tqspi->qspi_enable_prod_override = ((buf[0] - '0')  > 0);
		return count;
	}

	return -ENODEV;
}

static ssize_t enable_prod_override_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	return sprintf(buf, "%d\n", tqspi->qspi_enable_prod_override);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_enable_prod_override, 0644, enable_prod_override_show,
						enable_prod_override_set);

static ssize_t enable_clk_always_on_set(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		tqspi->clock_always_on = ((buf[0] - '0')  > 0);
		if (tqspi->clock_always_on)
			tegra_qspi_clk_enable(tqspi);
		else
			tegra_qspi_clk_disable(tqspi);
		return count;
	}

	return -ENODEV;
}

static ssize_t enable_clk_always_on_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	return sprintf(buf, "%d\n", tqspi->clock_always_on);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_enable_clk_always_on, 0644, enable_clk_always_on_show,
						enable_clk_always_on_set);

static ssize_t bus_speed_set(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;
	int ret = 0;
	long speed;
	u32 actual_speed;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		ret = kstrtol(buf, 10, &speed);
		if (ret != 0)
			return -EINVAL;
		if (speed == 0) {
			tqspi->qspi_force_bus_speed = false;
			return count;
		}
		if (speed > tqspi->qspi_max_frequency/tqspi->bus_clk_div)
			return -EINVAL;
		if (tqspi->cur_speed == speed)
			return count;
		tqspi->cur_speed = speed;
		set_best_clk_source(tqspi, speed);
		ret = clk_set_rate(tqspi->clk, speed*tqspi->bus_clk_div);
		if (ret < 0) {
			dev_err(tqspi->dev,
				"Failed to set QSPI clock freq: %d\n",
				ret);
			return -EINVAL;
		}
		actual_speed = clk_get_rate(tqspi->clk)/tqspi->bus_clk_div;
		if (actual_speed <= 0)
			return -EINVAL;
		ret = clk_set_rate(tqspi->sdr_ddr_clk, actual_speed);
		if (ret < 0) {
			dev_err(tqspi->dev,
				"Failed to set QSPI OUT clock freq: %d\n",
				ret);
			return -EINVAL;
		}
		tqspi->qspi_force_bus_speed = true;
		return count;
	}

	return -ENODEV;
}

static ssize_t bus_speed_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;
	u32 actual_qspi_speed;
	u32 actual_qspi_out_speed;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	actual_qspi_speed = clk_get_rate(tqspi->clk);
	actual_qspi_out_speed = clk_get_rate(tqspi->sdr_ddr_clk);

	return sprintf(buf, "qspi:%d, qspi_out:%d\n",
			actual_qspi_speed,
			actual_qspi_out_speed);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_bus_speed, 0644, bus_speed_show,
						bus_speed_set);

static ssize_t force_pio_mode_set(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		tqspi->qspi_force_pio_mode = ((buf[0] - '0')  > 0);
		return count;
	}

	return -ENODEV;
}

static ssize_t force_pio_mode_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	return sprintf(buf, "%d\n", tqspi->qspi_force_pio_mode);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_force_pio_mode, 0644, force_pio_mode_show,
						force_pio_mode_set);

static ssize_t force_dma_mode_set(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	if (tqspi && count) {
		tqspi->qspi_force_dma_mode = ((buf[0] - '0')  > 0);
		return count;
	}

	return -ENODEV;
}

static ssize_t force_dma_mode_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi;

	if (!master)
		return -ENODEV;

	tqspi = spi_master_get_devdata(master);
	return sprintf(buf, "%d\n", tqspi->qspi_force_dma_mode);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_force_dma_mode, 0644, force_dma_mode_show,
						force_dma_mode_set);

static struct attribute *tegra_qspi_attrs[] = {
	&dev_attr_qspi_force_unpacked_mode.attr,
	&dev_attr_qspi_enable_cmbseq_mode.attr,
	&dev_attr_qspi_enable_prod_override.attr,
	&dev_attr_qspi_enable_clk_always_on.attr,
	&dev_attr_qspi_bus_speed.attr,
	&dev_attr_qspi_force_pio_mode.attr,
	&dev_attr_qspi_force_dma_mode.attr,
	NULL,
};

ATTRIBUTE_GROUPS(tegra_qspi);

#endif

#ifdef QSPI_DUMP_REGISTERS
static void tegra_qspi_dump_regs(const char *heading,
				 struct tegra_qspi_data *tqspi)
{
	u32 command1_reg;
	u32 fifo_status_reg, misc_reg, gl_config_reg;
	u32 dma_ctrl_reg, dma_blk_reg, intr_mask_reg;
	u32 trans_status_reg;
	u32 cmd_config;
	u32 addr_config;
	u32 addr_value;
	u32 cmd_value;

	cmd_value = tegra_qspi_readl(tqspi, QSPI_CMB_SEQ_CMD);
	addr_value = tegra_qspi_readl(tqspi, QSPI_CMB_SEQ_ADDR);
	cmd_config = tegra_qspi_readl(tqspi, QSPI_CMB_SEQ_CMD_CFG);
	addr_config = tegra_qspi_readl(tqspi, QSPI_CMB_SEQ_ADDR_CFG);

	command1_reg = tegra_qspi_readl(tqspi, QSPI_COMMAND1);
	fifo_status_reg = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
	dma_ctrl_reg = tegra_qspi_readl(tqspi, QSPI_DMA_CTL);
	trans_status_reg = tegra_qspi_readl(tqspi, QSPI_TRANS_STATUS);
	dma_blk_reg = tegra_qspi_readl(tqspi, QSPI_DMA_BLK);
	intr_mask_reg = tegra_qspi_readl(tqspi, QSPI_INTR_MASK);
	misc_reg = tegra_qspi_readl(tqspi, QSPI_MISC_REG);
	gl_config_reg = tegra_qspi_readl(tqspi, QSPI_GLOBAL_CONFIG);

	if (heading)
		dev_info(tqspi->dev, "%s\n", heading);

	dev_err(tqspi->dev, "CMD_0: \t\t\t0x%08lx\n", command1_reg);
	dev_err(tqspi->dev, "FIFO_STS: \t\t\t0x%08x\n", fifo_status_reg);
	dev_err(tqspi->dev, "DMA_CTL: \t\t\t0x%08lx\n", dma_ctrl_reg);
	dev_err(tqspi->dev, "TRANS_STS: \t\t\t0x%08lx\n", trans_status_reg);
	dev_err(tqspi->dev, "GLOBAL_CONFIG: \t\t\t0x%08lx\n", gl_config_reg);
	dev_err(tqspi->dev, "DMA_BLK:  \t\t\t0x%08lx\n", dma_blk_reg);
	dev_err(tqspi->dev, "INTR:  \t\t\t0x%08lx\n", intr_mask_reg);
	dev_err(tqspi->dev, "MISC-REG: \t\t\t0x%08lx\n", misc_reg);
	dev_err(tqspi->dev, "CMD_VAl:  \t\t\t0x%08lx\n", cmd_value);
	dev_err(tqspi->dev, "ADR_VAL:  \t\t\t0x%08lx\n", addr_value);
	dev_err(tqspi->dev, "CMD_CFG:  \t\t\t0x%08lx\n", cmd_config);
	dev_err(tqspi->dev, "ADR_CFG:  \t\t\t0x%08lx\n", addr_config);
#else
static void tegra_qspi_dump_regs(const char *heading,
				 struct tegra_qspi_data *tqspi)
{}
#endif

static void tegra_qspi_clear_status(struct tegra_qspi_data *tqspi)
{
	unsigned long val;

	/* Write 1 to clear status register */
	val = tegra_qspi_readl(tqspi, QSPI_TRANS_STATUS);
	tegra_qspi_writel(tqspi, val, QSPI_TRANS_STATUS);

	val = tegra_qspi_readl(tqspi, QSPI_INTR_MASK);
	if (!(val & QSPI_INTR_RDY_MASK)) {
		val |= (QSPI_INTR_RDY_MASK | QSPI_INTR_RX_TX_FIFO_ERR);
		tegra_qspi_writel(tqspi, val, QSPI_INTR_MASK);
	}

	/* Clear fifo status error if any */
	val = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
	if (val & QSPI_ERR)
		tegra_qspi_writel(tqspi, QSPI_ERR | QSPI_FIFO_ERROR,
				  QSPI_FIFO_STATUS);
}

static int check_and_clear_fifo(struct tegra_qspi_data *tqspi)
{
	unsigned long status;
	int cnt = QSPI_FIFO_FLUSH_MAX_DELAY;

	/* Make sure that Rx and Tx fifo are empty */
	status = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
	if ((status & QSPI_FIFO_EMPTY) == QSPI_FIFO_EMPTY)
		return 0;

	/* flush the fifo */
	status |= (QSPI_RX_FIFO_FLUSH | QSPI_TX_FIFO_FLUSH);
	tegra_qspi_writel(tqspi, status, QSPI_FIFO_STATUS);
	do {
		status = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
		if ((status & QSPI_FIFO_EMPTY) == QSPI_FIFO_EMPTY)
			return 0;
		udelay(1);
	} while (cnt--);

	dev_err(tqspi->dev, "Failed to flush Rx/Tx fifo(status 0x%08lx)\n",
		status);

	return -EIO;
}

static unsigned tegra_qspi_calculate_curr_xfer_param(
		struct spi_device *spi, struct tegra_qspi_data *tqspi,
		struct spi_transfer *t)
{
	unsigned remain_len = t->len - tqspi->cur_pos;
	unsigned max_word;
	unsigned bits_per_word;
	unsigned max_len;
	unsigned total_fifo_words;

	bits_per_word = t->bits_per_word ? t->bits_per_word :
		spi->bits_per_word;
	tqspi->bytes_per_word = (bits_per_word - 1) / 8 + 1;

#ifdef QSPI_BRINGUP_BUILD
	if (!tqspi->qspi_force_unpacked_mode &&
	    (bits_per_word % 8 == 0) && (t->len > 3)) {
		tqspi->is_packed = true;
		tqspi->words_per_32bit = 32 / bits_per_word;
	} else {
		tqspi->is_packed = false;
		tqspi->words_per_32bit = 1;
	}
#else
	if ((bits_per_word == 8 || bits_per_word == 16) && (t->len > 3)) {
		tqspi->is_packed = true;
		tqspi->words_per_32bit = 32 / bits_per_word;
	} else {
		tqspi->is_packed = false;
		tqspi->words_per_32bit = 1;
	}
#endif
	if (tqspi->is_packed) {
		max_len = min(remain_len, tqspi->max_buf_size);
		tqspi->curr_dma_words = max_len / tqspi->bytes_per_word;
		total_fifo_words = (max_len + 3) / 4;
#ifdef QSPI_BRINGUP_BUILD
		if (tqspi->qspi_force_pio_mode)
			if (tqspi->curr_dma_words > QSPI_FIFO_DEPTH) {
				tqspi->curr_dma_words = QSPI_FIFO_DEPTH;
				total_fifo_words = QSPI_FIFO_DEPTH;
			}
#endif
	} else {
		max_word = (remain_len - 1) / tqspi->bytes_per_word + 1;
		max_word = min(max_word, tqspi->max_buf_size / 4);
		tqspi->curr_dma_words = max_word;
		total_fifo_words = max_word;
#ifdef QSPI_BRINGUP_BUILD
		if (tqspi->qspi_force_pio_mode)
			if (tqspi->curr_dma_words > QSPI_FIFO_DEPTH) {
				tqspi->curr_dma_words = QSPI_FIFO_DEPTH;
				total_fifo_words = QSPI_FIFO_DEPTH;
			}
#endif
	}

	return total_fifo_words;
}

static unsigned tegra_qspi_fill_tx_fifo_from_client_txbuf(
		struct tegra_qspi_data *tqspi, struct spi_transfer *t)
{
	unsigned nbytes;
	unsigned tx_empty_count;
	unsigned long fifo_status;
	unsigned max_n_32bit;
	unsigned i, count;
	unsigned long x;
	unsigned int written_words;
	unsigned fifo_words_left;
	u8 *tx_buf = (u8 *)t->tx_buf + tqspi->cur_tx_pos;

	fifo_status = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
	tx_empty_count = QSPI_TX_FIFO_EMPTY_COUNT(fifo_status);

	if (tqspi->is_packed) {
		fifo_words_left = tx_empty_count * tqspi->words_per_32bit;
		written_words = min(fifo_words_left, tqspi->curr_dma_words);
		nbytes = written_words * tqspi->bytes_per_word;
		max_n_32bit = DIV_ROUND_UP(nbytes, 4);
		for (count = 0; count < max_n_32bit; count++) {
			x = 0;
			for (i = 0; (i < 4) && nbytes; i++, nbytes--)
				x |= (unsigned long)
					(((unsigned)(*tx_buf++)) << (i * 8));
			tegra_qspi_writel(tqspi, x, QSPI_TX_FIFO);
		}
	} else {
		max_n_32bit = min(tqspi->curr_dma_words,  tx_empty_count);
		written_words = max_n_32bit;
		nbytes = written_words * tqspi->bytes_per_word;
		for (count = 0; count < max_n_32bit; count++) {
			x = 0;
			for (i = 0; nbytes && (i < tqspi->bytes_per_word);
					i++, nbytes--)
				x |= (unsigned long)
					(((unsigned)(*tx_buf++)) << (i * 8));
			tegra_qspi_writel(tqspi, x, QSPI_TX_FIFO);
		}
	}
	tqspi->cur_tx_pos += written_words * tqspi->bytes_per_word;

	return written_words;
}

static unsigned int tegra_qspi_read_rx_fifo_to_client_rxbuf(
		struct tegra_qspi_data *tqspi, struct spi_transfer *t)
{
	unsigned rx_full_count;
	unsigned long fifo_status;
	unsigned i, count;
	unsigned long x;
	unsigned int read_words = 0;
	unsigned len;
	u8 *rx_buf = (u8 *)t->rx_buf + tqspi->cur_rx_pos;

	fifo_status = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
	rx_full_count = QSPI_RX_FIFO_FULL_COUNT(fifo_status);

	if (tqspi->is_packed) {
		len = tqspi->curr_dma_words * tqspi->bytes_per_word;
		for (count = 0; count < rx_full_count; count++) {
			x = tegra_qspi_readl(tqspi, QSPI_RX_FIFO);
			for (i = 0; len && (i < 4); i++, len--)
				*rx_buf++ = (x >> i * 8) & 0xFF;
		}
		tqspi->cur_rx_pos += tqspi->curr_dma_words *
					tqspi->bytes_per_word;
		read_words += tqspi->curr_dma_words;
	} else {
		unsigned int bits_per_word;

		bits_per_word = t->bits_per_word ? t->bits_per_word :
			tqspi->cur_qspi->bits_per_word;
		for (count = 0; count < rx_full_count; count++) {
			x = tegra_qspi_readl(tqspi, QSPI_RX_FIFO);
			for (i = 0; (i < tqspi->bytes_per_word); i++)
				*rx_buf++ = (x >> (i * 8)) & 0xFF;
		}
		tqspi->cur_rx_pos += rx_full_count * tqspi->bytes_per_word;
		read_words += rx_full_count;
	}

	return read_words;
}

static void tegra_qspi_copy_client_txbuf_to_qspi_txbuf(
		struct tegra_qspi_data *tqspi, struct spi_transfer *t)
{
	unsigned len;

	/* Make the dma buffer to read by cpu */
	dma_sync_single_for_cpu(tqspi->dev, tqspi->tx_dma_phys,
				tqspi->dma_buf_size, DMA_TO_DEVICE);

	if (tqspi->is_packed) {
		len = tqspi->curr_dma_words * tqspi->bytes_per_word;
		memcpy(tqspi->tx_dma_buf, t->tx_buf + tqspi->cur_pos, len);
	} else {
		unsigned int i;
		unsigned int count;
		u8 *tx_buf = (u8 *)t->tx_buf + tqspi->cur_tx_pos;
		unsigned consume = tqspi->curr_dma_words *
					tqspi->bytes_per_word;

		for (count = 0; count < tqspi->curr_dma_words; count++) {
			u32 x = 0;

			for (i = 0; consume && (i < tqspi->bytes_per_word);
					i++, consume--)
				x |= ((*tx_buf++) << i * 8);
			tqspi->tx_dma_buf[count] = x;
		}
	}
	tqspi->cur_tx_pos += tqspi->curr_dma_words * tqspi->bytes_per_word;

	/* Make the dma buffer to read by dma */
	dma_sync_single_for_device(tqspi->dev, tqspi->tx_dma_phys,
				   tqspi->dma_buf_size, DMA_TO_DEVICE);
}

static void tegra_qspi_copy_qspi_rxbuf_to_client_rxbuf(
		struct tegra_qspi_data *tqspi, struct spi_transfer *t)
{
	unsigned len;

	/* Make the dma buffer to read by cpu */
	dma_sync_single_for_cpu(tqspi->dev, tqspi->rx_dma_phys,
				tqspi->dma_buf_size, DMA_FROM_DEVICE);

	if (tqspi->is_packed) {
		len = tqspi->curr_dma_words * tqspi->bytes_per_word;
		memcpy(t->rx_buf + tqspi->cur_rx_pos, tqspi->rx_dma_buf, len);
	} else {
		unsigned int i;
		unsigned int count;
		unsigned char *rx_buf = t->rx_buf + tqspi->cur_rx_pos;
		unsigned int x;
		unsigned int rx_mask, bits_per_word;

		bits_per_word = t->bits_per_word ? t->bits_per_word :
			tqspi->cur_qspi->bits_per_word;
		rx_mask = (1ULL << bits_per_word) - 1;
		for (count = 0; count < tqspi->curr_dma_words; count++) {
			x = tqspi->rx_dma_buf[count];
			x &= rx_mask;
			for (i = 0; (i < tqspi->bytes_per_word); i++)
				*rx_buf++ = (x >> (i * 8)) & 0xFF;
		}
	}
	tqspi->cur_rx_pos += tqspi->curr_dma_words * tqspi->bytes_per_word;

	/* Make the dma buffer to read by dma */
	dma_sync_single_for_device(tqspi->dev, tqspi->rx_dma_phys,
				   tqspi->dma_buf_size, DMA_FROM_DEVICE);
}

static void tegra_qspi_dma_complete(void *args)
{
	struct completion *dma_complete = args;

	complete(dma_complete);
}

static int tegra_qspi_start_tx_dma(struct tegra_qspi_data *tqspi, int len)
{
	reinit_completion(&tqspi->tx_dma_complete);
	tqspi->tx_dma_desc = dmaengine_prep_slave_single(tqspi->tx_dma_chan,
			tqspi->tx_dma_phys, len, DMA_MEM_TO_DEV,
			DMA_PREP_INTERRUPT |  DMA_CTRL_ACK);
	if (!tqspi->tx_dma_desc) {
		dev_err(tqspi->dev, "Failed to get Tx DMA Desc\n");
		return -EIO;
	}

	tqspi->tx_dma_desc->callback = tegra_qspi_dma_complete;
	tqspi->tx_dma_desc->callback_param = &tqspi->tx_dma_complete;

	dmaengine_submit(tqspi->tx_dma_desc);
	dma_async_issue_pending(tqspi->tx_dma_chan);

	return 0;
}

static int tegra_qspi_start_rx_dma(struct tegra_qspi_data *tqspi, int len)
{
	reinit_completion(&tqspi->rx_dma_complete);
	tqspi->rx_dma_desc = dmaengine_prep_slave_single(tqspi->rx_dma_chan,
			tqspi->rx_dma_phys, len, DMA_DEV_TO_MEM,
			DMA_PREP_INTERRUPT |  DMA_CTRL_ACK);
	if (!tqspi->rx_dma_desc) {
		dev_err(tqspi->dev, "Failed to get Rx Dma Desc\n");
		return -EIO;
	}

	tqspi->rx_dma_desc->callback = tegra_qspi_dma_complete;
	tqspi->rx_dma_desc->callback_param = &tqspi->rx_dma_complete;

	dmaengine_submit(tqspi->rx_dma_desc);
	dma_async_issue_pending(tqspi->rx_dma_chan);

	return 0;
}

static int tegra_qspi_start_dma_based_transfer(
		struct tegra_qspi_data *tqspi, struct spi_transfer *t)
{
	unsigned long val, command1;
	unsigned int len, intr_mask;
	int ret = 0, maxburst;
	struct dma_slave_config dma_sconfig;

	/* Make sure that Rx and Tx fifo are empty */
	ret = check_and_clear_fifo(tqspi);
	if (ret != 0)
		return ret;
	/* TX_EN/RX_EN should not be set here */
	command1 = tqspi->command1_reg;
	tegra_qspi_writel(tqspi, command1, QSPI_COMMAND1);

	val = QSPI_DMA_BLK_SET(tqspi->curr_dma_words - 1);
	tegra_qspi_writel(tqspi, val, QSPI_DMA_BLK);

	if (tqspi->is_packed)
		len = DIV_ROUND_UP(tqspi->curr_dma_words *
				   tqspi->bytes_per_word, 4) * 4;
	else
		len = tqspi->curr_dma_words * 4;
	val = 0;
	/* Set attention level based on length of transfer */
	if (len & 0xF) {
		val |= QSPI_TX_TRIG_1 | QSPI_RX_TRIG_1;
		maxburst = 1;
	} else if (((len) >> 4) & 0x1) {
		val |= QSPI_TX_TRIG_4 | QSPI_RX_TRIG_4;
		maxburst = 4;
	} else {
		val |= QSPI_TX_TRIG_8 | QSPI_RX_TRIG_8;
		maxburst = 8;
	}
	if ((tqspi->cur_direction & DATA_DIR_TX) ||
	    (tqspi->cur_direction & DATA_DIR_RX)) {
		intr_mask = tegra_qspi_readl(tqspi, QSPI_INTR_MASK);
		intr_mask &= ~(QSPI_INTR_RDY_MASK | QSPI_INTR_RX_TX_FIFO_ERR);
		tegra_qspi_writel(tqspi, intr_mask, QSPI_INTR_MASK);
	}

	tegra_qspi_writel(tqspi, val, QSPI_DMA_CTL);
	tqspi->dma_control_reg = val;

	if (tqspi->cur_direction & DATA_DIR_TX) {
		command1 |= QSPI_TX_EN;
		dma_sconfig.dst_addr = tqspi->phys + QSPI_TX_FIFO;
		dma_sconfig.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		dma_sconfig.dst_maxburst = maxburst;
		dmaengine_slave_config(tqspi->tx_dma_chan, &dma_sconfig);

		tegra_qspi_copy_client_txbuf_to_qspi_txbuf(tqspi, t);
		ret = tegra_qspi_start_tx_dma(tqspi, len);
		if (ret < 0) {
			dev_err(tqspi->dev, "Failed to start Tx DMA: %d\n",
				ret);
			return ret;
		}
	}

	if (tqspi->cur_direction & DATA_DIR_RX) {
		command1 |= QSPI_RX_EN;
		/* Make the dma buffer to read by dma */
		dma_sync_single_for_device(tqspi->dev, tqspi->rx_dma_phys,
					   tqspi->dma_buf_size,
					   DMA_FROM_DEVICE);
		dma_sconfig.src_addr = tqspi->phys + QSPI_RX_FIFO;
		dma_sconfig.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		dma_sconfig.src_maxburst = maxburst;
		dmaengine_slave_config(tqspi->rx_dma_chan, &dma_sconfig);

		ret = tegra_qspi_start_rx_dma(tqspi, len);
		if (ret < 0) {
			dev_err(tqspi->dev, "Failed to start Rx DMA: %d\n",
				ret);
			if (tqspi->cur_direction & DATA_DIR_TX)
				dmaengine_terminate_all(tqspi->tx_dma_chan);
			return ret;
		}
	}
	tqspi->is_curr_dma_xfer = true;
	tqspi->dma_control_reg = val;
	val |= QSPI_DMA_EN;

	/* TX_EN/RX_EN need to set after DMA_BLK to avoid spurious interrupt */
	tegra_qspi_writel(tqspi, command1, QSPI_COMMAND1);

	tegra_qspi_dump_regs("DMA Transfer started", tqspi);
	tegra_qspi_writel(tqspi, val, QSPI_DMA_CTL);

	return ret;
}

static int tegra_qspi_start_cpu_based_transfer(
		struct tegra_qspi_data *tqspi, struct spi_transfer *t)
{
	unsigned long val;
	unsigned int cur_words, intr_mask;
	int ret = 0;

	/* Make sure Tx/Rx fifo is empty */
	ret = check_and_clear_fifo(tqspi);
	if (ret != 0)
		return ret;

	/* TX_EN/RX_EN should not be set here */
	tegra_qspi_writel(tqspi, tqspi->command1_reg, QSPI_COMMAND1);

	if (tqspi->cur_direction & DATA_DIR_TX)
		cur_words = tegra_qspi_fill_tx_fifo_from_client_txbuf(tqspi, t);
	else
		cur_words = tqspi->curr_dma_words;

	val = QSPI_DMA_BLK_SET(cur_words - 1);
	tegra_qspi_writel(tqspi, val, QSPI_DMA_BLK);

	val = 0;

	if ((tqspi->cur_direction & DATA_DIR_TX) ||
	    (tqspi->cur_direction & DATA_DIR_RX)) {
		intr_mask = tegra_qspi_readl(tqspi, QSPI_INTR_MASK);
		intr_mask &= ~(QSPI_INTR_RDY_MASK | QSPI_INTR_RX_TX_FIFO_ERR);
		tegra_qspi_writel(tqspi, intr_mask, QSPI_INTR_MASK);
	}

	tqspi->is_curr_dma_xfer = false;
	val = tqspi->command1_reg;
	/* TX_EN/RX_EN need to set after DMA_BLK to avoid spurious interrupt */
	if (tqspi->cur_direction & DATA_DIR_RX)
		val |= QSPI_RX_EN;
	if (tqspi->cur_direction & DATA_DIR_TX)
		val |= QSPI_TX_EN;
	tegra_qspi_writel(tqspi, val, QSPI_COMMAND1);

	tegra_qspi_dump_regs("CPU Transfer started", tqspi);

	val |= QSPI_PIO;
	tegra_qspi_writel(tqspi, val, QSPI_COMMAND1);

	return 0;
}

static int tegra_qspi_init_dma_param(struct tegra_qspi_data *tqspi,
				     bool dma_to_memory)
{
	struct dma_chan *dma_chan;
	u32 *dma_buf;
	dma_addr_t dma_phys;
	int ret;
	struct dma_slave_config dma_sconfig;

	dma_chan = dma_request_slave_channel_reason(tqspi->dev,
						    dma_to_memory ?
							"rx" : "tx");
	if (IS_ERR(dma_chan)) {
		ret = PTR_ERR(dma_chan);
		dev_err(tqspi->dev, "Failed to get DMA channel, will retryi: %d\n",
			ret);
		return ret;
	}

	dma_buf = dma_alloc_coherent(tqspi->dev, tqspi->dma_buf_size,
				     &dma_phys, GFP_KERNEL);
	if (!dma_buf) {
		dev_err(tqspi->dev, "Failed to allocate coherant DMA buffer\n");
		dma_release_channel(dma_chan);
		return -ENOMEM;
	}

	if (dma_to_memory) {
		dma_sconfig.src_addr = tqspi->phys + QSPI_RX_FIFO;
		dma_sconfig.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		dma_sconfig.src_maxburst = 0;
	} else {
		dma_sconfig.dst_addr = tqspi->phys + QSPI_TX_FIFO;
		dma_sconfig.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		dma_sconfig.dst_maxburst = 0;
	}

	ret = dmaengine_slave_config(dma_chan, &dma_sconfig);
	if (ret)
		goto scrub;
	if (dma_to_memory) {
		tqspi->rx_dma_chan = dma_chan;
		tqspi->rx_dma_buf = dma_buf;
		tqspi->rx_dma_phys = dma_phys;
	} else {
		tqspi->tx_dma_chan = dma_chan;
		tqspi->tx_dma_buf = dma_buf;
		tqspi->tx_dma_phys = dma_phys;
	}

	return 0;

scrub:
	dma_free_coherent(tqspi->dev, tqspi->dma_buf_size, dma_buf, dma_phys);
	dma_release_channel(dma_chan);

	return ret;
}

static void tegra_qspi_deinit_dma_param(struct tegra_qspi_data *tqspi,
					bool dma_to_memory)
{
	u32 *dma_buf;
	dma_addr_t dma_phys;
	struct dma_chan *dma_chan;

	if (dma_to_memory) {
		dma_buf = tqspi->rx_dma_buf;
		dma_chan = tqspi->rx_dma_chan;
		dma_phys = tqspi->rx_dma_phys;
		tqspi->rx_dma_chan = NULL;
		tqspi->rx_dma_buf = NULL;
	} else {
		dma_buf = tqspi->tx_dma_buf;
		dma_chan = tqspi->tx_dma_chan;
		dma_phys = tqspi->tx_dma_phys;
		tqspi->tx_dma_buf = NULL;
		tqspi->tx_dma_chan = NULL;
	}
	if (!dma_chan)
		return;

	dma_free_coherent(tqspi->dev, tqspi->dma_buf_size, dma_buf, dma_phys);
	dma_release_channel(dma_chan);
}

static int tegra_qspi_validate_request(struct spi_device *spi,
				       struct tegra_qspi_data *tqspi,
				       struct spi_transfer *t,
				       bool is_ddr)
{
	int req_mode;

	req_mode = spi->mode & 0x3;
	if ((req_mode == SPI_MODE_1) || (req_mode == SPI_MODE_2)) {
		dev_err(tqspi->dev, "QSPI does not support mode %d\n",
			req_mode);
		return -EINVAL;
	}

	if ((req_mode == SPI_MODE_3) && is_ddr) {
		dev_err(tqspi->dev, "DDR is not supported in mode 3\n");
		return -EINVAL;
	}

	if ((t->bits_per_word != 8) && (t->bits_per_word != 16) &&
	    (t->bits_per_word != 32)) {
		dev_err(tqspi->dev, "QSPI does not support bpw = %d\n",
			t->bits_per_word);
		return -EINVAL;
	}

	if (((t->bits_per_word == 16) && (t->len & 0x1)) ||
	    ((t->bits_per_word == 32) && (t->len & 0x3))) {
		dev_err(tqspi->dev, "QSPI: length %d and bits-per-word %d must align\n",
			t->len, t->bits_per_word);
		return -EINVAL;
	}

	return 0;
}

static bool tegra_qspi_tap(struct tegra_qspi_data *tqspi,
	char *name, int tap, unsigned int mask, unsigned int shift, u32 *cmd2)
{
	if (tap < 0)
		return false;
	if (tap & ~mask)
		dev_warn(tqspi->dev, "%s (%d) should be within %d..%d range\n",
			name, tap, 0, mask);
	tap &= mask;
	*cmd2 &= ~(mask << shift);
	*cmd2 |= (tap << shift);
	return true;
}

static void tegra_qspi_tap_delays(struct tegra_qspi_data *tqspi,
	int tx_tap_delay, int rx_tap_delay)
{
	u32 cmd2 = tegra_qspi_readl(tqspi, QSPI_COMMAND2);
	bool changed = false;

	if (tegra_qspi_tap(tqspi, "tx_tap_delay", tx_tap_delay, 0x1F, 10, &cmd2))
		changed = true;
	if (tegra_qspi_tap(tqspi, "rx_tap_delay", rx_tap_delay, 0xFF, 0, &cmd2))
		changed = true;
	if (changed) {
		dev_info(tqspi->dev, "rx tap = %d, tx tap = %d, COMMAND2 = %08x\n",
			rx_tap_delay, tx_tap_delay, cmd2);
		tegra_qspi_writel(tqspi, cmd2, QSPI_COMMAND2);
	}
}

static void tegra_qspi_set_gr_registers(struct tegra_qspi_data *tqspi)
{
	char prod_name[MAX_PROD_NAME];
	int clk_mhz;
	int err;

#ifdef QSPI_BRINGUP_BUILD
	if (tqspi->qspi_enable_prod_override)
		return;
#endif
	if (!tqspi->prod_list)
		goto regs_por;

	/* If available, initialise the config registers
	 * for QSPI with the values mentioned in prod list.
	 */
	err = tegra_prod_set_by_name(&tqspi->base, "prod", tqspi->prod_list);
	if (err < 0)
		dev_info_once(tqspi->dev,
			      "Prod config not found for QSPI: %d\n", err);

	clk_mhz = tqspi->cur_speed / 1000000;

	if (tqspi->is_ddr_mode)
		sprintf(prod_name, "prod_c_ddr");
	else
		sprintf(prod_name, "prod_c_sdr");

	err = tegra_prod_set_by_name(&tqspi->base, prod_name, tqspi->prod_list);
	if (!err)
		dev_info_once(tqspi->dev,
			      "Failed to apply prod name[%s] for qspi\n",
			      prod_name);

	return;
regs_por:
	/* If NOT defined in prod list or error in applying prod settings,
	 * then initialise golden registers with POR values.
	 */
	tegra_qspi_writel(tqspi, 0, QSPI_COMMAND2);
	tegra_qspi_writel(tqspi, 0, QSPI_CS_TIMING1);
	tegra_qspi_writel(tqspi, CS_ACTIVE_BETWEEN_PACKETS_0, QSPI_CS_TIMING2);
	tegra_qspi_writel(tqspi, 0, QSPI_CS_TIMING3);
}

static int tegra_qspi_start_transfer_one(struct spi_device *spi,
					 struct spi_transfer *t,
					 bool is_first_of_msg,
					 bool is_single_xfer)
{
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(spi->master);
#ifndef QSPI_BRINGUP_BUILD
	struct tegra_qspi_device_controller_data *cdata = spi->controller_data;
#endif
	u32 speed = 0;
	u32 actual_speed = 0;
	u8 bits_per_word;
	unsigned total_fifo_words;
	int ret;
	unsigned long command1;
	int req_mode;
	u8 bus_width = X1;
	bool is_ddr = false;
	u8 bus_clk_div = tqspi->bus_clk_div;

	bits_per_word = t->bits_per_word;
	tqspi->cur_qspi = spi;
	tqspi->cur_pos = 0;
	tqspi->cur_rx_pos = 0;
	tqspi->cur_tx_pos = 0;
	tqspi->curr_xfer = t;
	tqspi->tx_status = 0;
	tqspi->rx_status = 0;
	total_fifo_words = tegra_qspi_calculate_curr_xfer_param(spi, tqspi, t);
#ifndef QSPI_BRINGUP_BUILD
	if (cdata) {
		if ((t->len - tqspi->cur_pos) >  cdata->x1_len_limit)
			speed = cdata->x4_bus_speed;
		else {
			is_ddr = false;
			speed = cdata->x1_bus_speed;
		}
		bus_clk_div = cdata->bus_clk_div;
	} else {
		dev_err(tqspi->dev, "Controller Data is not available\n");
		return -EINVAL;
	}
#else
	if (tqspi->qspi_force_bus_speed)
		speed = tqspi->cur_speed;
	else
		speed = t->speed_hz;
#endif
	if (bus_clk_div < 1 || bus_clk_div > 2)
		bus_clk_div = tqspi->bus_clk_div;
	/*
	 * NOTE:
	 * 1.Bus width can be x4 even for command/addr for QPI commands.
	 *   So caller requested bus width should be considered.
	 * 2. is_ddr is not applicable for write. Write is always in SDR mode.
	 */
	is_ddr = get_sdr_ddr(t->delay_usecs);
	bus_width = get_bus_width(t->delay_usecs);
	ret = tegra_qspi_validate_request(spi, tqspi, t, is_ddr);
	if (ret)
		return ret;
	if (!speed || speed > tqspi->qspi_max_frequency/bus_clk_div)
		speed = tqspi->qspi_max_frequency/bus_clk_div;
	if (speed != tqspi->cur_speed ||
	    bus_clk_div != tqspi->bus_clk_div) {
		ret = clk_set_rate(tqspi->clk, speed*bus_clk_div);
		if (ret < 0) {
			dev_err(tqspi->dev,
				"Failed to set QSPI clock freq: %d\n", ret);
			return -EINVAL;
		}
		actual_speed = clk_get_rate(tqspi->clk)/bus_clk_div;
		ret = clk_set_rate(tqspi->sdr_ddr_clk, actual_speed);
		if (ret < 0) {
			dev_err(tqspi->dev,
				"Failed to set QSPI clock freq: %d\n", ret);
			return -EINVAL;
		}
		tqspi->cur_speed = speed;
		tqspi->bus_clk_div = bus_clk_div;
	}
#if 0
	if (is_ddr != tqspi->is_ddr_mode) {
		actual_speed = clk_get_rate(tqspi->clk);
		if (is_ddr)
			ret = clk_set_rate(tqspi->sdr_ddr_clk,
					   (actual_speed >> 1));
		else
			ret = clk_set_rate(tqspi->sdr_ddr_clk, actual_speed);
		if (ret < 0) {
			dev_err(tqspi->dev, "Failed to set QSPI-out clock freq: %d\n",
				ret);
			return -EINVAL;
		}
		tqspi->is_ddr_mode = is_ddr;
	}
#endif
	if (is_first_of_msg) {
		tegra_qspi_clear_status(tqspi);

		command1 = tqspi->def_command1_reg;
		command1 |= QSPI_BIT_LENGTH(bits_per_word - 1);

		command1 &= ~QSPI_CONTROL_MODE_MASK;
		req_mode = spi->mode & 0x3;
		if (req_mode == SPI_MODE_0) {
			command1 |= QSPI_CONTROL_MODE_0;
		} else if (req_mode == SPI_MODE_3) {
			command1 |= QSPI_CONTROL_MODE_3;
		} else {
			dev_err(tqspi->dev, "QSPI does not support mode %d\n",
				req_mode);
			return -EINVAL;
		}
		/* Programming mode first suggested by HW - Bug 200082074 */
		tegra_qspi_writel(tqspi, command1, QSPI_COMMAND1);
		/* Toggle CS to active state now */
		if (spi->mode & SPI_CS_HIGH)
			command1 |= QSPI_CS_SW_VAL;
		else
			command1 &= ~QSPI_CS_SW_VAL;
		tegra_qspi_writel(tqspi, command1, QSPI_COMMAND1);
	} else {
		command1 = tqspi->command1_reg;
		command1 &= ~QSPI_BIT_LENGTH(~0);
		command1 |= QSPI_BIT_LENGTH(bits_per_word - 1);
	}

	command1 &= ~QSPI_SDR_DDR_SEL;
	if (is_ddr)
		command1 |= QSPI_SDR_DDR_SEL;

	command1 &= ~QSPI_INTERFACE_WIDTH_MASK;
	command1 |= QSPI_INTERFACE_WIDTH(bus_width);

	command1 &= ~QSPI_PACKED;
	if (tqspi->is_packed)
		command1 |= QSPI_PACKED;

	command1 &= ~(QSPI_TX_EN | QSPI_RX_EN);
	tqspi->cur_direction = 0;
	if (t->rx_buf)
		tqspi->cur_direction |= DATA_DIR_RX;

	if (t->tx_buf)
		tqspi->cur_direction |= DATA_DIR_TX;

	tqspi->command1_reg = command1;

#ifdef QSPI_BRINGUP_BUILD
	if (tqspi->qspi_force_dma_mode) {
		ret = tegra_qspi_start_dma_based_transfer(tqspi, t);
		return ret;
	}

	if (tqspi->qspi_force_pio_mode) {
		ret = tegra_qspi_start_cpu_based_transfer(tqspi, t);
		return ret;
	}
#endif

	if (total_fifo_words > QSPI_FIFO_DEPTH)
		ret = tegra_qspi_start_dma_based_transfer(tqspi, t);
	else
		ret = tegra_qspi_start_cpu_based_transfer(tqspi, t);

	return ret;
}

static void tegra_qspi_clean(struct spi_device *spi)
{
	kfree(spi->controller_data);
	spi->controller_data = NULL;
}

static int tegra_qspi_setup(struct spi_device *spi)
{
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(spi->master);
	struct tegra_qspi_device_controller_data *cdata = spi->controller_data;
	unsigned long val;
	unsigned long flags;
	int ret;

	dev_dbg(&spi->dev, "setup %d bpw, %scpol, %scpha, %dHz\n",
		spi->bits_per_word,
		spi->mode & SPI_CPOL ? "" : "~",
		spi->mode & SPI_CPHA ? "" : "~",
		spi->max_speed_hz);

	if (spi->chip_select >= MAX_CHIP_SELECT) {
		dev_err(tqspi->dev, "QSPI Chip select %d is not supported\n",
			spi->chip_select);
		return -EINVAL;
	}

	if (!cdata) {
		cdata = tegra_qspi_get_cdata_dt(spi);
		spi->controller_data = cdata;
	}

	/* Set speed to the spi max fequency if qspi device has not set */
	spi->max_speed_hz = spi->max_speed_hz ? : tqspi->qspi_max_frequency;
	ret = pm_runtime_get_sync(tqspi->dev);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to get runtime PM: %d\n", ret);
		return ret;
	}
	spin_lock_irqsave(&tqspi->lock, flags);
	/* keep default cs state to inactive */
	val = tqspi->def_command1_reg;
	if (spi->mode & SPI_CS_HIGH)
		val  &= ~QSPI_CS_SW_VAL;
	else
		val |= QSPI_CS_SW_VAL;

	tqspi->def_command1_reg = val;
	tegra_qspi_writel(tqspi, tqspi->def_command1_reg, QSPI_COMMAND1);
	spin_unlock_irqrestore(&tqspi->lock, flags);
	pm_runtime_mark_last_busy(tqspi->dev);
	pm_runtime_put_autosuspend(tqspi->dev);

	return 0;
}

static int tegra_qspi_cs_low(struct spi_device *spi, bool state)
{
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(spi->master);
	int ret;
	unsigned long val;
	unsigned long flags;

	if (spi->chip_select >= MAX_CHIP_SELECT) {
		dev_err(tqspi->dev, "QSPI Chip select %d is not supported\n",
			spi->chip_select);
		return -EINVAL;
	}

	ret = pm_runtime_get_sync(tqspi->dev);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to get runtime PM: %d\n", ret);
		return ret;
	}
	spin_lock_irqsave(&tqspi->lock, flags);

	val = tegra_qspi_readl(tqspi, QSPI_COMMAND1);
	if (state)
		val &= ~QSPI_CS_SW_VAL;
	else
		val |= QSPI_CS_SW_VAL;
	tegra_qspi_writel(tqspi, val, QSPI_COMMAND1);

	spin_unlock_irqrestore(&tqspi->lock, flags);
	pm_runtime_mark_last_busy(tqspi->dev);
	pm_runtime_put_autosuspend(tqspi->dev);

	return 0;
}

static int tegra_qspi_combined_sequence_transfer(struct tegra_qspi_data *tqspi,
						 struct spi_message *msg)
{
	bool is_first_msg = true, is_ddr = false;
	int single_xfer;
	struct spi_transfer *xfer;
	struct spi_device *spi = msg->spi;
	u8 transfer_phase = 0, bus_width = X1;
	int ret;
	u32 qspi_setting = 0;
	u32 address_value = 0;
	u32 cmd_config = 0, addr_config = 0;
	u8 cmd_value = 0, len = 0, val = 0;

	/* Enable Combined sequence mode */
	val = tegra_qspi_readl(tqspi, QSPI_GLOBAL_CONFIG);
	val |= QSPI_CMB_SEQ_EN;
	tegra_qspi_writel(tqspi, val, QSPI_GLOBAL_CONFIG);
	single_xfer = list_is_singular(&msg->transfers);
	/* Process individual transfer list */
	list_for_each_entry(xfer, &msg->transfers, transfer_list) {
		if (transfer_phase == CMD_TRANSFER) {
			/* Extract Command configuration and value */
			qspi_setting = xfer->delay_usecs;
			is_ddr = get_sdr_ddr(qspi_setting);
			bus_width = get_bus_width(qspi_setting);

			if (is_ddr)
				cmd_config |= QSPI_COMMAND_SDR_DDR;
			else
				cmd_config &= ~QSPI_COMMAND_SDR_DDR;
			cmd_config |= QSPI_COMMAND_X1_X2_X4(bus_width);
			cmd_config |= QSPI_COMMAND_SIZE_SET(
						(xfer->len * 8) - 1);
			cmd_value = *((const u8 *)(xfer->tx_buf));

		} else if (transfer_phase == ADDR_TRANSFER) {
			/* Extract Address configuration and value */
			qspi_setting = xfer->delay_usecs;

			is_ddr = get_sdr_ddr(qspi_setting);
			bus_width = get_bus_width(qspi_setting);
			len = xfer->len;

			if (is_ddr)
				addr_config |= QSPI_ADDRESS_SDR_DDR;
			else
				addr_config &= ~QSPI_ADDRESS_SDR_DDR;
			addr_config |= QSPI_ADDRESS_X1_X2_X4(bus_width);
			addr_config |= QSPI_ADDRESS_SIZE_SET(
						(xfer->len * 8) - 1);
			address_value = *((const u32 *)(xfer->tx_buf));
		} else {
			/* Program Command, Address value in register */
			tegra_qspi_writel(tqspi, cmd_value, QSPI_CMB_SEQ_CMD);
			tegra_qspi_writel(tqspi, address_value,
					  QSPI_CMB_SEQ_ADDR);
			/* Program Command and Address config in register */
			tegra_qspi_writel(tqspi, cmd_config,
					  QSPI_CMB_SEQ_CMD_CFG);
			tegra_qspi_writel(tqspi, addr_config,
					  QSPI_CMB_SEQ_ADDR_CFG);

			reinit_completion(&tqspi->xfer_completion);
			/* Start Data transfer */
			ret = tegra_qspi_start_transfer_one(spi, xfer,
							    is_first_msg,
							    single_xfer);

			if (ret < 0) {
				dev_err(tqspi->dev, "Failed to start transfer-one: %d\n",
					ret);
				return ret;
			}

			is_first_msg = false;
			ret = wait_for_completion_timeout
					(&tqspi->xfer_completion,
					QSPI_DMA_TIMEOUT);

			if (WARN_ON(ret == 0)) {
				dev_err(tqspi->dev, "QSPI Transfer failed with timeout: %d\n",
					ret);
				if (tqspi->is_curr_dma_xfer &&
				    (tqspi->cur_direction & DATA_DIR_TX))
					dmaengine_terminate_all(
						tqspi->tx_dma_chan);

				if (tqspi->is_curr_dma_xfer &&
				    (tqspi->cur_direction & DATA_DIR_RX))
					dmaengine_terminate_all(
						tqspi->rx_dma_chan);

				/* Reset controller if timeout happens */
				reset_control_reset(tqspi->rstc);
				ret = -EIO;
				return ret;
			}

			if (tqspi->tx_status ||  tqspi->rx_status) {
				dev_err(tqspi->dev, "QSPI Transfer failed\n");
				tqspi->tx_status = 0;
				tqspi->rx_status = 0;
				ret = -EIO;
				return ret;
			}
		}
		msg->actual_length += xfer->len;
		transfer_phase++;
	}

	return 0;
}

static int tegra_qspi_non_combined_sequence_transfer
	(struct tegra_qspi_data *tqspi, struct spi_message *msg)
{
	bool is_first_msg = true;
	int single_xfer;
	struct spi_transfer *xfer;
	struct spi_device *spi = msg->spi;
	int ret;
	u8 val = 0;

	val = tegra_qspi_readl(tqspi, QSPI_GLOBAL_CONFIG);
	val &= ~QSPI_CMB_SEQ_EN;
	tegra_qspi_writel(tqspi, val, QSPI_GLOBAL_CONFIG);

	single_xfer = list_is_singular(&msg->transfers);
	list_for_each_entry(xfer, &msg->transfers, transfer_list) {
		reinit_completion(&tqspi->xfer_completion);
		ret = tegra_qspi_start_transfer_one(spi, xfer,
						    is_first_msg,
						    single_xfer);
		if (ret < 0) {
			dev_err(tqspi->dev, "Failed to start transfer-one: %d\n",
				ret);
			return ret;
		}
		is_first_msg = false;
		ret = wait_for_completion_timeout(&tqspi->xfer_completion,
						  QSPI_DMA_TIMEOUT);
		if (WARN_ON(ret == 0)) {
			dev_err(tqspi->dev, "QSPI Transfer failed with timeout\n");
			if (tqspi->is_curr_dma_xfer &&
			    (tqspi->cur_direction & DATA_DIR_TX))
				dmaengine_terminate_all(tqspi->tx_dma_chan);

			if (tqspi->is_curr_dma_xfer &&
			    (tqspi->cur_direction & DATA_DIR_RX))
				dmaengine_terminate_all(tqspi->rx_dma_chan);

			/* Reset controller in case of timeout happens */
			reset_control_reset(tqspi->rstc);
				ret = -EIO;
				return ret;
		}

		if (tqspi->tx_status ||  tqspi->rx_status) {
			dev_err(tqspi->dev, "QSPI Transfer failed\n");
			tqspi->tx_status = 0;
			tqspi->rx_status = 0;
			ret = -EIO;
			return ret;
		}
		msg->actual_length += xfer->len;
	}

	return 0;
}

static int tegra_qspi_transfer_one_message(struct spi_master *master,
					   struct spi_message *msg)
{
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(master);
	struct spi_transfer *xfer;
	u8 count_number_of_transfers = 0;
	int ret;

	msg->status = 0;
	msg->actual_length = 0;
	ret = pm_runtime_get_sync(tqspi->dev);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to get runtime PM: %d\n", ret);
		msg->status = ret;
		spi_finalize_current_message(master);
		return ret;
	}
	list_for_each_entry(xfer, &msg->transfers, transfer_list) {
		count_number_of_transfers++;
	}
	/*
	* Do Combined sequence mode related processing if it is enabled in DT
	* Support for Combined Sequence mode is available from T18X onwards
	* Combined sequence mode is applicable for <CMD><ADDR><DATA> transfers
	* Non combined mode transfer is used in other transfers
	*/

	if (tqspi->qspi_enable_cmbseq_mode  && count_number_of_transfers == 3) {
		tqspi->dcycle_non_cmbseq_mode = false;
		ret = tegra_qspi_combined_sequence_transfer(tqspi, msg);
		if (ret < 0) {
			dev_err(tqspi->dev, "QSPI combined sequence transfer failed: %d\n",
				ret);
			goto exit;
		}
	} else {
		tqspi->dcycle_non_cmbseq_mode = true;
		ret = tegra_qspi_non_combined_sequence_transfer(tqspi, msg);
		if (ret < 0) {
			dev_err(tqspi->dev, "QSPI non-combined sequence transfer failed: %d\n",
				ret);
		   goto exit;
		}
	}
	ret = 0;
exit:
	tegra_qspi_writel(tqspi, tqspi->def_command1_reg, QSPI_COMMAND1);
	pm_runtime_mark_last_busy(tqspi->dev);
	pm_runtime_put_autosuspend(tqspi->dev);
	msg->status = ret;
	spi_finalize_current_message(master);

	return ret;
}

#ifdef QSPI_BRINGUP_BUILD
static void handle_combined_sequence(struct tegra_qspi_data *tqspi)
{
	u8 val = 0;

	/* clear combined sequence enable */
	val = tegra_qspi_readl(tqspi, QSPI_GLOBAL_CONFIG);
	val &= ~QSPI_CMB_SEQ_EN;
	tegra_qspi_writel(tqspi, val, QSPI_GLOBAL_CONFIG);
}
#endif

static irqreturn_t handle_cpu_based_xfer(struct tegra_qspi_data *tqspi)
{
	struct spi_transfer *t = tqspi->curr_xfer;
	unsigned long flags;

	spin_lock_irqsave(&tqspi->lock, flags);
	if (tqspi->tx_status ||  tqspi->rx_status) {
		dev_err(tqspi->dev, "CpuXfer ERROR, status 0x%08x\n",
			tqspi->status_reg);
		dev_err(tqspi->dev, "CpuXfer command1:dmacontro->0x%08x:0x%08x\n",
			tqspi->command1_reg, tqspi->dma_control_reg);
		reset_control_reset(tqspi->rstc);
		complete(&tqspi->xfer_completion);
		tqspi->tx_status = 0;
		tqspi->rx_status = 0;
		goto exit;
	}

	if (tqspi->cur_direction & DATA_DIR_RX)
		tegra_qspi_read_rx_fifo_to_client_rxbuf(tqspi, t);

	if (tqspi->cur_direction & DATA_DIR_TX)
		tqspi->cur_pos = tqspi->cur_tx_pos;
	else
		tqspi->cur_pos = tqspi->cur_rx_pos;

	if (tqspi->cur_pos >= t->len) {
		complete(&tqspi->xfer_completion);
		goto exit;
	}
	tegra_qspi_calculate_curr_xfer_param(tqspi->cur_qspi, tqspi, t);
	tegra_qspi_start_cpu_based_transfer(tqspi, t);
exit:
	spin_unlock_irqrestore(&tqspi->lock, flags);

	return IRQ_HANDLED;
}

static irqreturn_t handle_dma_based_xfer(struct tegra_qspi_data *tqspi)
{
	struct spi_transfer *t = tqspi->curr_xfer;
	long wait_status;
	int err = 0;
	unsigned total_fifo_words;
	unsigned long flags;

	/* Abort dmas if any error */
	if (tqspi->cur_direction & DATA_DIR_TX) {
		if (tqspi->tx_status) {
			dmaengine_terminate_all(tqspi->tx_dma_chan);
			err += 1;
		} else {
			wait_status = wait_for_completion_interruptible_timeout(
					&tqspi->tx_dma_complete,
					QSPI_DMA_TIMEOUT);
			if (wait_status <= 0) {
				dmaengine_terminate_all(tqspi->tx_dma_chan);
				dev_err(tqspi->dev, "TxDma Xfer failed\n");
				err += 1;
			}
		}
	}

	if (tqspi->cur_direction & DATA_DIR_RX) {
		if (tqspi->rx_status) {
			dmaengine_terminate_all(tqspi->rx_dma_chan);
			err += 2;
		} else {
			wait_status = wait_for_completion_interruptible_timeout(
				&tqspi->rx_dma_complete, QSPI_DMA_TIMEOUT);
			if (wait_status <= 0) {
				dmaengine_terminate_all(tqspi->rx_dma_chan);
				dev_err(tqspi->dev, "RxDma Xfer failed\n");
				err += 2;
			}
		}
	}

	spin_lock_irqsave(&tqspi->lock, flags);
	if (err) {
		dev_err(tqspi->dev, "DmaXfer ERROR, status 0x%08x\n",
			tqspi->status_reg);
		dev_err(tqspi->dev, "DmaXfer command1:dmacontro->0x%08x:0x%08x\n",
			tqspi->command1_reg, tqspi->dma_control_reg);
		reset_control_reset(tqspi->rstc);
		complete(&tqspi->xfer_completion);
		tqspi->rx_status = 0;
		tqspi->tx_status = 0;
		spin_unlock_irqrestore(&tqspi->lock, flags);
		return IRQ_HANDLED;
	}

	if (tqspi->cur_direction & DATA_DIR_RX)
		tegra_qspi_copy_qspi_rxbuf_to_client_rxbuf(tqspi, t);

	if (tqspi->cur_direction & DATA_DIR_TX)
		tqspi->cur_pos = tqspi->cur_tx_pos;
	else
		tqspi->cur_pos = tqspi->cur_rx_pos;

	if (tqspi->cur_pos >= t->len) {
		complete(&tqspi->xfer_completion);
		goto exit;
	}

#ifdef QSPI_BRINGUP_BUILD
	if (tqspi->qspi_force_dma_mode) {
		err = tegra_qspi_start_dma_based_transfer(tqspi, t);
		goto exit;
	}
#endif

	/* Continue transfer in current message */
	total_fifo_words = tegra_qspi_calculate_curr_xfer_param(tqspi->cur_qspi,
								tqspi, t);
	if (total_fifo_words > QSPI_FIFO_DEPTH)
		err = tegra_qspi_start_dma_based_transfer(tqspi, t);
	else
		err = tegra_qspi_start_cpu_based_transfer(tqspi, t);

exit:
	spin_unlock_irqrestore(&tqspi->lock, flags);

	return IRQ_HANDLED;
}

static irqreturn_t tegra_qspi_isr_thread(int irq, void *context_data)
{
	struct tegra_qspi_data *tqspi = context_data;

#ifdef QSPI_BRINGUP_BUILD
	if (tqspi->qspi_enable_cmbseq_mode)
		handle_combined_sequence(tqspi);
#endif
	if (!tqspi->is_curr_dma_xfer)
		return handle_cpu_based_xfer(tqspi);

	return handle_dma_based_xfer(tqspi);
}

static irqreturn_t tegra_qspi_isr(int irq, void *context_data)
{
	struct tegra_qspi_data *tqspi = context_data;

	tegra_qspi_dump_regs("From QSPI ISR", tqspi);
	tqspi->status_reg = tegra_qspi_readl(tqspi, QSPI_FIFO_STATUS);
	if (tqspi->cur_direction & DATA_DIR_TX)
		tqspi->tx_status = tqspi->status_reg &
			(QSPI_TX_FIFO_UNF | QSPI_TX_FIFO_OVF);

	if (tqspi->cur_direction & DATA_DIR_RX)
		tqspi->rx_status = tqspi->status_reg &
			(QSPI_RX_FIFO_OVF | QSPI_RX_FIFO_UNF);

	if (!(tqspi->cur_direction & DATA_DIR_TX) &&
	    !(tqspi->cur_direction & DATA_DIR_RX))
		dev_err(tqspi->dev, "QSPI get spurious interrupt, Status = 0x%08x\n",
			tqspi->status_reg);

	tegra_qspi_clear_status(tqspi);

	return IRQ_WAKE_THREAD;
}

static int tegra_qspi_clk_enable(struct tegra_qspi_data *tqspi)
{
	int ret;

	ret = clk_prepare_enable(tqspi->clk);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to enable QSPI clock: %d\n", ret);
		return ret;
	}

	ret = clk_prepare_enable(tqspi->sdr_ddr_clk);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to enable QSPI-OUT clk: %d\n", ret);
		clk_disable_unprepare(tqspi->clk);
		return ret;
	}

	return ret;
}

static void tegra_qspi_clk_disable(struct tegra_qspi_data *tqspi)
{
	clk_disable_unprepare(tqspi->sdr_ddr_clk);
	clk_disable_unprepare(tqspi->clk);
}

static void set_best_clk_source(struct tegra_qspi_data *tqspi,
				unsigned long rate)
{
	long new_rate;
	unsigned long err_rate;
	unsigned int fin_err = rate;
	int ret;
	struct clk *pclk, *fpclk = NULL;
	const char *pclk_name, *fpclk_name = NULL;
	struct device_node *node = tqspi->dev->of_node;
	struct property *prop;

	if (!of_property_count_strings(node, "nvidia,clk-parents"))
		return;

	of_property_for_each_string(node, "nvidia,clk-parents",
				    prop, pclk_name) {
		pclk = clk_get(tqspi->dev, pclk_name);
		if (IS_ERR(pclk))
			continue;

		ret = clk_set_parent(tqspi->clk, pclk);
		if (ret < 0) {
			dev_warn(tqspi->dev, "Failed to set parent clk: %d\n",
				 ret);
			continue;
		}

		new_rate = clk_round_rate(tqspi->clk, rate);
		if (new_rate < 0)
			continue;

		err_rate = abs(new_rate - rate);
		if (err_rate < fin_err) {
			fpclk = pclk;
			fin_err = err_rate;
			fpclk_name = pclk_name;
		}
	}

	if (fpclk) {
		dev_dbg(tqspi->dev, "Setting clk_src %s\n", fpclk_name);
		clk_set_parent(tqspi->clk, fpclk);
	}
}

static struct tegra_qspi_device_controller_data *tegra_qspi_get_cdata_dt(
			struct spi_device *spi)
{
	struct tegra_qspi_device_controller_data *cdata = NULL;
	struct device_node *np = spi->dev.of_node, *data_np = NULL;
	u32 pval;

	if (!np) {
		dev_dbg(&spi->dev, "Device must have DT node handle\n");
		return NULL;
	}

	data_np = of_get_child_by_name(np, "controller-data");
	if (!data_np) {
		dev_dbg(&spi->dev, "child node 'controller-data' not found\n");
		return NULL;
	}

	cdata = kzalloc(sizeof(*cdata), GFP_KERNEL);
	if (!cdata)
		return NULL;

	if (!of_property_read_u32(data_np, "nvidia,x1-len-limit", &pval))
		cdata->x1_len_limit = pval;

	if (!of_property_read_u32(data_np, "nvidia,x1-bus-speed", &pval))
		cdata->x1_bus_speed = pval;

	if (!of_property_read_u32(data_np, "nvidia,x1-dymmy-cycle", &pval))
		cdata->x1_dymmy_cycle = pval;

	if (!of_property_read_u32(data_np, "nvidia,x4-bus-speed", &pval))
		cdata->x4_bus_speed = pval;

	if (!of_property_read_u32(data_np, "nvidia,x4-dymmy-cycle", &pval))
		cdata->x4_dymmy_cycle = pval;

	if (!of_property_read_u32(data_np, "nvidia,x4-is-ddr", &pval))
		cdata->x4_is_ddr = pval;

	if (!of_property_read_u32(data_np, "nvidia,ifddr-div2-sdr", &pval))
		cdata->ifddr_div2_sdr = pval;

	if (!of_property_read_u32(data_np, "nvidia,ctrl-bus-clk-ratio",
				  &pval))
		cdata->bus_clk_div = (u8)pval;

	cdata->is_combined_seq_mode_en = of_property_read_bool(data_np,
						"nvidia,combined-seq-mode-en");

	/* Bus speed mentioned in device tree should be what is applied
	 * on interface. Earlier version used to apply half of the bus
	 * speed defined in device tree. To maintain backward compatibility
	 * with old device tree, applied bus speed is half of that defined in
	 * device tree if 'nvidia,ifddr-div2-sdr' is defined
	 */
	if (cdata->ifddr_div2_sdr && cdata->x1_bus_speed)
		cdata->x1_bus_speed /= 2;

	if (cdata->ifddr_div2_sdr && cdata->x4_bus_speed)
		cdata->x4_bus_speed /= 2;

	return cdata;
}

static void tegra_qspi_parse_dt(struct device *dev,
				struct tegra_qspi_data *tqspi)
{
	struct device_node *np = dev->of_node;
	u32 pval;
	int ret;

	tqspi->enable_dma_support = of_property_read_bool(np, "dma-names");

	ret = of_property_read_u32(np, "spi-max-frequency", &pval);
	if (!ret)
		tqspi->qspi_max_frequency = pval;
	else
		tqspi->qspi_max_frequency = 136000000; /* 136MHz */

	tqspi->clock_always_on = of_property_read_bool(np,
						       "nvidia,clock-always-on");
}

static int tegra_qspi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct spi_master	*master;
	struct tegra_qspi_data	*tqspi;
	struct resource		*r;
	int ret, qspi_irq;
	u32 as_delay;
	u32 actual_speed = 0;

	master = spi_alloc_master(&pdev->dev, sizeof(*tqspi));
	if (!master) {
		dev_err(&pdev->dev, "SPI master allocation failed\n");
		return -ENOMEM;
	}

	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH;
	master->setup = tegra_qspi_setup;
	master->cleanup = tegra_qspi_clean;
	master->transfer_one_message = tegra_qspi_transfer_one_message;
	master->num_chipselect = MAX_CHIP_SELECT;
	master->bus_num = -1;
	master->spi_cs_low  = tegra_qspi_cs_low;

	dev_set_drvdata(&pdev->dev, master);
	tqspi = spi_master_get_devdata(master);
	tqspi->master = master;

	tegra_qspi_parse_dt(&pdev->dev, tqspi);
	tqspi->dev = &pdev->dev;
	tqspi->prod_list = devm_tegra_prod_get(&pdev->dev);
	if (IS_ERR(tqspi->prod_list)) {
		dev_info(&pdev->dev, "Prod settings list not found\n");
		tqspi->prod_list = NULL;
	}

	spin_lock_init(&tqspi->lock);

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(&pdev->dev, "Failed to get IO memory\n");
		ret = -ENODEV;
		goto exit_free_master;
	}
	tqspi->phys = r->start;
	tqspi->base = devm_ioremap_resource(&pdev->dev, r);
	if (IS_ERR(tqspi->base)) {
		ret = PTR_ERR(tqspi->base);
		dev_err(dev, "Failed to request memregion/iomap address: %d\n",
			ret);
		goto exit_free_master;
	}

	tqspi->rstc = devm_reset_control_get(&pdev->dev, "qspi");
	if (IS_ERR(tqspi->rstc)) {
		ret = PTR_ERR(tqspi->rstc);
		dev_err(&pdev->dev, "Failed to get reset control: %d\n", ret);
		goto exit_free_master;
	}
	reset_control_reset(tqspi->rstc);

	qspi_irq = platform_get_irq(pdev, 0);
	tqspi->irq = qspi_irq;
	ret = devm_request_threaded_irq(dev, tqspi->irq, tegra_qspi_isr,
					tegra_qspi_isr_thread, IRQF_ONESHOT,
					dev_name(&pdev->dev), tqspi);
	if (ret < 0) {
		dev_err(dev, "Failed to register interrupt: %d\n", tqspi->irq);
		goto exit_free_master;
	}

	tqspi->clk = devm_clk_get(&pdev->dev, "qspi");
	if (IS_ERR(tqspi->clk)) {
		ret = PTR_ERR(tqspi->clk);
		dev_err(&pdev->dev, "Failed to get QSPI clock: %d\n", ret);
		goto exit_free_master;
	}

	tqspi->sdr_ddr_clk = devm_clk_get(&pdev->dev, "qspi_out");
	if (IS_ERR(tqspi->sdr_ddr_clk)) {
		ret = PTR_ERR(tqspi->sdr_ddr_clk);
		dev_err(&pdev->dev, "Failed to get QSPI-OUT: %d\n", ret);
		goto exit_free_master;
	}

	/* Set default mode to SDR */
	tqspi->is_ddr_mode = false;
	tqspi->max_buf_size = QSPI_FIFO_DEPTH << 2;
	tqspi->dma_buf_size = DEFAULT_SPI_DMA_BUF_LEN;
	if (tqspi->enable_dma_support) {
		ret = tegra_qspi_init_dma_param(tqspi, true);
		if (ret < 0) {
			dev_err(&pdev->dev, "Failed to initialise RxDma: %d\n",
				ret);
			goto exit_free_master;
		}

		ret = tegra_qspi_init_dma_param(tqspi, false);
		if (ret < 0) {
			dev_err(&pdev->dev, "Failed to initialise TxDma: %d\n",
				ret);
			goto exit_rx_dma_free;
		}
		tqspi->max_buf_size = tqspi->dma_buf_size;
		init_completion(&tqspi->tx_dma_complete);
		init_completion(&tqspi->rx_dma_complete);
	}

	init_completion(&tqspi->xfer_completion);

	if (tqspi->clock_always_on) {
		ret = tegra_qspi_clk_enable(tqspi);
		if (ret < 0)
			goto exit_deinit_dma;
	}
	ret = of_property_read_u32(dev->of_node, "qspi-autosuspend-delay",
				   &as_delay);
	if (ret)
		as_delay = 3000; /* defalut autosuspend delay */

	pm_runtime_set_autosuspend_delay(&pdev->dev, as_delay);
	pm_runtime_use_autosuspend(&pdev->dev);
	pm_runtime_enable(&pdev->dev);
	if (!pm_runtime_enabled(&pdev->dev)) {
		ret = tegra_qspi_runtime_resume(&pdev->dev);
		if (ret)
			goto exit_pm_disable;
	}

	ret = pm_runtime_get_sync(&pdev->dev);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to get runtime PM: %d\n", ret);
		goto exit_pm_disable;
	}
	set_best_clk_source(tqspi, tqspi->qspi_max_frequency);
	ret = clk_set_rate(tqspi->clk, tqspi->qspi_max_frequency);
	if (ret) {
		dev_err(dev, "Failed to set qspi clk freq %d\n", ret);
		goto exit_pm_disable;
	}
	tqspi->cur_speed = tqspi->qspi_max_frequency;
	actual_speed = clk_get_rate(tqspi->clk);
	if (actual_speed > 0) {
		ret = clk_set_rate(tqspi->sdr_ddr_clk, actual_speed >> 1);
		if (ret) {
			dev_err(dev, "Failed to set qspi_out clk freq %d\n",
				ret);
			goto exit_pm_disable;
		}
		tqspi->bus_clk_div = 2;
	}

	tqspi->def_command1_reg  = QSPI_M_S | QSPI_CS_SW_HW |  QSPI_CS_SW_VAL;
	tegra_qspi_writel(tqspi, tqspi->def_command1_reg, QSPI_COMMAND1);
	tqspi->def_command2_reg = tegra_qspi_readl(tqspi, QSPI_COMMAND2);
	tegra_qspi_set_gr_registers(tqspi);
	tegra_qspi_tap_delays(tqspi, tx_tap_delay, rx_tap_delay);
	pm_runtime_mark_last_busy(&pdev->dev);
	pm_runtime_put_autosuspend(&pdev->dev);

	master->dev.of_node = pdev->dev.of_node;
	ret = devm_spi_register_master(&pdev->dev, master);
	if (ret < 0) {
		dev_err(dev, "Failed to register spi master: %d\n", ret);
		goto exit_pm_disable;
	}

#ifdef QSPI_BRINGUP_BUILD
	ret = sysfs_create_group(&dev->kobj, tegra_qspi_groups[0]);
	if (ret)
		goto exit_pm_disable;
	tqspi->qspi_force_bus_speed = false;
#endif
	return ret;

exit_pm_disable:
	pm_runtime_put_noidle(&pdev->dev);
	pm_runtime_disable(&pdev->dev);
	if (!pm_runtime_status_suspended(&pdev->dev))
		tegra_qspi_runtime_suspend(&pdev->dev);
	if (tqspi->clock_always_on)
		tegra_qspi_clk_disable(tqspi);
exit_deinit_dma:
	tegra_qspi_deinit_dma_param(tqspi, false);
exit_rx_dma_free:
	tegra_qspi_deinit_dma_param(tqspi, true);
exit_free_master:
	spi_master_put(master);

	return ret;
}

static int tegra_qspi_remove(struct platform_device *pdev)
{
	struct spi_master *master = dev_get_drvdata(&pdev->dev);
	struct tegra_qspi_data	*tqspi = spi_master_get_devdata(master);

#ifdef QSPI_BRINGUP_BUILD
	sysfs_remove_group(&pdev->dev.kobj, tegra_qspi_groups[0]);
#endif

	if (tqspi->tx_dma_chan)
		tegra_qspi_deinit_dma_param(tqspi, false);

	if (tqspi->rx_dma_chan)
		tegra_qspi_deinit_dma_param(tqspi, true);

	pm_runtime_put_noidle(&pdev->dev);
	pm_runtime_disable(&pdev->dev);
	if (!pm_runtime_status_suspended(&pdev->dev))
		tegra_qspi_runtime_suspend(&pdev->dev);

	if (tqspi->clock_always_on)
		tegra_qspi_clk_disable(tqspi);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int tegra_qspi_suspend(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(master);
	int ret;

	ret = spi_master_suspend(master);

	if (tqspi->clock_always_on)
		tegra_qspi_clk_disable(tqspi);

	return ret;
}

static int tegra_qspi_resume(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(master);
	int ret;

	if (tqspi->clock_always_on) {
		ret = tegra_qspi_clk_enable(tqspi);
		if (ret < 0)
			return ret;
	}
	ret = pm_runtime_get_sync(dev);
	if (ret < 0) {
		dev_err(tqspi->dev, "Failed to get runtime PM: %d\n", ret);
		return ret;
	}
	tegra_qspi_writel(tqspi, tqspi->command1_reg, QSPI_COMMAND1);
	tegra_qspi_set_gr_registers(tqspi);
	tegra_qspi_tap_delays(tqspi, tx_tap_delay, rx_tap_delay);
	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);

	return spi_master_resume(master);
}
#endif

static int tegra_qspi_runtime_suspend(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(master);

	/* Flush all write which are in PPSB queue by reading back */
	tegra_qspi_readl(tqspi, QSPI_COMMAND1);

	tegra_qspi_clk_disable(tqspi);

	return 0;
}

static int tegra_qspi_runtime_resume(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct tegra_qspi_data *tqspi = spi_master_get_devdata(master);

	return tegra_qspi_clk_enable(tqspi);
}

static const struct dev_pm_ops tegra_qspi_pm_ops = {
	SET_RUNTIME_PM_OPS(tegra_qspi_runtime_suspend,
			   tegra_qspi_runtime_resume, NULL)
	SET_SYSTEM_SLEEP_PM_OPS(tegra_qspi_suspend, tegra_qspi_resume)
};

static const struct of_device_id tegra_qspi_of_match[] = {
	{ .compatible = "nvidia,tegra186-qspi", },
	{ .compatible = "nvidia,tegra210-qspi", },
	{}
};
MODULE_DEVICE_TABLE(of, tegra_qspi_of_match);

static struct platform_driver tegra_qspi_driver = {
	.driver = {
		.name		= "tegra-qspi",
		.pm		= &tegra_qspi_pm_ops,
		.of_match_table	= tegra_qspi_of_match,
	},
	.probe =	tegra_qspi_probe,
	.remove =	tegra_qspi_remove,
};
module_platform_driver(tegra_qspi_driver);

MODULE_DESCRIPTION("NVIDIA Tegra186 QSPI Controller Driver");
MODULE_AUTHOR("Laxman Dewangan <ldewangan@nvidia.com>");
MODULE_AUTHOR("Amlan Kundu <akundu@nvidia.com>");
MODULE_LICENSE("GPL v2");
