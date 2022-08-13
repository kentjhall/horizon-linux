/*
 * MTD SPI driver for qspi flash chips
 *
 * Author: Mike Lavender, mike@steroidmicros.com
 * Copyright (c) 2005, Intec Automation Inc.
 * Copyright (c) 2013-2021, NVIDIA CORPORATION. All rights reserved.
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mod_devicetable.h>

#include <linux/mtd/cfi.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/of_platform.h>

#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <linux/mtd/qspi_mtd.h>

/*
 * NOTE: Below Macro is used to optimize the QPI/QUAD mode switch logic...
 * - QPI/QUAD mode is used for flash write. QUAD mode is used for flash read.
 * - When QPI is enabled, QUAD is don't care.
 * - If below macro is disabled...
 *  o QPI/QUAD mode is enabled/disabled at the start/end of each flash write
 *    function call.
 *  o QUAD mode is enabled/disabled at the start/end of each flash read
 *    function call.
 * - If below macro is enabled...
 *  o QPI/QUAD mode is enabled at the start of flash write. QPI/QUAD mode is
 *    disabled whenever erase is invoked. QPI mode is disabled on read.
 *  o QUAD mode is enabled at the start of flash read. QUAD mode is disabled
 *    whenever erase is invoked. QUAD is don't care in QPI mode.
 */
#define QMODE_SWITCH_OPTIMIZED

#define COMMAND_WIDTH				1
#define ADDRESS_WIDTH				4
#define WE_RETRY_COUNT				200
#define WIP_RETRY_COUNT				2000000
#define QUAD_ENABLE_WAIT_TIME			1000
#define WRITE_ENABLE_WAIT_TIME			10
#define WRITE_ENABLE_SLEEP_TIME			10
#define WIP_ENABLE_WAIT_TIME			10
#define WIP_ENABLE_SLEEP_TIME			50
#define BITS8_PER_WORD				8
#define BITS16_PER_WORD				16
#define BITS32_PER_WORD				32
#define RWAR_SR1NV				0x0
#define RWAR_CR1NV				0x2
#define RWAR_SR1V				0x00800000
#define RWAR_CR1V				0x00800002
#define RWAR_CR2V				0x00800003
#define RWAR_CR3V				0x00800004
#define WRAR					0x71
#define SR1NV_WRITE_DIS				(1<<7)
#define SR1NV_BLOCK_PROT			(0x7<<2)
#define CR3V_512PAGE_SIZE			(1<<4)
#define RDCR_DUMMY_CYCLE			(3<<6)

#define JEDEC_ID_S25FX512S	0x010220
#define JEDEC_ID_S25FS256S	0x010219
#define JEDEC_ID_MX25U51279G	0xC2953A
#define JEDEC_ID_MX75U25690F	0xC22939
#define JEDEC_ID_MX25U3235F	0xC22536

static uint8_t macronix_device_id;
static int qspi_write_en(struct qspi *flash,
		uint8_t is_enable, uint8_t is_sleep);
static int wait_till_ready(struct qspi *flash, uint8_t is_sleep);
static int qspi_read_any_reg(struct qspi *flash,
			uint32_t regaddr, uint8_t *pdata);
static int qspi_write_any_reg(struct qspi *flash,
		uint32_t regaddr, uint8_t data);
static void set_mode(struct spi_transfer *tfr, uint8_t is_ddr,
		uint8_t bus_width, uint8_t op_code);

static inline struct qspi *mtd_to_qspi(struct mtd_info *mtd)
{
	return container_of(mtd, struct qspi, mtd);
}

#ifdef QSPI_BRINGUP_BUILD
static int max_qpi_set(struct qspi *flash, uint8_t is_set)
{
	uint8_t tx_buf[1];
	int err, status = PASS;
	struct spi_message m;
	struct spi_transfer t;
	uint8_t code;

	code = (is_set) ? OPCODE_QPI_ENABLE : OPCODE_QPI_DISABLE;
	tx_buf[0] = code;

	spi_message_init(&m);

	memset(&t, 0, sizeof(t));
	t.len = COMMAND_WIDTH;
	t.tx_buf = tx_buf;
	t.bits_per_word = BITS8_PER_WORD;

	set_mode(&t, FALSE, flash->curr_cmd_mode, STATUS_READ);
	spi_message_add_tail(&t, &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed %d", __func__, err);
		status = FAIL;
	}

	return status;
}
/*
 * Enable/ Disable QPI Mode. Shall be called with
 * 1. flash->lock taken.
 * 2. WIP bit cleared
 */

static int qspi_qpi_flag_set(struct qspi *flash, uint8_t is_set)
{
	uint8_t regval;
	int status = PASS;

	dev_dbg(&flash->spi->dev, "%s %d\n", __func__, is_set);

	if (((flash->curr_cmd_mode == X4) && is_set) ||
			((flash->curr_cmd_mode == X1) && !is_set)) {
		return status;
	}

	if (flash->flash_info->jedec_id == JEDEC_ID_MX25U51279G) {
		max_qpi_set(flash, is_set);
	} else {
		status = qspi_read_any_reg(flash, RWAR_CR2V, &regval);
		if (status) {
			dev_err(&flash->spi->dev,
				"error: %s CR2V read failed: ", __func__);
			dev_err(&flash->spi->dev,
				"bset: %d, status: x%x\n", is_set, status);
			return status;
		}

		if (is_set)
			regval |= QPI_ENABLE;
		else
			regval &= ~QPI_ENABLE;

		status = qspi_write_any_reg(flash, RWAR_CR2V, regval);
		if (status) {
			dev_err(&flash->spi->dev,
				"error: %s CR2V write failed: ", __func__);
			dev_err(&flash->spi->dev,
				"bset: %d, status: x%x\n", is_set, status);
			return status;
		}
	}

	if (is_set)
		flash->curr_cmd_mode = X4;
	else
		flash->curr_cmd_mode = X1;

	status = wait_till_ready(flash, FALSE);
	if (status) {
		dev_err(&flash->spi->dev,
			"error: %s: WIP failed: ", __func__);
		dev_err(&flash->spi->dev,
			"bset:%d, status: x%x\n", is_set, status);
	}

	return status;
}

static ssize_t force_sdr_set(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct qspi *flash = dev_get_drvdata(dev);

	if (flash && count) {
		flash->force_sdr = ((buf[0] - '0') > 0);
		return count;
	}

	return -ENODEV;
}

static ssize_t force_sdr_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qspi *flash = dev_get_drvdata(dev);

	return sprintf(buf, "%d", flash->force_sdr);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_force_sdr, 0644, force_sdr_show,
						force_sdr_set);

static ssize_t qspi_mode_set(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct qspi *flash = dev_get_drvdata(dev);
	u16 mode;

	if (flash && count) {
		mode = (buf[0] - '0') & (SPI_CPHA|SPI_CPOL);
		flash->spi->mode &= ~(SPI_CPHA|SPI_CPOL);
		flash->spi->mode |= mode;
		return count;
	}

	return -ENODEV;
}

static ssize_t qspi_mode_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qspi *flash = dev_get_drvdata(dev);
	u16 mode = flash->spi->mode & (SPI_CPHA|SPI_CPOL);

	return sprintf(buf, "%d\n", mode);
}

static DEVICE_ATTR(qspi_mode, 0644, qspi_mode_show, qspi_mode_set);

static ssize_t enable_qpi_mode_set(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct qspi *flash = dev_get_drvdata(dev);

	if (flash && count) {
		flash->enable_qpi_mode = ((buf[0] - '0') > 0);
		if (flash->enable_qpi_mode)
			qspi_qpi_flag_set(flash, TRUE);
		else
			qspi_qpi_flag_set(flash, FALSE);
		return count;
	}

	return -ENODEV;
}

static ssize_t enable_qpi_mode_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qspi *flash = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", flash->enable_qpi_mode);
}

static DEVICE_ATTR(qspi_enable_qpi_mode, 0644, enable_qpi_mode_show,
		enable_qpi_mode_set);

static ssize_t force_bus_width_set(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct qspi *flash = dev_get_drvdata(dev);
	u8 bus_width;

	if (flash && count) {
		bus_width = buf[0] - '0';
		flash->override_bus_width = 1;
		switch (bus_width) {
		case 1:
			flash->qspi_bus_width = X1;
			break;
		case 2:
			flash->qspi_bus_width = X2;
			break;
		case 4:
			flash->qspi_bus_width = X4;
			break;
		default:
			flash->override_bus_width = 0;
			break;
		}
		return count;
	}

	return -ENODEV;
}

static ssize_t force_bus_width_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qspi *flash = dev_get_drvdata(dev);
	char *bus_width_str = "invalid";

	switch (flash->qspi_bus_width) {
	case X1:
		bus_width_str = "X1";
		break;
	case X2:
		bus_width_str = "X2";
		break;
	case X4:
		bus_width_str = "X4";
		break;
	default:
		bus_width_str = "invalid";
		break;
	}
	return sprintf(buf, "overide = %d bus_width = %s\n",
		       flash->override_bus_width, bus_width_str);

	return -ENODEV;
}

static DEVICE_ATTR(qspi_force_bus_width, 0644, force_bus_width_show,
		force_bus_width_set);

static ssize_t bits_per_word_set(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct qspi *flash;
	u16 bits_per_word;
	char tmp;
	int8_t read;
	/* Read upto a maximum of 3 characters. */
	const int8_t MAX_READ = 3;

	if (dev == NULL || buf == NULL)
		return -EINVAL;

	flash = dev_get_drvdata(dev);
	if (flash == NULL)
		return -ENODEV;

	bits_per_word = 0;
	read = (int8_t) ((count <= MAX_READ) ? count : MAX_READ);
	while (read-- > 0) {
		tmp = *buf++;
		if (tmp < '0' || tmp > '9')
			break;

		bits_per_word = bits_per_word * 10 + (tmp - '0');
	}

	/* Set iff the input is a valid BPW. */
	if (bits_per_word == BITS8_PER_WORD ||
		bits_per_word == BITS16_PER_WORD ||
		bits_per_word == BITS32_PER_WORD)
		flash->qspi_bits_per_word = (u8) bits_per_word;

	return count;
}

static ssize_t bits_per_word_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct qspi *flash;

	if (dev == NULL || buf == NULL)
		return -EINVAL;

	flash = dev_get_drvdata(dev);
	if (flash == NULL)
		return -ENODEV;

	return sprintf(buf, "%u", flash->qspi_bits_per_word);
}

static DEVICE_ATTR(qspi_bits_per_word, 0644, bits_per_word_show,
		bits_per_word_set);

static struct attribute *qspi_mtd_attrs[] = {
	&dev_attr_qspi_force_sdr.attr,
	&dev_attr_qspi_mode.attr,
	&dev_attr_qspi_enable_qpi_mode.attr,
	&dev_attr_qspi_force_bus_width.attr,
	&dev_attr_qspi_bits_per_word.attr,
	NULL,
};

ATTRIBUTE_GROUPS(qspi_mtd);

#endif
/*
 * Set Mode for transfer request
 * Function sets Bus width, DDR/SDR and opcode
 */

static void set_mode(struct spi_transfer *tfr, uint8_t is_ddr,
		uint8_t bus_width, uint8_t op_code)
{
	tfr->delay_usecs = set_op_mode(op_code) | set_bus_width(bus_width);
	if (is_ddr)
		tfr->delay_usecs |= set_sdr_ddr;
}

/*
 * Copy Paramters from default command table
 * Command table contains command, address and data
 * related information associated with opcode
 */

static void copy_cmd_default(struct qcmdset *qcmd, struct qcmdset *cmd_table)
{
	qcmd->qcmd.op_code = cmd_table->qcmd.op_code;
	qcmd->qcmd.is_ddr = cmd_table->qcmd.is_ddr;
	qcmd->qcmd.bus_width = cmd_table->qcmd.bus_width;
	qcmd->qcmd.post_txn = cmd_table->qcmd.post_txn;
	qcmd->qaddr.address = cmd_table->qaddr.address;
	qcmd->qaddr.is_ddr = cmd_table->qaddr.is_ddr;
	qcmd->qaddr.len = cmd_table->qaddr.len;
	qcmd->qaddr.bus_width = cmd_table->qaddr.bus_width;
	qcmd->qaddr.dummy_cycles = cmd_table->qaddr.dummy_cycles;
	qcmd->qdata.is_ddr = cmd_table->qdata.is_ddr;
	qcmd->qdata.bus_width = cmd_table->qdata.bus_width;
}

static int max_enable_4byte(struct qspi *flash)
{
	uint8_t tx_buf[1];
	int err, status = PASS;
	struct spi_message m;
	struct spi_transfer t;
	uint8_t code = OPCODE_4BYTE_ENABLE;

	tx_buf[0] = code;

	spi_message_init(&m);

	memset(&t, 0, sizeof(t));
	t.len = COMMAND_WIDTH;
	t.tx_buf = tx_buf;
	t.bits_per_word = BITS8_PER_WORD;

	set_mode(&t, FALSE, flash->curr_cmd_mode, STATUS_READ);
	spi_message_add_tail(&t, &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed %d", __func__, err);
		status = FAIL;
	}

	return status;
}

/*
 * Copy Paramters from default command table
 * Command table contains command, address and data
 * related information associated with opcode
 */

static int read_sr1_reg(struct qspi *flash, uint8_t *regval)
{
	uint8_t tx_buf[1], rx_buf[1];
	int status = PASS, err;
	struct spi_transfer t[2];
	struct spi_message m;
	uint8_t code = RDSR1;

	spi_message_init(&m);

	memset(t, 0, sizeof(t));
	tx_buf[0] = code;
	t[0].len = COMMAND_WIDTH;
	t[0].tx_buf = tx_buf;
	t[0].bits_per_word = BITS8_PER_WORD;
	set_mode(&t[0], FALSE, flash->curr_cmd_mode, STATUS_READ);

	spi_message_add_tail(&t[0], &m);
	t[1].len = COMMAND_WIDTH;
	t[1].rx_buf = rx_buf;
	t[1].bits_per_word = BITS8_PER_WORD;
	set_mode(&t[1], FALSE, flash->curr_cmd_mode, STATUS_READ);

	spi_message_add_tail(&t[1], &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed %d",
			__func__, status);
		status = FAIL;
	}

	*regval = rx_buf[0];
	return status;
}

static int read_max_cfg_reg(struct qspi *flash, uint8_t *regval)
{
	uint8_t rx_buf[1], tx_buf[1];
	int err, status = PASS;
	struct spi_message m;
	struct spi_transfer t[2];
	uint8_t code = MX_RDCR;

	tx_buf[0] = code;

	spi_message_init(&m);

	memset(t, 0, sizeof(t));
	t[0].len = COMMAND_WIDTH;
	t[0].tx_buf = tx_buf;
	t[0].bits_per_word = BITS8_PER_WORD;

	set_mode(&t[0], FALSE, flash->curr_cmd_mode, STATUS_READ);
	spi_message_add_tail(&t[0], &m);

	t[1].len = COMMAND_WIDTH;
	t[1].rx_buf = rx_buf;
	t[1].bits_per_word = BITS8_PER_WORD;

	set_mode(&t[1], FALSE, flash->curr_cmd_mode, STATUS_READ);
	spi_message_add_tail(&t[1], &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed %d", __func__, err);
		status = FAIL;
	}

	*regval = rx_buf[0];
	return status;
}

static int qspi_write_status_cfgr_reg(struct qspi *flash, uint8_t sr,
				      uint8_t cfgr, bool write_cfg)
{
	uint8_t tx_buf[3];
	int err, status = PASS;
	struct spi_message m;
	struct spi_transfer t;
	uint8_t code = MX_WRSR;

	tx_buf[0] = code;
	tx_buf[1] = sr;
	if (write_cfg)
		tx_buf[2] = cfgr;

	err = qspi_write_en(flash, TRUE, FALSE);
	if (err) {
		dev_err(&flash->spi->dev, "%s: WE failed\n", __func__);
		return err;
	}

	spi_message_init(&m);

	memset(&t, 0, sizeof(t));
	if (write_cfg)
		t.len = COMMAND_WIDTH + 2;
	else
		t.len = COMMAND_WIDTH + 1;
	t.tx_buf = tx_buf;
	t.bits_per_word = BITS8_PER_WORD;

	set_mode(&t, FALSE, flash->curr_cmd_mode, STATUS_READ);
	spi_message_add_tail(&t, &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed %d", __func__, err);
		status = FAIL;
	}

	return status;
}

static int qspi_write_status_reg(struct qspi *flash, uint8_t sr, uint8_t cfgr)
{
	return qspi_write_status_cfgr_reg(flash, sr, cfgr, TRUE);
}

/*
 * Function to read mutiple bytes for eg
 * can be used for RDID command
 */
static __maybe_unused int read_multi(struct qspi *flash, uint8_t code,
				uint8_t *buff, uint32_t len)
{
	int err = PASS;
	struct spi_transfer t[2];
	struct spi_message m;

	spi_message_init(&m);

	memset(t, 0, sizeof(t));
	t[0].len = COMMAND_WIDTH;
	t[0].tx_buf = &code;
	t[0].bits_per_word = BITS8_PER_WORD;
	set_mode(&t[0], FALSE, flash->curr_cmd_mode, STATUS_READ);

	spi_message_add_tail(&t[0], &m);
	t[1].len = len;
	t[1].rx_buf = buff;
	t[1].bits_per_word = BITS8_PER_WORD;
	set_mode(&t[1], FALSE, flash->curr_cmd_mode, STATUS_READ);

	spi_message_add_tail(&t[1], &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed %d",
			__func__, err);
		return err;
	}

	return err;
}

/*
 * Function for WRAR command. Shall be called with
 * 1. flash->lock taken.
 * 2. WIP bit cleared
 * NOTE: Caller needs to poll for WIP
 */
static int qspi_write_any_reg(struct qspi *flash,
			uint32_t regaddr, uint8_t data)
{
	uint8_t cmd_addr_buf[4];
	struct spi_transfer t[3];
	struct spi_message m;
	struct qcmdset *cmd_table;
	int err;

	cmd_table = &flash->cmd_info_table[WRITE_ANY_REG];

	err = qspi_write_en(flash, TRUE, FALSE);
	if (err) {
		dev_err(&flash->spi->dev,
			"error: %s: WE failed: reg:x%x data:x%x, Status: x%x ",
			__func__, regaddr, data, err);
		return err;
	}

	spi_message_init(&m);
	memset(t, 0, sizeof(t));

	cmd_addr_buf[0] = cmd_table->qcmd.op_code;
	cmd_addr_buf[1] = (regaddr >> 16) & 0xFF;
	cmd_addr_buf[2] = (regaddr >> 8) & 0xFF;
	cmd_addr_buf[3] = regaddr & 0xFF;

	t[0].tx_buf = cmd_addr_buf;
	t[0].len = cmd_table->qaddr.len + 1;
	t[0].bits_per_word = BITS8_PER_WORD;
	set_mode(&t[0], cmd_table->qaddr.is_ddr,
		flash->curr_cmd_mode, cmd_table->qcmd.op_code);
	spi_message_add_tail(&t[0], &m);

	t[1].tx_buf = &data;
	t[1].len = 1;
	t[1].bits_per_word = BITS8_PER_WORD;
	set_mode(&t[1], cmd_table->qdata.is_ddr,
		flash->curr_cmd_mode, cmd_table->qcmd.op_code);
	t[1].cs_change = TRUE;
	spi_message_add_tail(&t[1], &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync Failed: reg:x%x dat:x%x sts:x%x\n",
			__func__, regaddr, data, err);
		return err;
	}

	return err;
}

/*
 * Function for RDAR command. Shall be called with
 * 1. flash->lock taken.
 * 2. WIP bit cleared
 */
static int qspi_read_any_reg(struct qspi *flash,
			uint32_t regaddr, uint8_t *pdata)
{
	uint8_t cmd_addr_buf[5];
	struct spi_transfer t[3];
	struct spi_message m;
	struct qcmdset *cmd_table;
	int err;

	cmd_table = &flash->cmd_info_table[READ_ANY_REG];

	spi_message_init(&m);
	memset(t, 0, sizeof(t));

	cmd_addr_buf[0] = cmd_table->qcmd.op_code;
	cmd_addr_buf[1] = (regaddr >> 16) & 0xFF;
	cmd_addr_buf[2] = (regaddr >> 8) & 0xFF;
	cmd_addr_buf[3] = regaddr & 0xFF;

	t[0].len = 1;
	t[0].bits_per_word = BITS8_PER_WORD;
	t[0].tx_buf = &cmd_addr_buf[0];
	set_mode(&t[0], cmd_table->qcmd.is_ddr,
		flash->curr_cmd_mode, cmd_table->qcmd.op_code);
	spi_message_add_tail(&t[0], &m);

	if (flash->curr_cmd_mode == X4)
		t[1].len = cmd_table->qaddr.len +
				4 * cmd_table->qaddr.dummy_cycles;
	else
		t[1].len = cmd_table->qaddr.len + cmd_table->qaddr.dummy_cycles;

	t[1].bits_per_word = BITS8_PER_WORD;
	t[1].tx_buf = &cmd_addr_buf[1];
	set_mode(&t[1], cmd_table->qaddr.is_ddr,
		flash->curr_cmd_mode, cmd_table->qcmd.op_code);
	spi_message_add_tail(&t[1], &m);

	t[2].len = 1;
	t[2].bits_per_word = BITS8_PER_WORD;
	t[2].rx_buf = pdata;
	set_mode(&t[2], cmd_table->qdata.is_ddr,
		flash->curr_cmd_mode, cmd_table->qcmd.op_code);
	/* in-activate the cs at the end */
	t[2].cs_change = TRUE;
	spi_message_add_tail(&t[2], &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call Failed: ", __func__);
		dev_err(&flash->spi->dev, "reg:x%x, Status: x%x ",
			regaddr, err);
		return err;
	}

	return 0;
}

static uint8_t qspi_flash_get_sfdp_id_macronix(struct qspi *flash)
{
	struct spi_transfer t[3];
	struct spi_message m;
	int ret;
	/* 3-byte address for getting SFDP-Value at address 0x0b from
	 * SFDP table. MSB first
	 */
	uint8_t cmd_addr_buf[4] = {0, 0, 0, SFDP_ADDR};
	uint8_t rx_buff[2];

	spi_message_init(&m);
	memset(t, 0, sizeof(t));

	/* take lock here to protect race condition
	 * in case of concurrent read and write with
	 * different cmd_mode selection.
	 */
	mutex_lock(&flash->lock);

	/* Set Controller data Parameters
	 * Set DDR/SDR, X1/X4 and Dummy Cycles from DT
	 */

	copy_cmd_default(&flash->cmd_table,
		&flash->cmd_info_table[READ_SFDP]);

	cmd_addr_buf[0] = flash->cmd_table.qcmd.op_code;

	t[0].len = 1;
	t[0].bits_per_word = BITS8_PER_WORD;
	t[0].tx_buf = &cmd_addr_buf[0];

	set_mode(&t[0],
		flash->cmd_table.qcmd.is_ddr,
		flash->cmd_table.qcmd.bus_width,
		flash->cmd_table.qcmd.op_code);

	spi_message_add_tail(&t[0], &m);

	t[1].len = ((flash->cmd_table.qaddr.len +
		(flash->cmd_table.qaddr.dummy_cycles/8)));
	t[1].bits_per_word = BITS8_PER_WORD;
	t[1].tx_buf = &cmd_addr_buf[1];

	set_mode(&t[1],
		flash->cmd_table.qaddr.is_ddr,
		flash->cmd_table.qaddr.bus_width,
		flash->cmd_table.qcmd.op_code);

	spi_message_add_tail(&t[1], &m);

	t[2].len = 2;
	t[2].bits_per_word = BITS8_PER_WORD;
	t[2].rx_buf = rx_buff;
	set_mode(&t[2],
		flash->cmd_table.qdata.is_ddr,
		flash->cmd_table.qdata.bus_width,
		flash->cmd_table.qcmd.op_code);

	/* in-activate the cs at the end */
	t[2].cs_change = TRUE;
	spi_message_add_tail(&t[2], &m);

	ret = spi_sync(flash->spi, &m);
	mutex_unlock(&flash->lock);

	/* since rx_buff[0] has the SPDF value for address 0x0b, so return
	 * rx_buff[0]
	 */
	return rx_buff[0];
}

static int max_dummy_cyle_set(struct qspi *flash, uint8_t cmd_code, int dummy)
{
	int status = PASS;
	uint8_t my_status, my_cfg, dummy_code = 0;

	if (cmd_code == flash->cmd_info_table[FAST_READ].qcmd.op_code) {
		switch (dummy) {
		case 6:
			dummy_code = 2;
			break;
		case 8:
			dummy_code = 1;
			break;
		case 10:
			dummy_code = 0;
			break;
		}
	}

	if (cmd_code == flash->cmd_info_table[DUAL_IO_READ].qcmd.op_code) {
		switch (dummy / 2) {
		case 4:
			dummy_code = 3;
			break;
		case 6:
			dummy_code = 2;
			break;
		case 8:
			dummy_code = 1;
			break;
		case 10:
			dummy_code = 0;
			break;
		}
	}

	if (cmd_code == flash->cmd_info_table[QUAD_IO_READ].qcmd.op_code) {
		switch (dummy / 4) {
		case 4:
			dummy_code = 2;
			break;
		case 6:
			dummy_code = 3;
			break;
		case 8:
			dummy_code = 1;
			break;
		case 10:
			dummy_code = 0;
			break;
		}
	}

	if (cmd_code == flash->cmd_info_table[DDR_QUAD_IO_READ].qcmd.op_code) {
		switch (dummy / 8) {
		case 4:
			dummy_code = 2;
			break;
		case 6:
			dummy_code = 3;
			break;
		case 8:
			dummy_code = 1;
			break;
		case 10:
			dummy_code = 0;
			break;
		}
	}

	read_sr1_reg(flash, &my_status);
	read_max_cfg_reg(flash, &my_cfg);
	dev_dbg(&flash->spi->dev, "status:%02x, cfg:%02x\n", my_status, my_cfg);

	if (macronix_device_id == SFDP_ID_MX25U3235F) {
		my_cfg &= ~RDCR_DUMMY_CYCLE;
		my_cfg |= dummy_code << 6;
	} else if ((macronix_device_id == SFDP_ID_MX25U3232F) ||
			(flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F)) {
		/* If DC[1:0]=0b11 for MX25U3232F sets, dummy-cycle increased
		 * from 6-cycle to 10-cycle
		 */
		my_cfg &= ~(3<<10);
		my_cfg |= dummy_code << 10;
	} else {
		dev_err(&flash->spi->dev, "Invalid macronix_device_id:%x\n",
			macronix_device_id);
		return -EINVAL;
	}
	qspi_write_status_reg(flash, my_status, my_cfg);

	read_sr1_reg(flash, &my_status);
	read_max_cfg_reg(flash, &my_cfg);
	dev_dbg(&flash->spi->dev, "status:%02x, cfg:%02x\n", my_status, my_cfg);

	return status;
}


/*
 * Enable/Disable QUAD flasg when QPI mode is disabled
 * Shall be called with...
 * 1. flash->lock taken.
 * 2. WIP bit cleared
 */
static int qspi_quad_flag_set(struct qspi *flash, uint8_t is_set)
{
	uint8_t regval;
	int status = PASS;
	uint8_t my_status, my_cfg;

	dev_dbg(&flash->spi->dev, "%s %d\n", __func__, is_set);

	if ((flash->is_quad_set && is_set) ||
		(!flash->is_quad_set && !is_set)) {
		return status;
	}
	if (flash->flash_info->jedec_id == JEDEC_ID_MX25U3235F) {
		read_sr1_reg(flash, &my_status);
		if (is_set)
			my_status |= MX_QUAD_ENABLE;
		else
			my_status &= ~MX_QUAD_ENABLE;
		qspi_write_status_cfgr_reg(flash, my_status, 0, FALSE);
	} else if ((flash->flash_info->jedec_id == JEDEC_ID_MX25U51279G) ||
			(flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F)) {
		read_sr1_reg(flash, &my_status);
		read_max_cfg_reg(flash, &my_cfg);

		if (is_set)
			my_status |= MX_QUAD_ENABLE;
		else
			my_status &= ~MX_QUAD_ENABLE;
		qspi_write_status_reg(flash, my_status, my_cfg);

		read_sr1_reg(flash, &my_status);
		read_max_cfg_reg(flash, &my_cfg);
	} else {
		status = qspi_read_any_reg(flash, RWAR_CR1V, &regval);
		if (status) {
			dev_err(&flash->spi->dev,
				"error: %s CR1V read failed: ", __func__);
			dev_err(&flash->spi->dev,
				"bset: %d, status: x%x\n", is_set, status);
			return status;
		}

		if (is_set)
			regval |= QUAD_ENABLE;
		else
			regval &= ~QUAD_ENABLE;

		status = qspi_write_any_reg(flash, RWAR_CR1V, regval);
		if (status) {
			dev_err(&flash->spi->dev,
				"error: %s CR1V write failed: ", __func__);
			dev_err(&flash->spi->dev,
				"bset: %d, status: x%x\n", is_set, status);
			return status;
		}
	}

	status = wait_till_ready(flash, FALSE);
	if (status) {
		dev_err(&flash->spi->dev,
			"error: %s: WIP failed: ", __func__);
		dev_err(&flash->spi->dev,
			"bset:%d, status: x%x\n", is_set, status);
	}

	flash->is_quad_set = is_set;
	return status;
}

/*
 * Enable/ Disable Write Enable Bit in Configuration Register
 * Set WEL bit to 1 before Erase and Write Operations
 */

static int qspi_write_en(struct qspi *flash,
		uint8_t is_enable, uint8_t is_sleep)
{
	struct spi_transfer t[1];
	uint8_t cmd_buf[5], regval;
	int status = 0, err, tried = 0, comp;
	struct spi_message m;

	do {
		if (tried++ == WE_RETRY_COUNT) {
			dev_err(&flash->spi->dev,
				"tired max times not changing WE bit\n");
			return FAIL;
		}
		memset(t, 0, sizeof(t));
		spi_message_init(&m);

		if (is_enable) {
			cmd_buf[0] = OPCODE_WRITE_ENABLE;
			comp = WEL_ENABLE;
		} else {
			cmd_buf[0] = OPCODE_WRITE_DISABLE;
			comp = WEL_DISABLE;
		}

		t[0].len = COMMAND_WIDTH;
		t[0].tx_buf = cmd_buf;
		t[0].bits_per_word = BITS8_PER_WORD;

		set_mode(&t[0], FALSE, flash->curr_cmd_mode,
				STATUS_READ);

		spi_message_add_tail(&t[0], &m);

		err = spi_sync(flash->spi, &m);
		if (err < 0) {
			dev_err(&flash->spi->dev,
				"error: %s spi_sync call failed x%x",
				__func__, status);
			return 1;
		}

		if (is_sleep)
			msleep(WRITE_ENABLE_SLEEP_TIME);
		else
			udelay(WRITE_ENABLE_WAIT_TIME);

		status = read_sr1_reg(flash, &regval);
		if (status) {
			dev_err(&flash->spi->dev,
				"error: %s: RDSR1 failed: Status: x%x ",
				__func__, status);
			return status;
		}
	} while ((regval & WEL_ENABLE) != comp);

	return status;
}

/*
 * Wait till flash is ready for erase/write operations.
 * Returns negative if error occurred.
 */

static int wait_till_ready(struct qspi *flash, uint8_t is_sleep)
{
	uint8_t regval, status = PASS;
	int tried = 0;

	do {
		if (tried++ == WIP_RETRY_COUNT) {
			dev_err(&flash->spi->dev,
				"tired max times not changing WIP bit\n");
			return FAIL;
		}
		if ((tried % 20) == 0)
			dev_dbg(&flash->spi->dev,
				"Waiting in WIP iter: %d\n", tried);

		if (is_sleep)
			msleep(WIP_ENABLE_SLEEP_TIME);
		else
			udelay(WIP_ENABLE_WAIT_TIME);

		status = read_sr1_reg(flash, &regval);
		if (status) {
			dev_err(&flash->spi->dev,
				"error: %s: RDSR1 failed: Status: x%x ",
				__func__, status);
			return status;
		}
	} while ((regval & WIP_ENABLE) == WIP_ENABLE);

	return status;
}

/*
 * Erase the whole flash memory
 *
 * Returns 0 if successful, non-zero otherwise.
 */

static int erase_chip(struct qspi *flash)
{
	uint8_t cmd_opcode;
	struct spi_transfer t[1];
	struct spi_message m;
	int status;

	dev_dbg(&flash->spi->dev, "%s %lldKiB\n", __func__,
		(long long)(flash->mtd.size >> 10));

	/* Send write enable, then erase commands. */
	status = qspi_write_en(flash, TRUE, TRUE);
	if (status) {
		dev_err(&flash->spi->dev,
			"error: %s: WE failed: Status: x%x ", __func__,
			status);
		return status;
	}
	copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[ERASE_BULK]);

	/* Set up command buffer. */
	cmd_opcode = OPCODE_CHIP_ERASE;

	spi_message_init(&m);
	memset(t, 0, sizeof(t));
	t[0].len = COMMAND_WIDTH;
	t[0].bits_per_word = BITS8_PER_WORD;
	t[0].tx_buf = &cmd_opcode;
	t[0].cs_change = TRUE;
	set_mode(&t[0], FALSE,
		X1, cmd_opcode);

#ifdef QSPI_BRINGUP_BUILD
	if (flash->enable_qpi_mode)
		set_mode(&t[0], FALSE, flash->curr_cmd_mode, cmd_opcode);
#endif

	spi_message_add_tail(&t[0], &m);
	status = spi_sync(flash->spi, &m);
	if (status < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed x%x", __func__, status);
		return status;
	}

	status = wait_till_ready(flash, TRUE);
	if (status) {
		dev_err(&flash->spi->dev,
			"error: %s: WIP failed: Status: x%x ", __func__,
			status);
		return status;
	}

	return 0;
}

/*
 * Erase one sector of flash memory at offset ``offset'' which is any
 * address within the sector which should be erased.
 *
 * Returns 0 if successful, non-zero otherwise.
 */
static int erase_sector(struct qspi *flash, u32 offset,
				uint8_t erase_opcode, u32 size)
{
	uint8_t cmd_addr_buf[5];
	struct spi_transfer t[1];
	struct spi_message m;
	int err = 0;

	dev_dbg(&flash->spi->dev, "%s %dKiB at 0x%08x\n", __func__,
		size / 1024, offset);

	/* Send write enable, then erase commands. */
	err = qspi_write_en(flash, TRUE, TRUE);
	if (err) {
		dev_err(&flash->spi->dev,
			"error: %s: WE failed: Status: x%x ", __func__, err);
		return err;
	}

	cmd_addr_buf[0] = erase_opcode;
	if (flash->cmd_table.qaddr.len == 3) {
		cmd_addr_buf[1] = (offset >> 16) & 0xFF;
		cmd_addr_buf[2] = (offset >> 8) & 0xFF;
		cmd_addr_buf[3] = offset & 0xFF;
	} else {
		cmd_addr_buf[1] = (offset >> 24) & 0xFF;
		cmd_addr_buf[2] = (offset >> 16) & 0xFF;
		cmd_addr_buf[3] = (offset >> 8) & 0xFF;
		cmd_addr_buf[4] = offset & 0xFF;
	}

	spi_message_init(&m);
	memset(t, 0, sizeof(t));

	t[0].len = (COMMAND_WIDTH + flash->cmd_table.qaddr.len);
	t[0].bits_per_word = BITS8_PER_WORD;
	t[0].tx_buf = cmd_addr_buf;

	t[0].cs_change = TRUE;
	set_mode(&t[0], FALSE,
		X1, flash->erase_opcode);

#ifdef QSPI_BRINGUP_BUILD
	if (flash->enable_qpi_mode)
		set_mode(&t[0], FALSE,
				flash->curr_cmd_mode, flash->erase_opcode);
#endif

	spi_message_add_tail(&t[0], &m);

	err = spi_sync(flash->spi, &m);
	if (err < 0) {
		dev_err(&flash->spi->dev,
			"error: %s spi_sync call failed x%x", __func__, err);
		return err;
	}

	err = wait_till_ready(flash, TRUE);
	if (err) {
		dev_err(&flash->spi->dev,
			"error: %s: WIP failed: Status: x%x ", __func__, err);
		return err;
	}

	return 0;
}

/****************************************************************************/

/*
 * MTD Erase, Read and Write implementation
 */

/****************************************************************************/

/*
 * Erase an address range on the flash chip.  The address range may extend
 * one or more erase sectors.  Return an error is there is a problem erasing.
 */
static int qspi_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct qspi *flash = mtd_to_qspi(mtd);
	u32 addr, len;
	uint32_t rem;

	dev_dbg(&flash->spi->dev, "%s at 0x%llx, len %lld\n", __func__,
		(long long)instr->addr, (long long)instr->len);

	div_u64_rem(instr->len, mtd->erasesize, &rem);

	if (rem)
		return -EINVAL;

	addr = instr->addr;
	len = instr->len;

	mutex_lock(&flash->lock);
	/* whole-chip erase? */
	if (len == flash->mtd.size) {
		if (erase_chip(flash)) {
			instr->state = MTD_ERASE_FAILED;
			mutex_unlock(&flash->lock);
			return -EIO;
		}

		/* "sector"-at-a-time erase */
	} else {
		if (flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F)
			flash->cmd_info_table[ERASE_SECT].qaddr.len = 4;
		copy_cmd_default(&flash->cmd_table,
				 &flash->cmd_info_table[ERASE_SECT]);

		/* Set up command buffer. */
		flash->erase_opcode = flash->cmd_table.qcmd.op_code;
		while (len) {
			if (erase_sector(flash, addr,
				flash->erase_opcode, mtd->erasesize)) {
				instr->state = MTD_ERASE_FAILED;
				mutex_unlock(&flash->lock);
				return -EIO;
			}
			/* Take care of subsectors erase if required */
			if (flash->flash_info->n_subsectors) {
				struct  flash_info *flinfo = flash->flash_info;
				u32 ssaddr = addr;
				u32 eaddr = min((addr + mtd->erasesize),
							flinfo->ss_endoffset);

				while ((ssaddr >= flinfo->ss_soffset) &&
					((ssaddr + flinfo->ss_size) <= eaddr)) {

					dev_dbg(&flash->spi->dev,
						"Erasing subblock @ x%x, ",
						ssaddr);
					dev_dbg(&flash->spi->dev, "len x%x\n",
						flinfo->ss_size);

					if (erase_sector(flash, ssaddr,
						flinfo->ss_erase_opcode,
							flinfo->ss_size)) {
						instr->state = MTD_ERASE_FAILED;
						mutex_unlock(&flash->lock);
						return -EIO;
					}
					ssaddr += flinfo->ss_size;
				}
			}
			addr += mtd->erasesize;
			len -= mtd->erasesize;
		}
	}

	mutex_unlock(&flash->lock);

	instr->state = MTD_ERASE_DONE;
	mtd_erase_callback(instr);

	return 0;
}

/*
 * Read an address range from the flash chip.  The address range
 * may be any size provided it is within the physical boundaries.
 */
static int qspi_read(struct mtd_info *mtd, loff_t from, size_t len,
		size_t *retlen, u_char *buf)
{
	struct qspi *flash = mtd_to_qspi(mtd);
	struct spi_transfer t[3];
	struct spi_message m;
	uint8_t merge_cmd_addr = FALSE;
	uint8_t cmd_addr_buf[5];
	int err;
	struct tegra_qspi_device_controller_data *cdata
				= flash->spi->controller_data;
#ifdef QSPI_BRINGUP_BUILD
	u8 bytes_per_word = flash->qspi_bits_per_word / 8;
#endif

	dev_dbg(&flash->spi->dev, "%s from 0x%08x, len %zd\n", __func__,
		(u32)from, len);

	if (!macronix_device_id &&
		(flash->flash_info->jedec_id == JEDEC_ID_MX25U3235F)) {
		macronix_device_id = qspi_flash_get_sfdp_id_macronix(flash);
	}

	spi_message_init(&m);
	memset(t, 0, sizeof(t));

	/* take lock here to protect race condition
	 * in case of concurrent read and write with
	 * different cmd_mode selection.
	 */
	mutex_lock(&flash->lock);

	/* Set Controller data Parameters
	 * Set DDR/SDR, X1/X4 and Dummy Cycles from DT
	 */

	if (cdata) {
		if (len > cdata->x1_len_limit) {
			if (cdata->x4_is_ddr) {
				copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[DDR_QUAD_IO_READ]);
			} else {
				if (flash->flash_info->jedec_id ==
							 JEDEC_ID_MX75U25690F)
					flash->cmd_info_table[QUAD_IO_READ].
								qaddr.len = 4;
				copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[QUAD_IO_READ]);
			}
		} else {
			copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[FAST_READ]);
		}
	} else {
		if (flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F)
			flash->cmd_info_table[QUAD_IO_READ].qaddr.len = 4;
		copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[QUAD_IO_READ]);
	}

#ifdef QSPI_BRINGUP_BUILD
	if (flash->force_sdr)
		if (flash->cmd_table.qcmd.op_code ==
			flash->cmd_info_table[DDR_QUAD_IO_READ].qcmd.op_code) {
			if (flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F)
				flash->cmd_info_table[QUAD_IO_READ].qaddr.
									len = 4;
			copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[QUAD_IO_READ]);
		}

	if (flash->override_bus_width) {
		if (flash->force_sdr)
			switch (flash->qspi_bus_width) {
			case X1:
				copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[FAST_READ]);
				break;
			case X2:
				copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[DUAL_IO_READ]);
				break;
			case X4:
				copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[QUAD_IO_READ]);
				break;
			}
		else
			switch (flash->qspi_bus_width) {
			case X1:
				copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[DDR_FAST_READ]);
				break;
			case X2:
				copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[DDR_DUAL_IO_READ]);
				break;
			case X4:
				copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[DDR_QUAD_IO_READ]);
				break;
			}
	}
#endif

	/* check if possible to merge cmd and address */
	if ((flash->cmd_table.qcmd.is_ddr ==
		flash->cmd_table.qaddr.is_ddr) &&
		(flash->cmd_table.qcmd.bus_width ==
		flash->cmd_table.qaddr.bus_width) &&
		flash->cmd_table.qcmd.post_txn > 0) {

		merge_cmd_addr = TRUE;
		flash->cmd_table.qcmd.post_txn =
			flash->cmd_table.qcmd.post_txn - 1;
	}
	cmd_addr_buf[0] = flash->cmd_table.qcmd.op_code;
	if (flash->cmd_table.qaddr.len == 3) {
		cmd_addr_buf[1] = (from >> 16) & 0xFF;
		cmd_addr_buf[2] = (from >> 8) & 0xFF;
		cmd_addr_buf[3] = from & 0xFF;
	} else {
		cmd_addr_buf[1] = (from >> 24) & 0xFF;
		cmd_addr_buf[2] = (from >> 16) & 0xFF;
		cmd_addr_buf[3] = (from >> 8) & 0xFF;
		cmd_addr_buf[4] = from & 0xFF;
	}

	if (merge_cmd_addr) {

		t[0].len = (flash->cmd_table.qaddr.len + 1
			+ (flash->cmd_table.qaddr.dummy_cycles/8));
		t[0].bits_per_word = BITS8_PER_WORD;
		t[0].tx_buf = cmd_addr_buf;

		set_mode(&t[0],
			flash->cmd_table.qcmd.is_ddr,
			flash->cmd_table.qcmd.bus_width,
			flash->cmd_table.qcmd.op_code);
		spi_message_add_tail(&t[0], &m);

		t[1].len = len;
#ifdef QSPI_BRINGUP_BUILD
		t[1].bits_per_word = ((t[1].len % bytes_per_word) == 0) ?
				      flash->qspi_bits_per_word :
				      BITS8_PER_WORD;
#else
		t[1].bits_per_word = BITS8_PER_WORD;
#endif
		t[1].rx_buf = buf;
		set_mode(&t[1],
			flash->cmd_table.qdata.is_ddr,
			flash->cmd_table.qdata.bus_width,
			flash->cmd_table.qcmd.op_code);

		/* in-activate the cs at the end */
		t[1].cs_change = TRUE;
		spi_message_add_tail(&t[1], &m);

	} else {

		t[0].len = 1;
		t[0].bits_per_word = BITS8_PER_WORD;
		t[0].tx_buf = &cmd_addr_buf[0];

		set_mode(&t[0],
			flash->cmd_table.qcmd.is_ddr,
			flash->cmd_table.qcmd.bus_width,
			flash->cmd_table.qcmd.op_code);

		spi_message_add_tail(&t[0], &m);

		t[1].len = ((flash->cmd_table.qaddr.len +
			(flash->cmd_table.qaddr.dummy_cycles/8)));
		t[1].bits_per_word = BITS8_PER_WORD;
		t[1].tx_buf = &cmd_addr_buf[1];

		set_mode(&t[1],
			flash->cmd_table.qaddr.is_ddr,
			flash->cmd_table.qaddr.bus_width,
			flash->cmd_table.qcmd.op_code);

		spi_message_add_tail(&t[1], &m);

		t[2].len = len;
#ifdef QSPI_BRINGUP_BUILD
		t[2].bits_per_word = ((t[2].len % bytes_per_word) == 0) ?
				      flash->qspi_bits_per_word :
				      BITS8_PER_WORD;
#else
		t[2].bits_per_word = BITS8_PER_WORD;
#endif
		t[2].rx_buf = buf;
		set_mode(&t[2],
			flash->cmd_table.qdata.is_ddr,
			flash->cmd_table.qdata.bus_width,
			flash->cmd_table.qcmd.op_code);

		/* in-activate the cs at the end */
		t[2].cs_change = TRUE;
		spi_message_add_tail(&t[2], &m);
	}

	if (flash->flash_info->jedec_id == JEDEC_ID_MX25U51279G ||
		flash->flash_info->jedec_id == JEDEC_ID_MX25U3235F ||
			flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F) {
		max_dummy_cyle_set(flash,
				flash->cmd_table.qcmd.op_code,
				flash->cmd_table.qaddr.dummy_cycles);
	}

#ifdef QSPI_BRINGUP_BUILD
	if (flash->enable_qpi_mode)
		qspi_qpi_flag_set(flash, FALSE);
#endif

	/* Enable QUAD bit before doing QUAD i/o operation */
	if (flash->cmd_table.qdata.bus_width == X4) {
		err = qspi_quad_flag_set(flash, TRUE);
		if (err) {
			mutex_unlock(&flash->lock);
			return err;
		}
	}

	spi_sync(flash->spi, &m);
	*retlen = m.actual_length -
		(flash->cmd_table.qaddr.len + 1 +
		(flash->cmd_table.qaddr.dummy_cycles/8));

	mutex_unlock(&flash->lock);
	return 0;
}

static int qspi_write(struct mtd_info *mtd, loff_t to, size_t len,
		size_t *retlen, const u_char *buf)
{
	struct qspi *flash = mtd_to_qspi(mtd);
	u32 page_offset, page_size;
	struct spi_transfer t[2];
	struct spi_message m;
	uint8_t cmd_addr_buf[5];
	uint8_t opcode;
	int err = 0;
	u32 offset = (unsigned long)to;
	struct tegra_qspi_device_controller_data *cdata =
					flash->spi->controller_data;
#ifdef QSPI_BRINGUP_BUILD
	u8 bytes_per_word = flash->qspi_bits_per_word / 8;
#endif

	dev_dbg(&flash->spi->dev, "%s to 0x%08x, len %zd\n", __func__, (u32)to,
		len);

	mutex_lock(&flash->lock);

	if (flash->flash_info->jedec_id == JEDEC_ID_MX75U25690F)
		flash->cmd_info_table[PAGE_PROGRAM].qaddr.len = 4;
	/* Set Controller data Parameters
	 * Set DDR/SDR, X1/X4 and Dummy Cycles from DT
	 */

	if (cdata) {
		if (len > cdata->x1_len_limit) {
			copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[PAGE_PROGRAM]);
		} else {
			copy_cmd_default(&flash->cmd_table,
					&flash->cmd_info_table[PAGE_PROGRAM]);
		}
	} else {
		copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[PAGE_PROGRAM]);
	}

#ifdef QSPI_BRINGUP_BUILD
	if (flash->enable_qpi_mode) {
		copy_cmd_default(&flash->cmd_table,
				&flash->cmd_info_table[QPI_PAGE_PROGRAM]);
	}
#endif

	cmd_addr_buf[0] = opcode = flash->cmd_table.qcmd.op_code;
	if (flash->cmd_table.qaddr.len != 4) {
		cmd_addr_buf[1] = (offset >> 16) & 0xFF;
		cmd_addr_buf[2] = (offset >> 8) & 0xFF;
		cmd_addr_buf[3] = offset & 0xFF;
	} else {
		cmd_addr_buf[1] = (offset >> 24) & 0xFF;
		cmd_addr_buf[2] = (offset >> 16) & 0xFF;
		cmd_addr_buf[3] = (offset >> 8) & 0xFF;
		cmd_addr_buf[4] = offset & 0xFF;
	}
	page_offset = offset & (flash->page_size - 1);

	/* do all the bytes fit onto one page? */
	if (page_offset + len <= flash->page_size) {

		spi_message_init(&m);
		memset(t, 0, sizeof(t));
		t[0].tx_buf = cmd_addr_buf;
		t[0].len = flash->cmd_table.qaddr.len + 1;
		t[0].bits_per_word = BITS8_PER_WORD;
		set_mode(&t[0], flash->cmd_table.qcmd.is_ddr,
			flash->cmd_table.qcmd.bus_width, opcode);

		spi_message_add_tail(&t[0], &m);

		t[1].tx_buf = buf;

		t[1].len = len;
#ifdef QSPI_BRINGUP_BUILD
		t[1].bits_per_word = ((t[1].len % bytes_per_word) == 0) ?
				      flash->qspi_bits_per_word :
				      BITS8_PER_WORD;
#else
		t[1].bits_per_word = BITS8_PER_WORD;
#endif
		set_mode(&t[1], flash->cmd_table.qcmd.is_ddr,
			flash->cmd_table.qdata.bus_width, opcode);

		t[1].cs_change = TRUE;
		spi_message_add_tail(&t[1], &m);
		/* Wait until finished previous write command. */
#ifdef QSPI_BRINGUP_BUILD
		if (flash->enable_qpi_mode)
			err = qspi_qpi_flag_set(flash, TRUE);
#endif
		if (err) {
			dev_err(&flash->spi->dev,
				"error: %s: QPI/QUAD set failed: Status: x%x ",
				__func__, err);
			mutex_unlock(&flash->lock);
			return err;
		}

		err = qspi_write_en(flash, TRUE, FALSE);
		if (err) {
			dev_err(&flash->spi->dev,
				"error: %s: WE failed: Status: x%x ",
				__func__, err);
			goto clear_qmode;
		}

		spi_sync(flash->spi, &m);

		err = wait_till_ready(flash, FALSE);
		if (err) {
			dev_err(&flash->spi->dev,
				"error: %s: WIP failed: Status: x%x ",
				__func__, err);
			goto clear_qmode;
		}

		*retlen = m.actual_length - (flash->cmd_table.qaddr.len + 1);
clear_qmode:
		mutex_unlock(&flash->lock);
		return err;
	} else {
		u32 i;
		spi_message_init(&m);
		memset(t, 0, sizeof(t));

		/* the size of data remaining on the first page */
		page_size = flash->page_size - page_offset;
		t[0].tx_buf = cmd_addr_buf;
		t[0].len = flash->cmd_table.qaddr.len + 1;

		t[0].bits_per_word = BITS8_PER_WORD;
		set_mode(&t[0], flash->cmd_table.qcmd.is_ddr,
			flash->cmd_table.qcmd.bus_width, opcode);

		spi_message_add_tail(&t[0], &m);

		t[1].tx_buf = buf;

		t[1].len = page_size;
#ifdef QSPI_BRINGUP_BUILD
		t[1].bits_per_word = ((t[1].len % bytes_per_word) == 0) ?
				      flash->qspi_bits_per_word :
				      BITS8_PER_WORD;
#else
		t[1].bits_per_word = BITS8_PER_WORD;
#endif
		set_mode(&t[1], flash->cmd_table.qcmd.is_ddr,
			flash->cmd_table.qdata.bus_width, opcode);

		t[1].cs_change = TRUE;
		spi_message_add_tail(&t[1], &m);

#ifdef QSPI_BRINGUP_BUILD
		if (flash->enable_qpi_mode)
			err = qspi_qpi_flag_set(flash, TRUE);
#endif
		if (err) {
			dev_err(&flash->spi->dev,
				"error: %s: QPI/QUAD set failed: Status: x%x ",
				__func__, err);
			mutex_unlock(&flash->lock);
			return 1;
		}

		err = qspi_write_en(flash, TRUE, FALSE);
		if (err) {
			dev_err(&flash->spi->dev,
				"error: %s: WE failed: Status: x%x ",
				__func__, err);
			goto clear_qmode1;
		}

		spi_sync(flash->spi, &m);

		err = wait_till_ready(flash, FALSE);
		if (err) {
			dev_err(&flash->spi->dev,
				"error: %s: WIP failed: Status: x%x ",
				__func__, err);
			goto clear_qmode1;
		}

		*retlen = m.actual_length - (flash->cmd_table.qaddr.len + 1);

		/* write everything in flash->page_size chunks */
		for (i = page_size; i < len; i += page_size) {
			page_size = len - i;
			if (page_size > flash->page_size)
				page_size = flash->page_size;
			/* Need to check for auto address increment */
			/* Check line no 584 to 597 code is required */
			spi_message_init(&m);
			memset(t, 0, sizeof(t));

			offset = to + i;

			/* write the next page to flash */
			cmd_addr_buf[0] = opcode =
				flash->cmd_table.qcmd.op_code;
			if (flash->cmd_table.qaddr.len == 3) {
				cmd_addr_buf[1] = (offset >> 16) & 0xFF;
				cmd_addr_buf[2] = (offset >> 8) & 0xFF;
				cmd_addr_buf[3] = offset & 0xFF;
			} else {
				cmd_addr_buf[1] = (offset >> 24) & 0xFF;
				cmd_addr_buf[2] = (offset >> 16) & 0xFF;
				cmd_addr_buf[3] = (offset >> 8) & 0xFF;
				cmd_addr_buf[4] = offset & 0xFF;
			}

			t[0].tx_buf = cmd_addr_buf;
			t[0].len = flash->cmd_table.qaddr.len + 1;

			t[0].bits_per_word = BITS8_PER_WORD;
			set_mode(&t[0],
				flash->cmd_table.qcmd.is_ddr,
				flash->cmd_table.qcmd.bus_width,
				opcode);

			spi_message_add_tail(&t[0], &m);

			t[1].tx_buf = (buf + i);
			t[1].len = page_size;
#ifdef QSPI_BRINGUP_BUILD
			t[1].bits_per_word = ((t[1].len % bytes_per_word) ==
					      0) ? flash->qspi_bits_per_word :
					      BITS8_PER_WORD;
#else
			t[1].bits_per_word = BITS8_PER_WORD;
#endif
			set_mode(&t[1],
				flash->cmd_table.qcmd.is_ddr,
				flash->cmd_table.qdata.bus_width,
				opcode);

			t[1].cs_change = TRUE;
			spi_message_add_tail(&t[1], &m);

			err = qspi_write_en(flash, TRUE, FALSE);
			if (err) {
				dev_err(&flash->spi->dev,
					"error: %s: WE failed: Status: x%x ",
					__func__, err);
				goto clear_qmode1;
			}

			spi_sync(flash->spi, &m);

			err = wait_till_ready(flash, FALSE);
			if (err) {
				dev_err(&flash->spi->dev,
					"error: %s: WIP failed: Status: x%x ",
					__func__, err);
				goto clear_qmode1;
			}
			*retlen +=
				m.actual_length -
				(flash->cmd_table.qaddr.len + 1);
		}
clear_qmode1:
		mutex_unlock(&flash->lock);

		return err;
	}
}

static const struct spi_device_id *jedec_probe(struct spi_device *spi)
{
	int			tmp;
	u8			code = OPCODE_RDID;
	u8			id[5];
	u32			jedec;
	u16			ext_jedec;
	struct flash_info	*info;

	/* JEDEC also defines an optional "extended device information"
	 * string for after vendor-specific data, after the three bytes
	 * we use here.  Supporting some chips might require using it.
	 */
	tmp = spi_write_then_read(spi, &code, 1, id, 5);
	if (tmp < 0) {
		dev_dbg(&spi->dev, "error %d reading JEDEC ID\n", tmp);
		return ERR_PTR(tmp);
	}

	jedec = id[0];
	jedec = jedec << 8;
	jedec |= id[1];
	jedec = jedec << 8;
	jedec |= id[2];

	ext_jedec = id[3] << 8 | id[4];
	for (tmp = 0; tmp < ARRAY_SIZE(qspi_ids) - 1; tmp++) {
		info = (void *)qspi_ids[tmp].driver_data;

		if (info->jedec_id == jedec) {
			if (info->ext_id != 0 && info->ext_id != ext_jedec)
				continue;
			return &qspi_ids[tmp];
		}
	}
	dev_err(&spi->dev, "unrecognized JEDEC id %06x\n", jedec);
	return ERR_PTR(-ENODEV);
}

static int qspi_init(struct qspi *flash)
{
	uint8_t regval;
	int ret;
	struct spi_device *spi = flash->spi;
	const struct spi_device_id	*id = spi_get_device_id(spi);
	struct flash_info *info =  (void *)id->driver_data;

	dev_dbg(&spi->dev, "%s ENTRY\n", __func__);

	if (info->jedec_id == JEDEC_ID_MX25U3235F) {
		max_qpi_set(flash, FALSE);
		return 0;
	}
	/*
	 * FIXME: Unlock the flash if locked. It is WAR to unlock the flash
	 *	  as locked bit is setting unexpectedly
	 */
	ret = qspi_read_any_reg(flash, RWAR_SR1NV, &regval);
	if (ret) {
		dev_err(&spi->dev,
			"error: %s RWAR_CR2V read failed: Status: x%x ",
			__func__, ret);
		return ret;
	}
	if (regval & (SR1NV_WRITE_DIS | SR1NV_BLOCK_PROT)) {
		regval = regval & ~(SR1NV_WRITE_DIS | SR1NV_BLOCK_PROT);
		qspi_write_any_reg(flash, RWAR_SR1NV, regval);
		wait_till_ready(flash, FALSE);
	}
	/* Set 512 page size when s25fx512s */
	if ((info->jedec_id == JEDEC_ID_S25FX512S) && (info->page_size == 512)) {
		ret = qspi_read_any_reg(flash, RWAR_CR3V, &regval);
		if (ret) {
			dev_err(&spi->dev,
				"error: %s RWAR_CR3V read failed: Status: x%x ",
				__func__, ret);
			return ret;
		}
		if ((regval & CR3V_512PAGE_SIZE) == 0) {
			regval = regval | CR3V_512PAGE_SIZE;
			qspi_write_any_reg(flash, RWAR_CR3V, regval);
			wait_till_ready(flash, FALSE);
		}
	}
	if (info->jedec_id == JEDEC_ID_MX25U51279G ||
			info->jedec_id == JEDEC_ID_MX75U25690F) {
		max_qpi_set(flash, FALSE);
		max_enable_4byte(flash);
	}
	dev_dbg(&spi->dev, "%s EXIT\n", __func__);

	return 0;
}

static int qspi_probe(struct spi_device *spi)
{
	const struct spi_device_id	*id;
	struct flash_platform_data	*data;
	struct qspi			*flash;
	struct flash_info		*info;
	unsigned			i;
	struct mtd_part_parser_data	ppdata;
	struct device_node __maybe_unused *np;
	struct tegra_qspi_device_controller_data *cdata = spi->controller_data;
	int ret;

	id = spi_get_device_id(spi);
	np = spi->dev.of_node;

#ifdef CONFIG_MTD_OF_PARTS
	if (!of_device_is_available(np))
		return -ENODEV;
#endif

	data = spi->dev.platform_data;
	if (data && data->type) {
		const struct spi_device_id *plat_id;

		for (i = 0; i < ARRAY_SIZE(qspi_ids) - 1; i++) {
			plat_id = &qspi_ids[i];
			if (strcmp(data->type, plat_id->name))
				continue;
			break;
		}

		if (i < ARRAY_SIZE(qspi_ids) - 1)
			id = plat_id;
		else
			dev_warn(&spi->dev, "unrecognized id %s\n", data->type);
	}

	info = (void *)id->driver_data;

	if (info->jedec_id) {
		const struct spi_device_id *jid;

		jid = jedec_probe(spi);
		if (IS_ERR(jid)) {
			return PTR_ERR(jid);
		} else if (jid != id) {
			dev_warn(&spi->dev, "found %s, expected %s\n",
					jid->name, id->name);
			id = jid;
			info = (void *)jid->driver_data;
		}
	}

	flash = devm_kzalloc(&spi->dev, sizeof(*flash), GFP_KERNEL);
	if (!flash)
		return -ENOMEM;


	if (info->jedec_id == JEDEC_ID_MX25U51279G)
		flash->cmd_info_table = macronix_cmd_info_table;
	else if (info->jedec_id == JEDEC_ID_S25FX512S ||
					info->jedec_id == JEDEC_ID_S25FS256S)
		flash->cmd_info_table = spansion_cmd_info_table;
	else if (info->jedec_id == JEDEC_ID_MX25U3235F ||
					info->jedec_id == JEDEC_ID_MX75U25690F)
		flash->cmd_info_table = macronix_porg_cmd_info_table;
	else {
		dev_err(&spi->dev, "error: %s: unsupported flash\n", __func__);
		return -EINVAL;
	}

	flash->spi = spi;
	flash->flash_info = info;
	mutex_init(&flash->lock);

	dev_set_drvdata(&spi->dev, flash);

	/*
	 * Atmel, SST and Intel/Numonyx serial flash tend to power
	 * up with the software protection bits set
	 */

	if (data && data->name)
		flash->mtd.name = data->name;
	else
		flash->mtd.name = dev_name(&spi->dev);

	flash->mtd.type = MTD_NORFLASH;
	flash->mtd.writesize = 1;
	flash->mtd.flags = MTD_CAP_NORFLASH;
	flash->mtd.size = info->sector_size * info->n_sectors;
	flash->mtd._erase = qspi_erase;
	flash->mtd._read = qspi_read;
	flash->mtd._write = qspi_write;
	flash->erase_opcode = OPCODE_SE;
	flash->mtd.erasesize = info->sector_size;

	flash->mtd.dev.parent = &spi->dev;
	flash->page_size = info->page_size;
	flash->mtd.writebufsize = flash->page_size;

	mtd_set_of_node(&flash->mtd, spi->dev.of_node);

	flash->addr_width = ADDRESS_WIDTH;
	cdata = flash->spi->controller_data;

	if (info->n_subsectors) {
		info->ss_endoffset = info->ss_soffset +
					info->ss_size * info->n_subsectors;
		if (info->ss_endoffset > flash->mtd.size) {
			dev_err(&spi->dev, "%s SSErr %x %x %x %llx\n", id->name,
				info->n_subsectors, info->ss_soffset,
					info->ss_size, flash->mtd.size);
			ret = -EINVAL;
			goto err_free_flash;
		}
		dev_info(&spi->dev, "%s SSG %x %x %x %llx\n", id->name,
				info->n_subsectors, info->ss_soffset,
					info->ss_size, flash->mtd.size);
	}

	dev_info(&spi->dev, "%s (%lld Kbytes)\n", id->name,
			(long long)flash->mtd.size >> 10);

	dev_info(&spi->dev,
	"mtd .name = %s, .size = 0x%llx (%lldMiB) .erasesize = 0x%.8x (%uKiB) .numeraseregions = %d\n",
		flash->mtd.name,
		(long long)flash->mtd.size, (long long)(flash->mtd.size >> 20),
		flash->mtd.erasesize, flash->mtd.erasesize / 1024,
		flash->mtd.numeraseregions);

	if (flash->mtd.numeraseregions)
		for (i = 0; i < flash->mtd.numeraseregions; i++)
			dev_info(&spi->dev,
				"mtd.eraseregions[%d] ={.offset = 0x%llx,.erasesize = "
					"0x%.8x (%uKiB),.numblocks = %d}\n",
				i,
				(long long)flash->mtd.eraseregions[i].offset,
				flash->mtd.eraseregions[i].erasesize,
				flash->mtd.eraseregions[i].erasesize / 1024,
				flash->mtd.eraseregions[i].numblocks);
	ret = qspi_init(flash);

	if (ret != 0)
		goto err_free_flash;

#ifdef QSPI_BRINGUP_BUILD
	ret = sysfs_create_group(&spi->dev.kobj, qspi_mtd_groups[0]);
	if (ret)
		goto err_free_flash;
#endif

	/* partitions should match sector boundaries; and it may be good to
	 * use readonly partitions for writeprotected sectors (BP2..BP0).
	 */
	ret = mtd_device_parse_register(&flash->mtd, NULL, &ppdata,
			data ? data->parts : NULL,
			data ? data->nr_parts : 0);
	if (ret < 0)
		goto err_remove_qspi_attrs;

	return ret;

err_remove_qspi_attrs:
	sysfs_remove_group(&spi->dev.kobj, qspi_mtd_groups[0]);
err_free_flash:
	return ret;
}

static int qspi_remove(struct spi_device *spi)
{
	struct qspi	*flash = dev_get_drvdata(&spi->dev);

#ifdef QSPI_BRINGUP_BUILD
	sysfs_remove_group(&spi->dev.kobj, qspi_mtd_groups[0]);
#endif
	mtd_device_unregister(&flash->mtd);
	return 0;
}


#ifdef CONFIG_PM
static int qspi_suspend(struct device *dev)
{
	int ret;
	uint8_t regval;

	struct qspi	*flash = dev_get_drvdata(dev);
	struct spi_device *spi = flash->spi;
	const struct spi_device_id	*id = spi_get_device_id(spi);
	struct flash_info *info =  (void *)id->driver_data;

	dev_dbg(dev, "%s ENTRY\n", __func__);

	/* configuration registers are not supported by macronix */
	if (info->jedec_id == JEDEC_ID_MX25U3235F)
		return 0;

	ret = qspi_read_any_reg(flash, RWAR_CR1V, &regval);
	if (ret) {
		dev_err(&flash->spi->dev,
			"error: %s CR1V read failed: status: %d", __func__, ret);
		return ret;
	}
	flash->rwar_cr1v_value = regval;


	ret = qspi_read_any_reg(flash, RWAR_CR2V, &regval);
	if (ret) {
		dev_err(&flash->spi->dev,
			"error: %s CR2V read failed: status: %d", __func__, ret);
		return ret;
	}

	flash->rwar_cr2v_value = regval;
	return ret;
}

static int qspi_resume(struct device *dev)
{
	int ret;
	struct qspi	*flash = dev_get_drvdata(dev);
	struct spi_device *spi = flash->spi;
	const struct spi_device_id	*id = spi_get_device_id(spi);
	struct flash_info *info =  (void *)id->driver_data;

	dev_dbg(dev, "%s ENTRY\n", __func__);

	/* configuration registers are not supported by macronix */
	if (info->jedec_id == JEDEC_ID_MX25U3235F)
		return 0;

	ret = qspi_init(flash);

	if (ret) {
		dev_err(dev,
			"error: %s qspi_init failed: Status: %d ",
			__func__, ret);
		return ret;
	}

	ret = qspi_write_any_reg(flash, RWAR_CR1V, flash->rwar_cr1v_value );
	if (ret) {
		dev_err(&flash->spi->dev,
			"error: %s CR1V write failed: status: %d", __func__, ret);
		return ret;
	}

	ret = qspi_write_any_reg(flash, RWAR_CR2V, flash->rwar_cr2v_value );
	if (ret) {
		dev_err(&flash->spi->dev,
			"error: %s CR2V write failed: status: %d", __func__, ret);
		return ret;
	}

	/* set suspend status to false */
	flash->suspend_status= false;

	return ret;
}

#else  /* CONFIG_PM */

#define qspi_suspend NULL
#define qspi_resume NULL

#endif  /* CONFIG_PM */

static const struct dev_pm_ops qspi_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(qspi_suspend, qspi_resume)
};

static struct spi_driver qspi_mtd_driver = {
	.driver = {
		.name	= "qspi_mtd",
		.owner	= THIS_MODULE,
		.pm		= &qspi_pm_ops,
	},
	.id_table	= qspi_ids,
	.probe	= qspi_probe,
	.remove	= qspi_remove,

};
module_spi_driver(qspi_mtd_driver);

MODULE_AUTHOR("Amlan Kundu <akundu@nvidia.com>, Ashutosh Patel <ashutoshp@nvidia.com>");
MODULE_DESCRIPTION("MTD SPI driver for Spansion/micron QSPI flash chips");
MODULE_LICENSE("GPL v2");
