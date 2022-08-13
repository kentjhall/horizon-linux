/*
 * drivers/spi/spi-im501.c
 * (C) Copyright 2014-2018
 * Fortemedia, Inc. <www.fortemedia.com>
 *
 * Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
 *
 * Author: HenryZhang <henryhzhang@fortemedia.com>;
 * 			LiFu <fuli@fortemedia.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/spi/spi.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/regulator/consumer.h>
#include <linux/pm_qos.h>
#include <linux/sysfs.h>
#include <linux/clk.h>
#include <linux/kfifo.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include <sound/tlv.h>
#include <asm/unistd.h>

#include "im501.h"
#include "spi-im501.h"

#ifdef CUBIETRUCK
#include <mach/sys_config.h>
#else
#include <linux/irq.h>
#include <linux/of_gpio.h>
#include <linux/hrtimer.h>
#endif

//#define SHOW_DL_TIME
#ifdef SHOW_DL_TIME
struct timex txc;
struct timex txc2;
struct timeval tv;
struct rtc_time rt;
#endif

//Fuli 20161215 define spi speed as constant
#define SPI_LOW_SPEED	1000000
#ifdef CUBIETRUCK
#define SPI_HIGH_SPEED	6000000
#else
#define SPI_HIGH_SPEED	20000000
#endif
//
#define FW_RD_CHECK
#define FW_BURST_RD_CHECK
//#define FW_MEM_RD_CHECK

//#define ENABLE_KERNEL_DUMP
#define ENABLE_KFIFO
#define MAX_KFIFO_BUFFER_SIZE		(131072*2)	/* >4 seconds */
#define CODEC2IM501_PDM_CLKI

//fuli 20170629 for new protocol of oneshot
#define SM501
//

void enable_pdm_clock(void);
void disable_pdm_clock(void);
static atomic_t dmic_clk_cnt = ATOMIC_INIT(0);

int im501_dsp_mode_old = -1;
int im501_vbuf_trans_status;
int ap_sleep_flag;
static struct spi_device *im501_spi;
int current_firmware_type = WAKEUP_FIRMWARE;
u8 firmware_type = WAKEUP_FIRMWARE;	//0: wakeup firmware; 1: ultrasound firmware

//#define VERIFY_PCM_KFIFO
#ifdef VERIFY_PCM_KFIFO
#define PCM_FILE "im501_oneshot_rec.pcm"
u8 *g_pcm_buf;
u32 g_pcm_size;
u32 g_offset;
#endif				//VERIFY_PCM_KFIFO

#define IM501_CDEV_NAME		"im501_pcm"
#define REC_FILE_PATH		"/data/im501_oneshot_kernel.pcm"
#define SPI_REC_FILE_PATH	"/data/im501_spi_rec_kernel.pcm"

struct im501_data_t {
	struct mutex lock;
	struct mutex spi_op_lock;
	dev_t record_chrdev;
	struct cdev record_cdev;
	struct device *record_dev;
	struct kfifo *pcm_kfifo;
	spinlock_t pcm_fifo_lock;
	struct class *cdev_class;
	atomic_t audio_owner;
	int irq_gpio;
	int reset_gpio;
};
struct im501_data_t *im501_data;

int im501_irq;
static struct work_struct im501_irq_work;
static struct work_struct im501_fw_load_work;
static struct workqueue_struct *im501_irq_wq;
static int im501_host_irqstatus; // To notify the HAL about the incoming irq.
//Fuli 20161216 resolve the issue about can only invoke interrupt once
static void im501_irq_handling_work(struct work_struct *work);
//

//Fuli 20170922 to support SPI recording
static char im501_spi_record_started;
struct file *fpdata = (struct file *)-1;
mm_segment_t oldfs;
static loff_t offset;
unsigned int output_counter;

int check_dsp_status(void);

int im501_spi_read_reg(u8 reg, u8 *val)
{
	struct spi_message message;
	struct spi_transfer x[2];
	int status;
	u8 write_buf[2];
	u8 read_buf[1];

	write_buf[0] = IM501_SPI_CMD_REG_RD;
	write_buf[1] = reg & 0xff;

	spi_message_init(&message);
	memset(x, 0, sizeof(x));

	x[0].len = 2;
	x[0].tx_buf = write_buf;
	spi_message_add_tail(&x[0], &message);

	x[1].len = 1;
	x[1].rx_buf = read_buf;
	spi_message_add_tail(&x[1], &message);

	status = spi_sync(im501_spi, &message);

	*val = read_buf[0];

	return status;
}

EXPORT_SYMBOL_GPL(im501_spi_read_reg);

int im501_spi_write_reg(u8 reg, u8 val)
{
	int status;
	u8 write_buf[3];

	write_buf[0] = IM501_SPI_CMD_REG_WR;
	write_buf[1] = reg;
	write_buf[2] = val;

	status = spi_write(im501_spi, write_buf, sizeof(write_buf));

	if (status)
		dev_err(&im501_spi->dev, "%s error %d\n", __func__, status);

	return status;
}

EXPORT_SYMBOL_GPL(im501_spi_write_reg);

int im501_spi_read_dram(u32 addr, u8 *pdata)
{
	struct spi_message message;
	struct spi_transfer x[2];
	int status, i;
	u8 write_buf[6];
	u8 read_buf[4];
	u8 spi_cmd = IM501_SPI_CMD_DM_RD, addr_msb;

	addr_msb = (addr >> 24) & 0xff;
	if (addr_msb == 0x10) {
		spi_cmd = IM501_SPI_CMD_IM_RD;
	} else if (addr_msb == 0xF) {
		spi_cmd = IM501_SPI_CMD_DM_RD;
	}

	write_buf[0] = spi_cmd;
	write_buf[1] = addr & 0xFF;
	write_buf[2] = (addr >> 8) & 0xFF;
	write_buf[3] = (addr >> 16) & 0xFF;
	write_buf[4] = 2;
	write_buf[5] = 0;

	spi_message_init(&message);
	memset(x, 0, sizeof(x));

	x[0].len = 6;
	x[0].tx_buf = write_buf;
	spi_message_add_tail(&x[0], &message);

	x[1].len = 4;
	x[1].rx_buf = read_buf;
	spi_message_add_tail(&x[1], &message);

	status = spi_sync(im501_spi, &message);

	for (i = 0; i < 4; i++) {
		*(pdata + i) = *(read_buf + i);
	}

	return status;
}

EXPORT_SYMBOL_GPL(im501_spi_read_dram);

int im501_spi_write_dram(u32 addr, u8 *pdata)
{
	int status;
	u8 buf[10];

	buf[0] = IM501_SPI_CMD_DM_WR;
	buf[1] = addr & 0xFF;
	buf[2] = (addr >> 8) & 0xFF;
	buf[3] = (addr >> 16) & 0xFF;
	buf[4] = 2;		//2 words
	buf[5] = 0;

	buf[6] = *pdata;
	buf[7] = *(pdata + 1);
	buf[8] = *(pdata + 2);
	buf[9] = *(pdata + 3);

	status = spi_write(im501_spi, buf, sizeof(buf));

	return status;

}

EXPORT_SYMBOL_GPL(im501_spi_write_dram);

/**
 * im501_spi_burst_read_dram - Read data from SPI by im501 dsp memory address.
 * @addr: Start address.
 * @rxbuf: Data Buffer for reading.
 * @len: Data length, it must be a multiple of 8.
 *
 * Returns true for success.
 */
int im501_spi_burst_read_dram(u32 addr, u8 *rxbuf, size_t len)
{
	int status;
	u8 spi_cmd = IM501_SPI_CMD_DM_RD, addr_msb;
	u8 write_buf[6];
	unsigned int end, offset = 0;

	struct spi_message message;
	struct spi_transfer x[2];

	addr_msb = (addr >> 24) & 0xff;
	if (addr_msb == 0x10) {
		spi_cmd = IM501_SPI_CMD_IM_RD;
	} else if (addr_msb == 0xF) {
		spi_cmd = IM501_SPI_CMD_DM_RD;
	}

	while (offset < len) {
		if (offset + IM501_SPI_BUF_LEN <= len)
			end = IM501_SPI_BUF_LEN;
		else
			end = len % IM501_SPI_BUF_LEN;

		write_buf[0] = spi_cmd;
		write_buf[1] = ((addr + offset) & 0x000000ff) >> 0;
		write_buf[2] = ((addr + offset) & 0x0000ff00) >> 8;
		write_buf[3] = ((addr + offset) & 0x00ff0000) >> 16;
		write_buf[4] = (end >> 1) & 0xff;
		write_buf[5] = (end >> (1 + 8)) & 0xff;

		spi_message_init(&message);
		memset(x, 0, sizeof(x));

		x[0].len = 6;
		x[0].tx_buf = write_buf;
		spi_message_add_tail(&x[0], &message);

		x[1].len = end;
		x[1].rx_buf = rxbuf + offset;
		spi_message_add_tail(&x[1], &message);

		status = spi_sync(im501_spi, &message);

		if (status) {
			dev_err(&im501_spi->dev, "%s: error in spi_sync\n",	__func__);
			return false;
		}

		offset += IM501_SPI_BUF_LEN;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(im501_spi_burst_read_dram);

//Fuli 20161215 extract a invert copy function for burst write
int im501_8byte_invert_copy(u8 *source, u8 *target)
{
	int i = 0;

	if (source == NULL || target == NULL)
		return -1;

	for (i = 0; i < 8; i++) {
		target[7 - i] = source[i];
	}

	return 0;
}

//

//Fuli 20161215 extract a copy function for burst write
int im501_8byte_copy(u8 *source, u8 *target)
{
	int i = 0;

	if (source == NULL || target == NULL)
		return -1;

	for (i = 0; i < 8; i++) {
		target[i] = source[i];
	}

	return 0;
}

//

/**
 * im501_spi_burst_write - Write data to SPI by im501 dsp memory address.
 * @addr: Start address.
 * @txbuf: Data Buffer for writng.
 * @len: Data length, it must be a multiple of 8.
 * @type: Firmware type, MSB and LSB, the iM501 firmware is in MSB, but the EFT firmware is in LSB.
 *
 * Returns true for success.
 */
int im501_spi_burst_write(u32 addr, const u8 *txbuf, size_t len, int fw_type)
{
	u8 spi_cmd, *write_buf, *local_buf;
	u32 offset = 0;
	int i, local_len, end, status;

	spi_cmd =
		(addr == 0x10000000) ? IM501_SPI_CMD_IM_WR : IM501_SPI_CMD_DM_WR;

	local_len = (len % 8) ? (((len / 8) + 1) * 8) : len;
	local_buf = kzalloc(local_len, GFP_KERNEL);
	if (local_buf == NULL)
		return -ENOMEM;

	memset(local_buf, 0, local_len);
	memcpy(local_buf, txbuf, len);

	write_buf = kzalloc(IM501_SPI_BUF_LEN + 6, GFP_KERNEL);
	if (write_buf == NULL) {
		kfree(local_buf);
		return -ENOMEM;
	}

	write_buf[0] = spi_cmd;	//Assign the command byte first, since it is fixed.
	while (offset < local_len) {
		if (offset + IM501_SPI_BUF_LEN <= local_len) {
			end = IM501_SPI_BUF_LEN;
		} else {
			end = local_len % IM501_SPI_BUF_LEN;
		}

		write_buf[1] = ((addr + offset) & 0x000000ff) >> 0;	//The memory address
		write_buf[2] = ((addr + offset) & 0x0000ff00) >> 8;
		write_buf[3] = ((addr + offset) & 0x00ff0000) >> 16;
		write_buf[4] = ((end / 2) & 0x00ff) >> 0;	//The word counter low byte.
		write_buf[5] = ((end / 2) & 0xff00) >> 8;	//Assign the high order word counter, since it is fixed.

		if (fw_type == IM501_DSP_FW) {
			for (i = 0; i < end; i += 8) {
				im501_8byte_invert_copy(local_buf + offset + i,
							write_buf + i + 6);
			}
		} else if (fw_type == IM501_EFT_FW) {
			for (i = 0; i < end; i += 8) {
				im501_8byte_copy(local_buf + offset + i,
						 write_buf + i + 6);
			}
		}

		status = spi_write(im501_spi, write_buf, end + 6);

		if (status) {
			dev_err(&im501_spi->dev, "%s error %d\n", __func__,
				status);
			kfree(write_buf);
			kfree(local_buf);
			return status;
		}

		offset += IM501_SPI_BUF_LEN;
	}

	kfree(write_buf);
	kfree(local_buf);

	return 0;
}

EXPORT_SYMBOL_GPL(im501_spi_burst_write);

//read frame counter to check DSP is working or not
int check_dsp_status(void)
{
	u32 framecount1, framecount2;
	int err = ESUCCESS;

	err =
		im501_spi_read_dram(TO_DSP_FRAMECOUNTER_ADDR, (u8 *) &framecount1);
	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev, "%s: call im501_spi_read_dram() return error(%d)\n",
			   __func__, err);
		return err;
	}

	msleep(50);

	err =
		im501_spi_read_dram(TO_DSP_FRAMECOUNTER_ADDR, (u8 *) &framecount2);
	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev, "%s: call im501_spi_read_dram() return error(%d)\n",
			   __func__, err);
		return err;
	}

	framecount1 = framecount1 >> 16;
	framecount2 = framecount2 >> 16;
	dev_dbg(&im501_spi->dev, "%s: framecount1=%x, framecount2=%x\n", __func__, framecount1,
		   framecount2);
	if (framecount1 != framecount2) {
		dev_info(&im501_spi->dev, "%s: im501 is working normally.\n", __func__);
	} else {
		dev_err(&im501_spi->dev, "%s: im501 is NOT working.\n", __func__);
		return EDSPNOTWORK;
	}

	return ESUCCESS;
}

/**
 * This function should be implemented by customers as a callback function.
 * The following is just a sample to control the PDM_CLKI on/off through UIF.
 * The parameter @pdm_clki_rate is reserved for future use.
 */
int codec2im501_pdm_clki_set(bool set_flag, u32 rate)
{
	if (set_flag == NORMAL_MODE) {
		dev_dbg(&im501_spi->dev, "%s: enable pdm_clki rate %d\n", __func__, rate);
		enable_pdm_clock();
		msleep(20);
	} else {
		dev_dbg(&im501_spi->dev, "%s: disable pdm_clki rate %d\n", __func__, rate);
		disable_pdm_clock();
		msleep(20);
	}
	return 0;
}

int im501_reset(void)
{
	if (im501_data->reset_gpio == -1)
		return 0;

	dev_info(&im501_spi->dev, "%s: reset im501 with gpio_number = %d\n", __func__, im501_data->reset_gpio);

	dev_dbg(&im501_spi->dev, "%s: set reset pin to low.\n", __func__);
	gpio_set_value(im501_data->reset_gpio, 0);
	msleep(20);
	dev_dbg(&im501_spi->dev, "%s: set reset pin to high.\n", __func__);
	gpio_set_value(im501_data->reset_gpio, 1);
	msleep(20);

	return 0;
}

void writeDataFile(char *buf, int count)
{
	loff_t ret;
	if (!IS_ERR(fpdata)) {
		oldfs = get_fs();
		set_fs(get_ds());
		dev_dbg(&im501_spi->dev, "writing %d\n", (int)count);
		ret = vfs_write(fpdata, buf, count, &offset);
		set_fs(oldfs);
	}
}

void openFileForWrite(unsigned char *filePath)
{
#ifdef ENABLE_KERNEL_DUMP
	offset = 0;
	oldfs = get_fs();
	set_fs(get_ds());
	if (!IS_ERR(fpdata)) {
		filp_close(fpdata, NULL);
		fpdata = NULL;
	}
	fpdata = filp_open(filePath, O_CREAT | O_RDWR, 0666);
	if (IS_ERR(fpdata))
		dev_err(&im501_spi->dev, "file open failed %s\n", filePath);
	else
		dev_info(&im501_spi->dev, "file open success %s\n", filePath);
	set_fs(oldfs);
#endif
}

void closeDataFile(void)
{
	if (!IS_ERR(fpdata)) {
		oldfs = get_fs();
		set_fs(get_ds());
		filp_close(fpdata, NULL);
		fpdata = (struct file *)-1;
		set_fs(oldfs);
	}
}

unsigned char fetch_voice_data(unsigned int start_addr, unsigned int data_length)
{
	unsigned char err = ESUCCESS;
	unsigned char *pbuf;
	unsigned int i, a, b;
	unsigned int read_size = 2048;

#ifdef SHOW_DL_TIME
	do_gettimeofday(&(txc.time));
#endif
	a = data_length / read_size;
	b = data_length % read_size;

	//dev_err(&im501_spi->dev, "%s: data_length=%d, a=%d, b=%d\n", __func__, data_length, a, b);
	pbuf = (unsigned char *)kzalloc(read_size, GFP_KERNEL);
	if (!pbuf) {
		dev_err(&im501_spi->dev, "%s: pbuf allocation failure.\n", __func__);
		return -1;
	}

	for (i = 0; i < a; i++) {
		err = im501_spi_burst_read_dram(start_addr, pbuf, read_size);
		if (err != NO_ERR) {
			if (pbuf)
				kfree(pbuf);
			dev_err(&im501_spi->dev, "%s: im501_spi_burst_read_dram() failure.\n",
				   __func__);
			return err;
		}

		start_addr += read_size;

#ifdef ENABLE_KERNEL_DUMP
		if (!IS_ERR(fpdata))
			writeDataFile(pbuf, read_size);
#endif
		//fuli 20170515 to reduce output dev_err(&im501_spi->dev, "%s: put the voice data to pcm FIFO.\n", __func__);
		//if(i % 10 == 0) dev_err(&im501_spi->dev, "%s: put the voice data to pcm FIFO.\n", __func__);
		//
#ifdef ENABLE_KFIFO

		if (!kfifo_is_full(im501_data->pcm_kfifo)) {
			spin_lock(&im501_data->pcm_fifo_lock);
			kfifo_in(im501_data->pcm_kfifo, pbuf, read_size);
			spin_unlock(&im501_data->pcm_fifo_lock);
		}
		else {
			dev_err(&im501_spi->dev, "%s: PCM FIFO is full.\n", __func__);
		}
#endif
	}

	if (b > 0) {
		err = im501_spi_burst_read_dram(start_addr, pbuf, b);
		if (err != ESUCCESS) {
			dev_err(&im501_spi->dev,
				"%s: im501_spi_burst_read_dram failure with %d.\n",
				__func__, err);
			if (pbuf)
				kfree(pbuf);
			return err;
		}
#ifdef ENABLE_KERNEL_DUMP
		if (!IS_ERR(fpdata))
			writeDataFile(pbuf, b);
#endif

#ifdef ENABLE_KFIFO
		if (!kfifo_is_full(im501_data->pcm_kfifo)) {
			spin_lock(&im501_data->pcm_fifo_lock);
			kfifo_in(im501_data->pcm_kfifo, pbuf, b);
			spin_unlock(&im501_data->pcm_fifo_lock);
		}
		else {
			dev_err(&im501_spi->dev, "%s: PCM FIFO is full.\n", __func__);
		}
#endif
	}

	if (pbuf)
		kfree(pbuf);
#ifdef SHOW_DL_TIME
	do_gettimeofday(&(txc2.time));
	dev_err(&im501_spi->dev, "%s: get one bank used %ld us\n", __func__,
		   (unsigned
		long)((unsigned long)(txc2.time.tv_sec -
					  txc.time.tv_sec) * 1000000L +
			  (unsigned long)(txc2.time.tv_usec - txc.time.tv_usec)));
#endif
	return err;

}

EXPORT_SYMBOL_GPL(fetch_voice_data);

unsigned char parse_to_host_command(to_host_cmd cmd)
{
	unsigned char err = ESUCCESS;
	unsigned int address = HW_VOICE_BUF_START;
	u8 *pdata;
	u32 spi_speed = SPI_HIGH_SPEED;
	int ret;
	char *hotword_str[2] = { "IM501_HOTWORD", NULL };
	//fuli 20170629 for new protocol
	int bank, sync_word_pos, data_size = HW_VOICE_BUF_BANK_SIZE;
	//

	//dev_err(&im501_spi->dev, "%s: cmd_byte = %#x\n", __func__, cmd.cmd_byte);
	if ((im501_vbuf_trans_status == 1) && (cmd.status == 1) && (cmd.cmd_byte == TO_HOST_CMD_DATA_BUF_RDY)) {	//Reuest host to read To-Host Buffer-Fast
		//dev_err(&im501_spi->dev, "%s: data ready\n", __func__);
#ifdef SM501			//fuli 20170629 the protocol is different from old version
		data_size = ((cmd.attri >> 13) & 0x7FF) << 1;	//16 bits sample, one sample occupies 2 bytes.
		bank = (cmd.attri >> 11) & 0x03;
		sync_word_pos = cmd.attri & 0x7FF;
		if ((bank == BANK0) || (bank == BANK0_SYNC)) {
			address = HW_VOICE_BUF_BANK0;
		} else if ((bank == BANK1) || (bank == BANK1_SYNC)) {
			address = HW_VOICE_BUF_BANK1;
		}
#else				//im502BE
		//fuli 20170629 no use          voice_buf_data.index   = (cmd.attri >>8) & 0xFFFF;  //package index
		if ((cmd.attri & 0xFF) == 0xF0) {
			address = HW_VOICE_BUF_START;	//BANK0 address
		} else if ((cmd.attri & 0xFF) == 0xF9) {
			address = HW_VOICE_BUF_START + HW_VOICE_BUF_BANK_SIZE;	//BANK1 address
		}
#endif

		if (im501_host_irqstatus == 1)
			dev_dbg(&im501_spi->dev, "%s: data ready at address=%x, data_size=%x\n",
				   __func__, address, data_size);
		err = fetch_voice_data(address, data_size);
		if (err != ESUCCESS) {
			dev_err(&im501_spi->dev, "%s: fetch_voice_data() return error.\n",
				   __func__);
			return err;
		}
		//cmd.status = 0;
		//Should be modified in accordance with customers scenario definitions.
		pdata = (u8 *) &cmd;
		pdata[3] &= 0x7F;	//changes the bit-31 to 0 to indicate that the hot has finished with the task.
		//dev_err(&im501_spi->dev, "%s: pdata[%#x, %#x, %#x, %#x]\n", __func__, pdata[0], pdata[1], pdata[2], pdata[3]);
		err = im501_spi_write_dram(TO_HOST_CMD_ADDR, pdata);
		if (err != ESUCCESS) {
			dev_err(&im501_spi->dev, "%s: im501_spi_write_dram() return error.\n",
				   __func__);
			return err;
		}
	} else {		//treat all other interrupt as keyword detect
		//if(cmd.cmd_byte == TO_HOST_CMD_KEYWORD_DET) {//Info host Keywords detected
		//dev_err(&im501_spi->dev, "%s: im501_vbuf_trans_status = %d\n", __func__, im501_vbuf_trans_status);
		if ((im501_vbuf_trans_status == 0) && (im501_dsp_mode_old == POWER_SAVING_MODE)) {	//only available when not transfer voice and in PSM
			im501_vbuf_trans_status = 1;
			im501_host_irqstatus = 1;

#ifdef CODEC2IM501_PDM_CLKI
			//to change the iM501 from PSM to Normal mode, and to keep the same setting
			//as the mode before changing to PSM, the Host just needs to turn on the PDMCLKI,
			//and no additional command is needed.
			codec2im501_pdm_clki_set(NORMAL_MODE, 0);
			im501_dsp_mode_old = NORMAL_MODE;
			mdelay(5);
#endif
			dev_info(&im501_spi->dev, "%s: keyword detected.\n", __func__);
			//dev_err(&im501_spi->dev, "%s: ap_sleep_flag = %d, im501_dsp_mode_old = %d\n", __func__, ap_sleep_flag, im501_dsp_mode_old);
			if (ap_sleep_flag) {
				im501_spi->mode = SPI_MODE_0;	/* clk active low */
				im501_spi->bits_per_word = 8;
				im501_spi->max_speed_hz = spi_speed;	//SPI_HIGH_SPEED

				ret = spi_setup(im501_spi);
				if (ret < 0) {
					dev_err(&im501_spi->dev,
						"spi_setup() failed\n");
					return -EIO;
				}
				msleep(20);

				ap_sleep_flag = 0;
			}
			//cmd.status = 0;
			//Should be modified in accordance with customers scenario definitions.
			pdata = (u8 *) &cmd;
			pdata[3] &= 0x7F;	//changes the bit-31 to 0 to indicate that the hot has finished with the task.
			//dev_err(&im501_spi->dev, "%s: pdata[%#x, %#x, %#x, %#x]\n", __func__, pdata[0], pdata[1], pdata[2], pdata[3]);
			err = im501_spi_write_dram(TO_HOST_CMD_ADDR, pdata);
			if (err != ESUCCESS) {
				dev_err(&im501_spi->dev,
					"%s: 1111 im501_spi_write_dram() return error.\n",
					__func__);
				return err;
			}
			//dev_err(&im501_spi->dev, "%s: start to get oneshot and save to file!!!!!!!!!!!!!!!!!!!!!!\n", __func__);
			openFileForWrite(REC_FILE_PATH);
			request_start_voice_buf_trans();
			kobject_uevent_env(&im501_spi->dev.kobj, KOBJ_CHANGE, hotword_str);

		} else {
			dev_info(&im501_spi->dev,
				"%s: Do not process other interrupt during process "
				"keyword detection and oneshot, or DSP is in normal mode.\n",
				__func__);
		}
	}

	return err;
}

unsigned char im501_send_to_dsp_command(to_501_cmd cmd)
{
	unsigned char err;
	unsigned int i;
	u8 pTempData[8];
	u8 *pdata;

	pdata = (u8 *) &cmd;
	//dev_err(&im501_spi->dev, "%s: attr=%#x, ext=%#x, status=%#x, cmd=%#x\n", __func__, cmd.attri, cmd.cmd_byte_ext, cmd.status, cmd.cmd_byte);

	err = im501_spi_write_dram(TO_DSP_CMD_ADDR, pdata);
	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev, "%s: call im501_spi_write_dram() return error(%d)\n",
			   __func__, err);
		return err;
	}

	err = im501_spi_write_reg(0x01, cmd.cmd_byte);	//generate interrupt to DSP
	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev, "%s: call im501_spi_write_reg() return error(%d)\n",
			   __func__, err);
		return err;
	}

	memset(pTempData, 0, 8);

	for (i = 0; i < 200; i++) {	//wait for (50*100us = 5ms) to check if DSP finished
		err = im501_spi_read_dram(TO_DSP_CMD_ADDR, pTempData);
		if (err != ESUCCESS) {
			dev_err(&im501_spi->dev,
				"%s: call im501_spi_read_dram() return error(%d)\n",
				__func__, err);
			return err;
		}
		//dev_err(&im501_spi->dev, "%s: pTempData[%#x, %#x, %#x, %#x]\n", __func__, pTempData[0], pTempData[1], pTempData[2], pTempData[3]);
		cmd.status = pTempData[3] >> 7;
		cmd.cmd_byte_ext = pTempData[3] & 0x7F;
		cmd.attri =
			pTempData[0] | (pTempData[1] * 256) | (pTempData[2] * 256 *
							   256);
		dev_info(&im501_spi->dev, "%s: cmd[%#x, %#x, %#x]\n", __func__, cmd.status,
			   cmd.cmd_byte_ext, cmd.attri);

		if (cmd.status != 0) {
			err = TO_501_CMD_ERR;
		} else {
			err = ESUCCESS;
			break;
		}
		msleep(20);
	}

	return err;
}

unsigned char im501_send_message_to_dsp(unsigned char cmd_index, unsigned int para)
{
	unsigned char err = ESUCCESS;
	to_501_cmd cmd;

	cmd.attri = para & 0xFFFFFF;
	cmd.cmd_byte_ext = (para >> 24) & 0x7F;
	cmd.status = 1;

	cmd.cmd_byte = cmd_index;	//((cmd_index & 0x3F) << 2) | 0x01; //D[1] : "1", interrupt DSP. This bit generates NMI (non-mask-able interrupt), D[0]: "1" generate mask-able interrupt

	dev_dbg(&im501_spi->dev, "%s: attri=%#x, cmd_byte_ext=%#x, status=%#x, cmd_byte=%#x\n",
		   __func__, cmd.attri, cmd.cmd_byte_ext, cmd.status, cmd.cmd_byte);
	err = im501_send_to_dsp_command(cmd);

	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev, "%s: fail to send message(%02x) to dsp. err=%d\n",
			 __func__, cmd_index >> 2, err);
	}
	return err;
}

unsigned char request_start_voice_buf_trans(void)
{
	unsigned char err = ESUCCESS;
	err = im501_send_message_to_dsp(TO_DSP_CMD_REQ_START_BUF_TRANS, 0);

	//Fuli 20161216 clear fifo when start to detect ketwords.
	dev_info(&im501_spi->dev, "%s: clear pcm fifo", __func__);
	spin_lock(&im501_data->pcm_fifo_lock);
	kfifo_reset(im501_data->pcm_kfifo);
	spin_unlock(&im501_data->pcm_fifo_lock);

	return err;
}

unsigned char request_stop_voice_buf_trans(void)
{
	unsigned char err = ESUCCESS;

	dev_info(&im501_spi->dev, "%s: stop voice transfer\n", __func__);
	err = im501_send_message_to_dsp(TO_DSP_CMD_REQ_STOP_BUF_TRANS, 0);
	im501_vbuf_trans_status = 0;

	return err;
}

unsigned char request_enter_psm(void)
{
	unsigned char err = ESUCCESS;

	if (im501_vbuf_trans_status == 1) {
		// stop voice transfer.
		request_stop_voice_buf_trans();
	}

	im501_vbuf_trans_status = 0;

	if (im501_dsp_mode_old != POWER_SAVING_MODE) {	//The current dsp mode is not PSM.
		dev_info(&im501_spi->dev,
			"ap_sleep_flag = %d, im501_dsp_mode_old = %d. iM501 is going to sleep.\n",
			 ap_sleep_flag, im501_dsp_mode_old);
		dev_dbg(&im501_spi->dev,
			"%s: the command is %#x\n", __func__, TO_DSP_CMD_REQ_ENTER_PSM);

		err = im501_send_message_to_dsp(TO_DSP_CMD_REQ_ENTER_PSM, 0);
		if (ESUCCESS != err) {
			dev_err(&im501_spi->dev,
				"%s: error occurs when switch to power saving mode, error = %d\n",
				__func__, err);
		}
#ifdef CODEC2IM501_PDM_CLKI
		mdelay(100);
		codec2im501_pdm_clki_set(POWER_SAVING_MODE, 0);
		mdelay(5);
#endif
		ap_sleep_flag = 1;
		im501_dsp_mode_old = POWER_SAVING_MODE;
		dev_dbg(&im501_spi->dev, "%s: ap_sleep_flag = %d, im501_dsp_mode_old = %d\n",
			   __func__, ap_sleep_flag, im501_dsp_mode_old);
	}

	return err;
}

unsigned char request_enter_normal(void)
{
	unsigned char err = ESUCCESS;

	dev_info(&im501_spi->dev, "%s: entering...\n", __func__);
	if (im501_vbuf_trans_status == 1) {
		// stop voice transfer.
		request_stop_voice_buf_trans();
	}

	im501_vbuf_trans_status = 0;

	if (im501_dsp_mode_old != NORMAL_MODE) {	//The current dsp mode is not NORMAL
#ifdef CODEC2IM501_PDM_CLKI
		mdelay(5);
		codec2im501_pdm_clki_set(NORMAL_MODE, 0);
		mdelay(100);
#endif

		//fuli 20170629
		err = im501_send_message_to_dsp(TO_DSP_CMD_REQ_ENTER_NORMAL, 0);
		if (ESUCCESS != err) {
			dev_err(&im501_spi->dev,
				"%s: error occurs when switch to normal mode, error = %d\n",
				__func__, err);
		}

		ap_sleep_flag = 0;
		im501_dsp_mode_old = NORMAL_MODE;
		dev_info(&im501_spi->dev,
			"%s: ap_sleep_flag = %d, im501_dsp_mode_old = %d\n",
			__func__, ap_sleep_flag, im501_dsp_mode_old);
	}

	return err;
}

int im501_spi_burst_read_check(u32 start_addr, u8 *buf, u32 data_length)
{
	int err;
	unsigned char *pbuf;
	unsigned int i, a, b;

	dev_info(&im501_spi->dev, "%s: entering...\n", __func__);
	a = data_length / IM501_SPI_BUF_LEN;
	b = data_length % IM501_SPI_BUF_LEN;

	pbuf = (unsigned char *)kzalloc(IM501_SPI_BUF_LEN, GFP_KERNEL);
	if (!pbuf) {
		dev_err(&im501_spi->dev, "%s: pbuf allocation failure.\n", __func__);
		return -1;
	}

	for (i = 0; i < a; i++) {
		dev_dbg(&im501_spi->dev, "%s: start_addr = %#x\n", __func__, start_addr);
		err =
			im501_spi_burst_read_dram(start_addr, pbuf,
						  IM501_SPI_BUF_LEN);
		if (err != ESUCCESS) {
			return err;
		}
		memcpy(buf + i * IM501_SPI_BUF_LEN, pbuf, IM501_SPI_BUF_LEN);

		start_addr += IM501_SPI_BUF_LEN;
	}

	if (b > 0) {
		err = im501_spi_burst_read_dram(start_addr, pbuf, b);
		if (err != ESUCCESS) {
			return err;
		}
		memcpy(buf + i * IM501_SPI_BUF_LEN, pbuf, b);
	}

	if (pbuf)
		kfree(pbuf);
	return err;
}

EXPORT_SYMBOL_GPL(im501_spi_burst_read_check);

#ifdef FW_RD_CHECK
static void im501_8byte_swap(u8 *rxbuf, u32 len)
{
	u8 local_buf[8];
	int i;

	for (i = 0; i < len / 8 * 8; i += 8) {
		local_buf[0] = rxbuf[i + 0];
		local_buf[1] = rxbuf[i + 1];
		local_buf[2] = rxbuf[i + 2];
		local_buf[3] = rxbuf[i + 3];
		local_buf[4] = rxbuf[i + 4];
		local_buf[5] = rxbuf[i + 5];
		local_buf[6] = rxbuf[i + 6];
		local_buf[7] = rxbuf[i + 7];

		rxbuf[i + 0] = local_buf[7];
		rxbuf[i + 1] = local_buf[6];
		rxbuf[i + 2] = local_buf[5];
		rxbuf[i + 3] = local_buf[4];
		rxbuf[i + 4] = local_buf[3];
		rxbuf[i + 5] = local_buf[2];
		rxbuf[i + 6] = local_buf[1];
		rxbuf[i + 7] = local_buf[0];
	}
}
#endif

static size_t im501_read_file(char *file_path, const u8 **buf)
{
	loff_t pos = 0;
	unsigned int file_size = 0;
	int read_len;
	struct file *fp;

	dev_info(&im501_spi->dev, "file_path = %s\n", file_path);
	fp = filp_open(file_path, O_RDONLY, 0);
	if (!IS_ERR(fp)) {
		dev_info(&im501_spi->dev, "The file is present.\n");

		file_size = vfs_llseek(fp, pos, SEEK_END);

		*buf = kzalloc(file_size, GFP_KERNEL);
		if (*buf == NULL) {
			filp_close(fp, 0);
			return 0;
		}

		read_len = kernel_read(fp, pos, (char *)*buf, file_size);
		if (read_len <= 0) {
			dev_err(&im501_spi->dev, "kernel_read error\n");
			read_len = 0;
		}

		filp_close(fp, 0);

		return read_len;
	}

	return 0;
}

static int im501_dsp_load_single_fw_file(u8 *fw_name, u32 addr, int fw_type)
{
	u8 *data;
	size_t size = 0;
#ifdef FW_RD_CHECK
	u8 *local_buf;
	int i;
#endif

#ifdef SHOW_DL_TIME
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec, &rt);
	dev_info(&im501_spi->dev, "%s: start time: %d-%d-%d %d:%d:%d \n", __func__,
		   rt.tm_year + 1900, rt.tm_mon, rt.tm_mday, rt.tm_hour, rt.tm_min,
		   rt.tm_sec);
#endif

	size = im501_read_file(fw_name, (const u8 **)&data);
	if (!size) {
		dev_err(&im501_spi->dev, "%s: firmware %s open failed.\n",
			__func__, fw_name);
		return -1;
	}
	if (size) {
		dev_info(&im501_spi->dev, "%s: firmware %s size = %zu, addr = %#x\n", __func__,
			   fw_name, size, addr);
		im501_spi_burst_write(addr, data, size, fw_type);

#ifdef FW_RD_CHECK
		local_buf = (u8 *) kzalloc(size, GFP_KERNEL);
		if (!local_buf)
			return -ENOMEM;
#ifdef FW_BURST_RD_CHECK
		im501_spi_burst_read_dram(addr, local_buf, size);
		if (fw_type == IM501_DSP_FW)
			im501_8byte_swap(local_buf, size);

		for (i = 0; i < size; i++) {
			if (local_buf[i] != data[i]) {
				dev_err(&im501_spi->dev, "%s: fw read %#x vs write %#x @ %#x\n",
					   __func__, local_buf[i], data[i],
					   addr + i);
			}
		}
#endif
		kfree(local_buf);
#endif
		kfree(data);
	}
#ifdef SHOW_DL_TIME
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec, &rt);
	dev_info(&im501_spi->dev, "%s: end   time: %d-%d-%d %d:%d:%d \n", __func__,
		   rt.tm_year + 1900, rt.tm_mon, rt.tm_mday, rt.tm_hour, rt.tm_min,
		   rt.tm_sec);
#endif
	return 0;
}

EXPORT_SYMBOL_GPL(im501_dsp_load_single_fw_file);

static int im501_dsp_load_fw(u8 firmware_type)
{				//0: wakeup firmware; 1: ultrasound firmware
	int err = 0;
	const struct firmware *fw = NULL;
	int fw_type = IM501_DSP_FW;

#ifdef FW_RD_CHECK
	u8 *local_buf;
	int i;
#endif

	dev_info(&im501_spi->dev, "%s: firmware_type=%d\n", __func__, firmware_type);
#ifdef SHOW_DL_TIME
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec, &rt);
	dev_info(&im501_spi->dev, "%s: start time: %d-%d-%d %d:%d:%d \n", __func__,
		   rt.tm_year + 1900, rt.tm_mon, rt.tm_mday, rt.tm_hour, rt.tm_min,
		   rt.tm_sec);
#endif

	if (firmware_type == WAKEUP_FIRMWARE)
		err = request_firmware(&fw, "im501_iram0.bin", &im501_spi->dev);
	else
		err = request_firmware(&fw, "../firmware1/im501_iram0.bin",
				 &im501_spi->dev);

	if (!fw) {
		dev_err(&im501_spi->dev,
			"%s: im501_iram0.bin firmware request failed.\n", __func__);
		return err;
	}

	if (fw) {
		dev_info(&im501_spi->dev, "%s: firmware im501_iram0.bin size = %zu \n", __func__,
			   fw->size);
		im501_spi_burst_write(0x10000000, fw->data, fw->size, fw_type);

#ifdef FW_RD_CHECK
		local_buf = (u8 *) kzalloc(fw->size, GFP_KERNEL);
		if (!local_buf)
			return -ENOMEM;
#ifdef FW_BURST_RD_CHECK
		im501_spi_burst_read_dram(0x10000000, local_buf, fw->size);
		if (fw_type == IM501_DSP_FW)
			im501_8byte_swap(local_buf, fw->size);

		for (i = 0; i < fw->size; i++) {
			if (local_buf[i] != fw->data[i]) {
				dev_err(&im501_spi->dev, "%s: fw read %#x vs write %#x @ %#x\n",
					   __func__, local_buf[i], fw->data[i],
					   0x10000000 + i);
				break;
			}
		}
#endif
		kfree(local_buf);
#endif
		release_firmware(fw);
		fw = NULL;
	}

	if (firmware_type == WAKEUP_FIRMWARE)
		err = request_firmware(&fw, "im501_dram0.bin", &im501_spi->dev);
	else
		err = request_firmware(&fw, "../firmware1/im501_dram0.bin",
				 &im501_spi->dev);

	if (!fw) {
		dev_err(&im501_spi->dev,
			"%s: im501_dram0.bin firmware request failed.\n", __func__);
		return err;
	}

	if (fw) {
		dev_info(&im501_spi->dev, "%s: firmware im501_dram0.bin size = %zu\n", __func__,
			   fw->size);
		im501_spi_burst_write(0x0ffc0000, fw->data, fw->size, fw_type);

#ifdef FW_RD_CHECK
		local_buf = (u8 *) kzalloc(fw->size, GFP_KERNEL);
		if (!local_buf)
			return -ENOMEM;

#ifdef FW_BURST_RD_CHECK
		im501_spi_burst_read_dram(0x0ffc0000, local_buf, fw->size);
		if (fw_type == IM501_DSP_FW)
			im501_8byte_swap(local_buf, fw->size);

		for (i = 0; i < fw->size; i++) {
			if (local_buf[i] != fw->data[i]) {
				dev_err(&im501_spi->dev, "%s: fw read %#x vs write %#x @ %#x\n",
					   __func__, local_buf[i], fw->data[i],
					   0x0ffc0000 + i);
				break;
			}
		}
#endif
		kfree(local_buf);
#endif

		release_firmware(fw);
		fw = NULL;
	}

	if (firmware_type == WAKEUP_FIRMWARE)
		err = request_firmware(&fw, "im501_dram1.bin", &im501_spi->dev);
	else
		err = request_firmware(&fw, "../firmware1/im501_dram1.bin",
				 &im501_spi->dev);

	if (!fw) {
		dev_err(&im501_spi->dev,
			"%s: im501_dram1.bin firmware request failed.\n", __func__);
		return err;
	}

	if (fw) {
		dev_info(&im501_spi->dev, "%s: firmware im501_dram1.bin size = %zu\n", __func__, fw->size);
		im501_spi_burst_write(0x0ffe0000, fw->data, fw->size, fw_type);

#ifdef FW_RD_CHECK
		local_buf = (u8 *) kzalloc(fw->size, GFP_KERNEL);
		if (!local_buf)
			return -ENOMEM;

#ifdef FW_BURST_RD_CHECK
		im501_spi_burst_read_dram(0x0ffe0000, local_buf, fw->size);
		if (fw_type == IM501_DSP_FW)
			im501_8byte_swap(local_buf, fw->size);

		for (i = 0; i < fw->size; i++) {
			if (local_buf[i] != fw->data[i]) {
				dev_err(&im501_spi->dev, "%s: fw read %#x vs write %#x @ %#x\n",
					   __func__, local_buf[i], fw->data[i],
					   0x0ffe0000 + i);
				break;
			}
		}
#endif
		kfree(local_buf);
#endif
		release_firmware(fw);
		fw = NULL;
	}

#ifdef SHOW_DL_TIME
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec, &rt);
	dev_info(&im501_spi->dev, "%s: end   time: %d-%d-%d %d:%d:%d \n", __func__,
		   rt.tm_year + 1900, rt.tm_mon, rt.tm_mday, rt.tm_hour, rt.tm_min,
		   rt.tm_sec);
#endif
	dev_info(&im501_spi->dev, "%s: firmware is loaded\n", __func__);
	return err;
}

void im501_write_check_spi_reg(u8 reg, u8 val)
{
	u8 ret_val;

	im501_spi_write_reg(reg, val);
	im501_spi_read_reg(0x00, (u8 *) &ret_val);
	if (ret_val != val)
		dev_err(&im501_spi->dev,
			"%s: read back value(%x) of reg%02x is different from the written value(%x). \n",
			__func__, ret_val, reg, val);

	return;
}

void enable_pdm_clock(void)
{
	if (atomic_read(&dmic_clk_cnt) > 0) {
		dev_info(&im501_spi->dev, "PDM clock already enabled\n");
		return;
	}
	atomic_set(&dmic_clk_cnt, 1);
}

void disable_pdm_clock(void)
{
	if (atomic_read(&dmic_clk_cnt) > 0)
		atomic_set(&dmic_clk_cnt, 0);
	else
		dev_info(&im501_spi->dev, "PDM clock already disabled\n");
}

void im501_start_capture_cb(void)
{
	int err;

	err = im501_send_message_to_dsp(TO_DSP_CMD_REQ_ENTER_BYPASS, 0x1);
	if (ESUCCESS != err) {
	dev_err(&im501_spi->dev,
		"%s: error when enabling hw bypass mode, error = %d\n",
		__func__, err);
	}
	msleep(20);
}

static void im501_fw_load(struct work_struct *work)
{
	u32 addr, regval;

	dev_info(&im501_spi->dev, "%s: entering...\n", __func__);

#ifdef CODEC2IM501_PDM_CLKI
	codec2im501_pdm_clki_set(NORMAL_MODE, 0);
	mdelay(5);		//Apply PDM_CLKI, and then wait for 1024 clock cycles
#endif

	//reset DSP
	im501_reset();

	//Enable DSP Clock, put DSP on hold and remove DSP reset
	im501_write_check_spi_reg(0x00, 0x07);
	im501_write_check_spi_reg(0x00, 0x05);

	mdelay(1);

	//Enable PDM_DATAO1
	addr = 0xFFFFF10;
	im501_spi_read_dram(addr, (u8 *)&regval);
	regval = regval & 0xFBFFFFFF;
	im501_spi_write_dram(addr, (u8 *)&regval);

	if (im501_dsp_load_fw(firmware_type) != 0) {
		dev_err(&im501_spi->dev, "im501 firmware load failed\n");
		codec2im501_pdm_clki_set(POWER_SAVING_MODE, 0);
		return;
	}
	mdelay(1);

	//Remove DSP “on hold” to “run"
	im501_write_check_spi_reg(0x00, 0x04);

	//check DSP working or not
	check_dsp_status();

	im501_dsp_mode_old = NORMAL_MODE;

	//after firmware download, keep DSP in NORMAL mode
	codec2im501_pdm_clki_set(POWER_SAVING_MODE, 0);

	return;
}

static void im501_spi_lock(struct mutex *lock)
{
	mutex_lock(lock);
}

static void im501_spi_unlock(struct mutex *lock)
{
	mutex_unlock(lock);
}

//Fuli 20171012 to support SPI recording
unsigned char im501_switch_to_spi_recording_mode(void)
{
	return im501_send_message_to_dsp(TO_DSP_CMD_REQ_SWITCH_SPI_REC, 1);
}

unsigned char im501_switch_to_normal_mode(void)
{
	return im501_send_message_to_dsp(TO_DSP_CMD_REQ_SWITCH_SPI_REC, 0);
}

static void im501_irq_handling_work(struct work_struct *work)
{
	unsigned char err;
	to_host_cmd cmd;
	u8 *pdata;
	u32 spi_speed = SPI_LOW_SPEED;
	int ret;

	//dev_err(&im501_spi->dev, "%s: entering...\n", __func__);
	if (im501_dsp_mode_old == POWER_SAVING_MODE) {
		dev_info(&im501_spi->dev, "%s: iM501 is in PSM, set the spi speed to %d\n",
			   __func__, spi_speed);
		im501_spi->mode = SPI_MODE_0;	/* clk active low */
		im501_spi->bits_per_word = 8;
		im501_spi->max_speed_hz = spi_speed;

		ret = spi_setup(im501_spi);
		if (ret < 0) {
			dev_err(&im501_spi->dev, "spi_setup() failed\n");
			return;	// -EIO;
		}
		msleep(20);
	}

	pdata = (u8 *) &cmd;
	err = im501_spi_read_dram(TO_HOST_CMD_ADDR, pdata);
	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev, "%s: im501_spi_read_dram error, error=%d\n",
			   __func__, err);
		return;
	}

	if ((im501_host_irqstatus == 1) || ((output_counter % 100) == 0)) {
		dev_dbg(&im501_spi->dev, "%s: pdata[%#x, %#x, %#x, %#x]\n", __func__, pdata[0],
			   pdata[1], pdata[2], pdata[3]);
	}
	output_counter++;

	cmd.status = pdata[3] >> 7;
	cmd.cmd_byte = pdata[3] & 0x7F;
	cmd.attri = pdata[0] | (pdata[1] * 256) | (pdata[2] * 256 * 256);
	//dev_err(&im501_spi->dev, "%s: cmd[%#x, %#x, %#x]\n", __func__, cmd.status, cmd.cmd_byte, cmd.attri);

	if (cmd.status != 1) {
		dev_err(&im501_spi->dev, "%s: got wrong command from DSP.\n", __func__);
	}

	im501_spi_lock(&im501_data->spi_op_lock);
	err = parse_to_host_command(cmd);
	im501_spi_unlock(&im501_data->spi_op_lock);

	if (err != ESUCCESS) {
		dev_err(&im501_spi->dev,
			"%s: error calling parse_to_host_command(), error=%d\n",
			__func__, err);
	}

	return;
}

static irqreturn_t im501_irq_handler(int irq, void *para)
{
	bool ret;

	ret = queue_work(im501_irq_wq, &im501_irq_work);
	if (!ret)
		dev_err(&im501_spi->dev, "%s: queue_work failed", __func__);

	return IRQ_HANDLED;
}

/* Access to the audio buffer is controlled through "audio_owner". Either the
 * character device can be opened. */
static int im501_record_open(struct inode *inode, struct file *file)
{
	dev_dbg(&im501_spi->dev, "%s: entering...\n", __func__);
	if (!atomic_add_unless(&im501_data->audio_owner, 1, 1))
		return -EBUSY;
	dev_dbg(&im501_spi->dev, "%s: im501_data->audio_owner.counter = %d\n", __func__,
		   im501_data->audio_owner.counter);

	file->private_data = im501_data;

	return 0;
}

static int im501_record_release(struct inode *inode, struct file *file)
{
	dev_dbg(&im501_spi->dev, "%s: decrease audio_owner.\n", __func__);
	atomic_dec(&im501_data->audio_owner);
	dev_dbg(&im501_spi->dev, "%s: im501_data->audio_owner.counter = %d\n", __func__,
		   im501_data->audio_owner.counter);

	return 0;
}

/* The write function is a hack to load the A-model on systems where the
 * firmware files are not accesible to the user. */
static ssize_t im501_record_write(struct file *file,
				  const char __user *buf,
				  size_t count_want, loff_t *f_pos)
{
	dev_dbg(&im501_spi->dev, "%s: entering...\n", __func__);
	return count_want;
}

/* Read out of the kfifo (as long as data is available). */
static ssize_t im501_record_read(struct file *file,
				 char __user *buf,
				 size_t count_want, loff_t *f_pos)
{
	struct im501_data_t *im501_data = (struct im501_data_t *)file->private_data;
	size_t not_copied;
	ssize_t to_copy = count_want;
	int avail;
	unsigned int copied, total_copied = 0;
	unsigned long timeout = jiffies + msecs_to_jiffies(500);

	dev_dbg(&im501_spi->dev, "%s: entering... count_want = %d, *f_pos = %d\n",
		__func__, (int)count_want, (int)*f_pos);
	avail = kfifo_len(im501_data->pcm_kfifo);
	//dev_info(&im501_spi->dev, "%s: avail = %d\n", __func__, avail);

	while ((total_copied < count_want) && time_before(jiffies, timeout)) {
		int ret;
		to_copy = avail;
		if (count_want - total_copied < avail)
			to_copy = count_want - total_copied;

		ret = kfifo_to_user(im501_data->pcm_kfifo, buf + total_copied,
			to_copy, &copied);
		if (ret)
			return -EIO;
		dev_dbg(&im501_spi->dev, "%s: %d bytes are copied:\n", __func__, copied);

		total_copied += copied;
		avail = kfifo_len(im501_data->pcm_kfifo);
		if ((total_copied < count_want) && !avail)
			msleep(20);
	}

	if (total_copied < count_want)
		dev_err(&im501_spi->dev, "im501: timeout during reading\n");

	not_copied = count_want - total_copied;
	*f_pos = *f_pos + (count_want - not_copied);

	return count_want - not_copied;
}

static const struct file_operations record_fops = {
	.owner = THIS_MODULE,
	.open = im501_record_open,
	.release = im501_record_release,
	.read = im501_record_read,
	.write = im501_record_write,
};

static int im501_create_cdev(struct spi_device *spi)
{
	int ret = 0, err = -1;
	struct device *dev = &spi->dev;
	int cdev_major, dev_no;

	atomic_set(&im501_data->audio_owner, 0);

	ret = alloc_chrdev_region(&im501_data->record_chrdev, 0, 1,
				IM501_CDEV_NAME);
	if (ret) {
		dev_err(dev, "%s: failed to allocate character device\n",
			__func__);
		return ret;
	}

	cdev_major = MAJOR(im501_data->record_chrdev);

	im501_data->cdev_class = class_create(THIS_MODULE, IM501_CDEV_NAME);
	if (IS_ERR(im501_data->cdev_class)) {
		dev_err(dev, "%s: failed to create class\n", __func__);
		return err;
	}

	dev_no = MKDEV(cdev_major, 1);

	cdev_init(&im501_data->record_cdev, &record_fops);

	im501_data->record_cdev.owner = THIS_MODULE;

	ret = cdev_add(&im501_data->record_cdev, dev_no, 1);
	if (ret) {
		dev_err(dev, "%s: failed to add character device\n", __func__);
		return ret;
	}
	dev_info(&im501_spi->dev, "%s: cdev_add ok...\n", __func__);

	im501_data->record_dev = device_create(im501_data->cdev_class, NULL,
						   dev_no, NULL, "%s",
						   IM501_CDEV_NAME);
	if (IS_ERR(im501_data->record_dev)) {
		dev_err(&im501_spi->dev, "%s: could not create device\n",
			__func__);
		return err;
	}
	dev_info(&im501_spi->dev, "%s: device_create ok...\n", __func__);

	spin_lock_init(&im501_data->pcm_fifo_lock);
	im501_data->pcm_kfifo = (struct kfifo *)kmalloc(sizeof(struct kfifo), GFP_KERNEL);
	if (im501_data->pcm_kfifo == NULL) {
		dev_err(&im501_spi->dev, "no fifo for pcm_kfifo\n");
		return -ENOMEM;
	}

	ret = kfifo_alloc(im501_data->pcm_kfifo, MAX_KFIFO_BUFFER_SIZE, GFP_KERNEL);
	if (ret) {
		dev_err(&im501_spi->dev, "no kfifo memory\n");
		return -1;
	}

	return ret;
}

static ssize_t im501_spi_device_read(struct file *file, char __user *buffer,
					 size_t length, loff_t *offset)
{
	char str[5];
	size_t ret = 0;
	char *local_buffer;
	dev_cmd_mode_gs *get_mode_ret_data;
	dev_cmd_reg_rw *get_reg_ret_data;
	dev_cmd_long *get_addr_ret_data;
	dev_cmd_short *get_irq_status;
	dev_cmd_fw_type *get_firmware_type_ret_data;
	int temp = 0;

	local_buffer = (char *)kzalloc(length * sizeof(char), GFP_KERNEL);
	if (!local_buffer) {
		dev_err(&im501_spi->dev, "%s: local_buffer allocation failure.\n", __func__);
		goto out;
	}
	temp = copy_from_user(local_buffer, buffer, length);

	//dev_err(&im501_spi->dev, "local_buffer = %d:, length = %d\n", local_buffer[0], length);
	switch (local_buffer[0]) {
	case FM_SMVD_REG_READ:
		get_reg_ret_data = (dev_cmd_reg_rw *) local_buffer;
		im501_spi_read_reg(get_reg_ret_data->reg_addr,
				   (u8 *) &get_reg_ret_data->reg_val);
		ret = sizeof(dev_cmd_reg_rw);
		break;

	case FM_SMVD_DSP_ADDR_READ:
		get_addr_ret_data = (dev_cmd_long *) local_buffer;
		im501_spi_read_dram(get_addr_ret_data->addr,
					(u8 *) &get_addr_ret_data->val);
		ret = sizeof(dev_cmd_long);
		break;

	case FM_SMVD_MODE_GET:
		get_mode_ret_data = (dev_cmd_mode_gs *) local_buffer;
		get_mode_ret_data->dsp_mode = (char)im501_dsp_mode_old;
		ret = sizeof(dev_cmd_mode_gs);
		break;

	case FM_SMVD_HOST_IRQQUERY:
		get_irq_status = (dev_cmd_short *) local_buffer;
		get_irq_status->val = im501_host_irqstatus;
		if (im501_host_irqstatus == 1) {
			im501_host_irqstatus = 0;
			dev_info(&im501_spi->dev, "%s: iM501 irq is coming..\n", __func__);
		}
		ret = sizeof(dev_cmd_short);
		break;

	case FM_SMVD_GET_FW_TYPE:
		get_firmware_type_ret_data = (dev_cmd_fw_type *) local_buffer;
		get_firmware_type_ret_data->firmware_type =
			(char)current_firmware_type;
		ret = sizeof(dev_cmd_fw_type);
		break;

	default:
		ret = sprintf(str, "0");
		break;
	}

	if (copy_to_user(buffer, local_buffer, ret))
		ret = -EFAULT;

 out:
	if (local_buffer)
		kfree(local_buffer);
	return ret;
}

static ssize_t im501_spi_device_write(struct file *file,
					  const char __user *buffer, size_t length,
					  loff_t *offset)
{
	dev_cmd_long *local_dev_cmd = NULL;
	dev_cmd_fwdl *local_dev_cmd_fwdl;
	/*if spi speed is fast enough, we can get total data from SPI together
	   dev_cmd_start_rec *local_rec_cmd;
	 */
	dev_cmd_message *local_msg_cmd;

	unsigned int cmd_name, cmd_addr, cmd_val;
	int dsp_mode;
	int new_firmware_type;
	unsigned char err = ESUCCESS;

	dev_info(&im501_spi->dev, "%s: entering...\n", __func__);
	if (im501_dsp_mode_old == -1) {
		dev_err(&im501_spi->dev, "%s: iM501 firmware not loaded.\n", __func__);
		err = -EIO;
		goto out;
	}

	local_dev_cmd =
		(dev_cmd_long *) kzalloc(sizeof(dev_cmd_long), GFP_KERNEL);
	if (!local_dev_cmd) {
		dev_err(&im501_spi->dev, "%s: local_dev_cmd allocation failure.\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	err = copy_from_user(local_dev_cmd, buffer, min(sizeof(dev_cmd_long), length));
	if (err) {
		dev_err(&im501_spi->dev, "%s: copy_from_user error\n", __func__);
		goto out;
	}

	dev_info(&im501_spi->dev, "local_dev_cmd->cmd_name = %d, length = %zu\n",
		   local_dev_cmd->cmd_name, length);
	cmd_name = local_dev_cmd->cmd_name;

	switch (cmd_name) {
		//The short commands
	case FM_SMVD_REG_WRITE:	//Command #1
		cmd_addr = local_dev_cmd->addr;
		cmd_val = local_dev_cmd->val;
		im501_spi_write_reg(cmd_addr, cmd_val);
		break;

	case FM_SMVD_DSP_ADDR_WRITE:	//Command #3
		cmd_addr = local_dev_cmd->addr;
		cmd_val = local_dev_cmd->val;
		im501_spi_write_dram(cmd_addr, (u8 *) &cmd_val);
		break;

	case FM_SMVD_MODE_SET:	//Command #4
		dev_info(&im501_spi->dev, "%s: FM_SMVD_MODE_SET dsp_mode = %d\n", __func__,
			   local_dev_cmd->addr);
		dsp_mode = local_dev_cmd->addr;
		// Temporarily set to PSM mode.
		if (dsp_mode == 0)
			request_enter_psm();
		else if (dsp_mode == 1)
			request_enter_normal();
		else if (dsp_mode == 4) {
			request_stop_voice_buf_trans();
			msleep(2000);
			closeDataFile();
			output_counter = 0;
		}
		//im501_dsp_mode_old = dsp_mode;
		break;

	case FM_SMVD_DL_EFT_FW:
		local_dev_cmd_fwdl = (dev_cmd_fwdl *) local_dev_cmd;
		// Ensure filename is terminated
		local_dev_cmd_fwdl->buf[sizeof(local_dev_cmd_fwdl->buf)-1] = '\0';
		im501_dsp_load_single_fw_file(local_dev_cmd_fwdl->buf,
						  local_dev_cmd_fwdl->dsp_addr,
						  IM501_EFT_FW);
		break;

	case FM_SMVD_SWITCH_FW:
		dev_info(&im501_spi->dev, "%s: FM_SMVD_SWITCH_FW firmware_type = %d\n", __func__,
			   local_dev_cmd->addr);
		new_firmware_type = local_dev_cmd->addr;

		if ((new_firmware_type == 0) || (new_firmware_type == 1)) {
			if (new_firmware_type == current_firmware_type) {
				dev_err(&im501_spi->dev,
					"%s: requested firmware type is the same as current firmware type, not need to change it.\n",
					__func__);
			} else {
				firmware_type = new_firmware_type;
				schedule_work(&im501_fw_load_work);
			}
		} else {
			dev_err(&im501_spi->dev,
				"%s: requested firmware type is not supported.\n",
				__func__);
		}
		break;

		//Fuli 20170922 to support SPI recording
		//do the same as one shot, app and lib will get sample data then generate pcm and wav by channel
	case FM_SMVD_START_SPI_REC:
		openFileForWrite(SPI_REC_FILE_PATH);

		im501_spi_record_started = 1;
		im501_host_irqstatus = 0;	//not wakeup by keywords

		//it will be set when im501 wakeup from PSM, set it here for SPI recording
		im501_vbuf_trans_status = 1;
		request_enter_normal();
		im501_switch_to_spi_recording_mode();
		request_start_voice_buf_trans();

		break;

	case FM_SMVD_STOP_SPI_REC:
		request_stop_voice_buf_trans();
		im501_spi_record_started = 0;

		//not sure it is needed or not
		im501_switch_to_normal_mode();

		msleep(1000);
		request_enter_psm();
		closeDataFile();
		output_counter = 0;
		break;

		//Fuli 20171022 to support general message interface
	case FM_SMVD_SEND_MESSAGE:
		local_msg_cmd = (dev_cmd_message *) local_dev_cmd;
		dev_info(&im501_spi->dev,
			"%s: will send message 0x%02X to DSP with data 0x%08X.\n",
			__func__, local_msg_cmd->message_index,
			 local_msg_cmd->message_data);
		err = im501_send_message_to_dsp(
				((local_msg_cmd->message_index & 0x3F) << 2) | 0x01,
				local_msg_cmd->message_data);
		break;

	case FM_SMVD_ENABLE_HOTWORD_DETECT:
		dev_info(&im501_spi->dev, "%s: enable hotword\n", __func__);
		codec2im501_pdm_clki_set(NORMAL_MODE, 0);
		mdelay(100);
		request_enter_psm();
		break;

	case FM_SMVD_DISABLE_HOTWORD_DETECT:
		dev_info(&im501_spi->dev, "%s: disable hotword\n", __func__);
		request_enter_normal();
		mdelay(100);
		codec2im501_pdm_clki_set(POWER_SAVING_MODE, 0);
		break;


	default:
		break;
	}
 out:
	if (local_dev_cmd)
		kfree(local_dev_cmd);
	return length;
}

struct file_operations im501_spi_fops = {
	.owner = THIS_MODULE,
	.read = im501_spi_device_read,
	.write = im501_spi_device_write,
};

static struct miscdevice im501_spi_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "im501_spi",
	.fops = &im501_spi_fops
};

//Henry add for try
static const struct spi_device_id im501_spi_id[] = {
	{"im501_spi", 0},
	{}
};

MODULE_DEVICE_TABLE(spi, im501_spi_id);
//End

#ifdef CONFIG_OF
static struct of_device_id im501_spi_dt_ids[] = {
	{.compatible = "fortemedia,im501_spi"},
	{},
};

MODULE_DEVICE_TABLE(of, im501_spi_dt_ids);
#endif

static int im501_spi_probe(struct spi_device *spi)
{
	int ret;
#ifdef CUBIETRUCK
	enum gpio_eint_trigtype trigtype;
	u32 trigenabled = 0;
	script_item_value_type_e type;
	script_item_u val;
	int irq_gpio;		/* irq gpio define */
#else
	struct device *dev = &spi->dev;
	struct device_node *np = dev->of_node;
#endif
	u32 spi_speed;

	im501_spi = spi;

	im501_data =
		(struct im501_data_t *)kzalloc(sizeof(struct im501_data_t),
					   GFP_KERNEL);
	if (im501_data == NULL) {
		dev_err(&im501_spi->dev, "%s: im501_data allocate fail\n", __func__);
		return -ENOMEM;
	}

	mutex_init(&im501_data->spi_op_lock);

#ifdef CODEC2IM501_PDM_CLKI
	codec2im501_pdm_clki_set(POWER_SAVING_MODE, 0);
	mdelay(5);
#endif

#ifdef CUBIETRUCK
	type = script_get_item("spi_board0", "max_speed_hz", &val);
	if (SCIRPT_ITEM_VALUE_TYPE_INT != type) {
		dev_err(&im501_spi->dev, "%s: request max_speed_hz error!\n", __func__);
		spi_speed = SPI_HIGH_SPEED;
	} else {
		spi_speed = val.val;
	}
#else
	ret = of_property_read_u32(np, "spi-max-frequency", &spi_speed);
	if (ret && ret != -EINVAL)
		spi_speed = SPI_HIGH_SPEED;
#endif

	spi->mode = SPI_MODE_0;	// clk active low
	spi->bits_per_word = 8;
	spi->max_speed_hz = spi_speed;

	ret = spi_setup(spi);
	if (ret < 0) {
		dev_err(&spi->dev, "spi_setup() failed\n");
		return -EIO;
	}
	dev_info(&im501_spi->dev, "%s: setup spi, spi_speed=%d \n", __func__, spi_speed);

	firmware_type = WAKEUP_FIRMWARE;
	/*request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
				"im501_fw", &spi->dev, GFP_KERNEL,
				(void *)&firmware_type, im501_fw_loaded);
*/
	im501_create_cdev(spi);

	ret = misc_register(&im501_spi_dev);
	if (ret)
		dev_err(&spi->dev, "Couldn't register control device\n");

	im501_vbuf_trans_status = 0;

	INIT_WORK(&im501_irq_work, im501_irq_handling_work);
	INIT_WORK(&im501_fw_load_work, im501_fw_load);
	im501_irq_wq = create_singlethread_workqueue("im501_irq_wq");

#ifdef CUBIETRUCK
	irq_gpio = GPIOH(16);
	im501_irq =
		sw_gpio_irq_request(irq_gpio, TRIG_EDGE_POSITIVE,
				(peint_handle) im501_irq_handler,
				NULL);
	dev_err(&im501_spi->dev, "%s: im501_irq = %d\n", __func__, im501_irq);
	if (im501_irq == 0) {
		dev_err(&im501_spi->dev, "%s: IM501 sw_gpio_irq_request failed\n", __func__);
		return 0;
	}

	ret = sw_gpio_eint_get_trigtype(irq_gpio, &trigtype);
	if (ret != 0) {
		dev_err(&im501_spi->dev, "%s: sw_gpio_eint_get_trigtype() failed.\n", __func__);
	} else {
		if (trigtype == TRIG_EDGE_POSITIVE) {
			dev_err(&im501_spi->dev, "%s: trigger type is TRIG_EDGE_POSITIVE.\n",
				   __func__);
		} else {
			dev_err(&im501_spi->dev, "%s: trigger type is %d\n", __func__, trigtype);
		}
	}
	ret = sw_gpio_eint_get_enable(irq_gpio, &trigenabled);
	if (ret != 0) {
		dev_err(&im501_spi->dev, "%s: sw_gpio_eint_get_enable() failed.\n", __func__);
	} else {
		dev_err(&im501_spi->dev, "%s: trigger enabled is %d\n", __func__, trigenabled);
	}
#else
	im501_data->irq_gpio = of_get_gpio(np, 0);
	if (gpio_request(im501_data->irq_gpio, "im501_irq")) {
		dev_err(&im501_spi->dev, "irq_gpio %d request failed!\n", im501_data->irq_gpio);
		return 0;
	}

	if (gpio_direction_input(im501_data->irq_gpio)) {
		dev_err(&im501_spi->dev, "irq_gpio gpio_direction_input failed!\n");
		return 0;
	}

	im501_irq = gpio_to_irq(im501_data->irq_gpio);
	irq_set_irq_type(im501_irq, IRQ_TYPE_EDGE_RISING);
	ret = request_irq(im501_irq, im501_irq_handler, IRQF_TRIGGER_RISING,
			 "im501_spi", NULL);
	if (ret) {
		dev_err(&im501_spi->dev, "%s: irq %d request fail!\n", __func__, im501_irq);
		return ret;
	}
#endif

	im501_data->reset_gpio = of_get_named_gpio(np, "reset-gpios", 0);
	if (gpio_request(im501_data->reset_gpio, "im501_reset")) {
		dev_err(&im501_spi->dev, "reset_gpio %d request failed!\n", im501_data->reset_gpio);
		return 0;
	}

	if (gpio_direction_output(im501_data->reset_gpio, 1)) {
		dev_err(&im501_spi->dev, "reset_gpio gpio_direction_output failed!\n");
		return 0;
	}

	schedule_work(&im501_fw_load_work);

	dev_info(&im501_spi->dev, "%s: success\n", __func__);

	return 0;
}

static int im501_spi_remove(struct spi_device *spi)
{
	dev_info(&im501_spi->dev, "%s: entering...\n", __func__);

#ifdef CUBIETRUCK
	sw_gpio_irq_free(im501_irq);
#endif

	flush_workqueue(im501_irq_wq);
	destroy_workqueue(im501_irq_wq);
	gpio_free(im501_data->irq_gpio);
	gpio_free(im501_data->reset_gpio);

	return 0;
}

static struct spi_driver im501_spi_driver = {
	.driver = {
		   .name = "im501_spi",
		   .owner = THIS_MODULE,
#ifdef CONFIG_OF
		   .of_match_table = of_match_ptr(im501_spi_dt_ids),
#endif
		   },
	.probe = im501_spi_probe,
	.remove = im501_spi_remove,
	//Henry add for try
	.id_table = im501_spi_id,
	//End of try
};

//module_spi_driver(im501_spi_driver);

static int __init im501_spi_init(void)
{
	int status;

	status = spi_register_driver(&im501_spi_driver);
	if (status < 0) {
		dev_err(&im501_spi->dev, "%s: im501_spi_driver failure. status = %d\n", __func__,
			   status);
	}
	dev_info(&im501_spi->dev, "%s: im501_spi_driver success. status = %d\n", __func__, status);
	return status;
}

module_init(im501_spi_init);

static void __exit im501_spi_exit(void)
{
	spi_unregister_driver(&im501_spi_driver);
}

module_exit(im501_spi_exit);

MODULE_DESCRIPTION("IM501 SPI driver");
MODULE_AUTHOR("<henryhzhang@fortemedia.com>, <fuli@fortemedia.com>");
MODULE_LICENSE("GPL v2");
