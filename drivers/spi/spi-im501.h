/*
 * drivers/spi/spi-im501.h
 * (C) Copyright 2014-2018
 * Fortemedia, Inc. <www.fortemedia.com>
 * Author: HenryZhang <henryhzhang@fortemedia.com>;
 * 			LiFu <fuli@fortemedia.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#ifndef __IM501_SPI_H__
#define __IM501_SPI_H__

//#define CUBIETRUCK

#define IM501_FIRMWARE_PATH	"/system/vendor/firmware/"

#define WAKEUP_FIRMWARE		0
#define ULTRASOUND_FIRMWARE	1

#ifdef CUBIETRUCK
#define IM501_SPI_BUF_LEN 48	//changed to 48 due to dma issue
#else
#define IM501_SPI_BUF_LEN 4000
#endif

#define POWER_SAVING_MODE	0
#define NORMAL_MODE			1

#define IM501_SPI_CMD_DM_WR             0x05
#define IM501_SPI_CMD_DM_RD             0x01
#define IM501_SPI_CMD_IM_WR             0x04
#define IM501_SPI_CMD_IM_RD             0x00
#define IM501_SPI_CMD_REG_WR            0x06
#define IM501_SPI_CMD_REG_RD            0x02

#define ESUCCESS			0
#define EUNKNOWN			10000
#define EDUPOPEN			10001
#define EFAILOPEN			10002
#define ENOTOPEN			10003
#define EPARAMINVAL			10004
#define EDATAINVAL			10005
#define ESPIREAD			10006
#define ESPIWRITE			10007
#define ESPISETFAIL			10008
#define EDSPNOTWORK			10009
#define ENOMEMORY			10010
#define EMEMFAULT			10011
#define ECANNOTENRECORD		10012
#define ENOSDCARD			10013
#define EFILECANNOTWRITE	10014
#define EINPROCESSING		10015
#define EFAILTOSETMODE		10016
#define ECOMMANDINVAL		10017

#define MAX_COMMENT_LEN			100
#define MAX_PATH_LEN			128
#define CONFIG_LINE_LEN			255

typedef struct cfg_mode_cmd_t {
	u32 mode;
	char path_setting_file_name[MAX_PATH_LEN];
	char dsp_setting_file_name[MAX_PATH_LEN];
	char comment[MAX_COMMENT_LEN];
} cfg_mode_cmd;

typedef struct dev_cmd_t {
	u32 reg_addr;
	u32 val;
} dev_cmd;

int im501_spi_read_reg(u8 reg, u8 *val);
int im501_spi_write_reg(u8 reg, u8 val);
int im501_spi_read_dram(u32 addr, u8 *pdata);
int im501_spi_write_dram(u32 addr, u8 *pdata);
int im501_spi_burst_read_dram(u32 addr, u8 *rxbuf, size_t len);

unsigned char request_start_voice_buf_trans(void);
unsigned char request_stop_voice_buf_trans(void);
unsigned char request_enter_psm(void);

/**
 * codec2im501_pdm_clki_set - external function to set/unset the pdm_clki to im501
 * @set_flag: the flag to set or unset the pdm_clki.
 *            true - set the clk, false - unset the clk.
 * @pdm_clki_rate: the demanded pdm_clki rate. 2MHz for DSP normal mode.
 *                 this parameter is not used when unset the pdm_clki.
 * Return: zero for success set/unset, or non-zero for failure.
 */
extern int codec2im501_pdm_clki_set(bool set_flag, u32 pdm_clki_rate);

#endif				/* __IM501_SPI_H__ */
