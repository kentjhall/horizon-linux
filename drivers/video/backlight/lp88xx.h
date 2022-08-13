/*
 * TI LP88XX Backlight Core Driver
 *
 * Copyright 2016 Texas Instruments
 *
 * Copyright (c) 2017, NVIDIA CORPORATION, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __BL_LP88XX_H
#define __BL_LP88XX_H

#include <linux/pwm.h>
#include <drm/drm_fixed.h>

#define EEPROM_NUM_ADDR			22
#define LP88XX_NUM_REGIONS		6
#define LP88XX_NUM_BRT_LEVELS		6

enum lp88xx_chip_id {
	LP8580,
	LP88XX,
};

struct lp88xx_io {
	int (*write)(void *p, u16 reg, u16 val);
	int (*read)(void *p, u16 reg, u16 *val);
};

struct eeprom_datum {
	u16 addr;
	u16 val;
};

struct lp88xx {
	struct device *dev;
	void *priv;
	struct lp88xx_io io;
	unsigned long region_used;	/* Bit mask for LED region map */
	struct pwm_device *pwm;
	unsigned int period;
	u16 max_dev_brt;
	struct eeprom_datum default_eeprom[EEPROM_NUM_ADDR];
	int eeprom_count;
	int led_strings_used;		/* Number of LED strings used */
	u32 max_input_brt;
	u16 brt_levels[LP88XX_NUM_BRT_LEVELS];	/* Brightness levels */
	u32 pwm_settle_time_int; /* settle time in pwm clock ticks */
	u32 pwm_flash_time_int; /* flash time in pwm clock tickcs */
	u32 frame_duration_ms;
	enum lp88xx_chip_id chip_id;
	bool eeprom_lock;
	bool nvsr_lock;
	bool low_persistence;
};

extern int lp88xx_common_probe(struct device *dev, struct lp88xx *lp);
#endif
