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

#include <linux/backlight.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pwm.h>
#include <linux/slab.h>

#include "lp88xx.h"

#define DEFAULT_BL_NAME			"lcd-bl"
#define LP88XX_MAX_INT_STATUS		3
#define LP88XX_INT_REG_OFFSET		2

#define LP88XX_REG_CAP2		0x06
#define LP88XX_CAP2_MASK		(BIT(12) | BIT(13) | BIT(14) | BIT(15))
#define LP88XX_CAP2_SHIFT		12

#define LP88XX_REG_BL_MODE		0x20
#define LP88XX_BL_MODE_MASK		(BIT(0) | BIT(1))
#define LP88XX_PWM_MODE			0
#define LP88XX_REGISTER_MODE		2
#define LP88XX_BL_EN			BIT(8)
#define LP88XX_NVSR_EN			BIT(11)

/* LP8580 */
#define LP8580_REG_BRT_BASE			0x26
#define LP8580_REG_GROUP1			0x2e
#define LP8580_REG_GROUP2			0x30
#define LP8580_REG_TIMING_CONFIG1		0x34
#define LP8580_FRAME_TIMING_MASK	0xE000
#define LP8580_EXTERNAL_VSYNC		BIT(15)
#define LP8580_INTERNAL_VSYNC		BIT(14)
#define LP8580_LEDX_BX				0x130
#define LP8580_LEDX_BX_DEFAULT		0xFFF8
#define LP8580_LED_BX_OFFSET		0x02
#define LP8580_LEDX_OFFSET		0x0C
#define LP8580_TIMER_T0				0x100
#define LP8580_TIMER_T1				0x102
#define LP8580_TIMER_T2				0x104

#define LP8580_TIMER_T0_OFFSET		0x02
#define LP8580_MAX_BRIGHTNESS		0x1fff

/* EEPROM */
#define LP88XX_EEPROM_CONTROL_1			0x270
#define LP88XX_EEPROM_CONTROL_2			0x272
#define LP88XX_EEPROM_CONTROL_3			0x274
#define LP88XX_EEPROM_CONTROL_4			0x276
#define LP88XX_EEPROM_UNLOCK			0x278
#define LP88XX_EEPROM_UNLOCK_SEQ1	0x1234
#define LP88XX_EEPROM_UNLOCK_SEQ2	0x5678
#define LP88XX_EEPROM_UNLOCK_SEQ3	0x9abc
#define LP88XX_EEPROM_LOCK_SEQ		0x0000
#define LP88XX_READ_EEPROM_DATA		BIT(3)
#define LP88XX_START_EEPROM_PROG	BIT(2)
#define LP88XX_EEPROM0_ADDR			0x0000
#define LP88XX_EEPROM1_ADDR			0x0001

/* PWM */
#define LP88XX_INTERNAL_PLL_FREQ	20000000
#define LP88XX_PWM_FREQ_CONFIG			0x24

/* NVSR */
#define LP88XX_NVSR_LOCK4			0x68
#define LP88XX_NVSR_LOCK5			0x6a
#define LP88XX_NVSR_UNLOCK_SEQ1		0x4356
#define LP88XX_NVSR_UNLOCK_SEQ2		0x9a5f
#define LP88XX_NVSR_UNLOCK_SEQ3		0x93da
#define LP88XX_DEFAULT_FRAME_DURATION	17

/* LP88xx */
#define LP88XX_REG_BRT_BASE			0x28
#define LP88XX_REG_GROUP1			0x30
#define LP88XX_REG_GROUP2			0x32
#define LP88XX_MAX_BRIGHTNESS		0xffff

#define LP88XX_GROUP_MASK		0x0f
#define LP88XX_GROUP_OFFSET		4

#define LP88XX_REG_USER_CONFIG		0x40
#define LP88XX_EN_ADV_SLOPE		BIT(4)
#define LP88XX_SLOPE_MASK		(BIT(5) | BIT(6) | BIT(7))
#define LP88XX_SLOPE_SHIFT		5

#define LP88XX_SLOPE_SHIFT		5
#define LP88XX_INT_STATUS1		0x54
#define LP88XX_INT_STATUS2		0x56
#define LP88XX_INT_STATUS3		0x58

#define LP88XX_REG_BRT_LED1		0x13c
#define LP88XX_REG_BRT_LED2		0x148
#define LP88XX_REG_BRT_LED3		0x154
#define LP88XX_REG_BRT_LED4		0x160
#define LP88XX_REG_BRT_LED5		0x16c

#define LP88XX_REG_DB_CTRL		0x178
#define LP88XX_LOAD_BRT			BIT(0)

#define LP88XX_MAX_PWM_HZ		20000

enum lp88xx_group_led {
	LP88XX_GROUP_LED0,
	LP88XX_GROUP_LED1,
	LP88XX_GROUP_LED2,
	LP88XX_GROUP_LED3,
	LP88XX_GROUP_LED4,
	LP88XX_GROUP_LED5,
};

enum lp88xx_region_id {
	LP88XX_REGION_BASE,
	LP88XX_REGION_LED1,
	LP88XX_REGION_LED2,
	LP88XX_REGION_LED3,
	LP88XX_REGION_LED4,
	LP88XX_REGION_LED5,
};

struct lp88xx_bl {
	struct lp88xx *lp;
	struct backlight_device *bldev;
	unsigned int reg_brt;
	bool is_db_used;	/* Double buffer used or not */
};

static int lp88xx_reg_read(struct lp88xx *lp, u16 reg, u16 *val)
{
	struct lp88xx_io *io = &lp->io;
	int ret;

	ret = io->read(lp->priv, reg, val);
	if (ret)
		dev_err(lp->dev, "IO read error: %d\n", ret);

	return ret;
}

static int lp88xx_reg_write(struct lp88xx *lp, u16 reg, u16 val)
{
	struct lp88xx_io *io = &lp->io;
	int ret;

	ret = io->write(lp->priv, reg, val);
	if (ret)
		dev_err(lp->dev, "IO write error: %d\n", ret);

	return ret;
}

static int lp88xx_read_eeprom(struct lp88xx *lp, u16 reg, u16 *val)
{
	int ret = 0;

	/* EEPROM Map addr to read */
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_CONTROL_2, reg);
	if (ret < 0)
		return ret;
	/* Start EEPROM read */
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_CONTROL_1,
				LP88XX_READ_EEPROM_DATA);
	if (ret < 0)
		return ret;
	/* Read returned value */
	ret = lp88xx_reg_read(lp, LP88XX_EEPROM_CONTROL_3, val);
	if (ret < 0)
		return ret;
	/*Sleep for 150 micro seconds after each read */
	udelay(150);
	return ret;
}

static int lp88xx_write_eeprom(struct lp88xx *lp, u16 reg, u16 val)
{
	int ret = 0;

	if (lp->eeprom_lock) {
		dev_err(lp->dev, "EEPROM is locked! Cannot write\n");
		return -EACCES;
	}

	/* EEPROM Map addr to write */
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_CONTROL_2, reg);
	if (ret < 0)
		return ret;
	/* Value to write */
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_CONTROL_4, val);
	if (ret < 0)
		return ret;
	/* Start EEPROM program */
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_CONTROL_1,
				LP88XX_START_EEPROM_PROG);
	if (ret < 0)
		return ret;
	/* Sleep for 20 milli seconds after each write */
	msleep(20);
	return ret;
}

static int lp88xx_unlock_eeprom(struct lp88xx *lp)
{
	int ret = 0;

	if (!lp->eeprom_lock)
		return ret;
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_UNLOCK,
			LP88XX_EEPROM_UNLOCK_SEQ1);
	if (ret < 0)
		return ret;
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_UNLOCK,
			LP88XX_EEPROM_UNLOCK_SEQ2);
	if (ret < 0)
		return ret;
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_UNLOCK,
			LP88XX_EEPROM_UNLOCK_SEQ3);
	if (ret < 0)
		return ret;

	lp->eeprom_lock = false;
	return ret;
}

static int lp88xx_lock_eeprom(struct lp88xx *lp)
{
	int ret = 0;

	if (lp->eeprom_lock)
		return ret;
	ret = lp88xx_reg_write(lp, LP88XX_EEPROM_UNLOCK,
			LP88XX_EEPROM_LOCK_SEQ);
	if (ret < 0)
		return ret;

	lp->eeprom_lock = true;
	return ret;
}

static int lp88xx_verify_default_eeproms(struct lp88xx *lp)
{
	int ret = 0;
	int index = 0;
	u16 addr, val, default_val = 0;

	for (index = 0; index < lp->eeprom_count; index++) {

		addr = lp->default_eeprom[index].addr;
		default_val = lp->default_eeprom[index].val;

		ret = lp88xx_read_eeprom(lp, addr, &val);
		if (ret) {
			dev_err(lp->dev, "Failed to read EEPROM%d data: %d\n",
				index, ret);
			return ret;
		}

		/* If EEPROM value doesn't match the expected value read
		 * from DT, update the EEPROM with the value read from DT .
		 */
		if (val != default_val) {
			dev_info(lp->dev,
			"EEPROM%d isn't right: 0x%04x, updating default: 0x%04x\n",
			addr, val, default_val);

			/* Unlock EEPROM before writing data to EEPROM */
			ret = lp88xx_unlock_eeprom(lp);
			if (ret) {
				dev_err(lp->dev, "Failed to unlock EEPROM: %d\n",
					ret);
				return ret;
			}

			ret = lp88xx_write_eeprom(lp, addr, default_val);
			if (ret) {
				dev_err(lp->dev,
					"Failed to write EEPROM%d data: %d\n",
					index, ret);
				goto lock_eeprom;
			}
		}
	}

lock_eeprom:
	/* Lock the EEPROM after write */
	ret = lp88xx_lock_eeprom(lp);
	if (ret) {
		dev_err(lp->dev, "Failed to lock  EEPROM: %d\n", ret);
		return ret;
	}

	return ret;
}

static int lp88xx_unlock_nvsr(struct lp88xx *lp)
{
	int ret = 0;
	u16 val = 0;

	if (!lp->nvsr_lock)
		return ret;

	ret = lp88xx_reg_read(lp, LP88XX_NVSR_LOCK4, &val);
	if (ret < 0)
		return ret;

	val ^= LP88XX_NVSR_UNLOCK_SEQ1;

	ret = lp88xx_reg_write(lp, LP88XX_NVSR_LOCK5, val);
	if (ret < 0)
		return ret;

	ret = lp88xx_reg_read(lp, LP88XX_NVSR_LOCK4, &val);
	if (ret < 0)
		return ret;

	val ^= LP88XX_NVSR_UNLOCK_SEQ2;

	ret = lp88xx_reg_write(lp, LP88XX_NVSR_LOCK5, val);
	if (ret < 0)
		return ret;

	ret = lp88xx_reg_read(lp, LP88XX_NVSR_LOCK4, &val);
	if (ret < 0)
		return ret;

	val ^= LP88XX_NVSR_UNLOCK_SEQ3;

	ret = lp88xx_reg_write(lp, LP88XX_NVSR_LOCK5, val);
	if (ret < 0)
		return ret;

	lp->nvsr_lock = false;

	return ret;
}

static int lp88xx_reg_update(struct lp88xx *lp, u16 reg, u16 mask, u16 val)
{
	int ret;
	u16 tmp = 0;

	ret = lp88xx_reg_read(lp, reg, &tmp);
	if (ret < 0)
		return ret;

	tmp &= ~mask;
	tmp |= val;

	return lp88xx_reg_write(lp, reg, tmp);
}

static bool lp88xx_is_valid_region(enum lp88xx_region_id id)
{
	if (id < LP88XX_REGION_BASE || id > LP88XX_REGION_LED5)
		return false;

	return true;
}

static int lp88xx_update_region(struct lp88xx *lp, int group, int id)
{
	unsigned int reg;
	unsigned int shift;

	switch (group) {
	case LP88XX_GROUP_LED0:
	case LP88XX_GROUP_LED1:
	case LP88XX_GROUP_LED2:
	case LP88XX_GROUP_LED3:
		reg = lp->chip_id ? LP88XX_REG_GROUP1 : LP8580_REG_GROUP1;
		shift = group * LP88XX_GROUP_OFFSET;
		break;
	case LP88XX_GROUP_LED4:
	case LP88XX_GROUP_LED5:
		reg = lp->chip_id ? LP88XX_REG_GROUP2 : LP8580_REG_GROUP2;
		shift = (group - 4) * LP88XX_GROUP_OFFSET;
		break;
	default:
		return -EINVAL;
	}

	return lp88xx_reg_update(lp, reg, LP88XX_GROUP_MASK << shift,
				 id << shift);
}

static bool lp88xx_is_new_region(struct lp88xx *lp, int id)
{
	return !test_and_set_bit(id, &lp->region_used);
}

static bool lp88xx_is_db_used(int id)
{
	return id != LP88XX_REGION_BASE;
}

static int lp88xx_bl_on(struct lp88xx *lp, int on)
{
	u16 val;

	if (on)
		val = LP88XX_BL_EN;
	else
		val = 0;

	return lp88xx_reg_update(lp, LP88XX_REG_BL_MODE, LP88XX_BL_EN, val);
}

static int lp88xx_nvsr_brightness_control_enable(struct lp88xx *lp)
{
	int ret = 0, i = 0, j = 0;

	/* Configure frame timing based on external VSYNC input */
	lp88xx_reg_update(lp, LP8580_REG_TIMING_CONFIG1,
			LP8580_FRAME_TIMING_MASK, LP8580_EXTERNAL_VSYNC);

	for (i = 0; i < lp->led_strings_used; i++) {

		/* Assign grouping to LED strings */
		lp88xx_update_region(lp, i, (i * 1));

		/* Change brightness levels for all regions */
		for (j = 0; j < LP88XX_NUM_BRT_LEVELS; j++) {
			lp88xx_reg_write(lp, LP8580_LEDX_BX +
				(j * LP8580_LED_BX_OFFSET) +
				(i * LP8580_LEDX_OFFSET), lp->brt_levels[j]);
		}
	}

	/* In effect, we flash from settle time to (settle time + flash time) */
	lp88xx_reg_write(lp, LP8580_TIMER_T1, lp->pwm_settle_time_int);
	lp88xx_reg_write(lp, LP8580_TIMER_T2, lp->pwm_flash_time_int +
						lp->pwm_settle_time_int);

	/* Enable NVSR and set sel_nvsr_mode to Mode 1 */
	lp88xx_reg_update(lp, LP88XX_REG_BL_MODE, LP88XX_NVSR_EN,
			LP88XX_NVSR_EN);

	return ret;
}

static int lp88xx_nvsr_brightness_control_disable(struct lp88xx *lp)
{
	int ret = 0, i = 0, j = 0;

	for (i = 0; i < lp->led_strings_used; i++) {

		/* Reset brightness levels for all regions */
		for (j = 0; j < LP88XX_NUM_BRT_LEVELS; j++) {
			lp88xx_reg_write(lp, LP8580_LEDX_BX +
				(j * LP8580_LED_BX_OFFSET) +
				(i * LP8580_LEDX_OFFSET),
				LP8580_LEDX_BX_DEFAULT);
		}

		/* Assign grouping to LED strings */
		lp88xx_update_region(lp, i, false);
	}

	/* Reset timer - Common for all LED strings */
	for (j = 0; j < LP88XX_NUM_BRT_LEVELS; j++) {
		lp88xx_reg_write(lp, LP8580_TIMER_T0 +
				(j * LP8580_TIMER_T0_OFFSET), 0);
	}

	/* Wait for the frame duration */
	msleep(lp->frame_duration_ms);

	/* Change frame timing back to internal VSYNC */
	lp88xx_reg_update(lp, LP8580_REG_TIMING_CONFIG1,
			LP8580_FRAME_TIMING_MASK, LP8580_INTERNAL_VSYNC);

	/* Disable NVSR mode */
	lp88xx_reg_update(lp, LP88XX_REG_BL_MODE, LP88XX_NVSR_EN, 0);

	return ret;
}

static fixed20_12 lp88xx_get_pwm_clock_period(struct lp88xx *lp)
{
	u16 pwm_counter_length = 0;
	u32 pwm_clk_freq = 0;
	int ret = 0;
	fixed20_12 fconst, freq;
	fixed20_12 pwm_clk_period_us = dfixed_init(0);

	ret = lp88xx_reg_read(lp, LP88XX_PWM_FREQ_CONFIG, &pwm_counter_length);
	if (ret < 0)
		return pwm_clk_period_us;

	pwm_clk_freq = LP88XX_INTERNAL_PLL_FREQ / (pwm_counter_length + 1);

	fconst.full = dfixed_const(1000000);
	freq.full = dfixed_const(pwm_clk_freq);
	pwm_clk_period_us.full = dfixed_div(fconst, freq);

	dev_dbg(lp->dev, "pwm clk period is %d.%dus\n",
		dfixed_trunc(pwm_clk_period_us),
		dfixed_frac(pwm_clk_period_us) * 1000 / ((1 << 12) - 1));
	return pwm_clk_period_us;
}

static int lp88xx_bl_update_status(struct backlight_device *bldev)
{
	struct lp88xx_bl *bl = bl_get_data(bldev);
	struct lp88xx *lp = bl->lp;
	u32 val = bldev->props.brightness;
	int duty;
	int ret = 0;

	val = val * lp->max_dev_brt / lp->max_input_brt;

	if (val > 0)
		lp88xx_bl_on(lp, 1);
	else
		lp88xx_bl_on(lp, 0);

	/* If low-persistence mode is set */
	if ((bldev->props.state & BL_CORE_LPMODE) && !lp->low_persistence) {
		lp88xx_nvsr_brightness_control_enable(lp);
		dev_dbg(lp->dev, "Enabling low-persistence mode\n");
		lp->low_persistence = true;
	}

	/* If low-persistence mode is unset */
	if (!(bldev->props.state & BL_CORE_LPMODE) && lp->low_persistence) {
		lp88xx_nvsr_brightness_control_disable(lp);
		dev_dbg(lp->dev, "Disabling low-persistence mode\n");
		lp->low_persistence = false;
	}

	/* PWM mode */
	if (lp->pwm) {
		duty = val * lp->period / bldev->props.max_brightness;
		pwm_config(lp->pwm, duty, lp->period);
		if (duty > 0)
			pwm_enable(lp->pwm);
		else
			pwm_disable(lp->pwm);

		return 0;
	}

	/* Register mode */
	ret = lp88xx_reg_write(lp, bl->reg_brt, val);
	if (ret)
		return ret;

	/* Additional command is required when double buffer is used */
	if (bl->is_db_used)
		return lp88xx_reg_write(lp, LP88XX_REG_DB_CTRL,
					LP88XX_LOAD_BRT);

	return 0;
}

static const struct backlight_ops lp88xx_bl_ops = {
	.options = BL_CORE_SUSPENDRESUME,
	.update_status = lp88xx_bl_update_status,
};

static int lp88xx_get_lp_params(struct lp88xx *lp)
{
	int ret = 0, num_levels = 0;
	struct device_node *timings_np, *mode_np;
	const __be32 *num_levels_list;
	u32 temp = 0;
	u32 pclk, refresh_rate;
	u32 h_back_porch, v_back_porch, h_front_porch, v_front_porch;
	u32 h_sync_width, v_sync_width, h_active, v_active, h_total, v_total;
	fixed20_12 per_line_us, fixed_refresh_rate, pwm_clk_period_us;
	fixed20_12 fixed_v_total, time_conv, fixed_temp, frame_duration_ms;
	fixed20_12 v_blank_period_us, v_blank_period_ms, v_blank_period;
	fixed20_12 settle_time_ms, settle_time_us, pwm_settle_time;
	fixed20_12 flash_time_ms, flash_time_us, pwm_flash_time;

	pwm_clk_period_us = lp88xx_get_pwm_clock_period(lp);
	if (!dfixed_trunc(pwm_clk_period_us) &&
	    !dfixed_frac(pwm_clk_period_us))  {
		dev_warn(lp->dev, "Failed to get pwm clock period %d\n",
				ret);
		return ret;
	}
	/* Parse panel timings */
	timings_np = of_parse_phandle(lp->dev->of_node, "panel-timings", 0);
	if (IS_ERR_OR_NULL(timings_np)) {
		dev_err(lp->dev, "cannot find panel timings\n");
		return PTR_ERR(timings_np);
	}

	mode_np = of_get_next_child(timings_np, NULL);

	of_property_read_u32(mode_np, "clock-frequency", &pclk);
	of_property_read_u32(mode_np, "hsync-len", &h_sync_width);
	of_property_read_u32(mode_np, "vsync-len", &v_sync_width);
	of_property_read_u32(mode_np, "hback-porch", &h_back_porch);
	of_property_read_u32(mode_np, "vback-porch", &v_back_porch);
	of_property_read_u32(mode_np, "hactive", &h_active);
	of_property_read_u32(mode_np, "vactive", &v_active);
	of_property_read_u32(mode_np, "hfront-porch", &h_front_porch);
	of_property_read_u32(mode_np, "vfront-porch", &v_front_porch);

	num_levels_list = of_get_property(lp->dev->of_node, "brt-levels",
						&num_levels);
	if (!num_levels_list) {
		dev_err(lp->dev, "warning: using default region brt\n");
		memset(lp->brt_levels, LP8580_LEDX_BX_DEFAULT,
			sizeof(lp->brt_levels));
	} else {
		num_levels /= sizeof(*num_levels_list);
		ret = of_property_read_u16_array(lp->dev->of_node, "brt-levels",
				lp->brt_levels, num_levels);
		if (ret) {
			dev_err(lp->dev, "Failed to get region brt: %d\n", ret);
			return ret;
		}
	}

	h_total = h_sync_width + h_back_porch + h_active + h_front_porch;
	v_total = v_sync_width + v_back_porch + v_active + v_front_porch;
	refresh_rate = pclk / (h_total * v_total);

	/* For s to ms, ms to us and vice-versa conversion */
	time_conv.full = dfixed_const(1000);
	fixed_refresh_rate.full = dfixed_const(refresh_rate);

	frame_duration_ms.full = dfixed_div(time_conv, fixed_refresh_rate);
	fixed_v_total.full = dfixed_const(v_total);
	v_blank_period.full = dfixed_const(v_back_porch + v_front_porch);

	/* Convert duration per line to us for better accuracy */
	fixed_temp.full = dfixed_mul(frame_duration_ms, time_conv);
	per_line_us.full = dfixed_div(fixed_temp, fixed_v_total);

	/* vertical blank period */
	fixed_temp.full = dfixed_mul(per_line_us, v_blank_period);
	v_blank_period_ms.full = dfixed_div(fixed_temp, time_conv);

	dev_dbg(lp->dev, "frame_duration_ms is %d.%dms\n",
			dfixed_trunc(frame_duration_ms),
			dfixed_frac(frame_duration_ms) *
					1000 / ((1 << 12) - 1));
	dev_dbg(lp->dev, "per_line_us is %d.%dus\n",
			dfixed_trunc(per_line_us),
			dfixed_frac(per_line_us) * 1000 / ((1 << 12) - 1));
	dev_dbg(lp->dev, "v_blank_period_ms is %d.%dms\n",
			dfixed_trunc(v_blank_period_ms),
			dfixed_frac(v_blank_period_ms) *
					1000 / ((1 << 12) - 1));

	ret = of_property_read_u32(lp->dev->of_node, "settle-time-us", &temp);
	if (ret) {
		dev_err(lp->dev, "cannot find settle time\n");
		return ret;
	}
	settle_time_us.full = dfixed_const(temp);
	settle_time_ms.full = dfixed_div(settle_time_us, time_conv);
	v_blank_period_us.full = dfixed_mul(v_blank_period_ms, time_conv);

	/* Flash time is optional.
	 * If not specified, use (vblank - settle time) as flash time.
	 */
	if (of_property_read_u32(lp->dev->of_node, "flash-time-us", &temp)) {
		dev_info(lp->dev, "use (vblank - settle time) as flash time\n");
		flash_time_us.full = dfixed_const(
					dfixed_trunc(v_blank_period_us) -
					dfixed_trunc(settle_time_us));
		flash_time_ms.full = dfixed_div(flash_time_us, time_conv);
	} else {
		flash_time_us.full = dfixed_const(temp);
		flash_time_ms.full = dfixed_div(flash_time_us, time_conv);
	}

	/* Timer offsets are counted as PWM clock periods */
	pwm_settle_time.full = dfixed_div(settle_time_us, pwm_clk_period_us);
	pwm_flash_time.full = dfixed_div(flash_time_us, pwm_clk_period_us);

	/* We are writing only the integer part into timer offset registers */
	lp->pwm_settle_time_int = dfixed_trunc(pwm_settle_time);
	lp->pwm_flash_time_int = dfixed_trunc(pwm_flash_time);
	lp->frame_duration_ms = dfixed_trunc(frame_duration_ms);

	dev_dbg(lp->dev, "settle time is %d.%dms, pwm settle time is %d\n",
		dfixed_trunc(settle_time_ms),
		dfixed_frac(settle_time_ms) * 100 / ((1 << 12) - 1),
		lp->pwm_settle_time_int);
	dev_dbg(lp->dev, "flash time is %d.%dms, pwm flash time is %d\n",
		dfixed_trunc(flash_time_ms),
		dfixed_frac(flash_time_ms) * 100 / ((1 << 12) - 1),
		lp->pwm_flash_time_int);

	return ret;
}

static int lp88xx_add_bl_device(struct lp88xx *lp, int id)
{
	struct lp88xx_bl *bl;
	struct device *dev = lp->dev;
	struct backlight_properties props;
	char name[64];
	int ret = 0;
	const char *pname;
	u32 temp = 0;
	unsigned int reg_brt[] = {
		[LP88XX_REGION_BASE] =
			lp->chip_id ? LP88XX_REG_BRT_BASE : LP8580_REG_BRT_BASE,
		[LP88XX_REGION_LED1] = LP88XX_REG_BRT_LED1,
		[LP88XX_REGION_LED2] = LP88XX_REG_BRT_LED2,
		[LP88XX_REGION_LED3] = LP88XX_REG_BRT_LED3,
		[LP88XX_REGION_LED4] = LP88XX_REG_BRT_LED4,
		[LP88XX_REGION_LED5] = LP88XX_REG_BRT_LED5,
	};

	bl = devm_kzalloc(dev, sizeof(*bl), GFP_KERNEL);
	if (!bl)
		return -ENOMEM;

	bl->lp = lp;
	bl->reg_brt = reg_brt[id];
	bl->is_db_used = lp88xx_is_db_used(id);

	memset(name, 0, sizeof(name));
	if (!of_property_read_string_index(dev->of_node, "names",
		id, &pname))
		snprintf(name, sizeof(name), "%s", pname);
	else
		snprintf(name, sizeof(name), "%s:%d", DEFAULT_BL_NAME, id);

	memset(&props, 0, sizeof(props));

	if (of_property_read_u32(dev->of_node, "low-persistence", &temp))
		props.low_persistence_capable = false;
	else
		props.low_persistence_capable = (bool) temp;

	if (props.low_persistence_capable) {
		/* Unlock NVSR for enabling NVSR brightness mode */
		ret = lp88xx_unlock_nvsr(lp);
		if (ret < 0) {
			dev_err(dev, "Failed to unlock nvsr %d\n", ret);
			return ret;
		}
	}

	if (props.low_persistence_capable) {
		/* Get low-persistence related params */
		if (lp88xx_get_lp_params(lp))
			return ret;
	}

	props.type = BACKLIGHT_PLATFORM;
	props.max_brightness = lp->max_input_brt;
	props.brightness = 0;
	if (of_property_read_s32(dev->of_node, "init-brt", &props.brightness))
		dev_warn(dev, "Using default init-brt \n");

	bl->bldev = devm_backlight_device_register(dev, name, dev, bl,
						   &lp88xx_bl_ops, &props);
	if (IS_ERR(bl))
		return PTR_ERR(bl);

	backlight_update_status(bl->bldev);

	return 0;
}

static int lp88xx_update_bl_mode(struct lp88xx *lp)
{
	struct pwm_device *pwm;
	unsigned int period;

	pwm = devm_pwm_get(lp->dev, NULL);
	if (IS_ERR(pwm) && PTR_ERR(pwm) != -EPROBE_DEFER) {
		dev_info(lp->dev, "Unable to request PWM, use register mode.\n");
		return lp88xx_reg_update(lp, LP88XX_REG_BL_MODE,
					 LP88XX_BL_MODE_MASK,
					 LP88XX_REGISTER_MODE);
	}

	period = pwm_get_period(pwm);
	if (period == 0 || period > LP88XX_MAX_PWM_HZ) {
		dev_err(lp->dev, "Invalid PWM frequency: %d\n", period);
		return -EINVAL;
	}

	lp->pwm = pwm;
	lp->period = period;

	return lp88xx_reg_update(lp, LP88XX_REG_BL_MODE, LP88XX_BL_MODE_MASK,
				 LP88XX_PWM_MODE);
}

static int lp88xx_get_slope_time_index(struct lp88xx *lp, unsigned int msec)
{
	unsigned int table[] = { 0, 1, 2, 50, 100, 200, 300, 500, };
	int size = ARRAY_SIZE(table);
	int i;

	if (msec <= table[0])
		return 0;

	if (msec > table[size - 1])
		return size - 1;

	for (i = 1; i < size; i++) {
		if (msec == table[i])
			return i;

		/* Find the approximate index by looking up table */
		if (msec > table[i - 1] && msec < table[i]) {
			if (msec - table[i - 1] > table[i] - msec)
				return i;
			else
				return i - 1;
		}
	}

	return 0;
}

static irqreturn_t lp88xx_irq_handler(int irq, void *ptr)
{
	struct lp88xx *lp = ptr;
	u16 status[LP88XX_MAX_INT_STATUS];
	int offset = 0;
	int i, ret;

	for (i = 0; i < LP88XX_MAX_INT_STATUS; i++) {
		ret = lp88xx_reg_read(lp, LP88XX_INT_STATUS1 + offset,
				      &status[i]);
		if (ret)
			return IRQ_NONE;

		dev_info(lp->dev, "INT STATUS %d: 0x%.4x\n", i, status[i]);

		offset += LP88XX_INT_REG_OFFSET;
	}

	return IRQ_HANDLED;
}

int lp88xx_common_probe(struct device *dev, struct lp88xx *lp)
{
	struct device_node *np = dev->of_node;
	struct property *prop;
	const __be32 *list, *p;
	u32 u = 0;
	u32 *region;
	u32 slope_ms;
	u8 index = 0;
	u16 val = 0;
	int en_gpio, irq_gpio;
	int i, ret, size;
	int eeprom_count = 0;

	/* HW enable pin control */
	en_gpio = of_get_named_gpio(np, "enable-gpios", 0);
	if (gpio_is_valid(en_gpio)) {
		ret = devm_gpio_request_one(dev, en_gpio, GPIOF_OUT_INIT_HIGH,
					    "lp88xx-en");
		if (ret) {
			dev_err(dev, "Enable pin request error: %d\n", ret);
			return ret;
		}

		usleep_range(1000, 1500);
	}

	/* Allocate backlight device upon parsing DT property */
	list = of_get_property(np, "region-map", &size);
	if (!list) {
		dev_err(dev, "Failed to get region map\n");
		return -EINVAL;
	}

	size /= sizeof(*list);
	if (size != LP88XX_NUM_REGIONS) {
		dev_err(dev, "Invalid region info. Size: %d\n", size);
		return -EINVAL;
	}

	region = devm_kzalloc(dev, sizeof(*region) * size, GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	ret = of_property_read_u32_array(np, "region-map", region, size);
	if (ret) {
		dev_err(dev, "Failed to get region map: %d\n", ret);
		return ret;
	}

	if (of_device_is_compatible(np, "ti,lp8580"))
		lp->chip_id = LP8580;
	else
		lp->chip_id = LP88XX;

	lp->eeprom_lock = true;
	lp->nvsr_lock = true;
	lp->low_persistence = false;

	ret = lp88xx_reg_read(lp, LP88XX_REG_CAP2, &val);
	if (ret) {
		dev_warn(dev, "warning: using default max brightness\n");
		lp->max_dev_brt =
			lp->chip_id ? LP88XX_MAX_BRIGHTNESS : LP8580_MAX_BRIGHTNESS;
	} else {
		val = (val & LP88XX_CAP2_MASK) >> LP88XX_CAP2_SHIFT;
		lp->max_dev_brt = (1U << val) - 1;
	}

	if (of_property_read_u32(dev->of_node, "max-input-brt",
		&lp->max_input_brt))
		lp->max_input_brt = lp->max_dev_brt;

	if (of_property_read_u32(dev->of_node, "led-strings-used",
					&lp->led_strings_used)) {
		dev_warn(dev, "warning: using default led-strings-used\n");
		lp->led_strings_used = LP88XX_NUM_REGIONS;
	}

	of_property_for_each_u32(dev->of_node, "default-eeprom", prop, p, u)
		eeprom_count++;

	if (eeprom_count) {
		lp->eeprom_count = eeprom_count;
		eeprom_count = 0;
		of_property_for_each_u32(dev->of_node, "default-eeprom", prop,
				p, u) {
			lp->default_eeprom[eeprom_count].addr = (u16)
						((u & 0xFFFF0000) >> 16);
			lp->default_eeprom[eeprom_count].val = (u16)u;
			eeprom_count++;
		}
	} else {
		dev_err(dev, "Failed to get default eeprom data\n");
	}

	for (i = 0; i < size; i++) {
		if (!lp88xx_is_valid_region(region[i])) {
			dev_err(dev, "Invalid region ID: %d\n", region[i]);
			return -EINVAL;
		}

		ret = lp88xx_update_region(lp, i, region[i]);
		if (ret) {
			dev_err(dev, "Failed to update region ID: %d\n", ret);
			return ret;
		}

		if (!lp88xx_is_new_region(lp, region[i]))
			continue;

		ret = lp88xx_add_bl_device(lp, region[i]);
		if (ret) {
			dev_err(dev, "Failed to add backlight: %d\n", ret);
			return ret;
		}
	}

	/* Verify default EEPROM data */
	ret = lp88xx_verify_default_eeproms(lp);
	if (ret) {
		dev_err(dev, "Failed to verify eeprom data: %d\n", ret);
		return ret;
	}

	/* Backlight mode configuration */
	ret = lp88xx_update_bl_mode(lp);
	if (ret) {
		dev_err(dev, "Failed to update backlight mode: %d\n", ret);
		return ret;
	}

	/* Configure slope time */
	if (!of_property_read_u32(np, "slope-time-ms", &slope_ms)) {
		index = lp88xx_get_slope_time_index(lp, slope_ms);
		ret = lp88xx_reg_update(lp, LP88XX_REG_USER_CONFIG,
					LP88XX_SLOPE_MASK,
					index << LP88XX_SLOPE_SHIFT);
		if (ret)
			return ret;
	}

	/* Apply advanced slope feature */
	if (of_property_read_bool(np, "advanced-slope-enabled")) {
		ret = lp88xx_reg_update(lp, LP88XX_REG_USER_CONFIG,
					LP88XX_EN_ADV_SLOPE,
					LP88XX_EN_ADV_SLOPE);
		if (ret)
			return ret;
	}

	/* Interrupt pin */
	irq_gpio = of_get_named_gpio(np, "irq-gpios", 0);
	if (gpio_is_valid(irq_gpio)) {
		ret = devm_gpio_request_one(dev, irq_gpio, GPIOF_DIR_IN,
					    "lp88xx-int");
		if (ret) {
			dev_err(dev, "IRQ pin request error: %d\n", ret);
			return ret;
		}

		return devm_request_threaded_irq(lp->dev, gpio_to_irq(irq_gpio),
					NULL, lp88xx_irq_handler,
					IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
					"lp88xx-irq", lp);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(lp88xx_common_probe);

MODULE_LICENSE("GPL v2");
