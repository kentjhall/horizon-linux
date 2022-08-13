/*
 * isl9238_charger.c -- ISL9238 Narrow o/p voltage DC charger driver
 *
 * Copyright (C) 2017-2018 NVIDIA CORPORATION. All rights reserved.
 *
 * Author: Venkat Reddy Talla <vreddytalla@nvidia.com>
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

#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/power/battery-charger-gauge-comm.h>
#include <linux/regmap.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/of_regulator.h>
#include <linux/regulator/machine.h>

#define MAX_STR_PRINT	50

/* Register definitions */
#define ISL9238_CHG_CURR_LIMIT		0x14
#define ISL9238_MAX_SYS_VOLTAGE		0x15
#define ISL9238_T1_T2_TWO_LEVEL		0x38
#define ISL9238_CONTROL0_OPTIONS	0x39
#define ISL9238_INFO1_CHG_STATUS	0x3A
#define ISL9238_ADPTR_CURR_LIMIT2	0x3B
#define ISL9238_CONTROL1_OPTIONS	0x3C
#define ISL9238_CONTROL2_OPTIONS	0x3D
#define ISL9238_MIN_SYS_VOLTAGE		0x3E
#define ISL9238_ADPTR_CURR_LIMIT1	0x3F
#define ISL9238_AC_PROCHOT		0x47
#define ISL9238_DC_PROCHOT		0x48
#define ISL9238_OTG_VOLTAGE		0x49
#define ISL9238_OTG_CURRENT		0x4A
#define ISL9238_INPUT_VOLTAGE		0x4B
#define ISL9238_CONTROL3_OPTIONS	0x4C
#define ISL9238_INFO2_CHG_STATUS	0x4D
#define ISL9238_CONTROL4_OPTIONS	0x4E
#define ISL9238_MANUFACTURER_ID		0xFE
#define ISL9238_DEVICE_ID		0xFF

#define ISL9238_CHG_CURR_LIMIT_MASK	0x1FFC
#define ISL9238_MAX_SYS_VOLTAGE_MASK	0x7FF8
#define ISL9238_MIN_SYS_VOLTAGE_MASK	0x3F00
#define ISL9238_INPUT_VOLTAGE_MASK	0x3F00
#define ISL9238_ADPTR_CURR_LIMIT1_MASK	0x1FFC
#define ISL9238_ADPTR_CURR_LIMIT2_MASK	0x1FFC
#define ISL9238_AC_PROCHOT_MASK		0x1F80
#define ISL9238_DC_PROCHOT_MASK		0x3F00
#define ISL9238_OTG_MASK		0x800
#define ISL9238_OTG_ENABLE		0x800
#define ISL9238_OTG_DISABLE		0x0
#define ISL9238_REGULATION_MASK		0x4
#define ISL9238_BAT_LEARN_MASK		0x1000
#define ISL9238_TURBO_MODE_MASK		0x40
#define ISL9238_TURBO_MODE_DISABLE	0x40
#define ISL9238_AUTO_CHARGE_MODE_MASK	0x80
#define ISL9238_SMBUS_TIMER_MASK	0x80
#define ISL9238_BATTERY_OVP_MASK	0x80
#define ISL9238_TRICKLE_CHG_CURR_MASK	0xC000
#define ISL9238_OTG_CURRENT_MASK	0x1F80
#define ISL9238_RELOAD_ACLIM_MASK	BIT(14)
#define ISL9238_REREAD_PROG_MASK	BIT(15)

#define ISL9238_TRICKLE_CHG_MODE		BIT(4)
#define ISL9238_LOW_VSYS_PROCHOT		BIT(10)
#define ISL9238_DC_PROCHOT_TRIP			BIT(11)
#define ISL9238_AC_OTG_CURR_PROCHOT		BIT(12)
#define ISL9238_LOW_POWER_MODE			BIT(15)
#define ISL9238_BATGON_PIN_STATE		BIT(12)
#define ISL9238_COMPARATOR_OUTPUT		BIT(13)
#define ISL9238_ACOK_PIN_STATE			BIT(14)
#define ISL9238_ACTIVE_CNTRL_LOOP_MASK		0x6000
#define ISL9238_CHG_CURRENT_LOOP		0x2000
#define ISL9238_ADAPTER_CURRENT_LOOP		0x4000
#define ISL9238_INPUT_VOLTAGE_LOOP		0x6000
#define ISL9238_CHARGER_MODE_MASK		0xE0
#define ISL9238_BOOST_MODE			0x20
#define ISL9238_BUCK_MODE			0x40
#define ISL9238_BUCK_BOOST_MODE			0x60
#define ISL9238_OTG_BOOST_MODE			0xA0
#define ISL9238_OTG_BUCK_MODE			0xC0
#define ISL9238_OTG_BUCK_BOOST_MODE		0xE0
#define ISL9238_BATTERY_STATE			BIT(12)
#define ISL9238_ADAPTER_STATE			BIT(14)
#define ISL9238_SMBUS_TIMER_ENABLE		BIT(7)
#define ISL9238_BATTERY_OVP_ENABLE		BIT(1)
#define ISL9238_TRIGGER_PROCHOT_ACOK		BIT(5)
#define ISL9238_TRIGGER_OTG_CURR		BIT(7)
#define ISL9238_PSYS_POWER_MONITOR		BIT(3)
#define ISL9238_ADPTR_CHG_CURR_MIN		0x8
#define ISL9238_ADPTR_CHG_CURR_MAX		0x2F80
#define ISL9238_BAT_CHG_CURRENT_SMBUSK		BIT(7)
#define ISL9238_DISABLE_RELOAD_ACLIM		BIT(14)
#define ISL9238_DISABLE_REREAD_PROG		BIT(15)

#define ISL9238_CURR_SENSE_RES_OTP	10
#define ISL9238_ADPTR_SENSE_RES_OTP	20

#define ISL9238_TEMP_H_CHG_DISABLE	60
#define ISL9238_TEMP_L_CHG_DISABLE	0

static const struct regmap_range isl9238_readable_ranges[] = {
	regmap_reg_range(ISL9238_CHG_CURR_LIMIT, ISL9238_CONTROL4_OPTIONS),
	regmap_reg_range(ISL9238_MANUFACTURER_ID, ISL9238_DEVICE_ID),
};

static const struct regmap_access_table isl9238_readable_table = {
	.yes_ranges = isl9238_readable_ranges,
	.n_yes_ranges = ARRAY_SIZE(isl9238_readable_ranges),
};

static const struct regmap_config isl9238_rmap_config = {
	.reg_bits		= 8,
	.val_bits		= 16,
	.max_register		= ISL9238_DEVICE_ID,
	.cache_type		= REGCACHE_NONE,
	.val_format_endian	= REGMAP_ENDIAN_NATIVE,
	.rd_table		= &isl9238_readable_table,
};

struct isl9238_vbus_pdata {
	struct regulator_init_data *ridata;
};

struct isl9238_chg_pdata {
	struct isl9238_vbus_pdata *vbus_pdata;
	int num_consumer_supplies;
	struct regulator_consumer_supply *consumer_supplies;
	struct regulator_init_data	*chg_ridata;

	const char *tz_name;
	int temp_poll_time;
	int temp_range_len;
	u32 *temp_range;
	int *temp_chg_curr_lim;
	u32 *max_battery_voltage;
	u32 *voltage_curr_lim;

	u32 charge_current_lim;
	u32 max_sys_voltage;
	u32 max_init_voltage;
	u32 min_sys_voltage;
	u32 input_voltage_limit;
	u32 adapter_current_lim1;
	u32 adapter_current_lim2;
	u32 acprochot_threshold;
	u32 dcprochot_threshold;
	u32 adapter_duration_t1;
	u32 adapter_duration_t2;
	u32 trickle_chg_current;
	u32 curr_sense_resistor;
	u32 adapter_sense_resistor;
	u32 otg_voltage;
	u32 otg_current;
	u32 terminate_chg_current;
	bool disable_input_regulation;
	bool enable_bat_learn_mode;
	bool disable_turbo_mode;
	bool enable_auto_charging;
	bool disable_safety_timer;
	bool enable_battery_ovp; /* over voltage protection */
	bool enable_prochot_acok; /*trigger prochot with acook */
	bool enable_prochot_otg_curr; /* trigger prochot with otgcurrent */
	bool enable_psys_monitor; /* system power monitor PSYS */
};

struct isl9238_charger {
	struct device		*dev;
	struct i2c_client	*client;
	struct regmap		*rmap;
	int			irq;

	struct mutex		mutex; /* mutex for charger */
	struct mutex		otg_mutex; /* mutex for otg */

	struct isl9238_chg_pdata *chg_pdata;

	struct regulator_dev		*vbus_rdev;
	struct regulator_desc		vbus_reg_desc;
	struct regulator_init_data	*vbus_ridata;
	struct device_node		*vbus_np;

	struct regulator_init_data	*chg_ridata;
	struct regulator_dev		*chg_rdev;
	struct regulator_desc		chg_reg_desc;
	struct device_node		*chg_np;

	struct battery_charger_dev	*bc_dev;

	bool	is_otg_connected;
	bool	shutdown_complete;
	bool	disable_sc7_during_charging;
	bool	wake_lock_released;
	bool	cable_connected;
	bool	thermal_chg_disable;
	bool	terminate_charging;
	bool	emulate_input_disconnected;
	u32	chg_status;
	u32	in_current_limit;
	u32	last_adapter_current;
	u32	in_voltage_limit;
	u32	last_adapter_voltage;
	u32	last_otg_voltage;
	u32	otg_voltage_limit;
	u32	curnt_sense_res;
	u32	adptr_sense_res;
	u32	charging_current_lim;
	u32	adapter_curr_lim1;
	u32	max_init_voltage;
	u32	max_sys_voltage;
	u32	terminate_chg_current;
	int	last_temp;
};

struct isl9238_charger *isl9238_bc;

static inline int isl9238_write(struct isl9238_charger *isl9238,
				u8 reg, unsigned int reg_val)
{
	return regmap_write(isl9238->rmap, reg, reg_val);
}

static inline int isl9238_read(struct isl9238_charger *isl9238, u8 reg)
{
	unsigned int reg_val;
	int ret;

	ret = regmap_read(isl9238->rmap, reg, &reg_val);
	if (ret < 0)
		return ret;

	return reg_val;
}

static int isl9238_update_bits(struct isl9238_charger *isl9238, u8 reg,
			       unsigned int mask, unsigned int reg_val)
{
	return regmap_update_bits(isl9238->rmap, reg, mask, reg_val);
}

static int isl9238_val_to_reg(int val, int offset, int div, int nbits,
			      bool roundup)
{
	int max_val = offset + (BIT(nbits) - 1) * div;

	if (val <= offset)
		return 0;

	if (val >= max_val)
		return BIT(nbits) - 1;

	if (roundup)
		return DIV_ROUND_UP(val - offset, div);
	else
		return (val - offset) / div;
}

#if defined(CONFIG_SYSFS)
static ssize_t charging_state_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int ret;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}
	ret = isl9238_read(isl9238_bc, ISL9238_CHG_CURR_LIMIT);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(dev, "register read fail: %d\n", ret);
		return ret;
	}

	if (ret)
		return snprintf(buf, MAX_STR_PRINT, "enabled\n");
	else
		return snprintf(buf, MAX_STR_PRINT, "disabled\n");
}

static ssize_t charging_state_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	unsigned int rval;
	int ret;
	bool enabled;

	if ((*buf == 'E') || (*buf == 'e'))
		enabled = true;
	else if ((*buf == 'D') || (*buf == 'd'))
		enabled = false;
	else
		return -EINVAL;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	if (enabled) {
		rval = isl9238_bc->charging_current_lim *
				isl9238_bc->curnt_sense_res /
				ISL9238_CURR_SENSE_RES_OTP;
		rval = rval & ISL9238_CHG_CURR_LIMIT_MASK;
		isl9238_bc->last_temp = 0;
		battery_charger_thermal_start_monitoring(isl9238_bc->bc_dev);
	} else {
		rval = 0;
		isl9238_bc->last_temp = 0;
		battery_charger_thermal_stop_monitoring(isl9238_bc->bc_dev);
	}

	ret = isl9238_write(isl9238_bc, ISL9238_CHG_CURR_LIMIT, rval);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(isl9238_bc->dev, "register write fail: %d\n", ret);
		return ret;
	}

	return count;
}

static ssize_t input_cable_state_show(struct device *dev,
				      struct device_attribute *attr, char *buf)

{
	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}
	mutex_unlock(&isl9238_bc->mutex);

	if (isl9238_bc->emulate_input_disconnected)
		return snprintf(buf, MAX_STR_PRINT, "Disconnected\n");
	else
		return snprintf(buf, MAX_STR_PRINT, "Connected\n");
}

static ssize_t input_cable_state_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)

{
	unsigned int rval;
	int ret;
	bool connect;

	if ((*buf == 'C') || (*buf == 'c'))
		connect = true;
	else if ((*buf == 'D') || (*buf == 'd'))
		connect = false;
	else
		return -EINVAL;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	if (connect) {
		isl9238_bc->emulate_input_disconnected = false;
		rval = isl9238_bc->adapter_curr_lim1 *
				isl9238_bc->adptr_sense_res /
				ISL9238_ADPTR_SENSE_RES_OTP;
		rval = rval & ISL9238_ADPTR_CURR_LIMIT1_MASK;
		isl9238_bc->last_temp = 0;
		battery_charger_thermal_start_monitoring(isl9238_bc->bc_dev);
	} else {
		isl9238_bc->emulate_input_disconnected = true;
		rval = 0;
		isl9238_bc->last_temp = 0;
		battery_charger_thermal_stop_monitoring(isl9238_bc->bc_dev);
	}

	ret = isl9238_write(isl9238_bc, ISL9238_ADPTR_CURR_LIMIT1, rval);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(isl9238_bc->dev, "register write fail: %d\n", ret);
		return ret;
	}

	if (connect)
		dev_info(isl9238_bc->dev,
			 "Emulation of charger cable disconnect disabled\n");
	else
		dev_info(isl9238_bc->dev,
			 "Emulated as charger cable disconnected\n");
	return count;
}

static ssize_t charge_current_limit_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	int ret;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	ret = isl9238_read(isl9238_bc, ISL9238_CHG_CURR_LIMIT);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(isl9238_bc->dev, "charge curnt read fail:%d", ret);
		return ret;
	}

	if (isl9238_bc->curnt_sense_res)
		ret = ret * ISL9238_CURR_SENSE_RES_OTP /
			isl9238_bc->curnt_sense_res;

	return snprintf(buf, MAX_STR_PRINT, "%u mA\n", ret);
}

static ssize_t charge_current_limit_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	int curr_val, rval, ret;

	if (kstrtouint(buf, 0, &curr_val)) {
		dev_err(isl9238_bc->dev, "current limit read fail\n");
		return -EINVAL;
	}

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	if (isl9238_bc->curnt_sense_res)
		curr_val = curr_val * isl9238_bc->curnt_sense_res /
			ISL9238_CURR_SENSE_RES_OTP;

	rval = curr_val & ISL9238_CHG_CURR_LIMIT_MASK;
	ret = isl9238_write(isl9238_bc, ISL9238_CHG_CURR_LIMIT, rval);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(isl9238_bc->dev, "charge curnt write fail:%d\n", ret);
		return ret;
	}

	return count;
}

static ssize_t charge_current_range_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	int ret = 0;

	ret = snprintf(buf + strlen(buf), MAX_STR_PRINT, "%d mA to %d mA\n",
		       ISL9238_ADPTR_CHG_CURR_MIN, ISL9238_ADPTR_CHG_CURR_MAX);

	return ret;
}

static ssize_t adapter_current_limit_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	int ret;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	ret = isl9238_read(isl9238_bc, ISL9238_ADPTR_CURR_LIMIT1);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(isl9238_bc->dev, "adptr curnt1 read fail:%d\n", ret);
		return ret;
	}

	if (isl9238_bc->adptr_sense_res)
		ret = ret * ISL9238_ADPTR_SENSE_RES_OTP /
			isl9238_bc->adptr_sense_res;

	return snprintf(buf, MAX_STR_PRINT, "%d mA\n", ret);
}

static ssize_t adapter_current_limit_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	int curnt_val, rval, ret;

	if (kstrtouint(buf, 0, &curnt_val)) {
		dev_err(isl9238_bc->dev, "current limit read fail\n");
		return -EINVAL;
	}

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	if (isl9238_bc->adptr_sense_res)
		curnt_val = curnt_val * isl9238_bc->adptr_sense_res /
			ISL9238_ADPTR_SENSE_RES_OTP;

	rval = curnt_val & ISL9238_ADPTR_CURR_LIMIT1_MASK;
	ret = isl9238_write(isl9238_bc, ISL9238_ADPTR_CURR_LIMIT1, rval);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret  < 0) {
		dev_err(isl9238_bc->dev, "adptr curnt1 write fail:%d\n", ret);
		return ret;
	}
	return count;
}

static ssize_t max_system_voltage_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	int ret;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	ret = isl9238_read(isl9238_bc, ISL9238_MAX_SYS_VOLTAGE);
	mutex_unlock(&isl9238_bc->mutex);
	if (ret < 0) {
		dev_err(isl9238_bc->dev, "system voltage read fail:%d\n", ret);
		return ret;
	}

	ret = ret & ISL9238_MAX_SYS_VOLTAGE_MASK;

	return snprintf(buf, MAX_STR_PRINT, "%d mV\n", ret);
}

static ssize_t adapter_current_range_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	int ret = 0;

	ret = snprintf(buf + strlen(buf), MAX_STR_PRINT, "%d mA to %d mA\n",
		       ISL9238_ADPTR_CHG_CURR_MIN,
		       ISL9238_ADPTR_CHG_CURR_MAX);

	return ret;
}

static ssize_t operating_modes_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	int rval;
	int ret = 0;

	mutex_lock(&isl9238_bc->mutex);
	if (isl9238_bc->shutdown_complete) {
		mutex_unlock(&isl9238_bc->mutex);
		return -EIO;
	}

	rval = isl9238_read(isl9238_bc, ISL9238_INFO1_CHG_STATUS);
	if (rval < 0) {
		dev_err(isl9238_bc->dev, "info1 reg read fail: %d\n", rval);
		mutex_unlock(&isl9238_bc->mutex);
		return rval;
	}

	if (rval & ISL9238_TRICKLE_CHG_MODE)
		ret = snprintf(buf, MAX_STR_PRINT,
			       "trickle charging mode is active\n");
	else
		ret = snprintf(buf, MAX_STR_PRINT,
			       "trickle charging mode is not active\n");

	if (rval & ISL9238_LOW_VSYS_PROCHOT)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"low_vsys prochot is tripped\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"low_vsys prochot is not tripped\n");

	if (rval & ISL9238_DC_PROCHOT_TRIP)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"dcprochot is tripped\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"dcprochot is not tripped\n");

	if (rval & ISL9238_AC_OTG_CURR_PROCHOT)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"acprochot/otgcurrentprochot is tripped\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"acprochot/otgcurrentprochot is not tripped\n");

	switch (rval & ISL9238_ACTIVE_CNTRL_LOOP_MASK) {
	case ISL9238_CHG_CURRENT_LOOP:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"charging current loop is active\n");
		break;
	case ISL9238_ADAPTER_CURRENT_LOOP:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"adapter current loop is active\n");
		break;
	case ISL9238_INPUT_VOLTAGE_LOOP:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"input voltage loop is active\n");
		break;
	default:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"max system voltage control loop is active\n");
		break;
	}

	if (rval & ISL9238_LOW_POWER_MODE)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"internal reference circuit is active\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"internal reference circuit is not active\n");

	rval = isl9238_read(isl9238_bc, ISL9238_INFO2_CHG_STATUS);
	if (rval < 0) {
		dev_err(isl9238_bc->dev, "info2 reg read fail: %d\n", rval);
		mutex_unlock(&isl9238_bc->mutex);
		return rval;
	}

	switch (rval & ISL9238_CHARGER_MODE_MASK) {
	case ISL9238_BOOST_MODE:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"boost mode is active\n");
		break;
	case ISL9238_BUCK_MODE:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"buck mode is active\n");
		break;
	case ISL9238_BUCK_BOOST_MODE:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"buck boost mode is active\n");
		break;
	case ISL9238_OTG_BOOST_MODE:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"otg boost mode is active\n");
		break;
	case ISL9238_OTG_BUCK_MODE:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"otg buck mode is active\n");
		break;
	case ISL9238_OTG_BUCK_BOOST_MODE:
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"otg buck boost mode is active\n");
		break;
	default:
		break;
	}

	if (rval & ISL9238_BATGON_PIN_STATE)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"no battery\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"battery is present\n");

	if (rval & ISL9238_COMPARATOR_OUTPUT)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"comparator output is high\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"comparator output is low\n");

	if (rval & ISL9238_ACOK_PIN_STATE)
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"adapter is present\n");
	else
		ret += snprintf(buf + strlen(buf), MAX_STR_PRINT,
				"no adapter\n");

	mutex_unlock(&isl9238_bc->mutex);
	return ret;
}

static DEVICE_ATTR_RW(charging_state);

static DEVICE_ATTR_RW(input_cable_state);

static DEVICE_ATTR_RW(charge_current_limit);

static DEVICE_ATTR_RO(charge_current_range);

static DEVICE_ATTR_RW(adapter_current_limit);

static DEVICE_ATTR_RO(adapter_current_range);

static DEVICE_ATTR_RO(max_system_voltage);

static DEVICE_ATTR_RO(operating_modes);

static struct attribute *isl9238_attributes[] = {
	&dev_attr_charging_state.attr,
	&dev_attr_input_cable_state.attr,
	&dev_attr_charge_current_limit.attr,
	&dev_attr_charge_current_range.attr,
	&dev_attr_adapter_current_limit.attr,
	&dev_attr_adapter_current_range.attr,
	&dev_attr_max_system_voltage.attr,
	&dev_attr_operating_modes.attr,
	NULL,
};

static const struct attribute_group isl9238_attr_group = {
	.attrs = isl9238_attributes,
};

static void isl9238_sysfs_init(struct device *dev)
{
	int err;
	static struct kobject *bc_kobj;

	bc_kobj = kobject_create_and_add("battery_charger", kernel_kobj);
	if (!bc_kobj) {
		dev_err(dev, "/sys/kernel/battery_charger sysfs create failed\n");
		return;
	}

	err = sysfs_create_group(bc_kobj, &isl9238_attr_group);
	if (err)
		dev_err(dev, "failed to create isl9238 sysfs entries\n");
}
#else
static void tisl9238_sysfs_init(struct device *dev)
{
}
#endif

static int isl9238_otg_enable(struct regulator_dev *rdev)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	int ret;

	mutex_lock(&isl9238->otg_mutex);
	isl9238->is_otg_connected = true;

	ret = isl9238_update_bits(isl9238, ISL9238_CONTROL1_OPTIONS,
				  ISL9238_OTG_MASK, ISL9238_OTG_ENABLE);
	if (ret < 0) {
		dev_err(isl9238->dev, "OTG enable failed %d", ret);
		mutex_unlock(&isl9238->otg_mutex);
		return ret;
	}
	mutex_unlock(&isl9238->otg_mutex);

	dev_info(isl9238->dev, "OTG enabled\n");
	return ret;
}

static int isl9238_otg_disable(struct regulator_dev *rdev)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	int ret;

	mutex_lock(&isl9238->otg_mutex);

	isl9238->is_otg_connected = false;
	ret = isl9238_update_bits(isl9238, ISL9238_CONTROL1_OPTIONS,
				  ISL9238_OTG_MASK, ISL9238_OTG_DISABLE);
	if (ret < 0) {
		dev_err(isl9238->dev, "OTG disable failed %d", ret);
		mutex_unlock(&isl9238->otg_mutex);
		return ret;
	}
	mutex_unlock(&isl9238->otg_mutex);

	dev_info(isl9238->dev, "OTG disabled\n");
	return ret;
}

static int isl9238_otg_is_enabled(struct regulator_dev *rdev)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	int ret;

	ret = isl9238_read(isl9238, ISL9238_CONTROL1_OPTIONS);
	if (ret < 0) {
		dev_err(isl9238->dev, "CONTROL1 read failed %d", ret);
		return ret;
	}
	return (ret & ISL9238_OTG_MASK) == ISL9238_OTG_ENABLE;
}

static int isl9238_otg_set_voltage(struct regulator_dev *rdev,
				   int min_uv, int max_uv,
				   unsigned int *selector)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	int otg_voltage_limit;
	int reg_val;
	int ret = -EINVAL;

	if (!isl9238->is_otg_connected) {
		dev_info(isl9238->dev, "otg not enabled\n");
		return ret;
	}

	if (max_uv == 0)
		return 0;

	dev_info(isl9238->dev, "setting otg voltage %d\n", max_uv / 1000);

	isl9238->last_otg_voltage = max_uv;
	otg_voltage_limit = max_uv / 1000;

	reg_val = isl9238_val_to_reg(otg_voltage_limit, 0, 12, 12, 0);
	ret = isl9238_write(isl9238, ISL9238_OTG_VOLTAGE, reg_val << 3);
	if (ret < 0) {
		dev_err(isl9238->dev, "otg voltage update failed %d\n", ret);
		return ret;
	}
	isl9238->otg_voltage_limit = otg_voltage_limit;

	return ret;
}

static int isl9238_otg_set_curr_limit(struct regulator_dev *rdev,
				      int min_ua, int max_ua)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	int ret = 0;
	int otg_current_lim, val;

	if (!isl9238->is_otg_connected) {
		dev_info(isl9238->dev, "otg not enabled\n");
		return -EINVAL;
	}

	if (max_ua == 0)
		return 0;

	dev_info(isl9238->dev, "setting otg current %d\n", max_ua / 1000);

	otg_current_lim = max_ua / 1000;

	if (isl9238->curnt_sense_res)
		otg_current_lim = otg_current_lim * isl9238->curnt_sense_res /
				ISL9238_CURR_SENSE_RES_OTP;

	val = otg_current_lim & ISL9238_OTG_CURRENT_MASK;
	ret = isl9238_write(isl9238, ISL9238_OTG_CURRENT, val);
	if (ret < 0)
		dev_err(isl9238->dev, "otg current write fail:%d\n", ret);

	return ret;
}

static struct regulator_ops isl9238_otg_ops = {
	.enable		= isl9238_otg_enable,
	.disable	= isl9238_otg_disable,
	.is_enabled	= isl9238_otg_is_enabled,
	.set_voltage	= isl9238_otg_set_voltage,
	.set_current_limit	= isl9238_otg_set_curr_limit,
};

static struct regulator_desc isl9238_otg_reg_desc = {
	.name		= "isl9238-vbus",
	.ops		= &isl9238_otg_ops,
	.type		= REGULATOR_VOLTAGE,
	.enable_time	= 220000,
	.owner		= THIS_MODULE,
};

static int isl9238_init_vbus_regulator(struct isl9238_charger *isl9238,
				       struct isl9238_chg_pdata *pdata)
{
	int ret = 0;
	struct regulator_config rconfig = { };

	if (!pdata->vbus_pdata) {
		dev_err(isl9238->dev, "No vbus platform data\n");
		return 0;
	}

	isl9238->vbus_reg_desc = isl9238_otg_reg_desc;
	isl9238->vbus_ridata = pdata->vbus_pdata->ridata;
	isl9238->vbus_ridata->constraints.valid_modes_mask =
					REGULATOR_MODE_NORMAL |
					REGULATOR_MODE_STANDBY;
	isl9238->vbus_ridata->constraints.valid_ops_mask =
					REGULATOR_CHANGE_MODE |
					REGULATOR_CHANGE_STATUS |
					REGULATOR_CHANGE_VOLTAGE |
					REGULATOR_CHANGE_CURRENT;

	/* Register vbus regulator */
	rconfig.dev = isl9238->dev;
	rconfig.of_node =  isl9238->vbus_np;
	rconfig.init_data = isl9238->vbus_ridata;
	rconfig.driver_data = isl9238;
	isl9238->vbus_rdev = devm_regulator_register(isl9238->dev,
				&isl9238->vbus_reg_desc, &rconfig);
	if (IS_ERR(isl9238->vbus_rdev)) {
		ret = PTR_ERR(isl9238->vbus_rdev);
		dev_err(isl9238->dev,
			"VBUS regulator register failed %d\n", ret);
		return ret;
	}
	return 0;
}

static int isl9238_set_charging_voltage(struct regulator_dev *rdev,
					int min_uv, int max_uv,
					unsigned int *selector)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	int in_voltage_limit;
	int reg_val;
	int ret = 0;

	if (isl9238->is_otg_connected)
		return -EINVAL;

	dev_info(isl9238->dev, "setting adapter voltage %d\n", max_uv / 1000);

	reg_val = isl9238->max_init_voltage & ISL9238_MAX_SYS_VOLTAGE_MASK;
	ret = isl9238_write(isl9238, ISL9238_MAX_SYS_VOLTAGE, reg_val);
	if (ret < 0) {
		dev_err(isl9238->dev, "max sys voltage write fail:%d\n", ret);
		return ret;
	}

	if (max_uv == 0)
		return 0;

	isl9238->last_adapter_voltage = max_uv;
	in_voltage_limit = max_uv / 1000;

	if (isl9238->wake_lock_released)
		in_voltage_limit = 5000;

	reg_val = isl9238_val_to_reg(in_voltage_limit, 0, 341, 6, 0);
	ret = isl9238_write(isl9238, ISL9238_INPUT_VOLTAGE, reg_val << 8);
	if (ret < 0) {
		dev_err(isl9238->dev, "set input voltage failed %d\n", ret);
		return ret;
	}
	isl9238->in_voltage_limit = in_voltage_limit;

	return 0;
}

static int isl9238_set_charging_current(struct regulator_dev *rdev,
					int min_ua, int max_ua)
{
	struct isl9238_charger *isl9238 = rdev_get_drvdata(rdev);
	unsigned int chg_current_limit, adapter_curr_limit = 0;
	int in_current_limit;
	int old_current_limit;
	int ret = 0;
	int val;

	if (isl9238->is_otg_connected)
		return -EINVAL;

	if (max_ua == 0) {
		/* disable charging by setting charging current to 0mA */
		ret = isl9238_write(isl9238, ISL9238_CHG_CURR_LIMIT, 0);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"charge current update failed %d\n", ret);
			return ret;
		}

		isl9238->wake_lock_released = false;
		isl9238->chg_status = BATTERY_DISCHARGING;
		isl9238->cable_connected = 0;
		dev_info(isl9238->dev, "stop thermal monitor\n");
		isl9238->last_temp = 0;
		battery_charger_thermal_stop_monitoring(isl9238->bc_dev);
		dev_info(isl9238->dev, "charging disabled\n");
		battery_charging_status_update(isl9238->bc_dev,
					       isl9238->chg_status);
		battery_charger_release_wake_lock(isl9238->bc_dev);

		/* set default adapter current limit */
		adapter_curr_limit = isl9238->adapter_curr_lim1;
		dev_info(isl9238->dev, "set default adapter current:%d\n",
			 adapter_curr_limit);

		if (isl9238->adptr_sense_res)
			adapter_curr_limit = adapter_curr_limit *
			isl9238->adptr_sense_res / ISL9238_ADPTR_SENSE_RES_OTP;

		val = adapter_curr_limit & ISL9238_ADPTR_CURR_LIMIT1_MASK;
		ret = isl9238_write(isl9238, ISL9238_ADPTR_CURR_LIMIT1, val);
		if (ret < 0)
			dev_err(isl9238->dev, "set adptr curr fail:%d\n", ret);
		return ret;
	}

	dev_info(isl9238->dev, "setting adapter current:%d\n", max_ua / 1000);

	/* enable charging by setting default charging current */
	if (isl9238->charging_current_lim) {
		chg_current_limit = isl9238->charging_current_lim;
		if (isl9238->curnt_sense_res)
			chg_current_limit = chg_current_limit *
				isl9238->curnt_sense_res /
				ISL9238_CURR_SENSE_RES_OTP;

		val = chg_current_limit & ISL9238_CHG_CURR_LIMIT_MASK;
		ret = isl9238_write(isl9238, ISL9238_CHG_CURR_LIMIT, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"charging current write fail:%d\n", ret);
			return ret;
		}
		dev_info(isl9238->dev, "charging enabled\n");
	}

	old_current_limit = isl9238->in_current_limit;
	isl9238->last_adapter_current = max_ua;

	in_current_limit = max_ua / 1000;
	isl9238->cable_connected = 1;
	isl9238->chg_status = BATTERY_CHARGING;

	if (isl9238->wake_lock_released)
		in_current_limit = 500;

	/*
	 * disable auto charge to set adapter current through smbus
	 * disable reload adapter current limit on usb plugin
	 * disable reread prog pin resistor
	 */
	ret = isl9238_update_bits(isl9238, ISL9238_CONTROL3_OPTIONS,
				  ISL9238_AUTO_CHARGE_MODE_MASK |
				  ISL9238_RELOAD_ACLIM_MASK |
				  ISL9238_REREAD_PROG_MASK,
				  ISL9238_BAT_CHG_CURRENT_SMBUSK |
				  ISL9238_DISABLE_RELOAD_ACLIM |
				  ISL9238_DISABLE_REREAD_PROG);
	if (ret < 0) {
		dev_err(isl9238->dev, "control3 reg write fail:%d\n", ret);
		return ret;
	}

	if (isl9238->adptr_sense_res)
		in_current_limit = in_current_limit *
			isl9238->adptr_sense_res / ISL9238_ADPTR_SENSE_RES_OTP;

	val = in_current_limit & ISL9238_ADPTR_CURR_LIMIT1_MASK;
	ret = isl9238_write(isl9238, ISL9238_ADPTR_CURR_LIMIT1, val);
	if (ret < 0) {
		dev_err(isl9238->dev, "set adapter current failed %d\n", ret);
		return ret;
	}
	isl9238->in_current_limit = in_current_limit;
	battery_charging_status_update(isl9238->bc_dev, isl9238->chg_status);
	dev_info(isl9238->dev, "start thermal monitor\n");
	isl9238->last_temp = 0;
	battery_charger_thermal_start_monitoring(isl9238->bc_dev);
	battery_charger_acquire_wake_lock(isl9238->bc_dev);

	return 0;
}

static struct regulator_ops isl9238_regulator_ops = {
	.set_current_limit = isl9238_set_charging_current,
	.set_voltage = isl9238_set_charging_voltage,
};

static struct regulator_desc isl9238_chg_reg_desc = {
	.name		= "isl9238-charger",
	.ops		= &isl9238_regulator_ops,
	.type		= REGULATOR_CURRENT,
	.owner		= THIS_MODULE,
};

static int isl9238_init_charger_regulator(struct isl9238_charger *isl9238,
					  struct isl9238_chg_pdata *pdata)
{
	struct regulator_config rconfig = { };
	int ret = 0;

	isl9238->chg_reg_desc = isl9238_chg_reg_desc;
	isl9238->chg_ridata = pdata->chg_ridata;
	isl9238->chg_ridata->driver_data = isl9238;
	isl9238->chg_ridata->constraints.valid_modes_mask =
					REGULATOR_MODE_NORMAL |
					REGULATOR_MODE_STANDBY;
	isl9238->chg_ridata->constraints.valid_ops_mask =
					REGULATOR_CHANGE_MODE |
					REGULATOR_CHANGE_STATUS |
					REGULATOR_CHANGE_CURRENT |
					REGULATOR_CHANGE_VOLTAGE;
	rconfig.dev = isl9238->dev;
	rconfig.of_node =  isl9238->chg_np;
	rconfig.init_data = isl9238->chg_ridata;
	rconfig.driver_data = isl9238;
	isl9238->chg_rdev = devm_regulator_register(isl9238->dev,
				&isl9238->chg_reg_desc, &rconfig);
	if (IS_ERR(isl9238->chg_rdev)) {
		ret = PTR_ERR(isl9238->chg_rdev);
		dev_err(isl9238->dev, "charger reg register fail %d\n", ret);
	}
	return ret;
}

static int isl9238_show_chip_version(struct isl9238_charger *isl9238)
{
	int ret;

	ret = isl9238_read(isl9238, ISL9238_MANUFACTURER_ID);
	if (ret < 0) {
		dev_err(isl9238->dev, "MFR id read failed: %d\n", ret);
		return ret;
	}

	dev_info(isl9238->dev, "ISL9238 Manufacture OTP id:0x%02X\n", ret);

	ret = isl9238_read(isl9238, ISL9238_DEVICE_ID);
	if (ret < 0) {
		dev_err(isl9238->dev, "device id read failed: %d\n", ret);
		return ret;
	}

	dev_info(isl9238->dev, "ISL9238 Device OTP id:0x%02X\n", ret);
	return 0;
}

static void isl9238_charger_get_op_modes(struct isl9238_charger *isl9238)
{
	int ret;

	ret = isl9238_read(isl9238, ISL9238_INFO1_CHG_STATUS);
	if (ret < 0) {
		dev_err(isl9238->dev, "info1 reg read failed: %d\n", ret);
		return;
	}
	dev_info(isl9238->dev, "info1:charger operating modes 0x%02x\n", ret);

	if (ret & ISL9238_TRICKLE_CHG_MODE)
		dev_info(isl9238->dev, "trickle charging mode is active\n");

	switch (ret & ISL9238_ACTIVE_CNTRL_LOOP_MASK) {
	case ISL9238_CHG_CURRENT_LOOP:
		dev_info(isl9238->dev, "charging current loop is active\n");
		break;
	case ISL9238_ADAPTER_CURRENT_LOOP:
		dev_info(isl9238->dev, "adapter current loop is active\n");
		break;
	case ISL9238_INPUT_VOLTAGE_LOOP:
		dev_info(isl9238->dev, "input voltage loop is active\n");
		break;
	default:
		dev_info(isl9238->dev,
			 "max system voltage control loop is active\n");
		break;
	}

	ret = isl9238_read(isl9238, ISL9238_INFO2_CHG_STATUS);
	if (ret < 0) {
		dev_err(isl9238->dev, "info2 reg read failed: %d\n", ret);
		return;
	}
	dev_info(isl9238->dev, "info2:charger operating modes 0x%02x\n", ret);

	switch (ret & ISL9238_CHARGER_MODE_MASK) {
	case ISL9238_BOOST_MODE:
		dev_info(isl9238->dev, "boost mode is active\n");
		break;
	case ISL9238_BUCK_MODE:
		dev_info(isl9238->dev, "buck mode is active\n");
		break;
	case ISL9238_BUCK_BOOST_MODE:
		dev_info(isl9238->dev, "buck boost mode is active\n");
		break;
	case ISL9238_OTG_BOOST_MODE:
		dev_info(isl9238->dev, "otg boost mode is active\n");
		break;
	case ISL9238_OTG_BUCK_MODE:
		dev_info(isl9238->dev, "otg buck mode is active\n");
		break;
	case ISL9238_OTG_BUCK_BOOST_MODE:
		dev_info(isl9238->dev, "otg buck boost mode is active\n");
		break;
	default:
		break;
	}

	if (ret & ISL9238_ADAPTER_STATE)
		dev_info(isl9238->dev, "adapter is connected\n");

	if (ret & ISL9238_BATTERY_STATE)
		dev_info(isl9238->dev, "no battery present\n");
}

static int isl9238_safetytimer_disable(struct isl9238_charger *isl9238)
{
	int ret;

	ret = isl9238_update_bits(isl9238, ISL9238_CONTROL0_OPTIONS,
				  ISL9238_SMBUS_TIMER_MASK,
				  ISL9238_SMBUS_TIMER_ENABLE);
	if (ret < 0)
		dev_err(isl9238->dev, "disable safety timer fail:%d\n", ret);
	else
		dev_info(isl9238->dev, "Charging SAFETY timer disabled\n");

	return ret;
}

static irqreturn_t isl9238_irq(int id, void *dev)
{
	struct isl9238_charger *isl9238 = dev;

	mutex_lock(&isl9238->mutex);
	if (isl9238->shutdown_complete)
		goto out;

	isl9238_charger_get_op_modes(isl9238);

out:
	mutex_unlock(&isl9238->mutex);
	return IRQ_HANDLED;
}

static int isl9238_charger_thermal_configure(
		struct battery_charger_dev *bc_dev,
		int temp, bool enable_charger, bool enable_charg_half_current,
		int battery_voltage)
{
	struct isl9238_charger *isl9238 = battery_charger_get_drvdata(bc_dev);
	struct isl9238_chg_pdata *chg_pdata;
	unsigned int val;
	int temp_chg_curr_lim = 0, volt_chg_curr_lim = 0;
	int bat_voltage, bat_current, max_system_voltage = 0;
	int charging_state = 0;
	int ret, i;

	if (isl9238->shutdown_complete)
		return 0;

	chg_pdata = isl9238->chg_pdata;
	if (!isl9238->cable_connected || !chg_pdata->temp_range_len)
		return 0;

	dev_info(isl9238->dev, "battery temp %d\n", temp);

	charging_state = battery_gauge_get_charging_status(isl9238->bc_dev);
	if (charging_state == POWER_SUPPLY_STATUS_FULL) {
		dev_info(isl9238->dev, "charging done:stop thermal monitor\n");
		battery_charger_thermal_stop_monitoring(isl9238->bc_dev);
		battery_charger_release_wake_lock(isl9238->bc_dev);
		return 0;
	}

	if ((isl9238->last_temp == temp) && !isl9238->terminate_charging)
		return 0;

	isl9238->last_temp = temp;
	isl9238->terminate_charging = false;

	bat_current = battery_gauge_get_charging_current(isl9238->bc_dev);
	if (bat_current <= isl9238->terminate_chg_current)
		isl9238->terminate_charging = true;

	if ((temp >= ISL9238_TEMP_H_CHG_DISABLE ||
	     temp <= ISL9238_TEMP_L_CHG_DISABLE) ||
	     isl9238->terminate_charging) {
		if (isl9238->thermal_chg_disable)
			return 0;
		/* set chg current to 0 to disable charging */
		ret = isl9238_write(isl9238, ISL9238_CHG_CURR_LIMIT, 0x0);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"charge current write fail:%d\n", ret);
			return ret;
		}

		if (isl9238->terminate_charging)
			dev_info(isl9238->dev,
				 "bat current:%d below terminate current:%d\n",
				 bat_current, isl9238->terminate_chg_current);
		dev_info(isl9238->dev, "thermal: charging disabled\n");
		isl9238->thermal_chg_disable = true;
		return 0;
	}

	for (i = 0; i < chg_pdata->temp_range_len; ++i) {
		if (temp <= chg_pdata->temp_range[i]) {
			temp_chg_curr_lim = chg_pdata->temp_chg_curr_lim[i];
			volt_chg_curr_lim = chg_pdata->voltage_curr_lim[i];
			max_system_voltage = chg_pdata->max_battery_voltage[i];
			if (isl9238->thermal_chg_disable) {
				dev_info(isl9238->dev,
					 "thermal: charging enabled\n");
				isl9238->thermal_chg_disable = false;
			}
			break;
		}
	}

	if (temp_chg_curr_lim != volt_chg_curr_lim) {
		bat_voltage =
			battery_gauge_get_battery_voltage(isl9238->bc_dev);
		dev_info(isl9238->dev, "battery voltage:%d mV\n", bat_voltage);
		dev_info(isl9238->dev, "battery current:%d mA\n", bat_current);
		if (bat_current <= volt_chg_curr_lim ||
		    bat_voltage >= max_system_voltage) {
			temp_chg_curr_lim = volt_chg_curr_lim;
			max_system_voltage = isl9238->max_sys_voltage;
		} else {
			max_system_voltage = isl9238->max_init_voltage;
		}
	}

	dev_info(isl9238->dev, "thermal:set max system voltage:%d mV\n",
		 max_system_voltage);

	val = max_system_voltage & ISL9238_MAX_SYS_VOLTAGE_MASK;
	ret = isl9238_write(isl9238, ISL9238_MAX_SYS_VOLTAGE, val);
	if (ret < 0) {
		dev_err(isl9238->dev, "reg write fail:%d\n", ret);
		return ret;
	}

	dev_info(isl9238->dev, "thermal:set charging current:%d mA\n",
		 temp_chg_curr_lim);

	if (isl9238->curnt_sense_res)
		temp_chg_curr_lim = temp_chg_curr_lim *
			isl9238->curnt_sense_res / ISL9238_CURR_SENSE_RES_OTP;

	val = temp_chg_curr_lim & ISL9238_CHG_CURR_LIMIT_MASK;
	ret = isl9238_write(isl9238, ISL9238_CHG_CURR_LIMIT, val);
	if (ret < 0)
		dev_err(isl9238->dev, "charge current write fail:%d\n", ret);

	return ret;
}

static int isl9238_report_charging_state(struct battery_charger_dev *bc_dev)
{
	struct isl9238_charger *isl9238 = battery_charger_get_drvdata(bc_dev);

	return isl9238->chg_status;
}

static struct battery_charging_ops isl9238_charger_bci_ops = {
	.get_charging_status = isl9238_report_charging_state,
	.thermal_configure = isl9238_charger_thermal_configure,
};

static struct battery_charger_info isl9238_charger_bci = {
	.cell_id = 0,
	.bc_ops = &isl9238_charger_bci_ops,
};

static int isl9238_charger_init(struct isl9238_charger *isl9238)
{
	unsigned int val;
	unsigned int chg_curr_lim;
	unsigned int curr_sense_res;
	unsigned int adptr_sense_res;
	unsigned int trickle_chg_curr;
	unsigned int adptr_curr_lim1;
	unsigned int adptr_curr_lim2;
	unsigned int otg_current_lim;
	int ret;

	chg_curr_lim = isl9238->chg_pdata->charge_current_lim;
	curr_sense_res = isl9238->chg_pdata->curr_sense_resistor;
	adptr_sense_res = isl9238->chg_pdata->adapter_sense_resistor;
	adptr_curr_lim1 = isl9238->chg_pdata->adapter_current_lim1;
	adptr_curr_lim2 = isl9238->chg_pdata->adapter_current_lim2;
	trickle_chg_curr = isl9238->chg_pdata->trickle_chg_current;
	otg_current_lim = isl9238->chg_pdata->otg_current;

	if (isl9238->chg_pdata->enable_auto_charging) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL3_OPTIONS,
					  ISL9238_AUTO_CHARGE_MODE_MASK, 0x0);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"auto charge mode enable failed %d\n", ret);
			return ret;
		}
	} else {
	ret = isl9238_update_bits(isl9238, ISL9238_CONTROL3_OPTIONS,
				  ISL9238_AUTO_CHARGE_MODE_MASK |
				  ISL9238_RELOAD_ACLIM_MASK |
				  ISL9238_REREAD_PROG_MASK,
				  ISL9238_BAT_CHG_CURRENT_SMBUSK |
				  ISL9238_DISABLE_RELOAD_ACLIM |
				  ISL9238_DISABLE_REREAD_PROG);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"control3 reg write fail:%d\n", ret);
			return ret;
		}
	}

	if (chg_curr_lim) {
		if (curr_sense_res)
			chg_curr_lim = chg_curr_lim *
				curr_sense_res / ISL9238_CURR_SENSE_RES_OTP;
		val = chg_curr_lim & ISL9238_CHG_CURR_LIMIT_MASK;
		ret = isl9238_write(isl9238, ISL9238_CHG_CURR_LIMIT, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"charge current update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->max_init_voltage) {
		val = isl9238->max_init_voltage & ISL9238_MAX_SYS_VOLTAGE_MASK;
		ret = isl9238_write(isl9238, ISL9238_MAX_SYS_VOLTAGE, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"max system voltage update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->min_sys_voltage) {
		val = isl9238->chg_pdata->min_sys_voltage &
					ISL9238_MIN_SYS_VOLTAGE_MASK;
		ret = isl9238_write(isl9238, ISL9238_MIN_SYS_VOLTAGE, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"min system voltage update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->input_voltage_limit) {
		val = isl9238_val_to_reg(
			isl9238->chg_pdata->input_voltage_limit, 0, 341, 6, 0);
		ret = isl9238_write(isl9238, ISL9238_INPUT_VOLTAGE, val << 8);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"input voltage update failed %d\n", ret);
			return ret;
		}
	}

	if (adptr_curr_lim1) {
		if (adptr_sense_res)
			adptr_curr_lim1 = adptr_curr_lim1 *
				adptr_sense_res / ISL9238_ADPTR_SENSE_RES_OTP;
		val = adptr_curr_lim1 & ISL9238_ADPTR_CURR_LIMIT1_MASK;
		ret = isl9238_write(isl9238, ISL9238_ADPTR_CURR_LIMIT1, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"adapter current_1 update failed %d\n", ret);
			return ret;
		}
	}

	if (adptr_curr_lim2) {
		if (adptr_sense_res)
			adptr_curr_lim2 = adptr_curr_lim2 *
				adptr_sense_res / ISL9238_ADPTR_SENSE_RES_OTP;
		val = adptr_curr_lim2 & ISL9238_ADPTR_CURR_LIMIT2_MASK;
		ret = isl9238_write(isl9238, ISL9238_ADPTR_CURR_LIMIT2, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"adapter current_2 update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->acprochot_threshold) {
		val = isl9238->chg_pdata->acprochot_threshold &
					ISL9238_AC_PROCHOT_MASK;
		ret = isl9238_write(isl9238, ISL9238_AC_PROCHOT, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"ac Prochot update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->dcprochot_threshold) {
		val = isl9238->chg_pdata->dcprochot_threshold &
					ISL9238_DC_PROCHOT_MASK;
		ret = isl9238_write(isl9238, ISL9238_DC_PROCHOT, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"dc Prochot update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->disable_input_regulation) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL0_OPTIONS,
					  ISL9238_REGULATION_MASK, 0x0);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"regulation disable failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->otg_voltage) {
		val = isl9238_val_to_reg(isl9238->chg_pdata->otg_voltage,
					 0, 12, 12, 0);
		ret = isl9238_write(isl9238, ISL9238_OTG_VOLTAGE, val << 3);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"otg voltage update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->otg_current) {
		if (curr_sense_res)
			otg_current_lim = otg_current_lim * curr_sense_res /
				ISL9238_CURR_SENSE_RES_OTP;

		val = otg_current_lim & ISL9238_OTG_CURRENT_MASK;
		ret = isl9238_write(isl9238, ISL9238_OTG_CURRENT, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"otg current update failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->disable_safety_timer) {
		ret = isl9238_safetytimer_disable(isl9238);
		if (ret < 0)
			return ret;
	}

	if (isl9238->chg_pdata->enable_bat_learn_mode) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL1_OPTIONS,
					  ISL9238_BAT_LEARN_MASK,
					  ISL9238_BAT_LEARN_MASK);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"bat learn mode enable failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->disable_turbo_mode) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL1_OPTIONS,
					  ISL9238_TURBO_MODE_MASK,
					  ISL9238_TURBO_MODE_DISABLE);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"Turbo mode disable failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->enable_battery_ovp) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL2_OPTIONS,
					  ISL9238_BATTERY_OVP_MASK,
					  ISL9238_BATTERY_OVP_ENABLE);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"battery ovp enable failed %d\n", ret);
			return ret;
		}
	}

	if (trickle_chg_curr) {
		if (trickle_chg_curr == 128)
			val = 0x4000;
		else if (trickle_chg_curr == 64)
			val = 0x8000;
		else if (trickle_chg_curr == 512)
			val = 0xC000;
		else
			val = 0x0;

		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL2_OPTIONS,
					  ISL9238_TRICKLE_CHG_CURR_MASK, val);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"trickle chg current config failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->enable_prochot_acok) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL4_OPTIONS,
					  ISL9238_TRIGGER_PROCHOT_ACOK,
					  ISL9238_TRIGGER_PROCHOT_ACOK);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"acok trigger enable failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->enable_prochot_otg_curr) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL4_OPTIONS,
					  ISL9238_TRIGGER_OTG_CURR,
					  ISL9238_TRIGGER_OTG_CURR);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"otg prochot trigger failed %d\n", ret);
			return ret;
		}
	}

	if (isl9238->chg_pdata->enable_psys_monitor) {
		ret = isl9238_update_bits(isl9238, ISL9238_CONTROL1_OPTIONS,
					  ISL9238_PSYS_POWER_MONITOR,
					  ISL9238_PSYS_POWER_MONITOR);
		if (ret < 0) {
			dev_err(isl9238->dev,
				"psys monitor enable failed %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static struct isl9238_chg_pdata *isl9238_parse_dt_data(
		struct i2c_client *client, struct device_node **vbus_np,
		struct device_node **chg_np)
{
	struct device_node *np = client->dev.of_node;
	struct device_node *vbus_reg_node = NULL;
	struct device_node *chg_reg_node = NULL;
	struct isl9238_chg_pdata *pdata;
	u32 pval;
	int ret;
	int count, temp_range_len = 0, curr_volt_table_len = 0;

	pdata = devm_kzalloc(&client->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	chg_reg_node = of_find_node_by_name(np, "charger");
	if (!chg_reg_node || !of_device_is_available(chg_reg_node)) {
		dev_info(&client->dev, "charger dt status disabled\n");
		return ERR_PTR(-EINVAL);
	}

	pdata->chg_ridata = of_get_regulator_init_data(&client->dev,
				chg_reg_node, &isl9238_chg_reg_desc);
	if (!pdata->chg_ridata)
		return ERR_PTR(-EINVAL);

	ret = of_property_read_u32(np, "isl,charge-current-limit-ma", &pval);
	if (!ret)
		pdata->charge_current_lim = pval;

	ret = of_property_read_u32(np, "isl,max-system-voltage-mv", &pval);
	if (!ret)
		pdata->max_sys_voltage = pval;

	ret = of_property_read_u32(np, "isl,max-init-voltage-mv", &pval);
	if (!ret)
		pdata->max_init_voltage = pval;

	ret = of_property_read_u32(np, "isl,min-system-voltage-mv", &pval);
	if (!ret)
		pdata->min_sys_voltage = pval;

	ret = of_property_read_u32(np, "isl,input-voltage-limit-mv", &pval);
	if (!ret)
		pdata->input_voltage_limit = pval;

	ret = of_property_read_u32(np, "isl,adapter-current-limit1-ma", &pval);
	if (!ret)
		pdata->adapter_current_lim1 = pval;

	ret = of_property_read_u32(np, "isl,adapter-current-limit2-ma", &pval);
	if (!ret)
		pdata->adapter_current_lim2 = pval;

	ret = of_property_read_u32(np, "isl,acprochot-threshold", &pval);
	if (!ret)
		pdata->acprochot_threshold = pval;

	ret = of_property_read_u32(np, "isl,dcprochot-threshold", &pval);
	if (!ret)
		pdata->dcprochot_threshold = pval;

	ret = of_property_read_u32(np, "isl,trickle-chg-current-ma", &pval);
	if (!ret)
		pdata->trickle_chg_current = pval;

	ret = of_property_read_u32(np, "isl,otg-voltage-mv", &pval);
	if (!ret)
		pdata->otg_voltage = pval;

	ret = of_property_read_u32(np, "isl,otg-current-ma", &pval);
	if (!ret)
		pdata->otg_current = pval;

	ret = of_property_read_u32(np, "isl,current-sense-res", &pval);
	if (!ret)
		pdata->curr_sense_resistor = pval;

	ret = of_property_read_u32(np, "isl,adapter-sense-res", &pval);
	if (!ret)
		pdata->adapter_sense_resistor = pval;

	ret = of_property_read_u32(np, "isl,terminate-chg-current", &pval);
	if (!ret)
		pdata->terminate_chg_current = pval / 1000;

	pdata->disable_input_regulation = of_property_read_bool(np,
				"isl,disable-regulation");

	pdata->enable_bat_learn_mode = of_property_read_bool(np,
				"isl,enable-bat-learn-mode");

	pdata->disable_turbo_mode = of_property_read_bool(np,
				"isl,disable-turbo-mode");

	pdata->enable_auto_charging = of_property_read_bool(np,
				"isl,enable-auto-charging");

	pdata->enable_battery_ovp = of_property_read_bool(np,
				"isl,enable-battery-ovp");

	pdata->enable_prochot_acok = of_property_read_bool(np,
				"isl,enable-trigger-acok");

	pdata->enable_prochot_otg_curr = of_property_read_bool(np,
				"isl,enable-prochot-otg-current");

	pdata->disable_safety_timer = of_property_read_bool(np,
				"isl,disable-smbus-timer");

	pdata->enable_psys_monitor = of_property_read_bool(np,
				"isl,enable-psys-monitor");

	pdata->tz_name = of_get_property(np, "isl,thermal-zone", NULL);

	ret = of_property_read_u32(np, "isl,temp-polling-time-sec", &pval);
	if (!ret)
		pdata->temp_poll_time = pval;

	temp_range_len = of_property_count_u32_elems(np, "isl,temp-range");
	pdata->temp_range_len = temp_range_len;

	if (temp_range_len <= 0)
		goto vbus_node;

	curr_volt_table_len =
		of_property_count_u32_elems(np, "isl,current-voltage-table");
	curr_volt_table_len = curr_volt_table_len / 3;

	if (temp_range_len != curr_volt_table_len) {
		dev_info(&client->dev, "current-thermal profile invalid\n");
		goto vbus_node;
	}

	pdata->temp_range = devm_kzalloc(&client->dev,
					 sizeof(u32) * temp_range_len,
					 GFP_KERNEL);
	if (!pdata->temp_range)
		return ERR_PTR(-ENOMEM);

	ret = of_property_read_u32_array(np, "isl,temp-range",
					 pdata->temp_range, temp_range_len);
	if (ret < 0)
		return ERR_PTR(ret);

	pdata->temp_chg_curr_lim = devm_kzalloc(&client->dev,
					   sizeof(u32) * curr_volt_table_len,
					   GFP_KERNEL);
	if (!pdata->temp_chg_curr_lim)
		return ERR_PTR(-ENOMEM);

	pdata->voltage_curr_lim = devm_kzalloc(&client->dev,
				   sizeof(u32) * curr_volt_table_len,
				   GFP_KERNEL);
	if (!pdata->voltage_curr_lim)
		return ERR_PTR(-ENOMEM);

	pdata->max_battery_voltage = devm_kzalloc(&client->dev,
				 sizeof(u32) * curr_volt_table_len,
				 GFP_KERNEL);
	if (!pdata->max_battery_voltage)
		return ERR_PTR(-ENOMEM);

	for (count = 0;  count < curr_volt_table_len; ++count) {
		ret = of_property_read_u32_index(np,
						 "isl,current-voltage-table",
						 count, &pval);
		if (!ret)
			pdata->temp_chg_curr_lim[count] = pval;

		ret = of_property_read_u32_index(np,
						 "isl,current-voltage-table",
						 count + 5, &pval);
		if (!ret)
			pdata->voltage_curr_lim[count] = pval;

		ret = of_property_read_u32_index(np,
						 "isl,current-voltage-table",
						 count + 10, &pval);
		if (!ret)
			pdata->max_battery_voltage[count] = pval;
	}

vbus_node:
	vbus_reg_node = of_find_node_by_name(np, "vbus");
	if (vbus_reg_node) {
		pdata->vbus_pdata = devm_kzalloc(&client->dev,
			sizeof(*pdata->vbus_pdata), GFP_KERNEL);
		if (!pdata->vbus_pdata)
			return ERR_PTR(-ENOMEM);

		pdata->vbus_pdata->ridata = of_get_regulator_init_data(
					&client->dev, vbus_reg_node,
					&isl9238_otg_reg_desc);
		if (!pdata->vbus_pdata->ridata)
			return ERR_PTR(-EINVAL);
	}

	*vbus_np = vbus_reg_node;
	*chg_np = chg_reg_node;

	return pdata;
}

static int isl9238_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct isl9238_charger *isl9238;
	struct isl9238_chg_pdata *pdata = NULL;
	struct device_node *vbus_np = NULL;
	struct device_node *chg_np = NULL;
	int ret = 0;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_WORD_DATA))
		return -EIO;

	if (client->dev.of_node) {
		pdata = isl9238_parse_dt_data(client, &vbus_np, &chg_np);
		if (IS_ERR(pdata)) {
			ret = PTR_ERR(pdata);
			dev_err(&client->dev, "Dts Parsing failed, %d\n", ret);
			return ret;
		}
	}

	isl9238 = devm_kzalloc(&client->dev, sizeof(*isl9238), GFP_KERNEL);
	if (!isl9238)
		return -ENOMEM;

	isl9238->rmap = devm_regmap_init_i2c(client, &isl9238_rmap_config);
	if (IS_ERR(isl9238->rmap)) {
		ret = PTR_ERR(isl9238->rmap);
		dev_err(&client->dev, "regmap init failed: %d\n", ret);
		return ret;
	}

	isl9238->dev = &client->dev;
	i2c_set_clientdata(client, isl9238);
	isl9238->client = client;
	isl9238->chg_pdata = pdata;
	isl9238->vbus_np = vbus_np;
	isl9238->chg_np = chg_np;
	isl9238->curnt_sense_res = isl9238->chg_pdata->curr_sense_resistor;
	isl9238->adptr_sense_res = isl9238->chg_pdata->adapter_sense_resistor;
	isl9238->charging_current_lim = isl9238->chg_pdata->charge_current_lim;
	isl9238->adapter_curr_lim1 = isl9238->chg_pdata->adapter_current_lim1;
	isl9238->max_init_voltage = isl9238->chg_pdata->max_init_voltage;
	isl9238->max_sys_voltage = isl9238->chg_pdata->max_sys_voltage;
	isl9238->terminate_chg_current =
			isl9238->chg_pdata->terminate_chg_current;
	isl9238_charger_bci.polling_time_sec =
			isl9238->chg_pdata->temp_poll_time;
	isl9238_charger_bci.tz_name = isl9238->chg_pdata->tz_name;
	isl9238->chg_status = BATTERY_DISCHARGING;

	isl9238_bc = isl9238;

	mutex_init(&isl9238->mutex);
	mutex_init(&isl9238->otg_mutex);

	ret = isl9238_show_chip_version(isl9238);
	if (ret < 0) {
		dev_err(&client->dev, "version read failed %d\n", ret);
		goto scrub_mutex;
	}

	isl9238_sysfs_init(&client->dev);

	ret = isl9238_charger_init(isl9238);
	if (ret < 0) {
		dev_err(&client->dev, "Charger init failed: %d\n", ret);
		goto scrub_mutex;
	}

	ret = isl9238_init_charger_regulator(isl9238, pdata);
	if (ret < 0) {
		dev_err(&client->dev, "Charger reg init failed %d\n", ret);
		goto scrub_mutex;
	}

	if (client->irq) {
		ret = devm_request_threaded_irq(isl9238->dev, client->irq, NULL,
						isl9238_irq, IRQF_ONESHOT |
						IRQF_TRIGGER_FALLING,
						dev_name(isl9238->dev),
						isl9238);
		if (ret < 0) {
			dev_warn(isl9238->dev,
				 "IRQ request IRQ fail:%d\n", ret);
			dev_info(isl9238->dev,
				 "isl bc driver without irq enabled\n");
			ret = 0;
		}
	}
	device_set_wakeup_capable(isl9238->dev, true);
	device_wakeup_enable(isl9238->dev);

	isl9238->bc_dev = battery_charger_register(isl9238->dev,
			&isl9238_charger_bci, isl9238);
	if (IS_ERR(isl9238->bc_dev)) {
		ret = PTR_ERR(isl9238->bc_dev);
		dev_err(isl9238->dev, "batt-chg register fail:%d\n", ret);
		goto scrub_mutex;
	}

	ret = isl9238_init_vbus_regulator(isl9238, pdata);
	if (ret < 0) {
		dev_err(&client->dev, "VBUS regulator init failed %d\n", ret);
		goto scrub_mutex;
	}

	/* get charger operating modes */
	isl9238_charger_get_op_modes(isl9238);

	return 0;

scrub_mutex:
	mutex_destroy(&isl9238->mutex);
	mutex_destroy(&isl9238->otg_mutex);
	return ret;
}

static void isl9238_shutdown(struct i2c_client *client)
{
	struct isl9238_charger *isl9238 = i2c_get_clientdata(client);

	mutex_lock(&isl9238->mutex);
	isl9238->shutdown_complete = 1;
	mutex_unlock(&isl9238->mutex);

	if (isl9238->is_otg_connected)
		isl9238_otg_disable(isl9238->vbus_rdev);

	if (!isl9238->cable_connected)
		return;

	dev_info(isl9238->dev, "shutdown:stop thermal monitor\n");
	battery_charger_thermal_stop_monitoring(isl9238->bc_dev);
}

#ifdef CONFIG_PM_SLEEP
static int isl9238_suspend(struct device *dev)
{
	struct isl9238_charger *isl9238 = dev_get_drvdata(dev);
	int charging_state = 0;
	int ret = 0;

	charging_state = battery_gauge_get_charging_status(isl9238->bc_dev);
	if (charging_state != POWER_SUPPLY_STATUS_FULL) {
		dev_err(isl9238->dev, "charging in progress: block suspend\n");
		ret = -EINVAL;
	}

	dev_info(isl9238->dev, "charging status:%d\n", charging_state);

	return ret;
}

static int isl9238_resume(struct device *dev)
{
	struct isl9238_charger *isl9238 = dev_get_drvdata(dev);

	isl9238_charger_get_op_modes(isl9238);

	return 0;
};
#endif

static const struct dev_pm_ops isl9238_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(isl9238_suspend, isl9238_resume)
};

static const struct of_device_id isl9238_of_match[] = {
	{ .compatible = "isil,isl9238", },
	{},
};
MODULE_DEVICE_TABLE(of, isl9238_of_match);

static const struct i2c_device_id isl9238_id[] = {
	{.name = "isl9238",},
	{},
};

static struct i2c_driver isl9238_i2c_driver = {
	.driver = {
		.name = "isl9238",
		.owner = THIS_MODULE,
		.of_match_table = isl9238_of_match,
		.pm = &isl9238_pm_ops,
	},
	.probe = isl9238_probe,
	.shutdown = isl9238_shutdown,
	.id_table = isl9238_id,
};

static int __init isl9238_module_init(void)
{
	return i2c_add_driver(&isl9238_i2c_driver);
}
subsys_initcall(isl9238_module_init);

static void __exit isl9238_cleanup(void)
{
	i2c_del_driver(&isl9238_i2c_driver);
}
module_exit(isl9238_cleanup);

MODULE_DESCRIPTION("ISL9238 battery charger driver");
MODULE_AUTHOR("Venkat Reddy Talla <vreddytalla@nvidia.com>");
MODULE_LICENSE("GPL v2");
