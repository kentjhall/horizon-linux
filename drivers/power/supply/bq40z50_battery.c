/*
 * bq40z50_battery.c -- BQ40z50 Multicell fuel gauge driver
 *
 * Copyright (C) 2018 NVIDIA CORPORATION. All rights reserved.
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

#define BQ40Z50_CAPACITY_ALARM		0x01
#define BQ40Z50_TEMPERATURE		0x08
#define BQ40Z50_VOLTAGE			0x09
#define BQ40Z50_CURRENT			0x0A
#define BQ40Z50_AVG_CURRENT		0x0B
#define BQ40Z50_MAX_ERROR		0x0C
#define BQ40Z50_STATE_OF_CHARGE		0x0D
#define BQ40Z50_ABSLUTE_SOC		0x0E
#define BQ40Z50_REMAINING_CAPACITY	0x0F
#define BQ40Z50_FULLCHG_CAPACITY	0x10
#define BQ40Z50_RUNTIME_TO_EMPTY	0x11
#define BQ40Z50_AVGTIME_TO_EMPTY	0x12
#define BQ40Z50_AVGTIME_TO_FULL		0x13
#define BQ40Z50_CHARGING_CURRENT	0x14
#define BQ40Z50_CHARGING_VOLTAGE	0x15
#define BQ40Z50_BATTERY_STATUS		0x16
#define BQ40Z50_CYCLE_COUNT		0x17
#define BQ40Z50_DESIGN_CAPACITY		0x18
#define BQ40Z50_DESIGN_VOLTAGE		0x19
#define BQ40Z50_SERIAL_NUMBER		0x1C
#define BQ40Z50_MANUFACTURER		0x20
#define BQ40Z50_DEVICE_NAME		0x21
#define BQ40Z50_DEVICE_TYPE		0x22
#define BQ40Z50_MANUFACTURER_DATA	0x23

#define BQ40Z50_CELL_VOLTAGE4		0x3C
#define BQ40Z50_CELL_VOLTAGE3		0x3D
#define BQ40Z50_CELL_VOLTAGE2		0x3E
#define BQ40Z50_CELL_VOLTAGE1		0x3F
#define BQ40Z50_BTP_DISCHARGE		0x4A
#define BQ40Z50_BTP_CHARGE		0x4B

#define BQ40Z50_SAFETY_ALERT		0x50
#define BQ40Z50_TURBO_CURRENT		0x5E

#define BQ40Z50_MAX_REGS		0x7F

#define BQ40Z50_BAT_DISCHARGING		0x40
#define BQ40Z50_BAT_FULL_CHARGED	0x20
#define BQ40Z50_BAT_FULL_DISCHARGED	0x10

#define BQ40Z50_BATTERY_LOW		15
#define BQ40Z50_BATTERY_FULL		100

#define BQ40Z50_DELAY			msecs_to_jiffies(60000)

#define MAX_STRING_PRINT		50

struct bq40z50_pdata {
	u32 design_capacity; /* in mAh */
	u32 design_voltage; /* in mV */
	u32 btp_discharge_set;
	u32 btp_charge_set;
	u32 threshold_soc;
	u32 maximum_soc;
	u32 full_charge_capacity;
};

struct bq40z50_chip {
	struct device		*dev;
	struct i2c_client		*client;
	struct delayed_work		work;
	struct delayed_work		fc_work;
	struct mutex			mutex; /* mutex for fg */
	struct regmap			*rmap;
	struct power_supply		*psy_bat;
	struct power_supply_desc	psy_desc;
	struct bq40z50_pdata		*pdata;
	struct battery_gauge_dev	*bg_dev;

	/* battery voltage */
	int vcell;
	/* battery capacity */
	int soc;
	/* State Of Charge */
	int status;
	/* battery health */
	int health;
	/* battery capacity */
	int capacity_level;

	int temperature;
	int read_failed;

	int design_capacity;
	int design_voltage;
	int btp_discharge_set;
	int btp_charge_set;

	int lasttime_soc;
	int lasttime_status;
	int shutdown_complete;
	int charge_complete;
	int print_once;
	bool enable_temp_prop;
	bool full_charge_state;
	bool low_battery_shutdown;
	u32 full_charge_capacity;
};

static const struct regmap_range bq40z50_readable_ranges[] = {
	regmap_reg_range(BQ40Z50_CAPACITY_ALARM, BQ40Z50_SERIAL_NUMBER),
	regmap_reg_range(BQ40Z50_MANUFACTURER, BQ40Z50_MANUFACTURER_DATA),
	regmap_reg_range(BQ40Z50_CELL_VOLTAGE4, BQ40Z50_CELL_VOLTAGE1),
	regmap_reg_range(BQ40Z50_BTP_DISCHARGE, BQ40Z50_BTP_CHARGE),
	regmap_reg_range(BQ40Z50_SAFETY_ALERT, BQ40Z50_TURBO_CURRENT),
};

static const struct regmap_access_table bq40z50_readable_table = {
	.yes_ranges = bq40z50_readable_ranges,
	.n_yes_ranges = ARRAY_SIZE(bq40z50_readable_ranges),
};

static const struct regmap_config bq40z50_rmap_config = {
	.reg_bits		= 8,
	.val_bits		= 16,
	.max_register		= BQ40Z50_MAX_REGS,
	.cache_type		= REGCACHE_NONE,
	.val_format_endian	= REGMAP_ENDIAN_NATIVE,
	.rd_table		= &bq40z50_readable_table,
};

static int bq40z50_read_word(struct bq40z50_chip *chip, u8 reg)
{
	unsigned int reg_val;
	int ret;

	ret = regmap_read(chip->rmap, reg, &reg_val);
	if (ret < 0)
		return ret;

	return reg_val;
}

static int bq40z50_write_word(struct bq40z50_chip *chip, u8 reg, u32 val)
{
	return regmap_write(chip->rmap, reg, val);
}

static int bq40z50_update_soc_voltage(struct bq40z50_chip *chip)
{
	int val;

	val = bq40z50_read_word(chip, BQ40Z50_VOLTAGE);
	if (val < 0)
		dev_err(chip->dev, "voltage read failed:%d\n", val);
	else
		chip->vcell = val;

	val = bq40z50_read_word(chip, BQ40Z50_STATE_OF_CHARGE);
	if (val < 0)
		dev_err(chip->dev, "soc read failed:%d\n", val);
	else
		chip->soc = val;

	val = bq40z50_read_word(chip, BQ40Z50_BATTERY_STATUS);
	if (val < 0) {
		dev_err(chip->dev, "battery status read failed:%d\n", val);
	} else {
		if (val & BQ40Z50_BAT_FULL_CHARGED)
			chip->charge_complete = true;
		else
			chip->charge_complete = false;
	}

	if (chip->low_battery_shutdown && chip->soc == 0)
		chip->soc = 1;

	if (chip->soc == BQ40Z50_BATTERY_FULL && chip->charge_complete) {
		chip->status = POWER_SUPPLY_STATUS_FULL;
		chip->capacity_level = POWER_SUPPLY_CAPACITY_LEVEL_FULL;
		chip->health = POWER_SUPPLY_HEALTH_GOOD;
	} else if (chip->soc < BQ40Z50_BATTERY_LOW) {
		chip->status = chip->lasttime_status;
		chip->health = POWER_SUPPLY_HEALTH_DEAD;
		chip->capacity_level = POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL;
	} else {
		chip->status = chip->lasttime_status;
		chip->health = POWER_SUPPLY_HEALTH_GOOD;
		chip->capacity_level = POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
	}

	return 0;
}

static void bq40z50_work(struct work_struct *work)
{
	struct bq40z50_chip *chip;

	chip = container_of(work, struct bq40z50_chip, work.work);

	mutex_lock(&chip->mutex);
	if (chip->shutdown_complete) {
		mutex_unlock(&chip->mutex);
		return;
	}

	bq40z50_update_soc_voltage(chip);

	if (chip->soc != chip->lasttime_soc ||
	    chip->status != chip->lasttime_status) {
		chip->lasttime_soc = chip->soc;
		power_supply_changed(chip->psy_bat);
	}

	mutex_unlock(&chip->mutex);
	schedule_delayed_work(&chip->work, BQ40Z50_DELAY);
}

static int bq40z50_get_temperature(struct bq40z50_chip *chip)
{
	int val;
	int retries = 2;
	int i;

	if (chip->shutdown_complete)
		return chip->temperature;

	for (i = 0; i < retries; i++) {
		val = bq40z50_read_word(chip, BQ40Z50_TEMPERATURE);
		if (val < 0)
			continue;
	}

	if (val < 0) {
		chip->read_failed++;
		dev_err(chip->dev, "temperature read fail:%d\n", val);
		if (chip->read_failed > 50)
			return val;
		return chip->temperature;
	}
	chip->read_failed = 0;
	chip->temperature = val;

	return val;
}

static enum power_supply_property bq40z50_battery_props[] = {
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
	POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW,
	POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG,
	POWER_SUPPLY_PROP_TIME_TO_FULL_AVG,
};

static int bq40z50_get_property(struct power_supply *psy,
				enum power_supply_property psp,
				union power_supply_propval *val)
{
	struct bq40z50_chip *chip = power_supply_get_drvdata(psy);
	int temp;
	int ret = 0;

	mutex_lock(&chip->mutex);
	if (chip->shutdown_complete) {
		mutex_unlock(&chip->mutex);
		return -EINVAL;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_TECHNOLOGY:
		val->intval = POWER_SUPPLY_TECHNOLOGY_LION;
		break;
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = chip->status;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = 1000 * chip->vcell;
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		val->intval = bq40z50_read_word(chip, BQ40Z50_CURRENT);
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = chip->soc;

		if (chip->print_once && (chip->soc > 15 || chip->soc < 5))
			chip->print_once = 0;

		if (chip->soc == 15 && chip->print_once != 15) {
			chip->print_once = 15;
			dev_warn(chip->dev,
				 "System Running low on battery - 15 percent\n");
		}
		if (chip->soc == 10 && chip->print_once != 10) {
			chip->print_once = 10;
			dev_warn(chip->dev,
				 "System Running low on battery - 10 percent\n");
		}
		if (chip->soc == 5 && chip->print_once != 5) {
			chip->print_once = 5;
			dev_warn(chip->dev,
				 "System Running low on battery - 5 percent\n");
		}
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = chip->health;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = 1;
		break;
	case POWER_SUPPLY_PROP_CAPACITY_LEVEL:
		val->intval = chip->capacity_level;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		temp = bq40z50_get_temperature(chip);
		/*
		 * fg device returns the temp in units 0.1K
		 * converting deci-kelvin to dec-celcius
		 * C = K -273.2
		 */
		if (temp >= 0)
			val->intval = chip->temperature - 2732;
		else
			ret = temp;
		break;
	case POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW:
		ret = bq40z50_read_word(chip, BQ40Z50_RUNTIME_TO_EMPTY);
		if (ret < 0)
			dev_err(chip->dev,
				"runtime to empty read failed:%d\n", ret);
		else
			val->intval = ret;
		break;
	case POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG:
		ret = bq40z50_read_word(chip, BQ40Z50_AVGTIME_TO_EMPTY);
		if (ret < 0)
			dev_err(chip->dev,
				"avgtime to empty read failed:%d\n", ret);
		else
			val->intval = ret;
		break;
	case POWER_SUPPLY_PROP_TIME_TO_FULL_AVG:
		ret = bq40z50_read_word(chip, BQ40Z50_AVGTIME_TO_FULL);
		if (ret < 0)
			dev_err(chip->dev,
				"avgtime to full read failed:%d\n", ret);
		else
			val->intval = ret;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	mutex_unlock(&chip->mutex);
	return ret;
}

static const struct power_supply_desc bq240z50_psy_desc = {
	.name = "battery",
	.type = POWER_SUPPLY_TYPE_BATTERY,
	.properties = bq40z50_battery_props,
	.num_properties = ARRAY_SIZE(bq40z50_battery_props),
	.get_property = bq40z50_get_property,
};

static ssize_t bq40z50_show_lowbat_shutdown_state(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct bq40z50_chip *bq40z50 = i2c_get_clientdata(client);

	mutex_lock(&bq40z50->mutex);
	if (bq40z50->shutdown_complete) {
		mutex_unlock(&bq40z50->mutex);
		return -EIO;
	}
	mutex_unlock(&bq40z50->mutex);

	if (bq40z50->low_battery_shutdown)
		return snprintf(buf, MAX_STRING_PRINT, "disabled\n");
	else
		return snprintf(buf, MAX_STRING_PRINT, "enabled\n");
}

static ssize_t bq40z50_set_lowbat_shutdown_state(struct device *dev,
						 struct device_attribute *attr,
						 const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct bq40z50_chip *bq40z50 = i2c_get_clientdata(client);
	bool enabled;

	if ((*buf == 'E') || (*buf == 'e'))
		enabled = true;
	else if ((*buf == 'D') || (*buf == 'd'))
		enabled = false;
	else
		return -EINVAL;

	mutex_lock(&bq40z50->mutex);
	if (bq40z50->shutdown_complete) {
		mutex_unlock(&bq40z50->mutex);
		return -EIO;
	}
	if (enabled)
		bq40z50->low_battery_shutdown = false;
	else
		bq40z50->low_battery_shutdown = true;
	mutex_unlock(&bq40z50->mutex);

	return count;
}

static DEVICE_ATTR(low_battery_shutdown, 0444,
		bq40z50_show_lowbat_shutdown_state,
		bq40z50_set_lowbat_shutdown_state);

static struct attribute *bq40z50_attributes[] = {
	&dev_attr_low_battery_shutdown.attr,
	NULL
};

static const struct attribute_group bq40z50_attr_group = {
	.attrs = bq40z50_attributes,
};

static irqreturn_t bq40z50_irq(int id, void *dev)
{
	struct bq40z50_chip *chip = dev;

	bq40z50_update_soc_voltage(chip);
	power_supply_changed(chip->psy_bat);
	dev_info(chip->dev, "irq: Battery Voltage %dmV and SoC %d%%\n",
		 chip->vcell, chip->soc);

	return IRQ_HANDLED;
}

static int bq40z50_report_battery_voltage(struct battery_gauge_dev *bg_dev)
{
	struct bq40z50_chip *chip = battery_gauge_get_drvdata(bg_dev);
	int val;

	val = bq40z50_read_word(chip, BQ40Z50_VOLTAGE);
	if (val < 0)
		dev_err(chip->dev, "%s: err %d\n", __func__, val);

	return val;
}

static int bq40z50_report_battery_current(struct battery_gauge_dev *bg_dev)
{
	struct bq40z50_chip *chip = battery_gauge_get_drvdata(bg_dev);

	return bq40z50_read_word(chip, BQ40Z50_CURRENT);
}

static int bq40z50_report_battery_soc(struct battery_gauge_dev *bg_dev)
{
	struct bq40z50_chip *chip = battery_gauge_get_drvdata(bg_dev);
	int val;

	val = bq40z50_read_word(chip, BQ40Z50_STATE_OF_CHARGE);
	if (val < 0) {
		dev_err(chip->dev, "%s: err %d\n", __func__, val);
		return val;
	}

	val =  battery_gauge_get_adjusted_soc(chip->bg_dev,
					      chip->pdata->threshold_soc,
					      chip->pdata->maximum_soc,
					      val * 100);

	return val;
}

static int bq40z50_report_charging_status(struct battery_gauge_dev *bg_dev)
{
	struct bq40z50_chip *chip = battery_gauge_get_drvdata(bg_dev);

	return chip->status;
}

static int bq40z50_update_battery_state(struct battery_gauge_dev *bg_dev,
					enum battery_charger_status status)
{
	struct bq40z50_chip *chip = battery_gauge_get_drvdata(bg_dev);
	int val;

	mutex_lock(&chip->mutex);
	if (chip->shutdown_complete) {
		mutex_unlock(&chip->mutex);
		return 0;
	}

	val = bq40z50_read_word(chip, BQ40Z50_STATE_OF_CHARGE);
	if (val < 0)
		dev_err(chip->dev, "%s: err %d\n", __func__, val);
	else
		chip->soc = battery_gauge_get_adjusted_soc(chip->bg_dev,
				chip->pdata->threshold_soc,
				chip->pdata->maximum_soc, val * 100);

	if (chip->low_battery_shutdown && chip->soc == 0)
		chip->soc = 1;

	if (status == BATTERY_CHARGING) {
		chip->charge_complete = 0;
		chip->status = POWER_SUPPLY_STATUS_CHARGING;
	} else if (status == BATTERY_CHARGING_DONE) {
		if (chip->soc == BQ40Z50_BATTERY_FULL) {
			chip->charge_complete = 1;
			chip->status = POWER_SUPPLY_STATUS_FULL;
			chip->capacity_level =
					POWER_SUPPLY_CAPACITY_LEVEL_FULL;
		}
		goto done;
	} else {
		chip->status = POWER_SUPPLY_STATUS_DISCHARGING;
		chip->charge_complete = 0;
	}
	chip->lasttime_status = chip->status;

done:
	mutex_unlock(&chip->mutex);
	power_supply_changed(chip->psy_bat);
	dev_info(chip->dev, "Battery state:%d SoC: %d%% UI state:%d\n",
		 status, chip->soc, chip->status);
	return 0;
}

static struct battery_gauge_ops bq40z50_bg_ops = {
	.update_battery_status = bq40z50_update_battery_state,
	.get_battery_soc = bq40z50_report_battery_soc,
	.get_battery_voltage = bq40z50_report_battery_voltage,
	.get_battery_current = bq40z50_report_battery_current,
	.get_charging_status = bq40z50_report_charging_status,
};

static struct battery_gauge_info bq40z50_bgi = {
	.cell_id = 0,
	.bg_ops = &bq40z50_bg_ops,
};

static int bq40z50_fg_init(struct bq40z50_chip *chip)
{
	int ret = 0;

	if (chip->design_capacity) {
		ret = bq40z50_write_word(chip, BQ40Z50_DESIGN_CAPACITY,
					 chip->design_capacity);
		if (ret < 0) {
			dev_err(chip->dev,
				"design capacity write fail:%d\n", ret);
			return ret;
		}
	}

	if (chip->design_voltage) {
		ret = bq40z50_write_word(chip, BQ40Z50_DESIGN_VOLTAGE,
					 chip->design_voltage);
		if (ret < 0) {
			dev_err(chip->dev,
				"design voltage write fail:%d\n", ret);
			return ret;
		}
	}

	if (chip->btp_charge_set) {
		ret = bq40z50_write_word(chip, BQ40Z50_BTP_CHARGE,
					 chip->btp_charge_set);
		if (ret < 0) {
			dev_err(chip->dev, "btp charge write fail:%d\n", ret);
			return ret;
		}
	}

	if (chip->btp_discharge_set) {
		ret = bq40z50_write_word(chip, BQ40Z50_BTP_DISCHARGE,
					 chip->btp_discharge_set);
		if (ret < 0)
			dev_err(chip->dev,
				"btp discharge write fail:%d\n", ret);
	}
	return ret;
}

static void bq40z50_parse_dt_data(struct i2c_client *client,
				  struct bq40z50_pdata *pdata)
{
	struct device_node *np = client->dev.of_node;
	u32 pval;
	int ret;

	ret = of_property_read_u32(np, "ti,design-capacity", &pval);
	if (!ret)
		pdata->design_capacity = pval;

	ret = of_property_read_u32(np, "ti,design-voltage", &pval);
	if (!ret)
		pdata->design_voltage = pval;

	ret = of_property_read_u32(np, "ti,btp-discharge-set", &pval);
	if (!ret)
		pdata->btp_discharge_set = pval;

	ret = of_property_read_u32(np, "ti,btp-charge-set", &pval);
	if (!ret)
		pdata->btp_charge_set = pval;

	ret = of_property_read_u32(np, "ti,kernel-threshold-soc", &pval);
	if (!ret)
		pdata->threshold_soc = pval;

	ret = of_property_read_u32(np, "ti,kernel-maximum-soc", &pval);
	if (!ret)
		pdata->maximum_soc = pval;
	else
		pdata->maximum_soc = 100;
}

static int bq40z50_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct bq40z50_chip *chip;
	struct power_supply_config bq40z50_psy_cfg = {};
	int ret;

	chip = devm_kzalloc(&client->dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	if (client->dev.of_node) {
		chip->pdata = devm_kzalloc(&client->dev,
					      sizeof(*chip->pdata), GFP_KERNEL);
		if (!chip->pdata)
			return -ENOMEM;
		bq40z50_parse_dt_data(client, chip->pdata);
	}

	mutex_init(&chip->mutex);
	i2c_set_clientdata(client, chip);

	chip->client = client;
	chip->dev = &client->dev;
	chip->low_battery_shutdown = 0;
	chip->shutdown_complete = 0;
	chip->charge_complete = 0;
	chip->status		= POWER_SUPPLY_STATUS_DISCHARGING;
	chip->lasttime_status	= POWER_SUPPLY_STATUS_DISCHARGING;
	chip->lasttime_soc	= 0;
	bq40z50_psy_cfg.of_node = client->dev.of_node;
	bq40z50_psy_cfg.drv_data = chip;

	chip->design_capacity = chip->pdata->design_capacity;
	chip->design_voltage = chip->pdata->design_voltage;
	chip->btp_discharge_set = chip->pdata->btp_discharge_set;
	chip->btp_charge_set = chip->pdata->btp_charge_set;

	chip->rmap = devm_regmap_init_i2c(client, &bq40z50_rmap_config);
	if (IS_ERR(chip->rmap)) {
		ret = PTR_ERR(chip->rmap);
		dev_err(chip->dev, "regmap init failed:%d\n", ret);
		goto psy_exit;
	}

	chip->bg_dev = battery_gauge_register(chip->dev, &bq40z50_bgi, chip);
	if (IS_ERR(chip->bg_dev)) {
		ret = PTR_ERR(chip->bg_dev);
		dev_err(chip->dev, "battery gauge register fail:%d\n", ret);
		goto psy_exit;
	}

	chip->psy_bat = devm_power_supply_register(&client->dev,
						   &bq240z50_psy_desc,
						   &bq40z50_psy_cfg);
	if (IS_ERR(chip->psy_bat)) {
		ret = PTR_ERR(chip->psy_bat);
		dev_err(chip->dev, "failed: power supply register\n");
		goto psy_exit;
	}

	ret = bq40z50_fg_init(chip);
	if (ret < 0)
		dev_err(chip->dev, "fg init failed:%d\n", ret);

	bq40z50_update_soc_voltage(chip);

	if (client->irq) {
		ret = devm_request_threaded_irq(&client->dev, client->irq,
						NULL, bq40z50_irq,
						IRQF_ONESHOT |
						IRQF_TRIGGER_FALLING,
						dev_name(&client->dev), chip);
		if (ret < 0) {
			dev_err(chip->dev, "irq request fail:%d\n", ret);
			goto psy_exit;
		}
	}
	device_set_wakeup_capable(&client->dev, 1);
	device_wakeup_enable(&client->dev);

	INIT_DEFERRABLE_WORK(&chip->work, bq40z50_work);
	schedule_delayed_work(&chip->work, 0);

	dev_info(chip->dev, "init: Battery Voltage %dmV and SoC %d%%\n",
		 chip->vcell, chip->soc);

	ret = sysfs_create_group(&client->dev.kobj, &bq40z50_attr_group);
	if (ret < 0) {
		dev_err(chip->dev, "sysfs create failed:%d\n", ret);
		goto psy_exit;
	}

	return 0;

psy_exit:
	mutex_destroy(&chip->mutex);
	return ret;
}

static int bq40z50_remove(struct i2c_client *client)
{
	struct bq40z50_chip *chip = i2c_get_clientdata(client);

	power_supply_unregister(chip->psy_bat);
	cancel_delayed_work_sync(&chip->work);
	mutex_destroy(&chip->mutex);

	return 0;
}

static void bq40z50_shutdown(struct i2c_client *client)
{
	struct bq40z50_chip *chip = i2c_get_clientdata(client);

	if (chip->client->irq)
		disable_irq(chip->client->irq);

	mutex_lock(&chip->mutex);
	chip->shutdown_complete = 1;
	mutex_unlock(&chip->mutex);

	cancel_delayed_work_sync(&chip->work);
	dev_info(chip->dev, "At shutdown voltage %dmV and SoC %d%%\n",
		 chip->vcell, chip->soc);
}

#ifdef CONFIG_PM_SLEEP
static int bq40z50_suspend(struct device *dev)
{
	struct bq40z50_chip *chip = dev_get_drvdata(dev);

	cancel_delayed_work_sync(&chip->work);

	if (device_may_wakeup(chip->dev) && chip->client->irq)
		enable_irq_wake(chip->client->irq);

	dev_info(chip->dev, "At suspend voltage %dmV and SoC %d%%\n",
		 chip->vcell, chip->soc);
	return 0;
}

static int bq40z50_resume(struct device *dev)
{
	struct bq40z50_chip *chip = dev_get_drvdata(dev);

	if (device_may_wakeup(chip->dev) && chip->client->irq)
		disable_irq_wake(chip->client->irq);

	mutex_lock(&chip->mutex);
	bq40z50_update_soc_voltage(chip);
	power_supply_changed(chip->psy_bat);
	mutex_unlock(&chip->mutex);

	dev_info(chip->dev, "At resume voltage %dmV and SoC %d%%\n",
		 chip->vcell, chip->soc);
	schedule_delayed_work(&chip->work, BQ40Z50_DELAY);
	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static SIMPLE_DEV_PM_OPS(bq40z50_pm_ops, bq40z50_suspend, bq40z50_resume);

#ifdef CONFIG_OF
static const struct of_device_id bq40z50_dt_match[] = {
	{ .compatible = "ti,bq40z50-battery" },
	{ },
};
MODULE_DEVICE_TABLE(of, bq40z50_dt_match);
#endif

static const struct i2c_device_id bq40z50_id[] = {
	{ "bq40z50-battery", 0 },
	{ },
};

static struct i2c_driver bq40z50_i2c_driver = {
	.driver	= {
		.name	= "bq40z50-battery",
		.owner = THIS_MODULE,
		.of_match_table = bq40z50_dt_match,
		.pm = &bq40z50_pm_ops,
	},
	.probe		= bq40z50_probe,
	.remove		= bq40z50_remove,
	.shutdown	= bq40z50_shutdown,
	.id_table	= bq40z50_id,
};

static int __init bq40z50_init(void)
{
	return i2c_add_driver(&bq40z50_i2c_driver);
}
fs_initcall_sync(bq40z50_init);

static void __exit bq40z50_cleanup(void)
{
	i2c_del_driver(&bq40z50_i2c_driver);
}
module_exit(bq40z50_cleanup);

MODULE_DESCRIPTION("bq40z50 fuel gauge driver");
MODULE_AUTHOR("Venkat Reddy Talla <vreddytalla@nvidia.com>");
MODULE_LICENSE("GPL v2");

