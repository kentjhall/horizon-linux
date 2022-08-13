/*
 * Driver for the Epson RTC module RX-6110 SA
 * Copyright(C) 2017 NVIDIA CORPORATION. All rights reserved.
 * Copyright(C) 2015 Pengutronix, Steffen Trumtrar <kernel@pengutronix.de>
 * Copyright(C) SEIKO EPSON CORPORATION 2013. All rights reserved.
 *
 * This driver software is distributed as is, without any warranty of any kind,
 * either express or implied as further specified in the GNU Public License.
 * This software may be used and distributed according to the terms of the GNU
 * Public License, version 2 as published by the Free Software Foundation.
 * See the file COPYING in the main directory of this archive for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/bcd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/regmap.h>
#include <linux/rtc.h>
#include <linux/i2c.h>
#include <linux/spi/spi.h>

/* RX-6110 Register definitions */
#define RX6110_REG_SEC			0x10
#define RX6110_REG_MIN			0x11
#define RX6110_REG_HOUR			0x12
#define RX6110_REG_WDAY			0x13
#define RX6110_REG_MDAY			0x14
#define RX6110_REG_MONTH		0x15
#define RX6110_REG_YEAR			0x16
#define RX6110_REG_RES1			0x17
#define RX6110_REG_ALMIN		0x18
#define RX6110_REG_ALHOUR		0x19
#define RX6110_REG_ALWDAY		0x1A
#define RX6110_REG_TCOUNT0		0x1B
#define RX6110_REG_TCOUNT1		0x1C
#define RX6110_REG_EXT			0x1D
#define RX6110_REG_FLAG			0x1E
#define RX6110_REG_CTRL			0x1F
#define RX6110_REG_USER0		0x20
#define RX6110_REG_USER1		0x21
#define RX6110_REG_USER2		0x22
#define RX6110_REG_USER3		0x23
#define RX6110_REG_USER4		0x24
#define RX6110_REG_USER5		0x25
#define RX6110_REG_USER6		0x26
#define RX6110_REG_USER7		0x27
#define RX6110_REG_USER8		0x28
#define RX6110_REG_USER9		0x29
#define RX6110_REG_USERA		0x2A
#define RX6110_REG_USERB		0x2B
#define RX6110_REG_USERC		0x2C
#define RX6110_REG_USERD		0x2D
#define RX6110_REG_USERE		0x2E
#define RX6110_REG_USERF		0x2F
#define RX6110_REG_RES2			0x30
#define RX6110_REG_RES3			0x31
#define RX6110_REG_IRQ			0x32

#define RX6110_BIT_ALARM_EN		BIT(7)

/* Extension Register (1Dh) bit positions */
#define RX6110_BIT_EXT_TSEL0		BIT(0)
#define RX6110_BIT_EXT_TSEL1		BIT(1)
#define RX6110_BIT_EXT_TSEL2		BIT(2)
#define RX6110_BIT_EXT_WADA		BIT(3)
#define RX6110_BIT_EXT_TE		BIT(4)
#define RX6110_BIT_EXT_USEL		BIT(5)
#define RX6110_BIT_EXT_FSEL0		BIT(6)
#define RX6110_BIT_EXT_FSEL1		BIT(7)

/* Flag Register (1Eh) bit positions */
#define RX6110_BIT_FLAG_VLF		BIT(1)
#define RX6110_BIT_FLAG_AF		BIT(3)
#define RX6110_BIT_FLAG_TF		BIT(4)
#define RX6110_BIT_FLAG_UF		BIT(5)

/* Control Register (1Fh) bit positions */
#define RX6110_BIT_CTRL_TBKE		BIT(0)
#define RX6110_BIT_CTRL_TBKON		BIT(1)
#define RX6110_BIT_CTRL_TSTP		BIT(2)
#define RX6110_BIT_CTRL_AIE		BIT(3)
#define RX6110_BIT_CTRL_TIE		BIT(4)
#define RX6110_BIT_CTRL_UIE		BIT(5)
#define RX6110_BIT_CTRL_STOP		BIT(6)
#define RX6110_BIT_CTRL_TEST		BIT(7)
#define RX6110_ALARM_LEN		3
#define RW_MODE				(S_IWUSR | S_IRUGO)

#define RX6110_DRIVER_NAME		"rx6110"

enum {
	RTC_SEC = 0,
	RTC_MIN,
	RTC_HOUR,
	RTC_WDAY,
	RTC_MDAY,
	RTC_MONTH,
	RTC_YEAR,
	RTC_NR_TIME
};

struct rx6110_data {
	struct rtc_device *rtc;
	struct regmap *regmap;
	struct mutex lock;
	const struct regmap_irq_chip *irqchip;
	int irq;
	int virq;
	struct regmap_irq_chip_data *irq_data;
};

/*Add irq_chip configuration*/
static const struct regmap_irq rx6110_irqs[] = {
	/* RTC interrupts */
	REGMAP_IRQ_REG(0, 0, RX6110_BIT_FLAG_AF),
	REGMAP_IRQ_REG(1, 0, RX6110_BIT_FLAG_TF),
	REGMAP_IRQ_REG(2, 0, RX6110_BIT_FLAG_VLF),
	REGMAP_IRQ_REG(3, 0, RX6110_BIT_FLAG_UF),
};

static const struct regmap_irq_chip rx6110_irq_chip = {
	.name		= "rx6110-rtc",
	.status_base	= RX6110_REG_FLAG,
	.mask_base	= RX6110_REG_CTRL,
	.num_regs	= 1,
	.irqs		= rx6110_irqs,
	.num_irqs	= ARRAY_SIZE(rx6110_irqs),
	.mask_invert	= 1,
};

 /**
 * rx6110_rtc_tm_to_data - convert rtc_time to native time encoding
 *
 * @tm: holds date and time
 * @data: holds the encoding in rx6110 native form
 */
static int rx6110_rtc_tm_to_data(struct rtc_time *tm, u8 *data)
{
	pr_debug("%s: date %ds %dm %dh %dmd %dm %dy\n", __func__,
		 tm->tm_sec, tm->tm_min, tm->tm_hour,
		 tm->tm_mday, tm->tm_mon, tm->tm_year);

	/*
	 * The year in the RTC is a value between 0 and 99.
	 * Assume that this represents the current century
	 * and disregard all other values.
	 */
	if (tm->tm_year < 100 || tm->tm_year >= 200)
		return -EINVAL;

	data[RTC_SEC] = bin2bcd(tm->tm_sec);
	data[RTC_MIN] = bin2bcd(tm->tm_min);
	data[RTC_HOUR] = bin2bcd(tm->tm_hour);
	data[RTC_WDAY] = BIT(tm->tm_wday);
	data[RTC_MDAY] = bin2bcd(tm->tm_mday);
	data[RTC_MONTH] = bin2bcd(tm->tm_mon + 1);
	data[RTC_YEAR] = bin2bcd(tm->tm_year % 100);

	return 0;
}

/**
 * rx6110_data_to_rtc_tm - convert native time encoding to rtc_time
 *
 * @data: holds the encoding in rx6110 native form
 * @tm: holds date and time
 */
static int rx6110_data_to_rtc_tm(u8 *data, struct rtc_time *tm)
{
	tm->tm_sec = bcd2bin(data[RTC_SEC] & 0x7f);
	tm->tm_min = bcd2bin(data[RTC_MIN] & 0x7f);
	/* only 24-hour clock */
	tm->tm_hour = bcd2bin(data[RTC_HOUR] & 0x3f);
	tm->tm_wday = ffs(data[RTC_WDAY] & 0x7f);
	tm->tm_mday = bcd2bin(data[RTC_MDAY] & 0x3f);
	tm->tm_mon = bcd2bin(data[RTC_MONTH] & 0x1f) - 1;
	tm->tm_year = bcd2bin(data[RTC_YEAR]) + 100;

	pr_debug("%s: date %ds %dm %dh %dmd %dm %dy\n", __func__,
		 tm->tm_sec, tm->tm_min, tm->tm_hour,
		 tm->tm_mday, tm->tm_mon, tm->tm_year);

	/*
	 * The year in the RTC is a value between 0 and 99.
	 * Assume that this represents the current century
	 * and disregard all other values.
	 */
	if (tm->tm_year < 100 || tm->tm_year >= 200)
		return -EINVAL;

	return 0;
}

/**
 * rx6110_set_time - set the current time in the rx6110 registers
 *
 * @dev: the rtc device in use
 * @tm: holds date and time
 *
 * BUG: The HW assumes every year that is a multiple of 4 to be a leap
 * year. Next time this is wrong is 2100, which will not be a leap year
 *
 * Note: If STOP is not set/cleared, the clock will start when the seconds
 *	 register is written
 *
 */
static int rx6110_set_time(struct device *dev, struct rtc_time *tm)
{
	struct rx6110_data *rx6110 = dev_get_drvdata(dev);
	u8 data[RTC_NR_TIME];
	int ret;

	ret = rx6110_rtc_tm_to_data(tm, data);
	if (ret < 0)
		return ret;

	pr_debug("rx6110 set time: %u:%u:%u, %u/%u/%u\n", data[2], data[1],
		data[0], data[4], data[5], data[6]);
	/* set STOP bit before changing clock/calendar */
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_CTRL,
				 RX6110_BIT_CTRL_STOP, RX6110_BIT_CTRL_STOP);
	if (ret)
		return ret;

	ret = regmap_bulk_write(rx6110->regmap, RX6110_REG_SEC, data,
				RTC_NR_TIME);
	if (ret)
		return ret;

	/* The time in the RTC is valid. Be sure to have VLF cleared. */
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_FLAG,
				 RX6110_BIT_FLAG_VLF, 0);
	if (ret)
		return ret;

	/* clear STOP bit after changing clock/calendar */
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_CTRL,
				 RX6110_BIT_CTRL_STOP, 0);

	return ret;
}

/**
 * rx6110_get_time - get the current time from the rx6110 registers
 * @dev: the rtc device in use
 * @tm: holds date and time
 */
static int rx6110_get_time(struct device *dev, struct rtc_time *tm)
{
	struct rx6110_data *rx6110 = dev_get_drvdata(dev);
	u8 data[RTC_NR_TIME];
	int flags;
	int ret;

	ret = regmap_read(rx6110->regmap, RX6110_REG_FLAG, &flags);
	if (ret)
		return -EINVAL;

	/* check for VLF Flag (set at power-on) */
	if ((flags & RX6110_BIT_FLAG_VLF)) {
		dev_warn(dev, "Voltage low, data is invalid.\n");
		return -EINVAL;
	}

	/* read registers to date */
	ret = regmap_bulk_read(rx6110->regmap, RX6110_REG_SEC, data,
			       RTC_NR_TIME);
	if (ret)
		return ret;
	pr_debug("rx6110 get time: %u:%u:%u, %u/%u/%u\n", data[2], data[1],
		data[0], data[4], data[5], data[6]);

	ret = rx6110_data_to_rtc_tm(data, tm);
	if (ret)
		return ret;

	dev_dbg(dev, "%s: date %ds %dm %dh %dmd %dm %dy\n", __func__,
		tm->tm_sec, tm->tm_min, tm->tm_hour,
		tm->tm_mday, tm->tm_mon, tm->tm_year);

	return rtc_valid_tm(tm);
}

/**struct regmap_range - A register range, used for access related checks
  *@RX6110_REG_SEC: address of first register
  *@RX6110_REG_IRQ: address of last register
  */
static const struct regmap_range regmap_range_cfg[] = {
	regmap_reg_range(RX6110_REG_SEC, RX6110_REG_IRQ),

};

static const struct regmap_access_table regmap_readble_table = {
	.yes_ranges = regmap_range_cfg,
	.n_yes_ranges = ARRAY_SIZE(regmap_range_cfg),
};

/* Alarm */
/* Clear alarm status bit. */
static int rx6110_rtc_clear_alarm(struct device *dev)
{
	struct rx6110_data *data = dev_get_drvdata(dev);
	int ret;

	ret = regmap_update_bits(data->regmap, RX6110_REG_FLAG,
		 RX6110_BIT_FLAG_AF, 0);
	if (ret)
		dev_err(dev, "%s: clearing alarm failed (%d)\n",
		__func__, ret);

	return ret;
}

/* Enable or disable alarm (i.e. alarm interrupt generation) */
static int rx6110_rtc_update_alarm(struct device *dev, int enable)
{
	struct rx6110_data *data = dev_get_drvdata(dev);
	int ret;

	ret = regmap_update_bits(data->regmap, RX6110_REG_CTRL,
		 0x08, enable ? 8 : 0);
	if (ret)
		dev_err(dev, "%s: writing alarm INT failed (%d)\n",
			 __func__, ret);

	return ret;
}

/*Creating sysfs nodes to set and read the values of
 * RX6110_BIT_EXT_WADA bit and RX6110_REG_ALWDAY (0x1A)
 * @WADA : this node is used to select either week alarm or day alarm
 * @WeekDay_alarm: this node is used to set the alarm value
*/
static const char alarm_week_str[] =
"Value represented as bitmask to visualize weekday,\r\n|Sun\t|Mon\t|Tue\t|Wed\t|Thr\t|Fri\t|Sat\r\n|%d\t|%d\t|%d\t|%d\t|%d\t|%d\t|%d\r\nHour:%d, Minute: %d\n";
#define WADA_SUN(x)		(x&0x01)
#define WADA_MON(x)		((x & 0x02) >> 1)
#define WADA_TUE(x)		((x & 0x04) >> 2)
#define WADA_WED(x)		((x & 0x08) >> 3)
#define WADA_THR(x)		((x & 0x10) >> 4)
#define WADA_FRI(x)		((x & 0x20) >> 5)
#define WADA_SAT(x)		((x & 0x40) >> 6)
#define ALARM_WEEKDAYS(x)	WADA_SUN(x), WADA_MON(x), WADA_TUE(x), \
				WADA_WED(x),\
				WADA_THR(x), WADA_FRI(x), WADA_SAT(x)
static ssize_t rx6110_WADA_show(struct device *dev,
	struct device_attribute *attr,
	char *buf)
{
	int ret;
	unsigned int bits;
	struct rx6110_data *rx6110;

	rx6110 = dev_get_drvdata(dev->parent);
	ret = regmap_read(rx6110->regmap, RX6110_REG_EXT, &bits);
	if (ret)
		return ret;

	if ((bits & RX6110_BIT_EXT_WADA) == 0)
		ret = snprintf(buf, sizeof("0: Weekly alarms configured\n"),
			"0: Weekly alarms configured\n");
	else
		ret = snprintf(buf, sizeof("1: Daily alarms configured\n"),
			"1: Daily alarms configured\n");

	return ret;
}

static ssize_t rx6110_WADA_store(struct device *dev,
	 struct device_attribute *attr,
	 const char *buf, size_t n)
{
	unsigned int bits;
	int ret;
	struct rx6110_data *rx6110 = dev_get_drvdata(dev->parent);

	if (n < 1)
		return 0;

	ret = kstrtouint(buf, 0, &bits);
	if (ret < 1)
		return ret;
	if (bits == 1)
		bits = RX6110_BIT_EXT_WADA;
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_EXT,
				 RX6110_BIT_EXT_WADA, bits);
	return n;
}

static ssize_t rx6110_AlarmData_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct rx6110_data *rx6110;
	int ret;
	unsigned int bits;
	struct rtc_time time;

	rx6110 = dev_get_drvdata(dev->parent);

	ret = regmap_read(rx6110->regmap, RX6110_REG_ALMIN, &bits);
	if (ret)
		return ret;
	if ((bits & 0x80) == 0)
		time.tm_min = bits & 0x7f;
	else
		time.tm_min = 0;

	ret = regmap_read(rx6110->regmap, RX6110_REG_ALHOUR, &bits);
	if (ret)
		return ret;
	if ((bits & 0x80) == 0)
		time.tm_hour = bits & 0x3f;
	else
		time.tm_hour = 0;

	ret = regmap_read(rx6110->regmap, RX6110_REG_ALWDAY, &bits);
	if (ret)
		return ret;
	if ((bits & 0x80) == 0)
		time.tm_mday = bits & 0x7f;
	else
		time.tm_mday = 0;

	ret = regmap_read(rx6110->regmap, RX6110_REG_EXT, &bits);
	if (ret)
		return ret;
	if ((bits & RX6110_BIT_EXT_WADA) == 0) {
		/*WADA bit is set, so day is selected */
		ret = snprintf(buf, sizeof(alarm_week_str), alarm_week_str,
			ALARM_WEEKDAYS(time.tm_mday), time.tm_hour,
			time.tm_min);
	} else {
		ret = snprintf(buf, sizeof("day:%d, Hour:%d, Minute: %d\n"),
			"day:%d, Hour:%d, Minute: %d\n",
			time.tm_mday, time.tm_hour, time.tm_min);
	}

	return ret;
}

static ssize_t rx6110_AlarmData_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t n)
{
	struct rx6110_data *rx6110;
	int ret;
	unsigned int bits, int_data[3];
	u8 data[RX6110_ALARM_LEN];

	rx6110 = dev_get_drvdata(dev->parent);

	if (n < 1)
		return 0;

	ret = sscanf(buf, "%u-%u:%u", &int_data[2], &int_data[1], &int_data[0]);
	if (ret < 3)
		return ret;
	/*Read WADA bit to check the mask for WDAY register*/
	ret = regmap_read(rx6110->regmap, RX6110_REG_EXT, &bits);
	if (ret)
		return ret;

	/*Convert to BCD format*/
	data[2] = bin2bcd(int_data[2] & 0x7f);
	data[1] = bin2bcd(int_data[1] & 0x7f);
	data[0] = bin2bcd(int_data[0] & 0x7f);
	if (bits & RX6110_BIT_EXT_WADA)
		data[2] &= 0x3f;
	else
		data[2] &= 0x7f;


	/*If all values are 0, disable the alarm*/
	if ((data[0] && data[1] && data[2]) == 0) {
		bits = 0;
		data[0] |= 0x80;
		data[1] |= 0x80;
		data[2] |= 0x80;
	} else
		bits = RX6110_BIT_CTRL_AIE;

	/*Write to minute, hour and wday registers*/
	ret = regmap_bulk_write(rx6110->regmap, RX6110_REG_ALMIN, data,
		RX6110_ALARM_LEN);
	if (ret)
		return ret;
	/*Write to control register with alarm interrupt status*/
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_CTRL,
		RX6110_BIT_CTRL_AIE, bits);
	if (ret)
		return ret;

	return n;
}

static DEVICE_ATTR(wada, RW_MODE, rx6110_WADA_show, rx6110_WADA_store);
static DEVICE_ATTR(weekday_alarm, RW_MODE, rx6110_AlarmData_show,
		 rx6110_AlarmData_store);

static const struct attribute *rx6110_attr[] = {
	&dev_attr_wada.attr,
	&dev_attr_weekday_alarm.attr,
	NULL,
};

/*__rx6110_rtc_set_alarm: compares the alarm time with the rtc time*/
static int __rx6110_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alarm,
		int *enable)
{
	struct rtc_time *alarm_tm = &alarm->time;
	struct rtc_time rtc_tm;
	unsigned long rtc_secs, alarm_secs;
	int ret;

	ret = rx6110_get_time(dev, &rtc_tm);
	if (ret)
		return ret;

	ret = rtc_tm_to_time(&rtc_tm, &rtc_secs);
	if (ret)
		return ret;

	ret = rtc_tm_to_time(alarm_tm, &alarm_secs);
	if (ret)
		return ret;

	/* If alarm time is before current time, disable the alarm */
	if (!alarm->enabled || alarm_secs <= rtc_secs) {
		*enable = 0;
	} else {
		/*
		* Chip only support alarms up to one month in the future.
		* Return an error if value is over one month.
		* Comparison is done by incrementing rtc_tm month field by one
		* and checking alarm value is still below.
		*/

		if (rtc_tm.tm_mon == 11) { /*handle year wrapping*/
			rtc_tm.tm_mon = 0;
			rtc_tm.tm_year += 1;
		} else {
			rtc_tm.tm_mon += 1;
		}

		ret = rtc_tm_to_time(&rtc_tm, &rtc_secs);
		if (ret)
			return ret;

		if (alarm_secs > rtc_secs) {
			dev_err(dev, "%s: max for alarm is one month (%d)\n",
			 __func__, ret);
			return -EINVAL;
		}

	}
	return 0;
}

static int rx6110_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct rx6110_data *data = dev_get_drvdata(dev);
	struct rtc_time *alarm_tm = &alarm->time;
	u8 regs[RX6110_ALARM_LEN];
	int ret, enable = 0;

	if (alarm->enabled)
		enable = 1;

	mutex_lock(&data->lock);

	/*Check if alarm is valid*/
	ret = __rx6110_rtc_set_alarm(dev, alarm, &enable);
	if (ret)
		goto err_unlock;

	/* Disable the alarm (AIE = 0) before modifying it */
	ret = rx6110_rtc_update_alarm(dev, 0);
	if (ret < 0) {
		dev_err(dev, "%s: unable to disable the alarm (%d)\n",
		 __func__, ret);
		goto err_unlock;
	}

	/* Program alarm registers */
	regs[0] = bin2bcd(alarm_tm->tm_min) & 0x7f;
	regs[1] = bin2bcd(alarm_tm->tm_hour) & 0x3f;
	regs[2] = bin2bcd(alarm_tm->tm_wday) & 0x3f;

	ret = regmap_bulk_write(data->regmap, RX6110_REG_ALMIN, regs,
				RX6110_ALARM_LEN);

	if (ret < 0) {
		dev_err(dev, "%s: writing alarm section failed (%d)\n",
			__func__, ret);
		goto err_unlock;
	}
	/*Set WADA bit high to enable day comparison*/
	ret = regmap_update_bits(data->regmap, RX6110_REG_EXT,
			RX6110_BIT_EXT_WADA, RX6110_BIT_EXT_WADA);
	if (ret) {
		dev_err(dev, "%s: writing WADA bit failed (%d)\n",
			__func__, ret);
	goto err_unlock;
	}

	/*clear alarm flag AF*/
	ret = rx6110_rtc_clear_alarm(dev);
	if (ret) {
		dev_err(dev, "%s: Cannot clear AF (%d)\n",
		 __func__, ret);
		goto err_unlock;
	}
		/* Enable alarm (AIE=1) */
	ret = rx6110_rtc_update_alarm(dev, enable);
	if (ret) {
		dev_err(dev, "%s: Failed to enable alarm interrupt (%d)\n",
		 __func__, ret);
		goto err_unlock;
	}

err_unlock:
	mutex_unlock(&data->lock);
	return ret;
}

/**__rx6110_rtc_read_alarm: reads the alarm registers and
  *		adjust the month and year if necessary
  */
static int __rx6110_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct rx6110_data *data = dev_get_drvdata(dev);
	struct rtc_time rtc_tm, *alarm_tm = &alarm->time;
	unsigned long rtc_secs, alarm_secs;
	u8 regs[RX6110_ALARM_LEN];
	unsigned int ext;
	int ret;

	ret = regmap_bulk_read(data->regmap, RX6110_REG_ALMIN,
		regs, RX6110_ALARM_LEN);
	if (ret) {
		dev_err(dev, "%s: reading alarm section failed (%d)\n",
			__func__, ret);
		return ret;
	}

	alarm_tm->tm_min = bcd2bin(regs[0] & 0x7f);
	alarm_tm->tm_hour = bcd2bin(regs[1] & 0x3f);
	alarm_tm->tm_wday = bcd2bin(regs[2] & 0x7f);
	/*
	* The alarm section does not store year/month. Use the data in rtc
	* as basis and increment month and then year if needed to get
	* alarm after current time.
	*/
	ret = rx6110_get_time(dev, &rtc_tm);
	if (ret)
		return ret;
	alarm_tm->tm_year = rtc_tm.tm_year;
	alarm_tm->tm_mon = rtc_tm.tm_mon;

	ret = rtc_tm_to_time(&rtc_tm, &rtc_secs);
	if (ret)
		return ret;

	ret = rtc_tm_to_time(alarm_tm, &alarm_secs);
	if (ret)
		return ret;
	/*
	* If WADA bit is set, alarm triggers on the configured day
	* else on the days selected in wday field
	*/
	ret = regmap_read(data->regmap, RX6110_REG_EXT, &ext);
	if (ret)
		return ret;

	/*If alarm bits are not enabled, then next alarm is empty*/
	if (!((regs[0] & RX6110_BIT_ALARM_EN) &&
		(regs[1] & RX6110_BIT_ALARM_EN) &&
		(regs[2] & RX6110_BIT_ALARM_EN))) {
		alarm->enabled = 0;
	/*If WADA is set then consider monthly alarm*/
	} else if (ext & RX6110_BIT_EXT_WADA) {
		if (alarm_secs < rtc_secs) {
			if (alarm_tm->tm_mon == 11) {
				alarm_tm->tm_mon = 0;
				alarm_tm->tm_year += 1;
			} else {
				alarm_tm->tm_mon += 1;
			}
		}
	} else if ((ext & RX6110_BIT_EXT_WADA) == 0) {
	/*Handle week day alarm*/
		if (alarm_secs < rtc_secs) {
			if ((alarm_tm->tm_mday + 7) >=
				(rtc_month_days(alarm_tm->tm_mon, alarm_tm->tm_year +
				1900))) {
				alarm_tm->tm_mday = (alarm_tm->tm_mday + 7) %
						(rtc_month_days(alarm_tm->tm_mon,
						alarm_tm->tm_year + 1900));
				if (alarm_tm->tm_mon == 11) {
					alarm_tm->tm_mon = 0;
					alarm_tm->tm_year += 1;
				} else {
					alarm_tm->tm_mon += 1;
				}
			} else {
				alarm_tm->tm_mday += 7;
			}
		}

	}

	return 0;
}

static int rx6110_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct rx6110_data *data = dev_get_drvdata(dev);
	unsigned int ir;
	int ret;

	mutex_lock(&data->lock);
	ret = __rx6110_rtc_read_alarm(dev, alarm);
	if (ret)
		goto err_unlock;
	/* enable alarm if AIE bit is '1' */
	ret = regmap_read(data->regmap, RX6110_REG_CTRL, &ir);
	if (ret) {
		dev_err(dev, "%s: reading alarm interrupt flag failed (%d)\n",
			__func__, ret);
		goto err_unlock;
	}

	alarm->enabled = !!(ir & RX6110_BIT_CTRL_AIE);
	alarm->pending = 0;
err_unlock:
	mutex_unlock(&data->lock);
	return ret;
}

static void rx6110_sysfs_init(struct device *dev)
{
	int ret = 0;

	if ((!dev) || !(&dev->kobj)) {
		pr_err("unable to create rx6110 kernel object!\n");
		return;
	}

	/* create sysfs */
	ret = sysfs_create_files(&dev->kobj, rx6110_attr);
	if (ret)
		pr_err("failed to create wada and weekday_alarm files\n");
}

static void rx6110_sysfs_exit(struct device *dev)
{
	if ((!dev) || !(&dev->kobj))
		return;
	sysfs_remove_files(&dev->kobj, rx6110_attr);
}

static const struct reg_sequence rx6110_default_regs1[] = {
	{ RX6110_REG_RES1,   0xB8},
	{ RX6110_REG_RES2,   0x00},
	{ RX6110_REG_RES3,   0x10},
	{ RX6110_REG_IRQ,    0x00},
};

static const struct reg_sequence rx6110_default_regs2[] = {
	{ RX6110_REG_ALMIN,  0x00},
	{ RX6110_REG_ALHOUR, 0x00},
	{ RX6110_REG_ALWDAY, 0x00},
};

/*Alarm IRQ handler*/
static irqreturn_t rx6110_alarm_irq(int irq, void *data)
{
	struct rx6110_data *rx6110 = data;
	int ret;

	dev_dbg(&rx6110->rtc->dev, "RTC alarm IRQ: %d\n", irq);
	rtc_update_irq(rx6110->rtc, 1, RTC_IRQF | RTC_AF);
	/* clear alarm flag */
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_FLAG,
				RX6110_BIT_FLAG_AF, 0);
	if (ret < 0)
		return ret;

	return IRQ_HANDLED;
}


/**
 * rx6110_init - initialize the rx6110 registers
 *
 * @rx6110: pointer to the rx6110 struct in use
 *
 */
static int rx6110_init(struct rx6110_data *rx6110)
{
	struct rtc_device *rtc = rx6110->rtc;
	int flags;
	int ret;

	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_EXT,
				 RX6110_BIT_EXT_TE, 0);
	if (ret)
		return ret;

	ret = regmap_register_patch(rx6110->regmap, rx6110_default_regs1,
				    ARRAY_SIZE(rx6110_default_regs1));
	if (ret)
		return ret;

/** Check for voltage low bit(VLF).
  *	0 : set the register values to default values
  *	1 : The Previous value of RTC registers are retained
  */
	ret = regmap_read(rx6110->regmap, RX6110_REG_FLAG, &flags);
	if (ret)
		return ret;

	if (flags & RX6110_BIT_FLAG_VLF) {
		dev_warn(&rtc->dev, "Voltage low, data loss detected.\n");
		ret = regmap_register_patch(rx6110->regmap,
			rx6110_default_regs2, ARRAY_SIZE(rx6110_default_regs2));
		if (ret)
			return ret;
	}

	/* check for Alarm Flag */
	if (flags & RX6110_BIT_FLAG_AF)
		dev_warn(&rtc->dev, "An alarm may have been missed.\n");


	/* clear all flags BUT VLF */
	ret = regmap_update_bits(rx6110->regmap, RX6110_REG_FLAG,
				RX6110_BIT_FLAG_AF |
				RX6110_BIT_FLAG_UF |
				RX6110_BIT_FLAG_TF |
				RX6110_BIT_FLAG_VLF,
				 0);
	if (ret < 0)
		return ret;

	rx6110->irqchip = &rx6110_irq_chip;
	ret = regmap_add_irq_chip(rx6110->regmap, rx6110->irq,
				  IRQF_TRIGGER_FALLING | IRQF_ONESHOT |
				  IRQF_SHARED, 0, rx6110->irqchip,
				  &rx6110->irq_data);
	if (ret < 0) {
		dev_err(&rx6110->rtc->dev, "Failed to add RTC irq chip: %d\n",
			ret);
		goto err_rtc;
	}

	/*Request virq for Alarm interrupt*/
	rx6110->virq = regmap_irq_get_virq(rx6110->irq_data, 0);
	if (rx6110->virq <= 0) {
		ret = -ENXIO;
		goto err_rtc;
	}
	dev_dbg(&rx6110->rtc->dev, "virq for rx6110 alarm irq: %d\n",
		rx6110->virq);
	ret = request_threaded_irq(rx6110->virq, NULL, rx6110_alarm_irq, 0,
		"rx6110_rtc_alarm", rx6110);
	if (ret < 0)
		dev_err(&rx6110->rtc->dev, "Failed to request alarm IRQ: %d: %d\n",
			rx6110->virq, ret);
err_rtc:
	return 0;
}



static const struct rtc_class_ops rx6110_rtc_ops = {
	.read_time = rx6110_get_time,
	.set_time = rx6110_set_time,
	.set_alarm = rx6110_rtc_set_alarm,
	.read_alarm = rx6110_rtc_read_alarm,
};

static const struct regmap_config regmap_rx6110_config = {
	.reg_bits = 8,
	.reg_stride = 0,
	.val_bits = 8,
	.max_register = RX6110_REG_IRQ,
	.read_flag_mask = 0x80,
	.rd_table = &regmap_readble_table,
};

#if IS_ENABLED(CONFIG_SPI_MASTER)

/**
 * rx6110_probe - initialize rtc driver
 * @spi: pointer to spi device
 */
static int rx6110_spi_probe(struct spi_device *spi)
{
	struct rx6110_data *rx6110;
	int err;

	if ((spi->bits_per_word && spi->bits_per_word != 8) ||
	    (spi->max_speed_hz > 2000000) ||
	    (spi->mode != (SPI_CS_HIGH | SPI_CPOL | SPI_CPHA))) {
		dev_warn(&spi->dev, "SPI settings: bits_per_word: %d, max_speed_hz: %d, mode: %xh\n",
			 spi->bits_per_word, spi->max_speed_hz, spi->mode);
		dev_warn(&spi->dev, "driving device in an unsupported mode");
	}

	rx6110 = devm_kzalloc(&spi->dev, sizeof(*rx6110), GFP_KERNEL);
	if (!rx6110)
		return -ENOMEM;
	mutex_init(&rx6110->lock);
	rx6110->regmap = devm_regmap_init_spi(spi, &regmap_rx6110_config);
	if (IS_ERR(rx6110->regmap)) {
		dev_err(&spi->dev, "regmap init failed for rtc rx6110\n");
		return PTR_ERR(rx6110->regmap);
	}

	spi_set_drvdata(spi, rx6110);
	device_set_wakeup_capable(&spi->dev, 1);
	rx6110->rtc = devm_rtc_device_register(&spi->dev,
					       RX6110_DRIVER_NAME,
					       &rx6110_rtc_ops, THIS_MODULE);

	if (IS_ERR(rx6110->rtc))
		return PTR_ERR(rx6110->rtc);

	/*Assign irq number from device*/
	rx6110->irq = spi->irq;

	err = rx6110_init(rx6110);


	if (err)
		return err;

/*max_user_freq:The maximum interrupt rate an unprivileged user may request
 *				 from this RTC(1Hz).
 */
	rx6110->rtc->max_user_freq = 1;
	rx6110_sysfs_init(&rx6110->rtc->dev);

	rx6110->rtc->uie_unsupported = 1;

	return 0;
}

static int rx6110_spi_remove(struct spi_device *spi)
{
	struct rx6110_data *rx6110 = spi_get_drvdata(spi);

	if ((!rx6110) || (!rx6110->rtc))
		return 0;
	free_irq(rx6110->virq, rx6110);
	rx6110_sysfs_exit(&rx6110->rtc->dev);
	return 0;
}

static const struct spi_device_id rx6110_spi_id[] = {
	{ "rx6110", 0},
	{}
};
MODULE_DEVICE_TABLE(spi, rx6110_id);

static struct spi_driver rx6110_spi_driver = {
	.driver = {
		.name = RX6110_DRIVER_NAME,
	},
		.probe = rx6110_spi_probe,
		.remove = rx6110_spi_remove,
		.id_table = rx6110_spi_id,
};

module_spi_driver(rx6110_spi_driver);

#endif

#if IS_ENABLED(CONFIG_I2C)
/**
  * rx6110_probe - initialize rtc driver
  * @i2c: pointer to i2c device
  */
static int rx6110_i2c_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	struct rx6110_data *rx6110;
	int err;

	rx6110 = devm_kzalloc(&client->dev, sizeof(*rx6110), GFP_KERNEL);

	if (!rx6110)
		return -ENOMEM;

	mutex_init(&rx6110->lock);
	rx6110->regmap = devm_regmap_init_i2c(client, &regmap_rx6110_config);

	if (IS_ERR(rx6110->regmap)) {
		dev_err(&client->dev, "%s: regmap allocation failed: %ld\n",
		 __func__, PTR_ERR(rx6110->regmap));
		return PTR_ERR(rx6110->regmap);
	}

	i2c_set_clientdata(client, rx6110);
	device_set_wakeup_capable(&client->dev, 1);
	rx6110->rtc = devm_rtc_device_register(&client->dev, RX6110_DRIVER_NAME,
			 &rx6110_rtc_ops, THIS_MODULE);

	if (IS_ERR(rx6110->rtc))
		return PTR_ERR(rx6110->rtc);

	/*Assign irq number from device*/
	rx6110->irq = client->irq;

	err = rx6110_init(rx6110);
	if (err)
		return err;
/** max_user_freq:The maximum interrupt rate an unprivileged user may request
  *				 from this RTC(1Hz).
  */
	rx6110->rtc->max_user_freq = 1;
	rx6110_sysfs_init(&rx6110->rtc->dev);

	rx6110->rtc->uie_unsupported = 1;

	return 0;
}

static int rx6110_i2c_remove(struct i2c_client *client)
{
	struct rx6110_data *rx6110 =
			(struct rx6110_data *)i2c_get_clientdata(client);
	if ((!rx6110) || !(&rx6110->rtc->dev))
		return 0;
	rx6110_sysfs_exit(&rx6110->rtc->dev);
	return 0;
}

static const struct i2c_device_id rx6110_i2c_id[] = {
	{ "rx6110", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, rx6110_i2c_id);

static struct i2c_driver rx6110_i2c_driver = {
	.driver = {
		.name = RX6110_DRIVER_NAME,
	},
	.probe		= rx6110_i2c_probe,
	.remove		= rx6110_i2c_remove,
	.id_table	= rx6110_i2c_id,
};
module_i2c_driver(rx6110_i2c_driver);

#endif

MODULE_AUTHOR("Val Krutov <val.krutov@erd.epson.com>,Poojashree <pms@nvidia.com>, Vishruth Jain <vishruthj@nvidia.com>");
MODULE_DESCRIPTION("RX-6110 SA RTC driver over SPI and I2C");
MODULE_LICENSE("GPL");
