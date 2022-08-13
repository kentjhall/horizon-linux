/*
 * Copyright (c) 2017, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pwm.h>
#include <linux/platform_device.h>
#include <soc/tegra/pmc.h>

struct tegra_pwm_led_soft_blink {
	struct pwm_chip chip;
	struct device *dev;
	u32 ramp_time;
	u32 double_pulse_period;
};

static int tegra_pwm_lsb_config(struct pwm_chip *p_chip, struct pwm_device *pwm,
				int duty_cycle, int period)
{
	struct tegra_pwm_led_soft_blink *pwm_lsb = container_of(p_chip,
				struct tegra_pwm_led_soft_blink, chip);

	int ramptime_ns;

	if (pwm->ramp_time)
		ramptime_ns = pwm->ramp_time;
	else
		ramptime_ns = pwm_lsb->ramp_time;

	return tegra_pmc_soft_led_blink_configure(duty_cycle, period,
						  ramptime_ns);
}

static int tegra_pwm_lsb_set_ramptime(struct pwm_chip *p_chip,
				      struct pwm_device *pwm, int ramp_time_ns)
{
	return tegra_pmc_soft_led_blink_set_ramptime(ramp_time_ns);
}

static int tegra_pwm_lsb_set_short_period(struct pwm_chip *p_chip,
					  struct pwm_device *pwm, int period)
{
	return tegra_pmc_soft_led_blink_set_short_period(period);
}

static int tegra_pwm_lsb_enable(struct pwm_chip *chip,
				struct pwm_device *pwm)
{
	return tegra_pmc_soft_led_blink_enable();
}

static void tegra_pwm_lsb_disable(struct pwm_chip *chip,
				  struct pwm_device *pwm)
{
	tegra_pmc_soft_led_blink_disable();
}

static const struct pwm_ops tegra_pwm_led_soft_blink_ops = {
	.config = tegra_pwm_lsb_config,
	.set_ramp_time = tegra_pwm_lsb_set_ramptime,
	.set_double_pulse_period = tegra_pwm_lsb_set_short_period,
	.enable = tegra_pwm_lsb_enable,
	.disable = tegra_pwm_lsb_disable,
	.owner = THIS_MODULE,
};

static int tegra_pwm_lsb_pasre_dt(struct tegra_pwm_led_soft_blink *pwm_lsb)
{
	struct device_node *np = pwm_lsb->dev->of_node;
	u32 pval;
	int ret;

	ret = of_property_read_u32(np, "pwm,led-breathing-ramp-time-ns", &pval);
	if (!ret)
		pwm_lsb->ramp_time = pval;
	else
		return ret;

	ret = of_property_read_u32(np, "pwm,led-breathing-short-period-ns",
				   &pval);
	if (!ret)
		pwm_lsb->double_pulse_period = pval;

	return ret;
}

static int tegra_pwm_led_soft_blink_probe(struct platform_device *pdev)
{
	struct tegra_pwm_led_soft_blink *pwm_lsb;
	int ret;

	pwm_lsb = devm_kzalloc(&pdev->dev, sizeof(*pwm_lsb), GFP_KERNEL);
	if (!pwm_lsb)
		return -ENOMEM;

	pwm_lsb->dev = &pdev->dev;

	ret = tegra_pwm_lsb_pasre_dt(pwm_lsb);
	if (ret < 0) {
		dev_err(&pdev->dev, "Reading data from DT failed: %d\n", ret);
		return ret;
	}

	pwm_lsb->chip.dev = &pdev->dev;
	pwm_lsb->chip.ops = &tegra_pwm_led_soft_blink_ops;
	pwm_lsb->chip.base = -1;
	pwm_lsb->chip.npwm = 1;

	ret = pwmchip_add(&pwm_lsb->chip);
	if (ret < 0) {
		dev_err(&pdev->dev, "pwmchip_add failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static int tegra_pwm_led_soft_blink_remove(struct platform_device *pdev)
{
	struct tegra_pwm_led_soft_blink *pwm_lsb = platform_get_drvdata(pdev);

	if (WARN_ON(!pwm_lsb))
		return -ENODEV;

	return pwmchip_remove(&pwm_lsb->chip);
}

static const struct of_device_id tegra_pwm_soft_blink_match[] = {
	{ .compatible = "nvidia,tegra210b01-pwm-led-soft-blink",},
	{ }
};

static struct platform_driver tegra_pwm_led_soft_blink_driver = {
	.driver = {
		.name = "tegra210b01-pwm-led-soft-blink",
		.of_match_table = tegra_pwm_soft_blink_match,
	},
	.probe = tegra_pwm_led_soft_blink_probe,
	.remove = tegra_pwm_led_soft_blink_remove,
};

module_platform_driver(tegra_pwm_led_soft_blink_driver);

MODULE_DESCRIPTION("PWM based NVIDIA Tegra led soft blink driver");
MODULE_AUTHOR("Venkat Reddy Talla <vreddytalla@nvidia.com>");
MODULE_LICENSE("GPL v2");
