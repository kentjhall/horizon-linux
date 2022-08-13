/*
 * Copyright (c) 2015-2021, NVIDIA CORPORATION.  All rights reserved.
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
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/clk.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/pwm.h>
#include <linux/slab.h>
#include <linux/reset.h>
#include <linux/of_device.h>
#include <linux/io.h>

/* Since oscillator clock (38.4MHz) serves as a clock source for
 * the tach input controller, 1.0105263MHz (i.e. 38.4/38) has to be
 * used as a clock value in the RPM calculations
 */
#define TACH_COUNTER_CLK				1010526

#define TACH_FAN_TACH0					0x0
#define TACH_FAN_TACH0_PERIOD_MASK			0x7FFFF
#define TACH_FAN_TACH0_PERIOD_MAX			0x7FFFF
#define TACH_FAN_TACH0_PERIOD_MIN			0x0
#define TACH_FAN_TACH0_WIN_LENGTH_SHIFT			25
#define TACH_FAN_TACH0_WIN_LENGTH_MASK			0x3
#define TACH_FAN_TACH0_OVERFLOW_MASK			BIT(24)

#define TACH_FAN_TACH1					0x4
#define TACH_FAN_TACH1_HI_MASK				0x7FFFF

struct pwm_tegra_tach {
	struct device		*dev;
	void __iomem		*regs;
	struct clk		*clk;
	struct reset_control	*rst;
	unsigned int		pulse_per_rev;
	unsigned int		capture_win_len;
	struct pwm_chip		chip;
};

static struct pwm_tegra_tach *to_tegra_pwm_chip(struct pwm_chip *chip)
{
	return container_of(chip, struct pwm_tegra_tach, chip);
}

static u32 tachometer_readl(struct pwm_tegra_tach *ptt, unsigned long reg)
{
	return readl(ptt->regs + reg);
}

static inline void tachometer_writel(struct pwm_tegra_tach *ptt, u32 val,
				     unsigned long reg)
{
	writel(val, ptt->regs + reg);
}

static int tegra_pwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
			    int duty_ns, int period_ns)
{
	/* Dummy implementation for avoiding error from core */
	return 0;
}

static int tegra_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	/* Dummy implementation for avoiding error from core */
	return 0;
}

static void tegra_pwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	/* Dummy implementation for avoiding error from core */
}

static int pwm_tegra_tacho_set_wlen(struct pwm_tegra_tach *ptt,
					int window_length)
{
	u32 tach0, wlen;

	wlen = ffs(window_length) - 1;
	tach0 = tachometer_readl(ptt, TACH_FAN_TACH0);
	tach0 &= ~(TACH_FAN_TACH0_WIN_LENGTH_MASK <<
			TACH_FAN_TACH0_WIN_LENGTH_SHIFT);
	tach0 |= wlen << TACH_FAN_TACH0_WIN_LENGTH_SHIFT;
	tachometer_writel(ptt, tach0, TACH_FAN_TACH0);

	return 0;
}

static int pwm_tegra_tacho_set_capture_wlen(struct pwm_chip *chip,
					    struct pwm_device *pwm,
					    int window_length)
{
	struct pwm_tegra_tach *ptt = to_tegra_pwm_chip(chip);

	if (hweight8(window_length) != 1) {
		dev_err(ptt->dev,
			"Invalid window length,valid values {1, 2, 4 or 8}\n");
		return -EINVAL;
	}

	if (ptt->pulse_per_rev > window_length) {
		dev_err(ptt->dev, "Window length must be pulse per rev (%d)\n",
			ptt->pulse_per_rev);
		return -EINVAL;
	}

	pwm_tegra_tacho_set_wlen(ptt, window_length);

	ptt->capture_win_len = window_length;

	return 0;
}

static int pwm_tegra_tacho_capture(struct pwm_chip *chip,
				   struct pwm_device *pwm,
				   struct pwm_capture *result,
				   unsigned long timeout)
{
	struct pwm_tegra_tach *ptt = to_tegra_pwm_chip(chip);
	unsigned long period;
	u32 tach0;

	tach0 = tachometer_readl(ptt, TACH_FAN_TACH1);
	result->duty_cycle = (tach0 & TACH_FAN_TACH1_HI_MASK);

	tach0 = tachometer_readl(ptt, TACH_FAN_TACH0);
	if (tach0 & TACH_FAN_TACH0_OVERFLOW_MASK) {
		/* Fan is stalled, clear overflow state by writing 1 */
		dev_info(ptt->dev, "Tachometer Overflow is detected\n");
		tachometer_writel(ptt, tach0, TACH_FAN_TACH0);
	}

	period = tach0 & TACH_FAN_TACH0_PERIOD_MASK;
	if ((period == TACH_FAN_TACH0_PERIOD_MIN) ||
	    (period == TACH_FAN_TACH0_PERIOD_MAX)) {
		dev_dbg(ptt->dev, "Period set to min/max (0x%lx), Invalid RPM\n",
			period);
		result->period = 0;
		result->duty_cycle = 0;
		return 0;
	}

	period = period + 1; /* Bug 200046190 */

	period = DIV_ROUND_CLOSEST_ULL(period * ptt->pulse_per_rev * 1000000ULL,
				       ptt->capture_win_len * TACH_COUNTER_CLK);

	/*
	 * period & duty cycles are in units of micro seconds. Hence,
	 * convert them into nano seconds and store it in result.
	 */
	result->period = period * 1000;
	result->duty_cycle = result->duty_cycle * 1000;

	return 0;
}

static const struct pwm_ops pwm_tegra_tach_ops = {
	.config = tegra_pwm_config,
	.enable = tegra_pwm_enable,
	.disable = tegra_pwm_disable,
	.capture = pwm_tegra_tacho_capture,
	.set_capture_window_length = pwm_tegra_tacho_set_capture_wlen,
	.owner = THIS_MODULE,
};

static void pwm_tegra_tach_read_platform_data(struct pwm_tegra_tach *ptt)
{
	struct device_node *np = ptt->dev->of_node;
	u32 pval;
	int ret;

	ret = of_property_read_u32(np, "pulse-per-rev", &pval);
	if (!ret)
		ptt->pulse_per_rev = pval;

	ret = of_property_read_u32(np, "capture-window-length", &pval);
	if (!ret)
		ptt->capture_win_len = pval;
}

static int pwm_tegra_tach_probe(struct platform_device *pdev)
{
	struct pwm_tegra_tach *ptt;
	struct pwm_device *pwm;
	struct resource *r;
	int ret;

	ptt = devm_kzalloc(&pdev->dev, sizeof(*ptt), GFP_KERNEL);
	if (!ptt)
		return -ENOMEM;

	ptt->dev = &pdev->dev;

	pwm_tegra_tach_read_platform_data(ptt);

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ptt->regs = devm_ioremap_resource(&pdev->dev, r);
	if (IS_ERR(ptt->regs))
		return PTR_ERR(ptt->regs);

	platform_set_drvdata(pdev, ptt);

	ptt->clk = devm_clk_get(&pdev->dev, "tach");
	if (IS_ERR(ptt->clk)) {
		dev_err(&pdev->dev, "Tachometer clock get failed\n");
		return PTR_ERR(ptt->clk);
	}

	ptt->rst = devm_reset_control_get(&pdev->dev, "tach");
	if (IS_ERR(ptt->rst)) {
		ret = PTR_ERR(ptt->rst);
		dev_err(&pdev->dev, "Reset control is not found: %d\n", ret);
		return ret;
	}

	ret = clk_prepare_enable(ptt->clk);
	if (ret) {
		dev_err(&pdev->dev, "Failed to prepare clock: %d\n", ret);
		return ret;
	}

	ret = clk_set_rate(ptt->clk, TACH_COUNTER_CLK);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to set clock rate %d: %d\n",
			TACH_COUNTER_CLK, ret);
		goto clk_unprep;
	}

	reset_control_reset(ptt->rst);

	ptt->chip.dev = &pdev->dev;
	ptt->chip.ops = &pwm_tegra_tach_ops;
	ptt->chip.base = -1;
	ptt->chip.npwm = 1;

	ret = pwmchip_add(&ptt->chip);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to add tachometer PWM: %d\n", ret);
		goto reset_assert;
	}

	/* As per spec, the WIN_LENGTH value should be greater than or equal to
	 * Pulse Per Revolution Value to measure the accurate time period values
	 */

	pwm = &ptt->chip.pwms[0];
	if (ptt->pulse_per_rev > ptt->capture_win_len)
		ptt->capture_win_len = ptt->pulse_per_rev;

	ret = pwm_tegra_tacho_set_capture_wlen(&ptt->chip, pwm, ptt->capture_win_len);
	if (ret < 0) {
		dev_err(ptt->dev, "Failed to set window length: %d\n", ret);
		goto pwm_remove;
	}

	return 0;

pwm_remove:
	pwmchip_remove(&ptt->chip);

reset_assert:
	reset_control_assert(ptt->rst);

clk_unprep:
	clk_disable_unprepare(ptt->clk);

	return ret;
}

static int pwm_tegra_tach_remove(struct platform_device *pdev)
{
	struct pwm_tegra_tach *ptt = platform_get_drvdata(pdev);

	if (WARN_ON(!ptt))
		return -ENODEV;

	reset_control_assert(ptt->rst);

	clk_disable_unprepare(ptt->clk);

	return pwmchip_remove(&ptt->chip);
}

static int pwm_tegra_tach_suspend(struct device *dev)
{
	return 0;
}

static int pwm_tegra_tach_resume(struct device *dev)
{
	struct pwm_tegra_tach *ptt = dev_get_drvdata(dev);

	pwm_tegra_tacho_set_wlen(ptt, ptt->capture_win_len);

	return 0;
}

static const struct dev_pm_ops pwm_tegra_tach_pm_ops = {
	.suspend        = pwm_tegra_tach_suspend,
	.resume         = pwm_tegra_tach_resume,
};

static const struct of_device_id pwm_tegra_tach_of_match[] = {
	{ .compatible = "nvidia,pwm-tegra186-tachometer" },
	{ .compatible = "nvidia,pwm-tegra194-tachometer" },
	{}
};
MODULE_DEVICE_TABLE(of, tegra_tach_of_match);

static struct platform_driver tegra_tach_driver = {
	.driver = {
		.name = "pwm-tegra-tachometer",
		.of_match_table = pwm_tegra_tach_of_match,
		.pm = &pwm_tegra_tach_pm_ops,
	},
	.probe = pwm_tegra_tach_probe,
	.remove = pwm_tegra_tach_remove,
};

module_platform_driver(tegra_tach_driver);

MODULE_DESCRIPTION("PWM based NVIDIA Tegra Tachometer driver");
MODULE_AUTHOR("Laxman Dewangan <ldewangan@nvidia.com>");
MODULE_AUTHOR("R Raj Kumar <rrajk@nvidia.com>");
MODULE_LICENSE("GPL v2");
