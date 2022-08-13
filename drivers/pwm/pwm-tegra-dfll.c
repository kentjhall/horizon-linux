/*
 * drivers/pwm/pwm-tegra-dfll.c
 *
 * Tegra DFLL PWM controller driver
 *
 * Copyright (c) 2016, NVIDIA Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pwm.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/pinctrl/consumer.h>
#include <soc/tegra/pwm-tegra-dfll.h>

/* DFLL_CTRL: DFLL control register */
#define DFLL_CTRL			0x00

/* DFLL_OUTPUT_CFG: closed loop mode control registers */
#define DFLL_OUTPUT_CFG			0x20
#define OUT_MASK			0x3f
#define DFLL_OUTPUT_CFG_PWM_DELTA	(0x1 << 7)
#define DFLL_OUTPUT_CFG_PWM_ENABLE	(0x1 << 6)
#define DFLL_OUTPUT_CFG_PWM_DIV_SHIFT	0
#define DFLL_OUTPUT_CFG_PWM_DIV_MASK	\
		(OUT_MASK << DFLL_OUTPUT_CFG_PWM_DIV_SHIFT)

/* MAX_DFLL_VOLTAGES: number of LUT entries in the DFLL IP block */
#define DFLL_MAX_VOLTAGES		33

#define DFLL_OF_PWM_PERIOD_CELL		1

/**
 * struct tegra_dfll_pwm_chip - DFLL PWM controller data
 * @pwm_pin: pinmux for PWM signals output
 * @pwm_enable_state: enabled states of pinmux for PWM signals output
 * @pwm_disable_state: disabled states of pinmux for PWM signals output
 * @mmio_base: mmio base for access DFLL registers
 * @ref_clk: referenced source clock
 * @pwm_rate: PWM rate for DFLL PWM output config register
 * @pwm_enable_gpio: PWM output buffer enable GPIO.
 */
struct tegra_dfll_pwm_chip {
	struct pwm_chip		chip;
	struct device		*dev;

	struct pinctrl		*pwm_pin;
	struct pinctrl_state	*pwm_enable_state;
	struct pinctrl_state	*pwm_disable_state;

	void __iomem		*mmio_base;
	struct clk		*ref_clk;

	unsigned long		ref_rate;
	unsigned long		pwm_rate;
	int			pwm_enable_gpio;
};

static struct tegra_dfll_pwm_chip *tdpc;

/*
 * Register accessors
 */
static inline u32 pwm_readl(u32 offs)
{
	return __raw_readl(tdpc->mmio_base + offs);
}

static inline void pwm_writel(u32 val, u32 offs)
{
	__raw_writel(val, tdpc->mmio_base + offs);
	pwm_readl(DFLL_CTRL);
}

static void dfll_pwm_enable(bool flag)
{
	u32 val;

	val = pwm_readl(DFLL_OUTPUT_CFG);

	if (flag)
		val |= DFLL_OUTPUT_CFG_PWM_ENABLE;
	else
		val &= ~DFLL_OUTPUT_CFG_PWM_ENABLE;

	pwm_writel(val, DFLL_OUTPUT_CFG);
}

/*
 * Calculate the DIV value and write into DFLL register
 */
static void dfll_pwm_init(void)
{
	u32 div, val;

	val = pwm_readl(DFLL_OUTPUT_CFG);

	div = DIV_ROUND_UP(tdpc->ref_rate, tdpc->pwm_rate);
	val |= (div << DFLL_OUTPUT_CFG_PWM_DIV_SHIFT) &
	      DFLL_OUTPUT_CFG_PWM_DIV_MASK;
	pwm_writel(val, DFLL_OUTPUT_CFG);
}

static int tegra_dfll_pwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
				int duty_ns, int period_ns)
{
	return 0;
}

static int tegra_dfll_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	dev_info(tdpc->dev, "DFLL_PWM regulator is available now\n");

	return 0;
}

static void tegra_dfll_pwm_disable(struct pwm_chip *chip,
				   struct pwm_device *pwm)
{
	dev_info(tdpc->dev, "DFLL_PWM is disabled\n");
}

/**
 * tegra_dfll_pwm_output_enable - enable DFLL PWM signals output
 *
 * Enable DFLL PWM signals output by changing related pinmux state
 */
int tegra_dfll_pwm_output_enable(void)
{
	int ret;

	dfll_pwm_init();
	dfll_pwm_enable(true);

	ret = pinctrl_select_state(tdpc->pwm_pin, tdpc->pwm_enable_state);
	if (ret < 0) {
		dev_err(tdpc->dev, "setting enable state failed\n");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(tegra_dfll_pwm_output_enable);

/**
 * tegra_dfll_pwm_output_disable - disable DFLL PWM signals output
 *
 * Disable DFLL PWM signals output by changing related pinmux state
 */
int tegra_dfll_pwm_output_disable(void)
{
	int ret;

	ret = pinctrl_select_state(tdpc->pwm_pin, tdpc->pwm_disable_state);
	if (ret < 0) {
		dev_err(tdpc->dev, "setting enable state failed\n");
		return -EINVAL;
	}
	dfll_pwm_enable(false);

	return 0;
}
EXPORT_SYMBOL(tegra_dfll_pwm_output_disable);

static const struct pwm_ops tegra_dfll_pwm_ops = {
	.config = tegra_dfll_pwm_config,
	.enable = tegra_dfll_pwm_enable,
	.disable = tegra_dfll_pwm_disable,
	.owner = THIS_MODULE,
};

/**
 * dt_parse_pwm_regulator - parse PWM regulator from device-tree
 *
 * Parse DFLL PWM controller client to get and calcluate initialized
 * DFLL PWM rate.
 */
static int dt_parse_pwm_regulator(void)
{
	struct device_node *r_dn =
		of_parse_phandle(tdpc->dev->of_node, "pwm-regulator", 0);
	struct of_phandle_args args;
	unsigned long val;
	int ret;

	/* pwm regulator device */
	if (!r_dn) {
		dev_err(tdpc->dev, "DT: missing pwm-regulator property\n");
		return -EINVAL;
	}

	ret = of_parse_phandle_with_args(r_dn, "pwms", "#pwm-cells", 0, &args);
	if (ret) {
		dev_err(tdpc->dev, "DT: failed to parse pwms property\n");
		return -EINVAL;
	}
	of_node_put(args.np);

	if (args.args_count <= DFLL_OF_PWM_PERIOD_CELL) {
		dev_err(tdpc->dev, "DT: low #pwm-cells %d\n", args.args_count);
		return -EINVAL;
	}

	/* convert pwm period in ns to DFLL pwm rate in Hz */
	val = args.args[DFLL_OF_PWM_PERIOD_CELL];
	val = (NSEC_PER_SEC / val) * (DFLL_MAX_VOLTAGES - 1);
	tdpc->pwm_rate = val;
	dev_info(tdpc->dev, "DFLL pwm-rate: %lu\n", val);

	return 0;
}

static int tegra_dfll_pwm_probe(struct platform_device *pdev)
{
	struct resource *res;
	int ret;

	tdpc = devm_kzalloc(&pdev->dev, sizeof(*tdpc), GFP_KERNEL);
	if (!tdpc)
		return -ENOMEM;

	tdpc->dev = &pdev->dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	tdpc->mmio_base = devm_ioremap_resource(tdpc->dev, res);
	if (IS_ERR(tdpc->mmio_base))
		return PTR_ERR(tdpc->mmio_base);

	platform_set_drvdata(pdev, tdpc);

	tdpc->chip.dev = tdpc->dev;
	tdpc->chip.ops = &tegra_dfll_pwm_ops;
	tdpc->chip.base = -1;
	tdpc->chip.npwm = 1;

	tdpc->pwm_enable_gpio = of_get_named_gpio(pdev->dev.of_node,
						  "pwm-enable-gpio", 0);
	if (tdpc->pwm_enable_gpio == -EPROBE_DEFER)
		return -EPROBE_DEFER;

	if (gpio_is_valid(tdpc->pwm_enable_gpio)) {
		ret = devm_gpio_request_one(&pdev->dev, tdpc->pwm_enable_gpio,
					    GPIOF_OUT_INIT_LOW | GPIOF_EXPORT,
					    "pwm-dfll-enable-gpio");
		if (ret < 0) {
			dev_err(&pdev->dev,
				"Failed to get PWM Enable GPIO %d: %d\n",
				tdpc->pwm_enable_gpio, ret);
			return ret;
		}
	}

	ret = pwmchip_add(&tdpc->chip);
	if (ret < 0) {
		dev_err(tdpc->dev, "pwmchip_add() failed: %d\n", ret);
		return ret;
	}

	tdpc->ref_clk = devm_clk_get(tdpc->dev, "ref");
	if (IS_ERR(tdpc->ref_clk)) {
		dev_err(tdpc->dev, "DT: missing ref clock\n");
		return PTR_ERR(tdpc->ref_clk);
	}

	tdpc->ref_rate = clk_get_rate(tdpc->ref_clk);

	tdpc->pwm_pin = devm_pinctrl_get(tdpc->dev);
	if (IS_ERR(tdpc->pwm_pin)) {
		dev_err(tdpc->dev, "DT: missing pinctrl device\n");
		return PTR_ERR(tdpc->pwm_pin);
	}

	tdpc->pwm_enable_state = pinctrl_lookup_state(tdpc->pwm_pin,
						"dvfs_pwm_enable");
	if (IS_ERR(tdpc->pwm_enable_state)) {
		dev_err(tdpc->dev, "DT: missing pwm enabled state\n");
		return PTR_ERR(tdpc->pwm_enable_state);
	}

	tdpc->pwm_disable_state = pinctrl_lookup_state(tdpc->pwm_pin,
						"dvfs_pwm_disable");
	if (IS_ERR(tdpc->pwm_disable_state)) {
		dev_err(tdpc->dev, "DT: missing pwm disabled state\n");
		return PTR_ERR(tdpc->pwm_disable_state);
	}

	ret = dt_parse_pwm_regulator();
	if (ret < 0) {
		dev_err(tdpc->dev, "failed to parse pwm regulator\n");
		return ret;
	}

	return 0;
}

static int tegra_dfll_pwm_remove(struct platform_device *pdev)
{
	return pwmchip_remove(&tdpc->chip);
}

static const struct of_device_id tegra_dfll_pwm_of_match[] = {
	{ .compatible = "nvidia,tegra210-dfll-pwm" },
	{ }
};

MODULE_DEVICE_TABLE(of, tegra_dfll_pwm_of_match);

static struct platform_driver tegra_dfll_pwm_driver = {
	.driver = {
		.name = "tegra-dfll-pwm",
		.of_match_table = tegra_dfll_pwm_of_match,
	},
	.probe = tegra_dfll_pwm_probe,
	.remove = tegra_dfll_pwm_remove,
};

module_platform_driver(tegra_dfll_pwm_driver);


static int __init tegra_dfll_pwm_buffer_init(void)
{
	/* Open external buffer via GPIO control (e.g., set GPIO high) */
	if (tdpc && gpio_is_valid(tdpc->pwm_enable_gpio))
		gpio_set_value_cansleep(tdpc->pwm_enable_gpio, 1);

	return 0;
}
late_initcall_sync(tegra_dfll_pwm_buffer_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NVIDIA Corporation");
MODULE_ALIAS("platform:tegra-dfll-pwm");
