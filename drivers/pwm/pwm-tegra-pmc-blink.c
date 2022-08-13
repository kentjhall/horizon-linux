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

struct tegra_blink_pwm_chip {
	struct pwm_chip chip;
	struct device *dev;
};

static int tegra_blink_pwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
				  int duty_ns, int period_ns)
{
	return tegra_pmc_pwm_blink_config(duty_ns, period_ns);
}

static int tegra_blink_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	return tegra_pmc_pwm_blink_enable();
}

static void tegra_blink_pwm_disable(struct pwm_chip *chip,
				    struct pwm_device *pwm)
{
	tegra_pmc_pwm_blink_disable();
}

static const struct pwm_ops tegra_blink_pwm_ops = {
	.config = tegra_blink_pwm_config,
	.enable = tegra_blink_pwm_enable,
	.disable = tegra_blink_pwm_disable,
	.owner = THIS_MODULE,
};

static int tegra_blink_pwm_probe(struct platform_device *pdev)
{
	struct tegra_blink_pwm_chip *pwm;
	int ret;

	pwm = devm_kzalloc(&pdev->dev, sizeof(*pwm), GFP_KERNEL);
	if (!pwm)
		return -ENOMEM;

	pwm->dev = &pdev->dev;
	platform_set_drvdata(pdev, pwm);

	pwm->chip.dev = &pdev->dev;
	pwm->chip.ops = &tegra_blink_pwm_ops;
	pwm->chip.base = -1;
	pwm->chip.npwm = 1;

	ret = pwmchip_add(&pwm->chip);
	if (ret < 0) {
		dev_err(&pdev->dev, "pwmchip_add() failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static int tegra_blink_pwm_remove(struct platform_device *pdev)
{
	struct tegra_blink_pwm_chip *pc = platform_get_drvdata(pdev);

	if (WARN_ON(!pc))
		return -ENODEV;

	return pwmchip_remove(&pc->chip);
}

static const struct of_device_id tegra_blink_pwm_of_match[] = {
	{ .compatible = "nvidia,tegra210-pmc-blink-pwm",},
	{ }
};

static struct platform_driver tegra_blink_pwm_driver = {
	.driver = {
		.name = "tegra210-blink-pwm",
		.of_match_table = tegra_blink_pwm_of_match,
	},
	.probe = tegra_blink_pwm_probe,
	.remove = tegra_blink_pwm_remove,
};

module_platform_driver(tegra_blink_pwm_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("NVIDIA Corporation");
