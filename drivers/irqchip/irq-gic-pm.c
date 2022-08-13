/*
 * Copyright (C) 2016-2019 NVIDIA CORPORATION, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/module.h>
#include <linux/clk.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/irqchip/arm-gic.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/irqchip/tegra-agic.h>

struct gic_clk_data {
	unsigned int num_clocks;
	const char *const *clocks;
};

struct gic_chip_pm {
	struct gic_chip_data *gic;
	const struct gic_clk_data *data;
	struct clk **clk;
};

static struct gic_chip_data *tegra_agic;

bool tegra_agic_irq_is_pending(int irq)
{
	if (WARN_ON(!tegra_agic))
		return false;

	return gic_irq_is_pending(tegra_agic, irq);
}
EXPORT_SYMBOL_GPL(tegra_agic_irq_is_pending);

void tegra_agic_clear_pending(int irq)
{
	if (WARN_ON(!tegra_agic))
		return;

	return gic_clear_pending(tegra_agic, irq);
}
EXPORT_SYMBOL_GPL(tegra_agic_clear_pending);

bool tegra_agic_irq_is_active(int irq)
{
	if (WARN_ON(!tegra_agic))
		return false;

	return gic_irq_is_active(tegra_agic, irq);
}
EXPORT_SYMBOL_GPL(tegra_agic_irq_is_active);

void tegra_agic_clear_active(int irq)
{
	if (WARN_ON(!tegra_agic))
		return;

	return gic_clear_active(tegra_agic, irq);
}
EXPORT_SYMBOL_GPL(tegra_agic_clear_active);

int tegra_agic_route_interrupt(int irq, enum tegra_agic_cpu cpu)
{
	if (WARN_ON(!tegra_agic))
		return -EINVAL;

	return gic_route_interrupt(tegra_agic, irq, cpu);
}
EXPORT_SYMBOL_GPL(tegra_agic_route_interrupt);

static int gic_runtime_resume(struct device *dev)
{
	struct gic_chip_pm *gic_chip_pm = dev_get_drvdata(dev);
	struct gic_chip_data *gic = gic_chip_pm->gic;
	const struct gic_clk_data *data = gic_chip_pm->data;
	const struct gic_data *cdata;
	int ret, i;

	cdata = of_device_get_match_data(dev);
	if (cdata && !cdata->is_hv) {
		for (i = 0; i < data->num_clocks; i++) {
			ret = clk_prepare_enable(gic_chip_pm->clk[i]);
			if (ret) {
				while (--i >= 0)
					clk_disable_unprepare
						(gic_chip_pm->clk[i]);

				dev_err(dev, " clk_enable failed: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * On the very first resume, the pointer to the driver data
	 * will be NULL and this is intentional, because we do not
	 * want to restore the GIC on the very first resume. So if
	 * the pointer is not valid just return.
	 */
	if (!gic)
		return 0;

	gic_dist_restore(gic);
	gic_cpu_restore(gic);

	return 0;
}

static int gic_runtime_suspend(struct device *dev)
{
	struct gic_chip_pm *gic_chip_pm = dev_get_drvdata(dev);
	struct gic_chip_data *gic = gic_chip_pm->gic;
	const struct gic_clk_data *data = gic_chip_pm->data;
	const struct gic_data *cdata;
	int i;

	gic_dist_save(gic);
	gic_cpu_save(gic);
	cdata = of_device_get_match_data(dev);

	if (cdata && !cdata->is_hv) {
		for (i = 0; i < data->num_clocks; i++)
			clk_disable_unprepare(gic_chip_pm->clk[i]);
	}
	return 0;
}

static int gic_get_clocks(struct device *dev, struct gic_chip_pm *gic_chip_pm)
{
	const struct gic_clk_data *data = gic_chip_pm->data;
	unsigned int i;

	if (!dev || !data)
		return -EINVAL;

	gic_chip_pm->clk = devm_kzalloc(dev, data->num_clocks *
				sizeof(struct clk *), GFP_KERNEL);
	if (!gic_chip_pm->clk)
		return -ENOMEM;

	for (i = 0; i < data->num_clocks; i++) {
		gic_chip_pm->clk[i] = devm_clk_get(dev, data->clocks[i]);
		if (IS_ERR(gic_chip_pm->clk[i])) {
			dev_err(dev, "failed to get clock %s\n",
				data->clocks[i]);
			return PTR_ERR(gic_chip_pm->clk[i]);
		}
	}

	return 0;
}

static int gic_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct gic_data *data;
	struct gic_chip_pm *gic_chip_pm;
	int ret, irq;

	data = of_device_get_match_data(&pdev->dev);
	if (!data) {
		dev_err(&pdev->dev, "no device match found\n");
		return -ENODEV;
	}

	gic_chip_pm = devm_kzalloc(dev, sizeof(*gic_chip_pm), GFP_KERNEL);
	if (!gic_chip_pm)
		return -ENOMEM;

	gic_chip_pm->data = data->clk_data;

	platform_set_drvdata(pdev, gic_chip_pm);

	irq = irq_of_parse_and_map(dev->of_node, 0);
	if (!irq) {
		dev_err(dev, "no parent interrupt found!\n");
		return -EINVAL;
	}

	if (!data->is_hv) {
		ret = gic_get_clocks(dev, gic_chip_pm);
		if (ret)
			goto irq_dispose;
	}

	pm_runtime_enable(dev);

	ret = pm_runtime_get_sync(dev);
	if (ret < 0)
		goto rpm_disable;

	ret = gic_of_init_child(dev, &gic_chip_pm->gic, irq);
	if (ret)
		goto rpm_put;

	pm_runtime_put(dev);

	if (of_device_is_compatible(dev->of_node, "nvidia,tegra210-agic") ||
	of_device_is_compatible(dev->of_node, "nvidia,tegra186-agic") ||
	of_device_is_compatible(dev->of_node, "nvidia,tegra186-agic-hv"))
		tegra_agic = gic_chip_pm->gic;

	dev_info(dev, "GIC IRQ controller registered\n");

	return 0;

rpm_put:
	pm_runtime_put_sync(dev);
rpm_disable:
	pm_runtime_disable(dev);
irq_dispose:
	irq_dispose_mapping(irq);

	return ret;
}

static const struct dev_pm_ops gic_pm_ops = {
	SET_RUNTIME_PM_OPS(gic_runtime_suspend,
			   gic_runtime_resume, NULL)
	SET_LATE_SYSTEM_SLEEP_PM_OPS(pm_runtime_force_suspend,
				     pm_runtime_force_resume)
};

static const char * const gic400_clocks[] = {
	"clk",
};

static const struct gic_clk_data gic400_data = {
	.num_clocks = ARRAY_SIZE(gic400_clocks),
	.clocks = gic400_clocks,
};

static const struct gic_data agic_t18x_hv_data = {
	.clk_data = &gic400_data,
	.supports_routing = true,
	.num_interfaces = MAX_AGIC_T18x_INTERFACES,
	.is_hv = true,
};

static const struct gic_data agic_t18x_data = {
	.clk_data = &gic400_data,
	.supports_routing = true,
	.num_interfaces = MAX_AGIC_T18x_INTERFACES,
	.is_hv = false,
};

static const struct gic_data agic_t21x_data = {
	.clk_data = &gic400_data,
	.supports_routing = true,
	.num_interfaces = MAX_AGIC_T210_INTERFACES,
	.is_hv = false,
};


static const struct of_device_id gic_match[] = {
	{ .compatible = "nvidia,tegra186-agic",	.data = &agic_t18x_data },
	{ .compatible = "nvidia,tegra210-agic",	.data = &agic_t21x_data },
	{ .compatible = "nvidia,tegra186-agic-hv", .data = &agic_t18x_hv_data },
	{},
};
MODULE_DEVICE_TABLE(of, gic_match);

static struct platform_driver gic_driver = {
	.probe		= gic_probe,
	.driver		= {
		.name	= "gic",
		.of_match_table	= gic_match,
		.pm	= &gic_pm_ops,
	}
};

builtin_platform_driver(gic_driver);
