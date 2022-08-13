/*
 * Copyright (c) 2016-2017, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/clk.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/clk-provider.h>

#include "clk.h"

#define SKIPPER_DIVISOR 256
#define SKIPPER_ENABLE BIT(31)

static int calc_skipper_mul(unsigned long rate, unsigned long prate)
{
	int mul;

	rate = rate * 256;
	mul = DIV_ROUND_UP(rate, prate);
	mul = max(mul, 1);
	mul = min(mul, 256);

	return mul;
}

static int clk_skipper_set_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long prate)
{
	struct tegra_clk_skipper *skipper = to_clk_skipper(hw);
	unsigned long flags = 0;
	int mul;
	u32 val;

	mul = calc_skipper_mul(rate, prate);

	if (skipper->lock)
		spin_lock_irqsave(skipper->lock, flags);

	val = readl_relaxed(skipper->reg);
	val &= ~(0xff << 8);
	val |= (mul - 1) << 8;
	if (mul == SKIPPER_DIVISOR)
		val &= ~SKIPPER_ENABLE;	/* disable for 1:1 */
	else
		val |= SKIPPER_ENABLE;	/* enable to skip */
	writel_relaxed(val, skipper->reg);

	if (skipper->lock)
		spin_unlock_irqrestore(skipper->lock, flags);

	return 0;
}

static int clk_skipper_determine_rate(struct clk_hw *hw,
				      struct clk_rate_request *req)
{
	int mul;

	req->rate = max(req->rate, req->min_rate);
	req->rate = min(req->rate, req->max_rate);

	mul = calc_skipper_mul(req->rate, req->best_parent_rate);

	req->rate = (req->best_parent_rate * mul) / SKIPPER_DIVISOR;

	return 0;
}

static unsigned long clk_skipper_recalc_rate(struct clk_hw *hw,
					     unsigned long prate)
{
	struct tegra_clk_skipper *skipper = to_clk_skipper(hw);
	u32 val;
	int mul;

	val = readl_relaxed(skipper->reg);
	mul = ((val >> 8) & 0xff) + 1;

	return (prate * mul) / SKIPPER_DIVISOR;
}

const struct clk_ops tegra_clk_skipper_ops = {
	.recalc_rate = clk_skipper_recalc_rate,
	.set_rate = clk_skipper_set_rate,
	.determine_rate = clk_skipper_determine_rate,
};

struct clk *tegra_clk_register_skipper(const char *name,
		const char *parent_name, void __iomem *reg,
		unsigned long flags, spinlock_t *lock)
{
	struct tegra_clk_skipper *skipper;
	struct clk *clk;
	struct clk_init_data init;
	u32 val;

	skipper = kzalloc(sizeof(*skipper), GFP_KERNEL);
	if (!skipper) {
		pr_err("%s: could not allocate skipper clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	init.name = name;
	init.ops = &tegra_clk_skipper_ops;
	init.flags = flags;
	init.parent_names = parent_name ? &parent_name : NULL;
	init.num_parents = parent_name ? 1 : 0;

	skipper->reg = reg;
	skipper->lock = lock;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	skipper->hw.init = &init;

	val = readl_relaxed(skipper->reg) & (~SKIPPER_ENABLE);
	val |= (SKIPPER_DIVISOR - 1) << 8;
	val |= SKIPPER_DIVISOR - 1;
	writel(val, skipper->reg);

	clk = clk_register(NULL, &skipper->hw);
	if (IS_ERR(clk))
		kfree(skipper);

	return clk;
}
