/*
 * Copyright (c) 2012-2017, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/clk-provider.h>
#include <linux/clk.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <soc/tegra/tegra-dvfs.h>

#include "clk.h"

static u8 clk_periph_get_parent(struct clk_hw *hw)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *mux_ops = periph->mux_ops;
	struct clk_hw *mux_hw = &periph->mux.hw;

	__clk_hw_set_clk(mux_hw, hw);

	return mux_ops->get_parent(mux_hw);
}

static int clk_periph_set_parent(struct clk_hw *hw, u8 index)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *mux_ops = periph->mux_ops;
	struct clk_hw *mux_hw = &periph->mux.hw;

	__clk_hw_set_clk(mux_hw, hw);

	return mux_ops->set_parent(mux_hw, index);
}

static unsigned long clk_periph_recalc_rate(struct clk_hw *hw,
					    unsigned long parent_rate)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *div_ops = periph->div_ops;
	struct clk_hw *div_hw = &periph->divider.hw;

	__clk_hw_set_clk(div_hw, hw);

	return div_ops->recalc_rate(div_hw, parent_rate);
}

static int clk_periph_determine_rate(struct clk_hw *hw,
				     struct clk_rate_request *req)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *div_ops = periph->div_ops;
	struct clk_hw *div_hw = &periph->divider.hw;

	__clk_hw_set_clk(div_hw, hw);

	return div_ops->determine_rate(div_hw, req);
}

static int set_request_parent(struct clk_hw *hw, struct clk_rate_request *req,
			      u8 parent_idx)
{
	struct clk_hw *parent_hw;
	unsigned long parent_rate;

	parent_hw = clk_hw_get_parent_by_index(hw, parent_idx);
	if (!parent_hw)
		return -EINVAL;

	parent_rate = clk_hw_get_rate(parent_hw);
	if (!parent_rate)
		return -EINVAL;

	req->best_parent_hw = parent_hw;
	req->best_parent_rate = parent_rate;
	return 0;
}

static int clk_periph_determine_reparent_rate(struct clk_hw *hw,
					      struct clk_rate_request *req)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *div_ops = periph->div_ops;
	struct clk_hw *div_hw = &periph->divider.hw;

	struct clk_rate_request low_rate_req = { };
	unsigned long rate = req->rate;

	__clk_hw_set_clk(div_hw, hw);

	/*
	 * First try to use low-rate parent. Keep it if derived rate is below
	 * low-rate threshold or matches target exactly.
	 */
	if (set_request_parent(hw, req, periph->rpolicy.low_rate_parent_idx))
		return -EINVAL;

	if (div_ops->determine_rate(div_hw, req))
		return -EINVAL;

	if (req->rate == rate || req->rate <= periph->rpolicy.threshold)
		return 0;

	low_rate_req = *req;
	req->rate = rate;	/* restore target */

	/*
	 * Now try to use high-rate parent. Keep it if derived rate is below
	 * rate reached from low-rate parent or low-rate parent is below target.
	 * Otherwise fall back on low-rate parent. This selection policy assumes
	 * that divider output rate is rounded up (divider rounded down), and
	 * best parent provides lowest rate above the target.
	 */
	if (set_request_parent(hw, req, periph->rpolicy.high_rate_parent_idx))
		return -EINVAL;

	if (div_ops->determine_rate(div_hw, req))
		return -EINVAL;

	if (low_rate_req.rate < rate || req->rate < low_rate_req.rate)
		return 0;

	*req = low_rate_req;
	return 0;
}

static int clk_periph_set_rate(struct clk_hw *hw, unsigned long rate,
			       unsigned long parent_rate)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *div_ops = periph->div_ops;
	struct clk_hw *div_hw = &periph->divider.hw;

	__clk_hw_set_clk(div_hw, hw);

	return div_ops->set_rate(div_hw, rate, parent_rate);
}

static int clk_periph_set_rate_and_parent(struct clk_hw *hw, unsigned long rate,
					  unsigned long parent_rate, u8 index)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *mux_ops = periph->mux_ops;
	struct clk_hw *mux_hw = &periph->mux.hw;
	const struct clk_ops *div_ops = periph->div_ops;
	struct clk_hw *div_hw = &periph->divider.hw;
	struct clk_hw *old_phw;
	unsigned long old_prate;
	int ret;

	__clk_hw_set_clk(mux_hw, hw);
	__clk_hw_set_clk(div_hw, hw);

	old_phw = clk_hw_get_parent_by_index(hw, mux_ops->get_parent(mux_hw));
	if (!old_phw)
		return -EINVAL;

	old_prate = clk_hw_get_rate(old_phw);
	if (!old_prate)
		return -EINVAL;

	if (old_prate < parent_rate) {
		ret = div_ops->set_rate(div_hw, rate * old_prate / parent_rate,
					old_prate);
		if (ret)
			return ret;
	}

	ret = mux_ops->set_parent(mux_hw, index);
	if (ret)
		return ret;

	return div_ops->set_rate(div_hw, rate, parent_rate);
}

static int clk_periph_is_enabled(struct clk_hw *hw)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *gate_ops = periph->gate_ops;
	struct clk_hw *gate_hw = &periph->gate.hw;

	__clk_hw_set_clk(gate_hw, hw);

	return gate_ops->is_enabled(gate_hw);
}

static int clk_periph_enable(struct clk_hw *hw)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *gate_ops = periph->gate_ops;
	struct clk_hw *gate_hw = &periph->gate.hw;

	__clk_hw_set_clk(gate_hw, hw);

	return gate_ops->enable(gate_hw);
}

static void clk_periph_disable(struct clk_hw *hw)
{
	struct tegra_clk_periph *periph = to_clk_periph(hw);
	const struct clk_ops *gate_ops = periph->gate_ops;
	struct clk_hw *gate_hw = &periph->gate.hw;

	gate_ops->disable(gate_hw);
}

static int clk_periph_prepare(struct clk_hw *hw)
{
	return tegra_dvfs_set_rate(hw->clk, clk_hw_get_rate(hw));
}

static void clk_periph_unprepare(struct clk_hw *hw)
{
	tegra_dvfs_set_rate(hw->clk, 0);
}

const struct clk_ops tegra_clk_periph_ops = {
	.get_parent = clk_periph_get_parent,
	.set_parent = clk_periph_set_parent,
	.recalc_rate = clk_periph_recalc_rate,
	.determine_rate = clk_periph_determine_rate,
	.set_rate = clk_periph_set_rate,
	.is_enabled = clk_periph_is_enabled,
	.enable = clk_periph_enable,
	.disable = clk_periph_disable,
	.prepare = clk_periph_prepare,
	.unprepare = clk_periph_unprepare,
};

static const struct clk_ops tegra_clk_periph_nodiv_ops = {
	.get_parent = clk_periph_get_parent,
	.set_parent = clk_periph_set_parent,
	.is_enabled = clk_periph_is_enabled,
	.enable = clk_periph_enable,
	.disable = clk_periph_disable,
	.prepare = clk_periph_prepare,
	.unprepare = clk_periph_unprepare,
};

static const struct clk_ops tegra_clk_periph_no_gate_ops = {
	.get_parent = clk_periph_get_parent,
	.set_parent = clk_periph_set_parent,
	.recalc_rate = clk_periph_recalc_rate,
	.determine_rate = clk_periph_determine_rate,
	.set_rate = clk_periph_set_rate,
	.prepare = clk_periph_prepare,
	.unprepare = clk_periph_unprepare,
};

const struct clk_ops tegra_clk_periph_reparent_ops = {
	.get_parent = clk_periph_get_parent,
	.set_parent = clk_periph_set_parent,
	.recalc_rate = clk_periph_recalc_rate,
	.determine_rate = clk_periph_determine_reparent_rate,
	.set_rate = clk_periph_set_rate,
	.set_rate_and_parent = clk_periph_set_rate_and_parent,
	.is_enabled = clk_periph_is_enabled,
	.enable = clk_periph_enable,
	.disable = clk_periph_disable,
	.prepare = clk_periph_prepare,
	.unprepare = clk_periph_unprepare,
};

static struct clk *_tegra_clk_register_periph(const char *name,
			const char * const *parent_names, int num_parents,
			struct tegra_clk_periph *periph,
			void __iomem *clk_base, u32 offset,
			unsigned long flags)
{
	struct clk *clk;
	struct clk_init_data init;
	const struct tegra_clk_periph_regs *bank;
	bool div = !(periph->gate.flags & TEGRA_PERIPH_NO_DIV);

	if (periph->gate.flags & TEGRA_PERIPH_NO_DIV) {
		flags |= CLK_SET_RATE_PARENT;
		init.ops = &tegra_clk_periph_nodiv_ops;
	} else if (periph->gate.flags & TEGRA_PERIPH_NO_GATE) {
		init.ops = &tegra_clk_periph_no_gate_ops;
	} else if (periph->rpolicy.threshold) {
		if (periph->divider.flags & TEGRA_DIVIDER_ROUND_UP) {
			WARN(1, "%s: %s: No reparenting with div round up\n",
			     __func__, name);
			init.ops = &tegra_clk_periph_ops;
		} else {
			init.ops = &tegra_clk_periph_reparent_ops;
		}
	} else
		init.ops = &tegra_clk_periph_ops;

	init.name = name;
	init.flags = flags;
	init.parent_names = parent_names;
	init.num_parents = num_parents;

	bank = get_reg_bank(periph->gate.clk_num);
	if (!bank)
		return ERR_PTR(-EINVAL);

	/* Data in .init is copied by clk_register(), so stack variable OK */
	periph->hw.init = &init;
	periph->magic = TEGRA_CLK_PERIPH_MAGIC;
	periph->mux.reg = clk_base + offset;
	periph->divider.reg = div ? (clk_base + offset) : NULL;
	periph->gate.clk_base = clk_base;
	periph->gate.regs = bank;
	periph->gate.enable_refcnt = periph_clk_enb_refcnt;

	clk = clk_register(NULL, &periph->hw);
	if (IS_ERR(clk))
		return clk;

	periph->mux.hw.clk = clk;
	periph->divider.hw.clk = div ? clk : NULL;
	periph->gate.hw.clk = clk;

	return clk;
}

struct clk *tegra_clk_register_periph(const char *name,
		const char * const *parent_names, int num_parents,
		struct tegra_clk_periph *periph, void __iomem *clk_base,
		u32 offset, unsigned long flags)
{
	return _tegra_clk_register_periph(name, parent_names, num_parents,
			periph, clk_base, offset, flags);
}

struct clk *tegra_clk_register_periph_nodiv(const char *name,
		const char * const *parent_names, int num_parents,
		struct tegra_clk_periph *periph, void __iomem *clk_base,
		u32 offset)
{
	periph->gate.flags |= TEGRA_PERIPH_NO_DIV;
	return _tegra_clk_register_periph(name, parent_names, num_parents,
			periph, clk_base, offset, CLK_SET_RATE_PARENT);
}
