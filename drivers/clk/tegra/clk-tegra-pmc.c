/*
 * Copyright (c) 2012, 2013, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/io.h>
#include <linux/clk-provider.h>
#include <linux/clkdev.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/clk/tegra.h>
#include <soc/tegra/pmc.h>

#include "clk.h"
#include "clk-id.h"

#define PMC_CLK_OUT_CNTRL 0x1a8
#define PMC_DPD_PADS_ORIDE 0x1c
#define PMC_DPD_PADS_ORIDE_BLINK_ENB 20
#define PMC_CTRL 0
#define PMC_CTRL_BLINK_ENB 7
#define PMC_BLINK_TIMER 0x40

struct pmc_clk_mux {
	struct clk_hw	hw;
	unsigned long	offs;
	u32		mask;
	u32		shift;
	spinlock_t	*lock;
};
#define to_pmc_clk_mux(_hw) container_of(_hw, struct pmc_clk_mux, hw)

struct pmc_clk_gate {
	struct clk_hw	hw;
	unsigned long	offs;
	u32		shift;
	spinlock_t	*lock;
};
#define to_pmc_clk_gate(_hw) container_of(_hw, struct pmc_clk_gate, hw)

struct pmc_clk_init_data {
	char *mux_name;
	char *gate_name;
	const char **parents;
	int num_parents;
	int mux_id;
	int gate_id;
	char *dev_name;
	u8 mux_shift;
	u8 gate_shift;
	struct pmc_clk_mux mux;
	struct pmc_clk_gate gate;
};

#define PMC_CLK(_num, _mux_shift, _gate_shift)\
	{\
		.mux_name = "clk_out_" #_num "_mux",\
		.gate_name = "clk_out_" #_num,\
		.parents = clk_out ##_num ##_parents,\
		.num_parents = ARRAY_SIZE(clk_out ##_num ##_parents),\
		.mux_id = tegra_clk_clk_out_ ##_num ##_mux,\
		.gate_id = tegra_clk_clk_out_ ##_num,\
		.dev_name = "extern" #_num,\
		.mux_shift = _mux_shift,\
		.gate_shift = _gate_shift,\
	}

static DEFINE_SPINLOCK(clk_out_lock);

static const char *clk_out1_parents[] = { "osc", "osc_div2",
	"osc_div4", "extern1",
};

static const char *clk_out2_parents[] = { "osc", "osc_div2",
	"osc_div4", "extern2",
};

static const char *clk_out3_parents[] = { "osc", "osc_div2",
	"osc_div4", "extern3",
};

static struct pmc_clk_init_data pmc_clks[] = {
	PMC_CLK(1, 6, 2),
	PMC_CLK(2, 14, 10),
	PMC_CLK(3, 22, 18),
};

static struct pmc_clk_gate blink_override;
static struct pmc_clk_gate blink;

static void pmc_clk_fence_udelay(u32 offs)
{
	tegra_pmc_readl(offs);	/* read fence */
	udelay(2);		/* tegra clk propagation delay 2 us */
}

static u8 pmc_clk_mux_get_parent(struct clk_hw *hw)
{
	struct pmc_clk_mux *mux = to_pmc_clk_mux(hw);
	int num_parents = clk_hw_get_num_parents(hw);
	u32 val;

	val = tegra_pmc_readl(mux->offs) >> mux->shift;
	val &= mux->mask;

	if (val >= num_parents)
		return -EINVAL;

	return val;
}

static int pmc_clk_mux_set_parent(struct clk_hw *hw, u8 index)
{
	struct pmc_clk_mux *mux = to_pmc_clk_mux(hw);
	u32 val;
	unsigned long flags = 0;

	spin_lock_irqsave(mux->lock, flags);

	val = tegra_pmc_readl(mux->offs);
	val &= ~(mux->mask << mux->shift);
	val |= index << mux->shift;
	tegra_pmc_writel_relaxed(val, mux->offs);
	pmc_clk_fence_udelay(mux->offs);

	spin_unlock_irqrestore(mux->lock, flags);

	return 0;
}

static const struct clk_ops pmc_clk_mux_ops = {
	.get_parent = pmc_clk_mux_get_parent,
	.set_parent = pmc_clk_mux_set_parent,
	.determine_rate = __clk_mux_determine_rate,
};

static struct clk *tegra_pmc_clk_mux_register(const char *name,
		const char * const *parent_names, int num_parents,
		unsigned long flags, struct pmc_clk_mux *mux,
		unsigned long offset, u32 shift, u32 mask, spinlock_t *lock)
{
	struct clk_init_data init;

	init.name = name;
	init.ops = &pmc_clk_mux_ops;
	init.parent_names = parent_names;
	init.num_parents = num_parents;
	init.flags = flags;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	mux->hw.init = &init;
	mux->offs = offset;
	mux->mask = mask;
	mux->shift = shift;
	mux->lock = lock;

	return clk_register(NULL, &mux->hw);
}

static int pmc_clk_is_enabled(struct clk_hw *hw)
{
	struct pmc_clk_gate *gate = to_pmc_clk_gate(hw);

	return tegra_pmc_readl(gate->offs) & BIT(gate->shift) ? 1 : 0;
}

static void pmc_clk_set_state(struct clk_hw *hw, int state)
{
	struct pmc_clk_gate *gate = to_pmc_clk_gate(hw);
	u32 val;
	unsigned long flags = 0;

	spin_lock_irqsave(gate->lock, flags);

	val = tegra_pmc_readl(gate->offs);
	val = state ? (val | BIT(gate->shift)) : (val & ~BIT(gate->shift));
	tegra_pmc_writel_relaxed(val, gate->offs);
	pmc_clk_fence_udelay(gate->offs);

	spin_unlock_irqrestore(gate->lock, flags);
}
static int pmc_clk_enable(struct clk_hw *hw)
{
	pmc_clk_set_state(hw, 1);

	return 0;
}

static void pmc_clk_disable(struct clk_hw *hw)
{
	pmc_clk_set_state(hw, 0);
}

static const struct clk_ops pmc_clk_gate_ops = {
	.is_enabled = pmc_clk_is_enabled,
	.enable = pmc_clk_enable,
	.disable = pmc_clk_disable,
};

static struct clk *tegra_pmc_clk_gate_register(const char *name,
		const char *parent_name, unsigned long flags,
		struct pmc_clk_gate *gate, unsigned long offset, u32 shift,
		spinlock_t *lock)
{
	struct clk_init_data init;

	init.name = name;
	init.ops = &pmc_clk_gate_ops;
	init.parent_names = &parent_name;
	init.num_parents = 1;
	init.flags = flags;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	gate->hw.init = &init;
	gate->offs = offset;
	gate->shift = shift;
	gate->lock = lock;

	return clk_register(NULL, &gate->hw);
}

void __init tegra_pmc_clk_init(void __iomem *pmc_base,
				struct tegra_clk *tegra_clks)
{
	struct clk *clk;
	struct clk **dt_clk;
	int i;

	for (i = 0; i < ARRAY_SIZE(pmc_clks); i++) {
		struct pmc_clk_init_data *data;

		data = pmc_clks + i;

		dt_clk = tegra_lookup_dt_id(data->mux_id, tegra_clks);
		if (!dt_clk)
			continue;

		clk = tegra_pmc_clk_mux_register(data->mux_name, data->parents,
				data->num_parents,
				CLK_SET_RATE_NO_REPARENT | CLK_SET_RATE_PARENT,
				&data->mux, PMC_CLK_OUT_CNTRL, data->mux_shift,
				0x7, &clk_out_lock);
		*dt_clk = clk;


		dt_clk = tegra_lookup_dt_id(data->gate_id, tegra_clks);
		if (!dt_clk)
			continue;

		clk = tegra_pmc_clk_gate_register(data->gate_name,
				data->mux_name, CLK_SET_RATE_PARENT,
				&data->gate, PMC_CLK_OUT_CNTRL,
				data->gate_shift, &clk_out_lock);
		*dt_clk = clk;
		clk_register_clkdev(clk, data->dev_name, data->gate_name);
	}

	/* blink */
	tegra_pmc_writel_relaxed(0, PMC_BLINK_TIMER);
	clk = tegra_pmc_clk_gate_register("blink_override", "clk_32k", 0,
				&blink_override, PMC_DPD_PADS_ORIDE,
				PMC_DPD_PADS_ORIDE_BLINK_ENB, NULL);

	dt_clk = tegra_lookup_dt_id(tegra_clk_blink, tegra_clks);
	if (!dt_clk)
		return;

	clk = tegra_pmc_clk_gate_register("blink", "blink_override", 0,
				&blink, PMC_CTRL, PMC_CTRL_BLINK_ENB, NULL);
	clk_register_clkdev(clk, "blink", NULL);
	*dt_clk = clk;
}

