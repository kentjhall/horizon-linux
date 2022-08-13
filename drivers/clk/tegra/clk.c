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

#include <linux/clkdev.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/clk/tegra.h>
#include <linux/reset-controller.h>
#include <linux/seq_file.h>

#include <asm/uaccess.h>

#include <soc/tegra/fuse.h>

#include "clk.h"

#define CLK_OUT_ENB_L			0x010
#define CLK_OUT_ENB_H			0x014
#define CLK_OUT_ENB_U			0x018
#define CLK_OUT_ENB_V			0x360
#define CLK_OUT_ENB_W			0x364
#define CLK_OUT_ENB_X			0x280
#define CLK_OUT_ENB_Y			0x298
#define CLK_OUT_ENB_SET_L		0x320
#define CLK_OUT_ENB_CLR_L		0x324
#define CLK_OUT_ENB_SET_H		0x328
#define CLK_OUT_ENB_CLR_H		0x32c
#define CLK_OUT_ENB_SET_U		0x330
#define CLK_OUT_ENB_CLR_U		0x334
#define CLK_OUT_ENB_SET_V		0x440
#define CLK_OUT_ENB_CLR_V		0x444
#define CLK_OUT_ENB_SET_W		0x448
#define CLK_OUT_ENB_CLR_W		0x44c
#define CLK_OUT_ENB_SET_X		0x284
#define CLK_OUT_ENB_CLR_X		0x288
#define CLK_OUT_ENB_SET_Y		0x29c
#define CLK_OUT_ENB_CLR_Y		0x2a0

#define RST_DEVICES_L			0x004
#define RST_DEVICES_H			0x008
#define RST_DEVICES_U			0x00C
#define RST_DEVICES_V			0x358
#define RST_DEVICES_W			0x35C
#define RST_DEVICES_X			0x28C
#define RST_DEVICES_Y			0x2a4
#define RST_DEVICES_SET_L		0x300
#define RST_DEVICES_CLR_L		0x304
#define RST_DEVICES_SET_H		0x308
#define RST_DEVICES_CLR_H		0x30c
#define RST_DEVICES_SET_U		0x310
#define RST_DEVICES_CLR_U		0x314
#define RST_DEVICES_SET_V		0x430
#define RST_DEVICES_CLR_V		0x434
#define RST_DEVICES_SET_W		0x438
#define RST_DEVICES_CLR_W		0x43c
#define RST_DEVICES_SET_X		0x290
#define RST_DEVICES_CLR_X		0x294
#define RST_DEVICES_SET_Y		0x2a8
#define RST_DEVICES_CLR_Y		0x2ac

#define SUPER_CCLKG_DIVIDER		0x36c

/* Global data of Tegra CPU CAR ops */
static struct tegra_cpu_car_ops dummy_car_ops;
struct tegra_cpu_car_ops *tegra_cpu_car_ops = &dummy_car_ops;

int *periph_clk_enb_refcnt;
bool has_ccplex_therm_control;
bool div1_5_not_allowed;

static int periph_banks;
static struct clk **clks;
static int clk_num;
static struct clk_onecell_data clk_data;
static uint32_t *skipped_clkids;
static int skipped_len;

#ifdef CONFIG_PM_SLEEP
static u32 *periph_ctx;
#endif

/* Handlers for SoC-specific reset lines */
static int (*special_reset_assert)(unsigned long);
static int (*special_reset_deassert)(unsigned long);
static unsigned int num_special_reset;

static const struct tegra_clk_periph_regs periph_regs[] = {
	[0] = {
		.enb_reg = CLK_OUT_ENB_L,
		.enb_set_reg = CLK_OUT_ENB_SET_L,
		.enb_clr_reg = CLK_OUT_ENB_CLR_L,
		.rst_reg = RST_DEVICES_L,
		.rst_set_reg = RST_DEVICES_SET_L,
		.rst_clr_reg = RST_DEVICES_CLR_L,
	},
	[1] = {
		.enb_reg = CLK_OUT_ENB_H,
		.enb_set_reg = CLK_OUT_ENB_SET_H,
		.enb_clr_reg = CLK_OUT_ENB_CLR_H,
		.rst_reg = RST_DEVICES_H,
		.rst_set_reg = RST_DEVICES_SET_H,
		.rst_clr_reg = RST_DEVICES_CLR_H,
	},
	[2] = {
		.enb_reg = CLK_OUT_ENB_U,
		.enb_set_reg = CLK_OUT_ENB_SET_U,
		.enb_clr_reg = CLK_OUT_ENB_CLR_U,
		.rst_reg = RST_DEVICES_U,
		.rst_set_reg = RST_DEVICES_SET_U,
		.rst_clr_reg = RST_DEVICES_CLR_U,
	},
	[3] = {
		.enb_reg = CLK_OUT_ENB_V,
		.enb_set_reg = CLK_OUT_ENB_SET_V,
		.enb_clr_reg = CLK_OUT_ENB_CLR_V,
		.rst_reg = RST_DEVICES_V,
		.rst_set_reg = RST_DEVICES_SET_V,
		.rst_clr_reg = RST_DEVICES_CLR_V,
	},
	[4] = {
		.enb_reg = CLK_OUT_ENB_W,
		.enb_set_reg = CLK_OUT_ENB_SET_W,
		.enb_clr_reg = CLK_OUT_ENB_CLR_W,
		.rst_reg = RST_DEVICES_W,
		.rst_set_reg = RST_DEVICES_SET_W,
		.rst_clr_reg = RST_DEVICES_CLR_W,
	},
	[5] = {
		.enb_reg = CLK_OUT_ENB_X,
		.enb_set_reg = CLK_OUT_ENB_SET_X,
		.enb_clr_reg = CLK_OUT_ENB_CLR_X,
		.rst_reg = RST_DEVICES_X,
		.rst_set_reg = RST_DEVICES_SET_X,
		.rst_clr_reg = RST_DEVICES_CLR_X,
	},
	[6] = {
		.enb_reg = CLK_OUT_ENB_Y,
		.enb_set_reg = CLK_OUT_ENB_SET_Y,
		.enb_clr_reg = CLK_OUT_ENB_CLR_Y,
		.rst_reg = RST_DEVICES_Y,
		.rst_set_reg = RST_DEVICES_SET_Y,
		.rst_clr_reg = RST_DEVICES_CLR_Y,
	},
};

static void __iomem *clk_base;
static DEFINE_MUTEX(pto_lock);
static DEFINE_SPINLOCK(pto_rmw_lock);

static int tegra_clk_rst_assert(struct reset_controller_dev *rcdev,
		unsigned long id)
{
	/*
	 * If peripheral is on the APB bus then we must read the APB bus to
	 * flush the write operation in apb bus. This will avoid peripheral
	 * access after disabling clock. Since the reset driver has no
	 * knowledge of which reset IDs represent which devices, simply do
	 * this all the time.
	 */
	tegra_read_chipid();

	if (id < periph_banks * 32) {
		writel_relaxed(BIT(id % 32),
			       clk_base + periph_regs[id / 32].rst_set_reg);
		fence_udelay(2, clk_base);
		return 0;
	} else if (id < periph_banks * 32 + num_special_reset) {
		return special_reset_assert(id);
	}

	return -EINVAL;
}

static int tegra_clk_rst_deassert(struct reset_controller_dev *rcdev,
		unsigned long id)
{
	if (id < periph_banks * 32) {
		writel_relaxed(BIT(id % 32),
			       clk_base + periph_regs[id / 32].rst_clr_reg);
		fence_udelay(2, clk_base);
		return 0;
	} else if (id < periph_banks * 32 + num_special_reset) {
		return special_reset_deassert(id);
	}

	return -EINVAL;
}

static int tegra_clk_rst_reset(struct reset_controller_dev *rcdev,
		unsigned long id)
{
	int err;

	err = tegra_clk_rst_assert(rcdev, id);
	if (err)
		return err;

	udelay(5);

	return tegra_clk_rst_deassert(rcdev, id);
}

const struct tegra_clk_periph_regs *get_reg_bank(int clkid)
{
	int reg_bank = clkid / 32;

	if (reg_bank < periph_banks)
		return &periph_regs[reg_bank];
	else {
		WARN_ON(1);
		return NULL;
	}
}

int tegra_super_cdiv_use_therm_controls(bool enable)
{
	u32 val;

	if (!has_ccplex_therm_control)
		return -EINVAL;

	val = readl(clk_base + SUPER_CCLKG_DIVIDER);
	if (enable)
		val |= BIT(30);
	else
		val &= ~BIT(30);

	writel(val, clk_base + SUPER_CCLKG_DIVIDER);

	return 0;
}
EXPORT_SYMBOL_GPL(tegra_super_cdiv_use_therm_controls);

#ifdef CONFIG_PM_SLEEP
void tegra_clk_periph_suspend(void __iomem *clk_base)
{
	int i, idx;

	idx = 0;
	for (i = 0; i < periph_banks; i++, idx++)
		periph_ctx[idx] =
			readl_relaxed(clk_base + periph_regs[i].rst_reg);

	for (i = 0; i < periph_banks; i++, idx++)
		periph_ctx[idx] =
			readl_relaxed(clk_base + periph_regs[i].enb_reg);
}

void tegra_clk_periph_force_on(u32 *clks_on, int count, void __iomem *clk_base)
{
	int i;

	WARN_ON(count != periph_banks);

	for (i = 0; i < count; i++)
		writel_relaxed(clks_on[i], clk_base + periph_regs[i].enb_reg);
}

void tegra_clk_periph_resume(void __iomem *clk_base)
{
	int i, idx;

	idx = 0;
	for (i = 0; i < periph_banks; i++, idx++)
		writel_relaxed(periph_ctx[idx],
			clk_base + periph_regs[i].rst_reg);

	/* ensure all resets have propagated */
	fence_udelay(2, clk_base);
	tegra_read_chipid();

	for (i = 0; i < periph_banks; i++, idx++)
		writel_relaxed(periph_ctx[idx],
			clk_base + periph_regs[i].enb_reg);

	/* ensure all enables have propagated */
	fence_udelay(2, clk_base);
	tegra_read_chipid();
}

static int tegra_clk_suspend_ctx_init(int banks)
{
	int err = 0;

	periph_ctx = kzalloc(2 * banks * sizeof(*periph_ctx), GFP_KERNEL);
	if (!periph_ctx)
		err = -ENOMEM;

	return err;
}
#endif

struct clk ** __init tegra_clk_init(void __iomem *regs, int num, int banks)
{
	clk_base = regs;

	if (WARN_ON(banks > ARRAY_SIZE(periph_regs)))
		return NULL;

	periph_clk_enb_refcnt = kzalloc(32 * banks *
				sizeof(*periph_clk_enb_refcnt), GFP_KERNEL);
	if (!periph_clk_enb_refcnt)
		return NULL;

	periph_banks = banks;

	clks = kzalloc(num * sizeof(struct clk *), GFP_KERNEL);
	if (!clks) {
		kfree(periph_clk_enb_refcnt);
		return NULL;
	}

	clk_num = num;

#ifdef CONFIG_PM_SLEEP
	if (tegra_clk_suspend_ctx_init(banks)) {
		kfree(periph_clk_enb_refcnt);
		kfree(clks);
		return NULL;
	}
#endif

	return clks;
}

void __init tegra_init_dup_clks(struct tegra_clk_duplicate *dup_list,
				struct clk *clks[], int clk_max)
{
	struct clk *clk;

	for (; dup_list->clk_id < clk_max; dup_list++) {
		clk = clks[dup_list->clk_id];
		dup_list->lookup.clk = clk;
		clkdev_add(&dup_list->lookup);
	}
}

static void tegra_handle_skipped_clks(struct device_node *np)
{
	struct property *prop;
	int err, i;

	prop = of_find_property(np, "nvidia,tegra-ignore-clks", &skipped_len);
	if (!prop)
		return;

	if (skipped_len % sizeof(*skipped_clkids)) {
		pr_err("clk: invalid nvidia,tegra-ignore-clks property len: %d\n",
			skipped_len);
		skipped_len = 0;
		return;
	}

	skipped_len /= sizeof(*skipped_clkids);
	skipped_clkids = kmalloc_array(skipped_len, sizeof(*skipped_clkids),
				 GFP_KERNEL);
	err = of_property_read_u32_array(np, "nvidia,tegra-ignore-clks",
					 skipped_clkids, skipped_len);
	if (err < 0) {
		pr_err("clk: error %d reading nvidia,tegra-ignore-clks property",
			err);
		kfree(skipped_clkids);
		skipped_len = 0;
		skipped_clkids = NULL;
		return;
	}

	for (i = 0; i < skipped_len; i++) {
		uint32_t skipid = skipped_clkids[i];
		struct clk *skipclk;

		if (skipid < clk_num)
			skipclk = clks[skipid];
		else {
			pr_err("clk: ignoring invalid ignored clk id: %d\n",
				skipid);
			continue;
		}

		if (!IS_ERR_OR_NULL(skipclk)) {
			clk_unregister(skipclk);
			clks[skipid] = NULL;
		} else {
			 pr_err("clk: ignoring unregistered ignored clk id: %d\n",
				skipid);
		}
	}
}

static bool clk_is_skipped(uint32_t clk_id)
{
	int i;

	if (!skipped_clkids)
		return false;

	for (i = 0; i < skipped_len; i++) {
		if (skipped_clkids[i] == clk_id)
			return true;
	}

	return false;
}

void __init tegra_init_from_table(struct tegra_clk_init_table *tbl,
				  struct clk *clks[], int clk_max)
{
	struct clk *clk;

	for (; tbl->clk_id < clk_max; tbl++) {
		if (clk_is_skipped(tbl->clk_id)) {
			pr_info("clk: clk %d removed. Skipping init entry\n",
				tbl->clk_id);
			continue;
		}

		clk = clks[tbl->clk_id];
		if (IS_ERR_OR_NULL(clk)) {
			pr_err("%s: invalid entry %ld in clks array for id %d\n",
			       __func__, PTR_ERR(clk), tbl->clk_id);
			WARN_ON(1);

			continue;
		}

		if (tbl->parent_id < clk_max) {
			struct clk *parent = clks[tbl->parent_id];
			if (clk_set_parent(clk, parent)) {
				pr_err("%s: Failed to set parent %s of %s\n",
				       __func__, __clk_get_name(parent),
				       __clk_get_name(clk));
				WARN_ON(1);
			}
		}

		if (tbl->rate) {
			bool can_set_rate = true;

			if ((tbl->flags & TEGRA_TABLE_RATE_CHANGE_OVERCLOCK) &&
			    __clk_is_enabled(clk)) {
				if (tbl->rate != clk_get_rate(clk)) {
					pr_err("%s: Can't set rate %lu of %s\n",
					       __func__, tbl->rate,
					       __clk_get_name(clk));
					WARN_ON(1);
				}
				can_set_rate = false;
			}

			if (can_set_rate && clk_set_rate(clk, tbl->rate)) {
				pr_err("%s: Failed to set rate %lu of %s\n",
				       __func__, tbl->rate,
				       __clk_get_name(clk));
				WARN_ON(1);
			}
		}

		if (tbl->state)
			if (clk_prepare_enable(clk)) {
				pr_err("%s: Failed to enable %s\n", __func__,
				       __clk_get_name(clk));
				WARN_ON(1);
			}
	}
}

static const struct reset_control_ops rst_ops = {
	.assert = tegra_clk_rst_assert,
	.deassert = tegra_clk_rst_deassert,
	.reset = tegra_clk_rst_reset,
};

static struct reset_controller_dev rst_ctlr = {
	.ops = &rst_ops,
	.owner = THIS_MODULE,
	.of_reset_n_cells = 1,
};

void tegra_rst_assertv(unsigned long *id, int num)
{
	int i;

	for (i = 0; i < num; i++, id++)
		tegra_clk_rst_assert(&rst_ctlr, *id);
}

void tegra_rst_deassertv(unsigned long *id, int num)
{
	int i;

	for (i = 0; i < num; i++, id++)
		tegra_clk_rst_deassert(&rst_ctlr, *id);
}

#ifdef CONFIG_TEGRA_CLK_DEBUG
static int rate_write_op(void *data, u64 rate)
{
	struct clk *clk = data;
	return clk_set_rate(clk, rate);
}

static int state_write_op(void *data, u64 state)
{
	struct clk *clk = data;
	if (state)
		return clk_prepare_enable(clk);
	else
		clk_disable_unprepare(clk);
	return 0;
}

static int state_read_op(void *data, u64 *state)
{
	struct clk *clk = data;

	*state = __clk_is_enabled(clk);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(rate_fops, state_read_op, rate_write_op, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(state_fops, state_read_op, state_write_op, "%llu\n");

static int show_parent(struct seq_file *s, void *data)
{
	struct clk *clk, *parent;

	clk = (struct clk *)s->private;
	parent = clk_get_parent(clk);

	if (parent)
		seq_printf(s, "%s\n", __clk_get_name(clk_get_parent(clk)));

	return 0;
}

ssize_t parent_fops_write(struct file *file, const char __user *buf,
			  size_t len, loff_t *ppos)
{
	char *parent_name;
	struct clk *parent;
	ssize_t ret = len;
	struct clk *clk;
	struct seq_file *s;
	int err;

	s = (struct seq_file *)file->private_data;
	clk = (struct clk *)s->private;

	parent_name = kmalloc(len, GFP_KERNEL);
	if (!parent_name)
		return -ENOMEM;

	if (copy_from_user(parent_name, buf, len)) {
		ret = -EFAULT;
		goto out;
	}

	/* strip trailing '\n' */
	while (len > 0 && parent_name[len-1] == '\n')
		parent_name[--len] = 0;

	parent = clk_get_sys("tegra-clk-debug", parent_name);
	if (IS_ERR_OR_NULL(parent)) {
		ret = -EINVAL;
		goto out;
	}

	err = clk_set_parent(clk, parent);
	if (err < 0)
		ret = err;

out:
	kfree(parent_name);

	return ret;
}

static int parent_fops_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_parent, inode->i_private);
}

static const struct file_operations parent_fops = {
	.owner		= THIS_MODULE,
	.open		= parent_fops_open,
	.release	= single_release,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.write		= parent_fops_write,
};
#endif

void tegra_clk_debugfs_add(struct clk *clk)
{
#ifdef CONFIG_TEGRA_CLK_DEBUG
	const char *name;
	struct clk_hw *hw;
	struct dentry *d;

	name = __clk_get_name(clk);
	hw = __clk_get_hw(clk);
	d = clk_debugfs_add_file(hw, "clk_update_rate", 0200, clk,
				 &rate_fops);
	if ((IS_ERR(d) && PTR_ERR(d) != -EAGAIN) || !d)
		pr_err("debugfs clk_update_rate failed %s\n", name);

	d = clk_debugfs_add_file(hw, "clk_state", 0644, clk,
				 &state_fops);
	if ((IS_ERR(d) && PTR_ERR(d) != -EAGAIN) || !d)
		pr_err("debugfs clk_state failed %s\n", name);

	d = clk_debugfs_add_file(hw, "clk_parent", 0644, clk,
				 &parent_fops);
	if ((IS_ERR(d) && PTR_ERR(d) != -EAGAIN) || !d)
		pr_err("debugfs clk_parent failed %s\n", name);
#endif
}

void __init tegra_add_of_provider(struct device_node *np)
{
	int i;

	tegra_handle_skipped_clks(np);

	for (i = 0; i < clk_num; i++) {
		if (IS_ERR(clks[i])) {
			pr_err
			    ("Tegra clk %d: register failed with %ld\n",
			     i, PTR_ERR(clks[i]));
		} else if (!clks[i]) {
			clks[i] = ERR_PTR(-EINVAL);
		} else
			tegra_clk_debugfs_add(clks[i]);
	}

	clk_data.clks = clks;
	clk_data.clk_num = clk_num;
	of_clk_add_provider(np, of_clk_src_onecell_get, &clk_data);

	rst_ctlr.of_node = np;
	rst_ctlr.nr_resets = periph_banks * 32 + num_special_reset;
	reset_controller_register(&rst_ctlr);
}

static int pto_get(void *data, u64 *output)
{
	struct tegra_pto_table *ptodef = (struct tegra_pto_table *)data;
	unsigned long flags = 0;
	u64 rate;
	u32 val, presel_val = 0;
	u8 cycle_count;

	if (ptodef->presel_reg) {
		spin_lock_irqsave(&pto_rmw_lock, flags);
		val = readl(clk_base + ptodef->presel_reg);
		presel_val = val & ptodef->presel_mask;
		val &= ~ptodef->presel_mask;
		val |= ptodef->presel_value;
		writel(val, clk_base + ptodef->presel_reg);
		spin_unlock_irqrestore(&pto_rmw_lock, flags);
	}

	mutex_lock(&pto_lock);

	cycle_count = ptodef->cycle_count;
	if (!cycle_count)
		cycle_count = 16;

	val = BIT(23) | BIT(13) | (cycle_count - 1);
	val |= 	ptodef->pto_id << 14;
	writel(val, clk_base + 0x60);
	writel(val | BIT(10), clk_base + 0x60);
	writel(val, clk_base + 0x60);
	writel(val | BIT(9), clk_base + 0x60);

	udelay(500);

	while(readl(clk_base + 0x64) & BIT(31))
		;

	val = readl(clk_base + 0x64);
	val &= GENMASK(23, 0);
	val *= ptodef->divider;

	mutex_unlock(&pto_lock);

	rate = (u64)val * 32768 / cycle_count;
	rate = DIV_ROUND_CLOSEST(rate, 1000) * 1000;
	*output = rate;

	if (ptodef->presel_reg) {
		spin_lock_irqsave(&pto_rmw_lock, flags);
		val = readl(clk_base + ptodef->presel_reg);
		val &= ~ptodef->presel_mask;
		val |= presel_val;
		writel(val, clk_base + ptodef->presel_reg);
		spin_unlock_irqrestore(&pto_rmw_lock, flags);
	}

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(pto_fops, pto_get, NULL, "%llu\n");

static int cycles_get(void *data, u64 *val)
{
	u8 *cycles = data;

	*val = *cycles;

	return 0;
}

static int cycles_set(void *data, u64 val)
{
	u8 *cycles = data;

	if (!val)
		val = 16;

	*cycles = min(val, 16LLU);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(cycles_fops, cycles_get, cycles_set, "%llu\n");

void tegra_register_pto(struct clk *clk, struct tegra_pto_table *ptodef)
{
	struct dentry *d;

	d = __clk_debugfs_add_file(clk, "pto_rate", 0400,
				   ptodef, &pto_fops);
	if ((IS_ERR(d) && PTR_ERR(d) != -EAGAIN) || !d)
		pr_err("debugfs pto_rate failed %s\n",
		       __clk_get_name(clk));

	if (!ptodef->cycle_count)
		ptodef->cycle_count = 16;

	d = __clk_debugfs_add_file(clk, "pto_cycles", 0600,
				   &ptodef->cycle_count, &cycles_fops);
	if ((IS_ERR(d) && PTR_ERR(d) != -EAGAIN) || !d)
		pr_err("debugfs pto_cycles failed %s\n",
		       __clk_get_name(clk));
}

void tegra_register_ptos(struct tegra_pto_table *ptodefs, int num_pto_defs)
{
	int i;
	struct clk *clk;

	for (i = 0; i < num_pto_defs; i++) {
		clk = clks[ptodefs[i].clk_id];
		if (IS_ERR(clk))
			continue;
		tegra_register_pto(clk, &ptodefs[i]);
	}
}

void __init tegra_init_special_resets(unsigned int num,
				      int (*assert)(unsigned long),
				      int (*deassert)(unsigned long))
{
	num_special_reset = num;
	special_reset_assert = assert;
	special_reset_deassert = deassert;
}

void __init tegra_register_devclks(struct tegra_devclk *dev_clks, int num)
{
	int i;

	for (i = 0; i < num; i++, dev_clks++)
		clk_register_clkdev(clks[dev_clks->dt_id], dev_clks->con_id,
				dev_clks->dev_id);

	for (i = 0; i < clk_num; i++) {
		if (!IS_ERR_OR_NULL(clks[i]))
			clk_register_clkdev(clks[i], __clk_get_name(clks[i]),
				"tegra-clk-debug");
	}
}

struct clk ** __init tegra_lookup_dt_id(int clk_id,
					struct tegra_clk *tegra_clk)
{
	if (tegra_clk[clk_id].present)
		return &clks[tegra_clk[clk_id].dt_id];
	else
		return NULL;
}

tegra_clk_apply_init_table_func tegra_clk_apply_init_table;

static int __init tegra_clocks_apply_init_table(void)
{
	if (!tegra_clk_apply_init_table)
		return 0;

	tegra_clk_apply_init_table();

	return 0;
}
arch_initcall_sync(tegra_clocks_apply_init_table);
