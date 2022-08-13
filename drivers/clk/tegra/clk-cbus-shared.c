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

#include <linux/slab.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/clk-provider.h>
#include <linux/clk.h>
#include <soc/tegra/tegra-dvfs.h>

#include "clk.h"

#define KHz 1000

/* there should be only 1 instance of sclk, so we can keep this global for now */
static unsigned long sclk_pclk_unity_ratio_rate_max = 136000000;

static int shared_bus_clk_notifier(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	struct clk_notifier_data *cnd = data;
	struct clk_hw *chw = __clk_get_hw(cnd->clk);
	struct tegra_clk_cbus_shared *bus = to_clk_cbus_shared(chw);

	switch (action) {
	case PRE_SUBTREE_CHANGE:
		bus->rate_propagating = 1;
		break;
	case POST_SUBTREE_CHANGE:
		bus->rate_propagating = 0;
		break;
	}
	pr_debug("%s: %s: event %lu\n",
		 __func__, clk_hw_get_name(&bus->hw), action);
	return NOTIFY_DONE;
}

static struct notifier_block shared_bus_clk_nb = {
	.notifier_call = shared_bus_clk_notifier,
};

static int register_bus_clk_notifier(struct clk *bus_clk)
{
	clk_notifier_register(bus_clk, &shared_bus_clk_nb);
	return 0;
}

static int cbus_switch_one(struct clk *client, struct clk *p)
{
	int ret = 0;
	unsigned long old_parent_rate, new_parent_rate, current_rate;

	current_rate = clk_get_rate(client);
	old_parent_rate = clk_get_rate(clk_get_parent(client));
	new_parent_rate = clk_get_rate(p);

	if (new_parent_rate > old_parent_rate) {
		u64 temp_rate;

		/*
		 * In order to not overclocking the IP block when changing the
		 * parent, we set the divider to a value which will give us an
		 * allowed rate when the new parent is selected.
		 */
		temp_rate = DIV_ROUND_UP_ULL((u64)clk_get_rate(client) *
			(u64)old_parent_rate, new_parent_rate);
		ret = clk_set_rate(client, temp_rate);
		if (ret) {
			pr_err("failed to set %s rate to %llu: %d\n",
				__clk_get_name(client), temp_rate, ret);
			return ret;
		}
	}

	ret = clk_set_parent(client, p);
	if (ret) {
		pr_err("failed to set %s parent to %s: %d\n",
			__clk_get_name(client),
			__clk_get_name(p), ret);
		return ret;
	}

	clk_set_rate(client, current_rate);

	return ret;
}

static int cbus_backup(struct clk_hw *hw)
{
	int ret = 0;
	struct tegra_clk_cbus_shared *cbus = to_clk_cbus_shared(hw);
	struct tegra_clk_cbus_shared *user;

	list_for_each_entry(user, &cbus->shared_bus_list,
				 u.shared_bus_user.node) {
		struct clk *client = user->u.shared_bus_user.client;

		if (client && __clk_is_enabled(client) &&
		 (clk_get_parent(client) == clk_get_parent(hw->clk))) {
			ret = cbus_switch_one(client, cbus->shared_bus_backup);
			if (ret)
				break;
		}
	}

	return ret;
}

static void cbus_restore(struct clk_hw *hw)
{
	struct tegra_clk_cbus_shared *user;
	struct tegra_clk_cbus_shared *cbus = to_clk_cbus_shared(hw);
	struct clk *parent;
	unsigned long parent_rate;

	parent = clk_get_parent(hw->clk);
	parent_rate = clk_get_rate(parent);

	list_for_each_entry(user, &cbus->shared_bus_list,
				 u.shared_bus_user.node) {
		struct clk *client = user->u.shared_bus_user.client;

		if (client) {
			unsigned long new_rate = user->u.shared_bus_user.rate;

			cbus_switch_one(client, clk_get_parent(hw->clk));

			if ((user->flags & TEGRA_SHARED_BUS_RACE_TO_SLEEP) ||
			    (new_rate > parent_rate)) {
				clk_set_rate(client, parent_rate);
				continue;
			}

			if (new_rate) {
				int div = parent_rate / new_rate;

				new_rate = (parent_rate + div - 1) / div;
			}
			clk_set_rate(client, new_rate);
		}
	}
}

static int clk_cbus_set_rate(struct clk_hw *hw, unsigned long rate,
			unsigned long parent_rate)
{
	int ret;
	struct clk *parent;
	struct tegra_clk_cbus_shared *cbus = to_clk_cbus_shared(hw);

	if (cbus->rate_updating)
		return 0;

	if (rate == 0)
		return 0;

	cbus->rate_updating = true;

	parent = clk_get_parent(hw->clk);
	if (IS_ERR_OR_NULL(parent)) {
		pr_err("%s: no %s parent\n", __func__, clk_hw_get_name(hw));
		cbus->rate_updating = false;
		return -EINVAL;
	}

	ret = clk_prepare_enable(parent);
	if (ret) {
		cbus->rate_updating = false;
		pr_err("%s: failed to enable %s clock: %d\n",
		       __func__, __clk_get_name(hw->clk), ret);
		return ret;
	}

	ret = cbus_backup(hw);
	if (ret)
		goto out;

	ret = clk_set_rate(parent, rate);
	if (ret) {
		pr_err("%s: failed to set %s clock rate %lu: %d\n",
		       __func__, __clk_get_name(hw->clk), rate, ret);
		goto out;
	}

	cbus_restore(hw);

out:
	cbus->rate_updating = false;
	clk_disable_unprepare(parent);
	return ret;
}

static long clk_cbus_round_rate(struct clk_hw *hw, unsigned long rate,
			unsigned long *parent_rate)
{
	struct clk *parent;
	long new_rate;
	unsigned long dvfs_rate;
	struct tegra_clk_cbus_shared *cbus = to_clk_cbus_shared(hw);
	bool pass_through = cbus->flags & TEGRA_SHARED_BUS_ROUND_PASS_THRU;

	parent = clk_get_parent(hw->clk);
	if (IS_ERR_OR_NULL(parent)) {
		pr_info("%s: no %s parent\n", __func__, clk_hw_get_name(hw));
		return *parent_rate;
	}

	if (!pass_through) {
		dvfs_rate = tegra_dvfs_round_rate(hw->clk, rate);
		if (IS_ERR_VALUE(dvfs_rate))
			pass_through = true;
	}

	if (pass_through)
		dvfs_rate = rate;

	new_rate = clk_round_rate(parent, dvfs_rate);
	if (new_rate < 0)
		return *parent_rate;

	if (!pass_through)
		WARN_ON(new_rate > dvfs_rate);

	return new_rate;
}

static unsigned long clk_cbus_recalc_rate(struct clk_hw *hw,
				unsigned long parent_rate)
{
	struct clk *parent = clk_get_parent(hw->clk);

	if (IS_ERR_OR_NULL(parent)) {
		pr_info("%s: no %s parent\n", __func__, clk_hw_get_name(hw));
		return parent_rate;
	}
	return clk_get_rate(parent);
}

static unsigned long _clk_cap_shared_bus(struct clk *c, unsigned long rate,
						unsigned long ceiling)
{
	unsigned long rounded_ceiling = clk_round_rate(c, ceiling);

	if (rounded_ceiling > ceiling) {
		struct clk_hw *hw = __clk_get_hw(c);
		unsigned long start, next, resolution = 2000; /* 2kHz */

		/* Div-by-2 search down for start */
		start = clk_round_rate(c, to_clk_cbus_shared(hw)->min_rate);
		do {
			next = start;
			start = max((start + ceiling) / 2, start + resolution);
			start = clk_round_rate(c, start);
		} while (start < ceiling);
		pr_debug("%s: start %lu, next %lu\n", __func__, start, next);

		/* Linear search rounding ladder up  */
		do {
			rounded_ceiling = next;
			next = clk_round_rate(c, next + resolution);
		} while (next <= ceiling);
	}

	return min(rate, rounded_ceiling);
}

static int clk_cbus_prepare(struct clk_hw *hw)
{
	return tegra_dvfs_set_rate(hw->clk, clk_get_rate(hw->clk));
}

static void clk_cbus_unprepare(struct clk_hw *hw)
{
	tegra_dvfs_set_rate(hw->clk, 0);
}

static bool bus_user_is_slower(struct tegra_clk_cbus_shared *a,
			       struct tegra_clk_cbus_shared *b)
{
	if (!a->max_rate)
		a->max_rate = tegra_dvfs_get_maxrate(a->hw.clk);

	if (!b->max_rate)
		b->max_rate = tegra_dvfs_get_maxrate(b->hw.clk);

	return a->max_rate < b->max_rate;
}

static unsigned long _clk_shared_bus_update(struct tegra_clk_cbus_shared *cbus,
			struct tegra_clk_cbus_shared **bus_top,
			struct tegra_clk_cbus_shared **bus_slow,
			unsigned long *rate_cap)
{
	struct tegra_clk_cbus_shared *c;
	struct tegra_clk_cbus_shared *slow = NULL;
	struct tegra_clk_cbus_shared *top = NULL;
	unsigned long override_rate = 0;
	unsigned long top_rate = 0;
	unsigned long rate = cbus->min_rate;
	unsigned long bw = 0;
	unsigned long ceiling = cbus->max_rate;
	bool rate_set = false;

	list_for_each_entry(c, &cbus->shared_bus_list,
			u.shared_bus_user.node) {
		bool cap_user = (c->u.shared_bus_user.mode == SHARED_CEILING);
		/*
		 * Ignore requests from disabled floor, bw users, and
		 * auto-users riding the bus. Always check the ceiling users
		 * so we don't need to enable it for capping the bus rate.
		 */
		if (c->u.shared_bus_user.enabled || cap_user) {
			unsigned long request_rate = c->u.shared_bus_user.rate;

			if (!(c->flags & TEGRA_SHARED_BUS_RATE_LIMIT))
				rate_set = true;

			switch (c->u.shared_bus_user.mode) {
			case SHARED_BW:
				bw += request_rate;
				if (bw > cbus->max_rate)
					bw = cbus->max_rate;
				break;
			case SHARED_CEILING:
				if (request_rate)
					ceiling = min(request_rate, ceiling);
				break;
			case SHARED_OVERRIDE:
				if (override_rate == 0)
					override_rate = request_rate;
				break;
			case SHARED_AUTO:
				break;
			case SHARED_FLOOR:
			default:
				if (rate <= request_rate) {
					if (!(c->flags & TEGRA_SHARED_BUS_RATE_LIMIT)
						|| (rate < request_rate))
						rate = request_rate;
				}
				if (c->u.shared_bus_user.client
					&& request_rate) {
					if (top_rate < request_rate) {
						top_rate = request_rate;
						top = c;
					} else if ((top_rate == request_rate)
						&& bus_user_is_slower(c, top)) {
						top = c;
					}
				}
			}
                        if (c->u.shared_bus_user.client &&
				(!slow || bus_user_is_slower(c, slow)))
				slow = c;
		}
	}

	rate = override_rate ? : max(rate, bw);
#ifdef CONFIG_TEGRA_CLK_DEBUG
	ceiling = override_rate ? cbus->max_rate : ceiling;
#endif

	if (bus_top && bus_slow && rate_cap) {
		*bus_top = top;
		*bus_slow = slow;
		*rate_cap = ceiling;
	} else {
		if (!rate_set && cbus->flags & TEGRA_SHARED_BUS_RETENTION)
			rate = clk_get_rate(cbus->hw.clk);

		rate = _clk_cap_shared_bus(cbus->hw.clk, rate, ceiling);
	}

	return rate;
}

static int _simple_shared_update(struct tegra_clk_cbus_shared *bus)
{
	unsigned long rate;
	int err;


	rate = _clk_shared_bus_update(bus, NULL, NULL, NULL);

	err = clk_set_rate(bus->hw.clk, rate);

	return err;
}

static int clk_shared_bus_update(struct clk *bus)
{
	struct tegra_clk_cbus_shared *cbus =
		to_clk_cbus_shared(__clk_get_hw(bus));
	int err;

	if (cbus->rate_update_started)
		return 0;

	cbus->rate_update_started = true;

	err = cbus->bus_update(cbus);

	cbus->rate_update_started = false;

	return err;
}

static int clk_shared_prepare(struct clk_hw *hw)
{
	int err = 0;
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);

	shared->u.shared_bus_user.enabled = true;
	err = clk_shared_bus_update(clk_get_parent(hw->clk));
	if (!err && shared->u.shared_bus_user.client)
		err = clk_prepare_enable(shared->u.shared_bus_user.client);

	return err;
}

static void clk_shared_unprepare(struct clk_hw *hw)
{
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);

	if (shared->u.shared_bus_user.client)
		clk_disable_unprepare(shared->u.shared_bus_user.client);

	shared->u.shared_bus_user.enabled = false;
	clk_shared_bus_update(clk_get_parent(hw->clk));
}

static int _connect_shared_update(struct tegra_clk_cbus_shared *bus)
{
	unsigned long rate;
	int err;

	rate = _clk_shared_bus_update(bus, NULL, NULL, NULL);

	bus->u.shared_bus_user.rate = rate;
	pr_debug("%s: %s: user.rate is set to %lu\n",
		 __func__, clk_hw_get_name(&bus->hw), rate);

	err = clk_shared_bus_update(clk_get_parent(bus->hw.clk));

	return err;
}

static int clk_shared_connect_master_prepare(struct clk_hw *hw)
{
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);

	shared->u.shared_bus_user.enabled = true;
	if (shared->u.shared_bus_user.client)
		return clk_prepare_enable(shared->u.shared_bus_user.client);

	return 0;
}

static void clk_shared_connect_master_unprepare(struct clk_hw *hw)
{
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);

	if (shared->u.shared_bus_user.client)
		clk_disable_unprepare(shared->u.shared_bus_user.client);

	shared->u.shared_bus_user.enabled = false;
}

static int clk_shared_set_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long parent_rate)
{
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);
	struct tegra_clk_cbus_shared *bus =
		to_clk_cbus_shared(clk_hw_get_parent(hw));

	if (bus->rate_propagating)
		return 0;

	shared->u.shared_bus_user.rate = rate;
	pr_debug("%s: %s: user.rate is set to %lu\n",
		 __func__, clk_hw_get_name(hw), rate);

	return clk_shared_bus_update(clk_get_parent(hw->clk));
}

static long clk_shared_round_rate(struct clk_hw *hw,
				  unsigned long rate,
				  unsigned long *parent_rate)
{
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);
	struct tegra_clk_cbus_shared *parent_cbus;
	struct clk *parent;
	long ret;

	parent = clk_get_parent(hw->clk);
	parent_cbus = to_clk_cbus_shared(__clk_get_hw(parent));

	/*
	 * Defer rounding requests until aggregated. BW users must not be
	 * rounded at all, others just clipped to bus range (some clients
	 * may use round api to find limits)
	 */
	if (shared->u.shared_bus_user.mode != SHARED_BW) {
		if (!parent_cbus->max_rate) {
			ret = clk_round_rate(parent, ULONG_MAX);
			if (ret > 0)
				parent_cbus->max_rate = ret;
		}

		if (rate > parent_cbus->max_rate)
			rate = parent_cbus->max_rate;
		else if (rate < parent_cbus->min_rate)
			rate = parent_cbus->min_rate;
	}
	return rate;
}

static unsigned long clk_shared_recalc_rate(struct clk_hw *hw,
				unsigned long parent_rate)
{
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);

	if (shared->u.shared_bus_user.mode == SHARED_CEILING)
		return shared->u.shared_bus_user.rate;

	if (!clk_hw_get_parent(clk_hw_get_parent(hw)))
		return shared->u.shared_bus_user.rate;

	if (shared->u.shared_bus_user.client &&
	    (~shared->flags & TEGRA_SHARED_BUS_RACE_TO_SLEEP)) {
		/* FIXME: for clocks with clients that can be divided down */
	}

	/*
	 * CCF wrongly assumes that the parent rate won't change during
	 * set_rate, so get the parent rate explicitly.
	 */
        return clk_hw_get_rate(clk_hw_get_parent(hw));
}

static int clk_gbus_prepare(struct clk_hw *hw)
{
	return tegra_dvfs_set_rate(hw->clk, clk_get_rate(hw->clk));
}

static void clk_gbus_unprepare(struct clk_hw *hw)
{
	/*
	 * gbus is unprepared when GPU is powered Off. However, current DVFS
	 * rate should be maintained (not set to 0), so that the GPU voltage
	 * is properly updated if temperature changes while GPU is Off, This
	 * would assure that voltage for the next GPU power On at the new
	 * temperature is safe.
	 *
	 *  tegra_dvfs_set_rate(hw->clk, 0);
	 */
}

static int clk_gbus_set_rate(struct clk_hw *hw, unsigned long rate,
			unsigned long parent_rate)
{
	int ret;
	struct clk *parent;
	struct tegra_clk_cbus_shared *gbus = to_clk_cbus_shared(hw);

	if (gbus->rate_updating)
		return 0;

	if (rate == 0)
		return 0;

	gbus->rate_updating = true;

	parent = clk_get_parent(hw->clk);
	if (IS_ERR_OR_NULL(parent)) {
		pr_err("%s: no %s parent\n", __func__, clk_hw_get_name(hw));
		gbus->rate_updating = false;
		return -EINVAL;
	}

	ret = clk_set_rate(parent, rate);

	gbus->rate_updating = false;
	return ret;
}

static unsigned long clk_cascade_master_recalc_rate(struct clk_hw *hw,
						    unsigned long parent_rate)
{
	struct clk *bus_clk;
	struct clk_hw *cascade_div_hw;
	struct tegra_clk_cbus_shared *bus;
	struct tegra_clk_cbus_shared *cascade_master = to_clk_cbus_shared(hw);


	if (cascade_master->top_clk) {
		bus_clk = cascade_master->top_clk;
		bus = to_clk_cbus_shared(__clk_get_hw(bus_clk));
		cascade_div_hw = clk_hw_get_parent(bus->u.system.pclk);
	} else {
		bus_clk = clk_get_parent(hw->clk);
		bus = to_clk_cbus_shared(__clk_get_hw(bus_clk));
		cascade_div_hw = clk_hw_get_parent(bus->u.system.hclk);
	}

	parent_rate = clk_hw_get_rate(clk_hw_get_parent(hw));
	return tegra_clk_frac_div_ops.recalc_rate(cascade_div_hw, parent_rate);
}

static int clk_system_set_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long parent_rate)
{
	int err = 0, i, current_div;
	struct tegra_clk_cbus_shared *system = to_clk_cbus_shared(hw);
	struct clk *pclk = system->u.system.pclk->clk;
	struct clk *hclk = system->u.system.hclk->clk;
	struct clk *div_clk = system->u.system.div_clk->clk;
	struct tegra_clk_frac_div *sclk_frac_div =
				to_clk_frac_div(system->u.system.div_clk);
	struct clk_div_sel *new_sel = NULL;
	unsigned long div_parent_rate, div_rate;

	if (system->rate_updating)
		return 0;

	system->rate_updating = true;

	clk_set_rate(hclk, parent_rate);
	clk_set_rate(pclk, parent_rate / 2);

	for (i = 0; i < system->u.system.round_table_size; i++) {
		if (rate == system->u.system.round_table[i].rate) {
			new_sel = &system->u.system.round_table[i];
			break;
		}
	}

	if (!new_sel) {
		err = -EINVAL;
		goto out;
	}

	div_rate = clk_get_rate(div_clk);
	if (div_rate == rate)
		goto out;

	div_parent_rate = clk_get_rate(clk_get_parent(div_clk));
	current_div = div71_get(div_rate, div_parent_rate,
				sclk_frac_div->width,
				sclk_frac_div->frac_width,
				sclk_frac_div->flags) + 2; /* match 7.1 format*/
	if (current_div < new_sel->div) {
		unsigned long sdiv_rate;

		/* new_sel->div is in 7.1 format.
		 * see fixed_src_bus_round_updown() for details.
		 */
		sdiv_rate = DIV_ROUND_UP(div_parent_rate * 2, new_sel->div);
		err = clk_set_rate(system->u.system.div_clk->clk, sdiv_rate);
		if (err < 0) {
			pr_err("%s: Failed to set %s rate to %lu\n",
				__func__,
				clk_hw_get_name(system->u.system.div_clk),
				new_sel->rate);
			goto out;
		}
	}

	err = clk_set_parent(system->u.system.mux_clk->clk, new_sel->src->clk);
	if (err < 0) {
		pr_err("%s: Failed to switch sclk source to %s\n", __func__,
			clk_hw_get_name(new_sel->src));
		goto out;
	}

	if (current_div > new_sel->div) {
		err = clk_set_rate(system->u.system.div_clk->clk, rate);
		if (err < 0) {
			pr_err("%s: Failed to set %s rate to %lu\n",
				__func__,
				clk_hw_get_name(system->u.system.div_clk),
				new_sel->rate);
			goto out;
		}
	}

out:
	system->rate_updating = false;
	return err;
}

static long fixed_src_bus_round_updown(struct clk_hw *src, u8 width, u8 frac,
			u8 flags, unsigned long rate, unsigned long max_rate,
			bool up, u32 *div)
{
	int divider;
	unsigned long source_rate, round_rate;
	source_rate = clk_get_rate(src->clk);

	if (up)
		flags &= ~TEGRA_DIVIDER_ROUND_UP;
	else
		flags |= TEGRA_DIVIDER_ROUND_UP;

	rate += up ? -1 : 1;

	/* returned divider will be in 7.1 format. This means the effective
	 * divider is (divider / 2) + 1. To handle this with int's we rewrite
	 * this as (divider + 2) / 2. We will return divider + 2 and expect
	 * the caller to multiply the parent rate by 2 when using this result.
	 */
	divider = div71_get(rate, source_rate, width, frac, flags);
	if (divider < 0) {
		divider = flags & TEGRA_DIVIDER_INT ? 0xFE : 0xFF;
		round_rate = source_rate * 2 / (divider + 2);
		goto _out;
	}

	round_rate = source_rate * 2 / (divider + 2);

	if (round_rate > max_rate) {
		divider += flags & TEGRA_DIVIDER_INT ? 2 : 1;
		divider = max(2, divider);
		round_rate = source_rate * 2 / (divider + 2);
	}
_out:
	if (div)
		*div = divider + 2;
	return round_rate;
}

/* This special sbus round function is implemented because:
 *
 * (a) sbus complex clock source is selected automatically based on rate
 *
 * (b) since sbus is a shared bus, and its frequency is set to the highest
 * enabled shared_bus_user clock, the target rate should be rounded up divider
 * ladder (if max limit allows it) - for pll_div and peripheral_div common is
 * rounding down - special case again.
 *
 * Note that final rate is trimmed (not rounded up) to avoid spiraling up in
 * recursive calls. Lost 1Hz is added in tegra21_sbus_cmplx_set_rate before
 * actually setting divider rate.
 */
static void sbus_build_round_table_one(struct tegra_clk_cbus_shared *sbus,
				       unsigned long rate, int j)
{
	struct clk_div_sel sel;
	struct clk_hw *sclk_hw = sbus->u.system.div_clk;
	struct tegra_clk_frac_div *sclk_frac_div = to_clk_frac_div(sclk_hw);
	u8 flags = sclk_frac_div->flags;
	u8 width = sclk_frac_div->width;
	u8 frac = sclk_frac_div->frac_width;

	sel.src = sbus->u.system.sclk_low;
	sel.rate = fixed_src_bus_round_updown(sel.src, width, frac, flags,
				rate, sbus->max_rate, false, &sel.div);
	sbus->u.system.round_table[j] = sel;

	/* Don't use high frequency source above threshold */
	if (rate <= sbus->u.system.threshold)
		return;

	sel.src = sbus->u.system.sclk_high;
	sel.rate = fixed_src_bus_round_updown(sel.src, width, frac, flags,
				rate, sbus->max_rate, false, &sel.div);
	if (sbus->u.system.round_table[j].rate < sel.rate)
		sbus->u.system.round_table[j] = sel;
}

/* Populate sbus (not Avalon) round table with dvfs entries (not knights) */
static void sbus_build_round_table(struct clk_hw *hw)
{
	int i, j = 0, num_freqs, err = 0;
	unsigned long rate;
	bool inserted_u = false;
	bool inserted_t = false;
	unsigned long threshold;
	unsigned long *freqs;
	struct tegra_clk_cbus_shared *sbus = to_clk_cbus_shared(hw);

	threshold = sbus->u.system.threshold;

	/*
	 * Make sure unity ratio threshold always inserted into the table.
	 * If no dvfs specified, just add maximum rate entry. Othrwise, add
	 * entries for all dvfs rates.
	 */
	err = tegra_dvfs_get_freqs(hw->clk, &freqs, &num_freqs);
	if (err < 0 || num_freqs == 0) {
		if (sbus->u.system.fallback)
			return;

		sbus->u.system.round_table =
			kzalloc(sizeof(struct clk_div_sel) * 3, GFP_KERNEL);
		if (!sbus->u.system.round_table) {
			WARN(1, "no space for knights");
			return;
		}
		if (threshold < sclk_pclk_unity_ratio_rate_max) {
			sbus_build_round_table_one(sbus, threshold, j++);
			sbus_build_round_table_one(sbus,
				sclk_pclk_unity_ratio_rate_max, j++);
		} else {
			sbus_build_round_table_one(sbus,
				sclk_pclk_unity_ratio_rate_max, j++);
			sbus_build_round_table_one(sbus, threshold, j++);
		}
		sbus_build_round_table_one(sbus, sbus->max_rate, j++);
		sbus->u.system.round_table_size = j;
		sbus->u.system.fallback = true;
		return;
	}

	if (sbus->u.system.fallback)
		kfree(sbus->u.system.round_table);

	sbus->u.system.round_table =
		kzalloc(num_freqs * sizeof(struct clk_div_sel), GFP_KERNEL);
	if (!sbus->u.system.round_table) {
		WARN(1, "no space for knights");
		return;
	}

	for (i = 0; i < num_freqs; i++) {
		rate = freqs[i];
		if (rate <= 1 * KHz)
			continue; /* skip 1kHz place holders */

		if (i && (rate == freqs[i - 1]))
			continue; /* skip duplicated rate */

		if (!inserted_u && (rate >= sclk_pclk_unity_ratio_rate_max)) {
			inserted_u = true;
			if (sclk_pclk_unity_ratio_rate_max == threshold)
				inserted_t = true;

			if (rate > sclk_pclk_unity_ratio_rate_max)
				sbus_build_round_table_one(
					sbus, sclk_pclk_unity_ratio_rate_max, j++);
		}
		if (!inserted_t && (rate >= threshold)) {
			inserted_t = true;
			if (rate > threshold)
				sbus_build_round_table_one(sbus, threshold, j++);
		}
		sbus_build_round_table_one(sbus, rate, j++);
	}
	sbus->u.system.round_table_size = j;
	sbus->u.system.fallback = false;
}

static long clk_system_round_rate(struct clk_hw *hw, unsigned long rate,
					unsigned long *parent_rate)
{
	struct tegra_clk_cbus_shared *system = to_clk_cbus_shared(hw);
	int i = 0;

	if (!system->u.system.round_table_size || system->u.system.fallback) {
		sbus_build_round_table(hw);
		if (!system->u.system.round_table_size) {
			WARN(1, "Invalid sbus round table\n");
			return -EINVAL;
		}
	}

	rate = max(rate, system->min_rate);

	for (i = 0; i < system->u.system.round_table_size - 1; i++) {
		unsigned long sel_rate = system->u.system.round_table[i].rate;

		if (abs(rate - sel_rate) <= 1)
			break;
		else if (rate < sel_rate)
			break;
	}

	return system->u.system.round_table[i].rate;
}

static unsigned long clk_system_recalc_rate(struct clk_hw *hw,
					unsigned long parent_rate)
{
	return clk_hw_get_rate(clk_hw_get_parent(hw));
}

static int _sbus_update(struct tegra_clk_cbus_shared *cbus)
{
	int err;
	unsigned long s_rate, h_rate, p_rate, ceiling, s_rate_raw;
	struct tegra_clk_cbus_shared *ahb, *apb;
	struct clk *skipper = clk_get_parent(cbus->hw.clk);
	bool p_requested;

	s_rate = _clk_shared_bus_update(cbus, &ahb, &apb, &ceiling);
	if (cbus->override_rate) {
		err = clk_set_rate(cbus->hw.clk, s_rate);
		if (!err)
			err = clk_set_rate(skipper, s_rate);
		return err;
	}

	ahb = to_clk_cbus_shared(cbus->u.system.ahb_bus);
	apb = to_clk_cbus_shared(cbus->u.system.apb_bus);
	h_rate = ahb->u.shared_bus_user.rate;
	p_rate = apb->u.shared_bus_user.rate;
	p_requested = apb->u.shared_bus_user.enabled;

	/* Propagate ratio requirements up from PCLK to SCLK */
	if (p_requested)
		h_rate = max(h_rate, p_rate * 2);
	s_rate = max(s_rate, h_rate);
	if (s_rate >= sclk_pclk_unity_ratio_rate_max)
		s_rate = max(s_rate, p_rate * 2);

	/* Propagate cap requirements down from SCLK to PCLK */
	s_rate_raw = s_rate;
	s_rate = _clk_cap_shared_bus(cbus->hw.clk, s_rate, ceiling);
	if (s_rate >= sclk_pclk_unity_ratio_rate_max)
		p_rate = min(p_rate, s_rate / 2);
	h_rate = min(h_rate, s_rate);
	if (p_requested)
		p_rate = min(p_rate, h_rate / 2);

	/* Set new sclk rate in safe 1:1:2, rounded "up" configuration */
	cbus->rate_updating = true;
	clk_set_rate(skipper, cbus->max_rate);
	cbus->rate_updating = false;

	err = clk_set_rate(cbus->hw.clk, s_rate);
	if (err)
		return err;

	cbus->rate_updating = true;
	clk_set_rate(skipper, s_rate_raw);
	cbus->rate_updating = false;

	/* Finally settle new bus divider values */
	clk_set_rate(cbus->u.system.hclk->clk, h_rate);
	clk_set_rate(cbus->u.system.pclk->clk, p_rate);

	return 0;
}

static int possible_rates_show(struct seq_file *s, void *data)
{
	struct clk_hw *hw = s->private;
	struct tegra_clk_cbus_shared *bus = to_clk_cbus_shared(hw);
	unsigned long rate = bus->min_rate;
	unsigned long end_rate = clk_hw_round_rate(hw, bus->max_rate);

	if (IS_ERR_VALUE(end_rate)) {
		seq_printf(s, "max boundary rounding broken\n");
		return 0;
	}

	/* shared bus clock must round up, unless top of range reached */
	while (rate < end_rate) {
		unsigned long rounded_rate = clk_hw_round_rate(hw, rate);
		if (IS_ERR_VALUE(rounded_rate) ||
		    (rounded_rate > bus->min_rate && rounded_rate <= rate)) {
			seq_printf(s, "...rates rounding broken\n");
			return 0;
		}

		if ((rounded_rate == bus->min_rate) && (rate > bus->min_rate)) {
			seq_printf(s, "... %lu ", end_rate / 1000);
			break;
		}

		rate = rounded_rate + 2000;	/* 2kHz resolution */
		seq_printf(s, "%ld ", rounded_rate / 1000);
	}
	seq_printf(s, "(kHz)\n");
	return 0;
}

static int possible_rates_open(struct inode *inode, struct file *file)
{
	return single_open(file, possible_rates_show, inode->i_private);
}

static const struct file_operations possible_rates_fops = {
	.open		= possible_rates_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int clk_shared_debug(struct clk_hw *hw, struct dentry *dir)
{
	struct dentry *d;
	struct tegra_clk_cbus_shared *shared = to_clk_cbus_shared(hw);

	d = debugfs_create_x32("clk_shared_bus_flags", S_IRUGO, dir,
			&shared->flags);
	if (!d)
		return -EINVAL;

	d = debugfs_create_file("clk_possible_rates", S_IRUGO, dir,
			hw, &possible_rates_fops);
	if (!d)
		return -EINVAL;

	return 0;
}

#ifdef CONFIG_TEGRA_CLK_DEBUG
static int pass_thru_get(void *data, u64 *val)
{
	*val = *((u32 *)data) & TEGRA_SHARED_BUS_ROUND_PASS_THRU ? 1 : 0;
	return 0;
}

static int pass_thru_set(void *data, u64 val)
{
	if (val)
		*((u32 *)data) |= TEGRA_SHARED_BUS_ROUND_PASS_THRU;
	else
		*((u32 *)data) &= ~TEGRA_SHARED_BUS_ROUND_PASS_THRU;
	return 0;
}


DEFINE_SIMPLE_ATTRIBUTE(pass_thru_fops, pass_thru_get, pass_thru_set, "%llu\n");

static void add_pass_thru_file(struct clk *c)
{
	struct tegra_clk_cbus_shared *bus = to_clk_cbus_shared(__clk_get_hw(c));

	struct dentry *d = __clk_debugfs_add_file(c, "clk_round_pass_thru",
		S_IRUGO | S_IWUGO, &bus->flags, &pass_thru_fops);

	if ((IS_ERR(d) && PTR_ERR(d) != -EAGAIN) || !d)
		pr_err("debugfs round_pass_thru failed %s\n",
		       __clk_get_name(c));
}
#else
static void add_pass_thru_file(struct clk *c)
{ }
#endif

static const struct clk_ops tegra_clk_system_ops = {
	.recalc_rate = clk_system_recalc_rate,
	.round_rate = clk_system_round_rate,
	.set_rate = clk_system_set_rate,
	.debug_init = clk_shared_debug,
};

static const struct clk_ops tegra_clk_cbus_ops = {
	.recalc_rate = clk_cbus_recalc_rate,
	.round_rate = clk_cbus_round_rate,
	.set_rate = clk_cbus_set_rate,
	.prepare = clk_cbus_prepare,
	.unprepare = clk_cbus_unprepare,
	.debug_init = clk_shared_debug,
};

static const struct clk_ops tegra_clk_shared_ops = {
	.prepare = clk_shared_prepare,
	.unprepare = clk_shared_unprepare,
	.set_rate = clk_shared_set_rate,
	.round_rate = clk_shared_round_rate,
	.recalc_rate = clk_shared_recalc_rate,
};

static const struct clk_ops tegra_clk_gbus_ops = {
	.prepare = clk_gbus_prepare,
	.unprepare = clk_gbus_unprepare,
	.recalc_rate = clk_cbus_recalc_rate,	/* re-used */
	.round_rate = clk_cbus_round_rate,	/* re-used */
	.set_rate = clk_gbus_set_rate,
	.debug_init = clk_shared_debug,
};

static const struct clk_ops tegra_clk_shared_master_ops = {
	.debug_init = clk_shared_debug,
};

static const struct clk_ops tegra_clk_shared_connect_master_ops = {
	.prepare = clk_shared_connect_master_prepare,
	.unprepare = clk_shared_connect_master_unprepare,
};

static const struct clk_ops tegra_clk_cascade_master_ops = {
	.prepare = clk_shared_prepare,
	.unprepare = clk_shared_unprepare,
	.set_rate = clk_shared_set_rate,
	.round_rate = clk_shared_round_rate,
	.recalc_rate = clk_cascade_master_recalc_rate,
};

struct clk *tegra_clk_register_sbus_cmplx(const char *name,
		const char *parent, const char *mux_clk, const char *div_clk,
		unsigned long flags, const char *pclk, const char *hclk,
		const char *sclk_low, const char *sclk_high,
		unsigned long threshold, unsigned long min_rate,
		unsigned long max_rate)
{
	struct clk *parent_clk, *c;
	struct clk_init_data init;
	struct tegra_clk_cbus_shared *system;

	system = kzalloc(sizeof(*system), GFP_KERNEL);
	if (!system)
		return ERR_PTR(-ENOMEM);

	parent_clk = __clk_lookup(parent);

	if (IS_ERR(parent_clk)) {
		kfree(system);
		return parent_clk;
	}

	c = __clk_lookup(mux_clk);
	if (IS_ERR(c)) {
		kfree(system);
		return c;
	}
	system->u.system.mux_clk = __clk_get_hw(c);
	c = __clk_lookup(pclk);
	if (IS_ERR(c)) {
		kfree(system);
		return c;
	}
	system->u.system.pclk = __clk_get_hw(c);
	c = __clk_lookup(hclk);
	if (IS_ERR(c)) {
		kfree(system);
		return c;
	}
	system->u.system.hclk = __clk_get_hw(c);
	c = __clk_lookup(sclk_low);
	if (IS_ERR(c)) {
		kfree(system);
		return c;
	}
	system->u.system.sclk_low = __clk_get_hw(c);
	c = __clk_lookup(sclk_high);
	if (IS_ERR(c)) {
		kfree(system);
		return c;
	}
	system->u.system.sclk_high = __clk_get_hw(c);

	if (div_clk) {
		c = __clk_lookup(div_clk);
		if (IS_ERR(c)) {
			kfree(system);
			return c;
		}
		system->u.system.div_clk = __clk_get_hw(c);
	} else {
		system->u.system.div_clk = __clk_get_hw(parent_clk);
	}

	system->u.system.threshold = threshold;

	system->min_rate = min_rate;
	system->max_rate = max_rate;
	system->bus_update = _sbus_update;

	INIT_LIST_HEAD(&system->shared_bus_list);

	flags |= CLK_GET_RATE_NOCACHE;

	init.name = name;
	init.ops = &tegra_clk_system_ops;
	init.flags = flags;
	init.parent_names = &parent;
	init.num_parents = 1;

	system->hw.init = &init;

	c = clk_register(NULL, &system->hw);
	if (!c) {
		kfree(system);
		return c;
	}

	register_bus_clk_notifier(c);
	return c;
}

struct clk *tegra_clk_register_cbus(const char *name,
		const char *parent, unsigned long flags,
		const char *backup, unsigned long min_rate,
		unsigned long max_rate)
{
	struct tegra_clk_cbus_shared *cbus;
	struct clk_init_data init;
	struct clk *backup_clk, *c;

	cbus = kzalloc(sizeof(*cbus), GFP_KERNEL);
	if (!cbus)
		return ERR_PTR(-ENOMEM);

	backup_clk = __clk_lookup(backup);
	if (IS_ERR(backup_clk)) {
		kfree(cbus);
		return backup_clk;
	}

	cbus->shared_bus_backup = backup_clk;
	cbus->min_rate = min_rate;
	cbus->max_rate = max_rate;
	cbus->bus_update = _simple_shared_update;
	cbus->flags = flags;

	INIT_LIST_HEAD(&cbus->shared_bus_list);

	init.name = name;
	init.ops = &tegra_clk_cbus_ops;
	init.flags = CLK_GET_RATE_NOCACHE;
	init.parent_names = &parent;
	init.num_parents = 1;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	cbus->hw.init = &init;

	c = clk_register(NULL, &cbus->hw);
	if (!c) {
		kfree(cbus);
		return c;
	}

	register_bus_clk_notifier(c);
	return c;
}

static struct tegra_clk_cbus_shared *tegra_clk_init_shared(const char *name,
		const char **parent, u8 num_parents, unsigned long flags,
		enum shared_bus_users_mode mode, const char *client)
{
	struct tegra_clk_cbus_shared *shared;
	struct tegra_clk_cbus_shared *parent_cbus;
	struct clk *client_clk, *parent_clk;

	if (num_parents > 2)
		return ERR_PTR(-EINVAL);

	parent_clk = __clk_lookup(parent[0]);
	if (IS_ERR_OR_NULL(parent_clk)) {
		/* Warning as clocks might be registered in a wrong order */
		WARN_ON(!parent_clk);
		pr_err("%s: failed to lookup parent clock (%s): %ld\n",
		       __func__, parent[0], PTR_ERR(parent_clk));
		return ERR_PTR(-EINVAL);
	}

	parent_cbus = to_clk_cbus_shared(__clk_get_hw(parent_clk));

	shared = kzalloc(sizeof(*shared), GFP_KERNEL);
	if (!shared)
		return ERR_PTR(-ENOMEM);

	if (client) {
		client_clk = __clk_lookup(client);
		if (IS_ERR(client_clk)) {
			kfree(shared);
			return ERR_PTR(PTR_ERR(client_clk));
		}
		shared->u.shared_bus_user.client = client_clk;
		shared->magic = TEGRA_CLK_SHARED_MAGIC;
		flags |= TEGRA_SHARED_BUS_RACE_TO_SLEEP;
	}

	shared->u.shared_bus_user.mode = mode;
	if (mode == SHARED_CEILING)
		shared->u.shared_bus_user.rate = parent_cbus->max_rate;
	else {
		shared->u.shared_bus_user.rate = clk_get_rate(parent_clk);
		/* If bus parent is not registered yet set default rate */
		if (!clk_get_parent(parent_clk))
			shared->u.shared_bus_user.rate =
				parent_cbus->users_default_rate;
	}

	shared->flags = flags;

	if (num_parents > 1) {
		struct clk *c = __clk_lookup(parent[1]);

		if (IS_ERR(c)) {
			kfree(shared);
			return ERR_PTR(PTR_ERR(c));
		}

		shared->u.shared_bus_user.inputs[0] = parent_clk;
		shared->u.shared_bus_user.inputs[1] = c;
	}
	shared->max_rate = parent_cbus->max_rate;

	INIT_LIST_HEAD(&shared->u.shared_bus_user.node);

	list_add_tail(&shared->u.shared_bus_user.node,
			&parent_cbus->shared_bus_list);

	return shared;
}

struct clk *tegra_clk_register_shared(const char *name,
		const char **parent, u8 num_parents, unsigned long flags,
		enum shared_bus_users_mode mode, const char *client)
{
	struct tegra_clk_cbus_shared *shared;
	struct clk_init_data init;
	struct clk *c;

	shared = tegra_clk_init_shared(name, parent, num_parents, flags,
				       mode, client);
	if (IS_ERR(shared))
		return ERR_PTR(PTR_ERR(shared));

	init.name = name;
	init.ops = &tegra_clk_shared_ops;
	init.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_NOCACHE;
	init.parent_names = parent;
	init.num_parents = 1;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	shared->hw.init = &init;

	c = clk_register(NULL, &shared->hw);
	if (!c)
		kfree(shared);

	return c;
}

struct clk *tegra_clk_register_shared_connect(const char *name,
		const char **parent, u8 num_parents, unsigned long flags,
		enum shared_bus_users_mode mode, const char *client)
{
	struct tegra_clk_cbus_shared *shared;
	struct clk_init_data init;
	struct clk *c;

	shared = tegra_clk_init_shared(name, parent, num_parents, flags,
				       mode, client);
	if (IS_ERR(shared))
		return ERR_PTR(PTR_ERR(shared));

	INIT_LIST_HEAD(&shared->shared_bus_list);

	init.name = name;
	init.ops = &tegra_clk_shared_connect_master_ops;
	init.flags = CLK_SET_RATE_PARENT | CLK_GET_RATE_NOCACHE
			| CLK_SET_RATE_NOCACHE;
	init.parent_names = parent;
	init.num_parents = 1;

	shared->bus_update = _connect_shared_update;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	shared->hw.init = &init;

	c = clk_register(NULL, &shared->hw);
	if (!c) {
		kfree(shared);
		return c;
	}

	register_bus_clk_notifier(c);
	return c;
}

struct clk *tegra_clk_register_gbus(const char *name,
		const char *parent, unsigned long flags,
		unsigned long min_rate, unsigned long max_rate)
{
	struct tegra_clk_cbus_shared *master;
	struct clk_init_data init;
	struct clk *c;

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&master->shared_bus_list);

	init.name = name;
	init.ops = &tegra_clk_gbus_ops;
	init.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_NOCACHE;
	init.parent_names = &parent;
	init.num_parents = 1;

	master->min_rate = min_rate;
	master->max_rate = max_rate;
	master->bus_update = _simple_shared_update;
	master->flags = flags;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	master->hw.init = &init;

	c = clk_register(NULL, &master->hw);
	if (!c) {
		kfree(master);
		return c;
	}

	register_bus_clk_notifier(c);
	add_pass_thru_file(c);
	return c;
}

/*
 * Not all shared clocks have a cbus clock as parent. The parent clock however
 * provides the head of the shared clock list. This clock provides a placeholder
 * for the head.
*/
struct clk *tegra_clk_register_shared_master(const char *name,
		const char *parent, unsigned long flags,
		unsigned long min_rate, unsigned long max_rate)
{
	struct tegra_clk_cbus_shared *master;
	struct clk_init_data init;
	struct clk *c;

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&master->shared_bus_list);

	init.name = name;
	init.ops = &tegra_clk_shared_master_ops;
	init.flags = CLK_SET_RATE_PARENT | CLK_GET_RATE_NOCACHE;
	init.parent_names = &parent;
	init.num_parents = 1;

	master->min_rate = min_rate;
	master->max_rate = max_rate;
	master->bus_update = _simple_shared_update;
	master->flags = flags;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	master->hw.init = &init;

	c = clk_register(NULL, &master->hw);
	if (!c) {
		kfree(master);
		return c;
	}

	register_bus_clk_notifier(c);
	return c;
}

struct clk *tegra_clk_register_cascade_master(const char *name,
		const char *parent, const char *sbusclkname,
		unsigned long flags)
{
	struct tegra_clk_cbus_shared *cascade_master, *parent_cbus;
	struct clk_init_data init;
	struct clk *c, *parent_clk, *sbus_clk = NULL;

	parent_clk = __clk_lookup(parent);
	if (IS_ERR(parent_clk))
		return parent_clk;

	if (sbusclkname) {
		sbus_clk = __clk_lookup(sbusclkname);
		if (IS_ERR(sbus_clk))
			return sbus_clk;
	}

	parent_cbus = to_clk_cbus_shared(__clk_get_hw(parent_clk));

	cascade_master = kzalloc(sizeof(*cascade_master), GFP_KERNEL);
	if (!cascade_master)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&cascade_master->shared_bus_list);

	INIT_LIST_HEAD(&cascade_master->u.shared_bus_user.node);

	list_add_tail(&cascade_master->u.shared_bus_user.node,
			&parent_cbus->shared_bus_list);

	init.name = name;
	init.ops = &tegra_clk_cascade_master_ops;
	init.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_NOCACHE;
 
	init.parent_names = &parent;
	init.num_parents = 1;

	cascade_master->bus_update = _simple_shared_update;
	cascade_master->u.shared_bus_user.rate = clk_get_rate(parent_clk);
	cascade_master->top_clk = sbus_clk;
	cascade_master->min_rate = parent_cbus->min_rate;
	cascade_master->max_rate = parent_cbus->max_rate;
	if (sbusclkname)
		cascade_master->max_rate /= 2;

	cascade_master->flags = flags;

	/* Data in .init is copied by clk_register(), so stack variable OK */
	cascade_master->hw.init = &init;

	c = clk_register(NULL, &cascade_master->hw);
	if (!c) {
		kfree(cascade_master);
		return c;
	}

	/* Adjust for possible divider from parent */
	cascade_master->u.shared_bus_user.rate = clk_get_rate(c);

	register_bus_clk_notifier(c);
	return c;
}
