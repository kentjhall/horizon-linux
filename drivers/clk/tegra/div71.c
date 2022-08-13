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

#include <linux/kernel.h>

#include "clk.h"

#define div_mask(w) ((1 << (w)) - 1)

int div71_get(unsigned long rate, unsigned parent_rate, u8 width,
	      u8 frac_width, u8 flags)
{
	s64 divider_ux1 = parent_rate;
	int mul;

	if (!rate)
		return div_mask(width);

	mul = 1 << frac_width;

	if (!(flags & TEGRA_DIVIDER_INT))
		divider_ux1 *= mul;

	if (flags & TEGRA_DIVIDER_ROUND_UP)
		divider_ux1 += rate - 1;

	do_div(divider_ux1, rate);

	if (flags & TEGRA_DIVIDER_INT)
		divider_ux1 *= mul;

	divider_ux1 -= mul;

	if (divider_ux1 > div_mask(width))
		return div_mask(width);

	if (div1_5_not_allowed && (divider_ux1 > 0) && (divider_ux1 < mul))
		divider_ux1 = (flags & TEGRA_DIVIDER_ROUND_UP) ? mul : 0;

	return divider_ux1;
}
