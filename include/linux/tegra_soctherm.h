/*
 * include/linux/tegra_soctherm.h
 *
 * Copyright (c) 2011-2017, NVIDIA CORPORATION. All rights reserved.
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

#ifndef __TEGRA_SOCTHERM_H
#define __TEGRA_SOCTHERM_H

void tegra_soctherm_gpu_tsens_invalidate(bool control);
void tegra_soctherm_cpu_tsens_invalidate(bool control);

#endif /* __TEGRA_SOCTHERM_H */
