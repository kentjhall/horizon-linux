/*
 * Copyright (c) 2016, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __SOC_TEGRA_DOORBELL_H__
#define __SOC_TEGRA_DOORBELL_H__

int tegra_ring_doorbell(unsigned int doorbell_id);
int tegra_register_doorbell_handler(unsigned int doorbell_id,
                                    void (*handler)(void *data),
                                    void *data);

#endif
