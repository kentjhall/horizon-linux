
/*
 * include/linux/extcon/extcon-disp.h
 *
 * extcon driver for display accessory detection compatible with switch-mid
 *
 * Copyright (c) 2018, NVIDIA CORPORATION, All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _EXTCON_DISP_H_
#define _EXTCON_DISP_H_ __FILE__

#include <linux/module.h>
#include <linux/extcon.h>

#define EXTCON_DISP_HPD_STATE_DISABLED	false
#define EXTCON_DISP_HPD_STATE_ENABLED	true
#define EXTCON_DISP_AUX_STATE_DISABLED	false
#define EXTCON_DISP_AUX_STATE_ENABLED	true

#ifdef CONFIG_EXTCON_DISP_STATE
/**
 * disp_state_extcon_switch_report() - Report the state of external
 * connector to extcon driver.
 * @cable:	Cable for which state is reported.
 * @state:	Reported state of cable
 */
void disp_state_extcon_switch_report(const unsigned int cable, bool state);
/**
 * disp_state_extcon_aux_report() - Wrapper on extcon switch report function
 * to facilitate reporting aux connectors by their instance id.
 * @aux_idx:	Audio connector instance for which state is reported
 * @state:		Reported state of cable
 */
void disp_state_extcon_aux_report(const unsigned int aux_idx, bool state);
#else
static inline void disp_state_extcon_switch_report(const unsigned int cable,
	bool state) { return; }
static inline void disp_state_extcon_aux_report(const unsigned int aux_idx,
	bool state) { return; }
#endif

#endif /* _EXTCON_DISP_H */
