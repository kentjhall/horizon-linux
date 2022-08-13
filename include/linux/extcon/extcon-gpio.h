/*
 * Single-state GPIO extcon driver based on extcon class
 *
 * Copyright (C) 2012 Samsung Electronics
 * Author: MyungJoo Ham <myungjoo.ham@samsung.com>
 *
 * based on switch class driver
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __EXTCON_GPIO_H__
#define __EXTCON_GPIO_H__ __FILE__

#include <linux/extcon.h>

/**
 * struct gpio_extcon_pdata - A simple GPIO-controlled extcon device.
 * @name:		The name of this GPIO extcon device.
 * @supported_cable:	Array of supported cable names ending with EXTCON_NONE.
 * @gpio:		Corresponding GPIO.
 * @gpio_active_low:	Boolean describing whether gpio active state is 1 or 0
 *			If true, low state of gpio means active.
 *			If false, high state of gpio means active.
 * @debounce:		Debounce time for GPIO IRQ in ms.
 * @irq_flags:		IRQ Flags (e.g., IRQF_TRIGGER_LOW).
 * @default_state: Default state of the connection if gpio is not provided.
 * @check_on_resume:	Boolean describing whether to check the state of gpio
 *			while resuming from sleep.
 */
struct gpio_extcon_pdata {
	const char *name;
	unsigned int supported_cable[2];
	int gpio;
	bool gpio_active_low;
	unsigned long debounce;
	unsigned long irq_flags;
	bool default_state;

	bool check_on_resume;
};

#endif /* __EXTCON_GPIO_H__ */
