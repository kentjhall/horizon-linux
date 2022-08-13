/*
 * Copyright (c) 2019, NVIDIA CORPORATION.  All rights reserved.
 *
 * Author:
 *	Leon Yu <leoyu@nvidia.com>
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

/*
 * LED System Throttle Trigger
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/leds.h>

DEFINE_LED_TRIGGER(ledtrig_throttle);

void ledtrig_throttle_event(void)
{
	unsigned long blink_delay = 100;

	led_trigger_blink_oneshot(ledtrig_throttle, &blink_delay,
		&blink_delay, 1);
}
EXPORT_SYMBOL(ledtrig_throttle_event);

static int __init ledtrig_throttle_init(void)
{
	led_trigger_register_simple("system-throttle", &ledtrig_throttle);

	return 0;
}
device_initcall(ledtrig_throttle_init);
