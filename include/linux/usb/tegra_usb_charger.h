/*
 * Copyright (c) 2017, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef __TEGRA_USB_CHARGER_H
#define __TEGRA_USB_CHARGER_H

#include <linux/platform_device.h>

/**
 * Tegra USB charger opaque handle
 */
struct tegra_usb_cd;

#if IS_ENABLED(CONFIG_USB_TEGRA_CD)

/**
 * Returns USB charger detection handle given a platform_device handle
 */
struct tegra_usb_cd *tegra_usb_get_ucd(struct platform_device *pdev);

/**
 * Releases USB charger detection handle.
 */
extern void tegra_usb_release_ucd(struct tegra_usb_cd *ucd);

/**
 * Detects the USB charger and returns the type.
 */
extern unsigned int
	tegra_ucd_detect_cable_and_set_current(struct tegra_usb_cd *ucd);

/**
 * Set custom USB charging current.
 */
extern void tegra_ucd_set_current(struct tegra_usb_cd *ucd, int current_ma);

/**
 * Set USB charging current for SDP, CDP as per gadget driver.
 */
extern void tegra_ucd_set_sdp_cdp_current(struct tegra_usb_cd *ucd,
		int current_ma);

/**
 * Set custom USB charger type, this automatically sets the corresponding
 * charging current.
 */
void tegra_ucd_set_charger_type(struct tegra_usb_cd *ucd,
			unsigned int connect_type);
#else /* CONFIG_USB_TEGRA_CD */

struct tegra_usb_cd *tegra_usb_get_ucd(struct platform_device *pdev)
{
	return ERR_PTR(-ENODEV);
}

void tegra_usb_release_ucd(struct tegra_usb_cd *ucd)
{
}

unsigned int
	tegra_ucd_detect_cable_and_set_current(struct tegra_usb_cd *ucd)
{
	return -EINVAL;
}

void tegra_ucd_set_current(struct tegra_usb_cd *ucd, int current_ma)
{
}

void tegra_ucd_set_sdp_cdp_current(struct tegra_usb_cd *ucd, int current_ma)
{
}

void tegra_ucd_set_charger_type(struct tegra_usb_cd *ucd,
			unsigned int connect_type)
{
}
#endif /* CONFIG_USB_TEGRA_CD */
#endif /* __TEGRA_USB_CHARGER_H */
