/*
 * Copyright (c) 2017-2018, NVIDIA Corporation. All rights reserved.
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
#ifndef __TEGRA_USB_CD_H
#define __TEGRA_USB_CD_H

#include <linux/phy/phy.h>
#include <linux/usb/tegra_usb_charger.h>
#include <linux/device.h>
#include <linux/phy/tegra/xusb.h>

/* Charger current limits, as per BC1.2 spec */
#define USB_CHARGING_DCP_CURRENT_LIMIT_UA 1500000u
#define USB_CHARGING_CDP_CURRENT_LIMIT_UA 1500000u
#define USB_CHARGING_SDP_CURRENT_LIMIT_UA 900000u
#define USB_CHARGING_NON_STANDARD_CHARGER_CURRENT_LIMIT_UA 500000u
#define USB_CHARGING_APPLE_CHARGER_500mA_CURRENT_LIMIT_UA 500000u
#define USB_CHARGING_APPLE_CHARGER_1000mA_CURRENT_LIMIT_UA 1000000u
#define USB_CHARGING_APPLE_CHARGER_2000mA_CURRENT_LIMIT_UA 2000000u

struct tegra_usb_cd;

struct tegra_usb_cd_ops {
	int     (*init)(struct tegra_usb_cd *ucd);
	int     (*open)(struct tegra_usb_cd *ucd);
	int     (*close)(struct tegra_usb_cd *ucd);
	int     (*power_on)(struct tegra_usb_cd *ucd);
	int     (*power_off)(struct tegra_usb_cd *ucd);
	int     (*suspend)(struct tegra_usb_cd *ucd);
	int     (*resume)(struct tegra_usb_cd *ucd);
	bool    (*dcp_cd)(struct tegra_usb_cd *ucd);
	bool    (*cdp_cd)(struct tegra_usb_cd *ucd);
	bool    (*qc2_cd)(struct tegra_usb_cd *ucd);
	bool    (*maxim14675_cd)(struct tegra_usb_cd *ucd);
	int     (*apple_cd)(struct tegra_usb_cd *ucd);
	void	(*vbus_pad_protection)(struct tegra_usb_cd *ucd, bool enable);
};

struct tegra_usb_cd {
	struct device *dev;
	struct tegra_usb_cd_ops *hw_ops;
	struct extcon_dev *edev;
	struct regulator *vbus_reg;
	struct phy *phy;
	struct tegra_xusb_padctl *padctl;
	int open_count;
	unsigned int connect_type;
	u32 sdp_cdp_current_limit_ma;
	u32 current_limit_ma;
	u32 dcp_current_limit_ma;
	u32 qc2_current_limit_ma;
	u32 qc2_voltage;
};

struct tegra_usb_cd_soc_data {
	int (*init_hw_ops)(struct tegra_usb_cd *ucd);
};

enum tegra_usb_cd_apple_chargers {
	APPLE_500MA,
	APPLE_1000MA,
	APPLE_2000MA,
};

int tegra_usb_cd_init_ops(struct tegra_usb_cd *ucd);

#endif /* __TEGRA_USB_CD_H */
