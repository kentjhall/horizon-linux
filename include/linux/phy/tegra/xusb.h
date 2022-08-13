/*
 * Copyright (c) 2016-2018, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef PHY_TEGRA_XUSB_H
#define PHY_TEGRA_XUSB_H

struct tegra_xusb_padctl;
struct device;
enum usb_device_speed;

/*
 * Tegra OTG port VBUS direction:
 * default (based on port capability) or
 * as source or sink
 */
enum tegra_vbus_dir {
	TEGRA_VBUS_DEFAULT,
	TEGRA_VBUS_SOURCE,
	TEGRA_VBUS_SINK
};
struct phy;

#define XUSB_MAX_OTG_PORT_NUM	4

struct tegra_xusb_padctl *tegra_xusb_padctl_get(struct device *dev);
void tegra_xusb_padctl_put(struct tegra_xusb_padctl *padctl);

int tegra_xusb_padctl_usb3_save_context(struct tegra_xusb_padctl *padctl,
					unsigned int port);
int tegra_xusb_padctl_hsic_set_idle(struct tegra_xusb_padctl *padctl,
				    unsigned int port, bool idle);
int tegra_xusb_padctl_hsic_reset(struct tegra_xusb_padctl *padctl,
				unsigned int port);
int tegra_xusb_padctl_usb3_set_lfps_detect(struct tegra_xusb_padctl *padctl,
					   unsigned int port, bool enable);
int tegra_xusb_padctl_set_vbus_override_early(struct tegra_xusb_padctl *padctl,
				unsigned int i);
int tegra_xusb_padctl_set_vbus_override(struct tegra_xusb_padctl *padctl,
				unsigned int i);
int tegra_xusb_padctl_clear_vbus_override(struct tegra_xusb_padctl *padctl,
				unsigned int i);
int tegra_xusb_padctl_set_id_override(struct tegra_xusb_padctl *padctl,
				unsigned int i);
int tegra_xusb_padctl_clear_id_override(struct tegra_xusb_padctl *padctl,
				unsigned int i);
bool tegra_xusb_padctl_has_otg_cap(struct tegra_xusb_padctl *padctl,
				struct phy *phy);

int tegra_xusb_padctl_vbus_power_on(struct tegra_xusb_padctl *padctl,
					unsigned int port);
int tegra_xusb_padctl_vbus_power_off(struct tegra_xusb_padctl *padctl,
					unsigned int port);

int tegra_xusb_padctl_enable_phy_sleepwalk(struct tegra_xusb_padctl *padctl,
					   struct phy *phy,
					   enum usb_device_speed speed);
int tegra_xusb_padctl_disable_phy_sleepwalk(struct tegra_xusb_padctl *padctl,
					   struct phy *phy);
int tegra_xusb_padctl_enable_phy_wake(struct tegra_xusb_padctl *padctl,
				      struct phy *phy);
int tegra_xusb_padctl_disable_phy_wake(struct tegra_xusb_padctl *padctl,
				       struct phy *phy);
int tegra_xusb_padctl_remote_wake_detected(struct tegra_xusb_padctl *padctl,
					struct phy *phy);
void tegra_phy_xusb_utmi_pad_power_on(struct phy *phy);
void tegra_phy_xusb_utmi_pad_power_down(struct phy *phy);
int tegra_phy_xusb_utmi_port_reset_quirk(struct phy *phy);
int tegra_xusb_padctl_set_dcd_debounce_time(struct tegra_xusb_padctl *padctl,
					struct phy *phy, u32 val);
int tegra_xusb_padctl_utmi_pad_charger_detect_on(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_utmi_pad_charger_detect_off(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_utmi_pad_enable_detect_filters(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_utmi_pad_disable_detect_filters(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_utmi_pad_set_protection_level(
				struct tegra_xusb_padctl *padctl,
				struct phy *phy, int level,
				enum tegra_vbus_dir dir);
int tegra_xusb_padctl_utmi_pad_dcd(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_noncompliant_div_detect(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_utmi_pad_primary_charger_detect(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_utmi_pad_secondary_charger_detect(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_enable_host_cdp(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_disable_host_cdp(struct tegra_xusb_padctl
					*padctl, struct phy *phy);
int tegra_xusb_padctl_overcurrent_detected(struct tegra_xusb_padctl *padctl,
					struct phy *phy);
void tegra_xusb_padctl_handle_overcurrent(struct tegra_xusb_padctl *padctl);
int tegra_xusb_padctl_get_vbus_id_num(struct tegra_xusb_padctl *padctl);
void tegra_xusb_padctl_get_vbus_id_ports(struct tegra_xusb_padctl *padctl,
	int i, int *usb2_port, int *usb3_port);
int tegra_xusb_padctl_usb3_port_gen1_only(struct phy *phy, bool on);

#endif /* PHY_TEGRA_XUSB_H */
