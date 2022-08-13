/*
 * Copyright (c) 2014-2021, NVIDIA CORPORATION.  All rights reserved.
 * Copyright (c) 2015, Google Inc.
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

#ifndef __PHY_TEGRA_XUSB_H
#define __PHY_TEGRA_XUSB_H

#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/usb/ch9.h>
#include <linux/phy/tegra/xusb.h>

/* legacy entry points for backwards-compatibility */
int tegra_xusb_padctl_legacy_probe(struct platform_device *pdev);
int tegra_xusb_padctl_legacy_remove(struct platform_device *pdev);

struct phy;
struct phy_provider;
struct platform_device;
struct regulator;

/*
 * lanes
 */
struct tegra_xusb_lane_soc {
	const char *name;

	unsigned int offset;
	unsigned int shift;
	unsigned int mask;

	const char * const *funcs;
	unsigned int num_funcs;
};

struct tegra_xusb_lane {
	const struct tegra_xusb_lane_soc *soc;
	struct tegra_xusb_pad *pad;
	struct device_node *np;
	struct list_head list;
	unsigned int function;
	unsigned int index;
};

int tegra_xusb_lane_parse_dt(struct tegra_xusb_lane *lane,
			     struct device_node *np);

struct tegra_xusb_usb3_lane {
	struct tegra_xusb_lane base;
};

static inline struct tegra_xusb_usb3_lane *
to_usb3_lane(struct tegra_xusb_lane *lane)
{
	return container_of(lane, struct tegra_xusb_usb3_lane, base);
}

struct tegra_xusb_usb2_lane {
	struct tegra_xusb_lane base;

	s32 hs_curr_level_offset;
	bool powered_on;
};

static inline struct tegra_xusb_usb2_lane *
to_usb2_lane(struct tegra_xusb_lane *lane)
{
	return container_of(lane, struct tegra_xusb_usb2_lane, base);
}

struct tegra_xusb_ulpi_lane {
	struct tegra_xusb_lane base;
};

static inline struct tegra_xusb_ulpi_lane *
to_ulpi_lane(struct tegra_xusb_lane *lane)
{
	return container_of(lane, struct tegra_xusb_ulpi_lane, base);
}

struct tegra_xusb_hsic_lane {
	struct tegra_xusb_lane base;

	u32 strobe_trim;
	u32 rx_strobe_trim;
	u32 rx_data_trim;
	u32 tx_rtune_n;
	u32 tx_rtune_p;
	u32 tx_rslew_n;
	u32 tx_rslew_p;
	bool auto_term;
};

static inline struct tegra_xusb_hsic_lane *
to_hsic_lane(struct tegra_xusb_lane *lane)
{
	return container_of(lane, struct tegra_xusb_hsic_lane, base);
}

struct tegra_xusb_pcie_lane {
	struct tegra_xusb_lane base;
};

static inline struct tegra_xusb_pcie_lane *
to_pcie_lane(struct tegra_xusb_lane *lane)
{
	return container_of(lane, struct tegra_xusb_pcie_lane, base);
}

struct tegra_xusb_sata_lane {
	struct tegra_xusb_lane base;
};

static inline struct tegra_xusb_sata_lane *
to_sata_lane(struct tegra_xusb_lane *lane)
{
	return container_of(lane, struct tegra_xusb_sata_lane, base);
}

struct tegra_xusb_lane_ops {
	struct tegra_xusb_lane *(*probe)(struct tegra_xusb_pad *pad,
					 struct device_node *np,
					 unsigned int index);
	void (*remove)(struct tegra_xusb_lane *lane);
};

bool tegra_xusb_lane_check(struct tegra_xusb_lane *lane,
				  const char *function);
/*
 * pads
 */
struct tegra_xusb_pad_soc;
struct tegra_xusb_padctl;

struct tegra_xusb_pad_ops {
	struct tegra_xusb_pad *(*probe)(struct tegra_xusb_padctl *padctl,
					const struct tegra_xusb_pad_soc *soc,
					struct device_node *np);
	void (*remove)(struct tegra_xusb_pad *pad);
};

struct tegra_xusb_pad_soc {
	const char *name;

	const struct tegra_xusb_lane_soc *lanes;
	unsigned int num_lanes;

	const struct tegra_xusb_pad_ops *ops;
};

struct tegra_xusb_pad {
	const struct tegra_xusb_pad_soc *soc;
	struct tegra_xusb_padctl *padctl;
	struct phy_provider *provider;
	struct phy **lanes;
	struct device dev;

	const struct tegra_xusb_lane_ops *ops;

	struct list_head list;
};

static inline struct tegra_xusb_pad *to_tegra_xusb_pad(struct device *dev)
{
	return container_of(dev, struct tegra_xusb_pad, dev);
}

int tegra_xusb_pad_init(struct tegra_xusb_pad *pad,
			struct tegra_xusb_padctl *padctl,
			struct device_node *np);
int tegra_xusb_pad_register(struct tegra_xusb_pad *pad,
			    const struct phy_ops *ops);
void tegra_xusb_pad_unregister(struct tegra_xusb_pad *pad);

struct tegra_xusb_usb3_pad {
	struct tegra_xusb_pad base;

	unsigned int enable;
	struct mutex lock;
};

static inline struct tegra_xusb_usb3_pad *
to_usb3_pad(struct tegra_xusb_pad *pad)
{
	return container_of(pad, struct tegra_xusb_usb3_pad, base);
}

struct tegra_xusb_usb2_pad {
	struct tegra_xusb_pad base;

	struct clk *clk;
	unsigned int enable;
	struct mutex lock;
};

static inline struct tegra_xusb_usb2_pad *
to_usb2_pad(struct tegra_xusb_pad *pad)
{
	return container_of(pad, struct tegra_xusb_usb2_pad, base);
}

struct tegra_xusb_ulpi_pad {
	struct tegra_xusb_pad base;
};

static inline struct tegra_xusb_ulpi_pad *
to_ulpi_pad(struct tegra_xusb_pad *pad)
{
	return container_of(pad, struct tegra_xusb_ulpi_pad, base);
}

struct tegra_xusb_hsic_pad {
	struct tegra_xusb_pad base;

	struct regulator *supply;
	struct clk *clk;
};

static inline struct tegra_xusb_hsic_pad *
to_hsic_pad(struct tegra_xusb_pad *pad)
{
	return container_of(pad, struct tegra_xusb_hsic_pad, base);
}

struct tegra_xusb_pcie_pad {
	struct tegra_xusb_pad base;

	struct reset_control *rst;
	struct clk *pll;

	unsigned int enable;
};

static inline struct tegra_xusb_pcie_pad *
to_pcie_pad(struct tegra_xusb_pad *pad)
{
	return container_of(pad, struct tegra_xusb_pcie_pad, base);
}

struct tegra_xusb_sata_pad {
	struct tegra_xusb_pad base;

	struct reset_control *rst;
	struct clk *pll;

	unsigned int enable;
};

static inline struct tegra_xusb_sata_pad *
to_sata_pad(struct tegra_xusb_pad *pad)
{
	return container_of(pad, struct tegra_xusb_sata_pad, base);
}

/*
 * ports
 */
struct tegra_xusb_port_ops;

struct tegra_xusb_port {
	struct tegra_xusb_padctl *padctl;
	struct tegra_xusb_lane *lane;
	unsigned int index;

	struct list_head list;
	struct device dev;

	const struct tegra_xusb_port_ops *ops;
};

struct tegra_xusb_lane_map {
	unsigned int port;
	const char *type;
	unsigned int index;
	const char *func;
};

struct tegra_xusb_lane *
tegra_xusb_port_find_lane(struct tegra_xusb_port *port,
			  const struct tegra_xusb_lane_map *map,
			  const char *function);

struct tegra_xusb_port *
tegra_xusb_find_port(struct tegra_xusb_padctl *padctl, const char *type,
		     unsigned int index);

enum tegra_xusb_usb_port_cap {
	USB_PORT_DISABLED = 0,
	USB_HOST_CAP,
	USB_DEVICE_CAP,
	USB_OTG_CAP,
};

struct tegra_xusb_usb2_port {
	struct tegra_xusb_port base;

	struct regulator *supply;
	bool internal;
	enum tegra_xusb_usb_port_cap port_cap;
	int oc_pin;
	int usb3_port_fake; /* only required for T210 device mode */
	int vbus_id;
	int hs_txeq;
};

static inline struct tegra_xusb_usb2_port *
to_usb2_port(struct tegra_xusb_port *port)
{
	return container_of(port, struct tegra_xusb_usb2_port, base);
}

struct tegra_xusb_usb2_port *
tegra_xusb_find_usb2_port(struct tegra_xusb_padctl *padctl,
			  unsigned int index);

struct tegra_xusb_ulpi_port {
	struct tegra_xusb_port base;

	struct regulator *supply;
	bool internal;
};

static inline struct tegra_xusb_ulpi_port *
to_ulpi_port(struct tegra_xusb_port *port)
{
	return container_of(port, struct tegra_xusb_ulpi_port, base);
}

struct tegra_xusb_hsic_port {
	struct tegra_xusb_port base;
};

static inline struct tegra_xusb_hsic_port *
to_hsic_port(struct tegra_xusb_port *port)
{
	return container_of(port, struct tegra_xusb_hsic_port, base);
}

struct tegra_xusb_hsic_port *
tegra_xusb_find_hsic_port(struct tegra_xusb_padctl *padctl, unsigned int index);

struct tegra_xusb_usb3_port {
	struct tegra_xusb_port base;
	bool context_saved;
	unsigned int port; /* port number of companion USB2 port */
	bool internal;
	enum tegra_xusb_usb_port_cap port_cap;
	int oc_pin;
	bool gen1_only;
	int vbus_id;

	u32 tap1;
	u32 amp;
	u32 ctle_z;
	u32 ctle_g;
};

static inline struct tegra_xusb_usb3_port *
to_usb3_port(struct tegra_xusb_port *port)
{
	return container_of(port, struct tegra_xusb_usb3_port, base);
}

struct tegra_xusb_usb3_port *
tegra_xusb_find_usb3_port(struct tegra_xusb_padctl *padctl,
			  unsigned int index);

struct tegra_xusb_port_ops {
	int (*enable)(struct tegra_xusb_port *port);
	void (*disable)(struct tegra_xusb_port *port);
	struct tegra_xusb_lane *(*map)(struct tegra_xusb_port *port);
};

/*
 * pad controller
 */
struct tegra_xusb_padctl_soc;

struct tegra_xusb_padctl_ops {
	struct tegra_xusb_padctl *
		(*probe)(struct device *dev,
			 const struct tegra_xusb_padctl_soc *soc);
	void (*remove)(struct tegra_xusb_padctl *padctl);
	int (*suspend_noirq)(struct tegra_xusb_padctl *padctl);
	int (*resume_noirq)(struct tegra_xusb_padctl *padctl);
	int (*usb3_save_context)(struct tegra_xusb_padctl *padctl,
				 unsigned int index);
	int (*hsic_set_idle)(struct tegra_xusb_padctl *padctl,
			     unsigned int index, bool idle);
	int (*hsic_reset)(struct tegra_xusb_padctl *padctl, unsigned int index);
	int (*usb3_set_lfps_detect)(struct tegra_xusb_padctl *padctl,
				    unsigned int index, bool enable);
	int (*vbus_override_early)(struct tegra_xusb_padctl *padctl,
				unsigned int i, bool set);
	int (*vbus_override)(struct tegra_xusb_padctl *padctl, unsigned int i,
				bool set);
	int (*id_override)(struct tegra_xusb_padctl *padctl, unsigned int i,
				bool set);
	bool (*has_otg_cap)(struct tegra_xusb_padctl *padctl, struct phy *phy);
	int (*vbus_power_on)(struct tegra_xusb_padctl *padctl,
				unsigned int index);
	int (*vbus_power_off)(struct tegra_xusb_padctl *padctl,
				unsigned int index);
	void (*otg_vbus_handle)(struct tegra_xusb_padctl *padctl,
				unsigned int vbus_id, unsigned int index);
	int (*phy_sleepwalk)(struct tegra_xusb_padctl *padctl, struct phy *phy,
			     bool enable, enum usb_device_speed speed);
	int (*phy_wake)(struct tegra_xusb_padctl *padctl, struct phy *phy,
			bool enable);
	int (*remote_wake_detected)(struct phy *phy);
	int (*set_debounce_time)(struct tegra_xusb_padctl *padctl,
				struct phy *phy, u32 val);
	int (*utmi_pad_charger_detect_on)(struct tegra_xusb_padctl *padctl,
				struct phy *phy);
	int (*utmi_pad_charger_detect_off)(struct tegra_xusb_padctl *padctl,
				struct phy *phy);
	int (*detect_filters)(struct tegra_xusb_padctl *padctl,
				struct phy *phy,
				bool on);
	int (*utmi_pad_set_protection_level)(struct tegra_xusb_padctl *padctl,
				struct phy *phy,
				int level,
				enum tegra_vbus_dir dir);
	int (*utmi_pad_dcd)(struct tegra_xusb_padctl *padctl,
				struct phy *phy);
	int (*noncompliant_div_detect)(struct tegra_xusb_padctl *padctl,
				struct phy *phy);
	int (*utmi_pad_primary_charger_detect)(struct tegra_xusb_padctl *padctl,
				struct phy *phy);
	int (*utmi_pad_secondary_charger_detect)(struct tegra_xusb_padctl
				*padctl, struct phy *phy);
	int (*set_host_cdp)(struct tegra_xusb_padctl *padctl, struct phy *phy,
				bool enable);
	int (*overcurrent_detected)(struct phy *phy);
	void (*handle_overcurrent)(struct tegra_xusb_padctl *padctl);
	void (*utmi_pad_power_on)(struct phy *phy);
	void (*utmi_pad_power_down)(struct phy *phy);
	int (*utmi_port_reset_quirk)(struct phy *phy);
	int (*usb3_port_gen1_only)(struct phy *phy, bool on);
};

struct tegra_xusb_padctl_soc {
	const struct tegra_xusb_pad_soc * const *pads;
	unsigned int num_pads;
	unsigned int num_oc_pins;

	struct {
		struct {
			const struct tegra_xusb_port_ops *ops;
			unsigned int count;
		} usb2, ulpi, hsic, usb3;
	} ports;

	const struct tegra_xusb_padctl_ops *ops;
	const char * const *supply_names;
	unsigned int num_supplies;
};

struct tegra_xusb_padctl {
	struct device *dev;
	void __iomem *regs;
	struct mutex lock;
	struct reset_control *rst;

	const struct tegra_xusb_padctl_soc *soc;

	struct tegra_xusb_pad *pcie;
	struct tegra_xusb_pad *sata;
	struct tegra_xusb_pad *ulpi;
	struct tegra_xusb_pad *usb2;
	struct tegra_xusb_pad *hsic;

	struct list_head ports;
	struct list_head lanes;
	struct list_head pads;

	unsigned int enable;

	struct clk *clk;

	/* vbus/id based OTG */
	int usb2_otg_port_base_1; /* one based usb2 port number */
	int usb3_otg_port_base_1; /* one based usb3 port number */
	struct work_struct otg_vbus_work;
	bool otg_vbus_updating[XUSB_MAX_OTG_PORT_NUM];
	int otg_vbus_usb2_port_base_1[XUSB_MAX_OTG_PORT_NUM];
	int otg_vbus_usb3_port_base_1[XUSB_MAX_OTG_PORT_NUM];
	bool otg_vbus_on[XUSB_MAX_OTG_PORT_NUM];
	bool otg_vbus_alwayson;
	int otg_port_num;

	bool cdp_used;
	bool is_xhci_iov;

	struct pinctrl *oc_pinctrl;
	/*
	 * array of pinctrl_state (of number num_oc_pins)
	 * for different OC states
	 */
	struct pinctrl_state **oc_tristate_enable;
	struct pinctrl_state **oc_passthrough_enable;
	struct pinctrl_state **oc_disable;

	struct regulator_bulk_data *supplies;
};

static inline void padctl_writel(struct tegra_xusb_padctl *padctl, u32 value,
				 unsigned long offset)
{
	dev_dbg(padctl->dev, "%08lx < %08x\n", offset, value);
	writel(value, padctl->regs + offset);
}

static inline u32 padctl_readl(struct tegra_xusb_padctl *padctl,
			       unsigned long offset)
{
	u32 value = readl(padctl->regs + offset);
	dev_dbg(padctl->dev, "%08lx > %08x\n", offset, value);
	return value;
}

static inline u32 padctl_readl_poll(struct tegra_xusb_padctl *padctl,
	unsigned long offset, u32 val, u32 mask, int us)
{
	u32 regval;
	int err;

	err = readl_poll_timeout_atomic(padctl->regs + offset, regval,
					 (regval & mask) == val, 1, us);
	dev_dbg(padctl->dev, "%08lx poll > %08x, %d\n", offset,
		regval, err);
	if (err) {
		dev_err(padctl->dev, "%08lx poll timeout > %08x\n", offset,
			regval);
	}

	return err;
}

struct tegra_xusb_lane *tegra_xusb_find_lane(struct tegra_xusb_padctl *padctl,
					     const char *name,
					     unsigned int index);

int tegra_xusb_select_vbus_en_state(struct tegra_xusb_padctl *padctl,
					   int pin, bool tristate);

#if defined(CONFIG_ARCH_TEGRA_124_SOC) || defined(CONFIG_ARCH_TEGRA_132_SOC)
extern const struct tegra_xusb_padctl_soc tegra124_xusb_padctl_soc;
#endif
#if defined(CONFIG_ARCH_TEGRA_210_SOC)
extern const struct tegra_xusb_padctl_soc tegra210_xusb_padctl_soc;
#endif
#if defined(CONFIG_ARCH_TEGRA_210_SOC)
extern const struct tegra_xusb_padctl_soc tegra210b01_xusb_padctl_soc;
#endif
#if defined(CONFIG_ARCH_TEGRA_18x_SOC)
extern const struct tegra_xusb_padctl_soc tegra186_xusb_padctl_soc;
#endif
#if defined(CONFIG_ARCH_TEGRA_19x_SOC)
extern const struct tegra_xusb_padctl_soc tegra194_xusb_padctl_soc;
#endif


#endif /* __PHY_TEGRA_XUSB_H */
