/*
 * Copyright (c) 2016-2021, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/tegra-soc.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/slab.h>
#include <linux/tegra_prod.h>
#include <soc/tegra/fuse.h>

#include "xusb.h"

#define TEGRA186_USB3_PHYS	(3)
#define TEGRA186_UTMI_PHYS	(3)
#define TEGRA186_HSIC_PHYS	(1)
#define TEGRA186_OC_PIN_NUM	(2)

/* FUSE USB_CALIB registers */
#define   HS_CURR_LEVEL_PADX_SHIFT(x)		((x) ? (11 + (x - 1) * 6) : 0)
#define   HS_CURR_LEVEL_PAD_MASK		(0x3f)
#define   HS_TERM_RANGE_ADJ_SHIFT		(7)
#define   HS_TERM_RANGE_ADJ_MASK		(0xf)
#define   HS_SQUELCH_SHIFT			(29)
#define   HS_SQUELCH_MASK			(0x7)

#define   RPD_CTRL_SHIFT			(0)
#define   RPD_CTRL_MASK				(0x1f)

/* Data contact detection timeout */
#define TDCD_TIMEOUT_MS                         400

/* XUSB PADCTL registers */
#define XUSB_PADCTL_USB2_PAD_MUX		(0x4)
#define   USB2_PORT_SHIFT(x)			((x) * 2)
#define   USB2_PORT_MASK			(0x3)
#define    PORT_XUSB				(1)
#define   HSIC_PORT_SHIFT(x)			((x) + 20)
#define   HSIC_PORT_MASK			(0x1)
#define    PORT_HSIC				(0)

#define XUSB_PADCTL_USB2_PORT_CAP		(0x8)
#define XUSB_PADCTL_SS_PORT_CAP			(0xc)
#define   PORTX_CAP_SHIFT(x)			((x) * 4)
#define   PORT_CAP_MASK				(0x3)
#define     PORT_CAP_DISABLED			(0x0)
#define     PORT_CAP_HOST			(0x1)
#define     PORT_CAP_DEVICE			(0x2)
#define     PORT_CAP_OTG			(0x3)

#define XUSB_PADCTL_USB2_OC_MAP                 (0x10)
#define XUSB_PADCTL_SS_OC_MAP                   (0x14)
#define   PORTX_OC_PIN_SHIFT(x)                 ((x) * 4)
#define   PORT_OC_PIN_MASK                      (0xf)
#define     OC_PIN_DETECTION_DISABLED           (0xf)
#define     OC_PIN_DETECTED(x)                  (x)
#define     OC_PIN_DETECTED_VBUS_PAD(x)         ((x) + 4)

#define XUSB_PADCTL_VBUS_OC_MAP                 (0x18)
#define   VBUS_OC_MAP_SHIFT(x)                  ((x) * 5 + 1)
#define   VBUS_OC_MAP_MASK                      (0xf)
#define     VBUS_OC_DETECTION_DISABLED          (0xf)
#define     VBUS_OC_DETECTED(x)                 (x)
#define     VBUS_OC_DETECTED_VBUS_PAD(x)        ((x) + 4)
#define   VBUS_ENABLE(x)                        (1 << (x) * 5)

#define XUSB_PADCTL_OC_DET                      (0x1c)
#define   SET_OC_DETECTED(x)                    (1 << (x))
#define   OC_DETECTED(x)                        (1 << (8 + (x)))
#define   OC_DETECTED_VBUS_PAD(x)               (1 << (12 + (x)))
#define   OC_DETECTED_VBUS_PAD_MASK             (0xf << 12)
#define   OC_DETECTED_INT_EN                    (1 << (20 + (x)))
#define   OC_DETECTED_INT_EN_VBUS_PAD(x)        (1 << (24 + (x)))

#define XUSB_PADCTL_ELPG_PROGRAM		(0x20)
#define   USB2_PORT_WAKE_INTERRUPT_ENABLE(x)	(1 << (x))
#define   USB2_PORT_WAKEUP_EVENT(x)		(1 << ((x) + 7))
#define   SS_PORT_WAKE_INTERRUPT_ENABLE(x)	(1 << ((x) + 14))
#define   SS_PORT_WAKEUP_EVENT(x)		(1 << ((x) + 21))
#define   USB2_HSIC_PORT_WAKE_INTERRUPT_ENABLE(x)	(1 << ((x) + 28))
#define   USB2_HSIC_PORT_WAKEUP_EVENT(x)	(1 << ((x) + 30))
#define   ALL_WAKE_EVENTS						\
	(USB2_PORT_WAKEUP_EVENT(0) | USB2_PORT_WAKEUP_EVENT(1) |	\
	USB2_PORT_WAKEUP_EVENT(2) | SS_PORT_WAKEUP_EVENT(0) |		\
	SS_PORT_WAKEUP_EVENT(1) | SS_PORT_WAKEUP_EVENT(2) |		\
	USB2_HSIC_PORT_WAKEUP_EVENT(0))

#define XUSB_PADCTL_ELPG_PROGRAM_1		(0x24)
#define   SSPX_ELPG_CLAMP_EN(x)			(1 << (0 + (x) * 3))
#define   SSPX_ELPG_CLAMP_EN_EARLY(x)		(1 << (1 + (x) * 3))
#define   SSPX_ELPG_VCORE_DOWN(x)		(1 << (2 + (x) * 3))

#define XUSB_PADCTL_USB2_OTG_PADX_CTL0(x)	(0x88 + (x) * 0x40)
#define   HS_CURR_LEVEL(x)			((x) & 0x3f)
#define   TERM_SEL				(1 << 25)
#define   USB2_OTG_PD				(1 << 26)
#define   USB2_OTG_PD2				(1 << 27)
#define   USB2_OTG_PD2_OVRD_EN			(1 << 28)
#define   USB2_OTG_PD_ZI			(1 << 29)

#define XUSB_PADCTL_USB2_OTG_PADX_CTL1(x)	(0x8c + (x) * 0x40)
#define   USB2_OTG_PD_DR			(1 << 2)
#define   TERM_RANGE_ADJ(x)			(((x) & 0xf) << 3)
#define   RPD_CTRL(x)				(((x) & 0x1f) << 26)

#define XUSB_PADCTL_USB2_OTG_PADX_CTL3(x)	(0x94 + (x) * 0x40)
#define   HS_TXEQ(x)				(((x) & 0x7) << 1)

#define XUSB_PADCTL_USB2_BATTERY_CHRG_TDCD_DBNC_TIMER_0 (0x280)
#define   TDCD_DBNC(x)                          (((x) & 0x7ff) << 0)

#define USB2_BATTERY_CHRG_OTGPADX_CTL0(x)       (0x80 + (x) * 0x40)
#define   PD_CHG                                (1 << 0)
#define   VDCD_DET_FILTER_EN                    (1 << 4)
#define   VDAT_DET                              (1 << 5)
#define   VDAT_DET_FILTER_EN                    (1 << 8)
#define   OP_SINK_EN                            (1 << 9)
#define   OP_SRC_EN                             (1 << 10)
#define   ON_SINK_EN                            (1 << 11)
#define   ON_SRC_EN                             (1 << 12)
#define   OP_I_SRC_EN                           (1 << 13)
#define   ZIP_FILTER_EN                         (1 << 21)
#define   ZIN_FILTER_EN                         (1 << 25)
#define   DCD_DETECTED                          (1 << 26)
#define   SRP_DETECT_EN                         (1 << 28)
#define   SRP_DETECTED                          (1 << 29)
#define   SRP_INTR_EN                           (1 << 30)
#define   GENERATE_SRP                          (1 << 31)

#define USB2_BATTERY_CHRG_OTGPADX_CTL1(x)       (0x84 + (x) * 0x40)
#define   DIV_DET_EN                            (1 << 4)
#define   PD_VREG                               (1 << 6)
#define   VREG_LEV(x)                           (((x) & 0x3) << 7)
#define   VREG_DIR(x)                           (((x) & 0x3) << 11)
#define   VREG_DIR_IN                           VREG_DIR(1)
#define   VREG_DIR_OUT                          VREG_DIR(2)
#define   USBOP_RPD_OVRD                        (1 << 16)
#define   USBOP_RPD_OVRD_VAL                    (1 << 17)
#define   USBOP_RPU_OVRD                        (1 << 18)
#define   USBOP_RPU_OVRD_VAL                    (1 << 19)
#define   USBON_RPD_OVRD                        (1 << 20)
#define   USBON_RPD_OVRD_VAL                    (1 << 21)
#define   USBON_RPU_OVRD                        (1 << 22)
#define   USBON_RPU_OVRD_VAL                    (1 << 23)

#define XUSB_PADCTL_USB2_BIAS_PAD_CTL0		(0x284)
#define   BIAS_PAD_PD				(1 << 11)
#define   HS_SQUELCH_LEVEL(x)			(((x) & 0x7) << 0)

#define XUSB_PADCTL_USB2_BIAS_PAD_CTL1		(0x288)
#define   USB2_TRK_START_TIMER(x)		(((x) & 0x7f) << 12)
#define   USB2_TRK_DONE_RESET_TIMER(x)		(((x) & 0x7f) << 19)
#define   USB2_PD_TRK				(1 << 26)

#define XUSB_PADCTL_HSIC_PADX_CTL0(x)		(0x300 + (x) * 0x20)
#define   HSIC_PD_TX_DATA0			(1 << 1)
#define   HSIC_PD_TX_STROBE			(1 << 3)
#define   HSIC_PD_RX_DATA0			(1 << 4)
#define   HSIC_PD_RX_STROBE			(1 << 6)
#define   HSIC_PD_ZI_DATA0			(1 << 7)
#define   HSIC_PD_ZI_STROBE			(1 << 9)
#define   HSIC_RPD_DATA0			(1 << 13)
#define   HSIC_RPD_STROBE			(1 << 15)
#define   HSIC_RPU_DATA0			(1 << 16)
#define   HSIC_RPU_STROBE			(1 << 18)

#define XUSB_PADCTL_HSIC_PAD_TRK_CTL0		(0x340)
#define   HSIC_TRK_START_TIMER(x)		(((x) & 0x7f) << 5)
#define   HSIC_TRK_DONE_RESET_TIMER(x)		(((x) & 0x7f) << 12)
#define   HSIC_PD_TRK				(1 << 19)

#define USB2_VBUS_ID				(0x360)
#define   VBUS_OVERRIDE				(1 << 14)
#define   ID_OVERRIDE(x)			(((x) & 0xf) << 18)
#define   ID_OVERRIDE_FLOATING			ID_OVERRIDE(8)
#define   ID_OVERRIDE_GROUNDED			ID_OVERRIDE(0)

/* XUSB AO registers */
#define XUSB_AO_USB_DEBOUNCE_DEL		(0x4)
#define   UHSIC_LINE_DEB_CNT(x)			(((x) & 0xf) << 4)
#define   UTMIP_LINE_DEB_CNT(x)			((x) & 0xf)

#define XUSB_AO_UTMIP_TRIGGERS(x)		(0x40 + (x) * 4)
#define   CLR_WALK_PTR				(1 << 0)
#define   CAP_CFG				(1 << 1)
#define   CLR_WAKE_ALARM			(1 << 3)

#define XUSB_AO_UHSIC_TRIGGERS(x)		(0x60 + (x) * 4)
#define   HSIC_CLR_WALK_PTR			(1 << 0)
#define   HSIC_CLR_WAKE_ALARM			(1 << 3)
#define   HSIC_CAP_CFG				(1 << 4)

#define XUSB_AO_UTMIP_SAVED_STATE(x)		(0x70 + (x) * 4)
#define   SPEED(x)				((x) & 0x3)
#define     UTMI_HS				SPEED(0)
#define     UTMI_FS				SPEED(1)
#define     UTMI_LS				SPEED(2)
#define     UTMI_RST				SPEED(3)

#define XUSB_AO_UHSIC_SAVED_STATE(x)		(0x90 + (x) * 4)
#define   MODE(x)				((x) & 0x1)
#define   MODE_HS				MODE(0)
#define   MODE_RST				MODE(1)

#define XUSB_AO_UTMIP_SLEEPWALK_CFG(x)		(0xd0 + (x) * 4)
#define XUSB_AO_UHSIC_SLEEPWALK_CFG(x)		(0xf0 + (x) * 4)
#define   FAKE_USBOP_VAL			(1 << 0)
#define   FAKE_USBON_VAL			(1 << 1)
#define   FAKE_USBOP_EN				(1 << 2)
#define   FAKE_USBON_EN				(1 << 3)
#define   FAKE_STROBE_VAL			(1 << 0)
#define   FAKE_DATA_VAL				(1 << 1)
#define   FAKE_STROBE_EN			(1 << 2)
#define   FAKE_DATA_EN				(1 << 3)
#define   WAKE_WALK_EN				(1 << 14)
#define   MASTER_ENABLE				(1 << 15)
#define   LINEVAL_WALK_EN			(1 << 16)
#define   WAKE_VAL(x)				(((x) & 0xf) << 17)
#define     WAKE_VAL_NONE			WAKE_VAL(12)
#define     WAKE_VAL_ANY			WAKE_VAL(15)
#define     WAKE_VAL_DS10			WAKE_VAL(2)
#define   LINE_WAKEUP_EN			(1 << 21)
#define   MASTER_CFG_SEL			(1 << 22)

#define XUSB_AO_UTMIP_SLEEPWALK(x)		(0x100 + (x) * 4)
/* phase A */
#define   USBOP_RPD_A				(1 << 0)
#define   USBON_RPD_A				(1 << 1)
#define   AP_A					(1 << 4)
#define   AN_A					(1 << 5)
#define   HIGHZ_A				(1 << 6)
/* phase B */
#define   USBOP_RPD_B				(1 << 8)
#define   USBON_RPD_B				(1 << 9)
#define   AP_B					(1 << 12)
#define   AN_B					(1 << 13)
#define   HIGHZ_B				(1 << 14)
/* phase C */
#define   USBOP_RPD_C				(1 << 16)
#define   USBON_RPD_C				(1 << 17)
#define   AP_C					(1 << 20)
#define   AN_C					(1 << 21)
#define   HIGHZ_C				(1 << 22)
/* phase D */
#define   USBOP_RPD_D				(1 << 24)
#define   USBON_RPD_D				(1 << 25)
#define   AP_D					(1 << 28)
#define   AN_D					(1 << 29)
#define   HIGHZ_D				(1 << 30)

#define XUSB_AO_UHSIC_SLEEPWALK(x)		(0x120 + (x) * 4)
/* phase A */
#define   RPD_STROBE_A				(1 << 0)
#define   RPD_DATA0_A				(1 << 1)
#define   RPU_STROBE_A				(1 << 2)
#define   RPU_DATA0_A				(1 << 3)
/* phase B */
#define   RPD_STROBE_B				(1 << 8)
#define   RPD_DATA0_B				(1 << 9)
#define   RPU_STROBE_B				(1 << 10)
#define   RPU_DATA0_B				(1 << 11)
/* phase C */
#define   RPD_STROBE_C				(1 << 16)
#define   RPD_DATA0_C				(1 << 17)
#define   RPU_STROBE_C				(1 << 18)
#define   RPU_DATA0_C				(1 << 19)
/* phase D */
#define   RPD_STROBE_D				(1 << 24)
#define   RPD_DATA0_D				(1 << 25)
#define   RPU_STROBE_D				(1 << 26)
#define   RPU_DATA0_D				(1 << 27)

#define XUSB_AO_UTMIP_PAD_CFG(x)		(0x130 + (x) * 4)
#define   FSLS_USE_XUSB_AO			(1 << 3)
#define   TRK_CTRL_USE_XUSB_AO			(1 << 4)
#define   RPD_CTRL_USE_XUSB_AO			(1 << 5)
#define   RPU_USE_XUSB_AO			(1 << 6)
#define   VREG_USE_XUSB_AO			(1 << 7)
#define   USBOP_VAL_PD				(1 << 8)
#define   USBON_VAL_PD				(1 << 9)
#define   E_DPD_OVRD_EN				(1 << 10)
#define   E_DPD_OVRD_VAL			(1 << 11)

#define XUSB_AO_UHSIC_PAD_CFG(x)		(0x150 + (x) * 4)
#define   STROBE_VAL_PD				(1 << 0)
#define   DATA0_VAL_PD				(1 << 1)
#define   USE_XUSB_AO				(1 << 4)

#define TEGRA186_LANE(_name, _offset, _shift, _mask, _type)		\
	{								\
		.name = _name,						\
		.offset = _offset,					\
		.shift = _shift,					\
		.mask = _mask,						\
		.num_funcs = ARRAY_SIZE(tegra186_##_type##_functions),	\
		.funcs = tegra186_##_type##_functions,			\
	}

#define to_xusb_port(x) container_of((x), struct tegra_xusb_port, dev)

struct tegra_xusb_fuse_calibration {
	u32 hs_curr_level[TEGRA186_UTMI_PHYS];
	u32 hs_squelch;
	u32 hs_term_range_adj;
	u32 rpd_ctrl;
};

struct tegra186_xusb_padctl_context {
	u32 vbus_id;
	u32 usb2_pad_mux;
	u32 usb2_port_cap;
	u32 ss_port_cap;
	u32 vbus_oc_map;
};

struct tegra186_xusb_padctl {
	struct tegra_xusb_padctl base;

	void __iomem *ao_regs;

	/* prod settings */
	struct tegra_prod *prod_list;
	struct tegra_xusb_fuse_calibration calib;

	/* utmi bias and tracking */
	struct clk *usb2_trk_clk;
	unsigned int bias_pad_enable;

	/* padctl context */
	struct tegra186_xusb_padctl_context context;
};

static inline void ao_writel(struct tegra186_xusb_padctl *priv, u32 value,
			     unsigned long offset)
{
	dev_dbg(priv->base.dev, "ao %08lx < %08x\n", offset, value);
	writel(value, priv->ao_regs + offset);
}

static inline u32 ao_readl(struct tegra186_xusb_padctl *priv,
			   unsigned long offset)
{
	u32 value = readl(priv->ao_regs + offset);

	dev_dbg(priv->base.dev, "ao %08lx > %08x\n", offset, value);
	return value;
}

static inline struct tegra186_xusb_padctl *
to_tegra186_xusb_padctl(struct tegra_xusb_padctl *padctl)
{
	return container_of(padctl, struct tegra186_xusb_padctl, base);
}

/* USB 2.0 UTMI PHY support */
static struct tegra_xusb_lane *
tegra186_usb2_lane_probe(struct tegra_xusb_pad *pad, struct device_node *np,
			 unsigned int index)
{
	struct tegra_xusb_usb2_lane *usb2;
	int err;

	usb2 = kzalloc(sizeof(*usb2), GFP_KERNEL);
	if (!usb2)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&usb2->base.list);
	usb2->base.soc = &pad->soc->lanes[index];
	usb2->base.index = index;
	usb2->base.pad = pad;
	usb2->base.np = np;

	err = tegra_xusb_lane_parse_dt(&usb2->base, np);
	if (err < 0) {
		kfree(usb2);
		return ERR_PTR(err);
	}

	return &usb2->base;
}

static void tegra186_usb2_lane_remove(struct tegra_xusb_lane *lane)
{
	struct tegra_xusb_usb2_lane *usb2 = to_usb2_lane(lane);

	kfree(usb2);
}

static const struct tegra_xusb_lane_ops tegra186_usb2_lane_ops = {
	.probe = tegra186_usb2_lane_probe,
	.remove = tegra186_usb2_lane_remove,
};

static void tegra186_utmi_bias_pad_power_on(struct tegra_xusb_padctl *padctl)
{
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	u32 reg;

	mutex_lock(&padctl->lock);
	if (priv->bias_pad_enable++ > 0) {
		mutex_unlock(&padctl->lock);
		return;
	}

	if (clk_prepare_enable(priv->usb2_trk_clk))
		dev_warn(padctl->dev, "failed to enable USB2 trk clock\n");

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_BIAS_PAD_CTL1);
	reg &= ~USB2_TRK_START_TIMER(~0);
	reg |= USB2_TRK_START_TIMER(0x1e);
	reg &= ~USB2_TRK_DONE_RESET_TIMER(~0);
	reg |= USB2_TRK_DONE_RESET_TIMER(0xa);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_BIAS_PAD_CTL1);

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_BIAS_PAD_CTL0);
	reg &= ~BIAS_PAD_PD;
	reg &= ~HS_SQUELCH_LEVEL(~0);
	reg |= HS_SQUELCH_LEVEL(priv->calib.hs_squelch);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_BIAS_PAD_CTL0);

	udelay(1);

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_BIAS_PAD_CTL1);
	reg &= ~USB2_PD_TRK;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_BIAS_PAD_CTL1);

	mutex_unlock(&padctl->lock);
}

static inline bool is_utmi_phy(struct phy *phy);
static void tegra186_utmi_bias_pad_power_off(struct tegra_xusb_padctl *padctl)
{
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	u32 reg;

	mutex_lock(&padctl->lock);

	if (WARN_ON(priv->bias_pad_enable == 0)) {
		mutex_unlock(&padctl->lock);
		return;
	}

	if (--priv->bias_pad_enable > 0) {
		mutex_unlock(&padctl->lock);
		return;
	}

	if (!padctl->cdp_used) {
		/* only turn BIAS pad off when host CDP isn't enabled */
		reg = padctl_readl(padctl, XUSB_PADCTL_USB2_BIAS_PAD_CTL0);
		reg |= BIAS_PAD_PD;
		padctl_writel(padctl, reg, XUSB_PADCTL_USB2_BIAS_PAD_CTL0);
	}

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_BIAS_PAD_CTL1);
	reg |= USB2_PD_TRK;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_BIAS_PAD_CTL1);

	clk_disable_unprepare(priv->usb2_trk_clk);

	mutex_unlock(&padctl->lock);
}

void tegra186_utmi_pad_power_on(struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_usb2_lane *usb2;
	struct tegra_xusb_padctl *padctl;
	unsigned int index;
	struct device *dev;
	u32 reg;

	if (!phy || !is_utmi_phy(phy))
		return;

	lane = phy_get_drvdata(phy);
	usb2 = to_usb2_lane(lane);
	padctl = lane->pad->padctl;
	index = lane->index;
	dev = padctl->dev;

	dev_dbg(dev, "power on UTMI pads %d\n", index);

	if (usb2->powered_on)
		return;

	tegra186_utmi_bias_pad_power_on(padctl);

	udelay(2);

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
	reg &= ~USB2_OTG_PD;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL1(index));
	reg &= ~USB2_OTG_PD_DR;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL1(index));

	usb2->powered_on = true;
}

void tegra186_utmi_pad_power_down(struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_usb2_lane *usb2;
	struct tegra_xusb_padctl *padctl;
	unsigned int index;
	struct device *dev;
	u32 reg;

	if (!phy || !is_utmi_phy(phy))
		return;

	lane = phy_get_drvdata(phy);
	usb2 = to_usb2_lane(lane);
	padctl = lane->pad->padctl;
	index = lane->index;
	dev = padctl->dev;

	dev_dbg(dev, "power down UTMI pad %d\n", index);

	if (!usb2->powered_on)
		return;

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
	reg |= USB2_OTG_PD;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL1(index));
	reg |= USB2_OTG_PD_DR;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL1(index));

	udelay(2);

	tegra186_utmi_bias_pad_power_off(padctl);
	usb2->powered_on = false;
}

#define oc_debug(u) \
		dev_dbg(u->dev, "%s(%d):OC_DET %#x, VBUS_OC_MAP %#x, "\
			"USB2_OC_MAP %#x, SS_OC_MAP %#x\n",\
			__func__, __LINE__,\
			padctl_readl(u, XUSB_PADCTL_OC_DET), \
			padctl_readl(u, XUSB_PADCTL_VBUS_OC_MAP), \
			padctl_readl(u, XUSB_PADCTL_USB2_OC_MAP), \
			padctl_readl(u, XUSB_PADCTL_SS_OC_MAP))

/* should only be called with a UTMI phy and with padctl->lock held */
static void tegra186_enable_vbus_oc(struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_padctl *padctl;
	unsigned int index;
	struct tegra_xusb_usb2_port *port;
	int pin;
	u32 reg;
	int i;

	lane = phy_get_drvdata(phy);
	padctl = lane->pad->padctl;
	index = lane->index;

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev,
			"no port found for USB2 lane %u\n", index);
		return;
	}

	if (!padctl->oc_pinctrl) {
		dev_dbg(padctl->dev,
			"%s no OC pinctrl device\n", __func__);
		return;
	}

	pin = port->oc_pin;
	if (pin < 0) {
		dev_dbg(padctl->dev,
			"%s no OC support for port %d\n", __func__, index);
		return;
	}

	dev_dbg(padctl->dev,
		"enable VBUS/OC on UTMI port %d, pin %d\n", index, pin);

	/* initialize OC: step 7 in PG p.1272 */
	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OC_MAP);
	reg &= ~(PORT_OC_PIN_MASK << PORTX_OC_PIN_SHIFT(index));
	reg |= OC_PIN_DETECTION_DISABLED << PORTX_OC_PIN_SHIFT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OC_MAP);

	/* need to disable VBUS_ENABLEx_OC_MAP before enabling VBUS */
	reg = padctl_readl(padctl, XUSB_PADCTL_VBUS_OC_MAP);
	reg &= ~(VBUS_OC_MAP_MASK << VBUS_OC_MAP_SHIFT(pin));
	reg |= VBUS_OC_DETECTION_DISABLED << VBUS_OC_MAP_SHIFT(pin);
	padctl_writel(padctl, reg, XUSB_PADCTL_VBUS_OC_MAP);

	/* WAR: disable UTMIPLL power down, not needed for current clk
	 * framework
	 */

	/* clear false OC_DETECTED VBUS_PADx */
	reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);
	reg &= ~OC_DETECTED_VBUS_PAD_MASK;
	reg |= OC_DETECTED_VBUS_PAD(pin);
	padctl_writel(padctl, reg, XUSB_PADCTL_OC_DET);

	udelay(100);

	/* WAR: enable UTMIPLL power down, not needed for current clk
	 * framework
	 * Sometimes it takes up to 250 ms for OC status to be cleared
	 */
	for (i = 0; i < 20; i++) {
		/* Enable VBUS */
		reg = padctl_readl(padctl, XUSB_PADCTL_VBUS_OC_MAP);
		reg |= VBUS_ENABLE(pin);
		padctl_writel(padctl, reg, XUSB_PADCTL_VBUS_OC_MAP);

		/* vbus has been supplied to device. A finite time (>10ms) for
		 * OC detection pin to be pulled-up
		 */
		msleep(20);

		/* check and clear if there is any stray OC */
		reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);
		if (reg & OC_DETECTED_VBUS_PAD(pin)) {
			/* clear stray OC */
			dev_dbg(padctl->dev,
				"clear OC on port %d pin %d, OC_DET=%#x\n",
				index, pin, reg);

			reg = padctl_readl(padctl, XUSB_PADCTL_VBUS_OC_MAP);
			reg &= ~VBUS_ENABLE(pin);
			padctl_writel(padctl, reg, XUSB_PADCTL_VBUS_OC_MAP);

			reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);
			reg &= ~OC_DETECTED_VBUS_PAD_MASK;
			reg |= OC_DETECTED_VBUS_PAD(pin);
			padctl_writel(padctl, reg, XUSB_PADCTL_OC_DET);
		} else
			break;
	}

	/* change the OC_MAP source and enable OC interrupt */
	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OC_MAP);
	reg &= ~(PORT_OC_PIN_MASK << PORTX_OC_PIN_SHIFT(index));
	reg |= (OC_PIN_DETECTED_VBUS_PAD(pin) & PORT_OC_PIN_MASK) <<
		PORTX_OC_PIN_SHIFT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OC_MAP);

	reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);
	reg &= ~OC_DETECTED_VBUS_PAD_MASK;
	reg |= OC_DETECTED_INT_EN_VBUS_PAD(pin);
	padctl_writel(padctl, reg, XUSB_PADCTL_OC_DET);

	reg = padctl_readl(padctl, XUSB_PADCTL_VBUS_OC_MAP);
	reg &= ~(VBUS_OC_MAP_MASK << VBUS_OC_MAP_SHIFT(pin));
	reg |= (VBUS_OC_DETECTED_VBUS_PAD(pin) & VBUS_OC_MAP_MASK) <<
		VBUS_OC_MAP_SHIFT(pin);
	padctl_writel(padctl, reg, XUSB_PADCTL_VBUS_OC_MAP);

	oc_debug(padctl);
}

/* should only be called with a UTMI phy and with padctl->lock held */
static void tegra186_disable_vbus_oc(struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_padctl *padctl;
	struct tegra_xusb_usb2_port *port;
	unsigned int index;
	int pin;
	u32 reg;

	lane = phy_get_drvdata(phy);
	padctl = lane->pad->padctl;
	index = lane->index;

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev,
			"no port found for USB2 lane %u\n", index);
		return;
	}

	if (!padctl->oc_pinctrl) {
		dev_dbg(padctl->dev,
			"%s no OC pinctrl device\n", __func__);
		return;
	}

	pin = port->oc_pin;
	if (pin < 0) {
		dev_dbg(padctl->dev,
			"%s no OC support for port %d\n", __func__, index);
		return;
	}

	dev_dbg(padctl->dev,
		"disable VBUS/OC on UTMI port %d, pin %d\n", index, pin);

	/* disable VBUS PAD interrupt for this port */
	reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);
	reg &= ~OC_DETECTED_INT_EN_VBUS_PAD(pin);
	padctl_writel(padctl, reg, XUSB_PADCTL_OC_DET);

	/* clear VBUS OC MAP, disable VBUS. Skip doing so if it's OTG port and
	 * OTG vbus always on is set.
	 */
	reg = padctl_readl(padctl, XUSB_PADCTL_VBUS_OC_MAP);
	reg &= ~(VBUS_OC_MAP_MASK << VBUS_OC_MAP_SHIFT(pin));
	reg |= VBUS_OC_DETECTION_DISABLED << VBUS_OC_MAP_SHIFT(pin);
	reg &= ~VBUS_ENABLE(pin);
	padctl_writel(padctl, reg, XUSB_PADCTL_VBUS_OC_MAP);
}

static int tegra186_utmi_phy_power_on(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_usb2_lane *usb2 = to_usb2_lane(lane);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	struct tegra_xusb_usb2_port *port;
	u32 reg;

	dev_dbg(dev, "phy power on UTMI %d\n", index);

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(dev, "no port found for USB2 lane %u\n", index);
		return -ENODEV;
	}

	if (priv->prod_list) {
		char prod_name[] = "prod_c_utmiX";
		int err;

		sprintf(prod_name, "prod_c_utmi%d", index);
		err = tegra_prod_set_by_name(&padctl->regs, prod_name,
					     priv->prod_list);
		if (err) {
			dev_dbg(dev, "failed to apply prod for utmi pad%d\n",
				index);
		}

		err = tegra_prod_set_by_name(&padctl->regs, "prod_c_bias",
					     priv->prod_list);
		if (err)
			dev_dbg(dev, "failed to apply prod for bias pad\n");
	}

	if (port->hs_txeq >= 0) {
		dev_dbg(dev, "UTMI port %d apply HS_TXEQ %d\n",
			index, port->hs_txeq);
		reg = padctl_readl(padctl,
				XUSB_PADCTL_USB2_OTG_PADX_CTL3(index));
		reg &= ~HS_TXEQ(~0);
		reg |= HS_TXEQ(port->hs_txeq);
		padctl_writel(padctl, reg,
				XUSB_PADCTL_USB2_OTG_PADX_CTL3(index));
	}

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_PAD_MUX);
	reg &= ~(USB2_PORT_MASK << USB2_PORT_SHIFT(index));
	reg |= (PORT_XUSB << USB2_PORT_SHIFT(index));
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_PAD_MUX);

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_PORT_CAP);
	reg &= ~(PORT_CAP_MASK << PORTX_CAP_SHIFT(index));
	if (port->port_cap == USB_PORT_DISABLED)
		reg |= (PORT_CAP_DISABLED << PORTX_CAP_SHIFT(index));
	else if (port->port_cap == USB_DEVICE_CAP)
		reg |= (PORT_CAP_DEVICE << PORTX_CAP_SHIFT(index));
	else if (port->port_cap == USB_HOST_CAP)
		reg |= (PORT_CAP_HOST << PORTX_CAP_SHIFT(index));
	else if (port->port_cap == USB_OTG_CAP)
		reg |= (PORT_CAP_OTG << PORTX_CAP_SHIFT(index));
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_PORT_CAP);

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
	reg &= ~USB2_OTG_PD_ZI;
	reg |= TERM_SEL;
	reg &= ~HS_CURR_LEVEL(~0);

	if (usb2->hs_curr_level_offset) {
		int hs_current_level;

		dev_dbg(dev, "UTMI port %d apply hs_curr_level_offset %d\n",
			index, usb2->hs_curr_level_offset);

		hs_current_level = (int) priv->calib.hs_curr_level[index] +
			usb2->hs_curr_level_offset;

		if (hs_current_level < 0)
			hs_current_level = 0;
		if (hs_current_level > 0x3f)
			hs_current_level = 0x3f;

		reg |= HS_CURR_LEVEL(hs_current_level);
	} else
		reg |= HS_CURR_LEVEL(priv->calib.hs_curr_level[index]);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL1(index));
	reg &= ~TERM_RANGE_ADJ(~0);
	reg |= TERM_RANGE_ADJ(priv->calib.hs_term_range_adj);
	reg &= ~RPD_CTRL(~0);
	reg |= RPD_CTRL(priv->calib.rpd_ctrl);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL1(index));

	return 0;
}

static int tegra186_utmi_phy_power_off(struct phy *phy)
{
	tegra186_utmi_pad_power_down(phy);

	return 0;
}

static int tegra186_utmi_phy_enable_sleepwalk(struct phy *phy,
					      enum usb_device_speed speed)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy enable sleepwalk UTMI %d speed %d\n", index, speed);

	mutex_lock(&padctl->lock);

	/* ensure sleepwalk logic is disabled */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~MASTER_ENABLE;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* ensure sleepwalk logics are in low power mode */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg |= MASTER_CFG_SEL;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* set debounce time */
	reg = ao_readl(priv, XUSB_AO_USB_DEBOUNCE_DEL);
	reg &= ~UTMIP_LINE_DEB_CNT(~0);
	reg |= UTMIP_LINE_DEB_CNT(1);
	ao_writel(priv, reg, XUSB_AO_USB_DEBOUNCE_DEL);

	/* ensure fake events of sleepwalk logic are desiabled */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~(FAKE_USBOP_VAL | FAKE_USBON_VAL |
		FAKE_USBOP_EN | FAKE_USBON_EN);
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* ensure wake events of sleepwalk logic are not latched */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~LINE_WAKEUP_EN;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* disable wake event triggers of sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~WAKE_VAL(~0);
	reg |= WAKE_VAL_NONE;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* power down the line state detectors of the pad */
	reg = ao_readl(priv, XUSB_AO_UTMIP_PAD_CFG(index));
	reg |= (USBOP_VAL_PD | USBON_VAL_PD);
	ao_writel(priv, reg, XUSB_AO_UTMIP_PAD_CFG(index));

	/* save state per speed */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SAVED_STATE(index));
	reg &= ~SPEED(~0);
	if (speed == USB_SPEED_HIGH)
		reg |= UTMI_HS;
	else if (speed == USB_SPEED_FULL)
		reg |= UTMI_FS;
	else if (speed == USB_SPEED_LOW)
		reg |= UTMI_LS;
	else
		reg |= UTMI_RST;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SAVED_STATE(index));

	/* enable the trigger of the sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg |= LINEVAL_WALK_EN;
	reg &= ~WAKE_WALK_EN;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* reset the walk pointer and clear the alarm of the sleepwalk logic,
	 * as well as capture the configuration of the USB2.0 pad
	 */
	reg = ao_readl(priv, XUSB_AO_UTMIP_TRIGGERS(index));
	reg |= (CLR_WALK_PTR | CLR_WAKE_ALARM | CAP_CFG);
	ao_writel(priv, reg, XUSB_AO_UTMIP_TRIGGERS(index));

	/* setup the pull-ups and pull-downs of the signals during the four
	 * stages of sleepwalk.
	 * if device is connected, program sleepwalk logic to maintain a J and
	 * keep driving K upon seeing remote wake.
	 */
	reg = (USBOP_RPD_A | USBOP_RPD_B | USBOP_RPD_C | USBOP_RPD_D);
	reg |= (USBON_RPD_A | USBON_RPD_B | USBON_RPD_C | USBON_RPD_D);
	if (speed == USB_SPEED_UNKNOWN) {
		reg |= (HIGHZ_A | HIGHZ_B | HIGHZ_C | HIGHZ_D);
	} else if ((speed == USB_SPEED_HIGH) || (speed == USB_SPEED_FULL)) {
		/* J state: D+/D- = high/low, K state: D+/D- = low/high */
		reg |= HIGHZ_A;
		reg |= (AP_A);
		reg |= (AN_B | AN_C | AN_D);
	} else if (speed == USB_SPEED_LOW) {
		/* J state: D+/D- = low/high, K state: D+/D- = high/low */
		reg |= HIGHZ_A;
		reg |= AN_A;
		reg |= (AP_B | AP_C | AP_D);
	}
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK(index));

	/* power up the line state detectors of the pad */
	reg = ao_readl(priv, XUSB_AO_UTMIP_PAD_CFG(index));
	reg &= ~(USBOP_VAL_PD | USBON_VAL_PD);
	ao_writel(priv, reg, XUSB_AO_UTMIP_PAD_CFG(index));

	usleep_range(150, 200);

	/* switch the electric control of the USB2.0 pad to XUSB_AO */
	reg = ao_readl(priv, XUSB_AO_UTMIP_PAD_CFG(index));
	reg |= (FSLS_USE_XUSB_AO | TRK_CTRL_USE_XUSB_AO |
		RPD_CTRL_USE_XUSB_AO | RPU_USE_XUSB_AO | VREG_USE_XUSB_AO);
	ao_writel(priv, reg, XUSB_AO_UTMIP_PAD_CFG(index));

	/* set the wake signaling trigger events */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~WAKE_VAL(~0);
	reg |= WAKE_VAL_ANY;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* enable the wake detection */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg |= (MASTER_ENABLE | LINE_WAKEUP_EN);
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_utmi_phy_disable_sleepwalk(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy disable sleepwalk UTMI %d\n", index);

	mutex_lock(&padctl->lock);

	/* disable the wake detection */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~(MASTER_ENABLE | LINE_WAKEUP_EN);
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* switch the electric control of the USB2.0 pad to XUSB vcore logic */
	reg = ao_readl(priv, XUSB_AO_UTMIP_PAD_CFG(index));
	reg &= ~(FSLS_USE_XUSB_AO | TRK_CTRL_USE_XUSB_AO |
		RPD_CTRL_USE_XUSB_AO | RPU_USE_XUSB_AO | VREG_USE_XUSB_AO);
	ao_writel(priv, reg, XUSB_AO_UTMIP_PAD_CFG(index));

	/* disable wake event triggers of sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));
	reg &= ~WAKE_VAL(~0);
	reg |= WAKE_VAL_NONE;
	ao_writel(priv, reg, XUSB_AO_UTMIP_SLEEPWALK_CFG(index));

	/* power down the line state detectors of the port */
	reg = ao_readl(priv, XUSB_AO_UTMIP_PAD_CFG(index));
	reg |= (USBOP_VAL_PD | USBON_VAL_PD);
	ao_writel(priv, reg, XUSB_AO_UTMIP_PAD_CFG(index));

	/* clear alarm of the sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UTMIP_TRIGGERS(index));
	reg |= CLR_WAKE_ALARM;
	ao_writel(priv, reg, XUSB_AO_UTMIP_TRIGGERS(index));

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_utmi_phy_enable_wake(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy enable wake UTMI %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= USB2_PORT_WAKEUP_EVENT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	usleep_range(10, 20);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= USB2_PORT_WAKE_INTERRUPT_ENABLE(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_utmi_phy_disable_wake(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy disable wake UTMI %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg &= ~USB2_PORT_WAKE_INTERRUPT_ENABLE(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	usleep_range(10, 20);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= USB2_PORT_WAKEUP_EVENT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_utmi_phy_init(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct tegra_xusb_usb2_port *port;
	int rc = 0;

	dev_dbg(padctl->dev, "phy init UTMI %d\n", index);

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for USB2 lane %u\n", index);
		return -ENODEV;
	}

	mutex_lock(&padctl->lock);

	if (port->port_cap == USB_OTG_CAP) {
		if (padctl->usb2_otg_port_base_1)
			dev_warn(padctl->dev, "enabling OTG on multiple USB2 ports\n");
		padctl->usb2_otg_port_base_1 = index + 1;
	}

	mutex_unlock(&padctl->lock);

	return rc;
}

static int tegra186_utmi_phy_exit(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct tegra_xusb_usb2_port *port;
	int rc = 0;

	dev_dbg(padctl->dev, "phy exit UTMI %d\n", index);

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for USB2 lane %u\n", index);
		return -ENODEV;
	}

	mutex_lock(&padctl->lock);

	if (index == padctl->usb2_otg_port_base_1 - 1)
		padctl->usb2_otg_port_base_1 = 0;

	mutex_unlock(&padctl->lock);

	return rc;
}

static const struct phy_ops utmi_phy_ops = {
	.init = tegra186_utmi_phy_init,
	.exit = tegra186_utmi_phy_exit,
	.power_on = tegra186_utmi_phy_power_on,
	.power_off = tegra186_utmi_phy_power_off,
	.owner = THIS_MODULE,
};

static inline bool is_utmi_phy(struct phy *phy)
{
	return phy->ops == &utmi_phy_ops;
}

static bool is_utmi_phy_has_otg_cap(struct tegra_xusb_padctl *padctl,
					struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	unsigned int index;
	struct tegra_xusb_usb2_port *port;

	if (!phy)
		return false;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for USB2 lane %u\n", index);
		return -ENODEV;
	}

	return port->port_cap == USB_OTG_CAP;
}

static struct tegra_xusb_pad *
tegra186_usb2_pad_probe(struct tegra_xusb_padctl *padctl,
			const struct tegra_xusb_pad_soc *soc,
			struct device_node *np)
{
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	struct tegra_xusb_usb2_pad *usb2;
	struct tegra_xusb_pad *pad;
	int err;

	usb2 = kzalloc(sizeof(*usb2), GFP_KERNEL);
	if (!usb2)
		return ERR_PTR(-ENOMEM);

	pad = &usb2->base;
	pad->ops = &tegra186_usb2_lane_ops;
	pad->soc = soc;

	err = tegra_xusb_pad_init(pad, padctl, np);
	if (err < 0) {
		kfree(usb2);
		goto out;
	}

	priv->usb2_trk_clk = devm_clk_get(&pad->dev, "trk");
	if (IS_ERR(usb2->clk)) {
		err = PTR_ERR(usb2->clk);
		dev_dbg(&pad->dev, "failed to get usb2 trk clock: %d\n", err);
		goto unregister;
	}

	err = tegra_xusb_pad_register(pad, &utmi_phy_ops);
	if (err < 0)
		goto unregister;

	dev_set_drvdata(&pad->dev, pad);

	return pad;

unregister:
	device_unregister(&pad->dev);
out:
	return ERR_PTR(err);
}

static void tegra186_usb2_pad_remove(struct tegra_xusb_pad *pad)
{
	struct tegra_xusb_usb2_pad *usb2 = to_usb2_pad(pad);

	kfree(usb2);
}

static const struct tegra_xusb_pad_ops tegra186_usb2_pad_ops = {
	.probe = tegra186_usb2_pad_probe,
	.remove = tegra186_usb2_pad_remove,
};

static const char * const tegra186_usb2_functions[] = {
	"xusb",
};

static const struct tegra_xusb_lane_soc tegra186_usb2_lanes[] = {
	TEGRA186_LANE("usb2-0", 0,  0, 0, usb2),
	TEGRA186_LANE("usb2-1", 0,  0, 0, usb2),
	TEGRA186_LANE("usb2-2", 0,  0, 0, usb2),
};

static const struct tegra_xusb_pad_soc tegra186_usb2_pad = {
	.name = "usb2",
	.num_lanes = ARRAY_SIZE(tegra186_usb2_lanes),
	.lanes = tegra186_usb2_lanes,
	.ops = &tegra186_usb2_pad_ops,
};

static ssize_t hs_txeq_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct tegra_xusb_port *port = to_xusb_port(dev);
	struct tegra_xusb_usb2_port *port2 = to_usb2_port(port);

	if (port2->hs_txeq == -1)
		return sprintf(buf, "port %d HS_TXEQ is not set\n",
				port->index);
	else
		return sprintf(buf, "port %d HS_TXEQ: 0x%08x\n",
				port->index, port2->hs_txeq);
}

static ssize_t hs_txeq_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct tegra_xusb_port *port = to_xusb_port(dev);
	struct tegra_xusb_usb2_port *port2 = to_usb2_port(port);
	int hs_txeq;

	if (kstrtoint(buf, 10, &hs_txeq))
		return -EINVAL;

	if ((hs_txeq >= 0) && (hs_txeq <= 7))
		port2->hs_txeq = hs_txeq;
	else if (hs_txeq < 0)
		port2->hs_txeq = -1;
	else
		return -EINVAL;

	return n;
}

static DEVICE_ATTR(hs_txeq, 0644, hs_txeq_show, hs_txeq_store);

static struct attribute *port_attrs[] = {
	&dev_attr_hs_txeq.attr,
	NULL,
};
static struct attribute_group port_attr_group = {
	.attrs = port_attrs,
};

static int tegra186_usb2_port_enable(struct tegra_xusb_port *port)
{
	return sysfs_create_group(&port->dev.kobj, &port_attr_group);
}

static void tegra186_usb2_port_disable(struct tegra_xusb_port *port)
{
	sysfs_remove_group(&port->dev.kobj, &port_attr_group);
}

static struct tegra_xusb_lane *
tegra186_usb2_port_map(struct tegra_xusb_port *port)
{
	return tegra_xusb_find_lane(port->padctl, "usb2", port->index);
}

static const struct tegra_xusb_port_ops tegra186_usb2_port_ops = {
	.enable = tegra186_usb2_port_enable,
	.disable = tegra186_usb2_port_disable,
	.map = tegra186_usb2_port_map,
};

/* HSIC PHY support */
static struct tegra_xusb_lane *
tegra186_hsic_lane_probe(struct tegra_xusb_pad *pad, struct device_node *np,
			 unsigned int index)
{
	struct tegra_xusb_hsic_lane *hsic;
	int err;

	hsic = kzalloc(sizeof(*hsic), GFP_KERNEL);
	if (!hsic)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&hsic->base.list);
	hsic->base.soc = &pad->soc->lanes[index];
	hsic->base.index = index;
	hsic->base.pad = pad;
	hsic->base.np = np;

	err = tegra_xusb_lane_parse_dt(&hsic->base, np);
	if (err < 0) {
		kfree(hsic);
		return ERR_PTR(err);
	}

	return &hsic->base;
}

static void tegra186_hsic_lane_remove(struct tegra_xusb_lane *lane)
{
	struct tegra_xusb_hsic_lane *hsic = to_hsic_lane(lane);

	kfree(hsic);
}

static const struct tegra_xusb_lane_ops tegra186_hsic_lane_ops = {
	.probe = tegra186_hsic_lane_probe,
	.remove = tegra186_hsic_lane_remove,
};

static int tegra186_hsic_phy_power_on(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	struct tegra_xusb_hsic_pad *pad;
	int err;
	u32 reg;

	dev_dbg(dev, "phy power on HSIC %d\n", index);

	pad = to_hsic_pad(lane->pad);
	if (!pad) {
		dev_err(dev, "no pad found for HSIC lane %u\n", index);
		return -ENODEV;
	}

	if (priv->prod_list) {
		char prod_name[] = "prod_c_hsicX";

		sprintf(prod_name, "prod_c_hsic%d", index);
		err = tegra_prod_set_by_name(&padctl->regs, prod_name,
					     priv->prod_list);
		if (err) {
			dev_dbg(dev, "failed to apply prod for hsic pad%d\n",
				index);
		}
	}

	err = regulator_enable(pad->supply);
	if (err) {
		dev_err(dev, "enable hsic %d power failed %d\n",
			index, err);
		return err;
	}

	err = clk_prepare_enable(pad->clk);
	if (err) {
		dev_err(dev, "failed to enable HSIC tracking clock %d\n",
			err);
	}

	reg = padctl_readl(padctl, XUSB_PADCTL_HSIC_PAD_TRK_CTL0);
	reg &= ~HSIC_TRK_START_TIMER(~0);
	reg |= HSIC_TRK_START_TIMER(0x1e);
	reg &= ~HSIC_TRK_DONE_RESET_TIMER(~0);
	reg |= HSIC_TRK_DONE_RESET_TIMER(0xa);
	padctl_writel(padctl, reg, XUSB_PADCTL_HSIC_PAD_TRK_CTL0);

	reg = padctl_readl(padctl, XUSB_PADCTL_HSIC_PADX_CTL0(index));
	reg &= ~(HSIC_PD_TX_DATA0 | HSIC_PD_TX_STROBE |
		HSIC_PD_RX_DATA0 | HSIC_PD_RX_STROBE |
		HSIC_PD_ZI_DATA0 | HSIC_PD_ZI_STROBE);
	padctl_writel(padctl, reg, XUSB_PADCTL_HSIC_PADX_CTL0(index));

	udelay(1);

	reg = padctl_readl(padctl, XUSB_PADCTL_HSIC_PAD_TRK_CTL0);
	reg &= ~HSIC_PD_TRK;
	padctl_writel(padctl, reg, XUSB_PADCTL_HSIC_PAD_TRK_CTL0);

	usleep_range(50, 60);

	clk_disable_unprepare(pad->clk);

	return 0;
}

static int tegra186_hsic_phy_power_off(struct phy *phy)
{

	return 0;
}

static int tegra186_hsic_phy_enable_sleepwalk(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "enable sleepwalk HSIC port %d\n", index);

	/* ensure sleepwalk logic is disabled */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~MASTER_ENABLE;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* ensure sleepwalk logics are in low power mode */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg |= MASTER_CFG_SEL;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* set debounce time */
	reg = ao_readl(priv, XUSB_AO_USB_DEBOUNCE_DEL);
	reg &= ~UHSIC_LINE_DEB_CNT(~0);
	reg |= UHSIC_LINE_DEB_CNT(1);
	ao_writel(priv, reg, XUSB_AO_USB_DEBOUNCE_DEL);

	/* ensure fake events of sleepwalk logic are desiabled */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~(FAKE_STROBE_VAL | FAKE_DATA_VAL |
		FAKE_STROBE_EN | FAKE_DATA_EN);
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* ensure wake events of sleepwalk logic are not latched */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~LINE_WAKEUP_EN;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* disable wake event triggers of sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~WAKE_VAL(~0);
	reg |= WAKE_VAL_NONE;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* power down the line state detectors of the port */
	reg = ao_readl(priv, XUSB_AO_UHSIC_PAD_CFG(index));
	reg |= (STROBE_VAL_PD | DATA0_VAL_PD);
	ao_writel(priv, reg, XUSB_AO_UHSIC_PAD_CFG(index));

	/* save state, HSIC always comes up as HS */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SAVED_STATE(index));
	reg &= ~MODE(~0);
	reg |= MODE_HS;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SAVED_STATE(index));

	/* enable the trigger of the sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg |= LINEVAL_WALK_EN;
	reg &= ~WAKE_WALK_EN;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* reset the walk pointer and clear the alarm of the sleepwalk logic,
	 * as well as capture the configuration of the USB2.0 port
	 */
	reg = ao_readl(priv, XUSB_AO_UHSIC_TRIGGERS(index));
	reg |= (HSIC_CLR_WALK_PTR | HSIC_CLR_WAKE_ALARM | HSIC_CAP_CFG);
	ao_writel(priv, reg, XUSB_AO_UHSIC_TRIGGERS(index));

	/* setup the pull-ups and pull-downs of the signals during the four
	 * stages of sleepwalk.
	 * maintain a HSIC IDLE and keep driving HSIC RESUME upon remote wake
	 */
	reg = (RPD_DATA0_A | RPU_DATA0_B | RPU_DATA0_C | RPU_DATA0_D);
	reg |= (RPU_STROBE_A | RPD_STROBE_B | RPD_STROBE_C | RPD_STROBE_D);
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK(index));

	/* power up the line state detectors of the port */
	reg = ao_readl(priv, XUSB_AO_UHSIC_PAD_CFG(index));
	reg &= ~(DATA0_VAL_PD | STROBE_VAL_PD);
	ao_writel(priv, reg, XUSB_AO_UHSIC_PAD_CFG(index));

	usleep_range(150, 200);

	/* switch the electric control of the USB2.0 pad to XUSB_AO */
	reg = ao_readl(priv, XUSB_AO_UHSIC_PAD_CFG(index));
	reg |= USE_XUSB_AO;
	ao_writel(priv, reg, XUSB_AO_UHSIC_PAD_CFG(index));

	/* set the wake signaling trigger events */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~WAKE_VAL(~0);
	reg |= WAKE_VAL_DS10;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* enable the wake detection */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg |= (MASTER_ENABLE | LINE_WAKEUP_EN);
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	return 0;
}

static int tegra186_hsic_phy_disable_sleepwalk(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "disable sleepwalk HSIC port %d\n", index);

	/* disable the wake detection */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~(MASTER_ENABLE | LINE_WAKEUP_EN);
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* switch the electric control of the USB2.0 pad to XUSB vcore logic */
	reg = ao_readl(priv, XUSB_AO_UHSIC_PAD_CFG(index));
	reg &= ~USE_XUSB_AO;
	ao_writel(priv, reg, XUSB_AO_UHSIC_PAD_CFG(index));

	/* disable wake event triggers of sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));
	reg &= ~WAKE_VAL(~0);
	reg |= WAKE_VAL_NONE;
	ao_writel(priv, reg, XUSB_AO_UHSIC_SLEEPWALK_CFG(index));

	/* power down the line state detectors of the port */
	reg = ao_readl(priv, XUSB_AO_UHSIC_PAD_CFG(index));
	reg |= (STROBE_VAL_PD | DATA0_VAL_PD);
	ao_writel(priv, reg, XUSB_AO_UHSIC_PAD_CFG(index));

	/* clear alarm of the sleepwalk logic */
	reg = ao_readl(priv, XUSB_AO_UHSIC_TRIGGERS(index));
	reg |= HSIC_CLR_WAKE_ALARM;
	ao_writel(priv, reg, XUSB_AO_UHSIC_TRIGGERS(index));

	return 0;
}

static int tegra186_hsic_phy_enable_wake(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy enable wake HSIC %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= USB2_HSIC_PORT_WAKE_INTERRUPT_ENABLE(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	usleep_range(10, 20);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= USB2_HSIC_PORT_WAKEUP_EVENT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_hsic_phy_disable_wake(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy disable wake HSIC %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg &= ~USB2_HSIC_PORT_WAKE_INTERRUPT_ENABLE(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	usleep_range(10, 20);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= USB2_HSIC_PORT_WAKEUP_EVENT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_hsic_phy_init(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct tegra_xusb_hsic_port *port;
	int rc = 0;

	dev_dbg(padctl->dev, "phy init HSIC %d\n", index);

	port = tegra_xusb_find_hsic_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for HSIC lane %u\n", index);
		return -ENODEV;
	}

	return rc;
}

static int tegra186_hsic_phy_exit(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct tegra_xusb_hsic_port *port;
	int rc = 0;

	dev_dbg(padctl->dev, "phy exit HSIC %d\n", index);

	port = tegra_xusb_find_hsic_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for HSIC lane %u\n", index);
		return -ENODEV;
	}

	return rc;
}

static const struct phy_ops hsic_phy_ops = {
	.init = tegra186_hsic_phy_init,
	.exit = tegra186_hsic_phy_exit,
	.power_on = tegra186_hsic_phy_power_on,
	.power_off = tegra186_hsic_phy_power_off,
	.owner = THIS_MODULE,
};

static inline bool is_hsic_phy(struct phy *phy)
{
	return phy->ops == &hsic_phy_ops;
}

static struct tegra_xusb_pad *
tegra186_hsic_pad_probe(struct tegra_xusb_padctl *padctl,
			const struct tegra_xusb_pad_soc *soc,
			struct device_node *np)
{
	struct tegra_xusb_hsic_pad *hsic;
	struct tegra_xusb_pad *pad;
	int err;

	hsic = kzalloc(sizeof(*hsic), GFP_KERNEL);
	if (!hsic)
		return ERR_PTR(-ENOMEM);

	pad = &hsic->base;
	pad->ops = &tegra186_hsic_lane_ops;
	pad->soc = soc;

	err = tegra_xusb_pad_init(pad, padctl, np);
	if (err < 0) {
		kfree(hsic);
		goto out;
	}

	hsic->clk = devm_clk_get(&pad->dev, "trk");
	if (IS_ERR(hsic->clk)) {
		err = PTR_ERR(hsic->clk);
		dev_dbg(&pad->dev, "failed to get hsic trk clock: %d\n", err);
		goto unregister;
	}

	hsic->supply = devm_regulator_get(&pad->dev, "vddio-hsic");
	if (IS_ERR(hsic->supply)) {
		err = PTR_ERR(hsic->supply);
		if (err != -EPROBE_DEFER) {
			dev_err(&pad->dev, "failed get vddio-hsic supply: %d\n",
				err);
		}
		goto unregister;
	}

	err = tegra_xusb_pad_register(pad, &hsic_phy_ops);
	if (err < 0)
		goto unregister;

	dev_set_drvdata(&pad->dev, pad);

	return pad;

unregister:
	device_unregister(&pad->dev);
out:
	return ERR_PTR(err);
}

static void tegra186_hsic_pad_remove(struct tegra_xusb_pad *pad)
{
	struct tegra_xusb_hsic_pad *hsic = to_hsic_pad(pad);

	kfree(hsic);
}

static const struct tegra_xusb_pad_ops tegra186_hsic_pad_ops = {
	.probe = tegra186_hsic_pad_probe,
	.remove = tegra186_hsic_pad_remove,
};

static const char * const tegra186_hsic_functions[] = {
	"xusb",
};

static const struct tegra_xusb_lane_soc tegra186_hsic_lanes[] = {
	TEGRA186_LANE("hsic-0", 0,  0, 0, hsic),
};

static const struct tegra_xusb_pad_soc tegra186_hsic_pad = {
	.name = "hsic",
	.num_lanes = ARRAY_SIZE(tegra186_hsic_lanes),
	.lanes = tegra186_hsic_lanes,
	.ops = &tegra186_hsic_pad_ops,
};

static int tegra186_hsic_port_enable(struct tegra_xusb_port *port)
{
	return 0;
}

static void tegra186_hsic_port_disable(struct tegra_xusb_port *port)
{
}

static struct tegra_xusb_lane *
tegra186_hsic_port_map(struct tegra_xusb_port *port)
{
	return tegra_xusb_find_lane(port->padctl, "hsic", port->index);
}

static const struct tegra_xusb_port_ops tegra186_hsic_port_ops = {
	.enable = tegra186_hsic_port_enable,
	.disable = tegra186_hsic_port_disable,
	.map = tegra186_hsic_port_map,
};

static int tegra186_hsic_set_idle(struct tegra_xusb_padctl *padctl,
				  unsigned int index, bool idle)
{
	struct device *dev = padctl->dev;
	u32 reg;

	if (index >= 1) {
		dev_err(dev, "%s invalid HSIC pad %u\n", __func__, index);
		return -EINVAL;
	}

	dev_dbg(dev, "%s set HSIC %u idle %d\n", __func__, index, idle);

	reg = padctl_readl(padctl, XUSB_PADCTL_HSIC_PADX_CTL0(index));
	reg &= ~(HSIC_RPD_DATA0 | HSIC_RPU_DATA0);
	reg &= ~(HSIC_RPU_STROBE | HSIC_RPD_STROBE);
	if (idle)
		reg |= (HSIC_RPD_DATA0 | HSIC_RPU_STROBE);
	padctl_writel(padctl, reg, XUSB_PADCTL_HSIC_PADX_CTL0(index));

	return 0;
}

static int tegra186_hsic_reset(struct tegra_xusb_padctl *padctl,
				unsigned int index)
{
	struct device *dev = padctl->dev;
	u32 reg;

	if (index >= 1) {
		dev_err(dev, "%s invalid HSIC pad %u\n", __func__, index);
		return -EINVAL;
	}

	dev_dbg(dev, "%s set HSIC %u reset\n", __func__, index);

	reg = padctl_readl(padctl, XUSB_PADCTL_HSIC_PADX_CTL0(index));
	reg &= ~(HSIC_RPD_DATA0 | HSIC_RPU_DATA0);
	reg &= ~(HSIC_RPU_STROBE | HSIC_RPD_STROBE);
	reg |= (HSIC_RPD_DATA0 | HSIC_RPD_STROBE);
	padctl_writel(padctl, reg, XUSB_PADCTL_HSIC_PADX_CTL0(index));

	return 0;
}

/* SuperSpeed PHY support */
static struct tegra_xusb_lane *
tegra186_usb3_lane_probe(struct tegra_xusb_pad *pad, struct device_node *np,
			 unsigned int index)
{
	struct tegra_xusb_usb3_lane *usb3;
	int err;

	usb3 = kzalloc(sizeof(*usb3), GFP_KERNEL);
	if (!usb3)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&usb3->base.list);
	usb3->base.soc = &pad->soc->lanes[index];
	usb3->base.index = index;
	usb3->base.pad = pad;
	usb3->base.np = np;

	err = tegra_xusb_lane_parse_dt(&usb3->base, np);
	if (err < 0) {
		kfree(usb3);
		return ERR_PTR(err);
	}

	return &usb3->base;
}

static void tegra186_usb3_lane_remove(struct tegra_xusb_lane *lane)
{
	struct tegra_xusb_usb3_lane *usb3 = to_usb3_lane(lane);

	kfree(usb3);
}

static const struct tegra_xusb_lane_ops tegra186_usb3_lane_ops = {
	.probe = tegra186_usb3_lane_probe,
	.remove = tegra186_usb3_lane_remove,
};
static int tegra186_usb3_port_enable(struct tegra_xusb_port *port)
{
	return 0;
}

static void tegra186_usb3_port_disable(struct tegra_xusb_port *port)
{
}

static struct tegra_xusb_lane *
tegra186_usb3_port_map(struct tegra_xusb_port *port)
{
	return tegra_xusb_find_lane(port->padctl, "usb3", port->index);
}

static const struct tegra_xusb_port_ops tegra186_usb3_port_ops = {
	.enable = tegra186_usb3_port_enable,
	.disable = tegra186_usb3_port_disable,
	.map = tegra186_usb3_port_map,
};

static int tegra186_usb3_phy_power_on(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	struct tegra_xusb_usb3_port *port;
	int pin;
	u32 reg;

	dev_dbg(dev, "phy power on USB3 %d\n", index);

	port = tegra_xusb_find_usb3_port(padctl, index);
	if (!port) {
		dev_err(dev, "no port found for USB3 lane %u\n", index);
		return -ENODEV;
	}
	pin = port->oc_pin;

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_SS_PORT_CAP);
	reg &= ~(PORT_CAP_MASK << PORTX_CAP_SHIFT(index));
	if (port->port_cap == USB_PORT_DISABLED)
		reg |= (PORT_CAP_DISABLED << PORTX_CAP_SHIFT(index));
	else if (port->port_cap == USB_DEVICE_CAP)
		reg |= (PORT_CAP_DEVICE << PORTX_CAP_SHIFT(index));
	else if (port->port_cap == USB_HOST_CAP)
		reg |= (PORT_CAP_HOST << PORTX_CAP_SHIFT(index));
	else if (port->port_cap == USB_OTG_CAP)
		reg |= (PORT_CAP_OTG << PORTX_CAP_SHIFT(index));
	padctl_writel(padctl, reg, XUSB_PADCTL_SS_PORT_CAP);

	/* setting SS OC map */
	if (pin >= 0) {
		reg = padctl_readl(padctl, XUSB_PADCTL_SS_OC_MAP);
		reg &= ~(PORT_OC_PIN_MASK << PORTX_OC_PIN_SHIFT(index));
		reg |= (OC_PIN_DETECTED_VBUS_PAD(pin) & PORT_OC_PIN_MASK) <<
			PORTX_OC_PIN_SHIFT(index);
		padctl_writel(padctl, reg, XUSB_PADCTL_SS_OC_MAP);
	}

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg &= ~SSPX_ELPG_VCORE_DOWN(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(100, 200);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg &= ~SSPX_ELPG_CLAMP_EN_EARLY(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(100, 200);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg &= ~SSPX_ELPG_CLAMP_EN(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_usb3_phy_power_off(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy power off USB3 %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg |= SSPX_ELPG_CLAMP_EN_EARLY(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(100, 200);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg |= SSPX_ELPG_CLAMP_EN(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(250, 350);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg |= SSPX_ELPG_VCORE_DOWN(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_usb3_phy_enable_sleepwalk(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy enable sleepwalk USB3 %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg |= SSPX_ELPG_CLAMP_EN_EARLY(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(100, 200);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg |= SSPX_ELPG_CLAMP_EN(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(250, 350);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_usb3_phy_disable_sleepwalk(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy disable sleepwalk USB3 %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg &= ~SSPX_ELPG_CLAMP_EN_EARLY(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	usleep_range(100, 200);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM_1);
	reg &= ~SSPX_ELPG_CLAMP_EN(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM_1);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_usb3_phy_enable_wake(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy enable wake USB3 %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= SS_PORT_WAKEUP_EVENT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	usleep_range(10, 20);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= SS_PORT_WAKE_INTERRUPT_ENABLE(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_usb3_phy_disable_wake(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	u32 reg;

	dev_dbg(dev, "phy disable wake USB3 %d\n", index);

	mutex_lock(&padctl->lock);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg &= ~SS_PORT_WAKE_INTERRUPT_ENABLE(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	usleep_range(10, 20);

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	reg &= ~ALL_WAKE_EVENTS;
	reg |= SS_PORT_WAKEUP_EVENT(index);
	padctl_writel(padctl, reg, XUSB_PADCTL_ELPG_PROGRAM);

	mutex_unlock(&padctl->lock);

	return 0;
}

static int tegra186_usb3_phy_init(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	struct device *dev = padctl->dev;
	unsigned int index = lane->index;
	struct tegra_xusb_usb3_port *port;
	struct tegra_xusb_usb2_port *companion_usb2_port;
	int rc = 0;

	dev_dbg(dev, "phy init USB3 %d\n", index);

	port = tegra_xusb_find_usb3_port(padctl, index);
	if (!port) {
		dev_err(dev, "no port found for USB3 lane %u\n", index);
		return -ENODEV;
	}

	companion_usb2_port = tegra_xusb_find_usb2_port(padctl, port->port);
	if (!companion_usb2_port) {
		dev_err(dev, "no companion port found for USB3 lane %u\n",
			index);
		return -ENODEV;
	}
	dev_dbg(dev, "USB3 port %d companion USB2 port %d mode %d\n", index,
		port->port, companion_usb2_port->port_cap);

	mutex_lock(&padctl->lock);

	port->port_cap = companion_usb2_port->port_cap;
	port->oc_pin = companion_usb2_port->oc_pin;

	if (port->port_cap == USB_OTG_CAP) {
		if (padctl->usb3_otg_port_base_1)
			dev_warn(dev, "enabling OTG on multiple USB3 ports\n");
		padctl->usb3_otg_port_base_1 = index + 1;
	}

	mutex_unlock(&padctl->lock);

	return rc;
}

static int tegra186_usb3_phy_exit(struct phy *phy)
{
	struct tegra_xusb_lane *lane = phy_get_drvdata(phy);
	struct tegra_xusb_padctl *padctl = lane->pad->padctl;
	unsigned int index = lane->index;
	struct device *dev = padctl->dev;
	struct tegra_xusb_usb3_port *port;
	int rc = 0;

	dev_dbg(dev, "phy exit USB3 %d\n", index);

	port = tegra_xusb_find_usb3_port(padctl, index);
	if (!port) {
		dev_err(dev, "no port found for USB3 lane %u\n", index);
		return -ENODEV;
	}

	mutex_lock(&padctl->lock);

	if (index == padctl->usb3_otg_port_base_1 - 1)
		padctl->usb3_otg_port_base_1 = 0;

	mutex_unlock(&padctl->lock);

	return rc;
}

static const struct phy_ops usb3_phy_ops = {
	.init = tegra186_usb3_phy_init,
	.exit = tegra186_usb3_phy_exit,
	.power_on = tegra186_usb3_phy_power_on,
	.power_off = tegra186_usb3_phy_power_off,
	.owner = THIS_MODULE,
};

static inline bool is_usb3_phy(struct phy *phy)
{
	return phy->ops == &usb3_phy_ops;
}

static bool is_usb3_phy_has_otg_cap(struct tegra_xusb_padctl *padctl,
					struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	unsigned int index;
	struct tegra_xusb_usb3_port *port;
	struct tegra_xusb_usb2_port *companion_usb2_port;

	if (!phy)
		return false;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	port = tegra_xusb_find_usb3_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for USB3 lane %u\n", index);
		return false;
	}

	companion_usb2_port = tegra_xusb_find_usb2_port(padctl, port->port);
	if (!companion_usb2_port)
		return false;

	return companion_usb2_port->port_cap == USB_OTG_CAP;
}

static struct tegra_xusb_pad *
tegra186_usb3_pad_probe(struct tegra_xusb_padctl *padctl,
			const struct tegra_xusb_pad_soc *soc,
			struct device_node *np)
{
	struct tegra_xusb_usb3_pad *usb3;
	struct tegra_xusb_pad *pad;
	int err;

	usb3 = kzalloc(sizeof(*usb3), GFP_KERNEL);
	if (!usb3)
		return ERR_PTR(-ENOMEM);

	pad = &usb3->base;
	pad->ops = &tegra186_usb3_lane_ops;
	pad->soc = soc;

	err = tegra_xusb_pad_init(pad, padctl, np);
	if (err < 0) {
		kfree(usb3);
		goto out;
	}

	err = tegra_xusb_pad_register(pad, &usb3_phy_ops);
	if (err < 0)
		goto unregister;

	dev_set_drvdata(&pad->dev, pad);

	return pad;

unregister:
	device_unregister(&pad->dev);
out:
	return ERR_PTR(err);
}

static void tegra186_usb3_pad_remove(struct tegra_xusb_pad *pad)
{
	struct tegra_xusb_usb2_pad *usb2 = to_usb2_pad(pad);

	kfree(usb2);
}

static const struct tegra_xusb_pad_ops tegra186_usb3_pad_ops = {
	.probe = tegra186_usb3_pad_probe,
	.remove = tegra186_usb3_pad_remove,
};

static const char * const tegra186_usb3_functions[] = {
	"xusb",
};

static const struct tegra_xusb_lane_soc tegra186_usb3_lanes[] = {
	TEGRA186_LANE("usb3-0", 0,  0, 0, usb3),
	TEGRA186_LANE("usb3-1", 0,  0, 0, usb3),
	TEGRA186_LANE("usb3-2", 0,  0, 0, usb3),
};

static const struct tegra_xusb_pad_soc tegra186_usb3_pad = {
	.name = "usb3",
	.num_lanes = ARRAY_SIZE(tegra186_usb3_lanes),
	.lanes = tegra186_usb3_lanes,
	.ops = &tegra186_usb3_pad_ops,
};

static const struct tegra_xusb_pad_soc * const tegra186_pads[] = {
	&tegra186_usb2_pad,
	&tegra186_usb3_pad,
	&tegra186_hsic_pad,
};

static int
tegra186_xusb_read_fuse_calibration(struct tegra186_xusb_padctl *padctl)
{
	unsigned int i;
	int rc;
	u32 reg;

	rc = tegra_fuse_readl(TEGRA_FUSE_SKU_CALIB_0, &reg);
	if (rc) {
		dev_err(padctl->base.dev, "read calib fuse failed %d\n", rc);
		return rc;
	}

	dev_dbg(padctl->base.dev, "FUSE_USB_CALIB_0 0x%x\n", reg);

	for (i = 0; i < TEGRA186_UTMI_PHYS; i++) {
		padctl->calib.hs_curr_level[i] =
			(reg >> HS_CURR_LEVEL_PADX_SHIFT(i)) &
			HS_CURR_LEVEL_PAD_MASK;
	}
	padctl->calib.hs_squelch = (reg >> HS_SQUELCH_SHIFT) & HS_SQUELCH_MASK;
	padctl->calib.hs_term_range_adj = (reg >> HS_TERM_RANGE_ADJ_SHIFT) &
					HS_TERM_RANGE_ADJ_MASK;

	rc = tegra_fuse_readl(TEGRA_FUSE_USB_CALIB_EXT_0, &reg);
	if (rc) {
		dev_err(padctl->base.dev, "read calib fuse failed %d\n", rc);
		return rc;
	}

	dev_dbg(padctl->base.dev, "FUSE_USB_CALIB_EXT_0 0x%x\n", reg);

	padctl->calib.rpd_ctrl = (reg >> RPD_CTRL_SHIFT) & RPD_CTRL_MASK;

	return 0;
}

static struct tegra_xusb_padctl *
tegra186_xusb_padctl_probe(struct device *dev,
			   const struct tegra_xusb_padctl_soc *soc)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra186_xusb_padctl *priv;
	struct resource *res;
	int err;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	priv->base.dev = dev;
	priv->base.soc = soc;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ao");
	priv->ao_regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(priv->ao_regs))
		return priv->ao_regs;

	err = tegra186_xusb_read_fuse_calibration(priv);
	if (err < 0)
		return ERR_PTR(err);

	priv->prod_list = devm_tegra_prod_get(dev);
	if (IS_ERR(priv->prod_list)) {
		dev_warn(dev, "Prod-settings is not available\n");
		priv->prod_list = NULL;
	}

	return &priv->base;
}

static void tegra186_xusb_padctl_remove(struct tegra_xusb_padctl *padctl)
{
	int i;
	int err;

	/* switch all VBUS_ENx pins back to default state */
	if (padctl->oc_pinctrl)
		for (i = 0; i < padctl->soc->num_oc_pins; i++) {
			err = pinctrl_select_state(padctl->oc_pinctrl,
						padctl->oc_disable[i]);
			if (err)
				dev_dbg(padctl->dev,
				"Set VBUS_ENx pins to default err=%d\n", err);
		}
}

static void tegra186_xusb_padctl_save(struct tegra_xusb_padctl *padctl)
{
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);

	priv->context.vbus_id = padctl_readl(padctl, USB2_VBUS_ID);
	priv->context.usb2_pad_mux =
				padctl_readl(padctl, XUSB_PADCTL_USB2_PAD_MUX);
	priv->context.usb2_port_cap =
				padctl_readl(padctl, XUSB_PADCTL_USB2_PORT_CAP);
	priv->context.ss_port_cap =
				padctl_readl(padctl, XUSB_PADCTL_SS_PORT_CAP);
	priv->context.vbus_oc_map =
				padctl_readl(padctl, XUSB_PADCTL_VBUS_OC_MAP);
}

static void tegra186_xusb_padctl_restore(struct tegra_xusb_padctl *padctl)
{
	struct tegra186_xusb_padctl *priv = to_tegra186_xusb_padctl(padctl);
	struct tegra_xusb_usb2_port *port;
	u32 i;
	int rc = 0;

	padctl_writel(padctl, priv->context.usb2_pad_mux,
			XUSB_PADCTL_USB2_PAD_MUX);
	padctl_writel(padctl, priv->context.usb2_port_cap,
			XUSB_PADCTL_USB2_PORT_CAP);
	padctl_writel(padctl, priv->context.ss_port_cap,
			XUSB_PADCTL_SS_PORT_CAP);
	padctl_writel(padctl, priv->context.vbus_id, USB2_VBUS_ID);

	/* ensure to enable the vbus oc, if needed */
	for (i = 0; i < padctl->soc->ports.usb2.count; i++) {
		port = tegra_xusb_find_usb2_port(padctl, i);
		if (port == NULL)
			continue;

		mutex_lock(&padctl->lock);
		if ((padctl->oc_pinctrl != NULL) && port->oc_pin >= 0
		&& !!(priv->context.vbus_oc_map & VBUS_ENABLE(port->oc_pin))) {
			rc = tegra_xusb_select_vbus_en_state(padctl,
							port->oc_pin, true);
			if (rc == 0)
				tegra186_enable_vbus_oc(padctl->usb2->lanes[i]);
		}
		mutex_unlock(&padctl->lock);
	}
}

static int tegra186_xusb_padctl_suspend_noirq(struct tegra_xusb_padctl *padctl)
{
	tegra186_xusb_padctl_save(padctl);

	return 0;
}

static int tegra186_xusb_padctl_resume_noirq(struct tegra_xusb_padctl *padctl)
{
	tegra186_xusb_padctl_restore(padctl);

	return 0;
}

static int tegra186_xusb_padctl_vbus_override(struct tegra_xusb_padctl *padctl,
		unsigned int i, bool set)
{
	u32 reg;

	reg = padctl_readl(padctl, USB2_VBUS_ID);
	if (set) {
		reg |= VBUS_OVERRIDE;
		reg &= ~ID_OVERRIDE(~0);
		reg |= ID_OVERRIDE_FLOATING;
	} else
		reg &= ~VBUS_OVERRIDE;
	padctl_writel(padctl, reg, USB2_VBUS_ID);

	padctl->otg_vbus_updating[i] = true;
	schedule_work(&padctl->otg_vbus_work);
	return 0;
}

static int tegra186_xusb_padctl_id_override(struct tegra_xusb_padctl *padctl,
		unsigned int i, bool set)
{
	u32 reg;

	reg = padctl_readl(padctl, USB2_VBUS_ID);
	if (set) {
		if (reg & VBUS_OVERRIDE) {
			reg &= ~VBUS_OVERRIDE;
			padctl_writel(padctl, reg, USB2_VBUS_ID);
			usleep_range(1000, 2000);

			reg = padctl_readl(padctl, USB2_VBUS_ID);
		}

		reg &= ~ID_OVERRIDE(~0);
		reg |= ID_OVERRIDE_GROUNDED;
	} else {
		reg &= ~ID_OVERRIDE(~0);
		reg |= ID_OVERRIDE_FLOATING;
	}
	padctl_writel(padctl, reg, USB2_VBUS_ID);

	padctl->otg_vbus_updating[i] = true;
	schedule_work(&padctl->otg_vbus_work);

	return 0;
}

static bool tegra186_xusb_padctl_has_otg_cap(struct tegra_xusb_padctl *padctl,
					struct phy *phy)
{
	if (is_utmi_phy(phy))
		return is_utmi_phy_has_otg_cap(padctl, phy);
	else if (is_usb3_phy(phy))
		return is_usb3_phy_has_otg_cap(padctl, phy);

	return false;
}

static int tegra186_xusb_padctl_vbus_power_on(struct tegra_xusb_padctl *padctl,
					unsigned int index)
{
	int rc = 0;
	int status;
	struct tegra_xusb_usb2_port *port;

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for USB2 lane %u\n", index);
		return -ENODEV;
	}

	if (!port->supply) {
		dev_err(padctl->dev, "no vbus-supply found for USB2-%u\n",
			index);
		return -ENODEV;
	}

	mutex_lock(&padctl->lock);

	if (padctl->oc_pinctrl && port->oc_pin >= 0) {
		rc = tegra_xusb_select_vbus_en_state(padctl,
						port->oc_pin, true);
		tegra186_enable_vbus_oc(padctl->usb2->lanes[index]);
	} else {
		status = regulator_is_enabled(port->supply);
		if (!status) {
			rc = regulator_enable(port->supply);
			if (rc)
				dev_err(padctl->dev,
				"enable usb2-%d vbus failed %d\n", index, rc);
		}

		dev_dbg(padctl->dev, "%s: usb2-%d vbus status: %d->%d\n",
			__func__, index, status,
			regulator_is_enabled(port->supply));
	}
	mutex_unlock(&padctl->lock);
	return rc;
}

static int tegra186_xusb_padctl_vbus_power_off(struct tegra_xusb_padctl *padctl,
					unsigned int index)
{
	int rc = 0;
	int status;
	struct tegra_xusb_usb2_port *port;

	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port) {
		dev_err(padctl->dev, "no port found for USB2 lane %u\n", index);
		return -ENODEV;
	}

	if (padctl->otg_vbus_alwayson) {
		dev_dbg(padctl->dev, "%s: usb2-%d vbus cannot off due to alwayson\n",
			__func__, index);
		return -EINVAL;
	}

	if (!port->supply) {
		dev_err(padctl->dev, "no vbus-supply found for USB2-%u\n",
			index);
		return -ENODEV;
	}

	mutex_lock(&padctl->lock);

	if (padctl->oc_pinctrl && port->oc_pin >= 0) {
		rc = tegra_xusb_select_vbus_en_state(padctl,
						port->oc_pin, false);
		tegra186_disable_vbus_oc(padctl->usb2->lanes[index]);
	} else {
		status = regulator_is_enabled(port->supply);
		if (status) {
			rc = regulator_disable(port->supply);
			if (rc)
				dev_err(padctl->dev,
					"disable usb2-%d vbus failed %d\n",
					index, rc);
		}

		dev_dbg(padctl->dev, "%s: usb2-%d vbus status: %d->%d\n",
			__func__, index, status,
			regulator_is_enabled(port->supply));
	}
	mutex_unlock(&padctl->lock);
	return rc;
}

static void
tegra186_xusb_padctl_otg_vbus_handle(struct tegra_xusb_padctl *padctl,
		unsigned int vbus_id, unsigned int index)
{
	u32 reg;
	int err;

	reg = padctl_readl(padctl, USB2_VBUS_ID);
	dev_dbg(padctl->dev, "USB2_VBUS_ID 0x%x otg_vbus_on was %d\n", reg,
		padctl->otg_vbus_on[0]);

	if ((reg & ID_OVERRIDE(~0)) == ID_OVERRIDE_GROUNDED) {
		/* entering host mode role */
		if (!padctl->otg_vbus_on[0]) {
			err = tegra186_xusb_padctl_vbus_power_on(padctl, index);
			if (!err)
				padctl->otg_vbus_on[0] = true;
		}
	} else if ((reg & ID_OVERRIDE(~0)) == ID_OVERRIDE_FLOATING) {
		/* leaving host mode role */
		if (padctl->otg_vbus_on[0]) {
			err = tegra186_xusb_padctl_vbus_power_off(padctl,
								  index);
			if (!err)
				padctl->otg_vbus_on[0] = false;
		}
	}
}

static int tegra186_xusb_padctl_phy_sleepwalk(struct tegra_xusb_padctl *padctl,
					      struct phy *phy, bool enable,
					      enum usb_device_speed speed)
{
	if (!phy)
		return 0;

	if (is_usb3_phy(phy)) {
		if (enable)
			return tegra186_usb3_phy_enable_sleepwalk(phy);
		else
			return tegra186_usb3_phy_disable_sleepwalk(phy);
	} else if (is_utmi_phy(phy)) {
		if (enable)
			return tegra186_utmi_phy_enable_sleepwalk(phy, speed);
		else
			return tegra186_utmi_phy_disable_sleepwalk(phy);
	} else if (is_hsic_phy(phy)) {
		if (enable)
			return tegra186_hsic_phy_enable_sleepwalk(phy);
		else
			return tegra186_hsic_phy_disable_sleepwalk(phy);
	} else
		return -EINVAL;

	return 0;
}

static int tegra186_xusb_padctl_phy_wake(struct tegra_xusb_padctl *padctl,
					 struct phy *phy, bool enable)
{
	if (!phy)
		return 0;

	if (is_usb3_phy(phy)) {
		if (enable)
			return tegra186_usb3_phy_enable_wake(phy);
		else
			return tegra186_usb3_phy_disable_wake(phy);
	} else if (is_utmi_phy(phy)) {
		if (enable)
			return tegra186_utmi_phy_enable_wake(phy);
		else
			return tegra186_utmi_phy_disable_wake(phy);
	} else if (is_hsic_phy(phy)) {
		if (enable)
			return tegra186_hsic_phy_enable_wake(phy);
		else
			return tegra186_hsic_phy_disable_wake(phy);
	} else
		return -EINVAL;

	return 0;
}

static int tegra186_usb3_phy_remote_wake_detected(
			struct tegra_xusb_padctl *padctl, int port)
{
	u32 reg;

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	if ((reg & SS_PORT_WAKE_INTERRUPT_ENABLE(port)) &&
			(reg & SS_PORT_WAKEUP_EVENT(port)))
		return true;
	else
		return false;
}

static int tegra186_utmi_phy_remote_wake_detected(
			struct tegra_xusb_padctl *padctl, int port)
{
	u32 reg;

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	if ((reg & USB2_PORT_WAKE_INTERRUPT_ENABLE(port)) &&
			(reg & USB2_PORT_WAKEUP_EVENT(port)))
		return true;
	else
		return false;
}

static int tegra186_hsic_phy_remote_wake_detected(
			struct tegra_xusb_padctl *padctl, int port)
{
	u32 reg;

	reg = padctl_readl(padctl, XUSB_PADCTL_ELPG_PROGRAM);
	if ((reg & USB2_HSIC_PORT_WAKE_INTERRUPT_ENABLE(port)) &&
			(reg & USB2_HSIC_PORT_WAKEUP_EVENT(port)))
		return true;
	else
		return false;
}

int tegra186_xusb_padctl_remote_wake_detected(struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_padctl *padctl;
	unsigned int index;

	if (!phy)
		return 0;

	lane = phy_get_drvdata(phy);
	padctl = lane->pad->padctl;
	index = lane->index;

	if (is_utmi_phy(phy))
		return tegra186_utmi_phy_remote_wake_detected(padctl, index);
	else if (is_usb3_phy(phy))
		return tegra186_usb3_phy_remote_wake_detected(padctl, index);
	else if (is_hsic_phy(phy))
		return tegra186_hsic_phy_remote_wake_detected(padctl, index);

	return -EINVAL;
}

static int tegra186_xusb_padctl_set_debounce_time(struct tegra_xusb_padctl
					*padctl, struct phy *phy, u32 val)
{
	u32 reg;

	if (!phy)
		return -EINVAL;

	reg = padctl_readl(padctl,
		XUSB_PADCTL_USB2_BATTERY_CHRG_TDCD_DBNC_TIMER_0);
	reg &= ~(TDCD_DBNC(0));
	reg |= TDCD_DBNC(val);
	padctl_writel(padctl, reg,
		XUSB_PADCTL_USB2_BATTERY_CHRG_TDCD_DBNC_TIMER_0);

	return 0;
}

static int tegra186_xusb_padctl_utmi_pad_charger_detect_on(
			struct tegra_xusb_padctl *padctl, struct phy *phy)
{
	u32 reg;
	unsigned int index;
	struct tegra_xusb_lane *lane;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	tegra186_utmi_pad_power_on(phy);

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
	reg &= ~USB2_OTG_PD_ZI;
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
	reg |= (USB2_OTG_PD2 | USB2_OTG_PD2_OVRD_EN);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg &= ~PD_CHG;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	/* Set DP/DN Pull up/down to zero by default */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	reg &= ~(USBOP_RPD_OVRD_VAL | USBOP_RPU_OVRD_VAL |
		USBON_RPD_OVRD_VAL | USBON_RPU_OVRD_VAL);
	reg |= (USBOP_RPD_OVRD | USBOP_RPU_OVRD |
		USBON_RPD_OVRD | USBON_RPU_OVRD);
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	/* Disable DP/DN as src/sink */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg &= ~(OP_SRC_EN | ON_SINK_EN |
	ON_SRC_EN | OP_SINK_EN);
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	return 0;
}

static int tegra186_xusb_padctl_utmi_pad_charger_detect_off(
			 struct tegra_xusb_padctl *padctl, struct phy *phy)
{
	u32 reg;
	struct tegra_xusb_lane *lane;
	unsigned int index;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	reg &= ~(USBOP_RPD_OVRD | USBOP_RPU_OVRD |
		 USBON_RPD_OVRD | USBON_RPU_OVRD);
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	/* power down necessary stuff */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg |= PD_CHG;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	reg = padctl_readl(padctl, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
	reg &= ~(USB2_OTG_PD2 | USB2_OTG_PD2_OVRD_EN);
	padctl_writel(padctl, reg, XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

	tegra186_utmi_pad_power_down(phy);

	return 0;
}

static int tegra186_xusb_padctl_detect_filters(
			struct tegra_xusb_padctl *padctl,
			struct phy *phy,
			bool on)
{
	u32 reg;
	unsigned int index;
	struct tegra_xusb_lane *lane;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	if (on) {
		reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		reg |= (VDCD_DET_FILTER_EN | VDAT_DET_FILTER_EN |
			ZIP_FILTER_EN | ZIN_FILTER_EN);
		padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	} else {
		reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		reg &= ~(VDCD_DET_FILTER_EN | VDAT_DET_FILTER_EN |
			ZIP_FILTER_EN | ZIN_FILTER_EN);
		padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	}
	return 0;
}

static int tegra186_xusb_padctl_utmi_pad_set_protection_level(
				struct tegra_xusb_padctl *padctl,
				struct phy *phy,
				int level,
				enum tegra_vbus_dir dir)
{
	u32 reg;
	unsigned int index;
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_port *xusb;
	struct tegra_xusb_usb2_port *usb2;
	char name[7];


	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;
	snprintf(name, ARRAY_SIZE(name), "usb2-%d", index);

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	if (level < 0) {
		/* disable pad protection */
		reg |= PD_VREG;
		reg &= ~VREG_LEV(~0);
		reg &= ~VREG_DIR(~0);
	} else {
		list_for_each_entry(xusb, &padctl->ports, list) {
			if (strcmp(dev_name(&xusb->dev), name) == 0)
				break;
		}
		usb2 = container_of(xusb, struct tegra_xusb_usb2_port, base);

		if (usb2->port_cap == USB_HOST_CAP ||
					dir == TEGRA_VBUS_SOURCE)
			reg |= VREG_DIR_OUT;
		else if (usb2->port_cap == USB_DEVICE_CAP ||
					dir == TEGRA_VBUS_SINK)
			reg |= VREG_DIR_IN;
		reg &= ~PD_VREG;
		reg &= ~VREG_DIR(~0);
		reg &= ~VREG_LEV(~0);
		reg |= VREG_LEV(level);
	}
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	return 0;
}

static int tegra186_xusb_padctl_utmi_pad_dcd(struct tegra_xusb_padctl *padctl,
					struct phy *phy)
{
	u32 reg;
	unsigned int index;
	int dcd_timeout_ms = 0;
	bool ret = false;
	struct tegra_xusb_lane *lane;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	/* data contact detection */
	/* Turn on IDP_SRC */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg |= OP_I_SRC_EN;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	/* Turn on D- pull-down resistor */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	reg |= USBON_RPD_OVRD_VAL;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	/* Wait for TDCD_DBNC */
	usleep_range(10000, 120000);

	while (dcd_timeout_ms < TDCD_TIMEOUT_MS) {
		reg = padctl_readl(padctl,
			USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		if (reg & DCD_DETECTED) {
			dev_dbg(padctl->dev, "USB2 port %d DCD successful\n",
				index);
			ret = true;
			break;
		}
		usleep_range(20000, 22000);
		dcd_timeout_ms += 22;
	}

	if (!ret)
		dev_info(padctl->dev, "%s: DCD timeout %d ms\n", __func__,
			dcd_timeout_ms);

	/* Turn off IP_SRC, clear DCD DETECTED*/
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg &= ~OP_I_SRC_EN;
	reg |= DCD_DETECTED;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	/* Turn off D- pull-down resistor */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	reg &= ~USBON_RPD_OVRD_VAL;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	return ret;
}

static int tegra186_xusb_padctl_noncompliant_div_detect(struct tegra_xusb_padctl
				*padctl, struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	u32 reg;
	unsigned int index;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	reg |= DIV_DET_EN;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	udelay(10);

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));
	reg &= ~DIV_DET_EN;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL1(index));

	return reg;
}

static int tegra186_xusb_padctl_utmi_pad_primary_charger_detect(
				struct tegra_xusb_padctl *padctl,
				struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	u32 reg;
	unsigned int index;
	int ret = false;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	/* Source D+ to D- */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg |= OP_SRC_EN | ON_SINK_EN;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	/* Wait for TVDPSRC_ON */
	msleep(40);

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	ret = !!(reg & VDAT_DET);

	/* Turn off OP_SRC, ON_SINK, clear VDAT, ZIN status change */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg &= ~(OP_SRC_EN | ON_SINK_EN);
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	return ret;
}

static int tegra186_xusb_padctl_utmi_pad_secondary_charger_detect(
				struct tegra_xusb_padctl *padctl,
				struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	u32 reg;
	unsigned int index;
	bool ret = false;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	/* Source D- to D+ */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg |= ON_SRC_EN | OP_SINK_EN;
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	/* Wait for TVDPSRC_ON */
	msleep(40);

	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	ret = !(reg & VDAT_DET);

	/* Turn off ON_SRC, OP_SINK, clear VDAT, ZIP status change */
	reg = padctl_readl(padctl, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
	reg &= ~(ON_SRC_EN | OP_SINK_EN);
	padctl_writel(padctl, reg, USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

	return ret;
}

static int tegra186_usb2_set_host_cdp(struct tegra_xusb_padctl *padctl,
					struct phy *phy, bool enable)
{
	struct tegra_xusb_lane *lane;
	u32 reg;
	unsigned int index;

	if (!phy)
		return -EINVAL;

	lane = phy_get_drvdata(phy);
	index = lane->index;

	dev_dbg(padctl->dev, "%sable USB2 port %d Tegra CDP\n",
		 enable ? "en" : "dis", index);
	if (enable) {
		reg = padctl_readl(padctl,
				   USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		reg &= ~PD_CHG;
		padctl_writel(padctl, reg,
			      USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

		reg = padctl_readl(padctl,
				   XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
		reg |= (USB2_OTG_PD2 | USB2_OTG_PD2_OVRD_EN);
		padctl_writel(padctl, reg,
			      XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

		reg = padctl_readl(padctl,
				   USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		reg |= ON_SRC_EN;
		padctl_writel(padctl, reg,
			      USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

		/* Dont let BIAS pad power down */
		padctl->cdp_used = true;
	} else {
		reg = padctl_readl(padctl,
				   USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		reg |= PD_CHG;
		padctl_writel(padctl, reg,
			      USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

		reg = padctl_readl(padctl,
				   XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));
		reg &= ~USB2_OTG_PD2_OVRD_EN;
		padctl_writel(padctl, reg,
			      XUSB_PADCTL_USB2_OTG_PADX_CTL0(index));

		reg = padctl_readl(padctl,
				   USB2_BATTERY_CHRG_OTGPADX_CTL0(index));
		reg &= ~ON_SRC_EN;
		padctl_writel(padctl, reg,
			      USB2_BATTERY_CHRG_OTGPADX_CTL0(index));

		padctl->cdp_used = false;
	}

	return 0;
}

int tegra186_phy_xusb_overcurrent_detected(struct phy *phy)
{
	struct tegra_xusb_lane *lane;
	struct tegra_xusb_padctl *padctl;
	struct tegra_xusb_usb2_port *port;
	unsigned int index;
	bool detected = false;
	u32 reg;
	int pin;

	if (!phy)
		return 0;

	lane = phy_get_drvdata(phy);
	padctl = lane->pad->padctl;
	if (!is_utmi_phy(phy))
		return -EINVAL;

	index = lane->index;
	port = tegra_xusb_find_usb2_port(padctl, index);
	if (!port)
		return -EINVAL;

	pin = port->oc_pin;
	if (pin < 0)
		return -EINVAL;

	reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);

	detected = !!(reg & OC_DETECTED_VBUS_PAD(pin));
	if (detected) {
		reg &= ~OC_DETECTED_VBUS_PAD_MASK;
		reg &= ~OC_DETECTED_INT_EN_VBUS_PAD(pin);
		padctl_writel(padctl, reg, XUSB_PADCTL_OC_DET);
	}

	return detected;
}

void tegra186_phy_xusb_handle_overcurrent(struct tegra_xusb_padctl *padctl)
{
	struct tegra_xusb_usb2_port *port;
	unsigned int i;
	u32 reg;
	int pin;

	oc_debug(padctl);
	mutex_lock(&padctl->lock);
	reg = padctl_readl(padctl, XUSB_PADCTL_OC_DET);

	for (i = 0; i < TEGRA186_UTMI_PHYS; i++) {
		port = tegra_xusb_find_usb2_port(padctl, i);
		if (!port)
			continue;

		pin = port->oc_pin;
		if (pin < 0)
			continue;

		if (reg & OC_DETECTED_VBUS_PAD(pin)) {
			dev_info(padctl->dev,
					"%s: clear port %d pin %d OC\n",
					__func__, i, pin);
			tegra186_enable_vbus_oc(padctl->usb2->lanes[i]);
		}
	}
	mutex_unlock(&padctl->lock);
}

static const struct tegra_xusb_padctl_ops tegra186_xusb_padctl_ops = {
	.probe = tegra186_xusb_padctl_probe,
	.remove = tegra186_xusb_padctl_remove,
	.suspend_noirq = tegra186_xusb_padctl_suspend_noirq,
	.resume_noirq = tegra186_xusb_padctl_resume_noirq,
	.vbus_override = tegra186_xusb_padctl_vbus_override,
	.id_override = tegra186_xusb_padctl_id_override,
	.has_otg_cap = tegra186_xusb_padctl_has_otg_cap,
	.vbus_power_on = tegra186_xusb_padctl_vbus_power_on,
	.vbus_power_off = tegra186_xusb_padctl_vbus_power_off,
	.otg_vbus_handle = tegra186_xusb_padctl_otg_vbus_handle,
	.phy_sleepwalk = tegra186_xusb_padctl_phy_sleepwalk,
	.phy_wake = tegra186_xusb_padctl_phy_wake,
	.remote_wake_detected = tegra186_xusb_padctl_remote_wake_detected,
	.set_debounce_time = tegra186_xusb_padctl_set_debounce_time,
	.utmi_pad_charger_detect_on =
			tegra186_xusb_padctl_utmi_pad_charger_detect_on,
	.utmi_pad_charger_detect_off =
			tegra186_xusb_padctl_utmi_pad_charger_detect_off,
	.detect_filters = tegra186_xusb_padctl_detect_filters,
	.utmi_pad_set_protection_level =
			tegra186_xusb_padctl_utmi_pad_set_protection_level,
	.utmi_pad_dcd = tegra186_xusb_padctl_utmi_pad_dcd,
	.noncompliant_div_detect = tegra186_xusb_padctl_noncompliant_div_detect,
	.utmi_pad_primary_charger_detect =
			tegra186_xusb_padctl_utmi_pad_primary_charger_detect,
	.utmi_pad_secondary_charger_detect =
			tegra186_xusb_padctl_utmi_pad_secondary_charger_detect,
	.set_host_cdp = tegra186_usb2_set_host_cdp,
	.overcurrent_detected = tegra186_phy_xusb_overcurrent_detected,
	.handle_overcurrent = tegra186_phy_xusb_handle_overcurrent,
	.utmi_pad_power_on = tegra186_utmi_pad_power_on,
	.utmi_pad_power_down = tegra186_utmi_pad_power_down,
	.hsic_set_idle = tegra186_hsic_set_idle,
	.hsic_reset = tegra186_hsic_reset,
};

static const char * const tegra186_supply_names[] = {
	"avdd_usb",		/* 3.3V, vddp_usb */
	"vclamp_usb",		/* 1.8V, vclamp_usb_init */
	"avdd_pll_erefeut",	/* 1.8V, pll_utmip_avdd */
};

const struct tegra_xusb_padctl_soc tegra186_xusb_padctl_soc = {
	.num_pads = ARRAY_SIZE(tegra186_pads),
	.num_oc_pins = TEGRA186_OC_PIN_NUM,
	.pads = tegra186_pads,
	.ports = {
		.usb2 = {
			.ops = &tegra186_usb2_port_ops,
			.count = TEGRA186_UTMI_PHYS,
		},
		.usb3 = {
			.ops = &tegra186_usb3_port_ops,
			.count = TEGRA186_USB3_PHYS,
		},
		.hsic = {
			.ops = &tegra186_hsic_port_ops,
			.count = TEGRA186_HSIC_PHYS,
		},
	},
	.ops = &tegra186_xusb_padctl_ops,
	.supply_names = tegra186_supply_names,
	.num_supplies = ARRAY_SIZE(tegra186_supply_names),
};
EXPORT_SYMBOL_GPL(tegra186_xusb_padctl_soc);

MODULE_AUTHOR("JC Kuo <jckuo@nvidia.com>");
MODULE_DESCRIPTION("Tegra186 (Parker) XUSB PADCTL driver");
MODULE_LICENSE("GPL v2");
