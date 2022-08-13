/*
 * drivers/net/phy/realtek.c
 *
 * Driver for Realtek PHYs
 *
 * Author: Johnson Leung <r58129@freescale.com>
 *
 * Copyright (c) 2004 Freescale Semiconductor, Inc.
 * Copyright (c) 2019 - 2020, NVIDIA CORPORATION. All rights reserved.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */
#include <linux/phy.h>
#include <linux/module.h>
#include <linux/netdevice.h>

#define RTL821x_PHYSR		0x11
#define RTL821x_PHYSR_DUPLEX	0x2000
#define RTL821x_PHYSR_SPEED	0xc000
#define RTL821x_INER		0x12
#define RTL821x_INER_INIT	0x6400
#define RTL821x_INSR		0x13
#define RTL8211E_INER_LINK_STATUS 0x400

#define RTL8211F_INER_LINK_STATUS 0x0010
#define RTL8211F_INSR		0x1d
#define RTL8211F_PAGE_SELECT	0x1f
#define RTL8211F_TX_DELAY	0x100
#define RTL8211F_DEFAULT_PAGE	0xa42
#define RTL8211F_PHYCR1_PAGE	0xa43
#define RTL8211F_LED_PAGE	0xd04

#define RTL8211F_PHYCR1_REG	0x18
#define RTL8211F_PHYCR2_REG	0x19
#define RTL8211F_ALDPS_ENABLED	0x4
#define RTL8211F_ALDPS_PLL_OFF	0x2
#define RTL8211F_LED0_LINK_1000	0x8
#define RTL8211F_LED1_LINK_1000	0x100
#define RTL8211F_LED1_LINK_100	0x40
#define RTL8211F_LED1_LINK_10	0x20
#define RTL8211F_LED1_LINK_ACTIVE	0x200
#define RTL8211F_PAGE_LCR_LED_CONTROL	0x10
#define RTL8211F_PAGE_EEE_LED_CONTROL	0x11

#define RTL8211F_INTERRUPT_SELECT_PAGE	0xd40
#define RTL8211F_WOL_FRAME_SELECT_PAGE	0xd80
#define RTL8211F_WOL_MAC_PAGE		0xd8c
#define RTL8211F_WOL_SETTING_PAGE	0xd8a

#define RTL8211F_INTERRUPT_SELECT_REG	0x16
#define RTL8211F_WOL_REG_MAC_WORD_0	0x10
#define RTL8211F_WOL_REG_MAC_WORD_1	0x11
#define RTL8211F_WOL_REG_MAC_WORD_2	0x12
#define RTL8211F_WOL_REG_PACKET_LEN	0x11
#define RTL8211F_WOL_REG_FRAME_EVENT	0x10

#define RTL8211F_WOL_PACKET_LEN			0x1fff
#define RTL8211F_WOL_SET_PACKET_LEN		BIT(15)
#define RTL8211F_WOL_ENABLE_MAGIC_PACKET	BIT(12)
#define RTL8211F_WOL_ENABLE_PMEB_EVENT		BIT(7)

#define BIT_SHIFT_8 8
#define MAC_ADDRESS_BYTE_0 0
#define MAC_ADDRESS_BYTE_1 1
#define MAC_ADDRESS_BYTE_2 2
#define MAC_ADDRESS_BYTE_3 3
#define MAC_ADDRESS_BYTE_4 4
#define MAC_ADDRESS_BYTE_5 5

MODULE_DESCRIPTION("Realtek PHY driver");
MODULE_AUTHOR("Johnson Leung");
MODULE_LICENSE("GPL");

static int rtl8211f_wol_settings(struct phy_device *phydev, bool enable)
{
	int ret;

	/* Set WoL events and packet length */

	ret = phy_write(phydev, RTL8211F_PAGE_SELECT,
			RTL8211F_WOL_SETTING_PAGE);
	if (ret)
		return ret;

	if (enable) {
		ret = phy_write(phydev, RTL8211F_WOL_REG_PACKET_LEN,
				(RTL8211F_WOL_PACKET_LEN |
				RTL8211F_WOL_SET_PACKET_LEN));
		if (ret)
			return ret;

		ret = phy_write(phydev, RTL8211F_WOL_REG_FRAME_EVENT,
				RTL8211F_WOL_ENABLE_MAGIC_PACKET);
		if (ret)
			return ret;
	} else {
		ret = phy_write(phydev, RTL8211F_WOL_REG_PACKET_LEN,
				RTL8211F_WOL_PACKET_LEN);
		if (ret)
			return ret;

		ret = phy_write(phydev, RTL8211F_WOL_REG_FRAME_EVENT, 0x0);
		if (ret)
			return ret;
	}

	return phy_write(phydev, RTL8211F_PAGE_SELECT, 0x0);
}

static int rtl821x_ack_interrupt(struct phy_device *phydev)
{
	int err;

	err = phy_read(phydev, RTL821x_INSR);

	return (err < 0) ? err : 0;
}

static int rtl8211f_ack_interrupt(struct phy_device *phydev)
{
	int err;

	phy_write(phydev, RTL8211F_PAGE_SELECT, 0xa43);
	err = phy_read(phydev, RTL8211F_INSR);
	/* restore to default page 0 */
	phy_write(phydev, RTL8211F_PAGE_SELECT, 0x0);

	return (err < 0) ? err : 0;
}

static int rtl8211b_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write(phydev, RTL821x_INER,
				RTL821x_INER_INIT);
	else
		err = phy_write(phydev, RTL821x_INER, 0);

	return err;
}

static int rtl8211e_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write(phydev, RTL821x_INER,
				RTL8211E_INER_LINK_STATUS);
	else
		err = phy_write(phydev, RTL821x_INER, 0);

	return err;
}

static int rtl8211f_config_intr(struct phy_device *phydev)
{
	int err;
	u16 reg;

	err = phy_write(phydev, RTL8211F_PAGE_SELECT, RTL8211F_DEFAULT_PAGE);
	if (err)
		return err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		reg = (RTL8211F_INER_LINK_STATUS |
			RTL8211F_WOL_ENABLE_PMEB_EVENT);
	else
		reg = 0;

	err = phy_write(phydev, RTL821x_INER, reg);
	if (err)
		return err;

	return phy_write(phydev, RTL8211F_PAGE_SELECT, 0);
}

static int rtl8211f_config_init(struct phy_device *phydev)
{
	int ret;
	u16 reg;

	ret = genphy_config_init(phydev);
	if (ret < 0)
		return ret;

	phy_write(phydev, RTL8211F_PAGE_SELECT, 0xd08);
	reg = phy_read(phydev, 0x11);

	/* enable TX-delay for rgmii-id and rgmii-txid, otherwise disable it */
	if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
	    phydev->interface == PHY_INTERFACE_MODE_RGMII_TXID)
		reg |= RTL8211F_TX_DELAY;
	else
		reg &= ~RTL8211F_TX_DELAY;

	phy_write(phydev, 0x11, reg);

	ret = phy_write(phydev, RTL8211F_PAGE_SELECT, RTL8211F_PHYCR1_PAGE);
	if (ret)
		return ret;

	reg = phy_read(phydev, RTL8211F_PHYCR1_REG);
	if (reg < 0)
		return reg;

	ret = phy_write(phydev, RTL8211F_PHYCR1_REG,
			reg | RTL8211F_ALDPS_ENABLED |
			RTL8211F_ALDPS_PLL_OFF);
	if (ret)
		return ret;

	reg = phy_read(phydev, RTL8211F_PHYCR2_REG);
	if (reg < 0)
		return reg;

	ret = phy_write(phydev, RTL8211F_PHYCR2_REG, reg & ~BIT(0));
	if (ret)
		return ret;

	ret = phy_write(phydev, RTL8211F_PAGE_SELECT, RTL8211F_LED_PAGE);
	if (ret)
		return ret;

	/* Enable all speeds for activity indicator  and LED0 for GBE */
	reg = RTL8211F_LED0_LINK_1000 | RTL8211F_LED1_LINK_1000 |
		RTL8211F_LED1_LINK_100 | RTL8211F_LED1_LINK_10 |
		RTL8211F_LED1_LINK_ACTIVE;

	ret = phy_write(phydev, RTL8211F_PAGE_LCR_LED_CONTROL, reg);
	if (ret)
		return ret;
	/* disable EEE LED control */
	ret = phy_write(phydev, RTL8211F_PAGE_EEE_LED_CONTROL, 0);
	if (ret)
		return ret;

	/* Write MAC required registers for WoL*/
	ret = phy_write(phydev, RTL8211F_PAGE_SELECT,
			RTL8211F_WOL_MAC_PAGE);
	if (ret)
		return ret;

	ret = phy_write(phydev, RTL8211F_WOL_REG_MAC_WORD_0,
			phydev->attached_dev->dev_addr[MAC_ADDRESS_BYTE_0] |
			(phydev->attached_dev->dev_addr[MAC_ADDRESS_BYTE_1]
			<< BIT_SHIFT_8));
	if (ret)
		return ret;

	ret = phy_write(phydev, RTL8211F_WOL_REG_MAC_WORD_1,
			phydev->attached_dev->dev_addr[MAC_ADDRESS_BYTE_2] |
			(phydev->attached_dev->dev_addr[MAC_ADDRESS_BYTE_3]
			<< BIT_SHIFT_8));
	if (ret)
		return ret;

	ret = phy_write(phydev, RTL8211F_WOL_REG_MAC_WORD_2,
			phydev->attached_dev->dev_addr[MAC_ADDRESS_BYTE_4] |
			(phydev->attached_dev->dev_addr[MAC_ADDRESS_BYTE_5]
			<< BIT_SHIFT_8));
	if (ret)
		return ret;

	phydev_dbg(phydev, "MAC address written to registers\n");

	/* restore to default page 0 */
	phy_write(phydev, RTL8211F_PAGE_SELECT, 0x0);

	return 0;
}

static void rtl8211f_get_wol(struct phy_device *phydev,
			     struct ethtool_wolinfo *wol)
{
	int ret;
	u32 value;

	/* For RTL 8211F Magic packet WoL is enabled by default */
	wol->supported = WAKE_MAGIC;

	ret = phy_write(phydev, RTL8211F_PAGE_SELECT,
			RTL8211F_WOL_SETTING_PAGE);
	if (ret)
		return;

	value = phy_read(phydev, RTL8211F_WOL_REG_FRAME_EVENT);
	if (value < 0)
		return;

	if (value & RTL8211F_WOL_ENABLE_MAGIC_PACKET)
		wol->wolopts = WAKE_MAGIC;
}

static int rtl8211f_set_wol(struct phy_device *phydev,
			    struct ethtool_wolinfo *wol)
{
	int ret;

	if (wol->wolopts & WAKE_MAGIC) {
		ret = rtl8211f_wol_settings(phydev, true);
		if (ret < 0)
			return ret;
		phydev_dbg(phydev, " WOL Enabled\n");
	} else {
		ret = rtl8211f_wol_settings(phydev, false);
		if (ret < 0)
			return ret;
		phydev_dbg(phydev, " WOL Disabled\n");
	}

	/* restore to default page 0 */
	return phy_write(phydev, RTL8211F_PAGE_SELECT, 0x0);
}

static struct phy_driver realtek_drvs[] = {
	{
		.phy_id         = 0x00008201,
		.name           = "RTL8201CP Ethernet",
		.phy_id_mask    = 0x0000ffff,
		.features       = PHY_BASIC_FEATURES,
		.flags          = PHY_HAS_INTERRUPT,
		.config_aneg    = &genphy_config_aneg,
		.read_status    = &genphy_read_status,
	}, {
		.phy_id		= 0x001cc912,
		.name		= "RTL8211B Gigabit Ethernet",
		.phy_id_mask	= 0x001fffff,
		.features	= PHY_GBIT_FEATURES,
		.flags		= PHY_HAS_INTERRUPT,
		.config_aneg	= &genphy_config_aneg,
		.read_status	= &genphy_read_status,
		.ack_interrupt	= &rtl821x_ack_interrupt,
		.config_intr	= &rtl8211b_config_intr,
	}, {
		.phy_id		= 0x001cc914,
		.name		= "RTL8211DN Gigabit Ethernet",
		.phy_id_mask	= 0x001fffff,
		.features	= PHY_GBIT_FEATURES,
		.flags		= PHY_HAS_INTERRUPT,
		.config_aneg	= genphy_config_aneg,
		.read_status	= genphy_read_status,
		.ack_interrupt	= rtl821x_ack_interrupt,
		.config_intr	= rtl8211e_config_intr,
		.suspend	= genphy_suspend,
		.resume		= genphy_resume,
	}, {
		.phy_id		= 0x001cc915,
		.name		= "RTL8211E Gigabit Ethernet",
		.phy_id_mask	= 0x001fffff,
		.features	= PHY_GBIT_FEATURES,
		.flags		= PHY_HAS_INTERRUPT,
		.config_aneg	= &genphy_config_aneg,
		.read_status	= &genphy_read_status,
		.ack_interrupt	= &rtl821x_ack_interrupt,
		.config_intr	= &rtl8211e_config_intr,
		.suspend	= genphy_suspend,
		.resume		= genphy_resume,
	}, {
		.phy_id		= 0x001cc916,
		.name		= "RTL8211F Gigabit Ethernet",
		.phy_id_mask	= 0x001fffff,
		.features	= PHY_GBIT_FEATURES,
		.flags		= PHY_HAS_INTERRUPT,
		.config_aneg	= &genphy_config_aneg,
		.config_init	= &rtl8211f_config_init,
		.read_status	= &genphy_read_status,
		.ack_interrupt	= &rtl8211f_ack_interrupt,
		.config_intr	= &rtl8211f_config_intr,
		.get_wol	= &rtl8211f_get_wol,
		.set_wol	= &rtl8211f_set_wol,
		.suspend	= genphy_suspend,
		.resume		= genphy_resume,
	},
};

module_phy_driver(realtek_drvs);

static struct mdio_device_id __maybe_unused realtek_tbl[] = {
	{ 0x001cc912, 0x001fffff },
	{ 0x001cc914, 0x001fffff },
	{ 0x001cc915, 0x001fffff },
	{ 0x001cc916, 0x001fffff },
	{ }
};

MODULE_DEVICE_TABLE(mdio, realtek_tbl);
