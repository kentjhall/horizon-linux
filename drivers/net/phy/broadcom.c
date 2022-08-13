/*
 *	drivers/net/phy/broadcom.c
 *
 *	Broadcom BCM5411, BCM5421 and BCM5461 Gigabit Ethernet
 *	transceivers.
 *
 *	Copyright (c) 2006  Maciej W. Rozycki
 *
 *	Inspired by code written by Amy Fong.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
/*
 * Copyright (c) 2020-2021, NVIDIA CORPORATION.  All rights reserved.
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

#include "bcm-phy-lib.h"
#include <linux/module.h>
#include <linux/phy.h>
#include <linux/brcmphy.h>


#define BRCM_PHY_MODEL(phydev) \
	((phydev)->drv->phy_id & (phydev)->drv->phy_id_mask)

#define BRCM_PHY_REV(phydev) \
	((phydev)->drv->phy_id & ~((phydev)->drv->phy_id_mask))

#ifdef CONFIG_EQOS_DISABLE_EEE
#define MII_BCM89610_CLAUSE22_DEVAD_FIELD	0x1F
#define MII_BCM89610_CLAUSE22_FUNCTION_FIELD	0xC000
#define MII_BCM89610_CLAUSE22_DEVAD_7		0x7
#define MII_BCM89610_CLAUSE22_FUNCTION_ADDR	(0UL << 14)
#define MII_BCM89610_CLAUSE22_FUNCTION_DATA	BIT(14)
#define MII_BCM89610_CLAUSE22_REG_ADDR		0xd
#define MII_BCM89610_CLAUSE22_REG_DATA		0xe
#define BCM89610_EEE_ADVERTISEMENT_REG		0x3c
#define BCM89610_EEE_ADVERTISEMENT_DISABLE	0x0
#endif /* CONFIG_EQOS_DISABLE_EEE */

MODULE_DESCRIPTION("Broadcom PHY driver");
MODULE_AUTHOR("Maciej W. Rozycki");
MODULE_LICENSE("GPL");

/* Tx FIFO latency. Set to one to allow jumbo frames to be sent */
#define MII_BCM89XX_ECR_TXFIFOLAT	0x0001
#define MII_BCM89XX_SHD_AUX_CONTROL	0x0
#define MII_BCM89XX_SHD_MISC_CONTROL	0x7
#define MII_BCM89XX_SHD_SELECT(shadow)	(((shadow)) << 0xC)

/* Indirect register access functions for 89xx */
static int bcm89xx_shadow_read(struct phy_device *phydev, u16 shadow)
{
	phy_write(phydev, MII_BCM54XX_AUX_CTL,
		((MII_BCM89XX_SHD_SELECT(shadow) | 0x7) & ~BIT(15)));
	return phy_read(phydev, MII_BCM54XX_AUX_CTL);
}

static void bcm89xx_shadow_write(struct phy_device *phydev, u8 shadow,
					u16 val)
{
	/* Bits 2:0 should contain shadow. */
	val = (val & 0xFFF8) | (shadow & 0x7);
	/* Bit 15 should be 1 for MII_BCM89XX_SHD_MISC_CONTROL */
	if (MII_BCM89XX_SHD_MISC_CONTROL == shadow)
		val |= BIT(15);
	phy_write(phydev, MII_BCM54XX_AUX_CTL, val);
}

static int bcm54xx_auxctl_write(struct phy_device *phydev, u16 regnum, u16 val)
{
	return phy_write(phydev, MII_BCM54XX_AUX_CTL, regnum | val);
}

/* Needs SMDSP clock enabled via bcm54xx_phydsp_config() */
static int bcm50610_a0_workaround(struct phy_device *phydev)
{
	int err;

	err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_AADJ1CH0,
				MII_BCM54XX_EXP_AADJ1CH0_SWP_ABCD_OEN |
				MII_BCM54XX_EXP_AADJ1CH0_SWSEL_THPF);
	if (err < 0)
		return err;

	err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_AADJ1CH3,
				MII_BCM54XX_EXP_AADJ1CH3_ADCCKADJ);
	if (err < 0)
		return err;

	err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_EXP75,
				MII_BCM54XX_EXP_EXP75_VDACCTRL);
	if (err < 0)
		return err;

	err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_EXP96,
				MII_BCM54XX_EXP_EXP96_MYST);
	if (err < 0)
		return err;

	err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_EXP97,
				MII_BCM54XX_EXP_EXP97_MYST);

	return err;
}

static int bcm54xx_phydsp_config(struct phy_device *phydev)
{
	int err, err2;

	/* Enable the SMDSP clock */
	err = bcm54xx_auxctl_write(phydev,
				   MII_BCM54XX_AUXCTL_SHDWSEL_AUXCTL,
				   MII_BCM54XX_AUXCTL_ACTL_SMDSP_ENA |
				   MII_BCM54XX_AUXCTL_ACTL_TX_6DB);
	if (err < 0)
		return err;

	if (BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610 ||
	    BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610M) {
		/* Clear bit 9 to fix a phy interop issue. */
		err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_EXP08,
					MII_BCM54XX_EXP_EXP08_RJCT_2MHZ);
		if (err < 0)
			goto error;

		if (phydev->drv->phy_id == PHY_ID_BCM50610) {
			err = bcm50610_a0_workaround(phydev);
			if (err < 0)
				goto error;
		}
	}

	if (BRCM_PHY_MODEL(phydev) == PHY_ID_BCM57780) {
		int val;

		val = bcm_phy_read_exp(phydev, MII_BCM54XX_EXP_EXP75);
		if (val < 0)
			goto error;

		val |= MII_BCM54XX_EXP_EXP75_CM_OSC;
		err = bcm_phy_write_exp(phydev, MII_BCM54XX_EXP_EXP75, val);
	}

error:
	/* Disable the SMDSP clock */
	err2 = bcm54xx_auxctl_write(phydev,
				    MII_BCM54XX_AUXCTL_SHDWSEL_AUXCTL,
				    MII_BCM54XX_AUXCTL_ACTL_TX_6DB);

	/* Return the first error reported. */
	return err ? err : err2;
}

static void bcm54xx_adjust_rxrefclk(struct phy_device *phydev)
{
	u32 orig;
	int val;
	bool clk125en = true;

	/* Abort if we are using an untested phy. */
	if (BRCM_PHY_MODEL(phydev) != PHY_ID_BCM57780 &&
	    BRCM_PHY_MODEL(phydev) != PHY_ID_BCM50610 &&
	    BRCM_PHY_MODEL(phydev) != PHY_ID_BCM50610M &&
	    BRCM_PHY_MODEL(phydev) != PHY_ID_BCM89610)
		return;

	val = bcm_phy_read_shadow(phydev, BCM54XX_SHD_SCR3);
	if (val < 0)
		return;

	orig = val;

	if ((BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610 ||
	     BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610M) &&
	    BRCM_PHY_REV(phydev) >= 0x3) {
		/*
		 * Here, bit 0 _disables_ CLK125 when set.
		 * This bit is set by default.
		 */
		clk125en = false;
	} else {
		if (phydev->dev_flags & PHY_BRCM_RX_REFCLK_UNUSED) {
			/* Here, bit 0 _enables_ CLK125 when set */
			val &= ~BCM54XX_SHD_SCR3_DEF_CLK125;
			clk125en = false;
		}
	}

	if (!clk125en || (phydev->dev_flags & PHY_BRCM_AUTO_PWRDWN_ENABLE))
		val &= ~BCM54XX_SHD_SCR3_DLLAPD_DIS;
	else
		val |= BCM54XX_SHD_SCR3_DLLAPD_DIS;

	if (phydev->dev_flags & PHY_BRCM_DIS_TXCRXC_NOENRGY)
		val |= BCM54XX_SHD_SCR3_TRDDAPD;

	if (orig != val)
		bcm_phy_write_shadow(phydev, BCM54XX_SHD_SCR3, val);

	val = bcm_phy_read_shadow(phydev, BCM54XX_SHD_APD);
	if (val < 0)
		return;

	orig = val;

	if (!clk125en || (phydev->dev_flags & PHY_BRCM_AUTO_PWRDWN_ENABLE))
		val |= BCM54XX_SHD_APD_EN;
	else
		val &= ~BCM54XX_SHD_APD_EN;

	if (orig != val)
		bcm_phy_write_shadow(phydev, BCM54XX_SHD_APD, val);
}

void bcm_phy_ultra_low_power(struct phy_device *phydev)
{
	unsigned int reg = 0;

	reg |= MII_BCM54XX_SHD_IDDQ | MII_BCM54XX_IDDQ_LP |
		MII_BCM54XX_EXT_CTL_WR_ENABLE;

	phy_write(phydev, MII_BCM54XX_SHD, reg);

	phydev->dev_flags |= BCM_IDDQ_EN;
}

void bcm54xx_low_power_mode(struct phy_device *phydev,
			    bool lp_mode_en)
{
	if (lp_mode_en) {
		if (phydev->dev_flags & BCM_IDDQ_EN) {
			pr_debug("%s(): bcm-phy already in iddq-lp mode\n",
				 __func__);
			return;
		}
		pr_info("%s(): put phy in iddq-lp mode\n", __func__);
		bcm_phy_ultra_low_power(phydev);
	} else {
		pr_debug("%s(): re-initialze phy after exiting "
			 "from iddq-lp mode\n", __func__);
		phydev->dev_flags &= ~BCM_IDDQ_EN;
	}
}

/* enable RGMII Out-of-Band Status */
static void bcm89xx_enable_oob(struct phy_device *phydev)
{
	int reg_val = 0;

	/* Read the value at MISC_CONTROL shadow register, set bit 5 to zero, */
	/* set bit 15 to 1 and write the value to MISC_CONTROL register */
	reg_val = bcm89xx_shadow_read(phydev, MII_BCM89XX_SHD_MISC_CONTROL);
	reg_val &= ~BIT(5); /* Bit 5 set to zero */
	bcm89xx_shadow_write(phydev, MII_BCM89XX_SHD_MISC_CONTROL, reg_val);

	/* Following register writes need to happen once.  They are needed
	 * to get 10mb working.
	 */
	phy_write(phydev, 0x18, 0x0c00);
	phy_write(phydev, 0x17, 0x0ff0);
	phy_write(phydev, 0x15, 0x2000);
	phy_write(phydev, 0x18, 0x0400);
}

#ifdef CONFIG_EQOS_DISABLE_EEE
static int bcm89610_disable_eee_adv(struct phy_device *phydev)
{
	int ret;
	u32 val;

	val = phy_read(phydev, MII_BCM89610_CLAUSE22_REG_ADDR);

	/* Clear function field and device address fields */
	val &= ~(MII_BCM89610_CLAUSE22_DEVAD_FIELD |
		 MII_BCM89610_CLAUSE22_FUNCTION_FIELD);
	/* Set function field to addr and device addr 7 */
	val |= (MII_BCM89610_CLAUSE22_DEVAD_7 |
		MII_BCM89610_CLAUSE22_FUNCTION_ADDR);

	ret = phy_write(phydev, MII_BCM89610_CLAUSE22_REG_ADDR, val);
	if (ret < 0)
		goto exit;

	ret = phy_write(phydev, MII_BCM89610_CLAUSE22_REG_DATA,
			BCM89610_EEE_ADVERTISEMENT_REG);
	if (ret < 0)
		goto exit;

	val = phy_read(phydev, MII_BCM89610_CLAUSE22_REG_ADDR);

	/* Clear function field and device address fields */
	val &= ~(MII_BCM89610_CLAUSE22_DEVAD_FIELD |
		 MII_BCM89610_CLAUSE22_FUNCTION_FIELD);
	/* Set function field to data and device addr 7 */
	val |= (MII_BCM89610_CLAUSE22_DEVAD_7 |
		MII_BCM89610_CLAUSE22_FUNCTION_DATA);

	ret = phy_write(phydev, MII_BCM89610_CLAUSE22_REG_ADDR, val);
	if (ret < 0)
		goto exit;

	val = phy_write(phydev, MII_BCM89610_CLAUSE22_REG_DATA,
			BCM89610_EEE_ADVERTISEMENT_DISABLE);
	if (ret < 0)
		goto exit;

exit:
	return ret;
}
#endif /* CONFIG_EQOS_DISABLE_EEE */

static int bcm54xx_config_init(struct phy_device *phydev)
{
	int reg, err;

	reg = phy_read(phydev, MII_BCM54XX_ECR);
	if (reg < 0)
		return reg;

	/* Mask interrupts globally.  */
	reg |= MII_BCM54XX_ECR_IM;
	err = phy_write(phydev, MII_BCM54XX_ECR, reg);
	if (err < 0)
		return err;

	/* Unmask events we are interested in.  */
	reg = ~(MII_BCM54XX_INT_DUPLEX |
		MII_BCM54XX_INT_SPEED |
		MII_BCM54XX_INT_LINK |
		MII_BCM54XX_INT_ANPR);

	/* unmask energy detect interrupt */
	if (BRCM_PHY_MODEL(phydev) == PHY_ID_BCM89610 ||
	    BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610)
		reg &= ~MII_BCM54XX_INT_EDETECT;

	err = phy_write(phydev, MII_BCM54XX_IMR, reg);
	if (err < 0)
		return err;

	if ((BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610 ||
	     BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610M) &&
	    (phydev->dev_flags & PHY_BRCM_CLEAR_RGMII_MODE))
		bcm_phy_write_shadow(phydev, BCM54XX_SHD_RGMII_MODE, 0);

	if ((phydev->dev_flags & PHY_BRCM_RX_REFCLK_UNUSED) ||
	    (phydev->dev_flags & PHY_BRCM_DIS_TXCRXC_NOENRGY) ||
	    (phydev->dev_flags & PHY_BRCM_AUTO_PWRDWN_ENABLE))
		bcm54xx_adjust_rxrefclk(phydev);

	/* enable energy detect interrupt status update */
	if (BRCM_PHY_MODEL(phydev) == PHY_ID_BCM89610 ||
	    BRCM_PHY_MODEL(phydev) == PHY_ID_BCM50610) {
		reg = bcm_phy_read_shadow(phydev, BCM54XX_SHD_SCR3);
		reg |= BCM54XX_SHD_SCR3_EDETECT_EN;
		bcm_phy_write_shadow(phydev, BCM54XX_SHD_SCR3, reg);
		bcm89xx_enable_oob(phydev);

		/* Enable phy to tx/rx jumbo frames. Driver
		 * will drop jumbo frames if it is not enabled.
		 */
		reg = phy_read(phydev, MII_BCM54XX_ECR);
		reg |= MII_BCM89XX_ECR_TXFIFOLAT;
		err = phy_write(phydev, MII_BCM54XX_ECR, reg);
		if (err < 0)
			return err;

		reg = bcm89xx_shadow_read(phydev, MII_BCM89XX_SHD_AUX_CONTROL);
		reg |= BIT(14); /* Enable rx of extended pkts */
		bcm89xx_shadow_write(phydev, MII_BCM89XX_SHD_AUX_CONTROL, reg);

#ifdef CONFIG_EQOS_DISABLE_EEE
		/* Disable EEE advertisement. Nvbugs 2678273 */
		err = bcm89610_disable_eee_adv(phydev);
		if (err < 0)
			return err;
#endif /* CONFIG_EQOS_DISABLE_EEE */
	}

	bcm54xx_phydsp_config(phydev);

	return 0;
}

static int bcm5482_config_init(struct phy_device *phydev)
{
	int err, reg;

	err = bcm54xx_config_init(phydev);

	if (phydev->dev_flags & PHY_BCM_FLAGS_MODE_1000BX) {
		/*
		 * Enable secondary SerDes and its use as an LED source
		 */
		reg = bcm_phy_read_shadow(phydev, BCM5482_SHD_SSD);
		bcm_phy_write_shadow(phydev, BCM5482_SHD_SSD,
				     reg |
				     BCM5482_SHD_SSD_LEDM |
				     BCM5482_SHD_SSD_EN);

		/*
		 * Enable SGMII slave mode and auto-detection
		 */
		reg = BCM5482_SSD_SGMII_SLAVE | MII_BCM54XX_EXP_SEL_SSD;
		err = bcm_phy_read_exp(phydev, reg);
		if (err < 0)
			return err;
		err = bcm_phy_write_exp(phydev, reg, err |
					BCM5482_SSD_SGMII_SLAVE_EN |
					BCM5482_SSD_SGMII_SLAVE_AD);
		if (err < 0)
			return err;

		/*
		 * Disable secondary SerDes powerdown
		 */
		reg = BCM5482_SSD_1000BX_CTL | MII_BCM54XX_EXP_SEL_SSD;
		err = bcm_phy_read_exp(phydev, reg);
		if (err < 0)
			return err;
		err = bcm_phy_write_exp(phydev, reg,
					err & ~BCM5482_SSD_1000BX_CTL_PWRDOWN);
		if (err < 0)
			return err;

		/*
		 * Select 1000BASE-X register set (primary SerDes)
		 */
		reg = bcm_phy_read_shadow(phydev, BCM5482_SHD_MODE);
		bcm_phy_write_shadow(phydev, BCM5482_SHD_MODE,
				     reg | BCM5482_SHD_MODE_1000BX);

		/*
		 * LED1=ACTIVITYLED, LED3=LINKSPD[2]
		 * (Use LED1 as secondary SerDes ACTIVITY LED)
		 */
		bcm_phy_write_shadow(phydev, BCM5482_SHD_LEDS1,
			BCM5482_SHD_LEDS1_LED1(BCM_LED_SRC_ACTIVITYLED) |
			BCM5482_SHD_LEDS1_LED3(BCM_LED_SRC_LINKSPD2));

		/*
		 * Auto-negotiation doesn't seem to work quite right
		 * in this mode, so we disable it and force it to the
		 * right speed/duplex setting.  Only 'link status'
		 * is important.
		 */
		phydev->autoneg = AUTONEG_DISABLE;
		phydev->speed = SPEED_1000;
		phydev->duplex = DUPLEX_FULL;
	}

	return err;
}

static int bcm5482_read_status(struct phy_device *phydev)
{
	int err;

	err = genphy_read_status(phydev);

	if (phydev->dev_flags & PHY_BCM_FLAGS_MODE_1000BX) {
		/*
		 * Only link status matters for 1000Base-X mode, so force
		 * 1000 Mbit/s full-duplex status
		 */
		if (phydev->link) {
			phydev->speed = SPEED_1000;
			phydev->duplex = DUPLEX_FULL;
		}
	}

	return err;
}

static int bcm5481_config_aneg(struct phy_device *phydev)
{
	int ret;

	/* Aneg firsly. */
	ret = genphy_config_aneg(phydev);

	/* Then we can set up the delay. */
	if (phydev->interface == PHY_INTERFACE_MODE_RGMII_RXID) {
		u16 reg;

		/*
		 * There is no BCM5481 specification available, so down
		 * here is everything we know about "register 0x18". This
		 * at least helps BCM5481 to successfully receive packets
		 * on MPC8360E-RDK board. Peter Barada <peterb@logicpd.com>
		 * says: "This sets delay between the RXD and RXC signals
		 * instead of using trace lengths to achieve timing".
		 */

		/* Set RDX clk delay. */
		reg = 0x7 | (0x7 << 12);
		phy_write(phydev, 0x18, reg);

		reg = phy_read(phydev, 0x18);
		/* Set RDX-RXC skew. */
		reg |= (1 << 8);
		/* Write bits 14:0. */
		reg |= (1 << 15);
		phy_write(phydev, 0x18, reg);
	}

	return ret;
}

static int brcm_phy_setbits(struct phy_device *phydev, int reg, int set)
{
	int val;

	val = phy_read(phydev, reg);
	if (val < 0)
		return val;

	return phy_write(phydev, reg, val | set);
}

static int brcm_fet_config_init(struct phy_device *phydev)
{
	int reg, err, err2, brcmtest;

	/* Reset the PHY to bring it to a known state. */
	err = phy_write(phydev, MII_BMCR, BMCR_RESET);
	if (err < 0)
		return err;

	reg = phy_read(phydev, MII_BRCM_FET_INTREG);
	if (reg < 0)
		return reg;

	/* Unmask events we are interested in and mask interrupts globally. */
	reg = MII_BRCM_FET_IR_DUPLEX_EN |
	      MII_BRCM_FET_IR_SPEED_EN |
	      MII_BRCM_FET_IR_LINK_EN |
	      MII_BRCM_FET_IR_ENABLE |
	      MII_BRCM_FET_IR_MASK;

	err = phy_write(phydev, MII_BRCM_FET_INTREG, reg);
	if (err < 0)
		return err;

	/* Enable shadow register access */
	brcmtest = phy_read(phydev, MII_BRCM_FET_BRCMTEST);
	if (brcmtest < 0)
		return brcmtest;

	reg = brcmtest | MII_BRCM_FET_BT_SRE;

	err = phy_write(phydev, MII_BRCM_FET_BRCMTEST, reg);
	if (err < 0)
		return err;

	/* Set the LED mode */
	reg = phy_read(phydev, MII_BRCM_FET_SHDW_AUXMODE4);
	if (reg < 0) {
		err = reg;
		goto done;
	}

	reg &= ~MII_BRCM_FET_SHDW_AM4_LED_MASK;
	reg |= MII_BRCM_FET_SHDW_AM4_LED_MODE1;

	err = phy_write(phydev, MII_BRCM_FET_SHDW_AUXMODE4, reg);
	if (err < 0)
		goto done;

	/* Enable auto MDIX */
	err = brcm_phy_setbits(phydev, MII_BRCM_FET_SHDW_MISCCTRL,
				       MII_BRCM_FET_SHDW_MC_FAME);
	if (err < 0)
		goto done;

	if (phydev->dev_flags & PHY_BRCM_AUTO_PWRDWN_ENABLE) {
		/* Enable auto power down */
		err = brcm_phy_setbits(phydev, MII_BRCM_FET_SHDW_AUXSTAT2,
					       MII_BRCM_FET_SHDW_AS2_APDE);
	}

done:
	/* Disable shadow register access */
	err2 = phy_write(phydev, MII_BRCM_FET_BRCMTEST, brcmtest);
	if (!err)
		err = err2;

	return err;
}

static int brcm_fet_ack_interrupt(struct phy_device *phydev)
{
	int reg;

	/* Clear pending interrupts.  */
	reg = phy_read(phydev, MII_BRCM_FET_INTREG);
	if (reg < 0)
		return reg;

	return 0;
}

static int brcm_fet_config_intr(struct phy_device *phydev)
{
	int reg, err;

	reg = phy_read(phydev, MII_BRCM_FET_INTREG);
	if (reg < 0)
		return reg;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		reg &= ~MII_BRCM_FET_IR_MASK;
	else
		reg |= MII_BRCM_FET_IR_MASK;

	err = phy_write(phydev, MII_BRCM_FET_INTREG, reg);
	return err;
}

static int bcm89610_probe(struct phy_device *phydev)
{
	bcm54xx_low_power_mode(phydev, true);

	return 0;
}

int bcm89610_suspend(struct phy_device *phydev)
{
	bcm54xx_low_power_mode(phydev, true);
	return 0;
}

int bcm89610_resume(struct phy_device *phydev)
{
	bcm54xx_low_power_mode(phydev, false);
	return 0;
}

static struct phy_driver broadcom_drivers[] = {
{
	.phy_id		= PHY_ID_BCM5411,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5411",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM5421,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5421",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM5461,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5461",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM54616S,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM54616S",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM5464,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5464",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM5481,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5481",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= bcm5481_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM5482,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5482",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm5482_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= bcm5482_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM50610,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM50610",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM50610M,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM50610M",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCM57780,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM57780",
	.features	= PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= bcm54xx_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= bcm_phy_ack_intr,
	.config_intr	= bcm_phy_config_intr,
}, {
	.phy_id		= PHY_ID_BCMAC131,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCMAC131",
	.features	= PHY_BASIC_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= brcm_fet_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= brcm_fet_ack_interrupt,
	.config_intr	= brcm_fet_config_intr,
}, {
	.phy_id		= PHY_ID_BCM5241,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Broadcom BCM5241",
	.features	= PHY_BASIC_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= brcm_fet_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.ack_interrupt	= brcm_fet_ack_interrupt,
	.config_intr	= brcm_fet_config_intr,
}, {
	.phy_id         = PHY_ID_BCM89610,
	.phy_id_mask    = 0xfffffff0,
	.name           = "Broadcom BCM89610",
	.features       = PHY_GBIT_FEATURES |
			  SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.flags          = PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.probe		= bcm89610_probe,
	.config_init    = bcm54xx_config_init,
	.config_aneg    = genphy_config_aneg,
	.read_status    = genphy_read_status,
	.low_power_mode = bcm54xx_low_power_mode,
	.ack_interrupt  = bcm_phy_ack_intr,
	.config_intr    = bcm_phy_config_intr,
	.resume		= bcm89610_resume,
	.suspend	= bcm89610_suspend,
} };

module_phy_driver(broadcom_drivers);

static struct mdio_device_id __maybe_unused broadcom_tbl[] = {
	{ PHY_ID_BCM5411, 0xfffffff0 },
	{ PHY_ID_BCM5421, 0xfffffff0 },
	{ PHY_ID_BCM5461, 0xfffffff0 },
	{ PHY_ID_BCM54616S, 0xfffffff0 },
	{ PHY_ID_BCM5464, 0xfffffff0 },
	{ PHY_ID_BCM5481, 0xfffffff0 },
	{ PHY_ID_BCM5482, 0xfffffff0 },
	{ PHY_ID_BCM50610, 0xfffffff0 },
	{ PHY_ID_BCM50610M, 0xfffffff0 },
	{ PHY_ID_BCM57780, 0xfffffff0 },
	{ PHY_ID_BCMAC131, 0xfffffff0 },
	{ PHY_ID_BCM5241, 0xfffffff0 },
	{ PHY_ID_BCM89610, 0xfffffff0 },
	{ }
};

MODULE_DEVICE_TABLE(mdio, broadcom_tbl);
