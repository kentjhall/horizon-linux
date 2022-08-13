/*
 * Copyright (c) 2017-2019 NVIDIA CORPORATION.  All rights reserved.
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

#include <dt-bindings/clock/tegra210-car.h>
#include <dt-bindings/reset/tegra210-car.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clkdev.h>
#include <linux/clk/tegra.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/syscore_ops.h>
#include <soc/tegra/tegra_emc.h>

#include "clk.h"
#include "clk-dfll.h"
#include "clk-id.h"

#define PLLE_SS_CTRL 0x68

#define PLLC_BASE 0x80
#define PLLC_OUT 0x84
#define PLLC_MISC0 0x88
#define PLLC_MISC1 0x8c
#define PLLC_MISC2 0x5d0
#define PLLC_MISC3 0x5d4

#define PLLC2_BASE 0x4e8
#define PLLC2_MISC0 0x4ec
#define PLLC2_MISC1 0x4f0
#define PLLC2_MISC2 0x4f4
#define PLLC2_MISC3 0x4f8

#define PLLC3_BASE 0x4fc
#define PLLC3_MISC0 0x500
#define PLLC3_MISC1 0x504
#define PLLC3_MISC2 0x508
#define PLLC3_MISC3 0x50c

#define PLLM_BASE 0x90
#define PLLM_MISC1 0x98
#define PLLM_MISC2 0x9c
#define PLLP_BASE 0xa0
#define PLLP_OUTA 0xa4
#define PLLP_OUTB 0xa8
#define PLLP_MISC0 0xac
#define PLLP_MISC1 0x680
#define PLLA_BASE 0xb0
#define PLLA_OUT 0xb4
#define PLLA_MISC0 0xbc
#define PLLA_MISC1 0xb8
#define PLLA_MISC2 0x5d8
#define PLLD_BASE 0xd0
#define PLLD_MISC0 0xdc
#define PLLD_MISC1 0xd8
#define PLLU_BASE 0xc0
#define PLLU_OUTA 0xc4
#define PLLU_MISC0 0xcc
#define PLLU_MISC1 0xc8
#define PLLX_BASE 0xe0
#define PLLX_MISC0 0xe4
#define PLLX_MISC1 0x510
#define PLLX_MISC2 0x514
#define PLLX_MISC3 0x518
#define PLLX_MISC4 0x5f0
#define PLLX_MISC5 0x5f4
#define PLLE_BASE 0xe8
#define PLLE_MISC0 0xec
#define PLLD2_BASE 0x4b8
#define PLLD2_MISC0 0x4bc
#define PLLD2_MISC1 0x570
#define PLLD2_MISC2 0x574
#define PLLD2_MISC3 0x578
#define PLLD2_MISC4 0x76c
#define PLLE_AUX 0x48c
#define PLLRE_BASE 0x4c4
#define PLLRE_MISC0 0x4c8
#define PLLRE_OUT1 0x4cc
#define PLLDP_BASE 0x590
#define PLLDP_MISC 0x594

#define PLLC4_BASE 0x5a4
#define PLLC4_MISC0 0x5a8
#define PLLC4_OUT 0x5e4
#define PLLMB_BASE 0x5e8
#define PLLMB_MISC1 0x5ec
#define PLLA1_BASE 0x6a4
#define PLLA1_MISC0 0x6a8
#define PLLA1_MISC1 0x6ac
#define PLLA1_MISC2 0x6b0
#define PLLA1_MISC3 0x6b4

#define CLK_SOURCE_VI 0x148
#define CLK_SOURCE_SOR0 0x414
#define CLK_SOURCE_SOR1 0x410

#define PLLU_IDDQ_BIT 31
#define PLLCX_IDDQ_BIT 27
#define PLLRE_IDDQ_BIT 24
#define PLLA_IDDQ_BIT 25
#define PLLD_IDDQ_BIT 20
#define PLLSS_IDDQ_BIT 18
#define PLLM_IDDQ_BIT 5
#define PLLMB_IDDQ_BIT 17
#define PLLXP_IDDQ_BIT 3

#define PLLCX_RESET_BIT 30

#define PLL_BASE_LOCK BIT(27)
#define PLLCX_BASE_LOCK BIT(26)
#define PLLE_MISC_LOCK BIT(11)
#define PLLE_MISC_IDDQ_SW_CTRL BIT(14)
#define PLLRE_MISC_LOCK BIT(27)

#define PLLE_AUX_USE_LOCKDET BIT(3)
#define PLLE_AUX_SS_SEQ_INCLUDE BIT(31)
#define PLLE_AUX_ENABLE_SWCTL BIT(4)
#define PLLE_AUX_SS_SWCTL BIT(6)
#define PLLE_AUX_SEQ_ENABLE BIT(24)

#define PLL_MISC_LOCK_ENABLE 18
#define PLLC_MISC_LOCK_ENABLE 24
#define PLLDU_MISC_LOCK_ENABLE 22
#define PLLU_MISC_LOCK_ENABLE 29
#define PLLE_MISC_LOCK_ENABLE 9
#define PLLRE_MISC_LOCK_ENABLE 30
#define PLLSS_MISC_LOCK_ENABLE 30
#define PLLP_MISC_LOCK_ENABLE 18
#define PLLM_MISC_LOCK_ENABLE 4
#define PLLMB_MISC_LOCK_ENABLE 16
#define PLLA_MISC_LOCK_ENABLE 28
#define PLLU_MISC_LOCK_ENABLE 29
#define PLLD_MISC_LOCK_ENABLE 18

#define PLLA_SDM_DIN_MASK 0xffff
#define PLLA_SDM_EN_MASK BIT(26)

#define PLLD_SDM_EN_MASK BIT(16)

#define PLLD2_SDM_EN_MASK BIT(31)
#define PLLD2_SSC_EN_MASK 0

#define PLLDP_SS_CFG	0x598
#define PLLDP_SDM_EN_MASK BIT(31)
#define PLLDP_SSC_EN_MASK BIT(30)
#define PLLDP_SS_CTRL1	0x59c
#define PLLDP_SS_CTRL2	0x5a0
#define PLLDP_MISC4	0x770

#define LVL2_CLK_GATE_OVRA 0xf8
#define LVL2_CLK_GATE_OVRC 0x3a0
#define LVL2_CLK_GATE_OVRD 0x3a4
#define LVL2_CLK_GATE_OVRE 0x554

#define PMC_PLLM_WB0_OVERRIDE 0x1dc
#define PMC_PLLM_WB0_OVERRIDE_2 0x2b0

#define UTMIP_PLL_CFG2 0x488
#define UTMIP_PLL_CFG2_STABLE_COUNT(x) (((x) & 0xfff) << 6)
#define UTMIP_PLL_CFG2_ACTIVE_DLY_COUNT(x) (((x) & 0x3f) << 18)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_A_POWERDOWN BIT(0)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_A_POWERUP BIT(1)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_B_POWERDOWN BIT(2)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_B_POWERUP BIT(3)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_C_POWERDOWN BIT(4)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_C_POWERUP BIT(5)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_D_POWERDOWN BIT(24)
#define UTMIP_PLL_CFG2_FORCE_PD_SAMP_D_POWERUP BIT(25)

#define UTMIP_PLL_CFG1 0x484
#define UTMIP_PLL_CFG1_ENABLE_DLY_COUNT(x) (((x) & 0x1f) << 27)
#define UTMIP_PLL_CFG1_XTAL_FREQ_COUNT(x) (((x) & 0xfff) << 0)
#define UTMIP_PLL_CFG1_FORCE_PLLU_POWERUP BIT(17)
#define UTMIP_PLL_CFG1_FORCE_PLLU_POWERDOWN BIT(16)
#define UTMIP_PLL_CFG1_FORCE_PLL_ENABLE_POWERUP BIT(15)
#define UTMIP_PLL_CFG1_FORCE_PLL_ENABLE_POWERDOWN BIT(14)
#define UTMIP_PLL_CFG1_FORCE_PLL_ACTIVE_POWERDOWN BIT(12)

#define UTMIP_PLL_CFG0 0x480

#define XUSBIO_PLL_CFG0				0x51c
#define XUSBIO_PLL_CFG0_PADPLL_RESET_SWCTL	BIT(0)
#define XUSBIO_PLL_CFG0_CLK_ENABLE_SWCTL	BIT(2)
#define XUSBIO_PLL_CFG0_PADPLL_USE_LOCKDET	BIT(6)
#define XUSBIO_PLL_CFG0_PADPLL_SLEEP_IDDQ	BIT(13)
#define XUSBIO_PLL_CFG0_SEQ_ENABLE		BIT(24)

#define UTMIPLL_HW_PWRDN_CFG0			0x52c
#define UTMIPLL_HW_PWRDN_CFG0_UTMIPLL_LOCK	BIT(31)
#define UTMIPLL_HW_PWRDN_CFG0_SEQ_START_STATE	BIT(25)
#define UTMIPLL_HW_PWRDN_CFG0_SEQ_ENABLE	BIT(24)
#define UTMIPLL_HW_PWRDN_CFG0_IDDQ_PD_INCLUDE	BIT(7)
#define UTMIPLL_HW_PWRDN_CFG0_USE_LOCKDET	BIT(6)
#define UTMIPLL_HW_PWRDN_CFG0_SEQ_RESET_INPUT_VALUE	BIT(5)
#define UTMIPLL_HW_PWRDN_CFG0_SEQ_IN_SWCTL	BIT(4)
#define UTMIPLL_HW_PWRDN_CFG0_CLK_ENABLE_SWCTL	BIT(2)
#define UTMIPLL_HW_PWRDN_CFG0_IDDQ_OVERRIDE	BIT(1)
#define UTMIPLL_HW_PWRDN_CFG0_IDDQ_SWCTL	BIT(0)

#define PLLU_HW_PWRDN_CFG0			0x530
#define PLLU_HW_PWRDN_CFG0_IDDQ_PD_INCLUDE	BIT(28)
#define PLLU_HW_PWRDN_CFG0_SEQ_ENABLE		BIT(24)
#define PLLU_HW_PWRDN_CFG0_USE_SWITCH_DETECT	BIT(7)
#define PLLU_HW_PWRDN_CFG0_USE_LOCKDET		BIT(6)
#define PLLU_HW_PWRDN_CFG0_CLK_ENABLE_SWCTL	BIT(2)
#define PLLU_HW_PWRDN_CFG0_CLK_SWITCH_SWCTL	BIT(0)

#define XUSB_PLL_CFG0				0x534
#define XUSB_PLL_CFG0_UTMIPLL_LOCK_DLY		0x3ff
#define XUSB_PLL_CFG0_PLLU_LOCK_DLY_MASK	(0x3ff << 14)

/* This register is re-purposed on T210b01 as UPHY management clock divider */
#define PEX_SATA_USB_RX_BYP			0x6d0

/*
 * SDM fractional divisor is 16-bit 2's complement signed number within
 * (-2^12 ... 2^12-1) range. Represented in PLL data structure as unsigned
 * 16-bit value, with "0" divisor mapped to 0xFFFF. Data "0" is used to
 * indicate that SDM is disabled.
 *
 * Effective ndiv value when SDM is enabled: ndiv + 1/2 + sdm_din/2^13
 */
#define PLL_SDM_COEFF BIT(13)
#define sdin_din_to_data(din)	((u16)((din) ? : 0xFFFFU))
#define sdin_data_to_din(dat)	(((dat) == 0xFFFFU) ? 0 : (s16)dat)
#define sdin_get_n_eff(cfg)	((cfg)->n * PLL_SDM_COEFF + ((cfg)->sdm_data ? \
		(PLL_SDM_COEFF/2 + sdin_data_to_din((cfg)->sdm_data)) : 0))

static void __iomem *clk_base;
static void __iomem *pmc_base;

static unsigned long osc_freq;
static unsigned long pll_ref_freq;
static bool pll_re_use_utmipll;

static DEFINE_SPINLOCK(pll_d_lock);
static DEFINE_SPINLOCK(pll_d2_lock);
static DEFINE_SPINLOCK(pll_e_lock);
static DEFINE_SPINLOCK(pll_re_lock);
static DEFINE_SPINLOCK(pll_u_lock);
static DEFINE_SPINLOCK(pll_p_uphy_lock);

#define PLL_ENABLE			(1 << 30)

/* PLLC, PLLC2, PLLC3, PLLA1 */
#define PLLCX_MISC1_IDDQ		(1 << 27)
#define PLLCX_MISC0_RESET		(1 << 30)

#define PLLCX_MISC0_DEFAULT_VALUE	0x40080000
#define PLLCX_MISC0_WRITE_MASK		0x400ffffb
#define PLLCX_MISC1_DEFAULT_VALUE	0x08000000
#define PLLCX_MISC1_WRITE_MASK		0x38003cff
#define PLLCX_MISC2_DEFAULT_VALUE	0x1f720f05
#define PLLCX_MISC2_WRITE_MASK		0xffffff17
#define PLLCX_MISC3_DEFAULT_VALUE	0x000000c4
#define PLLCX_MISC3_WRITE_MASK		0x00ffffff

/* PLLA */
#define PLLA_BASE_IDDQ			(1 << 25)
#define PLLA_BASE_LOCK			(1 << 27)

#define PLLA_MISC0_LOCK_ENABLE		(1 << 28)
#define PLLA_MISC0_LOCK_OVERRIDE	(1 << 27)

#define PLLA_MISC2_EN_SDM		(1 << 26)
#define PLLA_MISC2_EN_DYNRAMP		(1 << 25)

#define PLLA_MISC0_DEFAULT_VALUE	0x10000000
#define PLLA_MISC0_WRITE_MASK		0x7fffffff
#define PLLA_MISC2_DEFAULT_VALUE	0x0
#define PLLA_MISC2_WRITE_MASK		0x06ffffff

#define PLLA_OUT_DEFAULT_VALUE		0x00000000
#define PLLA_OUT_VREG_MASK		0xf0000000

/* PLLD */
#define PLLD_MISC0_EN_SDM		(1 << 16)
#define PLLD_MISC0_LOCK_OVERRIDE	(1 << 17)
#define PLLD_MISC0_LOCK_ENABLE		(1 << 18)
#define PLLD_MISC0_IDDQ			(1 << 20)
#define PLLD_MISC0_DSI_CLKENABLE	(1 << 21)

#define PLLD_MISC0_DEFAULT_VALUE	0x00140000
#define PLLD_MISC0_WRITE_MASK		0x3ff7ffff
#define PLLD_MISC1_DEFAULT_VALUE	0x00000000
#define PLLD_MISC1_WRITE_MASK		0xf0ffffff

/* PLLD2 and PLLDP  and PLLC4 */
#define PLLDSS_BASE_LOCK		(1 << 27)
#define PLLDSS_BASE_LOCK_OVERRIDE	(1 << 24)
#define PLLDSS_BASE_IDDQ		(1 << 18)
#define PLLDSS_BASE_REF_SEL_SHIFT	25
#define PLLDSS_BASE_REF_SEL_MASK	(0x3 << PLLDSS_BASE_REF_SEL_SHIFT)

#define PLLDSS_MISC0_LOCK_ENABLE	(1 << 30)

#define PLLDSS_MISC1_CFG_EN_SDM		(1 << 31)
#define PLLDSS_MISC1_CFG_EN_SSC		(1 << 30)

#define PLLD2_MISC0_DEFAULT_VALUE	0x40000000
#define PLLD2_MISC1_CFG_DEFAULT_VALUE	0x10000000
#define PLLD2_MISC2_CTRL1_DEFAULT_VALUE	0xF6E0F620
#define PLLD2_MISC3_CTRL2_DEFAULT_VALUE	0x00010000
#define PLLD2_MISC4_VREG_DEFAULT_VALUE	0x00000000

#define PLLDP_MISC0_DEFAULT_VALUE	0x40000000
#define PLLDP_MISC1_CFG_DEFAULT_VALUE	0xc0000000
#define PLLDP_MISC2_CTRL1_DEFAULT_VALUE	0xf600f200
#define PLLDP_MISC3_CTRL2_DEFAULT_VALUE	0x2005f600
#define PLLDP_MISC4_VREG_DEFAULT_VALUE	0x00000000

#define PLLDSS_MISC0_WRITE_MASK		0x47ffffff
#define PLLDSS_MISC1_CFG_WRITE_MASK	0xf8000000
#define PLLDSS_MISC2_CTRL1_WRITE_MASK	0xffffffff
#define PLLDSS_MISC3_CTRL2_WRITE_MASK	0xffffffff
#define PLLDSS_MISC4_VREG_WRITE_MASK	0xf0000000

#define PLLC4_MISC0_DEFAULT_VALUE	0x40000000
#define PLLC4_OUT_DEFAULT_VALUE		0x00000000
#define PLLC4_OUT_VREG_MASK		0xf0000000

/* PLLRE */
#define PLLRE_BASE_CLKIN_SEL		(1 << 22)

#define PLLRE_MISC0_LOCK_ENABLE		(1 << 30)
#define PLLRE_MISC0_LOCK_OVERRIDE	(1 << 29)
#define PLLRE_MISC0_LOCK		(1 << 27)
#define PLLRE_MISC0_IDDQ		(1 << 24)

#define PLLRE_BASE_DEFAULT_VALUE	0x00000000
#define PLLRE_MISC0_DEFAULT_VALUE	0x41000000

#define PLLRE_BASE_DEFAULT_MASK		0x1c000000
#define PLLRE_MISC0_WRITE_MASK		0x67ffffff

#define PLLRE_OUT1_DEFAULT_VALUE	0x00000000
#define PLLRE_OUT1_VREG_MASK		0xf0000000

/* PLLX */
#define PLLX_USE_DYN_RAMP		1
#define PLLX_BASE_LOCK			(1 << 27)

#define PLLX_MISC0_FO_G_DISABLE		(0x1 << 28)
#define PLLX_MISC0_LOCK_ENABLE		(0x1 << 18)

#define PLLX_MISC2_DYNRAMP_STEPB_SHIFT	24
#define PLLX_MISC2_DYNRAMP_STEPB_MASK	(0xFF << PLLX_MISC2_DYNRAMP_STEPB_SHIFT)
#define PLLX_MISC2_DYNRAMP_STEPA_SHIFT	16
#define PLLX_MISC2_DYNRAMP_STEPA_MASK	(0xFF << PLLX_MISC2_DYNRAMP_STEPA_SHIFT)
#define PLLX_MISC2_NDIV_NEW_SHIFT	8
#define PLLX_MISC2_NDIV_NEW_MASK	(0xFF << PLLX_MISC2_NDIV_NEW_SHIFT)
#define PLLX_MISC2_LOCK_OVERRIDE	(0x1 << 4)
#define PLLX_MISC2_DYNRAMP_DONE		(0x1 << 2)
#define PLLX_MISC2_EN_DYNRAMP		(0x1 << 0)

#define PLLX_MISC3_IDDQ			(0x1 << 3)

#define PLLX_MISC0_DEFAULT_VALUE	PLLX_MISC0_LOCK_ENABLE
#define PLLX_MISC0_WRITE_MASK		0x10c40000
#define PLLX_MISC1_DEFAULT_VALUE	0x00000000
#define PLLX_MISC1_WRITE_MASK		0xf0ffffff
#define PLLX_MISC2_DEFAULT_VALUE	0x00000000
#define PLLX_MISC2_WRITE_MASK		0xffffff11
#define PLLX_MISC3_DEFAULT_VALUE	PLLX_MISC3_IDDQ
#define PLLX_MISC3_WRITE_MASK		0x01ff0f0f
#define PLLX_MISC4_DEFAULT_VALUE	0x00000000
#define PLLX_MISC4_WRITE_MASK		0x8000ffff
#define PLLX_MISC5_DEFAULT_VALUE	0x00000000
#define PLLX_MISC5_WRITE_MASK		0x0000ffff

#define PLLX_HW_CTRL_CFG		0x548
#define PLLX_HW_CTRL_CFG_SWCTRL		(0x1 << 0)

/* PLLMB */
#define PLLMB_BASE_LOCK			(1 << 27)

#define PLLMB_MISC1_LOCK_OVERRIDE	(1 << 18)
#define PLLMB_MISC1_IDDQ		(1 << 17)
#define PLLMB_MISC1_LOCK_ENABLE		(1 << 16)

#define PLLMB_MISC1_DEFAULT_VALUE	0x00030000
#define PLLMB_MISC1_WRITE_MASK		0x0007ffff

/* PLLP */
#define PLLP_BASE_OVERRIDE		(1 << 28)
#define PLLP_BASE_LOCK			(1 << 27)

#define PLLP_MISC0_LOCK_ENABLE		(1 << 18)
#define PLLP_MISC0_LOCK_OVERRIDE	(1 << 17)
#define PLLP_MISC0_IDDQ			(1 << 3)

#define PLLP_MISC1_HSIO_EN_SHIFT	29
#define PLLP_MISC1_HSIO_EN		(1 << PLLP_MISC1_HSIO_EN_SHIFT)
#define PLLP_MISC1_XUSB_EN_SHIFT	28
#define PLLP_MISC1_XUSB_EN		(1 << PLLP_MISC1_XUSB_EN_SHIFT)

#define PLLP_MISC0_DEFAULT_VALUE	0x00040008
#define PLLP_MISC1_DEFAULT_VALUE	0x00000000

#define PLLP_MISC0_WRITE_MASK		0xfdc6000f
#define PLLP_MISC1_WRITE_MASK		0x70ffffff

/* PLLU */
#define PLLU_BASE_LOCK			(1 << 27)
#define PLLU_BASE_OVERRIDE		(1 << 24)
#define PLLU_BASE_CLKENABLE_USB		(1 << 21)
#define PLLU_BASE_CLKENABLE_HSIC	(1 << 22)
#define PLLU_BASE_CLKENABLE_ICUSB	(1 << 23)
#define PLLU_BASE_CLKENABLE_48M		(1 << 25)
#define PLLU_BASE_CLKENABLE_ALL		(PLLU_BASE_CLKENABLE_USB |\
					 PLLU_BASE_CLKENABLE_HSIC |\
					 PLLU_BASE_CLKENABLE_ICUSB |\
					 PLLU_BASE_CLKENABLE_48M)

#define PLLU_BASE_MNP_DEFAULT_VALUE	0x00011902

#define PLLU_MISC0_IDDQ			(1 << 31)
#define PLLU_MISC0_LOCK_ENABLE		(1 << 29)
#define PLLU_MISC1_LOCK_OVERRIDE	(1 << 0)

#define PLLU_MISC0_DEFAULT_VALUE	0xa0000000
#define PLLU_MISC1_DEFAULT_VALUE	0x00000000

#define PLLU_MISC0_WRITE_MASK		0xbfffffff
#define PLLU_MISC1_WRITE_MASK		0xf0000007

/* UTMIPLL */
#define UTMIP_PLL_CFG0_WRITE_MASK	0x1fffffff
#define UTMIP_PLL_CFG0_DEFAULT_VALUE	0x00190101

/* PLLE */
#define PLLE_SS_ENABLE	1
#define PLLE_SS_MAX_VAL 0x25
#define PLLE_SS_INC_VAL (0x1 << 16)
#define PLLE_SS_INCINTRV_VAL (0x20 << 24)
#define PLLE_SS_COEFFICIENTS_VAL \
	(PLLE_SS_MAX_VAL | PLLE_SS_INC_VAL | PLLE_SS_INCINTRV_VAL)

#define mask(w) ((1 << (w)) - 1)
#define divm_mask(p) mask(p->params->div_nmp->divm_width)
#define divn_mask(p) mask(p->params->div_nmp->divn_width)
#define divp_mask(p) mask(p->params->div_nmp->divp_width)

#define divm_shift(p) ((p)->params->div_nmp->divm_shift)
#define divn_shift(p) ((p)->params->div_nmp->divn_shift)
#define divp_shift(p) ((p)->params->div_nmp->divp_shift)

#define divm_mask_shifted(p) (divm_mask(p) << divm_shift(p))
#define divn_mask_shifted(p) (divn_mask(p) << divn_shift(p))
#define divp_mask_shifted(p) (divp_mask(p) << divp_shift(p))

#define PLL_LOCKDET_DELAY 2	/* Lock detection safety delays */
static int tegra210b01_wait_for_pll_stable(struct tegra_clk_pll *pll,
					   u32 reg, u32 mask)
{
	int i;
	u32 val = 0;

	for (i = 0; i < pll->params->lock_delay / PLL_LOCKDET_DELAY + 1; i++) {
		udelay(PLL_LOCKDET_DELAY);
		val = readl_relaxed(clk_base + reg);
		if ((val & mask) == mask) {
			udelay(PLL_LOCKDET_DELAY);
			return 0;
		}
	}
	return -ETIMEDOUT;
}

static inline void _pll_misc_chk_default(void __iomem *base,
					struct tegra_clk_pll_params *params,
					u8 misc_num, u32 default_val, u32 mask)
{
	u32 boot_val = readl_relaxed(base + params->ext_misc_reg[misc_num]);

	boot_val &= mask;
	default_val &= mask;
	if (boot_val != default_val) {
		pr_warn("boot misc%d 0x%x: expected 0x%x\n",
			misc_num, boot_val, default_val);
		pr_warn(" (comparison mask = 0x%x)\n", mask);
		params->defaults_set = false;
	}
}

/*
 * PLLCX: PLLC, PLLC2, PLLC3, PLLA1
 * Hybrid PLLs with dynamic ramp. Dynamic ramp is allowed for any transition
 * that changes NDIV only, while PLL is already locked.
 */
static void pllcx_check_defaults(struct tegra_clk_pll_params *params)
{
	u32 default_val;

	default_val = PLLCX_MISC0_DEFAULT_VALUE & (~PLLCX_MISC0_RESET);
	_pll_misc_chk_default(clk_base, params, 0, default_val,
			PLLCX_MISC0_WRITE_MASK);

	default_val = PLLCX_MISC1_DEFAULT_VALUE & (~PLLCX_MISC1_IDDQ);
	_pll_misc_chk_default(clk_base, params, 1, default_val,
			PLLCX_MISC1_WRITE_MASK);

	default_val = PLLCX_MISC2_DEFAULT_VALUE;
	_pll_misc_chk_default(clk_base, params, 2, default_val,
			PLLCX_MISC2_WRITE_MASK);

	default_val = PLLCX_MISC3_DEFAULT_VALUE;
	_pll_misc_chk_default(clk_base, params, 3, default_val,
			PLLCX_MISC3_WRITE_MASK);
}

static void tegra210b01_pllcx_set_defaults(const char *name,
					   struct tegra_clk_pll *pllcx)
{
	pllcx->params->defaults_set = true;

	if (readl_relaxed(clk_base + pllcx->params->base_reg) &
			PLL_ENABLE && !pllcx->params->defaults_set) {
		/* PLL is ON: only check if defaults already set */
		pllcx_check_defaults(pllcx->params);
		if (!pllcx->params->defaults_set)
			pr_warn("%s already enabled. Postponing set full defaults\n",
				name);
		return;
	}

	/* Defaults assert PLL reset, and set IDDQ */
	writel_relaxed(PLLCX_MISC0_DEFAULT_VALUE,
			clk_base + pllcx->params->ext_misc_reg[0]);
	writel_relaxed(PLLCX_MISC1_DEFAULT_VALUE,
			clk_base + pllcx->params->ext_misc_reg[1]);
	writel_relaxed(PLLCX_MISC2_DEFAULT_VALUE,
			clk_base + pllcx->params->ext_misc_reg[2]);
	writel_relaxed(PLLCX_MISC3_DEFAULT_VALUE,
			clk_base + pllcx->params->ext_misc_reg[3]);
	fence_udelay(1, clk_base);
}

static void _pllc_set_defaults(struct tegra_clk_pll *pllcx)
{
	tegra210b01_pllcx_set_defaults("PLL_C", pllcx);
}

static void _pllc2_set_defaults(struct tegra_clk_pll *pllcx)
{
	tegra210b01_pllcx_set_defaults("PLL_C2", pllcx);
}

static void _pllc3_set_defaults(struct tegra_clk_pll *pllcx)
{
	tegra210b01_pllcx_set_defaults("PLL_C3", pllcx);
}

static void _plla1_set_defaults(struct tegra_clk_pll *pllcx)
{
	tegra210b01_pllcx_set_defaults("PLL_A1", pllcx);
}

/*
 * PLLA
 * PLL with dynamic ramp and fractional SDM. Dynamic ramp is not used.
 * Fractional SDM is allowed to provide exact audio rates.
 */
static void tegra210b01_plla_set_defaults(struct tegra_clk_pll *plla)
{
	u32 mask;
	u32 val = readl_relaxed(clk_base + plla->params->base_reg);

	plla->params->defaults_set = true;

	if (val & PLL_ENABLE) {
		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		if (val & PLLA_BASE_IDDQ) {
			pr_warn("PLL_A boot enabled with IDDQ set\n");
			plla->params->defaults_set = false;
		}

		val = PLLA_MISC0_DEFAULT_VALUE;	/* ignore lock enable */
		mask = PLLA_MISC0_LOCK_ENABLE | PLLA_MISC0_LOCK_OVERRIDE;
		_pll_misc_chk_default(clk_base, plla->params, 0, val,
				~mask & PLLA_MISC0_WRITE_MASK);

		val = PLLA_MISC2_DEFAULT_VALUE; /* ignore all but control bit */
		_pll_misc_chk_default(clk_base, plla->params, 2, val,
				PLLA_MISC2_EN_DYNRAMP);

		val = readl_relaxed(clk_base + PLLA_OUT) & PLLA_OUT_VREG_MASK;
		if (val != PLLA_OUT_DEFAULT_VALUE) {
			pr_warn("boot PLL_A vreg 0x%x: expected 0x%x\n",
				val, PLLA_OUT_DEFAULT_VALUE);
			plla->params->defaults_set = false;
		}

		/* Enable lock detect */
		val = readl_relaxed(clk_base + plla->params->ext_misc_reg[0]);
		val &= ~mask;
		val |= PLLA_MISC0_DEFAULT_VALUE & mask;
		writel_relaxed(val, clk_base + plla->params->ext_misc_reg[0]);
		fence_udelay(1, clk_base);

		if (!plla->params->defaults_set)
			pr_warn("PLL_A already enabled. Postponing set full defaults\n");

		return;
	}

	/* set IDDQ, enable lock detect, disable dynamic ramp and SDM */
	val |= PLLA_BASE_IDDQ;
	writel_relaxed(val, clk_base + plla->params->base_reg);
	writel_relaxed(PLLA_MISC0_DEFAULT_VALUE,
			clk_base + plla->params->ext_misc_reg[0]);
	writel_relaxed(PLLA_MISC2_DEFAULT_VALUE,
			clk_base + plla->params->ext_misc_reg[2]);
	val = readl_relaxed(clk_base + PLLA_OUT) & (~PLLA_OUT_VREG_MASK);
	writel_relaxed(val | PLLA_OUT_DEFAULT_VALUE, clk_base + PLLA_OUT);
	fence_udelay(1, clk_base);
}

/*
 * PLLD
 * PLL with fractional SDM.
 */
static void tegra210b01_plld_set_defaults(struct tegra_clk_pll *plld)
{
	u32 val;
	u32 mask = 0xffff;

	plld->params->defaults_set = true;

	if (readl_relaxed(clk_base + plld->params->base_reg) &
			PLL_ENABLE) {

		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		val = PLLD_MISC1_DEFAULT_VALUE;
		_pll_misc_chk_default(clk_base, plld->params, 1,
				val, PLLD_MISC1_WRITE_MASK);

		/* ignore lock, DSI and SDM controls, make sure IDDQ not set */
		val = PLLD_MISC0_DEFAULT_VALUE & (~PLLD_MISC0_IDDQ);
		mask |= PLLD_MISC0_DSI_CLKENABLE | PLLD_MISC0_LOCK_ENABLE |
			PLLD_MISC0_LOCK_OVERRIDE | PLLD_MISC0_EN_SDM;
		_pll_misc_chk_default(clk_base, plld->params, 0, val,
				~mask & PLLD_MISC0_WRITE_MASK);

		if (!plld->params->defaults_set)
			pr_warn("PLL_D already enabled. Postponing set full defaults\n");

		/* Enable lock detect */
		mask = PLLD_MISC0_LOCK_ENABLE | PLLD_MISC0_LOCK_OVERRIDE;
		val = readl_relaxed(clk_base + plld->params->ext_misc_reg[0]);
		val &= ~mask;
		val |= PLLD_MISC0_DEFAULT_VALUE & mask;
		writel_relaxed(val, clk_base + plld->params->ext_misc_reg[0]);
		fence_udelay(1, clk_base);

		return;
	}

	val = readl_relaxed(clk_base + plld->params->ext_misc_reg[0]);
	val &= PLLD_MISC0_DSI_CLKENABLE;
	val |= PLLD_MISC0_DEFAULT_VALUE;
	/* set IDDQ, enable lock detect, disable SDM */
	writel_relaxed(val, clk_base + plld->params->ext_misc_reg[0]);
	writel_relaxed(PLLD_MISC1_DEFAULT_VALUE, clk_base +
			plld->params->ext_misc_reg[1]);
	fence_udelay(1, clk_base);
}

/*
 * PLLD2, PLLDP
 * PLL with fractional SDM and Spread Spectrum (SDM is a must if SSC is used).
 */
static void plldss_defaults(const char *pll_name, struct tegra_clk_pll *plldss,
		u32 misc0_val, u32 misc1_val, u32 misc2_val, u32 misc3_val,
		u32 misc4_val)
{
	u32 default_val;
	u32 val = readl_relaxed(clk_base + plldss->params->base_reg);

	plldss->params->defaults_set = true;

	if (val & PLL_ENABLE) {
		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		if (val & PLLDSS_BASE_IDDQ) {
			pr_warn("plldss boot enabled with IDDQ set\n");
			plldss->params->defaults_set = false;
		}

		/* ignore lock enable */
		default_val = misc0_val;
		_pll_misc_chk_default(clk_base, plldss->params, 0, default_val,
				     PLLDSS_MISC0_WRITE_MASK &
				     (~PLLDSS_MISC0_LOCK_ENABLE));

		/*
		 * If SSC is used, check all settings, otherwise just confirm
		 * that SSC is not used on boot as well. Do nothing when using
		 * this function for PLLC4 that has only MISC0.
		 */
		if (plldss->params->ssc_ctrl_en_mask) {
			default_val = misc1_val;
			_pll_misc_chk_default(clk_base, plldss->params, 1,
				default_val, PLLDSS_MISC1_CFG_WRITE_MASK);
			default_val = misc2_val;
			_pll_misc_chk_default(clk_base, plldss->params, 2,
				default_val, PLLDSS_MISC2_CTRL1_WRITE_MASK);
			default_val = misc3_val;
			_pll_misc_chk_default(clk_base, plldss->params, 3,
				default_val, PLLDSS_MISC3_CTRL2_WRITE_MASK);
		} else if (plldss->params->ext_misc_reg[1]) {
			default_val = misc1_val;
			_pll_misc_chk_default(clk_base, plldss->params, 1,
				default_val, PLLDSS_MISC1_CFG_WRITE_MASK &
				(~PLLDSS_MISC1_CFG_EN_SDM));
		}

		default_val = misc4_val;
		_pll_misc_chk_default(clk_base, plldss->params, 4,
			default_val, PLLDSS_MISC4_VREG_WRITE_MASK);

		if (!plldss->params->defaults_set)
			pr_warn("%s already enabled. Postponing set full defaults\n",
				pll_name);

		/* Enable lock detect */
		if (val & PLLDSS_BASE_LOCK_OVERRIDE) {
			val &= ~PLLDSS_BASE_LOCK_OVERRIDE;
			writel_relaxed(val, clk_base +
					plldss->params->base_reg);
		}

		val = readl_relaxed(clk_base + plldss->params->ext_misc_reg[0]);
		val &= ~PLLDSS_MISC0_LOCK_ENABLE;
		val |= misc0_val & PLLDSS_MISC0_LOCK_ENABLE;
		writel_relaxed(val, clk_base + plldss->params->ext_misc_reg[0]);
		fence_udelay(1, clk_base);

		return;
	}

	/* set IDDQ, enable lock detect, configure SDM/SSC  */
	val |= PLLDSS_BASE_IDDQ;
	val &= ~PLLDSS_BASE_LOCK_OVERRIDE;
	writel_relaxed(val, clk_base + plldss->params->base_reg);

	writel_relaxed(misc0_val, clk_base +
			plldss->params->ext_misc_reg[0]);
	/* if SSC used set by 1st enable */
	writel_relaxed(misc1_val & (~PLLDSS_MISC1_CFG_EN_SSC),
			clk_base + plldss->params->ext_misc_reg[1]);
	writel_relaxed(misc2_val, clk_base + plldss->params->ext_misc_reg[2]);
	writel_relaxed(misc3_val, clk_base + plldss->params->ext_misc_reg[3]);
	writel_relaxed(misc4_val, clk_base + plldss->params->ext_misc_reg[4]);
	fence_udelay(1, clk_base);
}

static void tegra210b01_plld2_set_defaults(struct tegra_clk_pll *plld2)
{
	plldss_defaults("PLL_D2", plld2, PLLD2_MISC0_DEFAULT_VALUE,
			PLLD2_MISC1_CFG_DEFAULT_VALUE,
			PLLD2_MISC2_CTRL1_DEFAULT_VALUE,
			PLLD2_MISC3_CTRL2_DEFAULT_VALUE,
			PLLD2_MISC4_VREG_DEFAULT_VALUE);
}

static void tegra210b01_plldp_set_defaults(struct tegra_clk_pll *plldp)
{
	plldss_defaults("PLL_DP", plldp, PLLDP_MISC0_DEFAULT_VALUE,
			PLLDP_MISC1_CFG_DEFAULT_VALUE,
			PLLDP_MISC2_CTRL1_DEFAULT_VALUE,
			PLLDP_MISC3_CTRL2_DEFAULT_VALUE,
			PLLDP_MISC4_VREG_DEFAULT_VALUE);
}

/*
 * PLLC4
 * Base and misc0 layout is the same as PLLD2/PLLDP, but no SDM/SSC support.
 * VCO is exposed to the clock tree via fixed 1/3 and 1/5 dividers.
 */
static void tegra210b01_pllc4_set_defaults(struct tegra_clk_pll *pllc4)
{
	u32 default_val;
	u32 val = readl_relaxed(clk_base + pllc4->params->base_reg);

	pllc4->params->defaults_set = true;

	if (val & PLL_ENABLE) {
		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		if (val & PLLDSS_BASE_IDDQ) {
			pr_warn("PLL_C4 boot enabled with IDDQ set\n");
			pllc4->params->defaults_set = false;
		}

		/* ignore lock enable */
		default_val = PLLC4_MISC0_DEFAULT_VALUE;
		_pll_misc_chk_default(clk_base, pllc4->params, 0, default_val,
				     PLLDSS_MISC0_WRITE_MASK &
				     (~PLLDSS_MISC0_LOCK_ENABLE));

		val = readl_relaxed(clk_base + PLLC4_OUT) & PLLC4_OUT_VREG_MASK;
		if (val != PLLC4_OUT_DEFAULT_VALUE) {
			pr_warn("boot PLL_C4 vreg 0x%x: expected 0x%x\n",
				val, PLLC4_OUT_DEFAULT_VALUE);
			pllc4->params->defaults_set = false;
		}

		/* Enable lock detect */
		if (val & PLLDSS_BASE_LOCK_OVERRIDE) {
			val &= ~PLLDSS_BASE_LOCK_OVERRIDE;
			writel_relaxed(val, clk_base + pllc4->params->base_reg);
		}

		val = readl_relaxed(clk_base + pllc4->params->ext_misc_reg[0]);
		val &= ~PLLDSS_MISC0_LOCK_ENABLE;
		val |= PLLC4_MISC0_DEFAULT_VALUE & PLLDSS_MISC0_LOCK_ENABLE;
		writel_relaxed(val, clk_base + pllc4->params->ext_misc_reg[0]);
		fence_udelay(1, clk_base);

		if (!pllc4->params->defaults_set)
			pr_warn("PLL_C4 already enabled. Postponing set full defaults\n");

		return;
	}

	/* set IDDQ, enable lock detect  */
	val |= PLLDSS_BASE_IDDQ;
	val &= ~PLLDSS_BASE_LOCK_OVERRIDE;
	writel_relaxed(val, clk_base + pllc4->params->base_reg);
	writel_relaxed(PLLC4_MISC0_DEFAULT_VALUE,
		       clk_base + pllc4->params->ext_misc_reg[0]);
	val = readl_relaxed(clk_base + PLLC4_OUT) & (~PLLC4_OUT_VREG_MASK);
	writel_relaxed(val | PLLC4_OUT_DEFAULT_VALUE, clk_base + PLLC4_OUT);
	fence_udelay(1, clk_base);
	return;
}

/*
 * PLLRE
 * VCO is exposed to the clock tree directly along with post-divider output
 */
static void tegra210b01_pllre_set_defaults(struct tegra_clk_pll *pllre)
{
	u32 mask;
	u32 val = readl_relaxed(clk_base + pllre->params->base_reg);

	pllre->params->defaults_set = true;

	if (val & PLL_ENABLE) {
		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		val &= PLLRE_BASE_DEFAULT_MASK;
		if (val != PLLRE_BASE_DEFAULT_VALUE) {
			pr_warn("pllre boot base 0x%x : expected 0x%x\n",
				val, PLLRE_BASE_DEFAULT_VALUE);
			pr_warn("(comparison mask = 0x%x)\n",
				PLLRE_BASE_DEFAULT_MASK);
			pllre->params->defaults_set = false;
		}

		val = readl_relaxed(clk_base + PLLRE_OUT1) &
			PLLRE_OUT1_VREG_MASK;
		if (val != PLLRE_OUT1_DEFAULT_VALUE) {
			pr_warn("boot PLLRE vreg 0x%x: expected 0x%x\n",
				val, PLLRE_OUT1_DEFAULT_VALUE);
			pllre->params->defaults_set = false;
		}

		/* Ignore lock enable */
		val = PLLRE_MISC0_DEFAULT_VALUE & (~PLLRE_MISC0_IDDQ);
		mask = PLLRE_MISC0_LOCK_ENABLE | PLLRE_MISC0_LOCK_OVERRIDE;
		_pll_misc_chk_default(clk_base, pllre->params, 0, val,
				~mask & PLLRE_MISC0_WRITE_MASK);

		/* Enable lock detect */
		val = readl_relaxed(clk_base + pllre->params->ext_misc_reg[0]);
		val &= ~mask;
		val |= PLLRE_MISC0_DEFAULT_VALUE & mask;
		writel_relaxed(val, clk_base + pllre->params->ext_misc_reg[0]);
		val = readl_relaxed(clk_base + PLLRE_OUT1) &
			(~PLLRE_OUT1_VREG_MASK);
		writel_relaxed(val | PLLRE_OUT1_DEFAULT_VALUE,
			       clk_base + PLLRE_OUT1);
		fence_udelay(1, clk_base);

		if (!pllre->params->defaults_set)
			pr_warn("PLL_RE already enabled. Postponing set full defaults\n");

		return;
	}

	/* set IDDQ, enable lock detect */
	val &= ~PLLRE_BASE_DEFAULT_MASK;
	val |= PLLRE_BASE_DEFAULT_VALUE & PLLRE_BASE_DEFAULT_MASK;
	writel_relaxed(val, clk_base + pllre->params->base_reg);
	writel_relaxed(PLLRE_MISC0_DEFAULT_VALUE,
			clk_base + pllre->params->ext_misc_reg[0]);
	fence_udelay(1, clk_base);
}

/*
 * PLLX
 * Dynamic ramp support
 */
static void pllx_get_dyn_steps(struct clk_hw *hw, u32 *step_a, u32 *step_b)
{
	unsigned long input_rate;

	/* cf rate */
	if (!IS_ERR_OR_NULL(hw->clk))
		input_rate = clk_hw_get_rate(clk_hw_get_parent(hw));
	else
		input_rate = 38400000;

	input_rate /= tegra_pll_get_fixed_mdiv(hw, input_rate);

	switch (input_rate) {
	case 12000000:
	case 12800000:
	case 13000000:
		*step_a = 0x2B;
		*step_b = 0x0B;
		return;
	case 19200000:
		*step_a = 0x12;
		*step_b = 0x08;
		return;
	case 38400000:
		*step_a = 0x04;
		*step_b = 0x05;
		return;
	default:
		pr_err("%s: Unexpected reference rate %lu\n",
			__func__, input_rate);
		BUG();
	}
}

static void pllx_check_defaults(struct tegra_clk_pll *pll)
{
	u32 default_val;

	default_val = PLLX_MISC0_DEFAULT_VALUE;
	/* ignore lock enable */
	_pll_misc_chk_default(clk_base, pll->params, 0, default_val,
			PLLX_MISC0_WRITE_MASK & (~PLLX_MISC0_LOCK_ENABLE));

	default_val = PLLX_MISC1_DEFAULT_VALUE;
	_pll_misc_chk_default(clk_base, pll->params, 1, default_val,
			PLLX_MISC1_WRITE_MASK);

	/* ignore all but control bit */
	default_val = PLLX_MISC2_DEFAULT_VALUE;
	_pll_misc_chk_default(clk_base, pll->params, 2,
			default_val, PLLX_MISC2_EN_DYNRAMP);

	default_val = PLLX_MISC3_DEFAULT_VALUE & (~PLLX_MISC3_IDDQ);
	_pll_misc_chk_default(clk_base, pll->params, 3, default_val,
			PLLX_MISC3_WRITE_MASK);

	default_val = PLLX_MISC4_DEFAULT_VALUE;
	_pll_misc_chk_default(clk_base, pll->params, 4, default_val,
			PLLX_MISC4_WRITE_MASK);

	default_val = PLLX_MISC5_DEFAULT_VALUE;
	_pll_misc_chk_default(clk_base, pll->params, 5, default_val,
			PLLX_MISC5_WRITE_MASK);
}

static void tegra210b01_pllx_set_defaults(struct tegra_clk_pll *pllx)
{
	u32 val;
	u32 step_a, step_b;

	pllx->params->defaults_set = true;

	/* Get ready dyn ramp state machine settings */
	pllx_get_dyn_steps(&pllx->hw, &step_a, &step_b);
	val = PLLX_MISC2_DEFAULT_VALUE & (~PLLX_MISC2_DYNRAMP_STEPA_MASK) &
		(~PLLX_MISC2_DYNRAMP_STEPB_MASK);
	val |= step_a << PLLX_MISC2_DYNRAMP_STEPA_SHIFT;
	val |= step_b << PLLX_MISC2_DYNRAMP_STEPB_SHIFT;

	if (readl_relaxed(clk_base + pllx->params->base_reg) & PLL_ENABLE) {

		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		pllx_check_defaults(pllx);

		if (!pllx->params->defaults_set)
			pr_warn("PLL_X already enabled. Postponing set full defaults\n");
		/* Configure dyn ramp, disable lock override */
		writel_relaxed(val, clk_base + pllx->params->ext_misc_reg[2]);

		/* Enable lock detect */
		val = readl_relaxed(clk_base + pllx->params->ext_misc_reg[0]);
		val &= ~PLLX_MISC0_LOCK_ENABLE;
		val |= PLLX_MISC0_DEFAULT_VALUE & PLLX_MISC0_LOCK_ENABLE;
		writel_relaxed(val, clk_base + pllx->params->ext_misc_reg[0]);
		fence_udelay(1, clk_base);

		return;
	}

	/* Enable lock detect and CPU output */
	writel_relaxed(PLLX_MISC0_DEFAULT_VALUE, clk_base +
			pllx->params->ext_misc_reg[0]);

	/* Setup */
	writel_relaxed(PLLX_MISC1_DEFAULT_VALUE, clk_base +
			pllx->params->ext_misc_reg[1]);

	/* Configure dyn ramp state machine, disable lock override */
	writel_relaxed(val, clk_base + pllx->params->ext_misc_reg[2]);

	/* Set IDDQ */
	writel_relaxed(PLLX_MISC3_DEFAULT_VALUE, clk_base +
			pllx->params->ext_misc_reg[3]);

	/* Disable SDM */
	writel_relaxed(PLLX_MISC4_DEFAULT_VALUE, clk_base +
			pllx->params->ext_misc_reg[4]);
	writel_relaxed(PLLX_MISC5_DEFAULT_VALUE, clk_base +
			pllx->params->ext_misc_reg[5]);
	fence_udelay(1, clk_base);
}

static int tegra210b01_pllx_dyn_ramp(struct tegra_clk_pll *pllx,
				     struct tegra_clk_pll_freq_table *cfg)
{
	u32 val, base, ndiv_new_mask;

	ndiv_new_mask = (divn_mask(pllx) >> pllx->params->div_nmp->divn_shift)
			 << PLLX_MISC2_NDIV_NEW_SHIFT;

	val = readl_relaxed(clk_base + pllx->params->ext_misc_reg[2]);
	val &= (~ndiv_new_mask);
	val |= cfg->n << PLLX_MISC2_NDIV_NEW_SHIFT;
	writel_relaxed(val, clk_base + pllx->params->ext_misc_reg[2]);
	fence_udelay(1, clk_base);

	val = readl_relaxed(clk_base + pllx->params->ext_misc_reg[2]);
	val |= PLLX_MISC2_EN_DYNRAMP;
	writel_relaxed(val, clk_base + pllx->params->ext_misc_reg[2]);
	fence_udelay(1, clk_base);

	tegra210b01_wait_for_pll_stable(pllx, pllx->params->ext_misc_reg[2],
				     PLLX_MISC2_DYNRAMP_DONE);

	base = readl_relaxed(clk_base + pllx->params->base_reg) &
		(~divn_mask_shifted(pllx));
	base |= cfg->n << pllx->params->div_nmp->divn_shift;
	writel_relaxed(base, clk_base + pllx->params->base_reg);
	fence_udelay(1, clk_base);

	val &= ~PLLX_MISC2_EN_DYNRAMP;
	writel_relaxed(val, clk_base + pllx->params->ext_misc_reg[2]);
	fence_udelay(1, clk_base);

	pr_debug("%s: dynamic ramp to m = %u n = %u p = %u, Fout = %lu kHz\n",
		 __clk_get_name(pllx->hw.clk), cfg->m, cfg->n, cfg->p,
		 cfg->input_rate / cfg->m * cfg->n /
		 pllx->params->pdiv_tohw[cfg->p].pdiv / 1000);

	return 0;
}

/*
 * PLLP
 * VCO is exposed to the clock tree directly along with post-divider output.
 * Both VCO and post-divider output rates are fixed at 408MHz and 204MHz,
 * respectively.
 */
static void pllp_check_defaults(struct tegra_clk_pll *pll, bool enabled)
{
	u32 val, mask;

	/* Ignore lock enable (will be set), make sure not in IDDQ if enabled */
	val = PLLP_MISC0_DEFAULT_VALUE & (~PLLP_MISC0_IDDQ);
	mask = PLLP_MISC0_LOCK_ENABLE | PLLP_MISC0_LOCK_OVERRIDE;
	if (!enabled)
		mask |= PLLP_MISC0_IDDQ;
	_pll_misc_chk_default(clk_base, pll->params, 0, val,
			~mask & PLLP_MISC0_WRITE_MASK);

	/* Ignore branch controls */
	val = PLLP_MISC1_DEFAULT_VALUE;
	mask = PLLP_MISC1_HSIO_EN | PLLP_MISC1_XUSB_EN;
	_pll_misc_chk_default(clk_base, pll->params, 1, val,
			~mask & PLLP_MISC1_WRITE_MASK);
}

static void tegra210b01_pllp_set_defaults(struct tegra_clk_pll *pllp)
{
	u32 mask;
	u32 val = readl_relaxed(clk_base + pllp->params->base_reg);

	/* Disable in h/w pll_p_out1 that is not routed to any module */
	writel_relaxed(0, clk_base + PLLP_OUTA);

	pllp->params->defaults_set = true;

	if (val & PLL_ENABLE) {

		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		pllp_check_defaults(pllp, true);
		if (!pllp->params->defaults_set)
			pr_warn("PLL_P already enabled. Postponing set full defaults\n");

		/* Enable lock detect */
		val = readl_relaxed(clk_base + pllp->params->ext_misc_reg[0]);
		mask = PLLP_MISC0_LOCK_ENABLE | PLLP_MISC0_LOCK_OVERRIDE;
		val &= ~mask;
		val |= PLLP_MISC0_DEFAULT_VALUE & mask;
		writel_relaxed(val, clk_base + pllp->params->ext_misc_reg[0]);
		fence_udelay(1, clk_base);

		return;
	}

	/* set IDDQ, enable lock detect */
	writel_relaxed(PLLP_MISC0_DEFAULT_VALUE,
			clk_base + pllp->params->ext_misc_reg[0]);

	/* Preserve branch control */
	val = readl_relaxed(clk_base + pllp->params->ext_misc_reg[1]);
	mask = PLLP_MISC1_HSIO_EN | PLLP_MISC1_XUSB_EN;
	val &= mask;
	val |= ~mask & PLLP_MISC1_DEFAULT_VALUE;
	writel_relaxed(val, clk_base + pllp->params->ext_misc_reg[1]);
	fence_udelay(1, clk_base);
}

/*
 * PLLU
 * VCO is exposed to the clock tree directly along with post-divider output.
 * Both VCO and post-divider output rates are fixed at 480MHz and 240MHz,
 * respectively.
 */
static void pllu_check_defaults(struct tegra_clk_pll_params *params,
				bool hw_control)
{
	u32 val, mask;

	/* Ignore lock enable (will be set) and IDDQ if under h/w control */
	val = PLLU_MISC0_DEFAULT_VALUE & (~PLLU_MISC0_IDDQ);
	mask = PLLU_MISC0_LOCK_ENABLE | (hw_control ? PLLU_MISC0_IDDQ : 0);
	_pll_misc_chk_default(clk_base, params, 0, val,
			~mask & PLLU_MISC0_WRITE_MASK);

	val = PLLU_MISC1_DEFAULT_VALUE;
	mask = PLLU_MISC1_LOCK_OVERRIDE;
	_pll_misc_chk_default(clk_base, params, 1, val,
			~mask & PLLU_MISC1_WRITE_MASK);
}

static void tegra210b01_pllu_set_defaults(struct tegra_clk_pll_params *pllu)
{
	u32 val = readl_relaxed(clk_base + pllu->base_reg);

	pllu->defaults_set = true;

	if (val & PLL_ENABLE) {

		/*
		 * PLL is ON: check if defaults already set, then set those
		 * that can be updated in flight.
		 */
		pllu_check_defaults(pllu, false);
		if (!pllu->defaults_set)
			pr_warn("PLL_U already enabled. Postponing set full defaults\n");

		/* Enable lock detect */
		val = readl_relaxed(clk_base + pllu->ext_misc_reg[0]);
		val &= ~PLLU_MISC0_LOCK_ENABLE;
		val |= PLLU_MISC0_DEFAULT_VALUE & PLLU_MISC0_LOCK_ENABLE;
		writel_relaxed(val, clk_base + pllu->ext_misc_reg[0]);

		val = readl_relaxed(clk_base + pllu->ext_misc_reg[1]);
		val &= ~PLLU_MISC1_LOCK_OVERRIDE;
		val |= PLLU_MISC1_DEFAULT_VALUE & PLLU_MISC1_LOCK_OVERRIDE;
		writel_relaxed(val, clk_base + pllu->ext_misc_reg[1]);
		fence_udelay(1, clk_base);

		return;
	}

	/* set IDDQ, enable lock detect */
	writel_relaxed(PLLU_MISC0_DEFAULT_VALUE,
			clk_base + pllu->ext_misc_reg[0]);
	writel_relaxed(PLLU_MISC1_DEFAULT_VALUE,
			clk_base + pllu->ext_misc_reg[1]);
	fence_udelay(1, clk_base);
}

/*
 * UTMIPLL
 * Running at fixed 960MHz rate with fixed 1:2 factor 480MHz output supplied
 * to USB link (not exposed to clock tree), and fixed 1:16 factor 60MHz supplied
 * to PLL_RE (exposed to clock tree).
 */
static int utmipll_set_defaults(bool locked)
{
	u32 val = readl_relaxed(clk_base + UTMIP_PLL_CFG0);

	if (locked)
		return (val & UTMIP_PLL_CFG0_WRITE_MASK) ==
			UTMIP_PLL_CFG0_DEFAULT_VALUE ? 0 : -EINVAL;

	writel_relaxed(UTMIP_PLL_CFG0_DEFAULT_VALUE,
		       clk_base + UTMIP_PLL_CFG0);
	fence_udelay(1, clk_base);

	return 0;
}

/*
 * Common configuration for PLLs with fixed input divider policy:
 * - always set fixed M-value based on the reference rate
 * - always set P-value value 1:1 for output rates above VCO minimum, and
 *   choose minimum necessary P-value for output rates below VCO maximum
 * - calculate N-value based on selected M and P
 * - calculate SDM_DIN fractional part
 */
static int tegra210b01_pll_fixed_mdiv_cfg(struct clk_hw *hw,
			struct tegra_clk_pll_freq_table *cfg,
			unsigned long rate, unsigned long input_rate)
{
	struct tegra_clk_pll *pll = to_clk_pll(hw);
	struct tegra_clk_pll_params *params = pll->params;
	int p;
	unsigned long cf, p_rate;
	u32 pdiv;

	if (!rate)
		return -EINVAL;

	if (!(params->flags & TEGRA_PLL_VCO_OUT)) {
		p = DIV_ROUND_UP(params->vco_min, rate);
		p = params->round_p_to_pdiv(p, &pdiv);
	} else {
		p = rate >= params->vco_min ? 1 : -EINVAL;
	}

	if (p < 0)
		return -EINVAL;

	cfg->m = tegra_pll_get_fixed_mdiv(hw, input_rate);
	cfg->p = p;

	/* Store P as HW value, as that is what is expected */
	cfg->p = tegra_pll_p_div_to_hw(pll, cfg->p);

	p_rate = rate * p;
	if (p_rate > params->vco_max)
		p_rate = params->vco_max;
	cf = input_rate / cfg->m;
	cfg->n = p_rate / cf;

	cfg->sdm_data = 0;
	cfg->output_rate = input_rate;
	if (params->sdm_ctrl_reg) {
		unsigned long rem = p_rate - cf * cfg->n;
		/* If ssc is enabled SDM enabled as well, even for integer n */
		if (rem || params->ssc_ctrl_reg) {
			u64 s = rem * PLL_SDM_COEFF;

			do_div(s, cf);
			s -= PLL_SDM_COEFF / 2;
			cfg->sdm_data = sdin_din_to_data(s);
		}
		cfg->output_rate *= sdin_get_n_eff(cfg);
		cfg->output_rate /= p * cfg->m * PLL_SDM_COEFF;
	} else {
		cfg->output_rate *= cfg->n;
		cfg->output_rate /= p * cfg->m;
	}

	cfg->input_rate = input_rate;

	return 0;
}

/*
 * clk_pll_set_gain - set gain to m, n to calculate correct VCO rate
 *
 * @cfg: struct tegra_clk_pll_freq_table * cfg
 *
 * For Normal mode:
 *     Fvco = Fref * NDIV / MDIV
 *
 * For fractional mode:
 *     Fvco = Fref * (NDIV + 0.5 + SDM_DIN / PLL_SDM_COEFF) / MDIV
 */
static void tegra210b01_clk_pll_set_gain(struct tegra_clk_pll_freq_table *cfg)
{
	cfg->n = sdin_get_n_eff(cfg);
	cfg->m *= PLL_SDM_COEFF;
}

static unsigned long
tegra210b01_clk_adjust_vco_min(struct tegra_clk_pll_params *params,
			       unsigned long parent_rate)
{
	return tegra_pll_adjust_vco_min_sdm(params, parent_rate, PLL_SDM_COEFF);
}

/*
 * PLL post divider maps - two types: quasi-linear and exponential
 * post divider.
 */
#define PLL_QLIN_PDIV_MAX	16
static const struct pdiv_map pll_qlin_pdiv_to_hw[] = {
	{ .pdiv =  1, .hw_val =  0 },
	{ .pdiv =  2, .hw_val =  1 },
	{ .pdiv =  3, .hw_val =  2 },
	{ .pdiv =  4, .hw_val =  3 },
	{ .pdiv =  5, .hw_val =  4 },
	{ .pdiv =  6, .hw_val =  5 },
	{ .pdiv =  8, .hw_val =  6 },
	{ .pdiv =  9, .hw_val =  7 },
	{ .pdiv = 10, .hw_val =  8 },
	{ .pdiv = 12, .hw_val =  9 },
	{ .pdiv = 15, .hw_val = 10 },
	{ .pdiv = 16, .hw_val = 11 },
	{ .pdiv = 18, .hw_val = 12 },
	{ .pdiv = 20, .hw_val = 13 },
	{ .pdiv = 24, .hw_val = 14 },
	{ .pdiv = 30, .hw_val = 15 },
	{ .pdiv = 31, .hw_val = 16 },
	{ .pdiv =  0, },
};

static u32 pll_qlin_p_to_pdiv(u32 p, u32 *pdiv)
{
	int i;

	if (p) {
		for (i = 0; i <= PLL_QLIN_PDIV_MAX; i++) {
			if (p <= pll_qlin_pdiv_to_hw[i].pdiv) {
				if (pdiv)
					*pdiv = i;
				return pll_qlin_pdiv_to_hw[i].pdiv;
			}
		}
	}

	return -EINVAL;
}

#define PLL_EXPO_PDIV_MAX	7
static const struct pdiv_map pll_expo_pdiv_to_hw[] = {
	{ .pdiv =   1, .hw_val = 0 },
	{ .pdiv =   2, .hw_val = 1 },
	{ .pdiv =   4, .hw_val = 2 },
	{ .pdiv =   8, .hw_val = 3 },
	{ .pdiv =  16, .hw_val = 4 },
	{ .pdiv =  32, .hw_val = 5 },
	{ .pdiv =  64, .hw_val = 6 },
	{ .pdiv = 128, .hw_val = 7 },
	{ .pdiv =   0, },
};

static u32 pll_expo_p_to_pdiv(u32 p, u32 *pdiv)
{
	if (p) {
		u32 i = fls(p);

		if (i == ffs(p))
			i--;

		if (i <= PLL_EXPO_PDIV_MAX) {
			if (pdiv)
				*pdiv = i;
			return 1 << i;
		}
	}
	return -EINVAL;
}

static struct div_nmp pllx_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 8,
	.divn_width = 8,
	.divp_shift = 20,
	.divp_width = 5,
};

static struct tegra_clk_pll_freq_table pll_x_freq_table[] = {
	/* 1 GHz */
	{ 38400000, 1000000000, 104, 2, 2, 0 }, /* actual: 998.4 MHz */
	{        0,          0,   0, 0, 0, 0 },
};

static struct tegra_clk_pll_params pll_x_params = {
	.input_min = 13500000,
	.input_max = 800000000,
	.cf_min = 13500000,
	.cf_max = 38400000,
	.vco_min = 1300000000,
	.vco_max = 3000000000UL,
	.base_reg = PLLX_BASE,
	.misc_reg = PLLX_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_enable_bit_idx = PLL_MISC_LOCK_ENABLE,
	.lock_delay = 300,
	.ext_misc_reg[0] = PLLX_MISC0,
	.ext_misc_reg[1] = PLLX_MISC1,
	.ext_misc_reg[2] = PLLX_MISC2,
	.ext_misc_reg[3] = PLLX_MISC3,
	.ext_misc_reg[4] = PLLX_MISC4,
	.ext_misc_reg[5] = PLLX_MISC5,
	.iddq_reg = PLLX_MISC3,
	.iddq_bit_idx = PLLXP_IDDQ_BIT,
	.max_p = PLL_QLIN_PDIV_MAX,
	.mdiv_default = 2,
	.dyn_ramp_reg = PLLX_MISC2,
	.stepa_shift = 16,
	.stepb_shift = 24,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.div_nmp = &pllx_nmp,
	.freq_table = pll_x_freq_table,
	.flags = TEGRA_PLL_USE_LOCK | TEGRA_PLL_HAS_LOCK_ENABLE,
	.dyn_ramp = tegra210b01_pllx_dyn_ramp,
	.set_defaults = tegra210b01_pllx_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct div_nmp pllcx_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 10,
	.divn_width = 8,
	.divp_shift = 20,
	.divp_width = 5,
};

static struct tegra_clk_pll_freq_table pll_cx_freq_table[] = {
	{ 38400000, 510000000, 53, 2, 2, 0 }, /* actual: 508.8 MHz */
	{        0,         0,  0, 0, 0, 0 },
};

static struct tegra_clk_pll_params pll_c_params = {
	.input_min = 19200000,
	.input_max = 700000000,
	.cf_min = 19200000,
	.cf_max = 38400000,
	.vco_min = 600000000,
	.vco_max = 1200000000,
	.base_reg = PLLC_BASE,
	.misc_reg = PLLC_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 300,
	.iddq_reg = PLLC_MISC1,
	.iddq_bit_idx = PLLCX_IDDQ_BIT,
	.reset_reg = PLLC_MISC0,
	.reset_bit_idx = PLLCX_RESET_BIT,
	.max_p = PLL_QLIN_PDIV_MAX,
	.ext_misc_reg[0] = PLLC_MISC0,
	.ext_misc_reg[1] = PLLC_MISC1,
	.ext_misc_reg[2] = PLLC_MISC2,
	.ext_misc_reg[3] = PLLC_MISC3,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.mdiv_default = 2,
	.div_nmp = &pllcx_nmp,
	.freq_table = pll_cx_freq_table,
	.flags = TEGRA_PLL_USE_LOCK,
	.set_defaults = _pllc_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct tegra_clk_pll_params pll_c2_params = {
	.input_min = 19200000,
	.input_max = 700000000,
	.cf_min = 19200000,
	.cf_max = 38400000,
	.vco_min = 600000000,
	.vco_max = 1200000000,
	.base_reg = PLLC2_BASE,
	.misc_reg = PLLC2_MISC0,
	.iddq_reg = PLLC2_MISC1,
	.iddq_bit_idx = PLLCX_IDDQ_BIT,
	.reset_reg = PLLC2_MISC0,
	.reset_bit_idx = PLLCX_RESET_BIT,
	.lock_mask = PLLCX_BASE_LOCK,
	.lock_delay = 300,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.mdiv_default = 2,
	.div_nmp = &pllcx_nmp,
	.max_p = PLL_QLIN_PDIV_MAX,
	.ext_misc_reg[0] = PLLC2_MISC0,
	.ext_misc_reg[1] = PLLC2_MISC1,
	.ext_misc_reg[2] = PLLC2_MISC2,
	.ext_misc_reg[3] = PLLC2_MISC3,
	.freq_table = pll_cx_freq_table,
	.flags = TEGRA_PLL_USE_LOCK,
	.set_defaults = _pllc2_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct tegra_clk_pll_params pll_c3_params = {
	.input_min = 19200000,
	.input_max = 700000000,
	.cf_min = 19200000,
	.cf_max = 38400000,
	.vco_min = 600000000,
	.vco_max = 1200000000,
	.base_reg = PLLC3_BASE,
	.misc_reg = PLLC3_MISC0,
	.lock_mask = PLLCX_BASE_LOCK,
	.lock_delay = 300,
	.iddq_reg = PLLC3_MISC1,
	.iddq_bit_idx = PLLCX_IDDQ_BIT,
	.reset_reg = PLLC3_MISC0,
	.reset_bit_idx = PLLCX_RESET_BIT,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.mdiv_default = 2,
	.div_nmp = &pllcx_nmp,
	.max_p = PLL_QLIN_PDIV_MAX,
	.ext_misc_reg[0] = PLLC3_MISC0,
	.ext_misc_reg[1] = PLLC3_MISC1,
	.ext_misc_reg[2] = PLLC3_MISC2,
	.ext_misc_reg[3] = PLLC3_MISC3,
	.freq_table = pll_cx_freq_table,
	.flags = TEGRA_PLL_USE_LOCK,
	.set_defaults = _pllc3_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct div_nmp pllss_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 8,
	.divn_width = 8,
	.divp_shift = 19,
	.divp_width = 5,
};

static struct tegra_clk_pll_freq_table pll_c4_vco_freq_table[] = {
	{ 38400000, 998400000, 52, 2, 1, 0 },
	{ 38400000, 787200000, 41, 2, 1, 0 },
	{        0,         0,  0, 0, 0, 0 },
};

static const struct clk_div_table pll_vco_post_div_table[] = {
	{ .val =  0, .div =  1 },
	{ .val =  1, .div =  2 },
	{ .val =  2, .div =  3 },
	{ .val =  3, .div =  4 },
	{ .val =  4, .div =  5 },
	{ .val =  5, .div =  6 },
	{ .val =  6, .div =  8 },
	{ .val =  7, .div =  9 },
	{ .val =  8, .div = 10 },
	{ .val =  9, .div = 12 },
	{ .val = 10, .div = 15 },
	{ .val = 11, .div = 16 },
	{ .val = 12, .div = 18 },
	{ .val = 13, .div = 20 },
	{ .val = 14, .div = 24 },
	{ .val = 15, .div = 30 },
	{ .val = 16, .div = 31 },
	{ .val =  0, .div =  0 },
};

static struct tegra_clk_pll_params pll_c4_vco_params = {
	.input_min = 12000000,
	.input_max = 800000000,
	.cf_min = 12000000,
	.cf_max = 38400000,
	.vco_min = 500000000,
	.vco_max = 1000000000,
	.base_reg = PLLC4_BASE,
	.misc_reg = PLLC4_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 300,
	.max_p = PLL_QLIN_PDIV_MAX,
	.ext_misc_reg[0] = PLLC4_MISC0,
	.iddq_reg = PLLC4_BASE,
	.iddq_bit_idx = PLLSS_IDDQ_BIT,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.mdiv_default = 2,
	.div_nmp = &pllss_nmp,
	.freq_table = pll_c4_vco_freq_table,
	.set_defaults = tegra210b01_pllc4_set_defaults,
	.flags = TEGRA_PLL_USE_LOCK | TEGRA_PLL_VCO_OUT,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct tegra_clk_pll_freq_table pll_e_freq_table[] = {
	/* PLLE special case: use cpcon field to store cml divider value */
	{  38400000, 100000000, 125,  2, 1, 14 },
	{         0,         0,   0,  0, 0,  0 },
};

static struct div_nmp plle_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 8,
	.divn_width = 8,
	.divp_shift = 24,
	.divp_width = 5,
};

static struct tegra_clk_pll_params pll_e_params = {
	.input_min = 19200000,
	.input_max = 800000000,
	.cf_min = 19200000,
	.cf_max = 38400000,
	.vco_min = 1250000000,
	.vco_max = 2500000000U,
	.base_reg = PLLE_BASE,
	.misc_reg = PLLE_MISC0,
	.aux_reg = PLLE_AUX,
	.lock_mask = PLLE_MISC_LOCK,
	.lock_enable_bit_idx = PLLE_MISC_LOCK_ENABLE,
	.lock_delay = 300,
	.div_nmp = &plle_nmp,
	.ssc_ctrl_en_mask = PLLE_SS_COEFFICIENTS_VAL,
#if PLLE_SS_ENABLE
	.ssc_ctrl_reg = PLLE_SS_CTRL,
#endif
	.freq_table = pll_e_freq_table,
	.flags = TEGRA_PLL_FIXED | TEGRA_PLL_LOCK_MISC | TEGRA_PLL_USE_LOCK |
		 TEGRA_PLL_HAS_LOCK_ENABLE,
	.fixed_rate = 100000000,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct tegra_clk_pll_freq_table pll_re_vco_freq_table[] = {
	{ 38400000, 672000000,  70,  4, 1, 0 },
	{ 38400000, 624000000,  65,  4, 1, 0 },
	{ 60000000, 625000000, 125, 12, 1, 0 },
	{        0,         0,   0,  0, 0, 0 },
};

static struct div_nmp pllre_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 8,
	.divn_width = 8,
	.divp_shift = 16,
	.divp_width = 5,
};

static struct tegra_clk_pll_params pll_re_vco_params = {
	.input_min = 9600000,
	.input_max = 800000000,
	.cf_min = 9600000,
	.cf_max = 19200000,
	.vco_min = 350000000,
	.vco_max = 700000000,
	.base_reg = PLLRE_BASE,
	.misc_reg = PLLRE_MISC0,
	.lock_mask = PLLRE_MISC_LOCK,
	.lock_delay = 300,
	.max_p = PLL_QLIN_PDIV_MAX,
	.ext_misc_reg[0] = PLLRE_MISC0,
	.iddq_reg = PLLRE_MISC0,
	.iddq_bit_idx = PLLRE_IDDQ_BIT,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.div_nmp = &pllre_nmp,
	.mdiv_default = 4,
	.freq_table = pll_re_vco_freq_table,
	.flags = TEGRA_PLL_USE_LOCK | TEGRA_PLL_LOCK_MISC | TEGRA_PLL_VCO_OUT,
	.set_defaults = tegra210b01_pllre_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct div_nmp pllp_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 10,
	.divn_width = 8,
	.divp_shift = 20,
	.divp_width = 5,
};

static struct tegra_clk_pll_freq_table pll_p_freq_table[] = {
	/* cf = 4.8MHz, allowed exception */
	{ 38400000, 408000000, 85, 8, 1, 0 },
	{        0,         0,  0, 0, 0, 0 },
};

static struct tegra_clk_pll_params pll_p_params = {
	.input_min = 9600000,
	.input_max = 800000000,
	.cf_min = 9600000,
	.cf_max = 19200000,
	.vco_min = 350000000,
	.vco_max = 700000000,
	.base_reg = PLLP_BASE,
	.misc_reg = PLLP_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 300,
	.iddq_reg = PLLP_MISC0,
	.iddq_bit_idx = PLLXP_IDDQ_BIT,
	.ext_misc_reg[0] = PLLP_MISC0,
	.ext_misc_reg[1] = PLLP_MISC1,
	.div_nmp = &pllp_nmp,
	.freq_table = pll_p_freq_table,
	.fixed_rate = 408000000,
	.flags = TEGRA_PLL_FIXED | TEGRA_PLL_USE_LOCK | TEGRA_PLL_VCO_OUT,
	.mdiv_default = 4,
	.set_defaults = tegra210b01_pllp_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct tegra_clk_pll_params pll_a1_params = {
	.input_min = 19200000,
	.input_max = 700000000,
	.cf_min = 19200000,
	.cf_max = 38400000,
	.vco_min = 600000000,
	.vco_max = 1200000000,
	.base_reg = PLLA1_BASE,
	.misc_reg = PLLA1_MISC0,
	.lock_mask = PLLCX_BASE_LOCK,
	.lock_delay = 300,
	.iddq_reg = PLLA1_MISC1,
	.iddq_bit_idx = PLLCX_IDDQ_BIT,
	.reset_reg = PLLA1_MISC0,
	.reset_bit_idx = PLLCX_RESET_BIT,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.div_nmp = &pllcx_nmp,
	.ext_misc_reg[0] = PLLA1_MISC0,
	.ext_misc_reg[1] = PLLA1_MISC1,
	.ext_misc_reg[2] = PLLA1_MISC2,
	.ext_misc_reg[3] = PLLA1_MISC3,
	.freq_table = pll_cx_freq_table,
	.flags = TEGRA_PLL_USE_LOCK,
	.mdiv_default = 2,
	.set_defaults = _plla1_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
};

static struct div_nmp plla_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 8,
	.divn_width = 8,
	.divp_shift = 20,
	.divp_width = 5,
};

static struct tegra_clk_pll_freq_table pll_a_freq_table[] = {
	{ 38400000, 282240000, 29, 2, 2, 1, 0xfccc }, /* actual: 282239063 */
	{ 38400000, 368640000, 38, 2, 2, 1, 0xfccc }, /* actual: 368639063 */
	{        0,         0,  0, 0, 0, 0,      0 },
};

static struct tegra_clk_pll_params pll_a_params = {
	.input_min = 12000000,
	.input_max = 800000000,
	.cf_min = 12000000,
	.cf_max = 38400000,
	.vco_min = 500000000,
	.vco_max = 1000000000,
	.base_reg = PLLA_BASE,
	.misc_reg = PLLA_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 300,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.iddq_reg = PLLA_BASE,
	.iddq_bit_idx = PLLA_IDDQ_BIT,
	.div_nmp = &plla_nmp,
	.sdm_din_reg = PLLA_MISC1,
	.sdm_din_mask = PLLA_SDM_DIN_MASK,
	.sdm_ctrl_reg = PLLA_MISC2,
	.sdm_ctrl_en_mask = PLLA_SDM_EN_MASK,
	.ext_misc_reg[0] = PLLA_MISC0,
	.ext_misc_reg[1] = PLLA_MISC1,
	.ext_misc_reg[2] = PLLA_MISC2,
	.freq_table = pll_a_freq_table,
	.flags = TEGRA_PLL_USE_LOCK | TEGRA_MDIV_NEW,
	.mdiv_default = 2,
	.set_defaults = tegra210b01_plla_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
	.set_gain = tegra210b01_clk_pll_set_gain,
	.adjust_vco = tegra210b01_clk_adjust_vco_min,
};

static struct div_nmp plld_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 11,
	.divn_width = 8,
	.divp_shift = 20,
	.divp_width = 3,
};

static struct tegra_clk_pll_freq_table pll_d_freq_table[] = {
	{ 38400000, 594000000, 30, 1, 2, 0, 0x0e00 },
	{        0,         0,  0, 0, 0, 0,      0 },
};

static struct tegra_clk_pll_params pll_d_params = {
	.input_min = 13500000,
	.input_max = 800000000,
	.cf_min = 13500000,
	.cf_max = 38400000,
	.vco_min = 800000000,
	.vco_max = 1620000000,
	.base_reg = PLLD_BASE,
	.misc_reg = PLLD_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 1000,
	.iddq_reg = PLLD_MISC0,
	.iddq_bit_idx = PLLD_IDDQ_BIT,
	.round_p_to_pdiv = pll_expo_p_to_pdiv,
	.pdiv_tohw = pll_expo_pdiv_to_hw,
	.div_nmp = &plld_nmp,
	.sdm_din_reg = PLLD_MISC0,
	.sdm_din_mask = PLLA_SDM_DIN_MASK,
	.sdm_ctrl_reg = PLLD_MISC0,
	.sdm_ctrl_en_mask = PLLD_SDM_EN_MASK,
	.ext_misc_reg[0] = PLLD_MISC0,
	.ext_misc_reg[1] = PLLD_MISC1,
	.freq_table = pll_d_freq_table,
	.flags = TEGRA_PLL_USE_LOCK,
	.mdiv_default = 1,
	.set_defaults = tegra210b01_plld_set_defaults,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
	.set_gain = tegra210b01_clk_pll_set_gain,
	.adjust_vco = tegra210b01_clk_adjust_vco_min,
};

static struct tegra_clk_pll_freq_table tegra210b01_pll_d2_freq_table[] = {
	{ 38400000, 594000000, 30, 1, 2, 0, 0x0e00 },
	{        0,         0,  0, 0, 0, 0,      0 },
};

/* s/w policy, always tegra_pll_ref */
static struct tegra_clk_pll_params pll_d2_params = {
	.input_min = 13500000,
	.input_max = 800000000,
	.cf_min = 13500000,
	.cf_max = 38400000,
	.vco_min = 780000000,
	.vco_max = 1620000000,
	.base_reg = PLLD2_BASE,
	.misc_reg = PLLD2_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 300,
	.iddq_reg = PLLD2_BASE,
	.iddq_bit_idx = PLLSS_IDDQ_BIT,
	.sdm_din_reg = PLLD2_MISC3,
	.sdm_din_mask = PLLA_SDM_DIN_MASK,
	.sdm_ctrl_reg = PLLD2_MISC1,
	.sdm_ctrl_en_mask = PLLD2_SDM_EN_MASK,
	.ssc_ctrl_reg = PLLD2_MISC1,
	.ssc_ctrl_en_mask = PLLD2_SSC_EN_MASK,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.div_nmp = &pllss_nmp,
	.ext_misc_reg[0] = PLLD2_MISC0,
	.ext_misc_reg[1] = PLLD2_MISC1,
	.ext_misc_reg[2] = PLLD2_MISC2,
	.ext_misc_reg[3] = PLLD2_MISC3,
	.ext_misc_reg[4] = PLLD2_MISC4,
	.max_p = PLL_QLIN_PDIV_MAX,
	.mdiv_default = 1,
	.freq_table = tegra210b01_pll_d2_freq_table,
	.set_defaults = tegra210b01_plld2_set_defaults,
	.flags = TEGRA_PLL_USE_LOCK,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
	.set_gain = tegra210b01_clk_pll_set_gain,
	.adjust_vco = tegra210b01_clk_adjust_vco_min,
};

static struct tegra_clk_pll_freq_table pll_dp_freq_table[] = {
	{ 38400000, 270000000, 42, 1, 6, 0, 0xf600 },
	{        0,         0,  0, 0, 0, 0,      0 },
};

static struct tegra_clk_pll_params pll_dp_params = {
	.input_min = 13500000,
	.input_max = 800000000,
	.cf_min = 13500000,
	.cf_max = 38400000,
	.vco_min = 780000000,
	.vco_max = 1620000000,
	.base_reg = PLLDP_BASE,
	.misc_reg = PLLDP_MISC,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 300,
	.iddq_reg = PLLDP_BASE,
	.iddq_bit_idx = PLLSS_IDDQ_BIT,
	.sdm_din_reg = PLLDP_SS_CTRL2,
	.sdm_din_mask = PLLA_SDM_DIN_MASK,
	.sdm_ctrl_reg = PLLDP_SS_CFG,
	.sdm_ctrl_en_mask = PLLDP_SDM_EN_MASK,
	.ssc_ctrl_reg = PLLDP_SS_CFG,
	.ssc_ctrl_en_mask = PLLDP_SSC_EN_MASK,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.div_nmp = &pllss_nmp,
	.ext_misc_reg[0] = PLLDP_MISC,
	.ext_misc_reg[1] = PLLDP_SS_CFG,
	.ext_misc_reg[2] = PLLDP_SS_CTRL1,
	.ext_misc_reg[3] = PLLDP_SS_CTRL2,
	.ext_misc_reg[4] = PLLDP_MISC4,
	.max_p = PLL_QLIN_PDIV_MAX,
	.mdiv_default = 1,
	.freq_table = pll_dp_freq_table,
	.set_defaults = tegra210b01_plldp_set_defaults,
	.flags = TEGRA_PLL_USE_LOCK,
	.calc_rate = tegra210b01_pll_fixed_mdiv_cfg,
	.set_gain = tegra210b01_clk_pll_set_gain,
	.adjust_vco = tegra210b01_clk_adjust_vco_min,
};

static struct div_nmp pllu_nmp = {
	.divm_shift = 0,
	.divm_width = 8,
	.divn_shift = 8,
	.divn_width = 8,
	.divp_shift = 16,
	.divp_width = 5,
};

static struct tegra_clk_pll_freq_table pll_u_freq_table[] = {
	{ 38400000, 240000000, 25, 2, 1, 0 },
	{        0,         0,  0, 0, 0, 0 },
};

static struct tegra_clk_pll_params pll_u_vco_params = {
	.input_min = 9600000,
	.input_max = 800000000,
	.cf_min = 9600000,
	.cf_max = 19200000,
	.vco_min = 350000000,
	.vco_max = 700000000,
	.base_reg = PLLU_BASE,
	.misc_reg = PLLU_MISC0,
	.lock_mask = PLL_BASE_LOCK,
	.lock_delay = 1000,
	.iddq_reg = PLLU_MISC0,
	.iddq_bit_idx = PLLU_IDDQ_BIT,
	.ext_misc_reg[0] = PLLU_MISC0,
	.ext_misc_reg[1] = PLLU_MISC1,
	.round_p_to_pdiv = pll_qlin_p_to_pdiv,
	.pdiv_tohw = pll_qlin_pdiv_to_hw,
	.div_nmp = &pllu_nmp,
	.mdiv_default = 2,
	.freq_table = pll_u_freq_table,
	.flags = TEGRA_PLLU | TEGRA_PLL_USE_LOCK | TEGRA_PLL_VCO_OUT,
};

struct utmi_clk_param {
	/* Oscillator Frequency in KHz */
	u32 osc_frequency;
	/* UTMIP PLL Enable Delay Count  */
	u8 enable_delay_count;
	/* UTMIP PLL Stable count */
	u16 stable_count;
	/*  UTMIP PLL Active delay count */
	u8 active_delay_count;
	/* UTMIP PLL Xtal frequency count */
	u16 xtal_freq_count;
};

static const struct utmi_clk_param utmi_parameters[] = {
	{
		.osc_frequency = 38400000, .enable_delay_count = 0x0,
		.stable_count = 0x0, .active_delay_count = 0x6,
		.xtal_freq_count = 0x80
	}, {
		.osc_frequency = 13000000, .enable_delay_count = 0x02,
		.stable_count = 0x33, .active_delay_count = 0x05,
		.xtal_freq_count = 0x7f
	}, {
		.osc_frequency = 19200000, .enable_delay_count = 0x03,
		.stable_count = 0x4b, .active_delay_count = 0x06,
		.xtal_freq_count = 0xbb
	}, {
		.osc_frequency = 12000000, .enable_delay_count = 0x02,
		.stable_count = 0x2f, .active_delay_count = 0x08,
		.xtal_freq_count = 0x76
	}, {
		.osc_frequency = 26000000, .enable_delay_count = 0x04,
		.stable_count = 0x66, .active_delay_count = 0x09,
		.xtal_freq_count = 0xfe
	}, {
		.osc_frequency = 16800000, .enable_delay_count = 0x03,
		.stable_count = 0x41, .active_delay_count = 0x0a,
		.xtal_freq_count = 0xa4
	},
};

static void tegra210b01_utmi_param_configure(void)
{
	u32 reg;
	int i;

	for (i = 0; i < ARRAY_SIZE(utmi_parameters); i++) {
		if (osc_freq == utmi_parameters[i].osc_frequency)
			break;
	}

	if (i >= ARRAY_SIZE(utmi_parameters)) {
		pr_err("%s: Unexpected oscillator freq %lu\n", __func__,
		       osc_freq);
		return;
	}

	reg = readl_relaxed(clk_base + UTMIPLL_HW_PWRDN_CFG0);
	reg &= ~UTMIPLL_HW_PWRDN_CFG0_IDDQ_OVERRIDE;
	writel_relaxed(reg, clk_base + UTMIPLL_HW_PWRDN_CFG0);

	fence_udelay(10, clk_base);

	reg = readl_relaxed(clk_base + UTMIP_PLL_CFG2);

	/* Program UTMIP PLL stable and active counts */
	/* [FIXME] arclk_rst.h says WRONG! This should be 1ms -> 0x50 Check! */
	reg &= ~UTMIP_PLL_CFG2_STABLE_COUNT(~0);
	reg |= UTMIP_PLL_CFG2_STABLE_COUNT(utmi_parameters[i].stable_count);

	reg &= ~UTMIP_PLL_CFG2_ACTIVE_DLY_COUNT(~0);
	reg |= UTMIP_PLL_CFG2_ACTIVE_DLY_COUNT(utmi_parameters[i].
					    active_delay_count);
	writel_relaxed(reg, clk_base + UTMIP_PLL_CFG2);

	/* Program UTMIP PLL delay and oscillator frequency counts */
	reg = readl_relaxed(clk_base + UTMIP_PLL_CFG1);

	reg &= ~UTMIP_PLL_CFG1_ENABLE_DLY_COUNT(~0);
	reg |= UTMIP_PLL_CFG1_ENABLE_DLY_COUNT(utmi_parameters[i].
					    enable_delay_count);

	reg &= ~UTMIP_PLL_CFG1_XTAL_FREQ_COUNT(~0);
	reg |= UTMIP_PLL_CFG1_XTAL_FREQ_COUNT(utmi_parameters[i].
					   xtal_freq_count);

	reg |= UTMIP_PLL_CFG1_FORCE_PLLU_POWERDOWN;
	writel_relaxed(reg, clk_base + UTMIP_PLL_CFG1);

	/* Remove power downs from UTMIP PLL control bits */
	reg = readl_relaxed(clk_base + UTMIP_PLL_CFG1);
	reg &= ~UTMIP_PLL_CFG1_FORCE_PLL_ENABLE_POWERDOWN;
	reg |= UTMIP_PLL_CFG1_FORCE_PLL_ENABLE_POWERUP;
	writel_relaxed(reg, clk_base + UTMIP_PLL_CFG1);
	fence_udelay(20, clk_base);

	/* Enable samplers for SNPS, XUSB_HOST, XUSB_DEV */
	reg = readl_relaxed(clk_base + UTMIP_PLL_CFG2);
	reg |= UTMIP_PLL_CFG2_FORCE_PD_SAMP_A_POWERUP;
	reg |= UTMIP_PLL_CFG2_FORCE_PD_SAMP_B_POWERUP;
	reg |= UTMIP_PLL_CFG2_FORCE_PD_SAMP_D_POWERUP;
	reg &= ~UTMIP_PLL_CFG2_FORCE_PD_SAMP_A_POWERDOWN;
	reg &= ~UTMIP_PLL_CFG2_FORCE_PD_SAMP_B_POWERDOWN;
	reg &= ~UTMIP_PLL_CFG2_FORCE_PD_SAMP_D_POWERDOWN;
	writel_relaxed(reg, clk_base + UTMIP_PLL_CFG2);
}

static void tegra210b01_utmi_hw_sequencer_enable(void)
{
	u32 reg;

	/* Setup HW control of UTMIPLL */
	reg = readl_relaxed(clk_base + UTMIP_PLL_CFG1);
	reg &= ~UTMIP_PLL_CFG1_FORCE_PLL_ENABLE_POWERDOWN;
	reg &= ~UTMIP_PLL_CFG1_FORCE_PLL_ENABLE_POWERUP;
	writel_relaxed(reg, clk_base + UTMIP_PLL_CFG1);

	reg = readl_relaxed(clk_base + UTMIPLL_HW_PWRDN_CFG0);
	reg |= UTMIPLL_HW_PWRDN_CFG0_USE_LOCKDET;
	reg &= ~UTMIPLL_HW_PWRDN_CFG0_CLK_ENABLE_SWCTL;
	writel_relaxed(reg, clk_base + UTMIPLL_HW_PWRDN_CFG0);

	fence_udelay(1, clk_base);

	reg = readl_relaxed(clk_base + XUSB_PLL_CFG0);
	reg &= ~XUSB_PLL_CFG0_UTMIPLL_LOCK_DLY;
	writel_relaxed(reg, clk_base + XUSB_PLL_CFG0);

	fence_udelay(1, clk_base);

	/* Enable HW control UTMIPLL */
	reg = readl_relaxed(clk_base + UTMIPLL_HW_PWRDN_CFG0);
	reg |= UTMIPLL_HW_PWRDN_CFG0_SEQ_ENABLE;
	writel_relaxed(reg, clk_base + UTMIPLL_HW_PWRDN_CFG0);

	fence_udelay(1, clk_base);
}

static int tegra210b01_enable_utmipll(void)
{
	u32 reg = readl_relaxed(clk_base + UTMIPLL_HW_PWRDN_CFG0);
	bool hw_on = reg & UTMIPLL_HW_PWRDN_CFG0_SEQ_ENABLE;
	bool locked = reg & UTMIPLL_HW_PWRDN_CFG0_UTMIPLL_LOCK;

	pr_info_once("%s: hw %s, lock %s, use_pllre %s\n", __func__,
		     hw_on ? "ON" : "OFF", locked ? "1" : "0",
		     pll_re_use_utmipll ? "YES" : "NO");

	if (hw_on) {
		if (pll_re_use_utmipll || utmipll_set_defaults(true)) {
			WARN(1, "UTMIP PLL: hw is ON with invalid %s\n",
			     pll_re_use_utmipll ? "PLLRE usage" : "M/N values");
			return -EINVAL;
		}
		return 0;
	}

	if (utmipll_set_defaults(locked)) {
		WARN_ON(1);
		return -EINVAL;
	}

	if (!locked)
		tegra210b01_utmi_param_configure();

	if (!pll_re_use_utmipll)
		tegra210b01_utmi_hw_sequencer_enable();

	return 0;
}

static int tegra210b01_enable_pllu(void)
{
	struct tegra_clk_pll_freq_table *fentry;
	struct tegra_clk_pll pllu;
	u32 reg;
	int ret;

	for (fentry = pll_u_freq_table; fentry->input_rate; fentry++) {
		if (fentry->input_rate == pll_ref_freq)
			break;
	}

	if (!fentry->input_rate) {
		pr_err("Unknown PLL_U reference frequency %lu\n", pll_ref_freq);
		return -EINVAL;
	}

	/* clear IDDQ bit */
	pllu.params = &pll_u_vco_params;
	reg = readl_relaxed(clk_base + pllu.params->ext_misc_reg[0]);
	reg &= ~BIT(pllu.params->iddq_bit_idx);
	writel_relaxed(reg, clk_base + pllu.params->ext_misc_reg[0]);
	fence_udelay(5, clk_base);

	reg = readl_relaxed(clk_base + PLLU_BASE);
	reg &= ~GENMASK(20,0);
	reg |= fentry->m;
	reg |= fentry->n << 8;
	reg |= fentry->p << 16;
	writel(reg, clk_base + PLLU_BASE);
	fence_udelay(1, clk_base);
	reg |= PLL_ENABLE;
	writel(reg, clk_base + PLLU_BASE);
	fence_udelay(1, clk_base);

	ret = tegra210b01_wait_for_pll_stable(&pllu, PLLU_BASE, PLL_BASE_LOCK);

	if (ret) {
		pr_err("Timed out waiting for PLL_U to lock\n");
		return -ETIMEDOUT;
	}

	return 0;
}

int tegra210b01_init_pllu(void)
{
	u32 reg;
	int err;
	struct tegra_clk_pll pllu;
	struct tegra_clk_pll *p = &pllu;

	tegra210b01_pllu_set_defaults(&pll_u_vco_params);
	reg = readl_relaxed(clk_base + PLLU_BASE);

	/* PLLU is modeled as fixed clock source - must have default MNP */
	pllu.params = &pll_u_vco_params;
	if ((reg & (divm_mask_shifted(p) | divn_mask_shifted(p) |
		   divp_mask_shifted(p))) != PLLU_BASE_MNP_DEFAULT_VALUE) {
		WARN_ON(1);
		return -EINVAL;
	}

	/* skip initialization when pllu is in hw controlled mode */
	if (reg & PLLU_BASE_OVERRIDE) {
		if (!(reg & PLL_ENABLE)) {
			err = tegra210b01_enable_pllu();
			if (err < 0) {
				WARN_ON(1);
				return err;
			}
		}
		/* enable hw controlled mode */
		reg = readl_relaxed(clk_base + PLLU_BASE);
		reg &= ~PLLU_BASE_OVERRIDE;
		writel(reg, clk_base + PLLU_BASE);

		reg = readl_relaxed(clk_base + PLLU_HW_PWRDN_CFG0);
		reg |= PLLU_HW_PWRDN_CFG0_USE_SWITCH_DETECT |
		       PLLU_HW_PWRDN_CFG0_USE_LOCKDET;
		reg &= ~(PLLU_HW_PWRDN_CFG0_CLK_ENABLE_SWCTL |
			PLLU_HW_PWRDN_CFG0_IDDQ_PD_INCLUDE |
			PLLU_HW_PWRDN_CFG0_CLK_SWITCH_SWCTL);
		writel_relaxed(reg, clk_base + PLLU_HW_PWRDN_CFG0);

		reg = readl_relaxed(clk_base + XUSB_PLL_CFG0);
		reg &= ~XUSB_PLL_CFG0_PLLU_LOCK_DLY_MASK;
		writel_relaxed(reg, clk_base + XUSB_PLL_CFG0);
		fence_udelay(1, clk_base);

		reg = readl_relaxed(clk_base + PLLU_HW_PWRDN_CFG0);
		reg |= PLLU_HW_PWRDN_CFG0_SEQ_ENABLE;
		writel_relaxed(reg, clk_base + PLLU_HW_PWRDN_CFG0);
		fence_udelay(1, clk_base);

		reg = readl_relaxed(clk_base + PLLU_BASE);
		reg &= ~PLLU_BASE_CLKENABLE_USB;
		writel_relaxed(reg, clk_base + PLLU_BASE);
	} else if (!(reg & PLL_ENABLE)) {
		WARN(1, "Disabled PLLU was put under h/w control\n");
	}

	/* enable UTMIPLL hw control if not yet done by the bootloader */
	return tegra210b01_enable_utmipll();
}

static struct tegra_audio_clk_info tegra210b01_audio_plls[] = {
	{ "pll_a", &pll_a_params, tegra_clk_pll_a, "pll_ref" },
	{ "pll_a1", &pll_a1_params, tegra_clk_pll_a1, "pll_ref",
		tegra_clk_register_pllc_tegra210 },
};

void __init tegra210b01_pll_init(void __iomem *car, void __iomem *pmc,
	unsigned long osc, unsigned long ref, struct clk **clks)
{
	struct clk *clk;

	clk_base = car;
	pmc_base = pmc;
	osc_freq = osc;
	pll_ref_freq = ref;

	/* PLL_RE reference clock must be selected by boot-loader */
	pll_re_use_utmipll = readl_relaxed(clk_base + PLLRE_BASE) &
		PLLRE_BASE_CLKIN_SEL;

	/* PLLC */
	clk = tegra_clk_register_pllc_tegra210("pll_c", "pll_ref", clk_base,
			pmc, 0, &pll_c_params, NULL);
	if (!WARN_ON(IS_ERR(clk)))
		clk_register_clkdev(clk, "pll_c", NULL);
	clks[TEGRA210_CLK_PLL_C] = clk;

	/* PLLC_OUT1 */
	clk = tegra_clk_register_divider("pll_c_out1_div", "pll_c",
			clk_base + PLLC_OUT, 0, TEGRA_DIVIDER_ROUND_UP,
			8, 8, 1, NULL);
	clk = tegra_clk_register_pll_out("pll_c_out1", "pll_c_out1_div",
				clk_base + PLLC_OUT, 1, 0,
				CLK_SET_RATE_PARENT, 0, NULL);
	clk_register_clkdev(clk, "pll_c_out1", NULL);
	clks[TEGRA210_CLK_PLL_C_OUT1] = clk;

	/* PLLC_UD */
	clk = clk_register_fixed_factor(NULL, "pll_c_ud", "pll_c",
					CLK_SET_RATE_PARENT, 1, 1);
	clk_register_clkdev(clk, "pll_c_ud", NULL);
	clks[TEGRA210_CLK_PLL_C_UD] = clk;

	/* PLLC2 */
	clk = tegra_clk_register_pllc_tegra210("pll_c2", "pll_ref", clk_base,
			     pmc, 0, &pll_c2_params, NULL);
	clk_register_clkdev(clk, "pll_c2", NULL);
	clks[TEGRA210_CLK_PLL_C2] = clk;

	/* PLLC3 */
	clk = tegra_clk_register_pllc_tegra210("pll_c3", "pll_ref", clk_base,
			     pmc, 0, &pll_c3_params, NULL);
	clk_register_clkdev(clk, "pll_c3", NULL);
	clks[TEGRA210_CLK_PLL_C3] = clk;

	/* PLLU_VCO */
	if (!tegra210b01_init_pllu()) {
		clk = clk_register_fixed_rate(NULL, "pll_u_vco", "pll_ref", 0,
					      480*1000*1000);
		clk_register_clkdev(clk, "pll_u_vco", NULL);
		clks[TEGRA210_CLK_PLL_U] = clk;

		/* PLLU_OUT */
		clk = clk_register_fixed_factor(NULL, "pll_u_out", "pll_u_vco",
						CLK_SET_RATE_PARENT, 1, 2);
		clk_register_clkdev(clk, "pll_u_out", NULL);
		clks[TEGRA210_CLK_PLL_U_OUT] = clk;

		/* UTMIPLL_60M */
		clk = clk_register_fixed_rate(NULL, "utmipll_60M", "pll_ref", 0,
					      60*1000*1000);
		clk_register_clkdev(clk, "utmipll_60M", NULL);
		clks[TEGRA210_CLK_UTMIPLL_60M] = clk;
	}

	/* PLLU_OUT1 */
	clk = tegra_clk_register_divider("pll_u_out1_div", "pll_u_out",
				clk_base + PLLU_OUTA, 0,
				TEGRA_DIVIDER_ROUND_UP,
				8, 8, 1, &pll_u_lock);
	clk = tegra_clk_register_pll_out("pll_u_out1", "pll_u_out1_div",
				clk_base + PLLU_OUTA, 1, 0,
				CLK_SET_RATE_PARENT, 0, &pll_u_lock);
	clk_register_clkdev(clk, "pll_u_out1", NULL);
	clks[TEGRA210_CLK_PLL_U_OUT1] = clk;

	/* PLLU_OUT2 */
	clk = tegra_clk_register_divider("pll_u_out2_div", "pll_u_out",
				clk_base + PLLU_OUTA, 0,
				TEGRA_DIVIDER_ROUND_UP,
				24, 8, 1, &pll_u_lock);
	clk = tegra_clk_register_pll_out("pll_u_out2", "pll_u_out2_div",
				clk_base + PLLU_OUTA, 17, 16,
				CLK_SET_RATE_PARENT, 0, &pll_u_lock);
	clk_register_clkdev(clk, "pll_u_out2", NULL);
	clks[TEGRA210_CLK_PLL_U_OUT2] = clk;

	/* PLLU_480M */
	clk = clk_register_gate(NULL, "pll_u_480M", "pll_u_vco",
				CLK_SET_RATE_PARENT, clk_base + PLLU_BASE,
				22, 0, &pll_u_lock);
	clk_register_clkdev(clk, "pll_u_480M", NULL);
	clks[TEGRA210_CLK_PLL_U_480M] = clk;

	/* PLLU_60M */
	clk = clk_register_gate(NULL, "pll_u_60M", "pll_u_out2",
				CLK_SET_RATE_PARENT, clk_base + PLLU_BASE,
				23, 0, &pll_u_lock);
	clk_register_clkdev(clk, "pll_u_60M", NULL);
	clks[TEGRA210_CLK_PLL_U_60M] = clk;

	/* PLLU_48M */
	clk = clk_register_gate(NULL, "pll_u_48M", "pll_u_out1",
				CLK_SET_RATE_PARENT, clk_base + PLLU_BASE,
				25, 0, &pll_u_lock);
	clk_register_clkdev(clk, "pll_u_48M", NULL);
	clks[TEGRA210_CLK_PLL_U_48M] = clk;

	/* PLLD */
	clk = tegra_clk_register_pll("pll_d", "pll_ref", clk_base, pmc, 0,
			    &pll_d_params, &pll_d_lock);
	clk_register_clkdev(clk, "pll_d", NULL);
	clks[TEGRA210_CLK_PLL_D] = clk;

	/* PLLD_OUT0 */
	clk = clk_register_fixed_factor(NULL, "pll_d_out0", "pll_d",
					CLK_SET_RATE_PARENT, 1, 2);
	clk_register_clkdev(clk, "pll_d_out0", NULL);
	clks[TEGRA210_CLK_PLL_D_OUT0] = clk;

	/* PLL_D_DSI_OUT */
	clk = clk_register_fixed_factor(NULL, "pll_d_dsi_out", "pll_d_out0",
					0, 1, 1);
	clks[TEGRA210_CLK_PLL_D_DSI_OUT] = clk;

	/* PLLRE */
	if (pll_re_use_utmipll) {
		clk = tegra_clk_register_pllre_tegra210(
			"pll_re_vco", "utmipll_60M", clk_base, pmc, 0,
			&pll_re_vco_params, &pll_re_lock, 60*1000*1000);
	} else {
		clk = tegra_clk_register_pllre_tegra210(
			"pll_re_vco", "pll_ref", clk_base, pmc, 0,
			&pll_re_vco_params, &pll_re_lock, pll_ref_freq);
	}
	clk_register_clkdev(clk, "pll_re_vco", NULL);
	clks[TEGRA210_CLK_PLL_RE_VCO] = clk;

	clk = clk_register_divider_table(NULL, "pll_re_out", "pll_re_vco", 0,
					 clk_base + PLLRE_BASE, 16, 5, 0,
					 pll_vco_post_div_table, &pll_re_lock);
	clk_register_clkdev(clk, "pll_re_out", NULL);
	clks[TEGRA210_CLK_PLL_RE_OUT] = clk;

	clk = tegra_clk_register_divider("pll_re_out1_div", "pll_re_vco",
					 clk_base + PLLRE_OUT1, 0,
					 TEGRA_DIVIDER_ROUND_UP,
					 8, 8, 1, NULL);
	clk = tegra_clk_register_pll_out("pll_re_out1", "pll_re_out1_div",
					 clk_base + PLLRE_OUT1, 1, 0,
					 CLK_SET_RATE_PARENT, 0, NULL);
	clks[TEGRA210_CLK_PLL_RE_OUT1] = clk;

	/* PLLE */
	clk = tegra_clk_register_plle_tegra210("pll_e", "pll_ref",
				      clk_base, 0, &pll_e_params, &pll_e_lock);
	clk_register_clkdev(clk, "pll_e", NULL);
	clks[TEGRA210_CLK_PLL_E] = clk;

	/* CML0 */
	clk = clk_register_gate(NULL, "cml0", "pll_e", 0, clk_base + PLLE_AUX,
				0, 0, &pll_e_lock);
	clk_register_clkdev(clk, "cml0", NULL);
	clks[TEGRA210_CLK_CML0] = clk;

	/* CML1 */
	clk = clk_register_gate(NULL, "cml1", "pll_e", 0, clk_base + PLLE_AUX,
				1, 0, &pll_e_lock);
	clk_register_clkdev(clk, "cml1", NULL);
	clks[TEGRA210_CLK_CML1] = clk;

	/* PLLC4 */
	clk = tegra_clk_register_pllre_tegra210("pll_c4_vco", "pll_ref",
		clk_base, pmc, 0, &pll_c4_vco_params, NULL, pll_ref_freq);
	clk_register_clkdev(clk, "pll_c4_vco", NULL);
	clks[TEGRA210_CLK_PLL_C4] = clk;

	/* PLLC4_OUT1 */
	clk = clk_register_fixed_factor(NULL, "pll_c4_out1", "pll_c4_vco",
					CLK_SET_RATE_PARENT, 1, 3);
	clk_register_clkdev(clk, "pll_c4_out1", NULL);
	clks[TEGRA210_CLK_PLL_C4_OUT1] = clk;

	/* PLLC4_OUT2 */
	clk = clk_register_fixed_factor(NULL, "pll_c4_out2", "pll_c4_vco",
					CLK_SET_RATE_PARENT, 1, 5);
	clk_register_clkdev(clk, "pll_c4_out2", NULL);
	clks[TEGRA210_CLK_PLL_C4_OUT2] = clk;

	/* PLLC4_OUT3 */
	clk = tegra_clk_register_divider("pll_c4_out3_div", "pll_c4_out0",
			clk_base + PLLC4_OUT, 0, TEGRA_DIVIDER_ROUND_UP,
			8, 8, 1, NULL);
	clk = tegra_clk_register_pll_out("pll_c4_out3", "pll_c4_out3_div",
				clk_base + PLLC4_OUT, 1, 0,
				CLK_SET_RATE_PARENT, 0, NULL);
	clk_register_clkdev(clk, "pll_c4_out3", NULL);
	clks[TEGRA210_CLK_PLL_C4_OUT3] = clk;

	/* PLLDP */
	clk = tegra_clk_register_pllss_tegra210("pll_dp", "pll_ref", clk_base,
					0, &pll_dp_params, NULL);
	clk_register_clkdev(clk, "pll_dp", NULL);
	clks[TEGRA210_CLK_PLL_DP] = clk;

	/* PLLD2 */
	clk = tegra_clk_register_pllss_tegra210("pll_d2", "pll_ref", clk_base,
					0, &pll_d2_params, &pll_d2_lock);
	clk_register_clkdev(clk, "pll_d2", NULL);
	clks[TEGRA210_CLK_PLL_D2] = clk;

	/* PLLD2_OUT0 */
	clk = clk_register_fixed_factor(NULL, "pll_d2_out0", "pll_d2",
					CLK_SET_RATE_PARENT, 1, 1);
	clk_register_clkdev(clk, "pll_d2_out0", NULL);
	clks[TEGRA210_CLK_PLL_D2_OUT0] = clk;

	/* PLLP_OUT2 */
	clk = clk_register_fixed_factor(NULL, "pll_p_out2", "pll_p",
					CLK_SET_RATE_PARENT, 1, 2);
	clk_register_clkdev(clk, "pll_p_out2", NULL);
	clks[TEGRA210_CLK_PLL_P_OUT2] = clk;

	/* PLLP_UD */
	clk = clk_register_fixed_factor(NULL, "pll_p_ud", "pll_p",
					CLK_SET_RATE_PARENT, 1, 1);
	clk_register_clkdev(clk, "pll_pud", NULL);
	clks[TEGRA210_CLK_PLL_P_UD] = clk;

	/* PLLP_UPHY_OUT */
	clk = tegra_clk_register_divider("pll_p_uphy_div", "pll_p_out_xusb",
		clk_base + PEX_SATA_USB_RX_BYP, 0,
		TEGRA_DIVIDER_ROUND_UP, 0, 8, 1, &pll_p_uphy_lock);
	clk = clk_register_gate(NULL, "pll_p_uphy_out", "pll_p_uphy_div",
		CLK_SET_RATE_PARENT | CLK_IGNORE_UNUSED,
		clk_base + PEX_SATA_USB_RX_BYP, 8, 0, &pll_p_uphy_lock);
	clk_register_clkdev(clk, "pll_p_uphy_out", NULL);
	clks[TEGRA210_CLK_PLL_P_UPHY_OUT] = clk;
}

void __init tegra210b01_audio_clk_init(void __iomem *clk_base,
				       void __iomem *pmc_base,
				       struct tegra_clk *tegra_clks)
{
	tegra_audio_clk_init(clk_base, pmc_base, tegra_clks,
			     tegra210b01_audio_plls,
			     ARRAY_SIZE(tegra210b01_audio_plls), 24576000);
}

void __init tegra210b01_super_clk_init(void __iomem *clk_base,
				       void __iomem *pmc_base,
				       struct tegra_clk *tegra_clks)
{
	tegra_super_clk_gen5_init(clk_base, pmc_base, tegra_clks,
				  &pll_x_params);
}
struct tegra_clk_pll_params __init *tegra210b01_get_pllp_params(void)
{
	return &pll_p_params;
}

struct tegra_clk_pll_params *tegra210b01_get_pllc4_params(void)
{
	return &pll_c4_vco_params;
}

const struct clk_div_table *tegra210b01_get_pll_vco_post_div_table(void)
{
	return pll_vco_post_div_table;
}

static struct tegra_clk_init_table t210b01_init_table[] __initdata = {
	{ TEGRA210_CLK_PLL_A, TEGRA210_CLK_CLK_MAX, 564480000, 1,
		TEGRA_TABLE_RATE_CHANGE_OVERCLOCK },
	{ TEGRA210_CLK_PLL_RE_VCO, TEGRA210_CLK_CLK_MAX, 0, 1,
		TEGRA_TABLE_RATE_CHANGE_OVERCLOCK },
	{ TEGRA210_CLK_PLL_DP, TEGRA210_CLK_CLK_MAX, 270000000, 0,
		TEGRA_TABLE_RATE_CHANGE_OVERCLOCK },
	{ TEGRA210_CLK_PLL_P_UPHY_OUT, TEGRA210_CLK_CLK_MAX, 102000000, 1 },
	{ TEGRA210_CLK_SDMMC_LEGACY, TEGRA210_CLK_PLL_P, 12000000, 0 },
	{ TEGRA210_CLK_I2CSLOW, TEGRA210_CLK_CLK_32K, 32000, 0 },
	{ TEGRA210_CLK_SPDIF_IN, TEGRA210_CLK_CLK_MAX, 136000000, 0 },
	{ TEGRA210_CLK_USB2_HSIC_TRK, TEGRA210_CLK_CLK_MAX, 9600000, 0 },
	{ TEGRA210_CLK_ENTROPY, TEGRA210_CLK_CLK_M, 0, 1},
	/* This MUST be the last entry. */
	{ TEGRA210_CLK_CLK_MAX, TEGRA210_CLK_CLK_MAX, 0, 0 },
};

void __init tegra210b01_clock_table_init(struct clk **clks)
{
	struct clk *clk;
	unsigned long rate;

	 /* Set PLL_RE at 625 MHz from UTMIPLL, or 672MHz, otherwise */
	rate = (pll_re_use_utmipll ? 625 : 672) * 1000 * 1000;
	clk = clks[TEGRA210_CLK_PLL_RE_VCO];
	WARN_ON(IS_ERR_OR_NULL(clk));
	if (clk_set_rate(clk, rate))
		WARN(1, "%s: Failed to set rate %lu of %s\n",
		     __func__, rate,   __clk_get_name(clk));

	tegra_init_from_table(t210b01_init_table, clks, TEGRA210_CLK_CLK_MAX);
}

static enum clk_id tegra210b01_integer_div_id[] = {
	tegra_clk_cilab,
	tegra_clk_cilcd,

	tegra_clk_spdif_out,

	tegra_clk_sbc1_9,
	tegra_clk_sbc2_9,
	tegra_clk_sbc3_9,
	tegra_clk_sbc4_9,

	tegra_clk_sdmmc_legacy,
	tegra_clk_i2cslow,
	tegra_clk_qspi,

	tegra_clk_soc_therm_8,
	tegra_clk_tsensor,
};

void tegra210b01_adjust_clks(struct tegra_clk *tegra_clks)
{
	int i;

	/* Adjust cap clocks */
	tegra_clks[tegra_clk_cap_vcore_sclk].present = false;
	tegra_clks[tegra_clk_cap_vcore_host1x].present = false;
	tegra_clks[tegra_clk_cap_vcore_mselect].present = false;
	tegra_clks[tegra_clk_cap_vcore_abus].present = false;

	tegra_clks[tegra_clk_cap_vcore_ape].dt_id =
		TEGRA210_CLK_CAP_VCORE_APE;
	tegra_clks[tegra_clk_cap_vcore_ape].present = true;

	tegra_clks[tegra_clk_cap_vcore_cbus].dt_id =
		TEGRA210_CLK_CAP_VCORE_CBUS;
	tegra_clks[tegra_clk_cap_vcore_cbus].present = true;

	/* Remove CPU_LP claster clocks */
	tegra_clks[tegra_clk_cclk_lp].present = false;
	tegra_clks[tegra_clk_pll_x_out0].present = false;

	/* Prevent 1:1.5 fractional divider setting */
	div1_5_not_allowed = true;

	/* Prevent any fractional setting */
	for (i = 0; i < ARRAY_SIZE(tegra210b01_integer_div_id); i++) {
		enum clk_id cid = tegra210b01_integer_div_id[i];

		if (cid >= tegra_clk_max || !tegra_clks[cid].present) {
			pr_warn("%s: clk %d is not present\n", __func__, cid);
			continue;
		}
		tegra_clks[cid].use_integer_div = true;
	}
}
