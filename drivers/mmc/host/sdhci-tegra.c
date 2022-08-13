/*
 * Copyright (C) 2010 Google, Inc.
 * Copyright (c) 2012-2018, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/reset.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/slot-gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/debugfs.h>
#include <linux/stat.h>
#include <linux/platform/tegra/emc_bwmgr.h>
#include <linux/padctrl/padctrl.h>
#include <linux/regulator/consumer.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/dma-mapping.h>
#include <linux/pm_runtime.h>
#include <linux/mmc/cmdq_hci.h>
#include <linux/ktime.h>

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/tegra_prod.h>
#include <soc/tegra/chip-id.h>
#include "sdhci-pltfm.h"

/* Tegra SDHOST controller vendor register definitions */
#define SDHCI_TEGRA_VENDOR_CLOCK_CTRL			0x100
#define SDHCI_CLOCK_CTRL_TAP_MASK			0xFF
#define SDHCI_CLOCK_CTRL_TAP_SHIFT			16
#define SDHCI_CLOCK_CTRL_TRIM_SHIFT			24
#define SDHCI_CLOCK_CTRL_TRIM_MASK			0x1F
#define SDHCI_CLOCK_CTRL_LEGACY_CLKEN_OVERRIDE		BIT(6)
#define SDHCI_CLOCK_CTRL_SDR50_TUNING_OVERRIDE		BIT(5)
#define SDHCI_CLOCK_CTRL_PADPIPE_CLKEN_OVERRIDE		BIT(3)
#define SDHCI_CLOCK_CTRL_SPI_MODE_CLKEN_OVERRIDE	BIT(2)
#define SDHCI_CLOCK_CTRL_SDMMC_CLK			BIT(0)

#define SDHCI_TEGRA_VENDOR_SYS_SW_CTRL		0x104
#define SDHCI_SYS_SW_CTRL_STROBE_EN		0x80000000

#define SDHCI_TEGRA_VENDOR_ERR_INTR_STATUS	0x108

#define SDHCI_TEGRA_VENDOR_CAP_OVERRIDES	0x10C

#define SDHCI_TEGRA_VENDOR_MISC_CTRL		0x120
#define SDHCI_MISC_CTRL_ENABLE_SDR104		0x8
#define SDHCI_MISC_CTRL_ENABLE_SDR50		0x10
#define SDHCI_MISC_CTRL_ENABLE_SDHCI_SPEC_300	0x20
#define SDHCI_MISC_CTRL_ENABLE_DDR50		0x200
#define SDHCI_MISC_CTRL_SDMMC_SPARE_0_MASK	0xFFFE

#define SDHCI_TEGRA_VENDOR_MISC_CTRL_1		0x124

#define SDHCI_TEGRA_VENDOR_MISC_CTRL_2		0x128
#define SDHCI_MISC_CTRL_2_CLK_OVR_ON		0x40000000

#define SDMMC_VNDR_IO_TRIM_CTRL_0		0x1AC
#define SDMMC_VNDR_IO_TRIM_CTRL_0_SEL_VREG_MASK	0x4

#define SDHCI_TEGRA_VENDOR_DLLCAL_CFG		0x1B0
#define SDHCI_DLLCAL_CFG_EN_CALIBRATE		0x80000000

#define SDHCI_DLLCAL_CFG_STATUS			0x1BC
#define SDHCI_DLLCAL_CFG_STATUS_DLL_ACTIVE	0x80000000

#define SDHCI_VNDR_TUN_CTRL0_0			0x1c0
#define SDHCI_VNDR_TUN_CTRL0_TUN_HW_TAP		0x20000
#define SDHCI_TUN_CTRL0_TUNING_ITER_MASK	0x7
#define SDHCI_TUN_CTRL0_TUNING_ITER_SHIFT	13
#define SDHCI_TUN_CTRL0_TUNING_WORD_SEL_MASK	0x7
#define SDHCI_VNDR_TUN_CTRL0_0_TUN_ITER_MASK	0x000E000
#define TUNING_WORD_SEL_MASK	0x7

#define SDHCI_TEGRA_VNDR_TUNING_STATUS0		0x1C8

#define SDHCI_TEGRA_VNDR_TUNING_STATUS1		0x1CC
#define SDHCI_TEGRA_VNDR_TUNING_STATUS1_TAP_MASK	0xFF
#define SDHCI_TEGRA_VNDR_TUNING_STATUS1_END_TAP_SHIFT	8

#define SDHCI_TEGRA_SDMEM_COMP_PADCTRL		0x1E0
#define SDHCI_TEGRA_PAD_E_INPUT_OR_E_PWRD_MASK	0x80000000
#define SDHCI_TEGRA_SDMEMCOMP_PADCTRL_VREF_SEL	0x0000000F
#define SDHCI_TEGRA_SDMEMCOMP_PADCTRL_DRVUP_OVR	0x07F00000

#define SDHCI_TEGRA_AUTO_CAL_CONFIG		0x1e4
#define SDHCI_AUTO_CAL_START			BIT(31)
#define SDHCI_AUTO_CAL_ENABLE			BIT(29)
#define SDHCI_AUTO_CAL_PUPD_OFFSETS		0x00007F7F

#define SDHCI_TEGRA_AUTO_CAL_STATUS	0x1EC
#define SDHCI_TEGRA_AUTO_CAL_ACTIVE	0x80000000

#define NVQUIRK_FORCE_SDHCI_SPEC_200	BIT(0)
#define NVQUIRK_ENABLE_BLOCK_GAP_DET	BIT(1)
#define NVQUIRK_ENABLE_SDHCI_SPEC_300	BIT(2)
#define NVQUIRK_ENABLE_SDR50		BIT(3)
#define NVQUIRK_ENABLE_SDR104		BIT(4)
#define NVQUIRK_ENABLE_DDR50		BIT(5)
#define NVQUIRK_HAS_PADCALIB		BIT(6)
#define NVQUIRK_HW_TAP_CONFIG		BIT(7)
#define NVQUIRK_DIS_CARD_CLK_CONFIG_TAP	BIT(8)
#define NVQUIRK_USE_PLATFORM_TUNING	BIT(9)
#define NVQUIRK_READ_REG_AFTER_WRITE	BIT(10)
#define NVQUIRK_SHADOW_XFER_MODE_WRITE	BIT(11)
/* Quirk to identify SLCG registers */
#define NVQUIRK_SDMMC_CLK_OVERRIDE	BIT(12)
#define NVQUIRK_UPDATE_PIN_CNTRL_REG	BIT(13)


#define MAX_CLK_PARENTS	5
#define MAX_DIVISOR_VALUE	128
#define MAX_TAP_VALUE	256

#define SET_REQ_TAP	0x0
#define SET_DDR_TAP	0x1
#define SET_DEFAULT_TAP	0x2
#define TUNING_WORD_BIT_SIZE 32
#define SDHOST_LOW_VOLT_MIN	1800000

/* Set min identification clock of 400 KHz */
#define SDMMC_TEGRA_FALLBACK_CLK_HZ	400000
#define SDHCI_RTPM_MSEC_TMOUT 10
#define SDMMC_EMC_MAX_FREQ	150000000
#define SDMMC_TIMEOUT_CLK_FREQ_HZ	12000000
#define SDMMC_TIMEOUT_CLK_FREQ_MHZ	12

static unsigned int sdmmc_emc_clinet_id[] = {
	TEGRA_BWMGR_CLIENT_SDMMC1,
	TEGRA_BWMGR_CLIENT_SDMMC2,
	TEGRA_BWMGR_CLIENT_SDMMC3,
	TEGRA_BWMGR_CLIENT_SDMMC4
};

/* uhs mask can be used to mask any of the UHS modes support */
#define MMC_UHS_MASK_SDR12	0x1
#define MMC_UHS_MASK_SDR25	0x2
#define MMC_UHS_MASK_SDR50	0x4
#define MMC_UHS_MASK_DDR50	0x8
#define MMC_UHS_MASK_SDR104	0x10
#define MMC_MASK_HS200		0x20
#define MMC_MASK_HS400		0x40
#define MMC_MASK_SD_HS		0x80

static char prod_device_states[MMC_TIMING_COUNTER][20] = {
	"prod_c_ds", /* MMC_TIMING_LEGACY */
	"prod_c_hs", /* MMC_TIMING_MMC_HS */
	"prod_c_hs", /* MMC_TIMING_SD_HS */
	"prod_c_sdr12", /* MMC_TIMING_UHS_SDR12 */
	"prod_c_sdr25", /* MMC_TIMING_UHS_SDR25 */
	"prod_c_sdr50", /* MMC_TIMING_UHS_SDR50 */
	"prod_c_sdr104", /* MMC_TIMING_UHS_SDR104 */
	"prod_c_ddr52", /* MMC_TIMING_UHS_DDR50 */
	"prod_c_ddr52", /* MMC_TIMING_MMC_DDR52 */
	"prod_c_hs200", /* MMC_TIMING_MMC_HS200 */
	"prod_c_hs400", /* MMC_TIMING_MMC_HS400 */
};

struct sdhci_tegra_soc_data {
	const struct sdhci_pltfm_data *pdata;
	u32 nvquirks;
	u32 cqequirks;
};

struct sdhci_tegra_clk_src_data {
	struct clk *parent_clk[MAX_CLK_PARENTS];
	const char *parent_clk_name[MAX_CLK_PARENTS];
	unsigned long parent_clk_rate[MAX_CLK_PARENTS];
	u8 parent_clk_src_cnt;
	int curr_parent_clk_idx;
};

struct sdhci_tegra {
	const struct sdhci_tegra_soc_data *soc_data;
	struct gpio_desc *power_gpio;
	struct reset_control *rst;
	bool ddr_signaling;
	bool pad_calib_required;
	struct clk *tmclk;
	struct sdhci_tegra_clk_src_data *clk_src_data;
	struct sdhci_host *host;
	struct delayed_work detect_delay;
	unsigned long curr_clk_rate;
	unsigned long max_clk_limit;
	unsigned long max_ddr_clk_limit;
	u32 boot_detect_delay;
	struct tegra_prod *prods;
	u8 tuned_tap_delay;
	bool rate_change_needs_clk;
	struct tegra_bwmgr_client *emc_clk;
	unsigned int tuning_status;
	#define TUNING_STATUS_DONE	1
	#define TUNING_STATUS_RETUNE	2
	bool disable_auto_cal;
	int timing;
	int current_voltage;
	unsigned int cd_irq;
	bool pwrdet_support;
	bool update_pinctrl_settings;
	bool wake_enable_failed;
	bool cd_wakeup_capable;
	int cd_gpio;
	bool enable_hwcq;
	struct pinctrl *pinctrl_sdmmc;
	struct pinctrl_state *e_33v_enable;
	struct pinctrl_state *e_33v_disable;
	struct pinctrl_state *schmitt_enable[2];
	struct pinctrl_state *schmitt_disable[2];
	struct pinctrl_state *drv_code_strength;
	struct pinctrl_state *default_drv_code_strength;
	bool en_periodic_cflush; /* Enable periodic cache flush for eMMC */
	u8 uhs_mask;
	unsigned int instance;
	int volt_switch_gpio;
	bool force_non_rem_rescan;
	bool static_parent_clk_mapping;
	int parent_clk_index[MMC_TIMING_COUNTER];
	bool disable_rtpm;
	bool disable_clk_gate;
	bool is_rail_enabled;
	bool vqmmc_always_on;
	bool vmmc_always_on;
	bool slcg_status;
	bool en_periodic_calib;
	unsigned int min_tap_delay;
	unsigned int max_tap_delay;
	ktime_t timestamp;
};

static int sdhci_tegra_parse_parent_list_from_dt(struct platform_device *pdev,
	struct sdhci_tegra *host);

/* Module params */
static unsigned int en_boot_part_access;

static void sdhci_tegra_debugfs_init(struct sdhci_host *host);
static void tegra_sdhci_vendor_trim_clear_sel_vreg(struct sdhci_host *host,
	bool enable);
static void tegra_sdhci_set_tap(struct sdhci_host *host, unsigned int tap,
	int type);
static int tegra_sdhci_suspend(struct sdhci_host *host);
static int tegra_sdhci_resume(struct sdhci_host *host);
static void tegra_sdhci_complete(struct sdhci_host *host);
static int tegra_sdhci_runtime_suspend(struct sdhci_host *host);
static int tegra_sdhci_runtime_resume(struct sdhci_host *host);
static void tegra_sdhci_post_resume(struct sdhci_host *host);
static void tegra_sdhci_set_clock(struct sdhci_host *host, unsigned int clock);
static void tegra_sdhci_update_sdmmc_pinctrl_register(struct sdhci_host *sdhci,
		bool set);

static bool tegra_sdhci_is_clk_enabled(struct sdhci_host *host, int reg)
{
	if (host->mmc->is_host_clk_enabled) {
		return true;
	} else {
		dev_err(mmc_dev(host->mmc),
			"Reg 0x%x being accessed without clock\n", reg);
		WARN_ON(1);
		return false;
	}
}

static u8 tegra_sdhci_readb(struct sdhci_host *host, int reg)
{
	if (!tegra_sdhci_is_clk_enabled(host, reg))
		return 0;

	return readb(host->ioaddr + reg);
}

static u16 tegra_sdhci_readw(struct sdhci_host *host, int reg)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;

	if (!tegra_sdhci_is_clk_enabled(host, reg))
		return 0;

	if (unlikely((soc_data->nvquirks & NVQUIRK_FORCE_SDHCI_SPEC_200) &&
			(reg == SDHCI_HOST_VERSION))) {
		/* Erratum: Version register is invalid in HW. */
		return SDHCI_SPEC_200;
	}

	return readw(host->ioaddr + reg);
}

static u32 tegra_sdhci_readl(struct sdhci_host *host, int reg)
{
	if (!tegra_sdhci_is_clk_enabled(host, reg))
		return 0;

	return readl(host->ioaddr + reg);
}
static void tegra_sdhci_writeb(struct sdhci_host *host, u8 val, int reg)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;

	if (!tegra_sdhci_is_clk_enabled(host, reg))
		return;

	writeb(val, host->ioaddr + reg);
	if (soc_data->nvquirks & NVQUIRK_READ_REG_AFTER_WRITE)
		readb(host->ioaddr + reg);
}

static void tegra_sdhci_writew(struct sdhci_host *host, u16 val, int reg)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;

	if (!tegra_sdhci_is_clk_enabled(host, reg))
		return;

	if (soc_data->nvquirks & NVQUIRK_SHADOW_XFER_MODE_WRITE) {
		switch (reg) {
		case SDHCI_TRANSFER_MODE:
			/*
			 * Postpone this write, we must do it together with a
			 * command write that is down below.
			 */
			pltfm_host->xfer_mode_shadow = val;
			return;
		case SDHCI_COMMAND:
			writel((val << 16) | pltfm_host->xfer_mode_shadow,
				host->ioaddr + SDHCI_TRANSFER_MODE);
			if (soc_data->nvquirks & NVQUIRK_READ_REG_AFTER_WRITE)
				readl(host->ioaddr + SDHCI_TRANSFER_MODE);
			return;
		}
	}

	writew(val, host->ioaddr + reg);
	if (soc_data->nvquirks & NVQUIRK_READ_REG_AFTER_WRITE)
		readw(host->ioaddr + reg);
}

static void tegra_sdhci_writel(struct sdhci_host *host, u32 val, int reg)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;

	if (!tegra_sdhci_is_clk_enabled(host, reg))
		return;

	/* Seems like we're getting spurious timeout and crc errors, so
	 * disable signalling of them. In case of real errors software
	 * timers should take care of eventually detecting them.
	 */
	if (unlikely(reg == SDHCI_SIGNAL_ENABLE))
		val &= ~(SDHCI_INT_TIMEOUT|SDHCI_INT_CRC);

	writel(val, host->ioaddr + reg);
	if (soc_data->nvquirks & NVQUIRK_READ_REG_AFTER_WRITE)
		readl(host->ioaddr + reg);

	if (unlikely((soc_data->nvquirks & NVQUIRK_ENABLE_BLOCK_GAP_DET) &&
			(reg == SDHCI_INT_ENABLE))) {
		/* Erratum: Must enable block gap interrupt detection */
		u8 gap_ctrl = readb(host->ioaddr + SDHCI_BLOCK_GAP_CONTROL);
		if (val & SDHCI_INT_CARD_INT)
			gap_ctrl |= 0x8;
		else
			gap_ctrl &= ~0x8;
		writeb(gap_ctrl, host->ioaddr + SDHCI_BLOCK_GAP_CONTROL);
		if (soc_data->nvquirks & NVQUIRK_READ_REG_AFTER_WRITE)
			readb(host->ioaddr + SDHCI_BLOCK_GAP_CONTROL);
	}
}

static void tegra_sdhci_dump_vendor_regs(struct sdhci_host *host)
{
	int reg, tuning_status;
	u32 tap_delay;
	u32 trim_delay;
	u8 i;

	pr_debug("======= %s: Tuning windows =======\n",
				mmc_hostname(host->mmc));
	reg = sdhci_readl(host, SDHCI_VNDR_TUN_CTRL0_0);
	for (i = 0; i <= TUNING_WORD_SEL_MASK; i++) {
		reg &= ~SDHCI_TUN_CTRL0_TUNING_WORD_SEL_MASK;
		reg |= i;
		sdhci_writel(host, reg, SDHCI_VNDR_TUN_CTRL0_0);
		tuning_status = sdhci_readl(host, SDHCI_TEGRA_VNDR_TUNING_STATUS0);
		pr_debug("%s: tuning window[%d]: %#x\n",
			mmc_hostname(host->mmc), i, tuning_status);
	}
	reg = sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
	tap_delay = reg >> SDHCI_CLOCK_CTRL_TAP_SHIFT;
	tap_delay &= SDHCI_CLOCK_CTRL_TAP_MASK;
	trim_delay = reg >> SDHCI_CLOCK_CTRL_TRIM_SHIFT;
	trim_delay &= SDHCI_CLOCK_CTRL_TRIM_MASK;
	pr_debug("sdhci: Tap value: %u | Trim value: %u\n", tap_delay,
			trim_delay);
	pr_debug("==================================\n");

	pr_debug("Vendor clock ctrl: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL));
	pr_debug("Vendor SysSW ctrl: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_SYS_SW_CTRL));
	pr_debug("Vendor Err interrupt status : %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_ERR_INTR_STATUS));
	pr_debug("Vendor Cap overrides: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_CAP_OVERRIDES));
	pr_debug("Vendor Misc ctrl: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_MISC_CTRL));
	pr_debug("Vendor Misc ctrl_1: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_MISC_CTRL_1));
	pr_debug("Vendor Misc ctrl_2: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VENDOR_MISC_CTRL_2));
	pr_debug("Vendor IO trim ctrl: %#x\n",
		sdhci_readl(host, SDMMC_VNDR_IO_TRIM_CTRL_0));
	pr_debug("Vendor Tuning ctrl: %#x\n",
		sdhci_readl(host, SDHCI_VNDR_TUN_CTRL0_0));
	pr_debug("SDMEM comp padctrl: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_SDMEM_COMP_PADCTRL));
	pr_debug("Autocal config: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_AUTO_CAL_CONFIG));
	pr_debug("Autocal status: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_AUTO_CAL_STATUS));
	pr_debug("Tuning Status1: %#x\n",
		sdhci_readl(host, SDHCI_TEGRA_VNDR_TUNING_STATUS1));
}

static void tegra_sdhci_card_event(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int err = 0;

	tegra_host->tuning_status = TUNING_STATUS_RETUNE;
	host->is_calib_done = false;
	if (!host->mmc->rem_card_present) {
		if (!IS_ERR_OR_NULL(host->mmc->supply.vmmc) &&
			regulator_is_enabled(host->mmc->supply.vmmc) &&
			!tegra_host->vmmc_always_on) {
				regulator_disable(host->mmc->supply.vmmc);
				pr_info("%s: Disabling vmmc regulator\n", mmc_hostname(host->mmc));
		}
	} else {
		if (!IS_ERR_OR_NULL(host->mmc->supply.vmmc) &&
			!regulator_is_enabled(host->mmc->supply.vmmc) &&
			!tegra_host->vmmc_always_on) {
				err = regulator_enable(host->mmc->supply.vmmc);
				pr_info("%s: Enabling vmmc regulator\n", mmc_hostname(host->mmc));
				if (err) {
					pr_warn("%s: Failed to enable vmmc regulator: %d\n",
						mmc_hostname(host->mmc), err);
					host->mmc->supply.vmmc = ERR_PTR(-EINVAL);
				}
		}
	}
}

static unsigned int tegra_sdhci_get_ro(struct sdhci_host *host)
{
	return mmc_gpio_get_ro(host->mmc);
}

static void tegra_sdhci_post_init(struct sdhci_host *host)
{
	struct mmc_host *mmc = host->mmc;
	int reg, timeout = 5;

	if ((mmc->ios.timing == MMC_TIMING_MMC_DDR52) ||
		(mmc->ios.timing == MMC_TIMING_UHS_DDR50)) {
		/*
		 * Tegra SDMMC controllers support DDR mode with only clock
		 * divisor 1. Set the clock frequency here again to ensure
		 * host and device clocks are correctly configured.
		 */
		tegra_sdhci_set_clock(host, host->max_clk);
	} else if (mmc->ios.timing == MMC_TIMING_MMC_HS400) {
		reg = sdhci_readl(host, SDHCI_TEGRA_VENDOR_DLLCAL_CFG);
		reg |= SDHCI_DLLCAL_CFG_EN_CALIBRATE;
		sdhci_writel(host, reg, SDHCI_TEGRA_VENDOR_DLLCAL_CFG);

		mdelay(1);

		/* Wait until DLL calibration is done */
		do {
			if (!(sdhci_readl(host, SDHCI_DLLCAL_CFG_STATUS) &
				SDHCI_DLLCAL_CFG_STATUS_DLL_ACTIVE))
				break;
			mdelay(1);
			timeout--;
		} while (timeout);

		if (!timeout)
			dev_err(mmc_dev(host->mmc),
				"DLL calibration timed out\n");
	}
}

static void tegra_sdhci_hs400_enhanced_strobe(struct sdhci_host *host, bool enable)
{
	int reg;

	reg = sdhci_readl(host, SDHCI_TEGRA_VENDOR_SYS_SW_CTRL);
	if (enable)
		reg |= SDHCI_SYS_SW_CTRL_STROBE_EN;
	else
		reg &= ~SDHCI_SYS_SW_CTRL_STROBE_EN;
	sdhci_writel(host, reg, SDHCI_TEGRA_VENDOR_SYS_SW_CTRL);
	tegra_sdhci_set_tap(host, 0, SET_DEFAULT_TAP);

}

static int tegra_sdhci_get_max_tuning_loop_counter(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int err = 0;

	err = tegra_prod_set_by_name_partially(&host->ioaddr,
			prod_device_states[host->mmc->ios.timing],
			tegra_host->prods, 0, SDHCI_VNDR_TUN_CTRL0_0,
			SDHCI_VNDR_TUN_CTRL0_0_TUN_ITER_MASK);
	if (err)
		dev_err(mmc_dev(host->mmc),
			"%s: error %d in tuning iteration update\n",
				__func__, err);

	return 257;
}

static bool tegra_sdhci_skip_retuning(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);

	if (tegra_host->tuning_status == TUNING_STATUS_DONE) {
		dev_info(mmc_dev(host->mmc),
			"Tuning done, restoring the best tap value : %u\n",
				tegra_host->tuned_tap_delay);
		tegra_sdhci_set_tap(host, tegra_host->tuned_tap_delay,
			SET_REQ_TAP);
		return true;
	}

	return false;
}

static void tegra_sdhci_apply_tuning_correction(struct sdhci_host *host,
		u16 tun_iter, u8 upthres, u8 lowthres, u8 fixed_tap)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	u32 reg, mask = 0x00000001;
	u8 i, j, edge1;
	unsigned int tun_word;
	bool start_fail_def = false;
	bool start_pass_def = false;
	bool end_fail_def = false;
	bool end_pass_def = false;
	bool first_pass_def = false;
	bool first_fail_def = false;
	u8 start_fail = 0;
	u8 end_fail = 0;
	u8 start_pass = 0;
	u8 end_pass = 0;
	u8 first_fail = 0;
	u8 first_pass = 0;

	/*Select the first valid window with starting and ending edges defined*/
	for (i = 0; i <= TUNING_WORD_SEL_MASK; i++) {
		if (i == (tun_iter/TUNING_WORD_BIT_SIZE))
			break;
		j = 0;
		reg = sdhci_readl(host, SDHCI_VNDR_TUN_CTRL0_0);
		reg &= ~TUNING_WORD_SEL_MASK;
		reg |= i;
		sdhci_writel(host, reg, SDHCI_VNDR_TUN_CTRL0_0);
		tun_word = sdhci_readl(host, SDHCI_TEGRA_VNDR_TUNING_STATUS0);
		while (j <= (TUNING_WORD_BIT_SIZE - 1)) {
			if (!(tun_word & (mask << j)) && !start_fail_def) {
				start_fail = i*TUNING_WORD_BIT_SIZE + j;
				start_fail_def = true;
				if (!first_fail_def) {
					first_fail = start_fail;
					first_fail_def = true;
				}
			} else if ((tun_word & (mask << j)) && !start_pass_def
					&& start_fail_def) {
				start_pass = i*TUNING_WORD_BIT_SIZE + j;
				start_pass_def = true;
				if (!first_pass_def) {
					first_pass = start_pass;
					first_pass_def = true;
				}
			} else if (!(tun_word & (mask << j)) && start_fail_def
					&& start_pass_def && !end_pass_def) {
				end_pass = i*TUNING_WORD_BIT_SIZE + j - 1;
				end_pass_def = true;
			} else if ((tun_word & (mask << j)) && start_pass_def
				&& start_fail_def && end_pass_def) {
				end_fail  = i*TUNING_WORD_BIT_SIZE + j - 1;
				end_fail_def = true;
				if ((end_pass - start_pass) >= upthres) {
					start_fail = end_pass + 1;
					start_pass = end_fail + 1;
					end_pass_def = false;
					end_fail_def = false;
					j++;
					continue;
				} else if ((end_pass - start_pass) < lowthres) {
					start_pass = end_fail + 1;
					end_pass_def = false;
					end_fail_def = false;
					j++;
					continue;
				}
				break;
			}
			j++;
			if ((i*TUNING_WORD_BIT_SIZE + j) == tun_iter - 1)
				break;
		}
		if (start_pass_def && end_pass_def && start_fail_def
				&& end_fail_def) {
			tegra_host->tuned_tap_delay = start_pass +
				(end_pass - start_pass)/2;
			return;
		}
	}
	/*
	 * If no edge found, retain tap set by HW tuning
	 */
	if (!first_fail_def) {
		WARN_ON("No edge detected\n");
		reg = sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
		tegra_host->tuned_tap_delay =
			((reg >> SDHCI_CLOCK_CTRL_TAP_SHIFT) &
				SDHCI_CLOCK_CTRL_TAP_MASK);
	}
	/*
	 * Set tap based on fixed value relative to first edge
	 * if no valid windows found
	 */
	if (!end_fail_def && first_fail_def && first_pass_def) {
		edge1 = first_fail + (first_pass - first_fail)/2;
		if ((edge1 - 1) > fixed_tap)
			tegra_host->tuned_tap_delay = edge1 - fixed_tap;
		else
			tegra_host->tuned_tap_delay = edge1 + fixed_tap;
	}

}

static void tegra_sdhci_post_tuning(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	u32 reg;
	u8 start_tap, end_tap, window_width, upperthreshold, lowerthreshold;
	u8 fixed_tap;
	u16 num_tun_iter;
	u32 clk_rate_mhz, period, bestcase, worstcase;
	u32 avg_tap_delay, min_tap_delay, max_tap_delay;

	min_tap_delay = tegra_host->min_tap_delay;
	max_tap_delay = tegra_host->max_tap_delay;
	if (!min_tap_delay || !max_tap_delay) {
		pr_info("%s: Tuning correction cannot be applied",
				mmc_hostname(host->mmc));
		goto retain_hw_tun_tap;
	}

	clk_rate_mhz = tegra_host->curr_clk_rate/1000000;
	period = 1000000/clk_rate_mhz;
	bestcase = period/min_tap_delay;
	worstcase = period/max_tap_delay;
	avg_tap_delay = (period*2)/(min_tap_delay + max_tap_delay);
	upperthreshold = ((2*worstcase) + bestcase)/2;
	lowerthreshold = worstcase/4;
	fixed_tap = avg_tap_delay/2;

	reg = sdhci_readl(host, SDHCI_TEGRA_VNDR_TUNING_STATUS1);
	start_tap = reg & SDHCI_TEGRA_VNDR_TUNING_STATUS1_TAP_MASK;
	end_tap = (reg >> SDHCI_TEGRA_VNDR_TUNING_STATUS1_END_TAP_SHIFT) &
			SDHCI_TEGRA_VNDR_TUNING_STATUS1_TAP_MASK;
	window_width = end_tap - start_tap;

	num_tun_iter = (sdhci_readl(host, SDHCI_VNDR_TUN_CTRL0_0) &
				SDHCI_VNDR_TUN_CTRL0_0_TUN_ITER_MASK) >>
				SDHCI_TUN_CTRL0_TUNING_ITER_SHIFT;

	switch (num_tun_iter) {
	case 0:
		num_tun_iter = 40;
		break;
	case 1:
		num_tun_iter = 64;
		break;
	case 2:
		num_tun_iter = 128;
		break;
	case 3:
		num_tun_iter = 196;
		break;
	case 4:
		num_tun_iter = 256;
		break;
	default:
		WARN_ON("Invalid value of number of tuning iterations");
	}
	/*
	 * Apply tuning correction if partial window is selected by HW tuning
	 * or window merge is detected
	 */
	if ((start_tap == 0) || (end_tap == 254) ||
	   ((end_tap == 126) && (num_tun_iter == 128)) ||
	   (end_tap == (num_tun_iter - 1)) ||
	   (window_width >= upperthreshold)) {
		tegra_sdhci_dump_vendor_regs(host);
		pr_info("%s: Applying tuning correction\n",
				mmc_hostname(host->mmc));
		tegra_sdhci_apply_tuning_correction(host, num_tun_iter,
				upperthreshold, lowerthreshold, fixed_tap);
		pr_info("%s: Tap value after applying correction %u\n",
			mmc_hostname(host->mmc), tegra_host->tuned_tap_delay);
	} else {
retain_hw_tun_tap:
		reg = sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
		tegra_host->tuned_tap_delay =
			((reg >> SDHCI_CLOCK_CTRL_TAP_SHIFT) &
				SDHCI_CLOCK_CTRL_TAP_MASK);
	}
	tegra_sdhci_set_tap(host, tegra_host->tuned_tap_delay, SET_REQ_TAP);
	tegra_host->tuning_status = TUNING_STATUS_DONE;

	pr_info("%s: hw tuning done ...\n", mmc_hostname(host->mmc));
	tegra_sdhci_dump_vendor_regs(host);
}

static void tegra_sdhci_vendor_trim_clear_sel_vreg(struct sdhci_host *host,
	bool enable)
{
	unsigned int misc_ctrl;

	misc_ctrl = sdhci_readl(host, SDMMC_VNDR_IO_TRIM_CTRL_0);
	if (enable) {
		misc_ctrl &= ~(SDMMC_VNDR_IO_TRIM_CTRL_0_SEL_VREG_MASK);
		sdhci_writel(host, misc_ctrl, SDMMC_VNDR_IO_TRIM_CTRL_0);
		udelay(3);
		sdhci_reset(host, SDHCI_RESET_CMD | SDHCI_RESET_DATA);
	} else {
		misc_ctrl |= (SDMMC_VNDR_IO_TRIM_CTRL_0_SEL_VREG_MASK);
		sdhci_writel(host, misc_ctrl, SDMMC_VNDR_IO_TRIM_CTRL_0);
		udelay(1);
	}
}

static void tegra_sdhci_mask_host_caps(struct sdhci_host *host, u8 uhs_mask)
{
	/* Mask any bus speed modes if set in platform data */
	if (uhs_mask & MMC_UHS_MASK_SDR12)
		host->mmc->caps &= ~MMC_CAP_UHS_SDR12;

	if (uhs_mask & MMC_UHS_MASK_SDR25)
		host->mmc->caps &= ~MMC_CAP_UHS_SDR25;

	if (uhs_mask & MMC_UHS_MASK_SDR50)
		host->mmc->caps &= ~MMC_CAP_UHS_SDR50;

	if (uhs_mask & MMC_UHS_MASK_SDR104)
		host->mmc->caps &= ~MMC_CAP_UHS_SDR104;

	if (uhs_mask & MMC_UHS_MASK_DDR50) {
		host->mmc->caps &= ~MMC_CAP_UHS_DDR50;
		host->mmc->caps &= ~MMC_CAP_1_8V_DDR;
	}

	if (uhs_mask & MMC_MASK_HS200) {
		host->mmc->caps2 &= ~MMC_CAP2_HS200;
		host->mmc->caps2 &= ~MMC_CAP2_HS400;
		host->mmc->caps2 &= ~MMC_CAP2_HS400_ES;
	}

	if (uhs_mask & MMC_MASK_HS400) {
		host->mmc->caps2 &= ~MMC_CAP2_HS400;
		host->mmc->caps2 &= ~MMC_CAP2_HS400_ES;
	}
	if (uhs_mask & MMC_MASK_SD_HS)
		host->mmc->caps &= ~MMC_CAP_SD_HIGHSPEED;
}

static void tegra_sdhci_reset(struct sdhci_host *host, u8 mask)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;
	u32 misc_ctrl, clk_ctrl, misc_ctrl_2;
	int err;
	bool clear_ddr_signalling = true;

	sdhci_reset(host, mask);

	if (!(mask & SDHCI_RESET_ALL))
		return;

	err = tegra_prod_set_by_name(&host->ioaddr, "prod",
		tegra_host->prods);
	if (err)
		dev_err(mmc_dev(host->mmc),
			"Failed to set prod-reset settings %d\n", err);

	/* Set the tap delay value */
	if (!tegra_sdhci_skip_retuning(host))
		tegra_sdhci_set_tap(host, 0, SET_DEFAULT_TAP);

	misc_ctrl = sdhci_readl(host, SDHCI_TEGRA_VENDOR_MISC_CTRL);
	clk_ctrl = sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
	misc_ctrl &= ~(SDHCI_MISC_CTRL_ENABLE_SDHCI_SPEC_300 |
		       SDHCI_MISC_CTRL_ENABLE_SDR50 |
		       SDHCI_MISC_CTRL_ENABLE_DDR50 |
		       SDHCI_MISC_CTRL_ENABLE_SDR104);

	/*
	 * If the board does not define a regulator for the SDHCI
	 * IO voltage, then don't advertise support for UHS modes
	 * even if the device supports it because the IO voltage
	 * cannot be configured.
	 */
	if (tegra_host->vqmmc_always_on || !IS_ERR(host->mmc->supply.vqmmc)) {
		/* Erratum: Enable SDHCI spec v3.00 support */
		if (soc_data->nvquirks & NVQUIRK_ENABLE_SDHCI_SPEC_300)
			misc_ctrl |= SDHCI_MISC_CTRL_ENABLE_SDHCI_SPEC_300;
		/* Advertise UHS modes as supported by host */
		if (soc_data->nvquirks & NVQUIRK_ENABLE_SDR50)
			misc_ctrl |= SDHCI_MISC_CTRL_ENABLE_SDR50;
		if ((soc_data->nvquirks & NVQUIRK_ENABLE_DDR50) &&
			!(tegra_host->uhs_mask & MMC_UHS_MASK_DDR50))
			misc_ctrl |= SDHCI_MISC_CTRL_ENABLE_DDR50;
		if (soc_data->nvquirks & NVQUIRK_ENABLE_SDR104)
			misc_ctrl |= SDHCI_MISC_CTRL_ENABLE_SDR104;
		if (soc_data->nvquirks & NVQUIRK_ENABLE_SDR50)
			clk_ctrl |= SDHCI_CLOCK_CTRL_SDR50_TUNING_OVERRIDE;
	}
	if (soc_data->nvquirks & NVQUIRK_SDMMC_CLK_OVERRIDE) {
		misc_ctrl_2 = sdhci_readl(host, SDHCI_TEGRA_VENDOR_MISC_CTRL_2);
		tegra_host->slcg_status = !(misc_ctrl_2 &
						SDHCI_MISC_CTRL_2_CLK_OVR_ON);
	} else
		tegra_host->slcg_status = !(clk_ctrl &
					SDHCI_CLOCK_CTRL_LEGACY_CLKEN_OVERRIDE);

	sdhci_writel(host, misc_ctrl, SDHCI_TEGRA_VENDOR_MISC_CTRL);
	sdhci_writel(host, clk_ctrl, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);

	/* SEL_VREG should be 0 for all modes*/
	tegra_sdhci_vendor_trim_clear_sel_vreg(host, true);

	if (soc_data->nvquirks & NVQUIRK_HAS_PADCALIB)
		tegra_host->pad_calib_required = true;

	/* ddr signalling post resume */
	if ((host->mmc->pm_flags & MMC_PM_KEEP_POWER) &&
		((host->mmc->ios.timing == MMC_TIMING_MMC_DDR52) ||
		(host->mmc->ios.timing == MMC_TIMING_UHS_DDR50)))
		clear_ddr_signalling = false;

	if (clear_ddr_signalling)
		tegra_host->ddr_signaling = false;
	tegra_sdhci_mask_host_caps(host, tegra_host->uhs_mask);
}

static void tegra_sdhci_set_bus_width(struct sdhci_host *host, int bus_width)
{
	u32 ctrl;

	ctrl = sdhci_readb(host, SDHCI_HOST_CONTROL);
	if ((host->mmc->caps & MMC_CAP_8_BIT_DATA) &&
	    (bus_width == MMC_BUS_WIDTH_8)) {
		ctrl &= ~SDHCI_CTRL_4BITBUS;
		ctrl |= SDHCI_CTRL_8BITBUS;
	} else {
		ctrl &= ~SDHCI_CTRL_8BITBUS;
		if (bus_width == MMC_BUS_WIDTH_4)
			ctrl |= SDHCI_CTRL_4BITBUS;
		else
			ctrl &= ~SDHCI_CTRL_4BITBUS;
	}
	sdhci_writeb(host, ctrl, SDHCI_HOST_CONTROL);
}

static void tegra_sdhci_configure_e_input(struct sdhci_host *host, bool enable)
{
	u32 reg;

	reg = sdhci_readl(host, SDHCI_TEGRA_SDMEM_COMP_PADCTRL);
	if (enable)
		reg |= SDHCI_TEGRA_PAD_E_INPUT_OR_E_PWRD_MASK;
	else
		reg &= ~SDHCI_TEGRA_PAD_E_INPUT_OR_E_PWRD_MASK;
	sdhci_writel(host, reg, SDHCI_TEGRA_SDMEM_COMP_PADCTRL);
	udelay(1);
}

static void tegra_sdhci_pad_autocalib(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	u32 val, signal_voltage;
	u16 clk;
	int card_clk_enabled, ret;
	const char *comp_vref;
	unsigned int timeout = 10;
	unsigned int timing = host->mmc->ios.timing;

	if (tegra_host->disable_auto_cal)
		return;

	signal_voltage = host->mmc->ios.signal_voltage;
	comp_vref = (signal_voltage == MMC_SIGNAL_VOLTAGE_330) ?
		"comp-vref-3v3" : "comp-vref-1v8";

	clk = sdhci_readw(host, SDHCI_CLOCK_CONTROL);
	card_clk_enabled = clk & SDHCI_CLOCK_CARD_EN;

	if (card_clk_enabled) {
		clk &= ~SDHCI_CLOCK_CARD_EN;
		sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);
	}

	tegra_sdhci_configure_e_input(host, true);
	udelay(1);

	ret = tegra_prod_set_by_name_partially(&host->ioaddr,
			prod_device_states[timing],
			tegra_host->prods, 0, SDHCI_TEGRA_SDMEM_COMP_PADCTRL,
			SDHCI_TEGRA_SDMEMCOMP_PADCTRL_VREF_SEL);
	if (ret < 0)
		dev_err(mmc_dev(host->mmc),
			"%s: error %d in comp vref settings\n",
			__func__, ret);

	/* Enable Auto Calibration*/
	ret = tegra_prod_set_by_name_partially(&host->ioaddr,
			prod_device_states[timing],
			tegra_host->prods, 0, SDHCI_TEGRA_AUTO_CAL_CONFIG,
			SDHCI_AUTO_CAL_ENABLE);
	if (ret < 0)
		dev_err(mmc_dev(host->mmc),
			"%s: error %d in autocal-en settings\n",
			__func__, ret);

	val = sdhci_readl(host, SDHCI_TEGRA_AUTO_CAL_CONFIG);
	val |= SDHCI_AUTO_CAL_START;
	sdhci_writel(host,val, SDHCI_TEGRA_AUTO_CAL_CONFIG);

	/* Program calibration offsets */
	ret = tegra_prod_set_by_name_partially(&host->ioaddr,
			prod_device_states[timing],
			tegra_host->prods, 0, SDHCI_TEGRA_AUTO_CAL_CONFIG,
			SDHCI_AUTO_CAL_PUPD_OFFSETS);
	if (ret < 0)
		dev_err(mmc_dev(host->mmc),
			"error %d in autocal-pu-pd-offset settings\n", ret);

	/* Wait 2us after auto calibration is enabled */
	udelay(2);

	/* Wait until calibration is done */
	do {
		if (!(sdhci_readl(host, SDHCI_TEGRA_AUTO_CAL_STATUS) &
				SDHCI_TEGRA_AUTO_CAL_ACTIVE))
			break;
		mdelay(1);
		timeout--;
	} while (timeout);

	if (!timeout)
		dev_err(mmc_dev(host->mmc), "Auto calibration timed out\n");

	tegra_sdhci_configure_e_input(host, false);

	if (card_clk_enabled) {
		clk |= SDHCI_CLOCK_CARD_EN;
		sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);
	}

	if (tegra_host->en_periodic_calib) {
		tegra_host->timestamp = ktime_get();
		host->timestamp = ktime_get();
		host->is_calib_done = true;
	}
}

static unsigned long get_nearest_clock_freq(unsigned long parent_rate,
	unsigned long desired_rate)
{
	unsigned long result, result_frac_div;
	int div, rem;

	if (parent_rate <= desired_rate)
		return parent_rate;

	div = parent_rate / desired_rate;
	div = (div > MAX_DIVISOR_VALUE) ? MAX_DIVISOR_VALUE : div;
	rem = parent_rate % desired_rate;
	result = parent_rate / div;
	if (div == MAX_DIVISOR_VALUE || !rem)
		return (parent_rate / div);
	else if (result > desired_rate) {
		result_frac_div = (parent_rate << 1) / ((div << 1) + 1);
		if (result_frac_div > desired_rate)
			return (parent_rate / (div + 1));
		else
			return result_frac_div;
	}

	return result;
}

static void tegra_sdhci_set_clk_parent(struct sdhci_host *host,
	unsigned long desired_rate)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	struct sdhci_tegra_clk_src_data *clk_src_data;
	unsigned long parent_clk_rate, rate, nearest_freq_rate = 0;
	int rc;
	int mode = 0;
	u8 i, sel_parent_idx = 0;

	if (tegra_platform_is_fpga())
		return;

	clk_src_data = tegra_host->clk_src_data;
	if (!clk_src_data) {
		dev_err(mmc_dev(host->mmc), "clk src data NULL");
		return;
	}

	if (tegra_host->static_parent_clk_mapping) {
		mode = host->mmc->ios.timing;
		if (tegra_host->parent_clk_index[mode] != -EINVAL) {
			sel_parent_idx = tegra_host->parent_clk_index[mode];
			goto set_parent;
		}
	}

	for (i = 0; i < clk_src_data->parent_clk_src_cnt; i++) {
		parent_clk_rate = clk_src_data->parent_clk_rate[i];
		rate = get_nearest_clock_freq(parent_clk_rate, desired_rate);
		if (rate > nearest_freq_rate) {
			nearest_freq_rate = rate;
			sel_parent_idx = i;
		}
	}

set_parent:
	dev_dbg(mmc_dev(host->mmc), "chosen clk parent %s, parent rate %lu\n",
		clk_src_data->parent_clk_name[sel_parent_idx],
		clk_src_data->parent_clk_rate[sel_parent_idx]);

	/* Do nothing if the desired parent is already set */
	if (clk_src_data->curr_parent_clk_idx == sel_parent_idx)
		return;
	else {
		rc = clk_set_parent(pltfm_host->clk,
			clk_src_data->parent_clk[sel_parent_idx]);
		if (rc)
			dev_err(mmc_dev(host->mmc),
				"Failed to set parent pll %d\n", rc);
		else
			clk_src_data->curr_parent_clk_idx = sel_parent_idx;
	}
}

static void tegra_sdhci_set_clk_rate(struct sdhci_host *host,
	unsigned long host_clk)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int rc;

	if (host_clk == tegra_host->curr_clk_rate)
		return;

	/* Set the required clock parent based on the desired rate */
	tegra_sdhci_set_clk_parent(host, host_clk);

	/*
	 * Proceed irrespective of parent selection as the interface could
	 * work at a lower frequency too. Parent clk selection would report
	 * errors in the logs.
	 */
	rc = clk_set_rate(pltfm_host->clk, host_clk);
	if (rc)
		dev_err(mmc_dev(host->mmc),
			"Failed to set %lu clk rate\n", host_clk);
	else {
		/*
		 * Clock frequency actually set would be slightly different from
		 * desired rate. Next request would again come for the desired
		 * rate. Hence, store the desired rate in curr_clk_rate.
		 */
		tegra_host->curr_clk_rate = host_clk;
	}
}

static unsigned long tegra_sdhci_apply_clk_limits(struct sdhci_host *host,
	unsigned int clock)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	unsigned long host_clk;

	if (tegra_host->ddr_signaling)
		host_clk = (tegra_host->max_ddr_clk_limit) ?
			tegra_host->max_ddr_clk_limit * 2 : clock * 2;
	else
		host_clk = (clock > tegra_host->max_clk_limit) ?
			tegra_host->max_clk_limit : clock;

	dev_dbg(mmc_dev(host->mmc), "Setting clk limit %lu\n", host_clk);
	return host_clk;
}

static void tegra_sdhci_set_clock(struct sdhci_host *host, unsigned int clock)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	unsigned long host_clk;
	int rc;
	u8 vndr_ctrl;
	ktime_t cur_time;
	s64 period_time;

	host_clk = tegra_sdhci_apply_clk_limits(host, clock);

	if (clock) {
		dev_dbg(mmc_dev(host->mmc), "Enabling clk %u, clk enabled %d\n",
			clock, host->mmc->is_host_clk_enabled);

		if (host->mmc->skip_host_clkgate) {
			sdhci_set_card_clock(host, true);
			return;
		}

		if (!tegra_host->rate_change_needs_clk)
			tegra_sdhci_set_clk_rate(host, host_clk);
		/* Enable SDMMC host CAR clock */
		if (!host->mmc->is_host_clk_enabled) {
			rc = clk_prepare_enable(pltfm_host->clk);
			if (rc) {
				dev_err(mmc_dev(host->mmc),
					"clk enable failed %d\n", rc);
				return;
			}
			rc = clk_prepare_enable(tegra_host->tmclk);
			if (rc) {
				dev_err(mmc_dev(host->mmc),
					"timeout clk enable failed %d\n", rc);
				return;
			}
			host->mmc->is_host_clk_enabled = true;
			vndr_ctrl = sdhci_readb(host,
				SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
			vndr_ctrl |= SDHCI_CLOCK_CTRL_SDMMC_CLK;
			sdhci_writeb(host, vndr_ctrl,
				SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
			/* power up / active state */
			tegra_sdhci_vendor_trim_clear_sel_vreg(host, true);
			if (tegra_host->emc_clk) {
				rc = tegra_bwmgr_set_emc(tegra_host->emc_clk,
						SDMMC_EMC_MAX_FREQ,
						TEGRA_BWMGR_SET_EMC_SHARED_BW);
				if (rc)
					dev_err(mmc_dev(host->mmc),
					"enabling eMC clock failed, err: %d\n",
					rc);
			}
		}

		/* Set the desired clk freq rate */
		if (tegra_host->rate_change_needs_clk)
			tegra_sdhci_set_clk_rate(host, host_clk);
		host->max_clk = clk_get_rate(pltfm_host->clk);
		dev_dbg(mmc_dev(host->mmc), "req clk %lu, set clk %d\n",
			host_clk, host->max_clk);
		/* Run auto calibration if required */
		if (tegra_host->pad_calib_required) {
			tegra_sdhci_pad_autocalib(host);
			tegra_host->pad_calib_required = false;
		}

		if (tegra_host->en_periodic_calib && host->is_calib_done) {
			cur_time = ktime_get();
			period_time = ktime_to_ms(ktime_sub(cur_time,
						tegra_host->timestamp));
			if (period_time >= SDHCI_PERIODIC_CALIB_TIMEOUT)
				tegra_sdhci_pad_autocalib(host);
		}

		/* Enable SDMMC internal and card clocks */
		sdhci_set_clock(host, clock);
	} else {
		dev_dbg(mmc_dev(host->mmc), "Disabling clk %u, clk enabled %d\n",
			clock, host->mmc->is_host_clk_enabled);

		if (host->mmc->skip_host_clkgate) {
			sdhci_set_card_clock(host, false);
			return;
		}
		/* Disable the card and internal clocks first */
		sdhci_set_clock(host, clock);

		/* Disable SDMMC host CAR clock */
		if (host->mmc->is_host_clk_enabled) {
			/* power down / idle state */
			tegra_sdhci_vendor_trim_clear_sel_vreg(host, false);

			vndr_ctrl = sdhci_readb(host,
				SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
			vndr_ctrl &= ~SDHCI_CLOCK_CTRL_SDMMC_CLK;
			sdhci_writeb(host, vndr_ctrl,
				SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
			host->mmc->is_host_clk_enabled = false;
			clk_disable_unprepare(tegra_host->tmclk);
			clk_disable_unprepare(pltfm_host->clk);
			if (tegra_host->emc_clk) {
				rc = tegra_bwmgr_set_emc(tegra_host->emc_clk, 0,
						TEGRA_BWMGR_SET_EMC_SHARED_BW);
				if (rc)
					dev_err(mmc_dev(host->mmc),
					"disabling eMC clock failed, err: %d\n",
					rc);
			}
		}

	}
}

static void tegra_sdhci_set_uhs_signaling(struct sdhci_host *host,
					  unsigned timing)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int ret;
	u8 tap_delay_type;
	bool tuning_mode = false;
	bool set_num_tun_iter = false;
	bool set_trim_delay = false;
	bool set_padpipe_clk_override = false;
	bool set_sdmmc_spare_0 = false;

	tegra_host->ddr_signaling = false;

	sdhci_set_uhs_signaling(host, timing);

	switch (timing) {
	case MMC_TIMING_UHS_SDR50:
	case MMC_TIMING_UHS_SDR104:
		tuning_mode = true;
		break;
	case MMC_TIMING_MMC_DDR52:
		set_sdmmc_spare_0 = true;
	case MMC_TIMING_UHS_DDR50:
		tegra_host->ddr_signaling = true;
		set_trim_delay = true;
		break;
	case MMC_TIMING_MMC_HS200:
		tuning_mode = true;
		set_num_tun_iter = true;
		set_trim_delay = true;
		break;
	case MMC_TIMING_MMC_HS400:
		tuning_mode = true;
		set_num_tun_iter = true;
		set_padpipe_clk_override = true;
		break;
	default:
		break;
	}
	if (timing > tegra_host->timing) {
		tegra_sdhci_pad_autocalib(host);
		tegra_host->timing = timing;
	}

	/* Set trim delay */
	if (set_trim_delay) {
		ret = tegra_prod_set_by_name_partially(&host->ioaddr,
				prod_device_states[timing], tegra_host->prods,
				0, SDHCI_TEGRA_VENDOR_CLOCK_CTRL,
				SDHCI_CLOCK_CTRL_TRIM_MASK <<
				SDHCI_CLOCK_CTRL_TRIM_SHIFT);
		if (ret < 0)
			dev_err(mmc_dev(host->mmc),
				"Failed to set trim value for timing %d, %d\n",
				timing, ret);
	}

	/* Set Tap delay */
	if (tegra_host->ddr_signaling)
		tap_delay_type = SET_DDR_TAP;
	else if ((tegra_host->tuning_status == TUNING_STATUS_DONE) &&
		tuning_mode)
		tap_delay_type = SET_REQ_TAP;
	else
		tap_delay_type = SET_DEFAULT_TAP;
	tegra_sdhci_set_tap(host, tegra_host->tuned_tap_delay, tap_delay_type);

	/*set padpipe_clk_override*/
	if (set_padpipe_clk_override) {
		ret = tegra_prod_set_by_name_partially(&host->ioaddr,
				prod_device_states[timing], tegra_host->prods,
				0, SDHCI_TEGRA_VENDOR_CLOCK_CTRL,
				SDHCI_CLOCK_CTRL_PADPIPE_CLKEN_OVERRIDE);
		if (ret < 0)
			dev_err(mmc_dev(host->mmc),
				"Failed to set padpipe clk override value for timing %d, %d\n",
				timing, ret);
	}
	/* Set number of tuning iterations */
	if (set_num_tun_iter) {
		ret = tegra_prod_set_by_name_partially(&host->ioaddr,
				prod_device_states[timing], tegra_host->prods,
				0, SDHCI_VNDR_TUN_CTRL0_0,
				SDHCI_TUN_CTRL0_TUNING_ITER_MASK <<
					SDHCI_TUN_CTRL0_TUNING_ITER_SHIFT);
		if (ret < 0)
			dev_err(mmc_dev(host->mmc),
				"Failed to set number of iterations for timing %d, %d\n",
				timing, ret);
	}
	/* Set SDMMC_SPARE_0*/
	if (set_sdmmc_spare_0) {
		ret = tegra_prod_set_by_name_partially(&host->ioaddr,
				prod_device_states[timing], tegra_host->prods,
				0, SDHCI_TEGRA_VENDOR_MISC_CTRL,
				 SDHCI_MISC_CTRL_SDMMC_SPARE_0_MASK);
		if (ret < 0)
			dev_err(mmc_dev(host->mmc),
				"Failed to set spare0 field for timing %d, %d\n",
				timing, ret);
	}
}

static unsigned int tegra_sdhci_get_max_clock(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	/*
	 * DDR modes require the host to run at double the card frequency, so
	 * the maximum rate we can support is half of the module input clock.
	 */
	return clk_round_rate(pltfm_host->clk, UINT_MAX) / 2;
}

static unsigned int tegra_sdhci_get_timeout_clock(struct sdhci_host *host)
{
	/*
	* Tegra SDMMC controller advertises 12MHz timeout clock. Controller
	* models in simulator might not advertise the timeout clock frequency.
	* To avoid errors, return 12MHz clock for supporting timeout clock
	* on simulators.
	*/
	return SDMMC_TIMEOUT_CLK_FREQ_MHZ;
}

static void tegra_sdhci_set_tap(struct sdhci_host *host, unsigned int tap,
	int type)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;
	u32 reg;
	u16 clk;
	bool card_clk_enabled = false;
	int err;

	if (tap > MAX_TAP_VALUE) {
		dev_err(mmc_dev(host->mmc), "Invalid tap value %d\n", tap);
		return;
	}

	if (soc_data->nvquirks & NVQUIRK_DIS_CARD_CLK_CONFIG_TAP) {
		clk = sdhci_readw(host, SDHCI_CLOCK_CONTROL);
		card_clk_enabled = clk & SDHCI_CLOCK_CARD_EN;
		if (card_clk_enabled) {
			clk &= ~SDHCI_CLOCK_CARD_EN;
			sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);
		}
	}

	/* Disable HW tap delay config */
	if (soc_data->nvquirks & NVQUIRK_HW_TAP_CONFIG) {
		reg = sdhci_readl(host, SDHCI_VNDR_TUN_CTRL0_0);
		reg &= ~SDHCI_VNDR_TUN_CTRL0_TUN_HW_TAP;
		sdhci_writel(host, reg, SDHCI_VNDR_TUN_CTRL0_0);
	}

	if (type & (SET_DDR_TAP | SET_DEFAULT_TAP)) {
		err = tegra_prod_set_by_name_partially(&host->ioaddr,
				"prod",	tegra_host->prods, 0,
				SDHCI_TEGRA_VENDOR_CLOCK_CTRL,
				SDHCI_CLOCK_CTRL_TAP_MASK <<
				SDHCI_CLOCK_CTRL_TAP_SHIFT);
		if (err < 0)
			dev_dbg(mmc_dev(host->mmc),
				"%s: error %d in tap settings, timing: %d\n",
				__func__, err, host->mmc->ios.timing);
	} else {
		reg = sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
		reg &= ~(SDHCI_CLOCK_CTRL_TAP_MASK <<
				SDHCI_CLOCK_CTRL_TAP_SHIFT);
		reg |= tap << SDHCI_CLOCK_CTRL_TAP_SHIFT;
		sdhci_writel(host, reg, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
	}

	/* Enable HW tap delay config */
	if (soc_data->nvquirks & NVQUIRK_HW_TAP_CONFIG) {
		reg = sdhci_readl(host, SDHCI_VNDR_TUN_CTRL0_0);
		reg |= SDHCI_VNDR_TUN_CTRL0_TUN_HW_TAP;
		sdhci_writel(host, reg, SDHCI_VNDR_TUN_CTRL0_0);
	}

	if ((soc_data->nvquirks & NVQUIRK_DIS_CARD_CLK_CONFIG_TAP) &&
		card_clk_enabled) {
		udelay(1);
		sdhci_reset(host, SDHCI_RESET_CMD | SDHCI_RESET_DATA);
		clk = sdhci_readw(host, SDHCI_CLOCK_CONTROL);
		clk |= SDHCI_CLOCK_CARD_EN;
		sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);
	}
}

static int tegra_sdhci_execute_tuning(struct sdhci_host *host, u32 opcode)
{
	unsigned int min, max;

	/*
	 * Start search for minimum tap value at 10, as smaller values are
	 * may wrongly be reported as working but fail at higher speeds,
	 * according to the TRM.
	 */
	min = 10;
	while (min < 255) {
		tegra_sdhci_set_tap(host, min, SET_REQ_TAP);
		if (!mmc_send_tuning(host->mmc, opcode, NULL))
			break;
		min++;
	}

	/* Find the maximum tap value that still passes. */
	max = min + 1;
	while (max < 255) {
		tegra_sdhci_set_tap(host, max, SET_REQ_TAP);
		if (mmc_send_tuning(host->mmc, opcode, NULL)) {
			max--;
			break;
		}
		max++;
	}

	/* The TRM states the ideal tap value is at 75% in the passing range. */
	tegra_sdhci_set_tap(host, min + ((max - min) * 3 / 4), SET_REQ_TAP);

	return mmc_send_tuning(host->mmc, opcode, NULL);
}

static void tegra_sdhci_set_padctrl(struct sdhci_host *host, int voltage)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int ret = 0;

	if (!tegra_host->pwrdet_support || IS_ERR_OR_NULL(tegra_host->pinctrl_sdmmc)
			|| IS_ERR_OR_NULL(tegra_host->e_33v_enable)
			|| IS_ERR_OR_NULL(tegra_host->e_33v_disable)) {
		dev_dbg(mmc_dev(host->mmc),
			"IO pad Volt setting skip: pwrdet-%d, pinctrl_sdmmc-%d"
			" e_33v_enable-%d, e_33v_disable-%d\n",
			tegra_host->pwrdet_support,
			IS_ERR_OR_NULL(tegra_host->pinctrl_sdmmc),
			IS_ERR_OR_NULL(tegra_host->e_33v_enable),
			IS_ERR_OR_NULL(tegra_host->e_33v_disable));
		return;
	}

	if (voltage == SDHOST_LOW_VOLT_MIN) {
		ret = pinctrl_select_state(tegra_host->pinctrl_sdmmc,
				tegra_host->e_33v_disable);
		if (ret < 0)
			dev_warn(mmc_dev(host->mmc),
				"setting E_33V dis failed, ret: %d\n", ret);
	} else {
		ret = pinctrl_select_state(tegra_host->pinctrl_sdmmc,
				tegra_host->e_33v_enable);
		if (ret < 0)
			dev_warn(mmc_dev(host->mmc),
				"setting E_33V en failed, ret: %d\n", ret);
	}
}

static void tegra_sdhci_signal_voltage_switch_pre(struct sdhci_host *host,
	int signal_voltage)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);

	/* Toggle power gpio for switching voltage on FPGA */
	if (gpio_is_valid(tegra_host->volt_switch_gpio)) {
		if (signal_voltage == MMC_SIGNAL_VOLTAGE_330) {
			gpio_set_value(tegra_host->volt_switch_gpio, 1);
			dev_info(mmc_dev(host->mmc),
				 "3.3V set by voltage switch gpio\n");
		} else {
			gpio_set_value(tegra_host->volt_switch_gpio, 0);
			dev_info(mmc_dev(host->mmc),
				 "1.8V set by voltage switch gpio\n");
			mdelay(1000);
		}
		return;
	}

	/* For 3.3V, pwrdet should be set before setting the voltage */
	if (signal_voltage == MMC_SIGNAL_VOLTAGE_330)
		tegra_sdhci_set_padctrl(host, 3300000);
}

static void tegra_sdhci_update_sdmmc_pinctrl_register(struct sdhci_host *sdhci,
	bool set)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(sdhci);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;
	struct pinctrl_state *set_schmitt[2];
	int ret;
	int i;

	if (!(soc_data->nvquirks & NVQUIRK_UPDATE_PIN_CNTRL_REG))
		return;

	if (set) {
		set_schmitt[0] = tegra_host->schmitt_enable[0];
		set_schmitt[1] = tegra_host->schmitt_enable[1];

		if (!IS_ERR_OR_NULL(tegra_host->drv_code_strength)) {
			ret = pinctrl_select_state(tegra_host->pinctrl_sdmmc,
				tegra_host->drv_code_strength);
			if (ret < 0)
				dev_warn(mmc_dev(sdhci->mmc),
				"setting drive code strength failed\n");
		}
	} else {
		set_schmitt[0] = tegra_host->schmitt_disable[0];
		set_schmitt[1] = tegra_host->schmitt_disable[1];

		if (!IS_ERR_OR_NULL(tegra_host->default_drv_code_strength)) {
			ret = pinctrl_select_state(tegra_host->pinctrl_sdmmc,
				tegra_host->default_drv_code_strength);
			if (ret < 0)
				dev_warn(mmc_dev(sdhci->mmc),
				"setting default drive code strength failed\n");
		}
	}

	for (i = 0; i < 2; i++) {
		if (IS_ERR_OR_NULL(set_schmitt[i]))
			continue;
		ret = pinctrl_select_state(tegra_host->pinctrl_sdmmc,
			set_schmitt[i]);
		if (ret < 0)
			dev_warn(mmc_dev(sdhci->mmc),
				"setting schmitt state failed\n");
	}
}

static void tegra_sdhci_signal_voltage_switch_post(struct sdhci_host *host,
	int signal_voltage)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int ret;

	if (signal_voltage == MMC_SIGNAL_VOLTAGE_180) {
		tegra_sdhci_set_padctrl(host, 1800000);
		tegra_sdhci_update_sdmmc_pinctrl_register(host, true);
		/*
		 * prod_c_1_8v and prod_c_3_3v are applicable to only
		 * t194 platforms
		 */
		ret = tegra_prod_set_by_name_partially(&host->ioaddr,
			"prod_c_1_8v", tegra_host->prods, 0,
			SDHCI_TEGRA_SDMEM_COMP_PADCTRL,
			SDHCI_TEGRA_SDMEMCOMP_PADCTRL_DRVUP_OVR);
		if (ret < 0)
			dev_dbg(mmc_dev(host->mmc),
				"%s: error %d in comp drvup settings at 1.8v\n",
				__func__, ret);
	} else {
		tegra_sdhci_update_sdmmc_pinctrl_register(host, false);
		ret = tegra_prod_set_by_name_partially(&host->ioaddr,
			"prod_c_3_3v", tegra_host->prods, 0,
			SDHCI_TEGRA_SDMEM_COMP_PADCTRL,
			SDHCI_TEGRA_SDMEMCOMP_PADCTRL_DRVUP_OVR);
		if (ret < 0)
			dev_dbg(mmc_dev(host->mmc),
				"%s: error %d in comp drvup settings at 3.3v\n",
				__func__, ret);
	}

	if (tegra_host->pad_calib_required)
		tegra_sdhci_pad_autocalib(host);
}

static void tegra_sdhci_voltage_switch(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;

	if (soc_data->nvquirks & NVQUIRK_HAS_PADCALIB)
		tegra_host->pad_calib_required = true;
}

static int sdhci_tegra_get_parent_pll_from_dt(struct sdhci_host *host,
	struct platform_device *pdev)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	struct device_node *np = pdev->dev.of_node;
	struct sdhci_tegra_clk_src_data *clk_src_data;
	struct clk *parent_clk;
	const char *pll_str;
	int i, cnt, j = 0;

	if (!np || !tegra_host)
		return -EINVAL;

	if (!of_find_property(np, "pll_source", NULL))
		return -ENXIO;

	clk_src_data = tegra_host->clk_src_data;
	cnt = of_property_count_strings(np, "pll_source");
	if (!cnt)
		return -EINVAL;

	if (cnt > MAX_CLK_PARENTS) {
		dev_warn(mmc_dev(host->mmc),
			"Parent sources list exceeded limit\n");
		cnt = MAX_CLK_PARENTS;
	}

	for (i = 0; i < cnt; i++) {
		of_property_read_string_index(np, "pll_source", i, &pll_str);
		parent_clk = devm_clk_get(&pdev->dev, pll_str);
		if (IS_ERR(parent_clk))
			dev_err(mmc_dev(host->mmc), "Failed to get %s clk\n",
				pll_str);
		else {
			clk_src_data->parent_clk_name[j] = pll_str;
			clk_src_data->parent_clk_rate[j] = clk_get_rate(parent_clk);
			clk_src_data->parent_clk[j++] = parent_clk;
		}
	}

	/* Count valid parent clock sources with clk structures */
	clk_src_data->parent_clk_src_cnt = j;
	/*
	 * Set current parent clock index to -1 to force parent clock setting.
	 */
	clk_src_data->curr_parent_clk_idx = -1;

	return 0;
}

static void tegra_sdhci_init_pinctrl_info(struct device *dev,
		struct sdhci_tegra *tegra_host)
{
	struct device_node *np = dev->of_node;
	int ret, i;

	if (!np)
		return;

	tegra_host->prods = devm_tegra_prod_get(dev);
	if (IS_ERR_OR_NULL(tegra_host->prods)) {
		dev_err(dev, "Prod-setting not available\n");
		tegra_host->prods = NULL;
	}

	if (tegra_host->pwrdet_support) {
		tegra_host->pinctrl_sdmmc = devm_pinctrl_get(dev);
		if (IS_ERR_OR_NULL(tegra_host->pinctrl_sdmmc)) {
			dev_err(dev, "Missing pinctrl info, err: %ld\n",
					PTR_ERR(tegra_host->pinctrl_sdmmc));
			tegra_host->pinctrl_sdmmc = NULL;
			return;
		}

		tegra_host->e_33v_enable =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
					"sdmmc_e_33v_enable");
		if (IS_ERR_OR_NULL(tegra_host->e_33v_enable))
			dev_dbg(dev, "Missing E_33V enable state, err:%ld\n",
					PTR_ERR(tegra_host->e_33v_enable));
		tegra_host->e_33v_disable =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
					"sdmmc_e_33v_disable");
		if (IS_ERR_OR_NULL(tegra_host->e_33v_disable))
			dev_dbg(dev, "Missing E_33V disable state, err:%ld\n",
				PTR_ERR(tegra_host->e_33v_disable));
	}

	if (tegra_host->update_pinctrl_settings) {
		tegra_host->schmitt_enable[0] =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
			"sdmmc_schmitt_enable");
		if (IS_ERR_OR_NULL(tegra_host->schmitt_enable[0]))
			dev_err(dev, "Missing schmitt enable state\n");

		tegra_host->schmitt_enable[1] =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
			"sdmmc_clk_schmitt_enable");
		if (IS_ERR_OR_NULL(tegra_host->schmitt_enable[1]))
			dev_err(dev, "Missing clk schmitt enable state\n");

		tegra_host->schmitt_disable[0] =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
			"sdmmc_schmitt_disable");
		if (IS_ERR_OR_NULL(tegra_host->schmitt_disable[0]))
			dev_err(dev, "Missing schmitt disable state\n");

		tegra_host->schmitt_disable[1] =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
			"sdmmc_clk_schmitt_disable");
		if (IS_ERR_OR_NULL(tegra_host->schmitt_disable[1]))
			dev_err(dev, "Missing clk schmitt disable state\n");

		for (i = 0; i < 2; i++) {
			if (!IS_ERR_OR_NULL(tegra_host->schmitt_disable[i])) {
				ret = pinctrl_select_state(tegra_host->pinctrl_sdmmc,
					tegra_host->schmitt_disable[i]);
				if (ret < 0)
					dev_warn(dev,
					"setting schmitt state failed\n");
			}
		}
		tegra_host->drv_code_strength =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
			"sdmmc_drv_code");
		if (IS_ERR_OR_NULL(tegra_host->drv_code_strength))
			dev_err(dev, "Missing sdmmc drive code state\n");

		tegra_host->default_drv_code_strength =
			pinctrl_lookup_state(tegra_host->pinctrl_sdmmc,
			"sdmmc_default_drv_code");
		if (IS_ERR_OR_NULL(tegra_host->default_drv_code_strength))
			dev_err(dev, "Missing sdmmc default drive code state\n");
	}
}

static void tegra_sdhci_pre_regulator_config(struct sdhci_host *sdhci,
	int vdd, bool flag)
{
	if (!vdd)
		return;

	tegra_sdhci_configure_e_input(sdhci, flag);
}

/* Configure voltage switch specific requirements */
static void tegra_sdhci_voltage_switch_req(struct sdhci_host *host, bool req)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	const struct sdhci_tegra_soc_data *soc_data = tegra_host->soc_data;
	u32 clk_ctrl;

	if (!req) {
		/* Disable SLCG */
		clk_ctrl = sdhci_readl(host, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
		clk_ctrl = clk_ctrl | SDHCI_CLOCK_CTRL_LEGACY_CLKEN_OVERRIDE;
		sdhci_writel(host, clk_ctrl, SDHCI_TEGRA_VENDOR_CLOCK_CTRL);

		if (soc_data->nvquirks & NVQUIRK_SDMMC_CLK_OVERRIDE) {
			clk_ctrl = sdhci_readl(host,
						SDHCI_TEGRA_VENDOR_MISC_CTRL_2);
			clk_ctrl = clk_ctrl | SDHCI_MISC_CTRL_2_CLK_OVR_ON;
			sdhci_writel(host, clk_ctrl,
						SDHCI_TEGRA_VENDOR_MISC_CTRL_2);
		}
	} else  {
		/* Restore SLCG */
		if (tegra_host->slcg_status) {
			clk_ctrl = sdhci_readl(host,
						SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
			clk_ctrl = clk_ctrl &
					~SDHCI_CLOCK_CTRL_LEGACY_CLKEN_OVERRIDE;
			sdhci_writel(host, clk_ctrl,
						SDHCI_TEGRA_VENDOR_CLOCK_CTRL);
			if (soc_data->nvquirks &
					NVQUIRK_SDMMC_CLK_OVERRIDE) {
				clk_ctrl = sdhci_readl(host,
						SDHCI_TEGRA_VENDOR_MISC_CTRL_2);
				clk_ctrl = clk_ctrl &
						~SDHCI_MISC_CTRL_2_CLK_OVR_ON;
				sdhci_writel(host, clk_ctrl,
						SDHCI_TEGRA_VENDOR_MISC_CTRL_2);
			}
		}
	}

}
static const struct sdhci_ops tegra_sdhci_ops = {
	.get_ro     = tegra_sdhci_get_ro,
	.read_b     = tegra_sdhci_readb,
	.read_w     = tegra_sdhci_readw,
	.read_l     = tegra_sdhci_readl,
	.write_b    = tegra_sdhci_writeb,
	.write_w    = tegra_sdhci_writew,
	.write_l    = tegra_sdhci_writel,
	.set_clock  = tegra_sdhci_set_clock,
	.set_bus_width = tegra_sdhci_set_bus_width,
	.reset      = tegra_sdhci_reset,
	.set_uhs_signaling = tegra_sdhci_set_uhs_signaling,
	.voltage_switch = tegra_sdhci_voltage_switch,
	.get_max_clock = tegra_sdhci_get_max_clock,
	.get_timeout_clock = tegra_sdhci_get_timeout_clock,
	.get_max_tuning_loop_counter = tegra_sdhci_get_max_tuning_loop_counter,
	.skip_retuning = tegra_sdhci_skip_retuning,
	.post_tuning = tegra_sdhci_post_tuning,
	.voltage_switch_pre = tegra_sdhci_signal_voltage_switch_pre,
	.voltage_switch_post = tegra_sdhci_signal_voltage_switch_post,
	.hs400_enhanced_strobe = tegra_sdhci_hs400_enhanced_strobe,
	.post_init = tegra_sdhci_post_init,
	.suspend = tegra_sdhci_suspend,
	.resume = tegra_sdhci_resume,
	.complete = tegra_sdhci_complete,
	.runtime_suspend = tegra_sdhci_runtime_suspend,
	.runtime_resume = tegra_sdhci_runtime_resume,
	.platform_resume = tegra_sdhci_post_resume,
	.card_event = tegra_sdhci_card_event,
	.dump_vendor_regs = tegra_sdhci_dump_vendor_regs,
	.pre_regulator_config	= tegra_sdhci_pre_regulator_config,
	.voltage_switch_req	= tegra_sdhci_voltage_switch_req,
	.pad_autocalib		= tegra_sdhci_pad_autocalib,
};

static const struct sdhci_pltfm_data sdhci_tegra20_pdata = {
	.quirks = SDHCI_QUIRK_BROKEN_TIMEOUT_VAL |
		  SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		  SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		  SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
	.ops  = &tegra_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra20 = {
	.pdata = &sdhci_tegra20_pdata,
	.nvquirks = NVQUIRK_FORCE_SDHCI_SPEC_200 |
		    NVQUIRK_ENABLE_BLOCK_GAP_DET,
};

static const struct sdhci_pltfm_data sdhci_tegra30_pdata = {
	.quirks = SDHCI_QUIRK_BROKEN_TIMEOUT_VAL |
		  SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK |
		  SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		  SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		  SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN |
		   SDHCI_QUIRK2_BROKEN_HS200,
	.ops  = &tegra_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra30 = {
	.pdata = &sdhci_tegra30_pdata,
	.nvquirks = NVQUIRK_ENABLE_SDHCI_SPEC_300 |
		    NVQUIRK_ENABLE_SDR50 |
		    NVQUIRK_ENABLE_SDR104 |
		    NVQUIRK_HAS_PADCALIB,
};

static const struct sdhci_ops tegra114_sdhci_ops = {
	.get_ro     = tegra_sdhci_get_ro,
	.read_w     = tegra_sdhci_readw,
	.write_b    = tegra_sdhci_writeb,
	.write_w    = tegra_sdhci_writew,
	.write_l    = tegra_sdhci_writel,
	.set_clock  = tegra_sdhci_set_clock,
	.set_bus_width = tegra_sdhci_set_bus_width,
	.reset      = tegra_sdhci_reset,
	.platform_execute_tuning = tegra_sdhci_execute_tuning,
	.set_uhs_signaling = tegra_sdhci_set_uhs_signaling,
	.voltage_switch = tegra_sdhci_voltage_switch,
	.get_max_clock = tegra_sdhci_get_max_clock,
};

static const struct sdhci_pltfm_data sdhci_tegra114_pdata = {
	.quirks = SDHCI_QUIRK_BROKEN_TIMEOUT_VAL |
		  SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK |
		  SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		  SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		  SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN |
		SDHCI_QUIRK2_SEL_SDR104_UHS_MODE_IN_SDR50,
	.ops  = &tegra114_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra114 = {
	.pdata = &sdhci_tegra114_pdata,
};

static const struct sdhci_pltfm_data sdhci_tegra124_pdata = {
	.quirks = SDHCI_QUIRK_BROKEN_TIMEOUT_VAL |
		  SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK |
		  SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		  SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		  SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN |
		   /*
		    * The TRM states that the SD/MMC controller found on
		    * Tegra124 can address 34 bits (the maximum supported by
		    * the Tegra memory controller), but tests show that DMA
		    * to or from above 4 GiB doesn't work. This is possibly
		    * caused by missing programming, though it's not obvious
		    * what sequence is required. Mark 64-bit DMA broken for
		    * now to fix this for existing users (e.g. Nyan boards).
		    */
		   SDHCI_QUIRK2_BROKEN_64_BIT_DMA |
		   SDHCI_QUIRK2_SEL_SDR104_UHS_MODE_IN_SDR50,
	.ops  = &tegra114_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra124 = {
	.pdata = &sdhci_tegra124_pdata,
};

static const struct sdhci_pltfm_data sdhci_tegra210_pdata = {
	.quirks = SDHCI_QUIRK_BROKEN_TIMEOUT_VAL |
		  SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		  SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		  SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK |
		  SDHCI_QUIRK_BROKEN_CARD_DETECTION |
		  SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC |
		  SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN |
		SDHCI_QUIRK2_USE_64BIT_ADDR |
		SDHCI_QUIRK2_ISSUE_CMD_DAT_RESET_TOGETHER |
		SDHCI_QUIRK2_SEL_SDR104_UHS_MODE_IN_SDR50 |
		SDHCI_QUIRK2_NO_CALC_MAX_BUSY_TO |
		SDHCI_QUIRK2_NON_STD_TUN_CARD_CLOCK |
		SDHCI_QUIRK2_HOST_OFF_CARD_ON,
	.ops  = &tegra_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra210 = {
	.pdata = &sdhci_tegra210_pdata,
	.nvquirks = NVQUIRK_HW_TAP_CONFIG |
		    NVQUIRK_DIS_CARD_CLK_CONFIG_TAP |
		    NVQUIRK_READ_REG_AFTER_WRITE |
		    NVQUIRK_ENABLE_SDHCI_SPEC_300 |
		    NVQUIRK_ENABLE_SDR50 |
		    NVQUIRK_ENABLE_DDR50 |
		    NVQUIRK_ENABLE_SDR104 |
		    NVQUIRK_UPDATE_PIN_CNTRL_REG |
		    NVQUIRK_HAS_PADCALIB |
		    SDHCI_MISC_CTRL_ENABLE_SDR50,
};

static const struct sdhci_pltfm_data sdhci_tegra186_pdata = {
	.quirks = SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		SDHCI_QUIRK_NO_HISPD_BIT |
		SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN |
		SDHCI_QUIRK2_USE_64BIT_ADDR |
		SDHCI_QUIRK2_HOST_OFF_CARD_ON |
		SDHCI_QUIRK2_SEL_SDR104_UHS_MODE_IN_SDR50,
	.ops  = &tegra_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra186 = {
	.pdata = &sdhci_tegra186_pdata,
	.nvquirks = NVQUIRK_HW_TAP_CONFIG |
		    NVQUIRK_ENABLE_SDR50 |
		    NVQUIRK_ENABLE_DDR50 |
		    NVQUIRK_ENABLE_SDR104 |
		    NVQUIRK_SDMMC_CLK_OVERRIDE |
		    SDHCI_MISC_CTRL_ENABLE_SDR50 |
		    NVQUIRK_HAS_PADCALIB,
	.cqequirks = CMDQ_QUIRK_SET_CMD_TIMING_R1B_DCMD,
};

static const struct sdhci_pltfm_data sdhci_tegra194_pdata = {
	.quirks = SDHCI_QUIRK_SINGLE_POWER_WRITE |
		  SDHCI_QUIRK_NO_HISPD_BIT |
		SDHCI_QUIRK_NO_HISPD_BIT |
		SDHCI_QUIRK_BROKEN_ADMA_ZEROLEN_DESC |
		SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN |
		SDHCI_QUIRK2_USE_64BIT_ADDR |
		SDHCI_QUIRK2_HOST_OFF_CARD_ON |
		SDHCI_QUIRK2_NON_STD_TUN_CARD_CLOCK,
	.ops  = &tegra_sdhci_ops,
};

static const struct sdhci_tegra_soc_data soc_data_tegra194 = {
	.pdata = &sdhci_tegra194_pdata,
	.nvquirks = NVQUIRK_HW_TAP_CONFIG |
		    NVQUIRK_ENABLE_SDR50 |
		    NVQUIRK_ENABLE_DDR50 |
		    NVQUIRK_ENABLE_SDR104 |
		    NVQUIRK_SDMMC_CLK_OVERRIDE |
		    SDHCI_MISC_CTRL_ENABLE_SDR50,
};
static const struct of_device_id sdhci_tegra_dt_match[] = {
	{ .compatible = "nvidia,tegra194-sdhci", .data = &soc_data_tegra194 },
	{ .compatible = "nvidia,tegra186-sdhci", .data = &soc_data_tegra186 },
	{ .compatible = "nvidia,tegra210-sdhci", .data = &soc_data_tegra210 },
	{ .compatible = "nvidia,tegra124-sdhci", .data = &soc_data_tegra124 },
	{ .compatible = "nvidia,tegra114-sdhci", .data = &soc_data_tegra114 },
	{ .compatible = "nvidia,tegra30-sdhci", .data = &soc_data_tegra30 },
	{ .compatible = "nvidia,tegra20-sdhci", .data = &soc_data_tegra20 },
	{}
};
MODULE_DEVICE_TABLE(of, sdhci_tegra_dt_match);

static int sdhci_tegra_parse_dt(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct sdhci_host *host = platform_get_drvdata(pdev);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	int val;

	if (!np)
		return -EINVAL;

	of_property_read_u32(np, "max-clk-limit", (u32 *)&tegra_host->max_clk_limit);
	of_property_read_u32(np, "ddr-clk-limit",
		(u32 *)&tegra_host->max_ddr_clk_limit);
	tegra_host->pwrdet_support = of_property_read_bool(np,
		"pwrdet-support");
	tegra_host->update_pinctrl_settings = of_property_read_bool(np,
		"nvidia,update-pinctrl-settings");
	tegra_host->cd_gpio = of_get_named_gpio(np, "cd-gpios", 0);
	tegra_host->cd_wakeup_capable = of_property_read_bool(np,
		"nvidia,cd-wakeup-capable");
#ifdef CONFIG_MMC_CQ_HCI
	tegra_host->enable_hwcq = of_property_read_bool(np, "nvidia,enable-hwcq");
#endif
	host->ocr_mask = MMC_VDD_27_36 | MMC_VDD_165_195;
	tegra_host->instance = of_alias_get_id(np, "sdhci");
	if (!of_property_read_u32(np, "mmc-ocr-mask", &val)) {
		if (val == 1)
			host->ocr_mask &= ~(MMC_VDD_26_27 | MMC_VDD_27_28);
		else if (val == 2)
			host->ocr_mask &= (MMC_VDD_32_33 | MMC_VDD_165_195);
		else if (val == 3)
			host->ocr_mask &= (MMC_VDD_33_34 | MMC_VDD_165_195);
	}
	tegra_host->rate_change_needs_clk = of_property_read_bool(np,
		"nvidia,clk-en-before-freq-update");
	tegra_host->volt_switch_gpio = of_get_named_gpio(np,
			"nvidia,voltage-switch-gpio", 0);

	tegra_host->en_periodic_cflush = of_property_read_bool(np,
			"nvidia,en-periodic-cflush");
	tegra_host->static_parent_clk_mapping = of_property_read_bool(np,
		 "nvidia,set-parent-clk");
	host->mmc->cd_cap_invert = of_property_read_bool(np, "cd-inverted");
	if (tegra_host->en_periodic_cflush) {
		val = 0;
		of_property_read_u32(np, "nvidia,periodic-cflush-to", &val);
		host->mmc->flush_timeout = val;
		if (val == 0) {
			tegra_host->en_periodic_cflush = false;
			dev_warn(&pdev->dev,
				 "Periodic cache flush feature disabled,"
				 "since flush timeout value is zero.\n");
		}
	}
	of_property_read_u32(np, "uhs-mask", (u32 *)&tegra_host->uhs_mask);
	of_property_read_u32(np, "nvidia,boot-detect-delay",
			&tegra_host->boot_detect_delay);

	tegra_host->force_non_rem_rescan = of_property_read_bool(np,
		"force-non-removable-rescan");

	tegra_host->disable_rtpm = of_property_read_bool(np,
		"nvidia,disable-rtpm");
	if (tegra_host->disable_rtpm) {
		tegra_host->disable_clk_gate = true;
#ifdef CONFIG_PM
		dev_info(&pdev->dev, "runtime pm disabled\n");
#endif
	} else {
		tegra_host->disable_clk_gate = of_property_read_bool(np,
			"disable-dynamic-clock-gating");
#ifdef CONFIG_PM
		if (tegra_host->disable_clk_gate)
			dev_info(&pdev->dev, "clock gating disabled\n");
#endif
	}

	tegra_host->vqmmc_always_on = of_property_read_bool(np,
		"nvidia,vqmmc-always-on");
	tegra_host->vmmc_always_on = of_property_read_bool(np,
		"nvidia,vmmc-always-on");
	tegra_host->en_periodic_calib = of_property_read_bool(np,
			"nvidia,en-periodic-calib");

	of_property_read_u32(np, "nvidia,min-tap-delay",
		&tegra_host->min_tap_delay);
	of_property_read_u32(np, "nvidia,max-tap-delay",
		&tegra_host->max_tap_delay);
	return 0;
}

static int sdhci_tegra_parse_parent_list_from_dt(struct platform_device *pdev,
	struct sdhci_tegra *tegra_host)
{
	struct device_node *np = pdev->dev.of_node;
	const char *curr_mode_parent_clk[MMC_TIMING_COUNTER];
	const char *pll_str;
	int i, j, cnt;

	if (!np)
		return -EINVAL;

	if (!of_find_property(np, "nvidia,parent_clk_list", NULL))
		return -ENXIO;

	cnt = of_property_count_strings(np, "nvidia,parent_clk_list");
	if (cnt != MMC_TIMING_COUNTER)
		return -EINVAL;

	for (i = 0; i < cnt; i++) {
		of_property_read_string_index(np, "nvidia,parent_clk_list",
			i, &pll_str);
		curr_mode_parent_clk[i] = pll_str;
		/* Initialize parent clock index array with invalid */
		tegra_host->parent_clk_index[i] = -EINVAL;
	}

	for (i = 0; i < tegra_host->clk_src_data->parent_clk_src_cnt; i++) {
		for (j = 0; j < MMC_TIMING_COUNTER; j++) {
			if (!strcmp(curr_mode_parent_clk[j],
				tegra_host->clk_src_data->parent_clk_name[i]))
				tegra_host->parent_clk_index[j] = i;
		}
	}
	return 0;
}


static void sdhci_delayed_detect(struct work_struct *work)
{
	struct sdhci_tegra *tegra_host;
	struct sdhci_host *host;

	tegra_host = container_of(work, struct sdhci_tegra, detect_delay.work);
	host = tegra_host->host;

	if (sdhci_add_host(host))
		goto err_add_host;

	if (!tegra_host->disable_rtpm) {
		pm_runtime_mark_last_busy(mmc_dev(host->mmc));
		pm_runtime_put_autosuspend(mmc_dev(host->mmc));
	}

	/* Initialize debugfs */
	sdhci_tegra_debugfs_init(host);
	return;

err_add_host:
	if (!tegra_host->disable_rtpm)
		pm_runtime_disable(mmc_dev(host->mmc));
}

static int sdhci_tegra_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	const struct sdhci_tegra_soc_data *soc_data;
	struct sdhci_host *host;
	struct sdhci_pltfm_host *pltfm_host;
	struct sdhci_tegra *tegra_host;
	struct clk *clk;
	struct sdhci_tegra_clk_src_data *clk_src_data;
	int rc;

	match = of_match_device(sdhci_tegra_dt_match, &pdev->dev);
	if (!match)
		return -EINVAL;
	soc_data = match->data;

	host = sdhci_pltfm_init(pdev, soc_data->pdata, sizeof(*tegra_host));
	if (IS_ERR(host))
		return PTR_ERR(host);
	pltfm_host = sdhci_priv(host);

	tegra_host = sdhci_pltfm_priv(pltfm_host);
	tegra_host->ddr_signaling = false;
	tegra_host->pad_calib_required = false;
	tegra_host->host = host;

	INIT_DELAYED_WORK(&tegra_host->detect_delay, sdhci_delayed_detect);

	/* FIXME: This is for until dma-mask binding is supported in DT.
	 *        Set coherent_dma_mask for each Tegra SKUs.
	 *        If dma_mask is NULL, set it to coherent_dma_mask. */
	pdev->dev.coherent_dma_mask = DMA_BIT_MASK(64);

	if (!pdev->dev.dma_mask)
		pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;

	tegra_host->soc_data = soc_data;

	rc = mmc_of_parse(host->mmc);
	if (rc)
		goto err_parse_dt;
	sdhci_tegra_parse_dt(pdev);

	clk_src_data = devm_kzalloc(&pdev->dev, sizeof(*clk_src_data),
		GFP_KERNEL);
	if (IS_ERR_OR_NULL(clk_src_data)) {
		dev_err(mmc_dev(host->mmc),
			"Insufficient memory for clk source data\n");
		return -ENOMEM;
	}
	tegra_host->clk_src_data = clk_src_data;
	rc = sdhci_tegra_get_parent_pll_from_dt(host, pdev);
	if (rc)
		dev_err(mmc_dev(host->mmc),
			"Failed to find parent clocks\n");

	if (tegra_host->static_parent_clk_mapping) {
		rc = sdhci_tegra_parse_parent_list_from_dt(pdev, tegra_host);
		if (rc) {
			tegra_host->static_parent_clk_mapping = false;
			dev_err(mmc_dev(host->mmc),
				"Failed to find parent clocks %d\n", rc);
		}
	}

	tegra_sdhci_init_pinctrl_info(&pdev->dev, tegra_host);

	if (tegra_host->soc_data->nvquirks & NVQUIRK_ENABLE_DDR50)
		host->mmc->caps |= MMC_CAP_1_8V_DDR;

	tegra_host->power_gpio = devm_gpiod_get_optional(&pdev->dev, "power",
							 GPIOD_OUT_HIGH);
	if (IS_ERR(tegra_host->power_gpio)) {
		rc = PTR_ERR(tegra_host->power_gpio);
		goto err_power_req;
	}

	clk = devm_clk_get(&pdev->dev, "sdmmc");
	if (IS_ERR(clk)) {
		dev_err(mmc_dev(host->mmc), "clk err\n");
		rc = PTR_ERR(clk);
		goto err_clk_get;
	}
	pltfm_host->clk = clk;

	tegra_host->tmclk = devm_clk_get(&pdev->dev, "sdmmc_legacy_tm");
	if (IS_ERR(tegra_host->tmclk)) {
		dev_err(mmc_dev(host->mmc), "timeout clk error\n");
		rc = PTR_ERR(tegra_host->tmclk);
		goto err_clk_get;
	};
	clk_set_rate(tegra_host->tmclk, SDMMC_TIMEOUT_CLK_FREQ_HZ);

	tegra_host->emc_clk =
		tegra_bwmgr_register(sdmmc_emc_clinet_id[tegra_host->instance]);

	if (IS_ERR_OR_NULL(tegra_host->emc_clk))
		dev_err(mmc_dev(host->mmc),
			"Client registration for eMC failed\n");
	else
		dev_info(mmc_dev(host->mmc),
			"Client registration for eMC Successful\n");


	tegra_host->rst = devm_reset_control_get(&pdev->dev, "sdhci");
	if (IS_ERR(tegra_host->rst))
		dev_err(mmc_dev(host->mmc), "reset err\n");
	else
		reset_control_reset(tegra_host->rst);

	if (tegra_host->disable_rtpm) {
		tegra_sdhci_set_clock(host, SDMMC_TEGRA_FALLBACK_CLK_HZ);
		host->mmc->is_host_clk_enabled = true;
	} else {
		if (tegra_host->disable_clk_gate) {
			tegra_sdhci_set_clock(host, SDMMC_TEGRA_FALLBACK_CLK_HZ);
			host->mmc->is_host_clk_enabled = true;
		}
		pm_runtime_enable(mmc_dev(host->mmc));
		pm_runtime_get_sync(mmc_dev(host->mmc));
		/*
		 * set autosuspend delay results in suspend call if
		 * set active is called before pm_runtime_enable
		 */
		pm_runtime_set_autosuspend_delay(mmc_dev(host->mmc),
			SDHCI_RTPM_MSEC_TMOUT);
		pm_runtime_use_autosuspend(mmc_dev(host->mmc));
	}

	if (gpio_is_valid(tegra_host->volt_switch_gpio)) {
		rc = gpio_request(tegra_host->volt_switch_gpio, "sdhci_power");
		if (rc)
			dev_err(mmc_dev(host->mmc),
				"failed to allocate gpio for voltage switch, "
				"err: %d\n", rc);
		gpio_direction_output(tegra_host->volt_switch_gpio, 1);
		gpio_set_value(tegra_host->volt_switch_gpio, 1);
		dev_info(mmc_dev(host->mmc),
				"3.3V set initially by voltage switch gpio\n");
	}

	if (gpio_is_valid(tegra_host->cd_gpio) &&
			tegra_host->cd_wakeup_capable) {
		tegra_host->cd_irq = gpio_to_irq(tegra_host->cd_gpio);
		if (tegra_host->cd_irq <= 0) {
			dev_err(mmc_dev(host->mmc),
				"failed to get gpio irq %d\n",
				tegra_host->cd_irq);
			tegra_host->cd_irq = 0;
		} else {
			device_init_wakeup(&pdev->dev, 1);
			dev_info(mmc_dev(host->mmc),
				"wakeup init done, cdirq %d\n",
				tegra_host->cd_irq);
		}
	}

	/*
	 * If there is no card detect gpio, assume that the
	 * card is always present.
	 */
	if (!gpio_is_valid(tegra_host->cd_gpio)) {
		host->mmc->rem_card_present = 1;
	} else {
		if (!host->mmc->cd_cap_invert)
			host->mmc->rem_card_present =
				(mmc_gpio_get_cd(host->mmc) == 0);
		else
			host->mmc->rem_card_present =
				mmc_gpio_get_cd(host->mmc);
	}

	if (!en_boot_part_access)
		host->mmc->caps2 |= MMC_CAP2_BOOTPART_NOACC;

	if (tegra_host->en_periodic_cflush)
		host->mmc->caps2 |= MMC_CAP2_PERIODIC_CACHE_FLUSH;

	if (tegra_host->vmmc_always_on)
		host->mmc->caps2 |= MMC_CAP2_SLOT_REG_ALWAYS_ON;

	host->mmc->caps2 |= MMC_CAP2_EN_CLK_TO_ACCESS_REG;
	host->mmc->caps |= MMC_CAP_WAIT_WHILE_BUSY;

	if (tegra_host->force_non_rem_rescan)
		host->mmc->caps2 |= MMC_CAP2_FORCE_RESCAN;

#ifdef CONFIG_MMC_CQ_HCI
	if (tegra_host->enable_hwcq) {
		host->mmc->caps2 |= MMC_CAP2_HW_CQ;
		host->cq_host = cmdq_pltfm_init(pdev);
		if (IS_ERR(host->cq_host)) {
			pr_err("CMDQ: Error in cmdq_platfm_init function\n");
		} else {
			pr_info("CMDQ: cmdq_platfm_init successful\n");
			host->cq_host->quirks = soc_data->cqequirks;
		}
	}
#endif
	if (tegra_host->en_periodic_calib)
		host->quirks2 |= SDHCI_QUIRK2_PERIODIC_CALIBRATION;

	schedule_delayed_work(&tegra_host->detect_delay,
			      msecs_to_jiffies(tegra_host->boot_detect_delay));
	return 0;

err_clk_get:
err_power_req:
err_parse_dt:
	sdhci_pltfm_free(pdev);
	return rc;
}

static int tegra_sdhci_suspend(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	struct platform_device *pdev = to_platform_device(mmc_dev(host->mmc));

	/* Enable wake irq at end of suspend */
	if (device_may_wakeup(&pdev->dev)) {
		if (enable_irq_wake(tegra_host->cd_irq)) {
			dev_err(mmc_dev(host->mmc),
				"Failed to enable wake irq %u\n",
				tegra_host->cd_irq);
			tegra_host->wake_enable_failed = true;
		}
	}
	tegra_sdhci_set_clock(host, 0);
	host->is_calib_done = false;

	return 0;
}

static int tegra_sdhci_resume(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	struct platform_device *pdev = to_platform_device(mmc_dev(host->mmc));
	int ret = 0;

	if (device_may_wakeup(&pdev->dev)) {
		if (!tegra_host->wake_enable_failed) {
			ret = disable_irq_wake(tegra_host->cd_irq);
			if (ret)
				dev_err(mmc_dev(host->mmc),
					"Failed to disable wakeirq %u,err %d\n",
					tegra_host->cd_irq, ret);
		}
	}

	if (gpio_is_valid(tegra_host->cd_gpio)) {
		if (!host->mmc->cd_cap_invert)
			host->mmc->rem_card_present =
				(mmc_gpio_get_cd(host->mmc) == 0);
		else
			host->mmc->rem_card_present =
				mmc_gpio_get_cd(host->mmc);
	} else {
		host->mmc->rem_card_present = true;
	}

	if (host->mmc->rem_card_present == false)
		tegra_host->tuning_status = TUNING_STATUS_RETUNE;

	/* Set min identificaion clock of 400 KHz */
	tegra_sdhci_set_clock(host, 400000);

	return ret;
}

static void tegra_sdhci_complete(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);

	if (!tegra_host->disable_rtpm) {
		pm_runtime_set_active(mmc_dev(host->mmc));
		pm_runtime_enable(mmc_dev(host->mmc));
		dev_dbg(mmc_dev(host->mmc), "resume complete runtime enable\n");
	}
}

static int tegra_sdhci_runtime_suspend(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);

	/* Disable clock */
	if (!tegra_host->disable_clk_gate)
		tegra_sdhci_set_clock(host, 0);

	return 0;
}

static int tegra_sdhci_runtime_resume(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	unsigned int clk;

	if (!tegra_host->disable_clk_gate) {
		/* Clock enable should be invoked with a non-zero freq */
		if (host->clock)
			clk = host->clock;
		else if (host->mmc->ios.clock)
			clk = host->mmc->ios.clock;
		else
			clk = SDMMC_TEGRA_FALLBACK_CLK_HZ;

		tegra_sdhci_set_clock(host, clk);
	}

	return 0;
}

static void tegra_sdhci_post_resume(struct sdhci_host *host)
{
	bool dll_calib_req = false;

	dll_calib_req = (host->mmc->card && mmc_card_mmc(host->mmc->card) &&
		(host->mmc->ios.timing == MMC_TIMING_MMC_HS400));
	if (dll_calib_req)
		tegra_sdhci_post_init(host);
}

static int sdhci_tegra_card_detect(struct sdhci_host *host, bool req)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	bool card_present = false;
	int err = 0;

	if (!(host->mmc->caps & MMC_CAP_NONREMOVABLE))
		if (host->mmc->rem_card_present)
			card_present = true;
	/* Check if card is inserted physically before performing */
	if (gpio_is_valid(tegra_host->cd_gpio)) {
		if ((mmc_gpio_get_cd(host->mmc)  == 1) &&
			(!host->mmc->cd_cap_invert)) {
			err = -ENXIO;
			dev_err(mmc_dev(host->mmc),
				"Card not inserted in slot\n");
			goto err_config;
		} else if ((mmc_gpio_get_cd(host->mmc)  == 0) &&
				(host->mmc->cd_cap_invert)) {
			err = -ENXIO;
			dev_err(mmc_dev(host->mmc),
				"Card not inserted in slot\n");
			goto err_config;
		}
	}

	/* Ignore the request if card already in requested state */
	if (card_present == req) {
		dev_info(mmc_dev(host->mmc),
			"Card already in requested state\n");
		goto err_config;
	} else {
		card_present = req;
	}

	if (card_present) {
		/* Virtual card insertion */
		host->mmc->rem_card_present = true;
		host->mmc->rescan_disable = 0;
		/* If vqmmc regulator and no 1.8V signalling,
		 *  then there's no UHS
		 */
		if (!IS_ERR(host->mmc->supply.vqmmc)) {
			err = regulator_enable(host->mmc->supply.vqmmc);
			if (err) {
				pr_warn("%s: Failed to enable vqmmc regulator: %d\n",
					mmc_hostname(host->mmc), err);
				host->mmc->supply.vqmmc = ERR_PTR(-EINVAL);
				goto err_config;
			}
			tegra_host->is_rail_enabled = true;
		}
		/* If vmmc regulator and no 1.8V signalling,
		 * then there's no UHS
		 */
		if (!IS_ERR(host->mmc->supply.vmmc)) {
			err = regulator_enable(host->mmc->supply.vmmc);
			if (err) {
				pr_warn("%s: Failed to enable vmmc regulator; %d\n",
					mmc_hostname(host->mmc), err);
				host->mmc->supply.vmmc = ERR_PTR(-EINVAL);
				goto err_config;
			}
			tegra_host->is_rail_enabled = true;
		}
	} else {
		/* Virtual card removal */
		host->mmc->rem_card_present = false;
		host->mmc->rescan_disable = 0;
		if (tegra_host->is_rail_enabled) {
			if (!IS_ERR(host->mmc->supply.vqmmc))
				regulator_disable(host->mmc->supply.vqmmc);
			if (!IS_ERR(host->mmc->supply.vmmc))
				regulator_disable(host->mmc->supply.vmmc);
			tegra_host->is_rail_enabled = false;
		}
	}
	host->mmc->trigger_card_event = true;
	mmc_detect_change(host->mmc, msecs_to_jiffies(200));

err_config:
	return err;
}

static int get_card_insert(void *data, u64 *val)
{
	struct sdhci_host *host = data;

	*val = host->mmc->rem_card_present;

	return 0;
}

static int set_card_insert(void *data, u64 val)
{
	struct sdhci_host *host = data;
	int err = 0;

	if (val > 1) {
		err = -EINVAL;
		dev_err(mmc_dev(host->mmc),
			"Usage error. Use 0 to remove, 1 to insert %d\n", err);
		goto err_detect;
	}

	if (host->mmc->caps & MMC_CAP_NONREMOVABLE) {
		err = -EINVAL;
		dev_err(mmc_dev(host->mmc),
			"usage error, Supports SDCARD hosts only %d\n", err);
		goto err_detect;
	}

	err = sdhci_tegra_card_detect(host, val);

err_detect:
	return err;
}

DEFINE_SIMPLE_ATTRIBUTE(sdhci_tegra_card_insert_fops, get_card_insert,
	set_card_insert, "%llu\n");
static void sdhci_tegra_debugfs_init(struct sdhci_host *host)
{
#ifdef CONFIG_DEBUG_FS
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_tegra *tegra_host = sdhci_pltfm_priv(pltfm_host);
	struct sdhci_tegra_clk_src_data *clk_src_data;
	struct dentry *sdhcidir, *clkdir, *retval;

	clk_src_data = tegra_host->clk_src_data;
	sdhcidir = debugfs_create_dir(dev_name(mmc_dev(host->mmc)), NULL);
	if (!sdhcidir) {
		dev_err(mmc_dev(host->mmc), "Failed to create debugfs\n");
		return;
	}

	/* Create clock debugfs dir under sdhci debugfs dir */
	clkdir = debugfs_create_dir("clock_data", sdhcidir);
	if (!clkdir)
		goto err;

	retval = debugfs_create_bool("slcg_status", S_IRUGO, clkdir,
				     &tegra_host->slcg_status);
	if (!retval)
		goto err;

	retval = debugfs_create_ulong("curr_clk_rate", S_IRUGO, clkdir,
		&tegra_host->curr_clk_rate);
	if (!retval)
		goto err;

	retval = debugfs_create_ulong("parent_clk_rate", S_IRUGO, clkdir,
		&clk_src_data->parent_clk_rate[
			clk_src_data->curr_parent_clk_idx]);
	if (!retval)
		goto err;
	/* backup original host timing capabilities as
	 * debugfs may override it later
	 */
	host->caps_timing_orig = host->mmc->caps &
				(MMC_CAP_SD_HIGHSPEED | MMC_CAP_UHS_DDR50
				 | MMC_CAP_UHS_SDR12 | MMC_CAP_UHS_SDR25
				 | MMC_CAP_UHS_SDR50 | MMC_CAP_UHS_SDR104);

	retval = debugfs_create_file("card_insert", S_IRUSR | S_IWUSR,
			sdhcidir, host, &sdhci_tegra_card_insert_fops);

	if (!retval)
		goto err;

	return;
err:
	debugfs_remove_recursive(sdhcidir);
	sdhcidir = NULL;
	dev_err(mmc_dev(host->mmc), "%s %s\n"
		, __func__, mmc_hostname(host->mmc));
	return;
#endif
}

static struct platform_driver sdhci_tegra_driver = {
	.driver		= {
		.name	= "sdhci-tegra",
		.of_match_table	= sdhci_tegra_dt_match,
		.pm	= &sdhci_pltfm_pmops,
	},
	.probe		= sdhci_tegra_probe,
	.remove		= sdhci_pltfm_unregister,
};
module_platform_driver(sdhci_tegra_driver);

module_param(en_boot_part_access, uint, 0444);

MODULE_DESCRIPTION("SDHCI driver for Tegra");
MODULE_AUTHOR("Google, Inc.");
MODULE_LICENSE("GPL v2");
