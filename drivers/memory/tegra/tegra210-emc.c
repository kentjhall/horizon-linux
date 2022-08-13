/*
 * Copyright (c) 2015-2019, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/kernel.h>
#include <linux/clk-provider.h>
#include <linux/clk.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/thermal.h>

#include <soc/tegra/bpmp_t210_abi.h>
#include <soc/tegra/tegra_bpmp.h>
#include <soc/tegra/tegra_emc.h>
#include <soc/tegra/fuse.h>

#include "tegra210-emc-reg.h"

#define TEGRA_EMC_TABLE_MAX_SIZE		16
#define EMC_STATUS_UPDATE_TIMEOUT		1000
#define TEGRA210_SAVE_RESTORE_MOD_REGS		12
#define TEGRA_EMC_DEFAULT_CLK_LATENCY_US	2000

#define EMC0_EMC_CMD_BRLSHFT_0_INDEX	0
#define EMC1_EMC_CMD_BRLSHFT_1_INDEX	1
#define EMC0_EMC_DATA_BRLSHFT_0_INDEX	2
#define EMC1_EMC_DATA_BRLSHFT_0_INDEX	3
#define EMC0_EMC_DATA_BRLSHFT_1_INDEX	4
#define EMC1_EMC_DATA_BRLSHFT_1_INDEX	5
#define EMC0_EMC_QUSE_BRLSHFT_0_INDEX	6
#define EMC1_EMC_QUSE_BRLSHFT_1_INDEX	7
#define EMC0_EMC_QUSE_BRLSHFT_2_INDEX	8
#define EMC1_EMC_QUSE_BRLSHFT_3_INDEX	9

#define TRIM_REG(chan, rank, reg, byte)					\
	((EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ## rank ## _ ## reg ##	\
	  _OB_DDLL_LONG_DQ_RANK ## rank ## _BYTE ## byte ## _MASK &	\
	  next_timing->trim_regs[EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ##	\
				 rank ## _ ## reg ## _INDEX]) >>	\
	 EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ## rank ## _ ## reg ##		\
	 _OB_DDLL_LONG_DQ_RANK ## rank ## _BYTE ## byte ## _SHIFT)	\
	+								\
	(((EMC_DATA_BRLSHFT_ ## rank ## _RANK ## rank ## _BYTE ##	\
	   byte ## _DATA_BRLSHFT_MASK &					\
	   next_timing->trim_perch_regs[EMC ## chan ##			\
			      _EMC_DATA_BRLSHFT_ ## rank ## _INDEX]) >>	\
	  EMC_DATA_BRLSHFT_ ## rank ## _RANK ## rank ## _BYTE ##	\
	  byte ## _DATA_BRLSHFT_SHIFT) * 64)

#define CALC_TEMP(rank, reg, byte1, byte2, n)				\
	((new[n] << EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ## rank ## _ ##	\
	  reg ## _OB_DDLL_LONG_DQ_RANK ## rank ## _BYTE ## byte1 ## _SHIFT) & \
	 EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ## rank ## _ ## reg ##		\
	 _OB_DDLL_LONG_DQ_RANK ## rank ## _BYTE ## byte1 ## _MASK)	\
	|								\
	((new[n + 1] << EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ## rank ## _ ##	\
	  reg ## _OB_DDLL_LONG_DQ_RANK ## rank ## _BYTE ## byte2 ## _SHIFT) & \
	 EMC_PMACRO_OB_DDLL_LONG_DQ_RANK ## rank ## _ ## reg ##		\
	 _OB_DDLL_LONG_DQ_RANK ## rank ## _BYTE ## byte2 ## _MASK)	\

static bool emc_enable = true;
module_param(emc_enable, bool, 0444);
static bool emc_force_max_rate;
module_param(emc_force_max_rate, bool, 0444);

enum TEGRA_EMC_SOURCE {
	TEGRA_EMC_SRC_PLLM,
	TEGRA_EMC_SRC_PLLC,
	TEGRA_EMC_SRC_PLLP,
	TEGRA_EMC_SRC_CLKM,
	TEGRA_EMC_SRC_PLLM_UD,
	TEGRA_EMC_SRC_PLLMB_UD,
	TEGRA_EMC_SRC_PLLMB,
	TEGRA_EMC_SRC_PLLP_UD,
	TEGRA_EMC_SRC_COUNT,
};

struct emc_sel {
	struct clk	*input;
	u32		value;
	unsigned long	input_rate;

	struct clk	*input_b;
	u32		value_b;
	unsigned long	input_rate_b;
};

#define DEFINE_REG(type, reg) (reg)
u32 burst_regs_per_ch_off[] = BURST_REGS_PER_CH_LIST;
u32 burst_regs_off[] = BURST_REGS_LIST;
u32 trim_regs_per_ch_off[] = TRIM_REGS_PER_CH_LIST;
u32 trim_regs_off[] = TRIM_REGS_LIST;
u32 burst_mc_regs_off[] = BURST_MC_REGS_LIST;
u32 la_scale_regs_off[] = BURST_UP_DOWN_REGS_LIST;
u32 vref_regs_per_ch_off[] = VREF_REGS_PER_CH_LIST;
#undef DEFINE_REG

#define DEFINE_REG(type, reg) (type)
u32 burst_regs_per_ch_type[] = BURST_REGS_PER_CH_LIST;
u32 trim_regs_per_ch_type[] = TRIM_REGS_PER_CH_LIST;
u32 vref_regs_per_ch_type[] = VREF_REGS_PER_CH_LIST;
#undef DEFINE_REG

static struct supported_sequence *seq;
static DEFINE_SPINLOCK(emc_access_lock);
static ktime_t clkchange_time;
int tegra_emc_table_size;
static int clkchange_delay = 100;
static int last_round_idx;
static int last_rate_idx;
static u32 tegra_dram_dev_num;
static u32 tegra_dram_type = -1;
static u32 tegra_ram_code;
static u32 current_clksrc;
static u32 timer_period_mr4 = 1000;
static u32 timer_period_training = 100;
static bool tegra_emc_init_done;
static void __iomem *emc_base;
static void __iomem *emc0_base;
static void __iomem *emc1_base;
static void __iomem *mc_base;
void __iomem *clk_base;
static unsigned long emc_max_rate;
#ifdef CONFIG_PM_SLEEP
static unsigned long emc_override_rate;
#endif
unsigned long dram_over_temp_state = TEGRA_DRAM_OVER_TEMP_NONE;
static struct emc_stats tegra_emc_stats;
struct emc_table *tegra_emc_table;
struct emc_table *tegra_emc_table_normal;
struct emc_table *tegra_emc_table_derated;
static struct emc_table *emc_timing;
static struct emc_table start_timing;
static struct emc_sel *emc_clk_sel;
static struct clk *emc_clk;
static struct clk *emc_override_clk;
static struct clk *tegra_emc_src[TEGRA_EMC_SRC_COUNT];
static const char *tegra_emc_src_names[TEGRA_EMC_SRC_COUNT] = {
	[TEGRA_EMC_SRC_PLLM] = "pll_m",
	[TEGRA_EMC_SRC_PLLC] = "pll_c",
	[TEGRA_EMC_SRC_PLLP] = "pll_p",
	[TEGRA_EMC_SRC_CLKM] = "clk_m",
	[TEGRA_EMC_SRC_PLLM_UD] = "pll_m_ud",
	[TEGRA_EMC_SRC_PLLMB_UD] = "pll_mb_ud",
	[TEGRA_EMC_SRC_PLLMB] = "pll_mb",
	[TEGRA_EMC_SRC_PLLP_UD] = "pll_p_ud",
};
static struct supported_sequence supported_seqs[] = {
	{
		0x5,
		emc_set_clock_r21012,
		NULL,
		"21012",
	},
	{
		0x6,
		emc_set_clock_r21015,
		__do_periodic_emc_compensation_r21015,
		"21018"
	},
	{
		0x7,
		emc_set_clock_r21021,
		__do_periodic_emc_compensation_r21021,
	},
	{
		0,
		NULL,
		NULL,
		NULL
	}
};

static int emc_get_dram_temperature(void);

/* MR4 parameters */
static u32 prev_temp = 0xffffffff; /* i.e -1. */
static u32 test_mode;
static int dram_temp_override;
static unsigned long mr4_freq_threshold;
static atomic_t mr4_temp_poll;
static atomic_t mr4_force_poll;
static atomic_t mr4_thresh_poll;

static void emc_mr4_poll(unsigned long nothing);
static struct timer_list emc_timer_mr4 =
	TIMER_DEFERRED_INITIALIZER(emc_mr4_poll, 0, 0);

static void emc_train(unsigned long nothing);
static struct timer_list emc_timer_training =
	TIMER_INITIALIZER(emc_train, 0, 0);

#ifdef CONFIG_DEBUG_FS
static u8 tegra210_emc_bw_efficiency = 80;
static u8 tegra210_emc_iso_share = 100;
static unsigned long last_iso_bw;
#endif

static u32 bw_calc_freqs[] = {
	5, 10, 20, 30, 40, 60, 80, 100, 120, 140, 160, 180,
	200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700
};

#ifdef CONFIG_DEBUG_FS
static u32 tegra210_lpddr3_iso_efficiency_os_idle[] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 63, 60, 54, 45, 45, 45, 45, 45, 45, 45
};
static u32 tegra210_lpddr3_iso_efficiency_general[] = {
	60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
	60, 59, 59, 58, 57, 56, 55, 54, 54, 54, 54
};

static u32 tegra210_lpddr4_iso_efficiency_os_idle[] = {
	56, 56, 56, 56, 56, 56, 56, 56, 56, 56, 56, 56,
	56, 56, 56, 56, 56, 56, 56, 56, 56, 49, 45
};
static u32 tegra210_lpddr4_iso_efficiency_general[] = {
	56, 55, 55, 54, 54, 53, 51, 50, 49, 48, 47, 46,
	45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45
};

static u32 tegra210_ddr3_iso_efficiency_os_idle[] = {
	65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
	65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65
};
static u32 tegra210_ddr3_iso_efficiency_general[] = {
	60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
	60, 59, 59, 58, 57, 56, 55, 54, 54, 54, 54
};

static u8 iso_share_calc_tegra210_os_idle(unsigned long iso_bw);
static u8 iso_share_calc_tegra210_general(unsigned long iso_bw);

static struct emc_iso_usage tegra210_emc_iso_usage[] = {
	{
		BIT(EMC_USER_DC1),
		80, iso_share_calc_tegra210_os_idle
	},
	{
		BIT(EMC_USER_DC2),
		80, iso_share_calc_tegra210_os_idle
	},
	{
		BIT(EMC_USER_DC1) | BIT(EMC_USER_DC2),
		50, iso_share_calc_tegra210_general
	},
	{
		BIT(EMC_USER_DC1) | BIT(EMC_USER_VI),
		50, iso_share_calc_tegra210_general
	},
	{
		BIT(EMC_USER_DC1) | BIT(EMC_USER_DC2) | BIT(EMC_USER_VI),
		50, iso_share_calc_tegra210_general
	},
};
#endif

inline void emc_writel(u32 val, unsigned long offset)
{
	writel(val, emc_base + offset);
}

inline u32 emc_readl(unsigned long offset)
{
	return readl(emc_base + offset);
}

inline void emc1_writel(u32 val, unsigned long offset)
{
	writel(val, emc1_base + offset);
}

inline u32 emc1_readl(unsigned long offset)
{
	return readl(emc1_base + offset);
}

inline void emc_writel_per_ch(u32 val, int type, unsigned long offset)
{
	switch (type) {
	case REG_EMC:
	case REG_EMC0:
		return writel(val, emc_base + offset);
	case REG_EMC1:
		return writel(val, emc1_base + offset);
	}
}

inline u32 emc_readl_per_ch(int type, unsigned long offset)
{
	u32 val = 0;
	switch (type) {
	case REG_EMC:
	case REG_EMC0:
		val = readl(emc_base + offset);
		break;
	case REG_EMC1:
		val = readl(emc1_base + offset);
		break;
	}
	return val;
}

inline void mc_writel(u32 val, unsigned long offset)
{
	writel(val, mc_base + offset);
}

inline u32 mc_readl(unsigned long offset)
{
	return readl(mc_base + offset);
}

static inline int get_start_idx(unsigned long rate)
{
	if (tegra_emc_table[last_round_idx].rate == rate)
		return last_round_idx;
	return 0;
}

static inline u32 emc_src_val(u32 val)
{
	return (val & EMC_CLK_EMC_2X_CLK_SRC_MASK) >>
		EMC_CLK_EMC_2X_CLK_SRC_SHIFT;
}

static inline u32 emc_div_val(u32 val)
{
	return (val & EMC_CLK_EMC_2X_CLK_DIVISOR_MASK) >>
		EMC_CLK_EMC_2X_CLK_DIVISOR_SHIFT;
}

inline void ccfifo_writel(u32 val, unsigned long addr, u32 delay)
{
	writel(val, emc_base + EMC_CCFIFO_DATA);
	writel((addr & 0xffff) | ((delay & 0x7fff) << 16) | (1 << 31),
		emc_base + EMC_CCFIFO_ADDR);
}

static void emc_mr4_poll(unsigned long nothing)
{
	int dram_temp;

	if (!test_mode)
		dram_temp = emc_get_dram_temperature();
	else
		dram_temp = dram_temp_override;

	if (prev_temp == dram_temp)
		goto reset;

	if (WARN(dram_temp < 0, "Unable to read DRAM temp (MR4)!\n"))
		goto reset;

	switch (dram_temp) {
	case 0:
	case 1:
	case 2:
	case 3:
		/*
		 * Temp is fine - go back to regular refresh.
		 */
		pr_info("Setting nominal refresh + timings.\n");
		tegra210_emc_set_over_temp_state(TEGRA_DRAM_OVER_TEMP_NONE);
		break;
	case 4:
		pr_info("Enabling 2x refresh.\n");
		tegra210_emc_set_over_temp_state(TEGRA_DRAM_OVER_TEMP_REFRESH_X2);
		break;
	case 5:
		pr_info("Enabling 4x refresh.\n");
		tegra210_emc_set_over_temp_state(TEGRA_DRAM_OVER_TEMP_REFRESH_X4);
		break;
	case 6:
		pr_info("Enabling 4x refresh + derating.\n");
		tegra210_emc_set_over_temp_state(TEGRA_DRAM_OVER_TEMP_THROTTLE);
		break;
	default:
		WARN(1, "%s: Invalid DRAM temp state %d\n",
		     __func__, dram_temp);
		break;
	}
	prev_temp = dram_temp;

reset:
	if (atomic_read(&mr4_temp_poll) == 0 &&
	    atomic_read(&mr4_force_poll) == 0 &&
	    atomic_read(&mr4_thresh_poll) == 0)
		return;

	if (mod_timer(&emc_timer_mr4,
		      jiffies + msecs_to_jiffies(timer_period_mr4)))
		pr_err("Failed to restart timer!!!\n");
}

/*
 * Tell the dram thermal driver to start/stop polling for the DRAM temperature.
 * This should be called when the DRAM temp might be hot, for example, if some
 * other temp sensor is reading very high.
 */
static void tegra_emc_mr4_temp_trigger(int do_poll)
{
	if (do_poll) {
		atomic_set(&mr4_temp_poll, 1);
		mod_timer(&emc_timer_mr4,
			  jiffies + msecs_to_jiffies(timer_period_mr4));
	} else {
		atomic_set(&mr4_temp_poll, 0);
	}
}

static void tegra_emc_mr4_thresh_trigger(int do_poll)
{
	if (do_poll) {
		atomic_set(&mr4_thresh_poll, 1);
		mod_timer(&emc_timer_mr4,
			  jiffies + msecs_to_jiffies(timer_period_mr4));
	} else {
		atomic_set(&mr4_thresh_poll, 0);
	}
}

/*
 * If the freq is higher than some threshold then poll. Only happens if a
 * threshold is actually defined.
 */
static void tegra_emc_mr4_freq_check(unsigned long freq)
{
	if (mr4_freq_threshold && freq >= mr4_freq_threshold)
		tegra_emc_mr4_thresh_trigger(1);
	else
		tegra_emc_mr4_thresh_trigger(0);
}

void tegra210_emc_mr4_set_freq_thresh(unsigned long thresh)
{
	mr4_freq_threshold = thresh;
}

static void emc_train(unsigned long nothing)
{
	unsigned long flags;

	if (!emc_timing)
		return;

	spin_lock_irqsave(&emc_access_lock, flags);
	if (seq->periodic_compensation)
		seq->periodic_compensation(emc_timing);
	spin_unlock_irqrestore(&emc_access_lock, flags);

	mod_timer(&emc_timer_training,
		  jiffies + msecs_to_jiffies(timer_period_training));
}

static void emc_timer_training_start(void)
{
	mod_timer(&emc_timer_training,
		  jiffies + msecs_to_jiffies(timer_period_training));
}

static void emc_timer_training_stop(void)
{
	del_timer(&emc_timer_training);
}

void tegra210_change_dll_src(struct emc_table *next_timing, u32 clksrc)
{
	u32 out_enb_x;
	u32 dll_setting = next_timing->dll_clk_src;
	u32 emc_clk_src;
	u32 emc_clk_div;

	out_enb_x = 0;
	emc_clk_src = (clksrc & EMC_CLK_EMC_2X_CLK_SRC_MASK) >>
		       EMC_CLK_EMC_2X_CLK_SRC_SHIFT;
	emc_clk_div = (clksrc & EMC_CLK_EMC_2X_CLK_DIVISOR_MASK) >>
		       EMC_CLK_EMC_2X_CLK_DIVISOR_SHIFT;

	dll_setting &= ~(DLL_CLK_EMC_DLL_CLK_SRC_MASK |
			 DLL_CLK_EMC_DLL_CLK_DIVISOR_MASK);
	dll_setting |= emc_clk_src << DLL_CLK_EMC_DLL_CLK_SRC_SHIFT;
	dll_setting |= emc_clk_div << DLL_CLK_EMC_DLL_CLK_DIVISOR_SHIFT;

	dll_setting &= ~DLL_CLK_EMC_DLL_DDLL_CLK_SEL_MASK;
	if (emc_clk_src == EMC_CLK_SOURCE_PLLMB_LJ)
		dll_setting |= (PLLM_VCOB <<
				DLL_CLK_EMC_DLL_DDLL_CLK_SEL_SHIFT);
	else if (emc_clk_src == EMC_CLK_SOURCE_PLLM_LJ)
		dll_setting |= (PLLM_VCOA <<
				DLL_CLK_EMC_DLL_DDLL_CLK_SEL_SHIFT);
	else
		dll_setting |= (EMC_DLL_SWITCH_OUT <<
				DLL_CLK_EMC_DLL_DDLL_CLK_SEL_SHIFT);

	writel(dll_setting, clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC_DLL);

	if (next_timing->clk_out_enb_x_0_clk_enb_emc_dll) {
		writel(CLK_OUT_ENB_X_CLK_ENB_EMC_DLL,
		       clk_base + CLK_RST_CONTROLLER_CLK_OUT_ENB_X_SET);
	} else {
		writel(CLK_OUT_ENB_X_CLK_ENB_EMC_DLL,
		       clk_base + CLK_RST_CONTROLLER_CLK_OUT_ENB_X_CLR);
	}
}

struct emc_table *get_timing_from_freq(unsigned long rate)
{
	int i;

	for (i = 0; i < tegra_emc_table_size; i++)
		if (tegra_emc_table[i].rate == rate)
			return &tegra_emc_table[i];

	return NULL;
}

int wait_for_update(u32 status_reg, u32 bit_mask, bool updated_state, int chan)
{
	int i, err = -ETIMEDOUT;
	u32 reg;

	for (i = 0; i < EMC_STATUS_UPDATE_TIMEOUT; i++) {
		reg = emc_readl_per_ch(chan, status_reg);
		if (!!(reg & bit_mask) == updated_state) {
			err = 0;
			goto done;
		}
		udelay(1);
	}

done:
	return err;
}

void do_clock_change(u32 clk_setting)
{
	int err;

	mc_readl(MC_EMEM_ADR_CFG);
	emc_readl(EMC_INTSTATUS);

	writel(clk_setting, clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC);
	readl(clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC);

	err = wait_for_update(EMC_INTSTATUS, EMC_INTSTATUS_CLKCHANGE_COMPLETE,
			      true, REG_EMC);
	if (err) {
		pr_err("%s: clock change completion error: %d", __func__, err);
		BUG();
	}
}

void emc_set_shadow_bypass(int set)
{
	u32 emc_dbg = emc_readl(EMC_DBG);

	if (set)
		emc_writel(emc_dbg | EMC_DBG_WRITE_MUX_ACTIVE, EMC_DBG);
	else
		emc_writel(emc_dbg & ~EMC_DBG_WRITE_MUX_ACTIVE, EMC_DBG);
}

u32 get_dll_state(struct emc_table *next_timing)
{
	bool next_dll_enabled;

	next_dll_enabled = !(next_timing->emc_emrs & 0x1);
	if (next_dll_enabled)
		return DLL_ON;
	else
		return DLL_OFF;
}

u32 div_o3(u32 a, u32 b)
{
	u32 result = a / b;

	if ((b * result) < a)
		return result + 1;
	else
		return result;
}

void emc_timing_update(int dual_chan)
{
	int err = 0;

	emc_writel(0x1, EMC_TIMING_CONTROL);
	err |= wait_for_update(EMC_EMC_STATUS,
			       EMC_EMC_STATUS_TIMING_UPDATE_STALLED, false,
			       REG_EMC);
	if (dual_chan)
		err |= wait_for_update(EMC_EMC_STATUS,
				       EMC_EMC_STATUS_TIMING_UPDATE_STALLED,
				       false, REG_EMC1);
	if (err) {
		pr_err("%s: timing update error: %d", __func__, err);
		BUG();
	}
}

void tegra210_update_emc_alt_timing(struct emc_table *current_timing)
{
	struct emc_table *current_table, *alt_timing;
	int i;

	if (!tegra_emc_table_derated)
		return;

	current_table = emc_get_table(dram_over_temp_state);
	i = current_timing - current_table;

	BUG_ON(i < 0 || i > tegra_emc_table_size);

	if (dram_over_temp_state == TEGRA_DRAM_OVER_TEMP_THROTTLE)
		alt_timing = &tegra_emc_table_normal[i];
	else
		alt_timing = &tegra_emc_table_derated[i];

	__emc_copy_table_params(current_timing, alt_timing,
				EMC_COPY_TABLE_PARAM_PERIODIC_FIELDS);
}

static void emc_copy_table_params(struct emc_table *src,
				  struct emc_table *dst,
				  int table_size,
				  int flags)
{
	int i;

	for (i = 0; i < table_size; i++)
		__emc_copy_table_params(&src[i], &dst[i], flags);
}

u32 tegra210_actual_osc_clocks(u32 in)
{
	if (in < 0x40)
		return in * 16;
	else if (in < 0x80)
		return 2048;
	else if (in < 0xc0)
		return 4096;
	else
		return 8192;
}

void tegra210_start_periodic_compensation(void)
{
	u32 mpc_req = 0x4b;

	emc_writel(mpc_req, EMC_MPC);
	mpc_req = emc_readl(EMC_MPC);
}

u32 tegra210_apply_periodic_compensation_trimmer(
		struct emc_table *next_timing, u32 offset)
{
	u32 i, temp = 0;
	u32 next_timing_rate_mhz = next_timing->rate / 1000;
	s32 tree_delta[4];
	s32 tree_delta_taps[4];
	s32 new[] = {
		TRIM_REG(0, 0, 0, 0),
		TRIM_REG(0, 0, 0, 1),
		TRIM_REG(0, 0, 1, 2),
		TRIM_REG(0, 0, 1, 3),

		TRIM_REG(1, 0, 2, 4),
		TRIM_REG(1, 0, 2, 5),
		TRIM_REG(1, 0, 3, 6),
		TRIM_REG(1, 0, 3, 7),

		TRIM_REG(0, 1, 0, 0),
		TRIM_REG(0, 1, 0, 1),
		TRIM_REG(0, 1, 1, 2),
		TRIM_REG(0, 1, 1, 3),

		TRIM_REG(1, 1, 2, 4),
		TRIM_REG(1, 1, 2, 5),
		TRIM_REG(1, 1, 3, 6),
		TRIM_REG(1, 1, 3, 7)
	};

	switch (offset) {
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_0:
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_1:
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_2:
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_3:
	case EMC_DATA_BRLSHFT_0:
		tree_delta[0] = 128 *
				(next_timing->current_dram_clktree_c0d0u0 -
				 next_timing->trained_dram_clktree_c0d0u0);
		tree_delta[1] = 128 *
				(next_timing->current_dram_clktree_c0d0u1 -
				 next_timing->trained_dram_clktree_c0d0u1);
		tree_delta[2] = 128 *
				(next_timing->current_dram_clktree_c1d0u0 -
				 next_timing->trained_dram_clktree_c1d0u0);
		tree_delta[3] = 128 *
				(next_timing->current_dram_clktree_c1d0u1 -
				 next_timing->trained_dram_clktree_c1d0u1);

		tree_delta_taps[0] = (tree_delta[0] *
				     (s32)next_timing_rate_mhz) / 1000000;
		tree_delta_taps[1] = (tree_delta[1] *
				     (s32)next_timing_rate_mhz) / 1000000;
		tree_delta_taps[2] = (tree_delta[2] *
				     (s32)next_timing_rate_mhz) / 1000000;
		tree_delta_taps[3] = (tree_delta[3] *
				     (s32)next_timing_rate_mhz) / 1000000;

		for (i = 0; i < 4; i++) {
			if ((tree_delta_taps[i] > next_timing->tree_margin) ||
			    (tree_delta_taps[i] <
			    (-1 * next_timing->tree_margin))) {
				new[i * 2] = new[i * 2] + tree_delta_taps[i];
				new[i * 2 + 1] = new[i * 2 + 1] +
						 tree_delta_taps[i];
			}
		}

		if (offset == EMC_DATA_BRLSHFT_0) {
			for (i = 0; i < 8; i++)
				new[i] = new[i] / 64;
		} else {
			for (i = 0; i < 8; i++)
				new[i] = new[i] % 64;
		}
		break;

	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_0:
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_1:
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_2:
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_3:
	case EMC_DATA_BRLSHFT_1:
		tree_delta[0] = 128 *
				(next_timing->current_dram_clktree_c0d1u0 -
				 next_timing->trained_dram_clktree_c0d1u0);
		tree_delta[1] = 128 *
				(next_timing->current_dram_clktree_c0d1u1 -
				 next_timing->trained_dram_clktree_c0d1u1);
		tree_delta[2] = 128 *
				(next_timing->current_dram_clktree_c1d1u0 -
				 next_timing->trained_dram_clktree_c1d1u0);
		tree_delta[3] = 128 *
				(next_timing->current_dram_clktree_c1d1u1 -
				 next_timing->trained_dram_clktree_c1d1u1);

		tree_delta_taps[0] = (tree_delta[0] *
				     (s32)next_timing_rate_mhz) / 1000000;
		tree_delta_taps[1] = (tree_delta[1] *
				     (s32)next_timing_rate_mhz) / 1000000;
		tree_delta_taps[2] = (tree_delta[2] *
				     (s32)next_timing_rate_mhz) / 1000000;
		tree_delta_taps[3] = (tree_delta[3] *
				     (s32)next_timing_rate_mhz) / 1000000;

		for (i = 0; i < 4; i++) {
			if ((tree_delta_taps[i] > next_timing->tree_margin) ||
			    (tree_delta_taps[i] <
			     (-1 * next_timing->tree_margin))) {
				new[8 + i * 2] = new[8 + i * 2] +
						 tree_delta_taps[i];
				new[8 + i * 2 + 1] = new[8 + i * 2 + 1] +
						     tree_delta_taps[i];
			}
		}

		if (offset == EMC_DATA_BRLSHFT_1) {
			for (i = 0; i < 8; i++)
				new[i + 8] = new[i + 8] / 64;
		} else {
			for (i = 0; i < 8; i++)
				new[i + 8] = new[i + 8] % 64;
		}
		break;
	}

	switch (offset) {
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_0:
		temp = CALC_TEMP(0, 0, 0, 1, 0);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_1:
		temp = CALC_TEMP(0, 1, 2, 3, 2);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_2:
		temp = CALC_TEMP(0, 2, 4, 5, 4);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK0_3:
		temp = CALC_TEMP(0, 3, 6, 7, 6);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_0:
		temp = CALC_TEMP(1, 0, 0, 1, 8);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_1:
		temp = CALC_TEMP(1, 1, 2, 3, 10);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_2:
		temp = CALC_TEMP(1, 2, 4, 5, 12);
		break;
	case EMC_PMACRO_OB_DDLL_LONG_DQ_RANK1_3:
		temp = CALC_TEMP(1, 3, 6, 7, 14);
		break;
	case EMC_DATA_BRLSHFT_0:
		temp = ((new[0] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE0_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE0_DATA_BRLSHFT_MASK) |
		       ((new[1] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE1_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE1_DATA_BRLSHFT_MASK) |
		       ((new[2] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE2_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE2_DATA_BRLSHFT_MASK) |
		       ((new[3] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE3_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE3_DATA_BRLSHFT_MASK) |
		       ((new[4] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE4_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE4_DATA_BRLSHFT_MASK) |
		       ((new[5] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE5_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE5_DATA_BRLSHFT_MASK) |
		       ((new[6] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE6_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE6_DATA_BRLSHFT_MASK) |
		       ((new[7] <<
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE7_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_0_RANK0_BYTE7_DATA_BRLSHFT_MASK);
		break;
	case EMC_DATA_BRLSHFT_1:
		temp = ((new[8] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE0_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE0_DATA_BRLSHFT_MASK) |
		       ((new[9] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE1_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE1_DATA_BRLSHFT_MASK) |
		       ((new[10] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE2_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE2_DATA_BRLSHFT_MASK) |
		       ((new[11] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE3_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE3_DATA_BRLSHFT_MASK) |
		       ((new[12] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE4_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE4_DATA_BRLSHFT_MASK) |
		       ((new[13] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE5_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE5_DATA_BRLSHFT_MASK) |
		       ((new[14] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE6_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE6_DATA_BRLSHFT_MASK) |
		       ((new[15] <<
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE7_DATA_BRLSHFT_SHIFT) &
			 EMC_DATA_BRLSHFT_1_RANK1_BYTE7_DATA_BRLSHFT_MASK);
		break;
	default:
		break;
	}

	return temp;
}

u32 tegra210_dll_prelock(struct emc_table *next_timing,
			 int dvfs_with_training, u32 clksrc)
{
	u32 emc_dig_dll_status;
	u32 dll_locked;
	u32 dll_out;
	u32 emc_cfg_dig_dll;
	u32 emc_dll_cfg_0;
	u32 emc_dll_cfg_1;
	u32 ddllcal_ctrl_start_trim_val;
	u32 dll_en;
	u32 dual_channel_lpddr4_case;
	u32 dll_priv_updated;

	dual_channel_lpddr4_case =
		      !!(emc_readl(EMC_FBIO_CFG7) & EMC_FBIO_CFG7_CH1_ENABLE) &
		      !!(emc_readl(EMC_FBIO_CFG7) & EMC_FBIO_CFG7_CH0_ENABLE);

	emc_dig_dll_status = 0;
	dll_locked = 0;
	dll_out = 0;
	emc_cfg_dig_dll = 0;
	emc_dll_cfg_0 = 0;
	emc_dll_cfg_1 = 0;
	ddllcal_ctrl_start_trim_val = 0;
	dll_en = 0;

	emc_cfg_dig_dll = emc_readl(EMC_CFG_DIG_DLL) &
			  ~EMC_CFG_DIG_DLL_CFG_DLL_LOCK_LIMIT_MASK;
	emc_cfg_dig_dll |= (3 << EMC_CFG_DIG_DLL_CFG_DLL_LOCK_LIMIT_SHIFT);
	emc_cfg_dig_dll &= ~EMC_CFG_DIG_DLL_CFG_DLL_EN;
	emc_cfg_dig_dll &= ~EMC_CFG_DIG_DLL_CFG_DLL_MODE_MASK;
	emc_cfg_dig_dll |= (3 << EMC_CFG_DIG_DLL_CFG_DLL_MODE_SHIFT);
	emc_cfg_dig_dll |= EMC_CFG_DIG_DLL_CFG_DLL_STALL_ALL_TRAFFIC;
	emc_cfg_dig_dll &= ~EMC_CFG_DIG_DLL_CFG_DLL_STALL_RW_UNTIL_LOCK;
	emc_cfg_dig_dll &= ~EMC_CFG_DIG_DLL_CFG_DLL_STALL_ALL_UNTIL_LOCK;

	emc_writel(emc_cfg_dig_dll, EMC_CFG_DIG_DLL);
	emc_writel(1, EMC_TIMING_CONTROL);

	wait_for_update(EMC_EMC_STATUS,
			EMC_EMC_STATUS_TIMING_UPDATE_STALLED, 0, REG_EMC);
	if (dual_channel_lpddr4_case)
		wait_for_update(EMC_EMC_STATUS,
				EMC_EMC_STATUS_TIMING_UPDATE_STALLED,
				0, REG_EMC1);

	do {
		emc_cfg_dig_dll = emc_readl(EMC_CFG_DIG_DLL);
		dll_en = emc_cfg_dig_dll & EMC_CFG_DIG_DLL_CFG_DLL_EN;
	} while (dll_en == 1);

	if (dual_channel_lpddr4_case) {
		do {
			emc_cfg_dig_dll = emc1_readl(EMC_CFG_DIG_DLL);
			dll_en = emc_cfg_dig_dll & EMC_CFG_DIG_DLL_CFG_DLL_EN;
		} while (dll_en == 1);
	}

	emc_dll_cfg_0 = next_timing->burst_regs[EMC_DLL_CFG_0_INDEX];

	emc_writel(emc_dll_cfg_0, EMC_DLL_CFG_0);

	if (next_timing->rate >= 400000 && next_timing->rate < 600000)
		ddllcal_ctrl_start_trim_val = 150;
	else if (next_timing->rate >= 600000 && next_timing->rate < 800000)
		ddllcal_ctrl_start_trim_val = 100;
	else if (next_timing->rate >= 800000 && next_timing->rate < 1000000)
		ddllcal_ctrl_start_trim_val = 70;
	else if (next_timing->rate >= 1000000 && next_timing->rate < 1200000)
		ddllcal_ctrl_start_trim_val = 30;
	else
		ddllcal_ctrl_start_trim_val = 20;

	emc_dll_cfg_1 = emc_readl(EMC_DLL_CFG_1);
	emc_dll_cfg_1 &= EMC_DLL_CFG_1_DDLLCAL_CTRL_START_TRIM_MASK;
	emc_dll_cfg_1 |= ddllcal_ctrl_start_trim_val;
	emc_writel(emc_dll_cfg_1, EMC_DLL_CFG_1);

	tegra210_change_dll_src(next_timing, clksrc);

	emc_cfg_dig_dll = emc_readl(EMC_CFG_DIG_DLL);
	emc_cfg_dig_dll |= EMC_CFG_DIG_DLL_CFG_DLL_EN;
	emc_writel(emc_cfg_dig_dll, EMC_CFG_DIG_DLL);

	emc_timing_update(dual_channel_lpddr4_case ?
			  DUAL_CHANNEL : SINGLE_CHANNEL);

	do {
		emc_cfg_dig_dll = emc_readl(EMC_CFG_DIG_DLL);
		dll_en = emc_cfg_dig_dll & EMC_CFG_DIG_DLL_CFG_DLL_EN;
	} while (dll_en == 0);

	if (dual_channel_lpddr4_case) {
		do {
			emc_cfg_dig_dll = emc1_readl(EMC_CFG_DIG_DLL);
			dll_en = emc_cfg_dig_dll & EMC_CFG_DIG_DLL_CFG_DLL_EN;
		} while (dll_en == 0);
	}

	do {
		emc_dig_dll_status = emc_readl(EMC_DIG_DLL_STATUS);
		dll_locked = emc_dig_dll_status & EMC_DIG_DLL_STATUS_DLL_LOCK;
		dll_priv_updated = emc_dig_dll_status &
				   EMC_DIG_DLL_STATUS_DLL_PRIV_UPDATED;
	} while (!dll_locked || !dll_priv_updated);

	emc_dig_dll_status = emc_readl(EMC_DIG_DLL_STATUS);
	return emc_dig_dll_status & EMC_DIG_DLL_STATUS_DLL_OUT_MASK;
}

u32 tegra210_dvfs_power_ramp_up(u32 clk, int flip_backward,
				struct emc_table *last_timing,
				struct emc_table *next_timing)
{
	u32 pmacro_cmd_pad;
	u32 pmacro_dq_pad;
	u32 pmacro_rfu1;
	u32 pmacro_cfg5;
	u32 pmacro_common_tx;
	u32 ramp_up_wait = 0;

	if (flip_backward) {
		pmacro_cmd_pad   = last_timing->
			burst_regs[EMC_PMACRO_CMD_PAD_TX_CTRL_INDEX];
		pmacro_dq_pad    = last_timing->
			burst_regs[EMC_PMACRO_DATA_PAD_TX_CTRL_INDEX];
		pmacro_rfu1      = last_timing->
			burst_regs[EMC_PMACRO_BRICK_CTRL_RFU1_INDEX];
		pmacro_cfg5      = last_timing->burst_regs[EMC_FBIO_CFG5_INDEX];
		pmacro_common_tx = last_timing->
			burst_regs[EMC_PMACRO_COMMON_PAD_TX_CTRL_INDEX];
	} else {
		pmacro_cmd_pad   = next_timing->
			burst_regs[EMC_PMACRO_CMD_PAD_TX_CTRL_INDEX];
		pmacro_dq_pad    = next_timing->
			burst_regs[EMC_PMACRO_DATA_PAD_TX_CTRL_INDEX];
		pmacro_rfu1      = next_timing->
			burst_regs[EMC_PMACRO_BRICK_CTRL_RFU1_INDEX];
		pmacro_cfg5      = next_timing->burst_regs[EMC_FBIO_CFG5_INDEX];
		pmacro_common_tx = next_timing->
			burst_regs[EMC_PMACRO_COMMON_PAD_TX_CTRL_INDEX];
	}
	pmacro_cmd_pad |= EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_DRVFORCEON;

	if (clk < 1000000 / DVFS_FGCG_MID_SPEED_THRESHOLD) {
		ccfifo_writel(pmacro_common_tx & 0xa,
			      EMC_PMACRO_COMMON_PAD_TX_CTRL, 0);
		ccfifo_writel(pmacro_common_tx & 0xf,
			      EMC_PMACRO_COMMON_PAD_TX_CTRL,
			      (100000 / clk) + 1);
		ramp_up_wait += 100000;
	} else {
		ccfifo_writel(pmacro_common_tx | 0x8,
			      EMC_PMACRO_COMMON_PAD_TX_CTRL, 0);
	}

	if (clk < 1000000 / DVFS_FGCG_HIGH_SPEED_THRESHOLD) {
		if (clk < 1000000 / IOBRICK_DCC_THRESHOLD) {
			pmacro_cmd_pad |=
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSP_TX_E_DCC |
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSN_TX_E_DCC;
			pmacro_cmd_pad &=
				~(EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_E_DCC |
				  EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_CMD_TX_E_DCC);
			ccfifo_writel(pmacro_cmd_pad,
				      EMC_PMACRO_CMD_PAD_TX_CTRL,
				      (100000 / clk) + 1);
			ramp_up_wait += 100000;

			pmacro_dq_pad |=
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSP_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSN_TX_E_DCC;
			pmacro_dq_pad &=
			       ~(EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQ_TX_E_DCC |
				 EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_CMD_TX_E_DCC);
			ccfifo_writel(pmacro_dq_pad,
				      EMC_PMACRO_DATA_PAD_TX_CTRL, 0);
			ccfifo_writel(pmacro_rfu1 & 0xfe40fe40,
				      EMC_PMACRO_BRICK_CTRL_RFU1, 0);
		} else {
			ccfifo_writel(pmacro_rfu1 & 0xfe40fe40,
				      EMC_PMACRO_BRICK_CTRL_RFU1,
				      (100000 / clk) + 1);
			ramp_up_wait += 100000;
		}

		ccfifo_writel(pmacro_rfu1 & 0xfeedfeed,
			      EMC_PMACRO_BRICK_CTRL_RFU1, (100000 / clk) + 1);
		ramp_up_wait += 100000;

		if (clk < 1000000 / IOBRICK_DCC_THRESHOLD) {
			pmacro_cmd_pad |=
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSP_TX_E_DCC |
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSN_TX_E_DCC |
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_E_DCC |
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_CMD_TX_E_DCC;
			ccfifo_writel(pmacro_cmd_pad,
				      EMC_PMACRO_CMD_PAD_TX_CTRL,
				      (100000 / clk) + 1);
			ramp_up_wait += 100000;

			pmacro_dq_pad |=
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSP_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSN_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQ_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_CMD_TX_E_DCC;
			ccfifo_writel(pmacro_dq_pad,
				      EMC_PMACRO_DATA_PAD_TX_CTRL, 0);
			ccfifo_writel(pmacro_rfu1,
				      EMC_PMACRO_BRICK_CTRL_RFU1, 0);
		} else {
			ccfifo_writel(pmacro_rfu1,
				      EMC_PMACRO_BRICK_CTRL_RFU1,
				      (100000 / clk) + 1);
			ramp_up_wait += 100000;
		}

		ccfifo_writel(pmacro_cfg5 & ~EMC_FBIO_CFG5_CMD_TX_DIS,
			      EMC_FBIO_CFG5, (100000 / clk) + 10);
		ramp_up_wait += 100000 + (10 * clk);
	} else if (clk < 1000000 / DVFS_FGCG_MID_SPEED_THRESHOLD) {
		ccfifo_writel(pmacro_rfu1 | 0x06000600,
			      EMC_PMACRO_BRICK_CTRL_RFU1, (100000 / clk) + 1);
		ccfifo_writel(pmacro_cfg5 & ~EMC_FBIO_CFG5_CMD_TX_DIS,
			      EMC_FBIO_CFG5, (100000 / clk) + 10);
		ramp_up_wait += 100000 + 10 * clk;
	} else {
		ccfifo_writel(pmacro_rfu1 | 0x00000600,
			      EMC_PMACRO_BRICK_CTRL_RFU1, 0);
		ccfifo_writel(pmacro_cfg5 & ~EMC_FBIO_CFG5_CMD_TX_DIS,
			      EMC_FBIO_CFG5, 12);
		ramp_up_wait += 12 * clk;
	}

	pmacro_cmd_pad &= ~EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_DRVFORCEON;
	ccfifo_writel(pmacro_cmd_pad, EMC_PMACRO_CMD_PAD_TX_CTRL, 5);

	return ramp_up_wait;
}

u32 tegra210_dvfs_power_ramp_down(u32 clk, int flip_backward,
				  struct emc_table *last_timing,
				  struct emc_table *next_timing)
{
	u32 ramp_down_wait = 0;
	u32 pmacro_cmd_pad;
	u32 pmacro_dq_pad;
	u32 pmacro_rfu1;
	u32 pmacro_cfg5;
	u32 pmacro_common_tx;
	u32 seq_wait;

	if (flip_backward) {
		pmacro_cmd_pad   = next_timing->
			burst_regs[EMC_PMACRO_CMD_PAD_TX_CTRL_INDEX];
		pmacro_dq_pad    = next_timing->
			burst_regs[EMC_PMACRO_DATA_PAD_TX_CTRL_INDEX];
		pmacro_rfu1      = next_timing->
			burst_regs[EMC_PMACRO_BRICK_CTRL_RFU1_INDEX];
		pmacro_cfg5      = next_timing->
			burst_regs[EMC_FBIO_CFG5_INDEX];
		pmacro_common_tx = next_timing->
			burst_regs[EMC_PMACRO_COMMON_PAD_TX_CTRL_INDEX];
	} else {
		pmacro_cmd_pad   = last_timing->
			burst_regs[EMC_PMACRO_CMD_PAD_TX_CTRL_INDEX];
		pmacro_dq_pad    = last_timing->
			burst_regs[EMC_PMACRO_DATA_PAD_TX_CTRL_INDEX];
		pmacro_rfu1      = last_timing->
			burst_regs[EMC_PMACRO_BRICK_CTRL_RFU1_INDEX];
		pmacro_cfg5      = last_timing->
			burst_regs[EMC_FBIO_CFG5_INDEX];
		pmacro_common_tx = last_timing->
			burst_regs[EMC_PMACRO_COMMON_PAD_TX_CTRL_INDEX];
	}

	pmacro_cmd_pad |= EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_DRVFORCEON;

	ccfifo_writel(pmacro_cmd_pad, EMC_PMACRO_CMD_PAD_TX_CTRL, 0);
	ccfifo_writel(pmacro_cfg5 | EMC_FBIO_CFG5_CMD_TX_DIS, EMC_FBIO_CFG5,
		      12);
	ramp_down_wait = 12 * clk;

	seq_wait = (100000 / clk) + 1;

	if (clk < (1000000 / DVFS_FGCG_HIGH_SPEED_THRESHOLD)) {
		if (clk < (1000000 / IOBRICK_DCC_THRESHOLD)) {
			pmacro_cmd_pad &=
				~(EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_E_DCC |
				  EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_CMD_TX_E_DCC);
			pmacro_cmd_pad |=
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSP_TX_E_DCC |
				EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSN_TX_E_DCC;
			ccfifo_writel(pmacro_cmd_pad,
				      EMC_PMACRO_CMD_PAD_TX_CTRL, seq_wait);
			ramp_down_wait += 100000;

			pmacro_dq_pad &=
			      ~(EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQ_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_CMD_TX_E_DCC);
			pmacro_dq_pad |=
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSP_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSN_TX_E_DCC;
			ccfifo_writel(pmacro_dq_pad,
				      EMC_PMACRO_DATA_PAD_TX_CTRL, 0);
			ccfifo_writel(pmacro_rfu1 & ~0x01120112,
				      EMC_PMACRO_BRICK_CTRL_RFU1, 0);
		} else {
			ccfifo_writel(pmacro_rfu1 & ~0x01120112,
				      EMC_PMACRO_BRICK_CTRL_RFU1, seq_wait);
			ramp_down_wait += 100000;
		}

		ccfifo_writel(pmacro_rfu1 & ~0x01bf01bf,
			      EMC_PMACRO_BRICK_CTRL_RFU1, seq_wait);
		ramp_down_wait += 100000;

		if (clk < (1000000 / IOBRICK_DCC_THRESHOLD)) {
			pmacro_cmd_pad &=
				~(EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQ_TX_E_DCC |
				  EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_CMD_TX_E_DCC |
				  EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSP_TX_E_DCC |
				  EMC_PMACRO_CMD_PAD_TX_CTRL_CMD_DQSN_TX_E_DCC);
			ccfifo_writel(pmacro_cmd_pad,
				      EMC_PMACRO_CMD_PAD_TX_CTRL, seq_wait);
			ramp_down_wait += 100000;

			pmacro_dq_pad &=
			      ~(EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQ_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_CMD_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSP_TX_E_DCC |
				EMC_PMACRO_DATA_PAD_TX_CTRL_DATA_DQSN_TX_E_DCC);
			ccfifo_writel(pmacro_dq_pad,
				      EMC_PMACRO_DATA_PAD_TX_CTRL, 0);
			ccfifo_writel(pmacro_rfu1 & ~0x07ff07ff,
				      EMC_PMACRO_BRICK_CTRL_RFU1, 0);
		} else {
			ccfifo_writel(pmacro_rfu1 & ~0x07ff07ff,
				      EMC_PMACRO_BRICK_CTRL_RFU1, seq_wait);
			ramp_down_wait += 100000;
		}
	} else {
		ccfifo_writel(pmacro_rfu1 & ~0xffff07ff,
			      EMC_PMACRO_BRICK_CTRL_RFU1, seq_wait + 19);
		ramp_down_wait += 100000 + (20 * clk);
	}

	if (clk < (1000000 / DVFS_FGCG_MID_SPEED_THRESHOLD)) {
		ramp_down_wait += 100000;
		ccfifo_writel(pmacro_common_tx & ~0x5,
			      EMC_PMACRO_COMMON_PAD_TX_CTRL, seq_wait);
		ramp_down_wait += 100000;
		ccfifo_writel(pmacro_common_tx & ~0xf,
			      EMC_PMACRO_COMMON_PAD_TX_CTRL, seq_wait);
		ramp_down_wait += 100000;
		ccfifo_writel(0, 0, seq_wait);
		ramp_down_wait += 100000;
	} else {
		ccfifo_writel(pmacro_common_tx & ~0xf,
			      EMC_PMACRO_COMMON_PAD_TX_CTRL, seq_wait);
	}

	return ramp_down_wait;
}

void tegra210_reset_dram_clktree_values(struct emc_table *table)
{
	#define __RESET_CLKTREE(TBL, C, D, U)				\
	TBL->current_dram_clktree_c ## C ## d ## D ## u ## U =		\
	TBL->trained_dram_clktree_c ## C ## d ## D ## u ## U

	__RESET_CLKTREE(table, 0, 0, 0);
	__RESET_CLKTREE(table, 0, 0, 1);
	__RESET_CLKTREE(table, 1, 0, 0);
	__RESET_CLKTREE(table, 1, 0, 1);
	__RESET_CLKTREE(table, 1, 1, 0);
	__RESET_CLKTREE(table, 1, 1, 1);
}

static void update_dll_control(u32 emc_cfg_dig_dll,
		int channel_mode, bool updated_state)
{
	emc_writel(emc_cfg_dig_dll, EMC_CFG_DIG_DLL);
	emc_timing_update(channel_mode);

	wait_for_update(EMC_CFG_DIG_DLL, EMC_CFG_DIG_DLL_CFG_DLL_EN,
			updated_state, REG_EMC);
	if (channel_mode == DUAL_CHANNEL)
		wait_for_update(EMC_CFG_DIG_DLL,
				EMC_CFG_DIG_DLL_CFG_DLL_EN,
				updated_state, REG_EMC1);
}

void tegra210_dll_disable(int channel_mode)
{
	u32 emc_cfg_dig_dll;

	emc_cfg_dig_dll = emc_readl(EMC_CFG_DIG_DLL);
	emc_cfg_dig_dll &= ~EMC_CFG_DIG_DLL_CFG_DLL_EN;

	update_dll_control(emc_cfg_dig_dll, channel_mode, false);
}

void tegra210_dll_enable(int channel_mode)
{
	u32 emc_cfg_dig_dll;

	emc_cfg_dig_dll = emc_readl(EMC_CFG_DIG_DLL);
	emc_cfg_dig_dll |= EMC_CFG_DIG_DLL_CFG_DLL_EN;

	update_dll_control(emc_cfg_dig_dll, channel_mode, true);
}

void tegra210_emc_timing_invalidate(void)
{
	emc_timing = NULL;
}
EXPORT_SYMBOL(tegra210_emc_timing_invalidate);

static enum {
	BPMP_EMC_UNKNOWN,
	BPMP_EMC_VALID,
	BPMP_EMC_INVALID,
} bpmp_emc_table_state = BPMP_EMC_UNKNOWN;
static struct mrq_emc_dvfs_table_response bpmp_emc_table;

static void tegra210_bpmp_emc_table_get(void)
{
	if (!tegra_bpmp_send_receive(MRQ_EMC_DVFS_TABLE, NULL, 0,
				     &bpmp_emc_table,
				     sizeof(bpmp_emc_table)))
		bpmp_emc_table_state = BPMP_EMC_VALID;
	else
		bpmp_emc_table_state = BPMP_EMC_INVALID;
}

bool tegra210_emc_is_ready(void)
{
	if (bpmp_emc_table_state == BPMP_EMC_UNKNOWN)
		tegra210_bpmp_emc_table_get();
	return tegra_emc_init_done || bpmp_emc_table_state == BPMP_EMC_VALID;
}
EXPORT_SYMBOL(tegra210_emc_is_ready);

unsigned long tegra210_predict_emc_rate(int millivolts)
{
	int i;
	unsigned long ret = 0;

	if (bpmp_emc_table_state == BPMP_EMC_UNKNOWN)
		tegra210_bpmp_emc_table_get();

	if (bpmp_emc_table_state == BPMP_EMC_VALID) {
		for (i = 0; i < bpmp_emc_table.num_pairs; ++i) {
			if (bpmp_emc_table.pairs[i].mv > millivolts)
				break;
			ret = bpmp_emc_table.pairs[i].freq * 1000;
		}
		return ret;
	}

	if (!emc_enable)
		return -ENODEV;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return -EINVAL;

	for (i = 0; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;
		if (tegra_emc_table[i].min_volt > millivolts)
			break;
		ret = tegra_emc_table[i].rate * 1000;
	}

	return ret;
}
EXPORT_SYMBOL(tegra210_predict_emc_rate);

static unsigned long tegra210_emc_get_rate(void)
{
	u32 val;
	u32 div_value;
	u32 src_value;
	unsigned long rate;

	if (!emc_enable)
		return -ENODEV;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return -EINVAL;

	val = readl(clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC);

	div_value = emc_div_val(val);
	src_value = emc_src_val(val);

	rate = clk_get_rate(tegra_emc_src[src_value]);

	do_div(rate, div_value + 2);

	return rate * 2;
}

static long tegra210_emc_round_rate(unsigned long rate)
{
	int i;
	int max = 0;

	if (!emc_enable)
		return 0;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return 0;

	if (emc_force_max_rate)
		return tegra_emc_table[tegra_emc_table_size - 1].rate * 1000;

	rate /= 1000;
	i = get_start_idx(rate);
	for (; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;

		max = i;
		if (tegra_emc_table[i].rate >= rate) {
			last_round_idx = i;
			return tegra_emc_table[i].rate * 1000;
		}
	}

	return tegra_emc_table[max].rate * 1000;
}

unsigned int tegra210_emc_get_clk_latency(unsigned long rate)
{
	int i, index = -1;

	if (!emc_enable || !tegra_emc_init_done || !tegra_emc_table_size)
		return TEGRA_EMC_DEFAULT_CLK_LATENCY_US;

	if (emc_force_max_rate)
		rate = tegra_emc_table[tegra_emc_table_size - 1].rate * 1000;

	rate /= 1000;
	for (i = 0; i < tegra_emc_table_size; i++) {
		if (tegra_emc_table[i].rate > rate)
			break;

		index = i;
	}

	if (index > 0 && tegra_emc_table[index].latency)
		return tegra_emc_table[index].latency;

	return TEGRA_EMC_DEFAULT_CLK_LATENCY_US;
}
EXPORT_SYMBOL(tegra210_emc_get_clk_latency);

static inline void emc_get_timing(struct emc_table *timing)
{
	int i;

	for (i = 0; i < timing->num_burst; i++) {
		if (burst_regs_off[i])
			timing->burst_regs[i] = emc_readl(burst_regs_off[i]);
		else
			timing->burst_regs[i] = 0;
	}

	for (i = 0; i < timing->num_burst_per_ch; i++)
		timing->burst_reg_per_ch[i] = emc_readl_per_ch(
			burst_regs_per_ch_type[i], burst_regs_per_ch_off[i]);

	for (i = 0; i < timing->num_trim; i++)
		timing->trim_regs[i] = emc_readl(trim_regs_off[i]);

	for (i = 0; i < timing->num_trim_per_ch; i++)
		timing->trim_perch_regs[i] = emc_readl_per_ch(
			trim_regs_per_ch_type[i], trim_regs_per_ch_off[i]);

	for (i = 0; i < timing->vref_num; i++)
		timing->vref_perch_regs[i] = emc_readl_per_ch(
			vref_regs_per_ch_type[i], vref_regs_per_ch_off[i]);

	for (i = 0; i < timing->num_mc_regs; i++)
		timing->burst_mc_regs[i] = mc_readl(burst_mc_regs_off[i]);

	for (i = 0; i < timing->num_up_down; i++)
		timing->la_scale_regs[i] = mc_readl(la_scale_regs_off[i]);

	timing->rate = clk_get_rate(emc_clk) / 1000;
}

static void emc_set_clock(struct emc_table *next_timing,
		struct emc_table *last_timing, int training, u32 clksrc)
{
	current_clksrc = clksrc;
	seq->set_clock(next_timing, last_timing, training, clksrc);

	if (next_timing->periodic_training)
		emc_timer_training_start();
	else
		emc_timer_training_stop();
	/* EMC freq dependent MR4 polling. */
	tegra_emc_mr4_freq_check(next_timing->rate);
}

static void emc_last_stats_update(int last_sel)
{
	unsigned long flags;
	u64 cur_jiffies = get_jiffies_64();

	spin_lock_irqsave(&tegra_emc_stats.spinlock, flags);

	if (tegra_emc_stats.last_sel < TEGRA_EMC_TABLE_MAX_SIZE)
		tegra_emc_stats.time_at_clock[tegra_emc_stats.last_sel] =
			tegra_emc_stats.time_at_clock[tegra_emc_stats.last_sel]
			+ (cur_jiffies - tegra_emc_stats.last_update);

	tegra_emc_stats.last_update = cur_jiffies;

	if (last_sel < TEGRA_EMC_TABLE_MAX_SIZE) {
		tegra_emc_stats.clkchange_count++;
		tegra_emc_stats.last_sel = last_sel;
	}
	spin_unlock_irqrestore(&tegra_emc_stats.spinlock, flags);
}

static int emc_table_lookup(unsigned long rate)
{
	int i;
	i = get_start_idx(rate);
	for (; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;

		if (tegra_emc_table[i].rate == rate)
			break;
	}

	if (i >= tegra_emc_table_size)
		return -EINVAL;
	return i;
}

static struct clk *tegra210_emc_predict_parent(unsigned long rate,
						unsigned long *parent_rate)
{
	int val;
	struct clk *old_parent, *new_parent;

	if (!tegra_emc_table)
		return ERR_PTR(-EINVAL);

	val = emc_table_lookup(rate / 1000);
	if (val < 0)
		return ERR_PTR(-EINVAL);

	*parent_rate = emc_clk_sel[val].input_rate * 1000;
	new_parent = emc_clk_sel[val].input;
	old_parent = clk_get_parent(emc_clk);

	if (*parent_rate == clk_get_rate(old_parent))
		return old_parent;

	if (clk_is_match(new_parent, old_parent))
		new_parent = emc_clk_sel[val].input_b;

	if (*parent_rate != clk_get_rate(new_parent))
		clk_set_rate(new_parent, *parent_rate);

	return new_parent;
}

static int tegra210_emc_set_rate(unsigned long rate)
{
	int i;
	u32 clk_setting;
	struct emc_table *last_timing;
	unsigned long flags;
	s64 last_change_delay;
	struct clk *parent;
	unsigned long parent_rate;

	if (!emc_enable)
		return -ENODEV;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return -EINVAL;

	if (emc_force_max_rate)
		rate = tegra_emc_table[tegra_emc_table_size - 1].rate * 1000;

	if (rate == tegra210_emc_get_rate())
		return 0;

	i = emc_table_lookup(rate / 1000);

	if (i < 0)
		return i;

	if (rate > 204000000 && !tegra_emc_table[i].trained)
		return -EINVAL;

	if (!emc_timing) {
		emc_get_timing(&start_timing);
		last_timing = &start_timing;
	} else
		last_timing = emc_timing;

	parent = tegra210_emc_predict_parent(rate, &parent_rate);
	if (clk_is_match(parent, emc_clk_sel[i].input))
		clk_setting = emc_clk_sel[i].value;
	else
		clk_setting = emc_clk_sel[i].value_b;

	last_change_delay = ktime_us_delta(ktime_get(), clkchange_time);
	if ((last_change_delay >= 0) && (last_change_delay < clkchange_delay))
		udelay(clkchange_delay - (int)last_change_delay);

	spin_lock_irqsave(&emc_access_lock, flags);
	emc_set_clock(&tegra_emc_table[i], last_timing, 0, clk_setting);
	clkchange_time = ktime_get();
	emc_timing = &tegra_emc_table[i];
	last_rate_idx = i;
	spin_unlock_irqrestore(&emc_access_lock, flags);

	emc_last_stats_update(i);

	return 0;
}

static inline int bw_calc_get_freq_idx(unsigned long bw)
{
	int max_idx = ARRAY_SIZE(bw_calc_freqs) - 1;
	int idx = (bw > bw_calc_freqs[max_idx] * 1000000) ? max_idx : 0;

	for (; idx < max_idx; idx++) {
		u32 freq = bw_calc_freqs[idx] * 1000000;
		if (bw < freq) {
			if (idx)
				idx--;
			break;
		} else if (bw == freq)
			break;
	}
	return idx;
}

#ifdef CONFIG_DEBUG_FS
static u8 iso_share_calc_tegra210_os_idle(unsigned long iso_bw)
{
	int freq_idx = bw_calc_get_freq_idx(iso_bw);
	u8 ret = 60;

	switch (tegra_dram_type) {
	case DRAM_TYPE_DDR3:
		ret = tegra210_ddr3_iso_efficiency_os_idle[freq_idx];
		break;
	case DRAM_TYPE_LPDDR4:
		ret = tegra210_lpddr4_iso_efficiency_os_idle[freq_idx];
		break;
	case DRAM_TYPE_LPDDR2:
		ret = tegra210_lpddr3_iso_efficiency_os_idle[freq_idx];
		break;
	}

	return ret;
}

static u8 iso_share_calc_tegra210_general(unsigned long iso_bw)
{
	int freq_idx = bw_calc_get_freq_idx(iso_bw);
	u8 ret = 60;

	switch (tegra_dram_type) {
	case DRAM_TYPE_DDR3:
		ret = tegra210_ddr3_iso_efficiency_general[freq_idx];
		break;
	case DRAM_TYPE_LPDDR4:
		ret = tegra210_lpddr4_iso_efficiency_general[freq_idx];
		break;
	case DRAM_TYPE_LPDDR2:
		ret = tegra210_lpddr3_iso_efficiency_general[freq_idx];
		break;
	}

	return ret;
}
#endif

static const struct emc_clk_ops tegra210_emc_clk_ops = {
	.emc_get_rate = tegra210_emc_get_rate,
	.emc_set_rate = tegra210_emc_set_rate,
	.emc_round_rate = tegra210_emc_round_rate,
	.emc_predict_parent = tegra210_emc_predict_parent,
};

const struct emc_clk_ops *tegra210_emc_get_ops(void)
{
	return &tegra210_emc_clk_ops;
}
EXPORT_SYMBOL(tegra210_emc_get_ops);

void set_over_temp_timing(struct emc_table *next_timing, unsigned long state)
{
#define REFRESH_X2      1
#define REFRESH_X4      2
#define REFRESH_SPEEDUP(val, speedup)					\
		(val = ((val) & 0xFFFF0000) | (((val) & 0xFFFF) >> (speedup)))

	u32 ref = next_timing->burst_regs[EMC_REFRESH_INDEX];
	u32 pre_ref = next_timing->burst_regs[EMC_PRE_REFRESH_REQ_CNT_INDEX];
	u32 dsr_cntrl =
		next_timing->burst_regs[EMC_DYN_SELF_REF_CONTROL_INDEX];

	switch (state) {
	case TEGRA_DRAM_OVER_TEMP_NONE:
	case TEGRA_DRAM_OVER_TEMP_THROTTLE:
		break;
	case TEGRA_DRAM_OVER_TEMP_REFRESH_X2:
		REFRESH_SPEEDUP(ref, REFRESH_X2);
		REFRESH_SPEEDUP(pre_ref, REFRESH_X2);
		REFRESH_SPEEDUP(dsr_cntrl, REFRESH_X2);
		break;
	case TEGRA_DRAM_OVER_TEMP_REFRESH_X4:
		REFRESH_SPEEDUP(ref, REFRESH_X4);
		REFRESH_SPEEDUP(pre_ref, REFRESH_X4);
		REFRESH_SPEEDUP(dsr_cntrl, REFRESH_X4);
		break;
	default:
	WARN(1, "%s: Failed to set dram over temp state %lu\n",
		__func__, state);
	return;
	}

	emc_writel(ref, burst_regs_off[EMC_REFRESH_INDEX]);
	emc_writel(pre_ref, burst_regs_off[EMC_PRE_REFRESH_REQ_CNT_INDEX]);
	emc_writel(dsr_cntrl, burst_regs_off[EMC_DYN_SELF_REF_CONTROL_INDEX]);
}

static int emc_read_mrr(int dev, int addr)
{
	int ret;
	u32 val, emc_cfg;

	if (tegra_dram_type != DRAM_TYPE_LPDDR2 &&
	    tegra_dram_type != DRAM_TYPE_LPDDR4)
		return -ENODEV;

	ret = wait_for_update(EMC_EMC_STATUS, EMC_EMC_STATUS_MRR_DIVLD, false,
			      REG_EMC);
	if (ret)
		return ret;

	emc_cfg = emc_readl(EMC_CFG);
	if (emc_cfg & EMC_CFG_DRAM_ACPD) {
		emc_writel(emc_cfg & ~EMC_CFG_DRAM_ACPD, EMC_CFG);
		emc_timing_update(0);
	}

	val = dev ? DRAM_DEV_SEL_1 : DRAM_DEV_SEL_0;
	val |= (addr << EMC_MRR_MA_SHIFT) & EMC_MRR_MA_MASK;
	emc_writel(val, EMC_MRR);

	ret = wait_for_update(EMC_EMC_STATUS, EMC_EMC_STATUS_MRR_DIVLD, true,
			      REG_EMC);
	if (emc_cfg & EMC_CFG_DRAM_ACPD) {
		emc_writel(emc_cfg, EMC_CFG);
		emc_timing_update(0);
	}
	if (ret)
		return ret;

	val = emc_readl(EMC_MRR) & EMC_MRR_DATA_MASK;
	return val;
}

static int emc_get_dram_temperature(void)
{
	int mr4,mr4_0, mr4_1;
	unsigned long flags;

	mr4 = mr4_0 = mr4_1 = 0;

	spin_lock_irqsave(&emc_access_lock, flags);
	mr4_0 = emc_read_mrr(0, 4);
	if (tegra_dram_dev_num == 2)
		mr4_1 = emc_read_mrr(1, 4);
	spin_unlock_irqrestore(&emc_access_lock, flags);

	if (mr4_0 < 0)
		return mr4_0;

	if (mr4_1 < 0)
		return mr4_1;

	mr4_0 = (mr4_0 & LPDDR2_MR4_TEMP_MASK) >> LPDDR2_MR4_TEMP_SHIFT;
	mr4_1 = (mr4_1 & LPDDR2_MR4_TEMP_MASK) >> LPDDR2_MR4_TEMP_SHIFT;

	/* Consider higher temperature of the two DDR Dies */
	mr4 = (mr4_0 > mr4_1) ? mr4_0 : mr4_1;

	return mr4;
}

static int emc_get_dram_temp(void *dev, int *temp)
{
	int mr4 = emc_get_dram_temperature();

	if (mr4 >= 0)
		*temp = mr4;

	return 0;
}

static const struct thermal_zone_of_device_ops dram_therm_ops = {
	.get_temp = emc_get_dram_temp,
};

struct emc_table *emc_get_table(unsigned long over_temp_state)
{
	if ((over_temp_state == TEGRA_DRAM_OVER_TEMP_THROTTLE) &&
	    (tegra_emc_table_derated != NULL))
		return tegra_emc_table_derated;
	else
		return tegra_emc_table_normal;
}

int tegra210_emc_set_over_temp_state(unsigned long state)
{
	unsigned long flags;
	struct emc_table *current_table;
	struct emc_table *new_table;

	if ((tegra_dram_type != DRAM_TYPE_LPDDR2 &&
	     tegra_dram_type != DRAM_TYPE_LPDDR4) ||
	     !emc_timing)
		return -ENODEV;

	if (state > TEGRA_DRAM_OVER_TEMP_THROTTLE)
		return -EINVAL;

	if (state == dram_over_temp_state)
		return 0;

	spin_lock_irqsave(&emc_access_lock, flags);

	current_table = emc_get_table(dram_over_temp_state);
	new_table = emc_get_table(state);
	dram_over_temp_state = state;

	if (current_table != new_table) {
		emc_set_clock(&new_table[last_rate_idx], emc_timing, 0,
			      current_clksrc | EMC_CLK_FORCE_CC_TRIGGER);
		emc_timing = &new_table[last_rate_idx];
		tegra_emc_table = new_table;
	} else {
		set_over_temp_timing(emc_timing, state);
		emc_timing_update(0);
		if (state != TEGRA_DRAM_OVER_TEMP_NONE)
			emc_writel(EMC_REF_FORCE_CMD, EMC_REF);
	}

	spin_unlock_irqrestore(&emc_access_lock, flags);

	return 0;
}

#ifdef CONFIG_DEBUG_FS
static int emc_stats_show(struct seq_file *s, void *data)
{
	int i;

	emc_last_stats_update(TEGRA_EMC_TABLE_MAX_SIZE);

	seq_printf(s, "%-10s %-10s\n", "rate kHz", "time");
	for (i = 0; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;

		seq_printf(s, "%-10u %-10llu\n",
			   tegra_emc_table[i].rate,
			   cputime64_to_clock_t(
					    tegra_emc_stats.time_at_clock[i]));
	}
	seq_printf(s, "%-15s %llu\n", "transitions:",
		   tegra_emc_stats.clkchange_count);
	seq_printf(s, "%-15s %llu\n", "time-stamp:",
		   cputime64_to_clock_t(tegra_emc_stats.last_update));

	return 0;
}

static int emc_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, emc_stats_show, inode->i_private);
}

static const struct file_operations emc_stats_fops = {
	.open		= emc_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int efficiency_get(void *data, u64 *val)
{
	*val = tegra210_emc_bw_efficiency;
	return 0;
}

static int efficiency_set(void *data, u64 val)
{
	tegra210_emc_bw_efficiency = (val > 100) ? 100 : val;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(efficiency_fops, efficiency_get,
			efficiency_set, "%llu\n");

static const char *emc_user_names[EMC_USER_NUM] = {
	"DC1",
	"DC2",
	"VI",
	"MSENC",
	"2D",
	"3D",
	"BB",
	"VDE",
	"VI2",
	"ISPA",
	"ISPB",
	"NVDEC",
	"NVJPG",
};

static int emc_usage_table_show(struct seq_file *s, void *data)
{
	int i, j;

	seq_printf(s, "EMC USAGE\t\tISO SHARE %% @ last bw %lu\n", last_iso_bw);

	for (i = 0; i < ARRAY_SIZE(tegra210_emc_iso_usage); i++) {
		u32 flags = tegra210_emc_iso_usage[i].emc_usage_flags;
		u8 share = tegra210_emc_iso_usage[i].iso_usage_share;
		bool fixed_share = true;
		bool first = false;

		if (tegra210_emc_iso_usage[i].iso_share_calculator) {
			share = tegra210_emc_iso_usage[i].iso_share_calculator(
				last_iso_bw);
			fixed_share = false;
		}

		seq_printf(s, "[%d]: ", i);
		if (!flags) {
			seq_puts(s, "reserved\n");
			continue;
		}

		for (j = 0; j < EMC_USER_NUM; j++) {
			u32 mask = 0x1 << j;
			if (!(flags & mask))
				continue;
			seq_printf(s, "%s%s", first ? "+" : "",
				   emc_user_names[j]);
			first = true;
		}
		seq_printf(s, "\r\t\t\t= %d(%s across bw)\n",
			   share, fixed_share ? "fixed" : "vary");
	}
	return 0;
}

static int emc_usage_table_open(struct inode *inode, struct file *file)
{
	return single_open(file, emc_usage_table_show, inode->i_private);
}

static const struct file_operations emc_usage_table_fops = {
	.open		= emc_usage_table_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int emc_dvfs_table_show(struct seq_file *s, void *data)
{
	int i;

	seq_puts(s, "Table Version Info (Table version, rev, rate):\n");
	for (i = 0; i < tegra_emc_table_size; i++) {
		seq_printf(s, "%s\n%d\n%d\n",
				tegra_emc_table_normal[i].dvfs_ver,
				tegra_emc_table_normal[i].rev,
				tegra_emc_table_normal[i].rate);
	}

	return 0;
}

static int emc_dvfs_table_open(struct inode *inode, struct file *file)
{
	return single_open(file, emc_dvfs_table_show, inode->i_private);
}

static const struct file_operations emc_dvfs_table_fops = {
	.open		= emc_dvfs_table_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int dram_temp_get(void *data, u64 *val)
{
	int temp = 0;
	emc_get_dram_temp(data, &temp);
	*val = temp;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(dram_temp_fops, dram_temp_get, NULL,
	"%lld\n");

static int over_temp_state_get(void *data, u64 *val)
{
	*val = dram_over_temp_state;
	return 0;
}

static int over_temp_state_set(void *data, u64 val)
{
	return tegra210_emc_set_over_temp_state(val);
}
DEFINE_SIMPLE_ATTRIBUTE(over_temp_state_fops, over_temp_state_get,
			over_temp_state_set, "%llu\n");

static int get_mr4_force_poll(void *data, u64 *val)
{
	*val = atomic_read(&mr4_force_poll);

	return 0;
}
static int set_mr4_force_poll(void *data, u64 val)
{
	atomic_set(&mr4_force_poll, (unsigned int)val);

	/* Explicitly wake up the DRAM monitoring thread. */
	if (atomic_read(&mr4_force_poll))
		mod_timer(&emc_timer_mr4,
			  jiffies + msecs_to_jiffies(timer_period_mr4));

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(mr4_force_poll_fops,
			get_mr4_force_poll,
			set_mr4_force_poll, "%llu\n");

static int dram_info_show(struct seq_file *s, void *data)
{
	uint32_t mr5, mr6, mr7, mr8, strap;
	unsigned long flags;

	strap = tegra_read_ram_code();
	spin_lock_irqsave(&emc_access_lock, flags);
	mr5 = emc_read_mrr(0, 5) & 0xffU;
	mr6 = emc_read_mrr(0, 6) & 0xffU;
	mr7 = emc_read_mrr(0, 7) & 0xffU;
	mr8 = emc_read_mrr(0, 8) & 0xffU;
	spin_unlock_irqrestore(&emc_access_lock, flags);
	seq_printf(s, "DRAM strap: %u\n"
		      "Manufacturer ID (MR5): %u\n"
		      "Revision ID-1 (MR6): %u\n"
		      "Revision ID-2 (MR7): %u\n"
		      "IO Width/Density/Type (MR8): 0x%02x\n",
		      strap, mr5, mr6, mr7, mr8);

	return 0;
}

static int dram_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, dram_info_show, inode->i_private);
}

static const struct file_operations dram_info_fops = {
	.open		= dram_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int tegra_emc_debug_init(void)
{
	struct dentry *emc_debugfs_root;
	struct dentry *dram_therm_debugfs;

	if (!tegra_emc_init_done)
		return -ENODEV;

	emc_debugfs_root = debugfs_create_dir("tegra_emc", NULL);
	if (!emc_debugfs_root)
		return -ENOMEM;

	dram_therm_debugfs = debugfs_create_dir("dram_therm",
						emc_debugfs_root);
	if (!dram_therm_debugfs)
		goto err_out;

	if (!debugfs_create_file("stats", S_IRUGO, emc_debugfs_root, NULL,
				 &emc_stats_fops))
		goto err_out;

	if (!debugfs_create_u32("clkchange_delay", S_IRUGO | S_IWUSR,
				emc_debugfs_root, (u32 *)&clkchange_delay))
		goto err_out;

	if (!debugfs_create_file("efficiency", S_IRUGO | S_IWUSR,
				 emc_debugfs_root, NULL, &efficiency_fops))
		goto err_out;

	if (!debugfs_create_file("emc_usage_table", S_IRUGO, emc_debugfs_root,
				 NULL, &emc_usage_table_fops))
		goto err_out;

	if (!debugfs_create_u8("emc_iso_share", S_IRUGO, emc_debugfs_root,
			       &tegra210_emc_iso_share))
		goto err_out;

	if (tegra_dram_type == DRAM_TYPE_LPDDR2 ||
		tegra_dram_type == DRAM_TYPE_LPDDR4) {
		if (!debugfs_create_file("dram_temp", S_IRUGO,
					 emc_debugfs_root, NULL,
					 &dram_temp_fops))
			goto err_out;
		if (!debugfs_create_file("over_temp_state", S_IRUGO | S_IWUSR,
					 emc_debugfs_root, NULL,
					 &over_temp_state_fops))
			goto err_out;
	}

	/* DRAM thermals. */
	if (!debugfs_create_u32("timer_period", S_IRUGO | S_IWUSR,
				dram_therm_debugfs, &timer_period_mr4))
		goto err_out;
	if (!debugfs_create_u32("test_mode", S_IRUGO | S_IWUSR,
				dram_therm_debugfs, &test_mode))
		goto err_out;
	if (!debugfs_create_u32("dram_temp_override", S_IRUGO | S_IWUSR,
				dram_therm_debugfs, &dram_temp_override))
		goto err_out;
	if (!debugfs_create_file("force_poll", S_IRUGO | S_IWUSR,
				 dram_therm_debugfs, NULL,
				 &mr4_force_poll_fops))
		goto err_out;

	if (tegra_dram_type == DRAM_TYPE_LPDDR4) {
		if (!debugfs_create_u32("training_timer_period",
					S_IRUGO | S_IWUSR, emc_debugfs_root,
					&timer_period_training))
			goto err_out;
	}

	if (!debugfs_create_file("tables_info", S_IRUGO, emc_debugfs_root,
				 NULL, &emc_dvfs_table_fops))
		goto err_out;
	if (!debugfs_create_file("dram_info", 0444, emc_debugfs_root,
				 NULL, &dram_info_fops))
		goto err_out;

	return 0;

err_out:
	debugfs_remove_recursive(emc_debugfs_root);
	return -ENOMEM;
}

late_initcall(tegra_emc_debug_init);
#endif

static const struct of_device_id mc_match[] = {
	{ .compatible = "nvidia,tegra210-mc" },
	{},
};

static const struct of_device_id car_match[] = {
	{ .compatible = "nvidia,tegra210-car" },
	{},
};

void __emc_copy_table_params(struct emc_table *src, struct emc_table *dst,
				int flags)
{
	int i;

	if (flags & EMC_COPY_TABLE_PARAM_PERIODIC_FIELDS) {
		dst->trained_dram_clktree_c0d0u0 =
			src->trained_dram_clktree_c0d0u0;
		dst->trained_dram_clktree_c0d0u1 =
			src->trained_dram_clktree_c0d0u1;
		dst->trained_dram_clktree_c0d1u0 =
			src->trained_dram_clktree_c0d1u0;
		dst->trained_dram_clktree_c0d1u1 =
			src->trained_dram_clktree_c0d1u1;
		dst->trained_dram_clktree_c1d0u0 =
			src->trained_dram_clktree_c1d0u0;
		dst->trained_dram_clktree_c1d0u1 =
			src->trained_dram_clktree_c1d0u1;
		dst->trained_dram_clktree_c1d1u0 =
			src->trained_dram_clktree_c1d1u0;
		dst->trained_dram_clktree_c1d1u1 =
			src->trained_dram_clktree_c1d1u1;
		dst->current_dram_clktree_c0d0u0 =
			src->current_dram_clktree_c0d0u0;
		dst->current_dram_clktree_c0d0u1 =
			src->current_dram_clktree_c0d0u1;
		dst->current_dram_clktree_c0d1u0 =
			src->current_dram_clktree_c0d1u0;
		dst->current_dram_clktree_c0d1u1 =
			src->current_dram_clktree_c0d1u1;
		dst->current_dram_clktree_c1d0u0 =
			src->current_dram_clktree_c1d0u0;
		dst->current_dram_clktree_c1d0u1 =
			src->current_dram_clktree_c1d0u1;
		dst->current_dram_clktree_c1d1u0 =
			src->current_dram_clktree_c1d1u0;
		dst->current_dram_clktree_c1d1u1 =
			src->current_dram_clktree_c1d1u1;
	}

	if (flags & EMC_COPY_TABLE_PARAM_TRIM_REGS) {
		for (i = 0; i < src->num_trim_per_ch; i++)
			dst->trim_perch_regs[i] = src->trim_perch_regs[i];

		for (i = 0; i < src->num_trim; i++)
			dst->trim_regs[i] = src->trim_regs[i];

		for (i = 0; i < src->num_burst_per_ch; i++)
			dst->burst_reg_per_ch[i] = src->burst_reg_per_ch[i];

		dst->trained = src->trained;
	}
}

static int find_matching_input(struct emc_table *table, struct emc_sel *sel)
{
	u32 div_value;
	u32 src_value;
	unsigned long input_rate = 0;
	struct clk *input_clk;
	struct clk_hw *emc_hw;

	div_value = emc_div_val(table->clk_src_emc);
	src_value = emc_src_val(table->clk_src_emc);

	if (div_value & 0x1) {
		pr_warn("Tegra EMC: invalid odd divider for EMC rate %u\n",
			table->rate);
		return -EINVAL;
	}

	emc_hw = __clk_get_hw(emc_clk);
	if (src_value >= clk_hw_get_num_parents(emc_hw)) {
		pr_warn("Tegra EMC: no matching input found for rate %u\n",
			table->rate);
		return -EINVAL;
	}

	if (!(table->clk_src_emc & EMC_CLK_MC_EMC_SAME_FREQ) !=
	    !(MC_EMEM_ARB_MISC0_EMC_SAME_FREQ &
	    table->burst_regs[MC_EMEM_ARB_MISC0_INDEX])) {
		pr_warn("Tegra EMC: ambiguous EMC to MC ratio for rate %u\n",
			table->rate);
		return -EINVAL;
	}

	input_clk = tegra_emc_src[src_value];
	if (input_clk == tegra_emc_src[TEGRA_EMC_SRC_PLLM]
		|| input_clk == tegra_emc_src[TEGRA_EMC_SRC_PLLM_UD]) {
		input_rate = table->rate * (1 + div_value / 2);
	} else {
		input_rate = clk_get_rate(input_clk) / 1000;
		if (input_rate != (table->rate * (1 + div_value / 2))) {
			pr_warn("Tegra EMC: rate %u doesn't match input\n",
				table->rate);
			return -EINVAL;
		}
	}

	sel->input = input_clk;
	sel->input_rate = input_rate;
	sel->value = table->clk_src_emc;
	sel->input_b = input_clk;
	sel->input_rate_b = input_rate;
	sel->value_b = table->clk_src_emc;

	if (input_clk == tegra_emc_src[TEGRA_EMC_SRC_PLLM]) {
		sel->input_b = tegra_emc_src[TEGRA_EMC_SRC_PLLMB];
		sel->value_b = table->clk_src_emc & ~EMC_CLK_EMC_2X_CLK_SRC_MASK;
		sel->value_b |= TEGRA_EMC_SRC_PLLMB << EMC_CLK_EMC_2X_CLK_SRC_SHIFT;
	}

	if (input_clk == tegra_emc_src[TEGRA_EMC_SRC_PLLM_UD]) {
		sel->input_b = tegra_emc_src[TEGRA_EMC_SRC_PLLMB_UD];
		sel->value_b = table->clk_src_emc & ~EMC_CLK_EMC_2X_CLK_SRC_MASK;
		sel->value_b |= TEGRA_EMC_SRC_PLLMB_UD << EMC_CLK_EMC_2X_CLK_SRC_SHIFT;
	}

	return 0;
}

static int tegra210_init_emc_data(struct platform_device *pdev)
{
	int i;
	unsigned long table_rate;
	unsigned long current_rate;

	emc_clk = devm_clk_get(&pdev->dev, "emc");
	if (IS_ERR(emc_clk)) {
		dev_err(&pdev->dev, "Can not find EMC clock\n");
		return -EINVAL;
	}

	emc_override_clk = devm_clk_get(&pdev->dev, "emc_override");
	if (IS_ERR(emc_override_clk))
		dev_err(&pdev->dev, "Cannot find EMC override clock\n");

	for (i = 0; i < TEGRA_EMC_SRC_COUNT; i++) {
		tegra_emc_src[i] = devm_clk_get(&pdev->dev,
						tegra_emc_src_names[i]);
		if (IS_ERR(tegra_emc_src[i])) {
			dev_err(&pdev->dev, "Can not find EMC source clock\n");
			return -ENODATA;
		}
	}

	tegra_emc_stats.clkchange_count = 0;
	spin_lock_init(&tegra_emc_stats.spinlock);
	tegra_emc_stats.last_update = get_jiffies_64();
	tegra_emc_stats.last_sel = TEGRA_EMC_TABLE_MAX_SIZE;

	tegra_dram_type = (emc_readl(EMC_FBIO_CFG5) &
			   EMC_FBIO_CFG5_DRAM_TYPE_MASK) >>
			   EMC_FBIO_CFG5_DRAM_TYPE_SHIFT;

	tegra_dram_dev_num = (mc_readl(MC_EMEM_ADR_CFG) & 0x1) + 1;

	if (tegra_dram_type != DRAM_TYPE_DDR3 &&
	    tegra_dram_type != DRAM_TYPE_LPDDR2 &&
	    tegra_dram_type != DRAM_TYPE_LPDDR4) {
		dev_err(&pdev->dev, "DRAM not supported\n");
		return -ENODATA;
	}

	tegra_emc_dt_parse_pdata(pdev, &tegra_emc_table_normal,
			&tegra_emc_table_derated, &tegra_emc_table_size);
	if (!tegra_emc_table_size ||
	    tegra_emc_table_size > TEGRA_EMC_TABLE_MAX_SIZE) {
		dev_err(&pdev->dev, "Invalid table size %d\n",
			tegra_emc_table_size);
		return -EINVAL;
	}
	tegra_emc_table = tegra_emc_table_normal;

	/*
	 * Copy trained trimmers from the normal table to the derated
	 * table for LP4. Bootloader trains only the normal table.
	 * Trimmers are the same for derated and normal tables.
	 */
	if (tegra_emc_table_derated && tegra_dram_type == DRAM_TYPE_LPDDR4)
		emc_copy_table_params(tegra_emc_table_normal,
				      tegra_emc_table_derated,
				      tegra_emc_table_size,
				      EMC_COPY_TABLE_PARAM_PERIODIC_FIELDS |
				      EMC_COPY_TABLE_PARAM_TRIM_REGS);

	seq = supported_seqs;
	while (seq->table_rev) {
		if (seq->table_rev == tegra_emc_table[0].rev)
			break;
		seq++;
	}
	if (!seq->set_clock) {
		seq = NULL;
		dev_err(&pdev->dev, "Invalid EMC sequence for table Rev. %d\n",
			tegra_emc_table[0].rev);
		return -EINVAL;
	}

	emc_clk_sel = devm_kcalloc(&pdev->dev,
				   tegra_emc_table_size,
				   sizeof(struct emc_sel),
				   GFP_KERNEL);
	if (!emc_clk_sel) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		return -ENOMEM;
	}

	current_rate = clk_get_rate(emc_clk) / 1000;
	for (i = 0; i < tegra_emc_table_size; i++) {
		table_rate = tegra_emc_table[i].rate;
		if (!table_rate)
			continue;

		if (emc_max_rate && table_rate > emc_max_rate)
			break;

		if (i && ((table_rate <= tegra_emc_table[i-1].rate) ||
		   (tegra_emc_table[i].min_volt <
		    tegra_emc_table[i-1].min_volt)))
			continue;

		if (tegra_emc_table[i].rev != tegra_emc_table[0].rev)
			continue;

		if (find_matching_input(&tegra_emc_table[i], &emc_clk_sel[i]))
			continue;

		if (table_rate == current_rate)
			tegra_emc_stats.last_sel = i;
	}

	dev_info(&pdev->dev, "validated EMC DFS table\n");

	start_timing.num_burst = tegra_emc_table[0].num_burst;
	start_timing.num_burst_per_ch =
		tegra_emc_table[0].num_burst_per_ch;
	start_timing.num_trim = tegra_emc_table[0].num_trim;
	start_timing.num_trim_per_ch =
		tegra_emc_table[0].num_trim_per_ch;
	start_timing.num_mc_regs = tegra_emc_table[0].num_mc_regs;
	start_timing.num_up_down = tegra_emc_table[0].num_up_down;
	start_timing.vref_num =
		tegra_emc_table[0].vref_num;

	return 0;
}

static int tegra210_emc_probe(struct platform_device *pdev)
{
	struct device_node *node;
	struct resource *r;
	int ret;

	node = of_find_matching_node(NULL, mc_match);
	if (!node) {
		dev_err(&pdev->dev, "Error finding MC device.\n");
		return -EINVAL;
	}

	mc_base = of_iomap(node, 0);
	if (!mc_base) {
		dev_err(&pdev->dev, "Can't map MC registers\n");
		return -EINVAL;
	}

	node = of_find_matching_node(NULL, car_match);
	if (!node) {
		dev_err(&pdev->dev, "Error finding CAR device.\n");
		return -EINVAL;
	}

	clk_base = of_iomap(node, 0);
	if (!clk_base) {
		dev_err(&pdev->dev, "Can't map CAR registers\n");
		return -EINVAL;
	}

	tegra_ram_code = tegra_read_ram_code();
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	emc_base = devm_ioremap_resource(&pdev->dev, r);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	emc0_base = devm_ioremap_resource(&pdev->dev, r);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	emc1_base = devm_ioremap_resource(&pdev->dev, r);

	ret = tegra210_init_emc_data(pdev);
	if (ret)
		return ret;

	tegra_emc_init_done = true;
#ifdef CONFIG_DEBUG_FS
	tegra_emc_debug_init();
#endif

	return 0;
}

static int tegra210b01_emc_probe(struct platform_device *pdev)
{
	emc_override_clk = devm_clk_get(&pdev->dev, "emc_override");
	if (IS_ERR(emc_override_clk)) {
		dev_err(&pdev->dev, "Cannot find T210B01 EMC override clock\n");
		return -ENODATA;
	}

	dev_info(&pdev->dev, "T210B01 EMC pm ops are registered\n");
	return 0;
}

static int tegra210x_emc_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;

	if (of_device_is_compatible(np, "nvidia,tegra210b01-emc"))
		return tegra210b01_emc_probe(pdev);

	return tegra210_emc_probe(pdev);
}

#ifdef CONFIG_PM_SLEEP
static int tegra210_emc_suspend(struct device *dev)
{
	if (!IS_ERR(emc_override_clk)) {
		emc_override_rate = clk_get_rate(emc_override_clk);
		clk_set_rate(emc_override_clk, 204000000);
		clk_prepare_enable(emc_override_clk);

		pr_debug("%s at rate %lu\n",
			 __func__, clk_get_rate(emc_override_clk));
	}

	return 0;
}

static int tegra210_emc_resume(struct device *dev)
{
	if (!IS_ERR(emc_override_clk)) {
		clk_set_rate(emc_override_clk, emc_override_rate);
		clk_disable_unprepare(emc_override_clk);

		pr_debug("%s at rate %lu\n",
			 __func__, clk_get_rate(emc_override_clk));
	}
	return 0;
}
#endif

static const struct dev_pm_ops tegra210_emc_pm_ops = {
	SET_LATE_SYSTEM_SLEEP_PM_OPS(tegra210_emc_suspend, tegra210_emc_resume)
};

static struct of_device_id tegra210_emc_of_match[] = {
	{ .compatible = "nvidia,tegra210-emc", },
	{ .compatible = "nvidia,tegra210b01-emc", },
	{ },
};

static struct platform_driver tegra210_emc_driver = {
	.driver         = {
		.name   = "tegra210-emc",
		.of_match_table = tegra210_emc_of_match,
		.pm	= &tegra210_emc_pm_ops,
	},
	.probe          = tegra210x_emc_probe,
};

static int __init tegra210_emc_init(void)
{
	return platform_driver_register(&tegra210_emc_driver);
}
subsys_initcall(tegra210_emc_init);

static int __init tegra210_emc_late_init(void)
{
	struct device_node *node;
	struct platform_device *pdev;

	if (!tegra_emc_init_done)
		return -ENODEV;

	node = of_find_matching_node(NULL, tegra210_emc_of_match);
	if (!node) {
		pr_err("Error finding EMC node.\n");
		return -EINVAL;
	}

	pdev = of_find_device_by_node(node);
	if (!pdev) {
		pr_err("Error finding EMC device.\n");
		return -EINVAL;
	}

	thermal_zone_of_sensor_register(&pdev->dev, 0, NULL, &dram_therm_ops);

	return 0;
}
late_initcall(tegra210_emc_late_init);

#ifdef CONFIG_THERMAL

#define TEGRA_DRAM_THERM_MAX_STATE     1

static int tegra_dram_cd_max_state(struct thermal_cooling_device *tcd,
				   unsigned long *state)
{
	*state = TEGRA_DRAM_THERM_MAX_STATE;
	return 0;
}

static int tegra_dram_cd_cur_state(struct thermal_cooling_device *tcd,
				   unsigned long *state)
{
	*state = (unsigned long)atomic_read(&mr4_temp_poll);
	return 0;
}

static int tegra_dram_cd_set_state(struct thermal_cooling_device *tcd,
				   unsigned long state)
{
	if (state == (unsigned long)atomic_read(&mr4_temp_poll))
		return 0;

	if (state)
		tegra_emc_mr4_temp_trigger(1);
	else
		tegra_emc_mr4_temp_trigger(0);
	return 0;
}

/*
 * Cooling device support.
 */
static struct thermal_cooling_device_ops emc_dram_cd_ops = {
	.get_max_state = tegra_dram_cd_max_state,
	.get_cur_state = tegra_dram_cd_cur_state,
	.set_cur_state = tegra_dram_cd_set_state,
};

static __init int tegra_emc_therm_init(void)
{
	void *ret;

	if (!tegra_emc_init_done)
		return -ENODEV;

	ret = thermal_cooling_device_register("tegra-dram", NULL,
					      &emc_dram_cd_ops);
	if (IS_ERR(ret))
		return PTR_ERR(ret);
	if (ret == NULL)
		return -ENODEV;

	pr_info("DRAM derating cdev registered.\n");

	return 0;
}
late_initcall(tegra_emc_therm_init);
#endif
