/*
 * Copyright (c) 2014-2018, NVIDIA CORPORATION.  All rights reserved.
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

#include <dt-bindings/clock/tegra210-car.h>
#include <dt-bindings/reset/tegra210-car.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/regulator/consumer.h>
#include <soc/tegra/tegra_powergate.h>
#include <soc/tegra/tegra-powergate-driver.h>
#include <soc/tegra/chip-id.h>
#include <linux/tegra_soctherm.h>
#include <soc/tegra/tegra-dvfs.h>
#include <trace/events/power.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clk/tegra.h>
#include <soc/tegra/reset.h>
#include <soc/tegra/common.h>
#include <soc/tegra/fuse.h>
#include <linux/platform/tegra/mc.h>
#include <soc/tegra/pmc.h>

#define MAX_CLK_EN_NUM			15
#define MAX_HOTRESET_CLIENT_NUM		4

enum clk_type {
	CLK_AND_RST,
	RST_ONLY,
	CLK_ONLY,
};

struct partition_clk_info {
	const char *clk_name;
	enum clk_type clk_type;
	struct clk *clk_ptr;
};

#define LVL2_CLK_GATE_OVRA 0xf8
#define LVL2_CLK_GATE_OVRC 0x3a0
#define LVL2_CLK_GATE_OVRD 0x3a4
#define LVL2_CLK_GATE_OVRE 0x554
/* sentinel for lvl2_ovr_info array */
#define LVL2_END	   0x1000

/* I2S registers to handle during APE power ungating */
#define TEGRA210_I2S_BASE  0x11000
#define TEGRA210_I2S_SIZE  0x100
#define TEGRA210_I2S_CTRLS 5
#define TEGRA210_I2S_CG	   0x88
#define TEGRA210_I2S_CTRL  0xa0

/* registers to control DISPA SLCG during power ungating */
#define DC_CMD_DISPLAY_COMMAND 0xc8
#define DC_COM_DSC_TOP_CTL 0xcf8

/* register to control VIC SLCG during power ungating */
#define NV_PVIC_THI_SLCG_OVERRIDE_LOW 0x8c

struct lvl2_ovr_info {
	u32 offset;
	u32 mask;
};

struct powergate_partition_info {
	const char *name;
	struct partition_clk_info clk_info[MAX_CLK_EN_NUM];
	struct partition_clk_info slcg_info[MAX_CLK_EN_NUM];
	struct lvl2_ovr_info lvl2_ovr_info[MAX_CLK_EN_NUM];
	void (*handle_lvl2_ovr)(void);
	unsigned long reset_id[MAX_CLK_EN_NUM];
	int reset_id_num;
	int refcount;
	bool disable_after_boot;
	struct mutex pg_mutex;
	bool skip_reset;
};

#define EMULATION_MC_FLUSH_TIMEOUT 100
#define TEGRA210_POWER_DOMAIN_NVENC TEGRA210_POWER_DOMAIN_MPE

enum mc_client_type {
	MC_CLIENT_AFI		= 0,
	MC_CLIENT_AVPC		= 1,
	MC_CLIENT_DC		= 2,
	MC_CLIENT_DCB		= 3,
	MC_CLIENT_HC		= 6,
	MC_CLIENT_HDA		= 7,
	MC_CLIENT_ISP2		= 8,
	MC_CLIENT_NVENC		= 11,
	MC_CLIENT_SATA		= 15,
	MC_CLIENT_VI		= 17,
	MC_CLIENT_VIC		= 18,
	MC_CLIENT_XUSB_HOST	= 19,
	MC_CLIENT_XUSB_DEV	= 20,
	MC_CLIENT_BPMP		= 21,
	MC_CLIENT_TSEC		= 22,
	MC_CLIENT_SDMMC1	= 29,
	MC_CLIENT_SDMMC2	= 30,
	MC_CLIENT_SDMMC3	= 31,
	MC_CLIENT_SDMMC4	= 32,
	MC_CLIENT_ISP2B		= 33,
	MC_CLIENT_NVDEC		= 37,
	MC_CLIENT_APE		= 38,
	MC_CLIENT_SE		= 39,
	MC_CLIENT_NVJPG		= 40,
	MC_CLIENT_TSECB		= 45,
	MC_CLIENT_LAST		= -1,
};

struct tegra210_mc_client_info {
	enum mc_client_type hot_reset_clients[MAX_HOTRESET_CLIENT_NUM];
};

static struct tegra210_mc_client_info tegra210_pg_mc_info[] = {
	[TEGRA210_POWER_DOMAIN_CRAIL] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_VENC] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_ISP2,
			[1] = MC_CLIENT_VI,
			[2] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_PCIE] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_AFI,
			[1] = MC_CLIENT_LAST,
		},
	},
#ifdef CONFIG_ARCH_TEGRA_HAS_SATA
	[TEGRA210_POWER_DOMAIN_SATA] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_SATA,
			[1] = MC_CLIENT_LAST,
		},
	},
#endif
	[TEGRA210_POWER_DOMAIN_NVENC] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_NVENC,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_SOR] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_DISA] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_DC,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_DISB] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_DCB,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_XUSBA] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_XUSBB] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_XUSB_DEV,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_XUSBC] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_XUSB_HOST,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_VIC] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_VIC,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_NVDEC] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_NVDEC,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_NVJPG] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_NVJPG,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_APE] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_APE,
			[1] = MC_CLIENT_LAST,
		},
	},
	[TEGRA210_POWER_DOMAIN_VE2] = {
		.hot_reset_clients = {
			[0] = MC_CLIENT_ISP2B,
			[1] = MC_CLIENT_LAST,
		},
	},
};

static void handle_lvl2_ovr_ape(void);
static void handle_lvl2_ovr_disp(void);
static void handle_lvl2_ovr_vic(void);

static struct powergate_partition_info tegra210_pg_partition_info[] = {
	[TEGRA210_POWER_DOMAIN_VENC] = {
		.name = "ve",
		.clk_info = {
			{ .clk_name = "ispa", .clk_type = CLK_ONLY },
			{ .clk_name = "vi", .clk_type = CLK_ONLY },
			{ .clk_name = "csi", .clk_type = CLK_ONLY },
			{ .clk_name = "vii2c", .clk_type = CLK_ONLY },
			{ .clk_name = "cilab", .clk_type = CLK_ONLY },
			{ .clk_name = "cilcd", .clk_type = CLK_ONLY },
			{ .clk_name = "cile", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "host1x" },
		},
		/* all lv2lovr functionality for this domain is handled by
		 * tegra210_venc_mbist_war
		 */
		.handle_lvl2_ovr = tegra210_venc_mbist_war,
		.reset_id = { TEGRA210_CLK_ISPA, TEGRA210_RST_VI,
			      TEGRA210_CLK_CSI, TEGRA210_CLK_VI_I2C },
		.reset_id_num = 4,
	},
	[TEGRA210_POWER_DOMAIN_PCIE] = {
		.name = "pcie",
		.skip_reset = true,
	},
#ifdef CONFIG_ARCH_TEGRA_HAS_SATA
	[TEGRA210_POWER_DOMAIN_SATA] = {
		.name = "sata",
		.disable_after_boot = false,
		.clk_info = {
			{ .clk_name = "sata_oob", .clk_type = CLK_ONLY },
			{ .clk_name = "cml1", .clk_type = CLK_ONLY },
			{ .clk_name = "sata_aux", .clk_type = CLK_ONLY },
			{ .clk_name = "sata", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRC,
			   .mask = BIT(0) | BIT(17) | BIT(19) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_SATA_OOB, TEGRA210_CLK_SATA_COLD,
			      TEGRA210_CLK_SATA },
		.reset_id_num = 3,
	},
#endif
	[TEGRA210_POWER_DOMAIN_NVENC] = {
		.name = "nvenc",
		.clk_info = {
			{ .clk_name = "nvenc", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRE, .mask = BIT(29) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_NVENC },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_SOR] = {
		.name = "sor",
		.clk_info = {
			{ .clk_name = "sor0", .clk_type = CLK_ONLY },
			{ .clk_name = "dsia", .clk_type = CLK_ONLY },
			{ .clk_name = "dsib", .clk_type = CLK_ONLY },
			{ .clk_name = "sor1", .clk_type = CLK_ONLY },
			{ .clk_name = "mipi-cal", .clk_type = CLK_ONLY },
			{ .clk_name = "dpaux", .clk_type = CLK_ONLY },
			{ .clk_name = "dpaux1", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "hda2hdmi" },
			{ .clk_name = "hda2codec_2x" },
			{ .clk_name = "disp1" },
			{ .clk_name = "disp2" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRA,
			   .mask = BIT(1) | BIT(2) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_SOR0, TEGRA210_CLK_DSIA,
			      TEGRA210_CLK_DSIB, TEGRA210_CLK_SOR1,
			      TEGRA210_CLK_MIPI_CAL, TEGRA210_CLK_DPAUX,
			      TEGRA210_CLK_DPAUX1 },
		.reset_id_num = 7,
	},
	[TEGRA210_POWER_DOMAIN_DISA] = {
		.name = "disa",
		.clk_info = {
			{ .clk_name = "disp1", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "la" },
			{ .clk_name = "host1x" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRA, .mask = BIT(1) },
			{ .offset = LVL2_END },
		},
		.handle_lvl2_ovr = handle_lvl2_ovr_disp,
		.reset_id = { TEGRA210_CLK_DISP1 },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_DISB] = {
		.name = "disb",
		.disable_after_boot = true,
		.clk_info = {
			{ .clk_name = "disp2", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "la" },
			{ .clk_name = "host1x" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRA, .mask = BIT(2) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_DISP2 },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_XUSBA] = {
		.name = "xusba",
		.clk_info = {
			{ .clk_name = "xusb_ss", .clk_type = CLK_ONLY },
			{ .clk_name = "xusb_ssp_src", .clk_type = CLK_ONLY },
			{ .clk_name = "xusb_hs_src", .clk_type = CLK_ONLY },
			{ .clk_name = "xusb_fs_src", .clk_type = CLK_ONLY },
			{ .clk_name = "xusb_dev_src", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "xusb_host" },
			{ .clk_name = "xusb_dev" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRC,
			   .mask = BIT(30) | BIT(31) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_XUSB_SS },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_XUSBB] = {
		.name = "xusbb",
		.clk_info = {
			{ .clk_name = "xusb_dev", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "xusb_ss" },
			{ .clk_name = "xusb_host" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRC,
			   .mask = BIT(30) | BIT(31) },
			{ .offset = LVL2_END },
		},
		.reset_id = { 95 },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_XUSBC] = {
		.name = "xusbc",
		.clk_info = {
			{ .clk_name = "xusb_host", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "xusb_ss" },
			{ .clk_name = "xusb_dev" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRC,
			   .mask = BIT(30) | BIT(31) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_XUSB_HOST },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_VIC] = {
		.name = "vic",
		.clk_info = {
			{ .clk_name = "vic03", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "host1x" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRE, .mask = BIT(5) },
			{ .offset = LVL2_END },
		},
		.handle_lvl2_ovr = handle_lvl2_ovr_vic,
		.reset_id = { TEGRA210_CLK_VIC03 },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_NVDEC] = {
		.name = "nvdec",
		.clk_info = {
			{ .clk_name = "nvdec", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "nvjpg" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRE,
			  .mask = BIT(9) | BIT(31) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_NVDEC },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_NVJPG] = {
		.name = "nvjpg",
		.clk_info = {
			{ .clk_name = "nvjpg", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "nvdec" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRE,
			  .mask = BIT(9) | BIT(31) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_NVJPG },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_APE] = {
		.name = "ape",
		.clk_info = {
			{ .clk_name = "ape", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
			{ .clk_name = "aclk" },
			{ .clk_name = "i2s0" },
			{ .clk_name = "i2s1" },
			{ .clk_name = "i2s2" },
			{ .clk_name = "i2s3" },
			{ .clk_name = "i2s4" },
			{ .clk_name = "spdif_out" },
			{ .clk_name = "d_audio" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRC, .mask = BIT(1) },
			{ .offset = LVL2_CLK_GATE_OVRE,
			  .mask = BIT(10) | BIT(11) },
			{ .offset = LVL2_END },
		},
		.handle_lvl2_ovr = handle_lvl2_ovr_ape,
		.reset_id = { TEGRA210_CLK_APE },
		.reset_id_num = 1,
	},
	[TEGRA210_POWER_DOMAIN_VE2] = {
		.name = "ve2",
		.clk_info = {
			{ .clk_name = "ispb", .clk_type = CLK_ONLY },
		},
		.slcg_info = {
			{ .clk_name = "mc_capa" },
			{ .clk_name = "mc_cbpa" },
			{ .clk_name = "mc_ccpa" },
			{ .clk_name = "mc_cdpa" },
		},
		.lvl2_ovr_info = {
			{ .offset = LVL2_CLK_GATE_OVRD, .mask = BIT(22) },
			{ .offset = LVL2_END },
		},
		.reset_id = { TEGRA210_CLK_ISPB },
		.reset_id_num = 1,
	},
};

struct mc_client_hotreset_reg {
	u32 control_reg;
	u32 status_reg;
};

struct tegra210_powergate_info {
	bool valid;
	unsigned int mask;
	int part_id;
	struct tegra210_mc_client_info *mc_info;
	struct powergate_partition_info *part_info;
};

#define T210_POWERGATE_INFO(_pg_id, _pg_bit, _part_id, _mc_id)		\
[TEGRA210_POWER_DOMAIN_##_pg_id] = {						\
	.valid = true,							\
	.mask = BIT(_pg_bit),						\
	.part_id = TEGRA210_POWER_DOMAIN_##_part_id,				\
	.mc_info = &tegra210_pg_mc_info[TEGRA210_POWER_DOMAIN_##_mc_id],	\
	.part_info = &tegra210_pg_partition_info[TEGRA210_POWER_DOMAIN_##_part_id], \
}

static struct tegra210_powergate_info t210_pg_info[TEGRA210_POWER_DOMAIN_MAX] = {
	T210_POWERGATE_INFO(CRAIL, 0, CRAIL, CRAIL),
	[1] = { .valid = false },
	T210_POWERGATE_INFO(VENC, 2, VENC, VENC),
	T210_POWERGATE_INFO(PCIE, 3, PCIE, PCIE),
	T210_POWERGATE_INFO(VDEC, 4, VDEC, VDEC),
	T210_POWERGATE_INFO(L2, 5, L2, L2),
	T210_POWERGATE_INFO(MPE, 6, MPE, MPE),
	T210_POWERGATE_INFO(HEG, 7, HEG, HEG),
	T210_POWERGATE_INFO(SATA, 8, SATA, SATA),
	T210_POWERGATE_INFO(CPU1, 9, CPU1, CPU1),
	T210_POWERGATE_INFO(CPU2, 10, CPU2, CPU2),
	T210_POWERGATE_INFO(CPU3, 11, CPU3, CPU3),
	T210_POWERGATE_INFO(CELP, 12, CELP, CELP),
	T210_POWERGATE_INFO(3D1, 13, 3D1, 3D1),
	T210_POWERGATE_INFO(CPU0, 14, CPU0, CPU0),
	T210_POWERGATE_INFO(C0NC, 15, C0NC, C0NC),
	T210_POWERGATE_INFO(C1NC, 16, C1NC, C1NC),
	T210_POWERGATE_INFO(SOR, 17, SOR, SOR),
	T210_POWERGATE_INFO(DISA, 18, DISA, DISA),
	T210_POWERGATE_INFO(DISB, 19, DISB, DISB),
	T210_POWERGATE_INFO(XUSBA, 20, XUSBA, XUSBA),
	T210_POWERGATE_INFO(XUSBB, 21, XUSBB, XUSBB),
	T210_POWERGATE_INFO(XUSBC, 22, XUSBC, XUSBC),
	T210_POWERGATE_INFO(VIC, 23, VIC, VIC),
	T210_POWERGATE_INFO(NVDEC, 25, NVDEC, NVDEC),
	T210_POWERGATE_INFO(NVJPG, 26, NVJPG, NVJPG),
	T210_POWERGATE_INFO(APE, 27, APE, APE),
	T210_POWERGATE_INFO(VE2, 29, VE2, VE2),
};

#define PMC_GPU_RG_CONTROL		0x2d4

#define PWRGATE_CLAMP_STATUS		0x2c
#define PWRGATE_TOGGLE			0x30
#define PWRGATE_TOGGLE_START		(1 << 8)
#define REMOVE_CLAMPING			0x34
#define PWRGATE_STATUS			0x38

static DEFINE_SPINLOCK(tegra210_pg_lock);

static void __iomem *tegra_mc;
static void __iomem *tegra_car;
static void __iomem *tegra_ape;
static void __iomem *tegra_dispa;
static void __iomem *tegra_vic;

static int tegra210_pg_powergate_partition(int id);
static int tegra210_pg_unpowergate_partition(int id);
static int tegra210_pg_mc_flush(int id);
static int tegra210_pg_mc_flush_done(int id);

static bool tegra210b01;

static u32  __maybe_unused mc_read(unsigned long reg)
{
        return readl(tegra_mc + reg);
}

#define HOTRESET_READ_COUNTS		5

static const char *tegra210_pg_get_name(int id)
{
	return t210_pg_info[id].part_info->name;
}

static spinlock_t *tegra210_pg_get_lock(void)
{
	return &tegra210_pg_lock;
}

static bool tegra210_pg_skip(int id)
{
	switch (t210_pg_info[id].part_id) {
	case TEGRA210_POWER_DOMAIN_VENC:
	case TEGRA210_POWER_DOMAIN_VE2:
		/* T210b01 has SE2 in place of ISP2 and powergate
		 * is not supported for SE2.
		 */
		if (tegra210b01)
			return true;
	default:
		return false;
	}
}

static bool tegra210_pg_is_powered(int id)
{
	u32 status = 0;

	status = tegra_pmc_readl(PWRGATE_STATUS) & t210_pg_info[id].mask;

	return !!status;
}

static int tegra_powergate_set(int id, bool new_state)
{
	bool status;
	unsigned long flags;
	spinlock_t *lock;
	u32 reg;

	/* 10us timeout for toggle operation if it takes affect*/
	int toggle_timeout = 10;

	/* 100 * 10 = 1000us timeout for toggle command to take affect in case
	   of contention with h/w initiated CPU power gating */
	int contention_timeout = 100;

	if (tegra_cpu_is_asim())
		return 0;

	lock = tegra210_pg_get_lock();

	spin_lock_irqsave(lock, flags);

	status = !!(tegra_pmc_readl(PWRGATE_STATUS) & t210_pg_info[id].mask);

	if (status == new_state) {
		spin_unlock_irqrestore(lock, flags);
		return 0;
	}

	switch (id) {
	case TEGRA210_POWER_DOMAIN_CPU0:
	case TEGRA210_POWER_DOMAIN_CPU1:
	case TEGRA210_POWER_DOMAIN_CPU2:
	case TEGRA210_POWER_DOMAIN_CPU3:
		/* CPU ungated in s/w only during boot/resume with outer
		   waiting loop and no contention from other CPUs */
		tegra_pmc_writel_relaxed(PWRGATE_TOGGLE_START | id, PWRGATE_TOGGLE);
		tegra_pmc_readl(PWRGATE_TOGGLE);
		spin_unlock_irqrestore(lock, flags);
		return 0;

	default:
		break;
	}

	/* Wait if PMC is already processing some other power gating request */
	do {
		udelay(1);
		reg = tegra_pmc_readl(PWRGATE_TOGGLE);
		contention_timeout--;
	} while ((contention_timeout > 0) && (reg & PWRGATE_TOGGLE_START));

	if (contention_timeout <= 0)
		pr_err(" Timed out waiting for PMC to submit \
				new power gate request \n");
	contention_timeout = 100;

	/* Submit power gate request */
	tegra_pmc_writel_relaxed(PWRGATE_TOGGLE_START | id, PWRGATE_TOGGLE);

	/* Wait while PMC accepts the request */
	do {
		udelay(1);
		reg = tegra_pmc_readl(PWRGATE_TOGGLE);
		contention_timeout--;
	} while ((contention_timeout > 0) && (reg & PWRGATE_TOGGLE_START));

	if (contention_timeout <= 0)
		pr_err(" Timed out waiting for PMC to accept \
				new power gate request \n");
	contention_timeout = 100;

	/* Check power gate status */
	do {
		do {
			udelay(1);
			status = !!(tegra_pmc_readl(PWRGATE_STATUS) &
				    t210_pg_info[id].mask);

			toggle_timeout--;
		} while ((status != new_state) && (toggle_timeout > 0));

		toggle_timeout = 10;
		contention_timeout--;
	} while ((status != new_state) && (contention_timeout > 0));

	spin_unlock_irqrestore(lock, flags);

	if (status != new_state) {
		WARN(1, "Could not set powergate %d to %d", id, new_state);
		return -EBUSY;
	}

	trace_power_domain_target(tegra210_pg_get_name(id), new_state,
			raw_smp_processor_id());

	return 0;
}

static const char *clk_get_name(struct clk *clk)
{
	return __clk_get_name(clk);
}

static int powergate_module(int id)
{
	tegra210_pg_mc_flush(id);

	return tegra_powergate_set(id, false);
}

static int partition_clk_enable(struct powergate_partition_info *pg_info)
{
	int ret;
	u32 idx;
	struct clk *clk;
	struct partition_clk_info *clk_info;

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		clk_info = &pg_info->clk_info[idx];
		clk = clk_info->clk_ptr;
		if (IS_ERR(clk) || !clk)
			break;

		if (clk_info->clk_type != RST_ONLY) {
			ret = clk_prepare_enable(clk);
			if (ret)
				goto err_clk_en;
		}
	}

	return 0;

err_clk_en:
	WARN(1, "Could not enable clk %s, error %d", clk_get_name(clk), ret);
	while (idx--) {
		clk_info = &pg_info->clk_info[idx];
		if (clk_info->clk_type != RST_ONLY)
			clk_disable_unprepare(clk_info->clk_ptr);
	}

	return ret;
}

static void partition_clk_disable(struct powergate_partition_info *pg_info)
{
	u32 idx;
	struct clk *clk;
	struct partition_clk_info *clk_info;

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		clk_info = &pg_info->clk_info[idx];
		clk = clk_info->clk_ptr;

		if (IS_ERR(clk) || !clk)
			break;

		if (clk_info->clk_type != RST_ONLY)
			clk_disable_unprepare(clk);
	}
}

static void get_clk_info(struct powergate_partition_info *pg_info)
{
	int idx;

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		if (!pg_info->clk_info[idx].clk_name)
			break;

		pg_info->clk_info[idx].clk_ptr =
			clk_get_sys(NULL, pg_info->clk_info[idx].clk_name);

		if (IS_ERR_OR_NULL(pg_info->clk_info[idx].clk_ptr))
			WARN(1, "Could not find clock %s for %s partition\n",
				pg_info->clk_info[idx].clk_name,
				pg_info->name);
	}
}

static void powergate_partition_assert_reset(struct powergate_partition_info *pg_info)
{
	tegra_rst_assertv(&pg_info->reset_id[0], pg_info->reset_id_num);
}

static void powergate_partition_deassert_reset(struct powergate_partition_info *pg_info)
{
	tegra_rst_deassertv(&pg_info->reset_id[0], pg_info->reset_id_num);
}

static int slcg_clk_enable(struct powergate_partition_info *pg_info)
{
	int ret;
	u32 idx;
	struct clk *clk;
	struct partition_clk_info *slcg_info;

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		slcg_info = &pg_info->slcg_info[idx];
		clk = slcg_info->clk_ptr;
		if (IS_ERR(clk) || !clk)
			break;

		ret = clk_prepare_enable(clk);
		if (ret)
			goto err_clk_en;
	}

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		u32 val;
		struct lvl2_ovr_info *lvl2;

		lvl2 = &pg_info->lvl2_ovr_info[idx];
		if (lvl2->offset == LVL2_END)
			break;
		val = readl_relaxed(tegra_car + lvl2->offset);
		val |= lvl2->mask;
		writel(val, tegra_car + lvl2->offset);
	}

	return 0;

err_clk_en:
	WARN(1, "Could not enable clk %s, error %d", __clk_get_name(clk), ret);
	while (idx--) {
		slcg_info = &pg_info->slcg_info[idx];
		clk_disable_unprepare(slcg_info->clk_ptr);
	}

	return ret;
}

static void slcg_clk_disable(struct powergate_partition_info *pg_info)
{
	u32 idx;
	struct clk *clk;
	struct partition_clk_info *slcg_info;

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		slcg_info = &pg_info->slcg_info[idx];
		clk = slcg_info->clk_ptr;

		if (IS_ERR(clk) || !clk)
			break;

		clk_disable_unprepare(clk);
	}

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		u32 val;
		struct lvl2_ovr_info *lvl2;

		lvl2 = &pg_info->lvl2_ovr_info[idx];
		lvl2 = &pg_info->lvl2_ovr_info[idx];
		if (lvl2->offset == LVL2_END)
			break;
		val = readl_relaxed(tegra_car + lvl2->offset);
		val &= ~lvl2->mask;
		writel(val, tegra_car + lvl2->offset);
	}
}

static void get_slcg_info(struct powergate_partition_info *pg_info)
{
	int idx;

	for (idx = 0; idx < MAX_CLK_EN_NUM; idx++) {
		if (!pg_info->slcg_info[idx].clk_name)
			break;

		pg_info->slcg_info[idx].clk_ptr =
			clk_get_sys(NULL, pg_info->slcg_info[idx].clk_name);

		if (IS_ERR_OR_NULL(pg_info->slcg_info[idx].clk_ptr))
			pr_err("### Could not find clock %s for %s partition\n",
				pg_info->slcg_info[idx].clk_name,
				pg_info->name);
	}
}

static void handle_lvl2_ovr_ape(void)
{
	unsigned long flags;
	u32 i2s_ctrl;
	spinlock_t *lock;
	int i;
	void __iomem *i2s_base;

	lock = tegra210_pg_get_lock();
	spin_lock_irqsave(lock, flags);

	for (i = 0; i < TEGRA210_I2S_CTRLS; i++) {
		i2s_base = tegra_ape + TEGRA210_I2S_BASE
				+ i * TEGRA210_I2S_SIZE;
		i2s_ctrl = readl_relaxed(i2s_base + TEGRA210_I2S_CTRL);
		writel(i2s_ctrl | BIT(10), i2s_base + TEGRA210_I2S_CTRL);

		writel(0, i2s_base + TEGRA210_I2S_CG);
		readl_relaxed(i2s_base + TEGRA210_I2S_CG);
		udelay(1);
		writel(1, i2s_base + TEGRA210_I2S_CG);

		writel(i2s_ctrl, i2s_base + TEGRA210_I2S_CTRL);
	}

	spin_unlock_irqrestore(lock, flags);
}

static void handle_lvl2_ovr_disp(void)
{
	unsigned long flags;
	spinlock_t *lock;
	u32 val;

	lock = tegra210_pg_get_lock();
	spin_lock_irqsave(lock, flags);

	val = readl_relaxed(tegra_dispa + DC_COM_DSC_TOP_CTL);
	writel(val | BIT(2), tegra_dispa + DC_COM_DSC_TOP_CTL);
	readl_relaxed(tegra_dispa + DC_CMD_DISPLAY_COMMAND);
	writel(val, tegra_dispa + DC_COM_DSC_TOP_CTL);
	readl_relaxed(tegra_dispa + DC_CMD_DISPLAY_COMMAND);

	spin_unlock_irqrestore(lock, flags);
}

static void handle_lvl2_ovr_vic(void)
{
	unsigned long flags;
	spinlock_t *lock;
	u32 val;

	lock = tegra210_pg_get_lock();
	spin_lock_irqsave(lock, flags);

	val = readl_relaxed(tegra_vic + NV_PVIC_THI_SLCG_OVERRIDE_LOW);
	writel(val | BIT(0) | GENMASK(7,2) | BIT(24),
		tegra_vic + NV_PVIC_THI_SLCG_OVERRIDE_LOW);
	readl_relaxed(tegra_vic + NV_PVIC_THI_SLCG_OVERRIDE_LOW);
	udelay(1);
	writel(val, tegra_vic + NV_PVIC_THI_SLCG_OVERRIDE_LOW);

	spin_unlock_irqrestore(lock, flags);
}

static int tegra210_powergate_remove_clamping(int id)
{
	u32 mask;
	int contention_timeout = 100;

	/*
	 * PCIE and VDE clamping masks are swapped with respect to their
	 * partition ids
	 */
	if (id ==  TEGRA210_POWER_DOMAIN_VDEC)
		mask = t210_pg_info[TEGRA210_POWER_DOMAIN_PCIE].mask;
	else if (id == TEGRA210_POWER_DOMAIN_PCIE)
		mask = t210_pg_info[TEGRA210_POWER_DOMAIN_VDEC].mask;
	else
		mask = t210_pg_info[id].mask;

	tegra_pmc_writel_relaxed(mask, REMOVE_CLAMPING);
	/* Wait until clamp is removed */
	do {
		udelay(1);
		contention_timeout--;
	} while ((contention_timeout > 0)
			&& (tegra_pmc_readl(PWRGATE_CLAMP_STATUS) & BIT(id)));

	WARN(contention_timeout <= 0, "Couldn't remove clamping");

	return 0;
}

static int __tegra1xx_powergate(int id, struct powergate_partition_info *pg_info)
{
	int ret;

	/* If first clk_ptr is null, fill clk info for the partition */
	if (!pg_info->clk_info[0].clk_ptr)
		get_clk_info(pg_info);

	ret = partition_clk_enable(pg_info);
	if (ret) {
		WARN(1, "Couldn't enable clock");
		return ret;
	}

	udelay(10);

	tegra210_pg_mc_flush(id);

	udelay(10);

	powergate_partition_assert_reset(pg_info);

	udelay(10);

	/* Powergating is done only if refcnt of all clks is 0 */
	partition_clk_disable(pg_info);

	udelay(10);

	ret = tegra_powergate_set(id, false);
	if (ret)
		goto err_power_off;

	return 0;

err_power_off:
	WARN(1, "Could not Powergate Partition %d", id);
	return ret;
}

static int tegra1xx_powergate(int id, struct powergate_partition_info *pg_info)
{
	return __tegra1xx_powergate(id, pg_info);
}

static int __tegra1xx_unpowergate(int id, struct powergate_partition_info *pg_info)
{
	int ret;

	/* If first clk_ptr is null, fill clk info for the partition */
	if (!pg_info->clk_info[0].clk_ptr)
		get_clk_info(pg_info);

	if (!pg_info->slcg_info[0].clk_ptr)
		get_slcg_info(pg_info);

	if (tegra210_pg_is_powered(id)) {
		return 0;
	}

	ret = tegra_powergate_set(id, true);
	if (ret)
		goto err_power;

	udelay(10);

	/* Un-Powergating fails if all clks are not enabled */
	ret = partition_clk_enable(pg_info);
	if (ret)
		goto err_clk_on;

	powergate_partition_assert_reset(pg_info);

	udelay(10);

	ret = tegra210_powergate_remove_clamping(id);
	if (ret)
		goto err_clamp;

	udelay(10);

	if (!pg_info->skip_reset) {
		powergate_partition_deassert_reset(pg_info);

		udelay(10);
	}

	tegra210_pg_mc_flush_done(id);

	udelay(10);

	if (!tegra210b01) {
		slcg_clk_enable(pg_info);

		if (pg_info->handle_lvl2_ovr)
			(pg_info->handle_lvl2_ovr)();

		slcg_clk_disable(pg_info);
	}

	/* Disable all clks enabled earlier. Drivers should enable clks */
	partition_clk_disable(pg_info);

	return 0;

err_clamp:
	partition_clk_disable(pg_info);
err_clk_on:
	powergate_module(id);
err_power:
	WARN(1, "Could not Un-Powergate %d", id);
	return ret;
}

static int tegra1xx_unpowergate(int id,
				struct powergate_partition_info *pg_info)
{
	return __tegra1xx_unpowergate(id, pg_info);
}

static int tegra210_pg_mc_flush(int id)
{
	u32 idx;
	enum mc_client_type mc_client_bit;
	int ret = EINVAL;

	for (idx = 0; idx < MAX_HOTRESET_CLIENT_NUM; idx++) {
		mc_client_bit =
			t210_pg_info[id].mc_info->hot_reset_clients[idx];
		if (mc_client_bit == MC_CLIENT_LAST)
			break;
		ret = tegra_mc_flush(mc_client_bit);
		if (ret)
			break;
	}

	return ret;
}

static int tegra210_pg_mc_flush_done(int id)
{
	u32 idx;
	enum mc_client_type mc_client_bit;
	int ret = -EINVAL;

	for (idx = 0; idx < MAX_HOTRESET_CLIENT_NUM; idx++) {
		mc_client_bit =
			t210_pg_info[id].mc_info->hot_reset_clients[idx];
		if (mc_client_bit == MC_CLIENT_LAST)
			break;
		ret = tegra_mc_flush_done(mc_client_bit);
		if (ret)
			break;
	}
	wmb();

	return ret;
}

static int tegra210_pg_powergate(int id)
{
	struct powergate_partition_info *partition = t210_pg_info[id].part_info;
	int ret = 0;

	trace_powergate(__func__, tegra210_pg_get_name(id), id, 1, 0);
	mutex_lock(&partition->pg_mutex);

	if (--partition->refcount > 0)
		goto exit_unlock;

	if ((partition->refcount < 0) || !tegra210_pg_is_powered(id)) {
		WARN(1, "Partition %s already powergated, refcount and status mismatch\n",
		     partition->name);
		goto exit_unlock;
	}

	ret = tegra1xx_powergate(id, partition);

exit_unlock:
	mutex_unlock(&partition->pg_mutex);
	trace_powergate(__func__, tegra210_pg_get_name(id), id, 0, ret);
	return ret;
}

static int tegra210_pg_unpowergate(int id)
{
	struct powergate_partition_info *partition = t210_pg_info[id].part_info;
	int ret = 0;

	trace_powergate(__func__, tegra210_pg_get_name(id), id, 1, 0);
	mutex_lock(&partition->pg_mutex);

	if (partition->refcount++ > 0)
		goto exit_unlock;

	if (tegra210_pg_is_powered(id)) {
		WARN(1, "Partition %s is already unpowergated, refcount and status mismatch\n",
		     partition->name);
		goto exit_unlock;
	}

	ret = tegra1xx_unpowergate(id, partition);

exit_unlock:
	mutex_unlock(&partition->pg_mutex);
	trace_powergate(__func__, tegra210_pg_get_name(id), id, 0, ret);
	return ret;
}

static int tegra210_pg_powergate_sor(int id)
{
	int ret;

	ret = tegra210_pg_powergate(id);
	if (ret)
		return ret;

	ret = tegra210_pg_powergate_partition(TEGRA210_POWER_DOMAIN_SOR);
	if (ret)
		return ret;

	return 0;
}

static int tegra210_pg_unpowergate_sor(int id)
{
	int ret;

	ret = tegra210_pg_unpowergate_partition(TEGRA210_POWER_DOMAIN_SOR);
	if (ret)
		return ret;

	ret = tegra210_pg_unpowergate(id);
	if (ret) {
		tegra210_pg_powergate_partition(TEGRA210_POWER_DOMAIN_SOR);
		return ret;
	}

	return 0;
}

static int tegra210_pg_nvdec_powergate(int id)
{
	tegra210_pg_powergate(TEGRA210_POWER_DOMAIN_NVDEC);
	tegra210_pg_powergate_partition(TEGRA210_POWER_DOMAIN_NVJPG);

	return 0;
}

static int tegra210_pg_nvdec_unpowergate(int id)
{
	tegra210_pg_unpowergate_partition(TEGRA210_POWER_DOMAIN_NVJPG);
	tegra210_pg_unpowergate(TEGRA210_POWER_DOMAIN_NVDEC);

	return 0;
}

static int tegra210_pg_sata_powergate(int id)
{
	tegra210_set_sata_pll_seq_sw(true);
	tegra210_pg_powergate(TEGRA210_POWER_DOMAIN_SATA);

	return 0;
}

static int tegra210_pg_sata_unpowergate(int id)
{
	tegra210_pg_unpowergate(TEGRA210_POWER_DOMAIN_SATA);
	tegra210_set_sata_pll_seq_sw(false);

	return 0;
}

static int tegra210_pg_powergate_partition(int id)
{
	int ret;

	switch (t210_pg_info[id].part_id) {
		case TEGRA210_POWER_DOMAIN_DISA:
		case TEGRA210_POWER_DOMAIN_DISB:
		case TEGRA210_POWER_DOMAIN_VENC:
			ret = tegra210_pg_powergate_sor(id);
			break;
		case TEGRA210_POWER_DOMAIN_NVDEC:
			ret = tegra210_pg_nvdec_powergate(id);
			break;
		case TEGRA210_POWER_DOMAIN_SATA:
			ret = tegra210_pg_sata_powergate(id);
			break;
		default:
			ret = tegra210_pg_powergate(id);
	}

	return ret;
}

static int tegra210_pg_unpowergate_partition(int id)
{
	int ret;

	switch (t210_pg_info[id].part_id) {
		case TEGRA210_POWER_DOMAIN_DISA:
		case TEGRA210_POWER_DOMAIN_DISB:
		case TEGRA210_POWER_DOMAIN_VENC:
			ret = tegra210_pg_unpowergate_sor(id);
			break;
		case TEGRA210_POWER_DOMAIN_NVDEC:
			ret = tegra210_pg_nvdec_unpowergate(id);
			break;
		case TEGRA210_POWER_DOMAIN_SATA:
			ret = tegra210_pg_sata_unpowergate(id);
			break;
		default:
			ret = tegra210_pg_unpowergate(id);
	}

	return ret;
}

static int tegra210_pg_init_refcount(void)
{
	int i;

	for (i = 0; i < TEGRA210_POWER_DOMAIN_MAX; i++) {
		if (!t210_pg_info[i].valid)
			continue;

		/* Consider main partion ID only */
		if (i != t210_pg_info[i].part_id)
			continue;

		if (tegra210_pg_is_powered(i))
			t210_pg_info[i].part_info->refcount = 1;
		else
			t210_pg_info[i].part_info->disable_after_boot = 0;

		mutex_init(&t210_pg_info[i].part_info->pg_mutex);
	}

	/* SOR refcount depends on other units */
	t210_pg_info[TEGRA210_POWER_DOMAIN_SOR].part_info->refcount =
		(tegra210_pg_is_powered(TEGRA210_POWER_DOMAIN_DISA) ? 1 : 0) +
		(tegra210_pg_is_powered(TEGRA210_POWER_DOMAIN_DISB) ? 1 : 0) +
		(tegra210_pg_is_powered(TEGRA210_POWER_DOMAIN_VENC) ? 1 : 0);

	/* NVJPG refcount needs to plus 1 if NVDEC is enabled */
	t210_pg_info[TEGRA210_POWER_DOMAIN_NVJPG].part_info->refcount +=
		(tegra210_pg_is_powered(TEGRA210_POWER_DOMAIN_NVDEC) ? 1 : 0);

	tegra210_pg_powergate_partition(TEGRA210_POWER_DOMAIN_XUSBA);
	tegra210_pg_powergate_partition(TEGRA210_POWER_DOMAIN_XUSBB);
	tegra210_pg_powergate_partition(TEGRA210_POWER_DOMAIN_XUSBC);

	return 0;
}

static bool tegra210_powergate_id_is_valid(int id)
{
	if ((id < 0) || (id >= TEGRA210_POWER_DOMAIN_MAX))
		return false;

	return t210_pg_info[id].valid;
}

static int tegra210_powergate_cpuid_to_powergate_id(int cpu)
{
	switch (cpu) {
	case 0:
		return TEGRA210_POWER_DOMAIN_CPU0;
	case 1:
		return TEGRA210_POWER_DOMAIN_CPU1;
	case 2:
		return TEGRA210_POWER_DOMAIN_CPU2;
	case 3:
		return TEGRA210_POWER_DOMAIN_CPU3;
	default:
		return -1;
	}

	return -1;
}

static struct tegra_powergate_driver_ops tegra210_pg_ops = {
	.soc_name = "tegra210",

	.num_powerdomains = TEGRA210_POWER_DOMAIN_MAX,
	.powergate_id_is_soc_valid = tegra210_powergate_id_is_valid,
	.powergate_cpuid_to_powergate_id =
				tegra210_powergate_cpuid_to_powergate_id,

	.get_powergate_lock = tegra210_pg_get_lock,
	.get_powergate_domain_name = tegra210_pg_get_name,

	.powergate_partition = tegra210_pg_powergate_partition,
	.unpowergate_partition = tegra210_pg_unpowergate_partition,

	.powergate_mc_flush = tegra210_pg_mc_flush,
	.powergate_mc_flush_done = tegra210_pg_mc_flush_done,

	.powergate_skip = tegra210_pg_skip,

	.powergate_is_powered = tegra210_pg_is_powered,

	.powergate_init_refcount = tegra210_pg_init_refcount,
	.powergate_remove_clamping = tegra210_powergate_remove_clamping,
};

#define TEGRA_MC_BASE   0x70019000
#define TEGRA_CAR_BASE	0x60006000
#define TEGRA_APE_BASE	0x702c0000
#define TEGRA_DISPA_BASE 0x54200000
#define TEGRA_VIC_BASE	0x54340000
#define TEGRA_VI_BASE	0x54080000
struct tegra_powergate_driver_ops *tegra210_powergate_init_chip_support(void)
{
	u32 hid, chipid, major;

	tegra_mc = ioremap(TEGRA_MC_BASE, 4096);
	if (!tegra_mc)
		return NULL;
	tegra_car = ioremap(TEGRA_CAR_BASE, 4096);
	if (!tegra_car)
		return NULL;
	tegra_ape = ioremap(TEGRA_APE_BASE, 256*1024);
	if (!tegra_ape)
		return NULL;
	tegra_dispa = ioremap(TEGRA_DISPA_BASE, 256*1024);
	if (!tegra_dispa)
		return NULL;
	tegra_vic = ioremap(TEGRA_VIC_BASE, 256*1024);
	if (!tegra_vic)
		return NULL;

	hid = tegra_read_chipid();
	chipid = tegra_hidrev_get_chipid(hid);
	major = tegra_hidrev_get_majorrev(hid);
	tegra210b01 = chipid == TEGRA210B01 && major >= 2;

	return &tegra210_pg_ops;
}

static int __init tegra210_disable_boot_partitions(void)
{
	int i;

	if (!soc_is_tegra210_n_before())
		return 0;

	pr_info("Disable partitions left on by BL\n");
	for (i = 0; i < TEGRA210_POWER_DOMAIN_MAX; i++) {
		if (!t210_pg_info[i].valid)
			continue;

		/* consider main partion ID only */
		if (i != t210_pg_info[i].part_id)
			continue;

		if (t210_pg_info[i].part_info->disable_after_boot) {
			pr_info("  %s\n", t210_pg_info[i].part_info->name);
			tegra210_pg_powergate_partition(i);
		}
	}

	return 0;
}
late_initcall(tegra210_disable_boot_partitions);
