/*
 * Copyright (c) 2012-2018, NVIDIA CORPORATION.  All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __SOC_TEGRA_CHIP_ID_H_
#define __SOC_TEGRA_CHIP_ID_H_

#define TEGRA20		0x20
#define TEGRA30		0x30
#define TEGRA114	0x35
#define TEGRA148	0x14
#define TEGRA124	0x40
#define TEGRA132	0x13
#define TEGRA210	0x21
#define TEGRA210B01	0x21
#define TEGRA186	0x18
#define TEGRA194	0x19
#define TEGRA234	0x23

#define TEGRA_FUSE_SKU_CALIB_0	0xf0
#define TEGRA30_FUSE_SATA_CALIB	0x124

#ifndef __ASSEMBLY__

#include <linux/of.h>

/* Tegra HIDREV/ChipID helper macros */
#define HIDREV_CHIPID_SHIFT		0x8
#define HIDREV_CHIPID_MASK		0xff
#define HIDREV_MAJORREV_SHIFT		0x4
#define HIDREV_MAJORREV_MASK		0xf
#define HIDREV_MINORREV_SHIFT		0x10
#define HIDREV_MINORREV_MASK		0xf
#define HIDREV_PRE_SI_PLAT_SHIFT	0x14
#define HIDREV_PRE_SI_PLAT_MASK		0xf

/* Helper functions to read HIDREV fields */
static inline u32 tegra_hidrev_get_chipid(u32 chipid)
{
	return (chipid >> HIDREV_CHIPID_SHIFT) & HIDREV_CHIPID_MASK;
}

static inline u32 tegra_hidrev_get_majorrev(u32 chipid)
{
	return (chipid >> HIDREV_MAJORREV_SHIFT) & HIDREV_MAJORREV_MASK;
}

static inline u32 tegra_hidrev_get_minorrev(u32 chipid)
{
	return (chipid >> HIDREV_MINORREV_SHIFT) & HIDREV_MINORREV_MASK;
}

static inline u32 tegra_hidrev_get_pre_si_plat(u32 chipid)
{
	return (chipid >> HIDREV_PRE_SI_PLAT_SHIFT) & HIDREV_PRE_SI_PLAT_MASK;
}

u32 tegra_read_chipid(void);

enum tegra_revision {
	TEGRA_REVISION_UNKNOWN = 0,
	TEGRA_REVISION_A01,
	TEGRA_REVISION_A01q,
	TEGRA_REVISION_A02,
	TEGRA_REVISION_A02p,
	TEGRA_REVISION_A03,
	TEGRA_REVISION_A03p,
	TEGRA_REVISION_A04,
	TEGRA_REVISION_A04p,
	TEGRA210_REVISION_A01,
	TEGRA210_REVISION_A01q,
	TEGRA210_REVISION_A02,
	TEGRA210_REVISION_A02p,
	TEGRA210_REVISION_A03,
	TEGRA210_REVISION_A03p,
	TEGRA210_REVISION_A04,
	TEGRA210_REVISION_A04p,
	TEGRA210B01_REVISION_A01,
	TEGRA186_REVISION_A01,
	TEGRA186_REVISION_A01q,
	TEGRA186_REVISION_A02,
	TEGRA186_REVISION_A02p,
	TEGRA186_REVISION_A03,
	TEGRA186_REVISION_A03p,
	TEGRA186_REVISION_A04,
	TEGRA186_REVISION_A04p,
	TEGRA194_REVISION_A01,
	TEGRA194_REVISION_A02,
	TEGRA194_REVISION_A02p,
	TEGRA_REVISION_QT,
	TEGRA_REVISION_SIM,
	TEGRA_REVISION_MAX,
};

enum tegra_ucm {
	TEGRA_UCM1 = 0,
	TEGRA_UCM2,
};

/* wrappers for the old fuse.h names */
#define soc_process_id core_process_id

struct tegra_sku_info {
	int sku_id;
	int cpu_process_id;
	int cpu_speedo_id;
	int cpu_speedo_value;
	int cpu_iddq_value;
	int core_process_id;
	int soc_speedo_id;
	int soc_speedo_value;
	int soc_iddq_value;
	int gpu_speedo_id;
	int gpu_process_id;
	int gpu_speedo_value;
	int gpu_iddq_value;
	enum tegra_revision revision;
	enum tegra_revision id_and_rev;
	enum tegra_ucm ucm;
	int speedo_rev;
};

u32 tegra_read_straps(void);
u32 tegra_read_chipid(void);
int tegra_miscreg_set_erd(u64 err_config);

extern struct tegra_sku_info tegra_sku_info;

enum tegra_chipid {
	TEGRA_CHIPID_UNKNOWN = 0,
	TEGRA_CHIPID_TEGRA14 = 0x14,
	TEGRA_CHIPID_TEGRA2 = 0x20,
	TEGRA_CHIPID_TEGRA3 = 0x30,
	TEGRA_CHIPID_TEGRA11 = 0x35,
	TEGRA_CHIPID_TEGRA12 = 0x40,
	TEGRA_CHIPID_TEGRA13 = 0x13,
	TEGRA_CHIPID_TEGRA21 = 0x21,
	TEGRA_CHIPID_TEGRA18 = 0x18,
	TEGRA_CHIPID_TEGRA19 = 0x19,
	TEGRA_CHIPID_TEGRA23 = 0x23,
};

enum tegra_platform {
	TEGRA_PLATFORM_SILICON = 0,
	TEGRA_PLATFORM_QT,
	TEGRA_PLATFORM_LINSIM,
	TEGRA_PLATFORM_FPGA,
	TEGRA_PLATFORM_UNIT_FPGA,
	TEGRA_PLATFORM_VDK,
	TEGRA_PLATFORM_MAX,
};

enum tegra_bondout_dev {
	BOND_OUT_CPU	= 0,
	BOND_OUT_ISPB	= 3,
	BOND_OUT_RTC,
	BOND_OUT_TMR,
	BOND_OUT_UARTA,
	BOND_OUT_UARTB,
	BOND_OUT_GPIO,
	BOND_OUT_SDMMC2,
	BOND_OUT_SPDIF,
	BOND_OUT_I2S2,
	BOND_OUT_ISC1,
	BOND_OUT_SDMMC1	= 14,
	BOND_OUT_SDMMC4,
	BOND_OUT_TWC,
	BOND_OUT_PWM,
	BOND_OUT_I2S3,
	BOND_OUT_VI	= 20,
	BOND_OUT_USBD	= 22,
	BOND_OUT_ISP,
	BOND_OUT_DISP2	= 26,
	BOND_OUT_DISP1,
	BOND_OUT_HOST1X,
	BOND_OUT_I2S1	= 30,
	BOND_OUT_CACHE2,
	BOND_OUT_MEM,
	BOND_OUT_AHBDMA,
	BOND_OUT_APBDMA,
	BOND_OUT_STAT_MON = 37,
	BOND_OUT_PMC,
	BOND_OUT_FUSE,
	BOND_OUT_KFUSE,
	BOND_OUT_SPI1,
	BOND_OUT_SPI2	= 44,
	BOND_OUT_XIO,
	BOND_OUT_SPI3,
	BOND_OUT_I2C5,
	BOND_OUT_DSI,
	BOND_OUT_CSI,
	BOND_OUT_I2C2	= 54,
	BOND_OUT_UARTC,
	BOND_OUT_MIPI_CAL,
	BOND_OUT_EMC,
	BOND_OUT_USB2,
	BOND_OUT_BSEV	= 63,
	BOND_OUT_UARTD	= 65,
	BOND_OUT_I2C3	= 67,
	BOND_OUT_SPI4,
	BOND_OUT_SDMMC3,
	BOND_OUT_PCIE,
	BOND_OUT_OWR,
	BOND_OUT_AFI,
	BOND_OUT_CSITE,
	BOND_OUT_LA	= 76,
	BOND_OUT_SOC_THERM = 78,
	BOND_OUT_DTV,
	BOND_OUT_I2C_SLOW = 81,
	BOND_OUT_DSIB,
	BOND_OUT_TSEC,
	BOND_OUT_IRAMA,
	BOND_OUT_IRAMB,
	BOND_OUT_IRAMC,
	BOND_OUT_IRAMD,
	BOND_OUT_CRAM2,
	BOND_OUT_XUSB_HOST,
	BOND_OUT_SUS_OUT = 92,
	BOND_OUT_DEV2_OUT,
	BOND_OUT_DEV1_OUT,
	BOND_OUT_XUSB_DEV,
	BOND_OUT_CPUG,
	BOND_OUT_MSELECT = BOND_OUT_CPUG + 3,
	BOND_OUT_TSENSOR,
	BOND_OUT_I2S4,
	BOND_OUT_I2S5,
	BOND_OUT_I2C4,
	BOND_OUT_AHUB = BOND_OUT_I2C4 + 3,
	BOND_OUT_HDA2CODEC_2X = BOND_OUT_AHUB + 5,
	BOND_OUT_ATOMICS,
	BOND_OUT_SPDIF_DOUBLER = BOND_OUT_ATOMICS + 6,
	BOND_OUT_ACTMON,
	BOND_OUT_EXTPERIPH1,
	BOND_OUT_EXTPERIPH2,
	BOND_OUT_EXTPERIPH3,
	BOND_OUT_SATA_OOB,
	BOND_OUT_SATA,
	BOND_OUT_HDA,
	BOND_OUT_TZRAM,
	BOND_OUT_SE,
	BOND_OUT_HDA2HDMICODEC,
	BOND_OUT_RESERVED1,
	BOND_OUT_PCIERX0,
	BOND_OUT_PCIERX1,
	BOND_OUT_PCIERX2,
	BOND_OUT_PCIERX3,
	BOND_OUT_PCIERX4,
	BOND_OUT_PCIERX5,
	BOND_OUT_CEC,
	BOND_OUT_XUSB = BOND_OUT_HDA2HDMICODEC + 15,
	BOND_OUT_SPARE = BOND_OUT_HDA2HDMICODEC + 32,
	BOND_OUT_SOR0 = BOND_OUT_SPARE + 22,
	BOND_OUT_SOR1 = BOND_OUT_SPARE + 23,
	BOND_OUT_GPU = BOND_OUT_SPARE + 24,
	BOND_OUT_SPARE1 = BOND_OUT_SPARE + 32,
	BOND_OUT_NVDEC = BOND_OUT_SPARE1 + 2,
	BOND_OUT_NVJPG,
	BOND_OUT_AXIAP,
	BOND_OUT_APE = BOND_OUT_SPARE1 + 6,
	BOND_OUT_ADSP,
	BOND_OUT_TSECB = BOND_OUT_SPARE1 + 14,
	BOND_OUT_NVENC = BOND_OUT_SPARE1 + 27,
	BOND_OUT_VIC = BOND_OUT_SPARE1 + 18
};

extern enum tegra_revision tegra_revision;
enum tegra_chipid tegra_get_chipid(void);
unsigned int tegra_get_minor_rev(void);
int tegra_get_lane_owner_info(void);

int tegra_split_mem_active(void);

/* check if in hypervisor mode */
bool is_tegra_hypervisor_mode(void);

void tegra_get_netlist_revision(u32 *netlist, u32* patchid);
bool tegra_cpu_is_asim(void);
bool tegra_cpu_is_dsim(void);
enum tegra_platform tegra_get_platform(void);
static inline bool tegra_platform_is_silicon(void)
{
	return tegra_get_platform() == TEGRA_PLATFORM_SILICON;
}
static inline bool tegra_platform_is_qt(void)
{
	return tegra_get_platform() == TEGRA_PLATFORM_QT;
}
static inline bool tegra_platform_is_fpga(void)
{
	return tegra_get_platform() == TEGRA_PLATFORM_FPGA;
}
static inline bool tegra_platform_is_unit_fpga(void)
{
	/* Deprecated API, return false */
	return false;
}
static inline bool tegra_platform_is_vdk(void)
{
	int plat = tegra_get_platform();
	return plat == TEGRA_PLATFORM_VDK;
}
static inline bool tegra_platform_is_sim(void)
{
	return tegra_platform_is_vdk();
}

extern void tegra_set_tegraid(u32 chipid, u32 major, u32 minor,
	u32 pre_si_plat, u32 nlist, u32 patch, const char *priv);
extern void tegra_get_tegraid_from_hw(void);
extern u32 tegra_read_emu_revid(void);
extern void tegra_set_tegraid_from_hw(void);
extern u8 tegra_get_chip_id(void);

#endif /* __ASSEMBLY__ */

#endif /* __SOC_TEGRA_CHIP_ID_H_ */
