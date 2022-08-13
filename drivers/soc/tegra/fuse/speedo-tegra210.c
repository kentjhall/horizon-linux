/*
 * Copyright (c) 2013-2017, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/bug.h>

#include <soc/tegra/fuse.h>

#include "fuse.h"

#define CPU_PROCESS_CORNERS	2
#define GPU_PROCESS_CORNERS	2
#define SOC_PROCESS_CORNERS	3

#define FUSE_CPU_SPEEDO_0	0x014
#define FUSE_CPU_SPEEDO_1	0x02c
#define FUSE_CPU_SPEEDO_2	0x030
#define FUSE_SOC_SPEEDO_0	0x034
#define FUSE_SOC_SPEEDO_1	0x038
#define FUSE_SOC_SPEEDO_2	0x03c
#define FUSE_CPU_IDDQ		0x018
#define FUSE_SOC_IDDQ		0x040
#define FUSE_GPU_IDDQ		0x128
#define FUSE_FT_REV		0x028

enum {
	THRESHOLD_INDEX_0,
	THRESHOLD_INDEX_1,
	THRESHOLD_INDEX_2,
	THRESHOLD_INDEX_COUNT,
};

static const u32 __initconst cpu_process_speedos[][CPU_PROCESS_CORNERS] = {
	{ 2119, UINT_MAX },
	{ 2119, UINT_MAX },
	{ 1650, UINT_MAX },
};

static const u32 __initconst gpu_process_speedos[][GPU_PROCESS_CORNERS] = {
	{ UINT_MAX, UINT_MAX },
	{ UINT_MAX, UINT_MAX },
	{ UINT_MAX, UINT_MAX },
};

static const u32 __initconst soc_process_speedos[][SOC_PROCESS_CORNERS] = {
	{ 1950,     2073,     UINT_MAX },
	{ UINT_MAX, UINT_MAX, UINT_MAX },
	{ 1598,     1709,     UINT_MAX },
};

static u8 __init get_speedo_revision(void)
{
	return tegra_fuse_read_spare(4) << 2 |
	       tegra_fuse_read_spare(3) << 1 |
	       tegra_fuse_read_spare(2) << 0;
}

static void __init rev_t210sku_to_speedo_ids(struct tegra_sku_info *sku_info,
					     u8 speedo_rev, int *threshold)
{
	int sku = sku_info->sku_id;
	int rev = sku_info->revision;
	bool a02 = (rev != TEGRA_REVISION_A01) && (rev != TEGRA_REVISION_A01q) &&
		(rev != TEGRA_REVISION_UNKNOWN);
	bool vcm31_sku = false;
	bool always_on = false;

	/* Assign to default */
	sku_info->cpu_speedo_id = 0;
	sku_info->soc_speedo_id = 0;
	sku_info->gpu_speedo_id = 0;
	sku_info->ucm = TEGRA_UCM1;
	*threshold = THRESHOLD_INDEX_0;
#ifdef CONFIG_OF
	vcm31_sku = of_property_read_bool(of_chosen, "nvidia,t210-vcm31-sku");
	always_on = of_property_read_bool(of_chosen,
					  "nvidia,tegra-always-on-personality");
#endif

	switch (sku) {
	case 0x00: /* Engineering SKU */
	case 0x01: /* Engineering SKU */
	case 0x13:
		if (a02) {
			sku_info->cpu_speedo_id = 5;
			sku_info->gpu_speedo_id = 2;
			break;
		}
		/* fall through for a01 */
	case 0x07:
	case 0x17:
	case 0x1F:
		if (vcm31_sku && sku == 0x17) {
			sku_info->cpu_speedo_id = 4;
			sku_info->soc_speedo_id = 1;
			sku_info->gpu_speedo_id = 4;
			*threshold = THRESHOLD_INDEX_1;
			break;
		}
		if (a02) {
			sku_info->cpu_speedo_id = 7;
			sku_info->gpu_speedo_id = 2;
			if (always_on) {
				sku_info->cpu_speedo_id = 8;
				sku_info->ucm = TEGRA_UCM2;
			}
			break;
		}
		/* fall through for a01 */
	case 0x27:
		if (a02) {
			sku_info->cpu_speedo_id = 1;
			sku_info->gpu_speedo_id = 2;
			break;
		}
		sku_info->gpu_speedo_id = 1;
		break;
	case 0x57:
		sku_info->cpu_speedo_id = 4;
		sku_info->soc_speedo_id = 1;
		sku_info->gpu_speedo_id = 4;
		*threshold = THRESHOLD_INDEX_1;
		break;
	case 0x83:
		if (a02) {
			sku_info->cpu_speedo_id = 3;
			sku_info->gpu_speedo_id = 3;
			break;
		}
		/* fall through for a01 */
	case 0x87:
		if (a02) {
			sku_info->cpu_speedo_id = 2;
			sku_info->gpu_speedo_id = 1;
			break;
		}
		/* fall through for a01 */
	case 0x8F:
		if (a02 && always_on) {
			sku_info->cpu_speedo_id = 9;
			sku_info->gpu_speedo_id = 2;
			sku_info->ucm = TEGRA_UCM2;
			break;
		}
	default:
		pr_err("Tegra210: invalid combination of SKU/revision/mode:\n");
		pr_err("Tegra210: SKU %#04x, rev %d, vcm31 %d, always_on %d\n",
		       sku, rev, vcm31_sku, always_on);
		/* Using the default for the error case */
		break;
	}
}

static void __init rev_t210b01sku_to_speedo_ids(struct tegra_sku_info *sku_info,
						u8 speedo_rev, int *threshold)
{
	int sku = sku_info->sku_id;
	int rev = sku_info->revision;

	/* Assign to default */
	sku_info->cpu_speedo_id = 0;
	sku_info->soc_speedo_id = 0;
	sku_info->gpu_speedo_id = 1;	/* T210b01 GPC PLL default NA mode */
	sku_info->ucm = TEGRA_UCM1;
	*threshold = THRESHOLD_INDEX_2;

	switch (sku) {
	case 0x00: /* Engineering SKU */
	case 0x01: /* Engineering SKU */
	case 0x83:
		break;
	case 0x87:
		sku_info->cpu_speedo_id = 3;
		break;
	default:
		pr_err("Tegra210b01: invalid combination of SKU/revision/mode:\n");
		pr_err("Tegra210b01: SKU %#04x, rev %d\n", sku, rev);
		/* Using the default for the error case */
		break;
	}
}

static bool __init is_t210b01_sku(struct tegra_sku_info *sku_info)
{
	switch (sku_info->id_and_rev) {
	case TEGRA210B01_REVISION_A01:
		return true;
	default:
		break;
	}
	return false;
}

static void __init rev_sku_to_speedo_ids(struct tegra_sku_info *sku_info,
					 u8 speedo_rev, int *threshold)
{
	if (is_t210b01_sku(sku_info))
		rev_t210b01sku_to_speedo_ids(sku_info, speedo_rev, threshold);
	else
		rev_t210sku_to_speedo_ids(sku_info, speedo_rev, threshold);
}

static int get_process_id(int value, const u32 *speedos, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++)
		if (value < speedos[i])
			return i;

	return -EINVAL;
}

void __init tegra210_init_speedo_data(struct tegra_sku_info *sku_info)
{
	int cpu_speedo[3], soc_speedo[3];
	unsigned int index;
	u8 speedo_revision = 0;

	BUILD_BUG_ON(ARRAY_SIZE(cpu_process_speedos) !=
			THRESHOLD_INDEX_COUNT);
	BUILD_BUG_ON(ARRAY_SIZE(gpu_process_speedos) !=
			THRESHOLD_INDEX_COUNT);
	BUILD_BUG_ON(ARRAY_SIZE(soc_process_speedos) !=
			THRESHOLD_INDEX_COUNT);

	/* Read speedo/IDDQ fuses */
	cpu_speedo[0] = tegra_fuse_read_early(FUSE_CPU_SPEEDO_0);
	cpu_speedo[1] = tegra_fuse_read_early(FUSE_CPU_SPEEDO_1);
	cpu_speedo[2] = tegra_fuse_read_early(FUSE_CPU_SPEEDO_2);

	soc_speedo[0] = tegra_fuse_read_early(FUSE_SOC_SPEEDO_0);
	soc_speedo[1] = tegra_fuse_read_early(FUSE_SOC_SPEEDO_1);
	soc_speedo[2] = tegra_fuse_read_early(FUSE_CPU_SPEEDO_2);

	sku_info->cpu_iddq_value = tegra_fuse_read_early(FUSE_CPU_IDDQ) * 4;
	sku_info->soc_iddq_value = tegra_fuse_read_early(FUSE_SOC_IDDQ) * 4;
	sku_info->gpu_iddq_value = tegra_fuse_read_early(FUSE_GPU_IDDQ) * 5;

	/*
	 * Determine CPU, GPU and SoC speedo values depending on speedo fusing
	 * revision. Note that GPU speedo value is fused in CPU_SPEEDO_2.
	 */
	speedo_revision = get_speedo_revision();
	sku_info->speedo_rev = speedo_revision;

	if (is_t210b01_sku(sku_info)) {
		sku_info->cpu_speedo_value = cpu_speedo[0];
		sku_info->gpu_speedo_value = cpu_speedo[2];
		sku_info->soc_speedo_value = soc_speedo[0];
	} else {
		if (speedo_revision >= 3) {
			sku_info->cpu_speedo_value = cpu_speedo[0];
			sku_info->gpu_speedo_value = cpu_speedo[2];
			sku_info->soc_speedo_value = soc_speedo[0];
		} else if (speedo_revision == 2) {
			sku_info->cpu_speedo_value =
				(-1938 + (1095 * cpu_speedo[0] / 100)) / 10;
			sku_info->gpu_speedo_value =
				(-1662 + (1082 * cpu_speedo[2] / 100)) / 10;
			sku_info->soc_speedo_value =
				(-705 + (1037 * soc_speedo[0] / 100)) / 10;
		} else {
			sku_info->cpu_speedo_value = 2100;
			sku_info->gpu_speedo_value = cpu_speedo[2] - 75;
			sku_info->soc_speedo_value = 1900;
		}
	}

	if ((sku_info->cpu_speedo_value <= 0) ||
	    (sku_info->gpu_speedo_value <= 0) ||
	    (sku_info->soc_speedo_value <= 0)) {
		WARN(1, "speedo value not fused\n");
		return;
	}

	rev_sku_to_speedo_ids(sku_info, speedo_revision, &index);

	sku_info->gpu_process_id = get_process_id(sku_info->gpu_speedo_value,
						  gpu_process_speedos[index],
						  GPU_PROCESS_CORNERS);

	sku_info->cpu_process_id = get_process_id(sku_info->cpu_speedo_value,
						  cpu_process_speedos[index],
						  CPU_PROCESS_CORNERS);

	sku_info->soc_process_id = get_process_id(sku_info->soc_speedo_value,
						  soc_process_speedos[index],
						  SOC_PROCESS_CORNERS);

	pr_info("Tegra Speedo/IDDQ fuse revision %u\n", speedo_revision);
	pr_info("Tegra: CPU Speedo ID %d, SoC Speedo ID %d, GPU Speedo ID %d\n",
		sku_info->cpu_speedo_id, sku_info->soc_speedo_id, sku_info->gpu_speedo_id);
	pr_info("Tegra: CPU Process ID %d, SoC Process ID %d, GPU Process ID %d\n",
		sku_info->cpu_process_id, sku_info->soc_process_id, sku_info->gpu_process_id);
	pr_info("Tegra: CPU Speedo Value %d, SoC Speedo Value %d, GPU Speedo Value %d\n",
		sku_info->cpu_speedo_value, sku_info->soc_speedo_value, sku_info->gpu_speedo_value);
	pr_info("Tegra: CPU IDDQ Value %d, SoC IDDQ Value %d, GPU IDDQ Value %d\n",
		sku_info->cpu_iddq_value, sku_info->soc_iddq_value, sku_info->gpu_iddq_value);
}
