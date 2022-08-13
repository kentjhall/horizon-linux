/*
 * Copyright (c) 2014-2018, NVIDIA CORPORATION.  All rights reserved.
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
 *
 */

#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include <linux/hw_random.h>

#include <soc/tegra/fuse.h>
#include <soc/tegra/common.h>
#include <soc/tegra/chip-id.h>

#include "fuse.h"

#define FUSE_SKU_INFO	0x10
#define TEGRA_APBMISC_EMU_REVID 0x60
#define TEGRA_MISCREG_EMU_REVID 0x3160
#define ERD_MASK_INBAND_ERR 0x1

#define PMC_STRAPPING_OPT_A_RAM_CODE_SHIFT	4
#define PMC_STRAPPING_OPT_A_RAM_CODE_MASK_LONG	\
	(0xf << PMC_STRAPPING_OPT_A_RAM_CODE_SHIFT)
#define PMC_STRAPPING_OPT_A_RAM_CODE_MASK_SHORT	\
	(0x3 << PMC_STRAPPING_OPT_A_RAM_CODE_SHIFT)

struct chip_revision {
	enum tegra_chipid	chipid;
	unsigned int		major;
	unsigned int		minor;
	char			sub_type;
	enum tegra_revision	revision;
	enum tegra_revision	id_and_rev;
};

struct apbmisc_data {
	u32 emu_revid_offset;
};

static void __iomem *apbmisc_base;
static void __iomem *strapping_base;
static bool long_ram_code;
static const struct apbmisc_data *apbmisc_data;

/*
 * The function sets ERD(Error Response Disable) bit.
 * This allows to mask inband errors and always send an
 * OKAY response from CBB to the master which caused error.
 */
int tegra_miscreg_set_erd(u64 err_config)
{
	int err = 0;
	if (!apbmisc_base)
		tegra_init_apbmisc();

	if (!apbmisc_base) {
		WARN(1, "apbmisc driver not initialized yet\n");
		return -ENODEV;
	}
	writel_relaxed(ERD_MASK_INBAND_ERR, apbmisc_base + err_config);
	return err;
}
EXPORT_SYMBOL(tegra_miscreg_set_erd);

u32 tegra_read_chipid(void)
{
	if (!apbmisc_base)
		tegra_init_apbmisc();

	if (!apbmisc_base) {
		WARN(1, "Tegra Chip ID not yet available\n");
		return 0;
	}

	/* In Virtualized system, return the saved value as
	 * MISC region is trap/emulated.
	 */
	if (is_tegra_hypervisor_mode()) {
		static u32 chipid;
		static bool chipid_set;

		if (unlikely(chipid_set == false)) {
			chipid = readl_relaxed(apbmisc_base + 4);
			chipid_set = true;
		}
		return chipid;
	}

	return readl_relaxed(apbmisc_base + 4);
}

u8 tegra_get_chip_id(void)
{
	if (!apbmisc_base)
		tegra_init_apbmisc();

	if (!apbmisc_base) {
		WARN(1, "Tegra Chip ID not yet available\n");
		return 0;
	}

	return (tegra_read_chipid() >> 8) & 0xff;
}
EXPORT_SYMBOL(tegra_get_chip_id);

u32 tegra_read_emu_revid(void)
{
	if (!apbmisc_base)
		tegra_init_apbmisc();

	if (!apbmisc_base) {
		WARN(1, "Tegra Chip ID not yet available\n");
		return 0;
	}

	return readl_relaxed(apbmisc_base + apbmisc_data->emu_revid_offset);
}

enum tegra_revision tegra_chip_get_revision(void)
{
	if (tegra_sku_info.id_and_rev == TEGRA_REVISION_UNKNOWN)
		tegra_init_revision();

	return tegra_sku_info.id_and_rev;
}
EXPORT_SYMBOL(tegra_chip_get_revision);

u32 tegra_get_sku_id(void)
{
	u32 value;
	if (!tegra_sku_info.sku_id) {
		tegra_fuse_readl(FUSE_SKU_INFO, &value);
		tegra_sku_info.sku_id = value;
	}

	return tegra_sku_info.sku_id;
}

u32 tegra_read_straps(void)
{
	if (strapping_base)
		return readl_relaxed(strapping_base);
	else
		return 0;
}

u32 tegra_read_ram_code(void)
{
	u32 straps = tegra_read_straps();

	if (long_ram_code)
		straps &= PMC_STRAPPING_OPT_A_RAM_CODE_MASK_LONG;
	else
		straps &= PMC_STRAPPING_OPT_A_RAM_CODE_MASK_SHORT;

	return straps >> PMC_STRAPPING_OPT_A_RAM_CODE_SHIFT;
}

const static struct apbmisc_data tegra20_apbmisc_data = {
	.emu_revid_offset = TEGRA_APBMISC_EMU_REVID
};

const static struct apbmisc_data tegra186_apbmisc_data = {
	.emu_revid_offset = TEGRA_MISCREG_EMU_REVID
};

static const struct of_device_id apbmisc_match[] = {
	{
		.compatible = "nvidia,tegra20-apbmisc",
		.data = &tegra20_apbmisc_data,
	},
	{
		.compatible = "nvidia,tegra186-miscreg",
		.data = &tegra186_apbmisc_data,
	},
	{},
};

#define CHIP_REVISION(id, maj, min, sub, rev) {	\
	.chipid = id,				\
	.major = maj,				\
	.minor = min,				\
	.sub_type = sub,			\
	.revision = TEGRA_REVISION_##rev,	\
	.id_and_rev = id##_REVISION_##rev }	\

static struct chip_revision tegra_chip_revisions[] = {
	CHIP_REVISION(TEGRA210, 1, 1, 0,   A01),
	CHIP_REVISION(TEGRA210, 1, 1, 'q', A01q),
	CHIP_REVISION(TEGRA210, 1, 2, 0,   A02),
	CHIP_REVISION(TEGRA210B01, 2, 1, 0, A01),
	CHIP_REVISION(TEGRA186, 1, 1, 0,   A01),
	CHIP_REVISION(TEGRA186, 1, 2, 0,   A02),
	CHIP_REVISION(TEGRA186, 1, 2, 'p', A02p),
	CHIP_REVISION(TEGRA194, 1, 1, 0, A01),
	CHIP_REVISION(TEGRA194, 1, 2, 0, A02),
	CHIP_REVISION(TEGRA194, 1, 2, 'p', A02p),
};

void tegra_init_revision(void)
{
	u32 id, chipid, major, minor, subrev;
	enum tegra_revision revision = TEGRA_REVISION_UNKNOWN;
	enum tegra_revision id_and_rev = TEGRA_REVISION_UNKNOWN;
	char sub_type = 0;
	int i;

	id = tegra_read_chipid();
	chipid = tegra_hidrev_get_chipid(id);
	major = tegra_hidrev_get_majorrev(id);
	minor = tegra_hidrev_get_minorrev(id);
	pr_info("tegra-id: chipid=%x.\n", id);

	/* For pre-silicon the major is 0, for silicon it is >= 1 */
	if (major == 0) {
		switch (minor) {
		case 1:
			revision = TEGRA_REVISION_A01;
			break;
		case 2:
			revision = TEGRA_REVISION_QT;
			break;
		case 3:
			revision = TEGRA_REVISION_SIM;
			add_hwgenerator_randomness(NULL, 0, 1000);
			break;
		}
		goto exit;
	}
	subrev = tegra_fuse_get_subrevision();
	switch (subrev) {
	case 1:
		sub_type = 'p';
		break;
	case 2:
		sub_type = 'q';
		break;
	case 3:
		sub_type = 'r';
		break;
	}
	pr_info("tegra-id: opt_subrevision=%x.\n", subrev);

	if (sub_type) {
		for (i = 0; i < ARRAY_SIZE(tegra_chip_revisions); i++) {
			if ((chipid != tegra_chip_revisions[i].chipid) ||
			    (minor != tegra_chip_revisions[i].minor) ||
			    (major != tegra_chip_revisions[i].major) ||
			    (sub_type != tegra_chip_revisions[i].sub_type))
				continue;

			revision = tegra_chip_revisions[i].revision;
			id_and_rev = tegra_chip_revisions[i].id_and_rev;
			break;
		}
	}

	if (revision == TEGRA_REVISION_UNKNOWN) {
		for (i = 0; i < ARRAY_SIZE(tegra_chip_revisions); i++) {
			if ((chipid != tegra_chip_revisions[i].chipid) ||
			    (minor != tegra_chip_revisions[i].minor) ||
			    (major != tegra_chip_revisions[i].major))
				continue;

			revision = tegra_chip_revisions[i].revision;
			id_and_rev = tegra_chip_revisions[i].id_and_rev;
			break;
		}
	}

exit:
	tegra_sku_info.revision = revision;
	tegra_sku_info.id_and_rev = id_and_rev;
	tegra_sku_info.sku_id = tegra_fuse_read_early(FUSE_SKU_INFO);
}

void tegra_init_apbmisc(void)
{
	struct resource apbmisc, straps;
	struct device_node *np;
	const struct of_device_id *match;

	np = of_find_matching_node_and_match(NULL, apbmisc_match, &match);
	if (!np) {
		/*
		 * Fall back to legacy initialization for 32-bit ARM only. All
		 * 64-bit ARM device tree files for Tegra are required to have
		 * an APBMISC node.
		 *
		 * This is for backwards-compatibility with old device trees
		 * that didn't contain an APBMISC node.
		 */
		if (IS_ENABLED(CONFIG_ARM) && soc_is_tegra()) {
			/* APBMISC registers (chip revision, ...) */
			apbmisc.start = 0x70000800;
			apbmisc.end = 0x70000863;
			apbmisc.flags = IORESOURCE_MEM;

			/* strapping options */
			if (of_machine_is_compatible("nvidia,tegra124")) {
				straps.start = 0x7000e864;
				straps.end = 0x7000e867;
			} else {
				straps.start = 0x70000008;
				straps.end = 0x7000000b;
			}

			straps.flags = IORESOURCE_MEM;

			pr_warn("Using APBMISC region %pR\n", &apbmisc);
			pr_warn("Using strapping options registers %pR\n",
				&straps);
		} else {
			/*
			 * At this point we're not running on Tegra, so play
			 * nice with multi-platform kernels.
			 */
			return;
		}
	} else {
		/*
		 * Extract information from the device tree if we've found a
		 * matching node.
		 */
		if (of_address_to_resource(np, 0, &apbmisc) < 0) {
			pr_err("failed to get APBMISC registers\n");
			return;
		}

		if (of_address_to_resource(np, 1, &straps) < 0) {
			pr_err("failed to get strapping options registers\n");
			return;
		}

		apbmisc_data = match->data;
	}

	apbmisc_base = ioremap_nocache(apbmisc.start, resource_size(&apbmisc));
	if (!apbmisc_base)
		pr_err("failed to map APBMISC registers\n");

	strapping_base = ioremap_nocache(straps.start, resource_size(&straps));
	if (!strapping_base)
		pr_err("failed to map strapping options registers\n");

	long_ram_code = of_property_read_bool(np, "nvidia,long-ram-code");
}
