/*
 * Copyright (c) 2016-2020, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <soc/tegra/chip-id.h>
#include <soc/tegra/fuse.h>

#define TEGRAID_CHIPID_MASK 0xFF00
#define TEGRAID_CHIPID_SHIFT 8
#define TEGRAID_MAJOR_MASK 0xF0
#define TEGRAID_MAJOR_SHIFT 4
#define TEGRAID_MINOR_MASK 0xF0000
#define TEGRAID_MINOR_SHIFT 16
#define TEGRAID_NETLIST_MASK 0xFF
#define TEGRAID_PATCH_MASK 0xFF00
#define TEGRAID_PATCH_SHIFT 8
#define TEGRA210_INT_CID 5
#define TEGRA186_INT_CID 6
#define TEGRA194_INT_CID 7

struct tegra_id {
	enum tegra_chipid chipid;
	enum tegra_revision revision;
	unsigned int major;
	unsigned int minor;
	unsigned int netlist;
	unsigned int patch;
	char *priv;
};

static const char *tegra_platform_name[TEGRA_PLATFORM_MAX] = {
	[TEGRA_PLATFORM_SILICON] = "silicon",
	[TEGRA_PLATFORM_QT]      = "quickturn",
	[TEGRA_PLATFORM_LINSIM]  = "linsim",
	[TEGRA_PLATFORM_FPGA]    = "fpga",
	[TEGRA_PLATFORM_UNIT_FPGA] = "unit fpga",
	[TEGRA_PLATFORM_VDK] = "vdk",
};

static struct tegra_id tegra_id;
static const char *tegra_platform_ptr;
static const char *tegra_cpu_ptr;
static u32 prod_mode;
static u64 chip_uid;

static int get_platform(char *val, const struct kernel_param *kp)
{
	enum tegra_platform platform;

	platform = tegra_get_platform();
	tegra_platform_ptr = tegra_platform_name[platform];
	return param_get_charp(val, kp);
}
static struct kernel_param_ops tegra_platform_ops = {
	.get = get_platform,
};
module_param_cb(tegra_platform, &tegra_platform_ops, &tegra_platform_ptr, 0444);

static int get_cpu_type(char *val, const struct kernel_param *kp)
{
	enum tegra_platform platform;

	if (tegra_cpu_is_asim()) {
		tegra_cpu_ptr = "asim";
	} else {
		platform = tegra_get_platform();
		tegra_cpu_ptr = tegra_platform_name[platform];
	}
	return param_get_charp(val, kp);
}
static struct kernel_param_ops tegra_cpu_ops = {
	.get = get_cpu_type,
};
module_param_cb(tegra_cpu, &tegra_cpu_ops, &tegra_cpu_ptr, 0444);

static int get_chip_id(char *val, const struct kernel_param *kp)
{
	if (tegra_id.chipid == TEGRA_CHIPID_UNKNOWN)
		tegra_set_tegraid_from_hw();

	return param_get_uint(val, kp);
}

static int get_revision(char *val, const struct kernel_param *kp)
{
	if (tegra_id.revision == TEGRA_REVISION_UNKNOWN)
		tegra_set_tegraid_from_hw();

	return param_get_uint(val, kp);
}

static int get_major_rev(char *val, const struct kernel_param *kp)
{
	if (tegra_id.revision == TEGRA_REVISION_UNKNOWN)
		tegra_set_tegraid_from_hw();

	return param_get_uint(val, kp);
}

static struct kernel_param_ops tegra_chip_id_ops = {
	.get = get_chip_id,
};

static struct kernel_param_ops tegra_revision_ops = {
	.get = get_revision,
};

static struct kernel_param_ops tegra_major_rev_ops = {
	.get = get_major_rev,
};

module_param_cb(tegra_chip_id, &tegra_chip_id_ops, &tegra_id.chipid, 0444);
module_param_cb(tegra_chip_rev, &tegra_revision_ops, &tegra_id.revision, 0444);
module_param_cb(tegra_chip_major_rev,
		&tegra_major_rev_ops, &tegra_id.major, 0444);

static int get_prod_mode(char *val, const struct kernel_param *kp)
{
	u32 reg = 0;
	int ret;

	if (tegra_get_platform() == TEGRA_PLATFORM_SILICON) {
		ret = tegra_fuse_readl(TEGRA_FUSE_PRODUCTION_MODE, &reg);
		if (!ret)
			prod_mode = reg;
	}
	return param_get_uint(val, kp);
}

static struct kernel_param_ops tegra_prod_mode_ops = {
	.get = get_prod_mode,
};

module_param_cb(tegra_prod_mode, &tegra_prod_mode_ops, &prod_mode, 0444);

void tegra_set_tegraid_from_hw(void)
{
	u32 cid;
	u32 emu_id;

	cid = tegra_read_chipid();
	emu_id = tegra_read_emu_revid();

	tegra_id.chipid  = (cid & TEGRAID_CHIPID_MASK) >> TEGRAID_CHIPID_SHIFT;
	tegra_id.major = (cid & TEGRAID_MAJOR_MASK) >> TEGRAID_MAJOR_SHIFT;
	tegra_id.minor   = (cid & TEGRAID_MINOR_MASK) >> TEGRAID_MINOR_SHIFT;
	tegra_id.netlist = emu_id & TEGRAID_NETLIST_MASK;
	tegra_id.patch   = (emu_id & TEGRAID_PATCH_MASK) >> TEGRAID_PATCH_SHIFT;
	tegra_id.revision = tegra_sku_info.revision;
}

enum tegra_chipid tegra_get_chipid(void)
{
	if (tegra_id.chipid == TEGRA_CHIPID_UNKNOWN)
		tegra_set_tegraid_from_hw();

	return tegra_id.chipid;
}
EXPORT_SYMBOL(tegra_get_chipid);

unsigned long long tegra_chip_uid(void)
{

	u64 uid = 0ull;
	u32 reg;
	u32 cid;
	u32 vendor;
	u32 fab;
	u32 lot;
	u32 wafer;
	u32 x;
	u32 y;
	u32 i;

	/*
	 * This used to be so much easier in prior chips. Unfortunately, there
	 * is no one-stop shopping for the unique id anymore. It must be
	 *  constructed from various bits of information burned into the fuses
	 *  during the manufacturing process. The 64-bit unique id is formed
	 *  by concatenating several bit fields. The notation used for the
	 *  various fields is <fieldname:size_in_bits> with the UID composed
	 *  thusly:
	 *
	 *  <CID:4><VENDOR:4><FAB:6><LOT:26><WAFER:6><X:9><Y:9>
	 *
	 * Where:
	 *
	 *	Field    Bits  Position Data
	 *	-------  ----  -------- ----------------------------------------
	 *	CID        4     60     Chip id
	 *	VENDOR     4     56     Vendor code
	 *	FAB        6     50     FAB code
	 *	LOT       26     24     Lot code (5-digit base-36-coded-decimal,
	 *				re-encoded to 26 bits binary)
	 *	WAFER      6     18     Wafer id
	 *	X          9      9     Wafer X-coordinate
	 *	Y          9      0     Wafer Y-coordinate
	 *	-------  ----
	 *	Total     64
	 */

	reg = tegra_get_chip_id();
	switch (reg) {
	case TEGRA210:
		cid = TEGRA210_INT_CID;
		break;
	case TEGRA186:
		cid = TEGRA186_INT_CID;
		break;
	case TEGRA194:
		cid = TEGRA194_INT_CID;
		break;
	default:
		cid = 0;
		break;
	};

	tegra_fuse_readl(FUSE_OPT_VENDOR_CODE, &reg);
	vendor = reg & FUSE_OPT_VENDOR_CODE_MASK;
	tegra_fuse_readl(FUSE_OPT_FAB_CODE, &reg);
	fab = reg & FUSE_OPT_FAB_CODE_MASK;

	/* Lot code must be re-encoded from a 5 digit base-36 'BCD' number
	 * to a binary number.
	 */
	lot = 0;
	tegra_fuse_readl(FUSE_OPT_LOT_CODE_0, &reg);
	reg = reg << 2;

	for (i = 0; i < 5; ++i) {
		u32 digit = (reg & 0xFC000000) >> 26;

		WARN_ON(digit >= 36);
		lot *= 36;
		lot += digit;
		reg <<= 6;
	}

	tegra_fuse_readl(FUSE_OPT_WAFER_ID, &reg);
	wafer = reg & FUSE_OPT_WAFER_ID_MASK;
	tegra_fuse_readl(FUSE_OPT_X_COORDINATE, &reg);
	x = reg & FUSE_OPT_X_COORDINATE_MASK;
	tegra_fuse_readl(FUSE_OPT_Y_COORDINATE, &reg);
	y = reg & FUSE_OPT_Y_COORDINATE_MASK;

	uid = ((unsigned long long)cid  << 60ull)
	    | ((unsigned long long)vendor << 56ull)
	    | ((unsigned long long)fab << 50ull)
	    | ((unsigned long long)lot << 24ull)
	    | ((unsigned long long)wafer << 18ull)
	    | ((unsigned long long)x << 9ull)
	    | ((unsigned long long)y << 0ull);
	return uid;
}

static int get_chip_uid(char *val, const struct kernel_param *kp)
{
	chip_uid = tegra_chip_uid();
	return param_get_ulong(val, kp);
}

static struct kernel_param_ops tegra_chip_uid_ops = {
	.get = get_chip_uid,
};

module_param_cb(tegra_chip_uid, &tegra_chip_uid_ops, &chip_uid, 0444);
