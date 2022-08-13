/*
 * Copyright (c) 2012, 2013, NVIDIA CORPORATION.  All rights reserved.
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

#include <linux/clk.h>
#include <linux/clk-provider.h>

#include "clk.h"
#include "clk-id.h"

struct tegra_shared_clk {
	char *name;
	char *client;
	union {
		const char **parents;
		const char *parent;
	} p;
	int num_parents;
	enum shared_bus_users_mode mode;
	int flags;
	int clk_id;
};

#define SHARED_CLK(_name, _parent, _mode, _flags, _client, _id)\
	{\
		.name = _name,\
		.p.parent = _parent,\
		.num_parents = 1,\
		.mode = _mode, \
		.flags = _flags, \
		.client = _client,\
		.clk_id = _id,\
	}

#define SHARED_LIMIT(_name, _parent, _mode, _flags, _client, _id)\
	{\
		.name = _name,\
		.p.parent = _parent,\
		.num_parents = 1,\
		.mode = _mode, \
		.flags = _flags | TEGRA_SHARED_BUS_RATE_LIMIT, \
		.client = _client,\
		.clk_id = _id,\
	}

static struct tegra_shared_clk shared_clks[] = {
	SHARED_LIMIT("cap.c2bus", "c2bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_c2bus),
	SHARED_LIMIT("cap.throttle.c2bus", "c2bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_throttle_c2bus),
	SHARED_LIMIT("floor.c2bus", "c2bus", 0, 0,  NULL, tegra_clk_floor_c2bus),
	SHARED_CLK("override.c2bus", "c2bus", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_c2bus),
	SHARED_LIMIT("edp.c2bus", "c2bus", SHARED_CEILING, 0, NULL, tegra_clk_edp_c2bus),
	SHARED_LIMIT("battery.c2bus", "c2bus", SHARED_CEILING, 0, NULL, tegra_clk_battery_c2bus),
	SHARED_LIMIT("cap.profile.c2bus", "c2bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_profile_c2bus),
	SHARED_LIMIT("cap.c3bus", "c3bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_c3bus),
	SHARED_LIMIT("cap.throttle.c3bus", "c3bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_throttle_c3bus),
	SHARED_CLK("override.c3bus", "c3bus", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_c3bus),
	SHARED_LIMIT("floor.c3bus", "c3bus", 0, 0, NULL, tegra_clk_floor_c3bus),
	SHARED_LIMIT("cap.sclk", "sbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_sclk),
	SHARED_LIMIT("cap.throttle.sclk", "sbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_throttle_sclk),
	SHARED_LIMIT("floor.sclk", "sbus", 0, 0, NULL, tegra_clk_floor_sclk),
	SHARED_CLK("override.sclk", "sbus", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_sclk),
	SHARED_CLK("avp.sclk", "sbus", 0, 0, NULL, tegra_clk_avp_sclk),
	SHARED_CLK("bsea.sclk", "sbus", 0, 0, NULL, tegra_clk_bsea_sclk),
	SHARED_CLK("usbd.sclk", "ahb.sclk", 0, 0, NULL, tegra_clk_usbd_sclk),
	SHARED_CLK("usb1.sclk", "ahb.sclk", 0, 0, NULL, tegra_clk_usb1_sclk),
	SHARED_CLK("usb2.sclk", "ahb.sclk", 0, 0, NULL, tegra_clk_usb2_sclk),
	SHARED_CLK("usb3.sclk", "ahb.sclk", 0, 0, NULL, tegra_clk_usb3_sclk),
	SHARED_CLK("wake.sclk", "sbus", 0, 0, NULL, tegra_clk_wake_sclk),
	SHARED_CLK("sbc1.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_sbc1_sclk),
	SHARED_CLK("sbc2.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_sbc2_sclk),
	SHARED_CLK("sbc3.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_sbc3_sclk),
	SHARED_CLK("sbc4.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_sbc4_sclk),
	SHARED_CLK("sbc5.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_sbc5_sclk),
	SHARED_CLK("sbc6.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_sbc6_sclk),
	SHARED_CLK("mon.avp", "sbus", 0, 0, NULL, tegra_clk_mon_avp),
	SHARED_LIMIT("cap.vcore.c2bus", "c2bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_c2bus),
	SHARED_LIMIT("cap.vcore.c3bus", "c3bus", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_c3bus),
	SHARED_CLK("camera.sclk", "sbus", 0, 0, NULL, tegra_clk_camera_sclk),
	SHARED_LIMIT("cap.vcore.sclk", "sbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_sclk),
	SHARED_CLK("qspi.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_qspi_sclk),
	SHARED_CLK("boot.apb.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_boot_apb_sclk),
	SHARED_CLK("gm20b.gbus", "gbus", 0, 0, NULL, tegra_clk_gm20b_gbus),
	SHARED_LIMIT("cap.gbus", "gbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_gbus),
	SHARED_LIMIT("edp.gbus", "gbus", SHARED_CEILING, 0, NULL, tegra_clk_edp_gbus),
	SHARED_LIMIT("cap.vgpu.gbus", "gbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_vgpu_gbus),
	SHARED_LIMIT("cap.throttle_gbus", "gbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_throttle_gbus),
	SHARED_LIMIT("cap.profile_gbus", "gbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_profile_gbus),
	SHARED_CLK("override.gbus", "gbus", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_gbus),
	SHARED_LIMIT("floor.gbus", "gbus", 0, 0, NULL, tegra_clk_floor_gbus),
	SHARED_LIMIT("floor.profile_gbus", "gbus", 0, 0, NULL, tegra_clk_floor_profile_gbus),
	SHARED_CLK("nv.host1x", "host1x_master", 0, 0, NULL, tegra_clk_nv_host1x),
	SHARED_CLK("vi.host1x", "host1x_master", 0, 0, NULL, tegra_clk_vi_host1x),
	SHARED_CLK("vii2c.host1x", "host1x_master", 0, 0, NULL, tegra_clk_vii2c_host1x),
	SHARED_LIMIT("cap.host1x", "host1x_master", SHARED_CEILING, 0, NULL, tegra_clk_cap_host1x),
	SHARED_LIMIT("cap.vcore.host1x", "host1x_master", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_host1x),
	SHARED_LIMIT("floor.host1x", "host1x_master", 0, 0, NULL, tegra_clk_floor_host1x),
	SHARED_CLK("override.host1x", "host1x_master", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_host1x),
	SHARED_CLK("cpu.mselect", "mselect_master", 0, 0, NULL, tegra_clk_cpu_mselect),
	SHARED_CLK("pcie.mselect", "mselect_master", 0, 0, NULL, tegra_clk_pcie_mselect),
	SHARED_LIMIT("cap.vcore.mselect", "mselect_master", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_mselect),
	SHARED_CLK("override.mselect", "mselect_master", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_mselect),
	SHARED_CLK("adma.ape", "ape_master", 0, 0, NULL, tegra_clk_adma_ape),
	SHARED_CLK("adsp.ape", "ape_master", 0, 0, NULL, tegra_clk_adsp_ape),
	SHARED_CLK("xbar.ape", "ape_master", 0, 0, NULL, tegra_clk_xbar_ape),
	SHARED_LIMIT("cap.vcore.ape", "ape_master", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_ape),
	SHARED_LIMIT("override.ape", "ape_master", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_ape),
	SHARED_CLK("adsp.cpu.abus", "abus", 0, 0, "aclk", tegra_clk_adsp_cpu_abus),
	SHARED_LIMIT("cap.vcore.abus", "abus", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_abus),
	SHARED_CLK("override.abus", "abus", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_abus),
	SHARED_LIMIT("cap.vcore.cbus", "cbus", SHARED_CEILING, 0, NULL, tegra_clk_cap_vcore_cbus),
	SHARED_CLK("override.cbus", "cbus", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_cbus),
	SHARED_CLK("sdmmc4.sclk", "ahb.sclk", 0, 0, NULL, tegra_clk_sdmmc4_ahb_sclk),
	SHARED_LIMIT("vic.floor.cbus", "c2bus", 0, 0, NULL, tegra_clk_vic_floor_cbus),
	SHARED_CLK("override.emc", "emc_master", SHARED_OVERRIDE, 0, NULL, tegra_clk_override_emc),
	SHARED_CLK("bwmgr.emc", "emc_master", 0, 0, NULL, tegra_clk_bwmgr_emc),
	SHARED_CLK("vcm.sclk", "sbus", 0, 0, NULL, tegra_clk_vcm_sclk),
	SHARED_CLK("vcm.ahb.sclk", "ahb.sclk", 0, 0, NULL, tegra_clk_vcm_ahb_sclk),
	SHARED_CLK("vcm.apb.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_vcm_apb_sclk),
	SHARED_CLK("wifi.sclk", "apb.sclk", 0, 0, NULL, tegra_clk_wifi_sclk),
};

void __init tegra_shared_clk_init(struct tegra_clk *tegra_clks)
{
	int i;
	const char **parents;
	struct tegra_shared_clk *data;
	struct clk *clk;
	struct clk **dt_clk;

	for (i = 0; i < ARRAY_SIZE(shared_clks); i++) {
		data = &shared_clks[i];
		if (data->num_parents == 1)
			parents = &data->p.parent;
		else
			parents = data->p.parents;

		dt_clk = tegra_lookup_dt_id(data->clk_id, tegra_clks);
		if (!dt_clk)
			continue;

		clk = tegra_clk_register_shared(data->name, parents,
				data->num_parents, data->flags, data->mode,
				data->client);
		*dt_clk = clk;
	}
}
