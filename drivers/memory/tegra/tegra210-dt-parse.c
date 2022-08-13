/*
 * drivers/platform/tegra/mc/tegra_emc_dt_parse.c
 *
 * Copyright (c) 2013-2017, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <soc/tegra/fuse.h>
#include <soc/tegra/tegra_emc.h>

#include "tegra210-emc-reg.h"

static struct device_node *tegra_emc_ramcode_devnode(
	struct device_node *np)
{
	struct device_node *iter;
	u32 reg;

	for_each_child_of_node(np, iter) {
		if (of_property_read_u32(iter, "nvidia,ram-code", &reg))
			continue;
		if (reg == tegra_read_ram_code())
			return of_node_get(iter);
	}

	return NULL;
}

static void *tegra_emc_dt_parse_pdata_comp(const char *emc_mode,
				    const char *comp,
				    void *pdata,
				    struct device_node *tnp,
				    struct platform_device *pdev,
				    int num_tables, int *table_count)
{
#define PNE_U32(node, entry, tbl_entry)					\
	do {								\
		int __ret__;						\
		u32 __tmp__;						\
									\
		__ret__ = of_property_read_u32((node), (entry), &__tmp__); \
		if (__ret__) {						\
			dev_err(&pdev->dev, "Failed to parse %s in %s: %d\n", \
				(entry), (node)->full_name, __ret__);	\
			continue;					\
		}							\
									\
		tables[i].tbl_entry = __tmp__;				\
	} while (0)

#define PNE_U32_ARRAY(node, entry, tbl_entry, length)			\
	do {								\
		int __ret__;						\
									\
		__ret__ = of_property_read_u32_array((node), (entry),	\
						     (tbl_entry), (length)); \
		if (__ret__) {						\
			dev_err(&pdev->dev, "Failed to parse %s in %s: %d\n", \
				(entry), (node)->full_name, __ret__);	\
			continue;					\
		}							\
	} while (0)

	int i = 0, ret = 0;
	struct device_node *iter;
	struct emc_table *tables;

	tables = devm_kzalloc(&pdev->dev,
			sizeof(*tables) * num_tables, GFP_KERNEL);

	if (!tables) {
		of_node_put(tnp);
		return tables;
	}

	for_each_child_of_node(tnp, iter) {
		if (of_device_is_compatible(iter, comp)) {
			const char *source_name;
			const char *dvfs_ver;

			ret = of_property_read_string(iter,
					"nvidia,source", &source_name);
			if (ret) {
				dev_err(&pdev->dev, "no source name in %s\n",
						iter->full_name);
				continue;
			}
			strlcpy(tables[i].clock_src, source_name,
					sizeof(tables[i].clock_src));

			ret = of_property_read_string(iter,
					"nvidia,dvfs-version", &dvfs_ver);
			if (ret) {
				dev_err(&pdev->dev, "no dvfs version in %s\n",
						iter->full_name);
				continue;
			}
			strlcpy(tables[i].dvfs_ver, dvfs_ver,
					sizeof(tables[i].dvfs_ver));

			PNE_U32(iter, "nvidia,revision", rev);
			PNE_U32(iter, "clock-frequency", rate);
			PNE_U32(iter, "nvidia,emc-min-mv", min_volt);
			PNE_U32(iter, "nvidia,gk20a-min-mv", gpu_min_volt);
			PNE_U32(iter, "nvidia,src-sel-reg", clk_src_emc);
			PNE_U32(iter, "nvidia,burst-regs-num", num_burst);
			PNE_U32(iter, "nvidia,emc-cfg-2", emc_cfg_2);
			PNE_U32(iter, "nvidia,emc-sel-dpd-ctrl",
				emc_sel_dpd_ctrl);
			PNE_U32(iter, "nvidia,emc-auto-cal-config",
				emc_auto_cal_config);
			PNE_U32(iter, "nvidia,emc-auto-cal-config2",
				emc_auto_cal_config2);
			PNE_U32(iter, "nvidia,emc-auto-cal-config3",
				emc_auto_cal_config3);
			PNE_U32(iter, "nvidia,emc-clock-latency-change",
				latency);
			PNE_U32_ARRAY(iter, "nvidia,emc-registers",
				      tables[i].burst_regs,
				      tables[i].num_burst);

			PNE_U32(iter, "nvidia,needs-training", needs_training);
			PNE_U32(iter, "nvidia,trained", trained);
			if (tables[i].rev < 0x6)
				goto skip_periodic_training_params;
			PNE_U32(iter, "nvidia,periodic_training",
				periodic_training);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c0d0u0",
				trained_dram_clktree_c0d0u0);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c0d0u1",
				trained_dram_clktree_c0d0u1);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c0d1u0",
				trained_dram_clktree_c0d1u0);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c0d1u1",
				trained_dram_clktree_c0d1u1);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c1d0u0",
				trained_dram_clktree_c1d0u0);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c1d0u1",
				trained_dram_clktree_c1d0u1);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c1d1u0",
				trained_dram_clktree_c1d1u0);
			PNE_U32(iter, "nvidia,trained_dram_clktree_c1d1u1",
				trained_dram_clktree_c1d1u1);
			PNE_U32(iter, "nvidia,current_dram_clktree_c0d0u0",
				current_dram_clktree_c0d0u0);
			PNE_U32(iter, "nvidia,current_dram_clktree_c0d0u1",
				current_dram_clktree_c0d0u1);
			PNE_U32(iter, "nvidia,current_dram_clktree_c0d1u0",
				current_dram_clktree_c0d1u0);
			PNE_U32(iter, "nvidia,current_dram_clktree_c0d1u1",
				current_dram_clktree_c0d1u1);
			PNE_U32(iter, "nvidia,current_dram_clktree_c1d0u0",
				current_dram_clktree_c1d0u0);
			PNE_U32(iter, "nvidia,current_dram_clktree_c1d0u1",
				current_dram_clktree_c1d0u1);
			PNE_U32(iter, "nvidia,current_dram_clktree_c1d1u0",
				current_dram_clktree_c1d1u0);
			PNE_U32(iter, "nvidia,current_dram_clktree_c1d1u1",
				current_dram_clktree_c1d1u1);
			PNE_U32(iter, "nvidia,run_clocks", run_clocks);
			PNE_U32(iter, "nvidia,tree_margin", tree_margin);

skip_periodic_training_params:
			PNE_U32(iter, "nvidia,burst-regs-per-ch-num",
				num_burst_per_ch);
			PNE_U32(iter, "nvidia,trim-regs-num", num_trim);
			PNE_U32(iter, "nvidia,trim-regs-per-ch-num",
				num_trim_per_ch);
			PNE_U32(iter, "nvidia,burst-mc-regs-num",
				num_mc_regs);
			PNE_U32(iter, "nvidia,la-scale-regs-num",
				num_up_down);
			PNE_U32(iter, "nvidia,vref-regs-num", vref_num);
			PNE_U32(iter, "nvidia,dram-timing-regs-num",
				dram_timing_num);
			PNE_U32(iter, "nvidia,min-mrs-wait", min_mrs_wait);
			PNE_U32(iter, "nvidia,emc-mrw", emc_mrw);
			PNE_U32(iter, "nvidia,emc-mrw2", emc_mrw2);
			PNE_U32(iter, "nvidia,emc-mrw3", emc_mrw3);
			PNE_U32(iter, "nvidia,emc-mrw4", emc_mrw4);
			PNE_U32(iter, "nvidia,emc-mrw9", emc_mrw9);
			PNE_U32(iter, "nvidia,emc-mrs", emc_mrs);
			PNE_U32(iter, "nvidia,emc-emrs", emc_emrs);
			PNE_U32(iter, "nvidia,emc-emrs2", emc_emrs2);
			PNE_U32(iter, "nvidia,emc-auto-cal-config4",
				emc_auto_cal_config4);
			PNE_U32(iter, "nvidia,emc-auto-cal-config5",
				emc_auto_cal_config5);
			PNE_U32(iter, "nvidia,emc-auto-cal-config6",
				emc_auto_cal_config6);
			PNE_U32(iter, "nvidia,emc-auto-cal-config7",
				emc_auto_cal_config7);
			PNE_U32(iter, "nvidia,emc-auto-cal-config8",
				emc_auto_cal_config8);
			PNE_U32(iter, "nvidia,emc-fdpd-ctrl-cmd-no-ramp",
				emc_fdpd_ctrl_cmd_no_ramp);
			PNE_U32(iter, "nvidia,dll-clk-src", dll_clk_src);
			PNE_U32(iter, "nvidia,clk-out-enb-x-0-clk-enb-emc-dll",
				clk_out_enb_x_0_clk_enb_emc_dll);

			if (tables[i].rev >= 0x7)
				PNE_U32_ARRAY(iter, "nvidia,ptfv",
					      tables[i].ptfv_list,
					      sizeof(tables[i].ptfv_list)
							/ sizeof(u32));

			PNE_U32_ARRAY(iter, "nvidia,emc-burst-regs-per-ch",
				      tables[i].burst_reg_per_ch,
				      tables[i].num_burst_per_ch);
			PNE_U32_ARRAY(iter, "nvidia,emc-shadow-regs-ca-train",
				      tables[i].shadow_regs_ca_train,
				      tables[i].num_burst);
			PNE_U32_ARRAY(iter, "nvidia,emc-shadow-regs-quse-train",
				      tables[i].shadow_regs_quse_train,
				      tables[i].num_burst);
			PNE_U32_ARRAY(iter, "nvidia,emc-shadow-regs-rdwr-train",
				      tables[i].shadow_regs_rdwr_train,
				      tables[i].num_burst);
			PNE_U32_ARRAY(iter, "nvidia,emc-trim-regs",
				      tables[i].trim_regs,
				      tables[i].num_trim);
			PNE_U32_ARRAY(iter, "nvidia,emc-trim-regs-per-ch",
				      tables[i].trim_perch_regs,
				      tables[i].num_trim_per_ch);
			PNE_U32_ARRAY(iter, "nvidia,emc-vref-regs",
				      tables[i].vref_perch_regs,
				      tables[i].vref_num);
			PNE_U32_ARRAY(iter, "nvidia,emc-dram-timing-regs",
				      tables[i].dram_timings,
				      tables[i].dram_timing_num);
			PNE_U32_ARRAY(iter, "nvidia,emc-burst-mc-regs",
				      tables[i].burst_mc_regs,
				      tables[i].num_mc_regs);
			PNE_U32_ARRAY(iter, "nvidia,emc-la-scale-regs",
				      tables[i].la_scale_regs,
				      tables[i].num_up_down);
			i++;
		}
	}
	*table_count = i;
	return tables;
}

static const struct of_device_id emc_table_match[] = {
	{
		.compatible = "nvidia,tegra210-emc-table",
		.data = "nvidia,tegra210-emc-table-derated",
	},
	{
		.compatible = "nvidia,tegra21-emc-table",
		.data = "nvidia,tegra21-emc-table-derated",
	},
	{ },
};

int tegra_emc_dt_parse_pdata(struct platform_device *pdev,
			       struct emc_table **tables,
			       struct emc_table **derated_tables,
			       int *num_entries)
{
	struct device_node *np = pdev->dev.of_node;
	struct device_node *tnp, *iter;
	int num_tables, table_count;
	u32 tegra_bct_strapping;
	const char *emc_mode = "nvidia,emc-mode-0";
	struct tegra21_emc_pdata *pdata = NULL;
	const char *comp = NULL;
	const char *comp_derated = NULL;
	const void *prop;

	if (!np) {
		dev_err(&pdev->dev,
			"Unable to find external-memory-controller node\n");
		return -ENODEV;
	}

	tegra_bct_strapping = tegra_read_ram_code();

	prop = of_get_property(pdev->dev.of_node,
			       "nvidia,poll_thresh_freq", NULL);
	if (prop) {
		unsigned long freq_thresh = (unsigned long)be32_to_cpup(prop);

		tegra210_emc_mr4_set_freq_thresh(freq_thresh);
		pr_info("tegra: emc: Using MR4 freq threshold: %lu\n",
			freq_thresh);
	}

	if (of_find_property(np, "nvidia,use-ram-code", NULL)) {
		tnp = tegra_emc_ramcode_devnode(np);

		if (!tnp) {
			dev_warn(&pdev->dev,
				"can't find emc table for ram-code 0x%02x\n",
				tegra_bct_strapping);
			return -ENODEV;
		}
	} else
		tnp = of_node_get(np);

	num_tables = 0;
	for_each_child_of_node(tnp, iter) {
		if (!comp) {
			const struct of_device_id *m =
				of_match_node(emc_table_match, iter);
			if (m) {
				comp = m->compatible;
				comp_derated = m->data;
				num_tables++;
			}
			continue;
		}
		if (of_device_is_compatible(iter, comp))
			num_tables++;
	}

	if (!num_tables) {
		*tables = NULL;
		goto out;
	}

	*tables = tegra_emc_dt_parse_pdata_comp(emc_mode, comp, pdata, tnp,
						pdev, num_tables, &table_count);
	*num_entries = table_count;

	/* populate the derated tables */
	num_tables = 0;
	for_each_child_of_node(tnp, iter) {
		if (of_device_is_compatible(iter, comp_derated))
			num_tables++;
	}

	if (!num_tables) {
		*derated_tables = NULL;
		goto out;
	}

	*derated_tables = tegra_emc_dt_parse_pdata_comp(emc_mode,
				comp_derated, pdata, tnp, pdev, num_tables,
				&table_count);

out:
	of_node_put(tnp);
	return 0;
}
