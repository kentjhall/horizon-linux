/*
 * Copyright (C) 2018 NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _ARM_SMMU_DEBUG_H
#define _ARM_SMMU_DEBUG_H

/* Maximum number of context banks per SMMU */
#define ARM_SMMU_MAX_CBS		128

struct smmu_debugfs_info {
	struct device	*dev;
	DECLARE_BITMAP(context_filter, ARM_SMMU_MAX_CBS);

	void __iomem 	*base;
	int 		size;

	struct dentry	*debugfs_root;
	struct dentry 	*cb_root;
	struct dentry 	*masters_root;

	int		num_context_banks;
	unsigned long 	pgshift;
	int		max_cbs;
	u16 		streamid_mask;

	struct debugfs_regset32 *regset;
	struct debugfs_regset32 *perf_regset;
};

void arm_smmu_debugfs_create(struct smmu_debugfs_info *info);
void arm_smmu_debugfs_add_master(struct device *dev, u8 *cbndx, u16 smendx[]);
#endif /* _ARM_SMMU_DEBUG_H */
