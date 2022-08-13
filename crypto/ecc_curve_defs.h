/*
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef _CRYTO_ECC_CURVE_DEFS_H
#define _CRYTO_ECC_CURVE_DEFS_H

struct ecc_point {
	u64 *x;
	u64 *y;
	u8 ndigits;
};

struct ecc_curve {
	char *name;
	struct ecc_point g;
	u64 *p;
	u64 *n;
};

#endif /* _CRYTO_ECC_CURVE_DEFS_H */
