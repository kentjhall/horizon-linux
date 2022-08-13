/*
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _CRYPTO_ECC_
#define _CRYPTO_ECC_

/* Curves IDs */
#define ECC_CURVE_NIST_P192	0x0001
#define ECC_CURVE_NIST_P256	0x0002
#define ECC_CURVE_BRAINPOOL_P256	0x0006

#define ECC_MAX_DIGITS	4 /* 256 */

#define ECC_DIGITS_TO_BYTES_SHIFT 3

#define ECC_MAX_DIGIT_BYTES (ECC_MAX_DIGITS << ECC_DIGITS_TO_BYTES_SHIFT)

#endif /* _CRYPTO_ECC_ */
