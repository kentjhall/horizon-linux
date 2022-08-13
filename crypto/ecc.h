/*
 * Copyright (c) 2013, Kenneth MacKay
 * All rights reserved.
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _CRYPTO_ECC_H
#define _CRYPTO_ECC_H

#include <crypto/ecc.h>

#include "ecc_curve_defs.h"

const struct ecc_curve *ecc_get_curve(unsigned int curve_id);
struct ecc_point *ecc_alloc_point(unsigned int ndigits);
void ecc_free_point(struct ecc_point *p);

void vli_clear(u64 *vli, unsigned int ndigits);
bool vli_is_zero(const u64 *vli, unsigned int ndigits);
unsigned int vli_num_digits(const u64 *vli, unsigned int ndigits);
unsigned int vli_num_bits(const u64 *vli, unsigned int ndigits);
void vli_set(u64 *dest, const u64 *src, unsigned int ndigits);
void vli_copy_to_buf(u8 *dst_buf, unsigned int buf_len,
		     const u64 *src_vli, unsigned int ndigits);
void vli_copy_from_buf(u64 *dst_vli, unsigned int ndigits,
		       const u8 *src_buf, unsigned int buf_len);
int vli_cmp(const u64 *left, const u64 *right, unsigned int ndigits);
u64 vli_lshift(u64 *result, const u64 *in, unsigned int shift,
	       unsigned int ndigits);
void vli_rshift1(u64 *vli, unsigned int ndigits);
u64 vli_add(u64 *result, const u64 *left, const u64 *right,
	    unsigned int ndigits);
u64 vli_sub(u64 *result, const u64 *left, const u64 *right,
	    unsigned int ndigits);
void vli_mult(u64 *result, const u64 *left, const u64 *right,
	      unsigned int ndigits);
void vli_square(u64 *result, const u64 *left, unsigned int ndigits);
void vli_mod_add(u64 *result, const u64 *left, const u64 *right,
		 const u64 *mod, unsigned int ndigits);
void vli_mod_sub(u64 *result, const u64 *left, const u64 *right,
		 const u64 *mod, unsigned int ndigits);
void vli_mod(u64 *result, const u64 *input, const u64 *mod,
	     unsigned int ndigits);
void vli_print(char *vli_name, const u64 *vli, unsigned int ndigits);
void vli_mod_mult(u64 *result, const u64 *left, const u64 *right,
		  const u64 *mod, unsigned int ndigits);
bool vli_mmod_fast(u64 *result, u64 *product,
		   const u64 *curve_prime, unsigned int ndigits);
void vli_mod_mult_fast(u64 *result, const u64 *left, const u64 *right,
		       const u64 *curve_prime, unsigned int ndigits);
void vli_mod_square_fast(u64 *result, const u64 *left,
			 const u64 *curve_prime, unsigned int ndigits);
void vli_mod_inv(u64 *result, const u64 *input, const u64 *mod,
		 unsigned int ndigits);

bool ecc_point_is_zero(const struct ecc_point *point);
void ecc_point_double_jacobian(u64 *x1, u64 *y1, u64 *z1,
			       u64 *curve_prime, unsigned int ndigits);
void ecc_point_add(u64 *x1, u64 *y1, u64 *x2, u64 *y2, u64 *curve_prime,
		   unsigned int ndigits);
void ecc_point_mult(struct ecc_point *result,
		    const struct ecc_point *point, const u64 *scalar,
		    u64 *initial_z, u64 *curve_prime,
		    unsigned int ndigits);
void ecc_swap_digits(const u64 *in, u64 *out, unsigned int ndigits);

/**
 * ecc_is_key_valid() - Validate a given ECC private key
 *
 * @curve_id:		id representing the curve to use
 * @ndigits:		curve number of digits
 * @private_key:	private key to be used for the given curve
 * @private_key_len:	private key len
 *
 * Returns 0 if the key is acceptable, a negative value otherwise
 */
int ecc_is_key_valid(unsigned int curve_id, unsigned int ndigits,
		     const u8 *private_key, unsigned int private_key_len);
int ecc_is_pub_key_valid(unsigned int curve_id, unsigned int ndigits,
			 const u8 *pub_key, unsigned int pub_key_len);

#endif /* _CRYPTO_ECC_H */
