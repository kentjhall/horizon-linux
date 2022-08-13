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

#include <linux/random.h>
#include <linux/slab.h>
#include <linux/swab.h>
#include <linux/fips.h>

#include "ecc.h"

typedef struct {
	u64 m_low;
	u64 m_high;
} uint128_t;

/* NIST P-192 */
static u64 nist_p192_g_x[] = { 0xF4FF0AFD82FF1012ull, 0x7CBF20EB43A18800ull,
				0x188DA80EB03090F6ull };
static u64 nist_p192_g_y[] = { 0x73F977A11E794811ull, 0x631011ED6B24CDD5ull,
				0x07192B95FFC8DA78ull };
static u64 nist_p192_p[] = { 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFEull,
				0xFFFFFFFFFFFFFFFFull };
static u64 nist_p192_n[] = { 0x146BC9B1B4D22831ull, 0xFFFFFFFF99DEF836ull,
				0xFFFFFFFFFFFFFFFFull };
static struct ecc_curve nist_p192 = {
	.name = "nist_192",
	.g = {
		.x = nist_p192_g_x,
		.y = nist_p192_g_y,
		.ndigits = 3,
	},
	.p = nist_p192_p,
	.n = nist_p192_n
};

/* NIST P-256 */
static u64 nist_p256_g_x[] = { 0xF4A13945D898C296ull, 0x77037D812DEB33A0ull,
				0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull };
static u64 nist_p256_g_y[] = { 0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull,
				0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull };
static u64 nist_p256_p[] = { 0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull,
				0x0000000000000000ull, 0xFFFFFFFF00000001ull };
static u64 nist_p256_n[] = { 0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull,
				0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull };
static struct ecc_curve nist_p256 = {
	.name = "nist_256",
	.g = {
		.x = nist_p256_g_x,
		.y = nist_p256_g_y,
		.ndigits = 4,
	},
	.p = nist_p256_p,
	.n = nist_p256_n
};

/* BrainPool P-256 */
static u64 bp_p256_g_x[] = { 0x3A4453BD9ACE3262ull, 0xB9DE27E1E3BD23C2ull,
				0x2C4B482FFC81B7AFull, 0x8BD2AEB9CB7E57CBull };

static u64 bp_p256_g_y[] = { 0x5C1D54C72F046997ull, 0xC27745132DED8E54ull,
				0x97F8461A14611DC9ull, 0x547EF835C3DAC4FDull };

static u64 bp_p256_p[] = { 0x2013481D1F6E5377ull, 0x6E3BF623D5262028ull,
				0x3E660A909D838D72ull, 0xA9FB57DBA1EEA9BCull };

static u64 bp_p256_n[] = { 0x901E0E82974856A7ull, 0x8C397AA3B561A6F7ull,
				0x3E660A909D838D71ull, 0xA9FB57DBA1EEA9BCull };

static struct ecc_curve bpcurve_p256 = {
	.name = "brainpool_256",
	.g = {
		.x = bp_p256_g_x,
		.y = bp_p256_g_y,
	},
	.p = bp_p256_p,
	.n = bp_p256_n,
};

const struct ecc_curve *ecc_get_curve(unsigned int curve_id)
{
	switch (curve_id) {
	/* In FIPS mode only allow P256 and higher */
	case ECC_CURVE_NIST_P192:
		return fips_enabled ? NULL : &nist_p192;
	case ECC_CURVE_NIST_P256:
		return &nist_p256;
	case ECC_CURVE_BRAINPOOL_P256:
		return &bpcurve_p256;
	default:
		return NULL;
	}
}
EXPORT_SYMBOL_GPL(ecc_get_curve);

static u64 *ecc_alloc_digits_space(unsigned int ndigits)
{
	size_t len = ndigits * sizeof(u64);

	if (!len)
		return NULL;

	return kmalloc(len, GFP_KERNEL);
}

static void ecc_free_digits_space(u64 *space)
{
	kzfree(space);
}

struct ecc_point *ecc_alloc_point(unsigned int ndigits)
{
	struct ecc_point *p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return NULL;

	p->x = ecc_alloc_digits_space(ndigits);
	if (!p->x)
		goto err_alloc_x;

	p->y = ecc_alloc_digits_space(ndigits);
	if (!p->y)
		goto err_alloc_y;

	p->ndigits = ndigits;

	return p;

err_alloc_y:
	ecc_free_digits_space(p->x);
err_alloc_x:
	kfree(p);
	return NULL;
}
EXPORT_SYMBOL_GPL(ecc_alloc_point);

void ecc_free_point(struct ecc_point *p)
{
	if (!p)
		return;

	kzfree(p->x);
	kzfree(p->y);
	kzfree(p);
}
EXPORT_SYMBOL_GPL(ecc_free_point);

void vli_clear(u64 *vli, unsigned int ndigits)
{
	int i;

	for (i = 0; i < ndigits; i++)
		vli[i] = 0;
}
EXPORT_SYMBOL_GPL(vli_clear);

/* Returns true if vli == 0, false otherwise. */
bool vli_is_zero(const u64 *vli, unsigned int ndigits)
{
	int i;

	for (i = 0; i < ndigits; i++) {
		if (vli[i])
			return false;
	}

	return true;
}
EXPORT_SYMBOL_GPL(vli_is_zero);

/* Returns nonzero if bit bit of vli is set. */
u64 vli_test_bit(const u64 *vli, unsigned int bit)
{
	return (vli[bit / 64] & ((u64)1 << (bit % 64)));
}
EXPORT_SYMBOL_GPL(vli_test_bit);

/* Counts the number of 64-bit "digits" in vli. */
unsigned int vli_num_digits(const u64 *vli, unsigned int ndigits)
{
	int i;

	/* Search from the end until we find a non-zero digit.
	 * We do it in reverse because we expect that most digits will
	 * be nonzero.
	 */
	for (i = ndigits - 1; i >= 0 && vli[i] == 0; i--);

	return (i + 1);
}
EXPORT_SYMBOL_GPL(vli_num_digits);

/* Counts the number of bits required for vli. */
unsigned int vli_num_bits(const u64 *vli, unsigned int ndigits)
{
	unsigned int i, num_digits;
	u64 digit;

	num_digits = vli_num_digits(vli, ndigits);
	if (num_digits == 0)
		return 0;

	digit = vli[num_digits - 1];
	for (i = 0; digit; i++)
		digit >>= 1;

	return ((num_digits - 1) * 64 + i);
}
EXPORT_SYMBOL_GPL(vli_num_bits);

/* Sets dest = src. */
void vli_set(u64 *dest, const u64 *src, unsigned int ndigits)
{
	int i;

	for (i = 0; i < ndigits; i++)
		dest[i] = src[i];
}
EXPORT_SYMBOL_GPL(vli_set);

/* Copy from vli to buf.
 * For buffers smaller than vli: copy only LSB nbytes from vli.
 * For buffers larger than vli : fill up remaining buf with zeroes.
 */
void vli_copy_to_buf(u8 *dst_buf, unsigned int buf_len,
		     const u64 *src_vli, unsigned int ndigits)
{
	unsigned int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	u8 *vli = (u8 *)src_vli;
	int i;

	for (i = 0; i < buf_len && i < nbytes; i++)
		dst_buf[i] = vli[i];

	for (; i < buf_len; i++)
		dst_buf[i] = 0;
}
EXPORT_SYMBOL_GPL(vli_copy_to_buf);

/* Copy from buffer to vli.
 * For buffers smaller than vli: fill up remaining vli with zeroes.
 * For buffers larger than vli : copy only LSB nbytes to vli.
 */
void vli_copy_from_buf(u64 *dst_vli, unsigned int ndigits,
		       const u8 *src_buf, unsigned int buf_len)
{
	unsigned int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	u8 *vli = (u8 *)dst_vli;
	int i;

	for (i = 0; i < buf_len && i < nbytes; i++)
		vli[i] = src_buf[i];

	for (; i < nbytes; i++)
		vli[i] = 0;
}
EXPORT_SYMBOL_GPL(vli_copy_from_buf);

/* Returns sign of left - right. */
int vli_cmp(const u64 *left, const u64 *right, unsigned int ndigits)
{
	int i;

	for (i = ndigits - 1; i >= 0; i--) {
		if (left[i] > right[i])
			return 1;
		else if (left[i] < right[i])
			return -1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vli_cmp);

/* Computes result = in << c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 64.
 */
u64 vli_lshift(u64 *result, const u64 *in, unsigned int shift,
	       unsigned int ndigits)
{
	u64 carry = 0;
	int i;

	for (i = 0; i < ndigits; i++) {
		u64 temp = in[i];

		result[i] = (temp << shift) | carry;
		carry = temp >> (64 - shift);
	}

	return carry;
}
EXPORT_SYMBOL_GPL(vli_lshift);

/* Computes vli = vli >> 1. */
void vli_rshift1(u64 *vli, unsigned int ndigits)
{
	u64 *end = vli;
	u64 carry = 0;

	vli += ndigits;

	while (vli-- > end) {
		u64 temp = *vli;
		*vli = (temp >> 1) | carry;
		carry = temp << 63;
	}
}
EXPORT_SYMBOL_GPL(vli_rshift1);

/* Computes result = left + right, returning carry. Can modify in place. */
u64 vli_add(u64 *result, const u64 *left, const u64 *right,
	    unsigned int ndigits)
{
	u64 carry = 0;
	int i;

	for (i = 0; i < ndigits; i++) {
		u64 sum;

		sum = left[i] + right[i] + carry;
		if (sum != left[i])
			carry = (sum < left[i]);

		result[i] = sum;
	}

	return carry;
}
EXPORT_SYMBOL_GPL(vli_add);

/* Computes result = left - right, returning borrow. Can modify in place. */
u64 vli_sub(u64 *result, const u64 *left, const u64 *right,
	    unsigned int ndigits)
{
	u64 borrow = 0;
	int i;

	for (i = 0; i < ndigits; i++) {
		u64 diff;

		diff = left[i] - right[i] - borrow;
		if (diff != left[i])
			borrow = (diff > left[i]);

		result[i] = diff;
	}

	return borrow;
}
EXPORT_SYMBOL_GPL(vli_sub);

static uint128_t mul_64_64(u64 left, u64 right)
{
	u64 a0 = left & 0xffffffffull;
	u64 a1 = left >> 32;
	u64 b0 = right & 0xffffffffull;
	u64 b1 = right >> 32;
	u64 m0 = a0 * b0;
	u64 m1 = a0 * b1;
	u64 m2 = a1 * b0;
	u64 m3 = a1 * b1;
	uint128_t result;

	m2 += (m0 >> 32);
	m2 += m1;

	/* Overflow */
	if (m2 < m1)
		m3 += 0x100000000ull;

	result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
	result.m_high = m3 + (m2 >> 32);

	return result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
	uint128_t result;

	result.m_low = a.m_low + b.m_low;
	result.m_high = a.m_high + b.m_high + (result.m_low < a.m_low);

	return result;
}

void vli_mult(u64 *result, const u64 *left, const u64 *right,
	      unsigned int ndigits)
{
	uint128_t r01 = { 0, 0 };
	u64 r2 = 0;
	unsigned int i, k;

	/* Compute each digit of result in sequence, maintaining the
	 * carries.
	 */
	for (k = 0; k < ndigits * 2 - 1; k++) {
		unsigned int min;

		if (k < ndigits)
			min = 0;
		else
			min = (k + 1) - ndigits;

		for (i = min; i <= k && i < ndigits; i++) {
			uint128_t product;

			product = mul_64_64(left[i], right[k - i]);

			r01 = add_128_128(r01, product);
			r2 += (r01.m_high < product.m_high);
		}

		result[k] = r01.m_low;
		r01.m_low = r01.m_high;
		r01.m_high = r2;
		r2 = 0;
	}

	result[ndigits * 2 - 1] = r01.m_low;
}
EXPORT_SYMBOL_GPL(vli_mult);

void vli_square(u64 *result, const u64 *left, unsigned int ndigits)
{
	uint128_t r01 = { 0, 0 };
	u64 r2 = 0;
	int i, k;

	for (k = 0; k < ndigits * 2 - 1; k++) {
		unsigned int min;

		if (k < ndigits)
			min = 0;
		else
			min = (k + 1) - ndigits;

		for (i = min; i <= k && i <= k - i; i++) {
			uint128_t product;

			product = mul_64_64(left[i], left[k - i]);

			if (i < k - i) {
				r2 += product.m_high >> 63;
				product.m_high = (product.m_high << 1) |
						 (product.m_low >> 63);
				product.m_low <<= 1;
			}

			r01 = add_128_128(r01, product);
			r2 += (r01.m_high < product.m_high);
		}

		result[k] = r01.m_low;
		r01.m_low = r01.m_high;
		r01.m_high = r2;
		r2 = 0;
	}

	result[ndigits * 2 - 1] = r01.m_low;
}
EXPORT_SYMBOL_GPL(vli_square);

/* Computes result = (left + right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
void vli_mod_add(u64 *result, const u64 *left, const u64 *right,
		 const u64 *mod, unsigned int ndigits)
{
	u64 carry;

	carry = vli_add(result, left, right, ndigits);

	/* result > mod (result = mod + remainder), so subtract mod to
	 * get remainder.
	 */
	if (carry || vli_cmp(result, mod, ndigits) >= 0)
		vli_sub(result, result, mod, ndigits);
}
EXPORT_SYMBOL_GPL(vli_mod_add);

/* Computes result = (left - right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
void vli_mod_sub(u64 *result, const u64 *left, const u64 *right,
		 const u64 *mod, unsigned int ndigits)
{
	u64 borrow = vli_sub(result, left, right, ndigits);

	/* In this case, p_result == -diff == (max int) - diff.
	 * Since -x % d == d - x, we can get the correct result from
	 * result + mod (with overflow).
	 */
	if (borrow)
		vli_add(result, result, mod, ndigits);
}
EXPORT_SYMBOL_GPL(vli_mod_sub);

/* Computes result = input % mod.
 * Assumes that input < mod, result != mod.
 */
void vli_mod(u64 *result, const u64 *input, const u64 *mod,
	     unsigned int ndigits)
{
	if (vli_cmp(input, mod, ndigits) >= 0)
		vli_sub(result, input, mod, ndigits);
	else
		vli_set(result, input, ndigits);
}
EXPORT_SYMBOL_GPL(vli_mod);

/* Print vli in big-endian format.
 * The bytes are printed in hex.
 */
void vli_print(char *vli_name, const u64 *vli, unsigned int ndigits)
{
	int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	int buf_size = 2 * ECC_MAX_DIGIT_BYTES + 1;
	unsigned char *c, buf[buf_size];
	int i, j;

	c = (unsigned char *)vli;

	for (i = nbytes - 1, j = 0; i >= 0 && j+1 < buf_size; i--, j += 2)
		snprintf(&buf[j], 3, "%02x", *(c + i));

	buf[j] = '\0';

	pr_info("%20s(BigEnd)=%s\n", vli_name, buf);
}
EXPORT_SYMBOL_GPL(vli_print);

/* Computes result = (left * right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 * Uses:
 *	(a * b) % m = ((a % m) * (b % m)) % m
 *	(a * b) % m = (a + a + ... + a) % m = b modular additions of (a % m)
 */
void vli_mod_mult(u64 *result, const u64 *left, const u64 *right,
		  const u64 *mod, unsigned int ndigits)
{
	u64 t1[ndigits], mm[ndigits];
	u64 aa[ndigits], bb[ndigits];

	vli_clear(result, ndigits);
	vli_set(aa, left, ndigits);
	vli_set(bb, right, ndigits);
	vli_set(mm, mod, ndigits);

	/* aa = aa % mm */
	vli_mod(aa, aa, mm, ndigits);

	/* bb = bb % mm */
	vli_mod(bb, bb, mm, ndigits);

	while (!vli_is_zero(bb, ndigits)) {

		/* if bb is odd i.e. 0th bit set then add
		 * aa i.e. result = (result + aa) % mm
		 */
		if (vli_test_bit(bb, 0))
			vli_mod_add(result, result, aa, mm, ndigits);

		/* bb = bb / 2 = bb >> 1 */
		vli_rshift1(bb, ndigits);

		/* aa = (aa * 2) % mm */
		vli_sub(t1, mm, aa, ndigits);
		if (vli_cmp(aa, t1, ndigits) == -1)
			/* if aa < t1 then aa = aa * 2 = aa << 1*/
			vli_lshift(aa, aa, 1, ndigits);
		else
			/* if aa >= t1 then aa = aa - t1 */
			vli_sub(aa, aa, t1, ndigits);
	}
}
EXPORT_SYMBOL_GPL(vli_mod_mult);

/* Computes p_result = p_product % curve_p.
 * See algorithm 5 and 6 from
 * http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf
 */
static void vli_mmod_fast_192(u64 *result, const u64 *product,
			      const u64 *curve_prime, u64 *tmp)
{
	const unsigned int ndigits = 3;
	int carry;

	vli_set(result, product, ndigits);

	vli_set(tmp, &product[3], ndigits);
	carry = vli_add(result, result, tmp, ndigits);

	tmp[0] = 0;
	tmp[1] = product[3];
	tmp[2] = product[4];
	carry += vli_add(result, result, tmp, ndigits);

	tmp[0] = tmp[1] = product[5];
	tmp[2] = 0;
	carry += vli_add(result, result, tmp, ndigits);

	while (carry || vli_cmp(curve_prime, result, ndigits) != 1)
		carry -= vli_sub(result, result, curve_prime, ndigits);
}

/* Computes result = product % curve_prime
 * from http://www.nsa.gov/ia/_files/nist-routines.pdf
 */
static void vli_mmod_fast_256(u64 *result, const u64 *product,
			      const u64 *curve_prime, u64 *tmp)
{
	int carry;
	const unsigned int ndigits = 4;

	/* t */
	vli_set(result, product, ndigits);

	/* s1 */
	tmp[0] = 0;
	tmp[1] = product[5] & 0xffffffff00000000ull;
	tmp[2] = product[6];
	tmp[3] = product[7];
	carry = vli_lshift(tmp, tmp, 1, ndigits);
	carry += vli_add(result, result, tmp, ndigits);

	/* s2 */
	tmp[1] = product[6] << 32;
	tmp[2] = (product[6] >> 32) | (product[7] << 32);
	tmp[3] = product[7] >> 32;
	carry += vli_lshift(tmp, tmp, 1, ndigits);
	carry += vli_add(result, result, tmp, ndigits);

	/* s3 */
	tmp[0] = product[4];
	tmp[1] = product[5] & 0xffffffff;
	tmp[2] = 0;
	tmp[3] = product[7];
	carry += vli_add(result, result, tmp, ndigits);

	/* s4 */
	tmp[0] = (product[4] >> 32) | (product[5] << 32);
	tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
	tmp[2] = product[7];
	tmp[3] = (product[6] >> 32) | (product[4] << 32);
	carry += vli_add(result, result, tmp, ndigits);

	/* d1 */
	tmp[0] = (product[5] >> 32) | (product[6] << 32);
	tmp[1] = (product[6] >> 32);
	tmp[2] = 0;
	tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d2 */
	tmp[0] = product[6];
	tmp[1] = product[7];
	tmp[2] = 0;
	tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d3 */
	tmp[0] = (product[6] >> 32) | (product[7] << 32);
	tmp[1] = (product[7] >> 32) | (product[4] << 32);
	tmp[2] = (product[4] >> 32) | (product[5] << 32);
	tmp[3] = (product[6] << 32);
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d4 */
	tmp[0] = product[7];
	tmp[1] = product[4] & 0xffffffff00000000ull;
	tmp[2] = product[5];
	tmp[3] = product[6] & 0xffffffff00000000ull;
	carry -= vli_sub(result, result, tmp, ndigits);

	if (carry < 0) {
		do {
			carry += vli_add(result, result, curve_prime, ndigits);
		} while (carry < 0);
	} else {
		while (carry || vli_cmp(curve_prime, result, ndigits) != 1)
			carry -= vli_sub(result, result, curve_prime, ndigits);
	}
}

/* Computes result = product % curve_prime
 *  from http://www.nsa.gov/ia/_files/nist-routines.pdf
*/
bool vli_mmod_fast(u64 *result, u64 *product,
		   const u64 *curve_prime, unsigned int ndigits)
{
	u64 tmp[2 * ndigits];

	switch (ndigits) {
	case 3:
		vli_mmod_fast_192(result, product, curve_prime, tmp);
		break;
	case 4:
		vli_mmod_fast_256(result, product, curve_prime, tmp);
		break;
	default:
		pr_err("unsupports digits size!\n");
		return false;
	}

	return true;
}
EXPORT_SYMBOL_GPL(vli_mmod_fast);

/* Computes result = (left * right) % curve_prime. */
void vli_mod_mult_fast(u64 *result, const u64 *left, const u64 *right,
		       const u64 *curve_prime, unsigned int ndigits)
{
	u64 product[2 * ndigits];

	vli_mult(product, left, right, ndigits);
	vli_mmod_fast(result, product, curve_prime, ndigits);
}
EXPORT_SYMBOL_GPL(vli_mod_mult_fast);

/* Computes result = left^2 % curve_prime. */
void vli_mod_square_fast(u64 *result, const u64 *left,
			 const u64 *curve_prime, unsigned int ndigits)
{
	u64 product[2 * ndigits];

	vli_square(product, left, ndigits);
	vli_mmod_fast(result, product, curve_prime, ndigits);
}
EXPORT_SYMBOL_GPL(vli_mod_square_fast);

#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / p_input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */
void vli_mod_inv(u64 *result, const u64 *input, const u64 *mod,
		 unsigned int ndigits)
{
	u64 a[ndigits], b[ndigits];
	u64 u[ndigits], v[ndigits];
	u64 carry;
	int cmp_result;

	if (vli_is_zero(input, ndigits)) {
		vli_clear(result, ndigits);
		return;
	}

	vli_set(a, input, ndigits);
	vli_set(b, mod, ndigits);
	vli_clear(u, ndigits);
	u[0] = 1;
	vli_clear(v, ndigits);

	while ((cmp_result = vli_cmp(a, b, ndigits)) != 0) {
		carry = 0;

		if (EVEN(a)) {
			vli_rshift1(a, ndigits);

			if (!EVEN(u))
				carry = vli_add(u, u, mod, ndigits);

			vli_rshift1(u, ndigits);
			if (carry)
				u[ndigits - 1] |= 0x8000000000000000ull;
		} else if (EVEN(b)) {
			vli_rshift1(b, ndigits);

			if (!EVEN(v))
				carry = vli_add(v, v, mod, ndigits);

			vli_rshift1(v, ndigits);
			if (carry)
				v[ndigits - 1] |= 0x8000000000000000ull;
		} else if (cmp_result > 0) {
			vli_sub(a, a, b, ndigits);
			vli_rshift1(a, ndigits);

			if (vli_cmp(u, v, ndigits) < 0)
				vli_add(u, u, mod, ndigits);

			vli_sub(u, u, v, ndigits);
			if (!EVEN(u))
				carry = vli_add(u, u, mod, ndigits);

			vli_rshift1(u, ndigits);
			if (carry)
				u[ndigits - 1] |= 0x8000000000000000ull;
		} else {
			vli_sub(b, b, a, ndigits);
			vli_rshift1(b, ndigits);

			if (vli_cmp(v, u, ndigits) < 0)
				vli_add(v, v, mod, ndigits);

			vli_sub(v, v, u, ndigits);
			if (!EVEN(v))
				carry = vli_add(v, v, mod, ndigits);

			vli_rshift1(v, ndigits);
			if (carry)
				v[ndigits - 1] |= 0x8000000000000000ull;
		}
	}

	vli_set(result, u, ndigits);
}
EXPORT_SYMBOL_GPL(vli_mod_inv);

/* ------ Point operations ------ */

/* Returns true if p_point is the point at infinity, false otherwise. */
bool ecc_point_is_zero(const struct ecc_point *point)
{
	return (vli_is_zero(point->x, point->ndigits) &&
		vli_is_zero(point->y, point->ndigits));
}
EXPORT_SYMBOL_GPL(ecc_point_is_zero);

/* Point multiplication algorithm using Montgomery's ladder with co-Z
 * coordinates. From http://eprint.iacr.org/2011/338.pdf
 */

/* Double in place */
void ecc_point_double_jacobian(u64 *x1, u64 *y1, u64 *z1,
			       u64 *curve_prime, unsigned int ndigits)
{
	/* t1 = x, t2 = y, t3 = z */
	u64 t4[ndigits];
	u64 t5[ndigits];

	if (vli_is_zero(z1, ndigits))
		return;

	/* t4 = y1^2 */
	vli_mod_square_fast(t4, y1, curve_prime, ndigits);
	/* t5 = x1*y1^2 = A */
	vli_mod_mult_fast(t5, x1, t4, curve_prime, ndigits);
	/* t4 = y1^4 */
	vli_mod_square_fast(t4, t4, curve_prime, ndigits);
	/* t2 = y1*z1 = z3 */
	vli_mod_mult_fast(y1, y1, z1, curve_prime, ndigits);
	/* t3 = z1^2 */
	vli_mod_square_fast(z1, z1, curve_prime, ndigits);

	/* t1 = x1 + z1^2 */
	vli_mod_add(x1, x1, z1, curve_prime, ndigits);
	/* t3 = 2*z1^2 */
	vli_mod_add(z1, z1, z1, curve_prime, ndigits);
	/* t3 = x1 - z1^2 */
	vli_mod_sub(z1, x1, z1, curve_prime, ndigits);
	/* t1 = x1^2 - z1^4 */
	vli_mod_mult_fast(x1, x1, z1, curve_prime, ndigits);

	/* t3 = 2*(x1^2 - z1^4) */
	vli_mod_add(z1, x1, x1, curve_prime, ndigits);
	/* t1 = 3*(x1^2 - z1^4) */
	vli_mod_add(x1, x1, z1, curve_prime, ndigits);
	if (vli_test_bit(x1, 0)) {
		u64 carry = vli_add(x1, x1, curve_prime, ndigits);

		vli_rshift1(x1, ndigits);
		x1[ndigits - 1] |= carry << 63;
	} else {
		vli_rshift1(x1, ndigits);
	}
	/* t1 = 3/2*(x1^2 - z1^4) = B */

	/* t3 = B^2 */
	vli_mod_square_fast(z1, x1, curve_prime, ndigits);
	/* t3 = B^2 - A */
	vli_mod_sub(z1, z1, t5, curve_prime, ndigits);
	/* t3 = B^2 - 2A = x3 */
	vli_mod_sub(z1, z1, t5, curve_prime, ndigits);
	/* t5 = A - x3 */
	vli_mod_sub(t5, t5, z1, curve_prime, ndigits);
	/* t1 = B * (A - x3) */
	vli_mod_mult_fast(x1, x1, t5, curve_prime, ndigits);
	/* t4 = B * (A - x3) - y1^4 = y3 */
	vli_mod_sub(t4, x1, t4, curve_prime, ndigits);

	vli_set(x1, z1, ndigits);
	vli_set(z1, y1, ndigits);
	vli_set(y1, t4, ndigits);
}
EXPORT_SYMBOL_GPL(ecc_point_double_jacobian);

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(u64 *x1, u64 *y1, u64 *z, u64 *curve_prime,
		    unsigned int ndigits)
{
	u64 t1[ndigits];

	vli_mod_square_fast(t1, z, curve_prime, ndigits);    /* z^2 */
	vli_mod_mult_fast(x1, x1, t1, curve_prime, ndigits); /* x1 * z^2 */
	vli_mod_mult_fast(t1, t1, z, curve_prime, ndigits);  /* z^3 */
	vli_mod_mult_fast(y1, y1, t1, curve_prime, ndigits); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void xycz_initial_double(u64 *x1, u64 *y1, u64 *x2, u64 *y2,
				u64 *p_initial_z, u64 *curve_prime,
				unsigned int ndigits)
{
	u64 z[ndigits];

	vli_set(x2, x1, ndigits);
	vli_set(y2, y1, ndigits);

	vli_clear(z, ndigits);
	z[0] = 1;

	if (p_initial_z)
		vli_set(z, p_initial_z, ndigits);

	apply_z(x1, y1, z, curve_prime, ndigits);

	ecc_point_double_jacobian(x1, y1, z, curve_prime, ndigits);

	apply_z(x2, y2, z, curve_prime, ndigits);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
 * or P => P', Q => P + Q
 */
static void xycz_add(u64 *x1, u64 *y1, u64 *x2, u64 *y2, u64 *curve_prime,
		     unsigned int ndigits)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u64 t5[ndigits];

	/* t5 = x2 - x1 */
	vli_mod_sub(t5, x2, x1, curve_prime, ndigits);
	/* t5 = (x2 - x1)^2 = A */
	vli_mod_square_fast(t5, t5, curve_prime, ndigits);
	/* t1 = x1*A = B */
	vli_mod_mult_fast(x1, x1, t5, curve_prime, ndigits);
	/* t3 = x2*A = C */
	vli_mod_mult_fast(x2, x2, t5, curve_prime, ndigits);
	/* t4 = y2 - y1 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);
	/* t5 = (y2 - y1)^2 = D */
	vli_mod_square_fast(t5, y2, curve_prime, ndigits);

	/* t5 = D - B */
	vli_mod_sub(t5, t5, x1, curve_prime, ndigits);
	/* t5 = D - B - C = x3 */
	vli_mod_sub(t5, t5, x2, curve_prime, ndigits);
	/* t3 = C - B */
	vli_mod_sub(x2, x2, x1, curve_prime, ndigits);
	/* t2 = y1*(C - B) */
	vli_mod_mult_fast(y1, y1, x2, curve_prime, ndigits);
	/* t3 = B - x3 */
	vli_mod_sub(x2, x1, t5, curve_prime, ndigits);
	/* t4 = (y2 - y1)*(B - x3) */
	vli_mod_mult_fast(y2, y2, x2, curve_prime, ndigits);
	/* t4 = y3 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	vli_set(x2, t5, ndigits);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
 * or P => P - Q, Q => P + Q
 */
static void xycz_add_c(u64 *x1, u64 *y1, u64 *x2, u64 *y2, u64 *curve_prime,
		       unsigned int ndigits)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u64 t5[ndigits];
	u64 t6[ndigits];
	u64 t7[ndigits];

	/* t5 = x2 - x1 */
	vli_mod_sub(t5, x2, x1, curve_prime, ndigits);
	/* t5 = (x2 - x1)^2 = A */
	vli_mod_square_fast(t5, t5, curve_prime, ndigits);
	/* t1 = x1*A = B */
	vli_mod_mult_fast(x1, x1, t5, curve_prime, ndigits);
	/* t3 = x2*A = C */
	vli_mod_mult_fast(x2, x2, t5, curve_prime, ndigits);
	/* t4 = y2 + y1 */
	vli_mod_add(t5, y2, y1, curve_prime, ndigits);
	/* t4 = y2 - y1 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	/* t6 = C - B */
	vli_mod_sub(t6, x2, x1, curve_prime, ndigits);
	/* t2 = y1 * (C - B) */
	vli_mod_mult_fast(y1, y1, t6, curve_prime, ndigits);
	/* t6 = B + C */
	vli_mod_add(t6, x1, x2, curve_prime, ndigits);
	/* t3 = (y2 - y1)^2 */
	vli_mod_square_fast(x2, y2, curve_prime, ndigits);
	/* t3 = x3 */
	vli_mod_sub(x2, x2, t6, curve_prime, ndigits);

	/* t7 = B - x3 */
	vli_mod_sub(t7, x1, x2, curve_prime, ndigits);
	/* t4 = (y2 - y1)*(B - x3) */
	vli_mod_mult_fast(y2, y2, t7, curve_prime, ndigits);
	/* t4 = y3 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	/* t7 = (y2 + y1)^2 = F */
	vli_mod_square_fast(t7, t5, curve_prime, ndigits);
	/* t7 = x3' */
	vli_mod_sub(t7, t7, t6, curve_prime, ndigits);
	/* t6 = x3' - B */
	vli_mod_sub(t6, t7, x1, curve_prime, ndigits);
	/* t6 = (y2 + y1)*(x3' - B) */
	vli_mod_mult_fast(t6, t6, t5, curve_prime, ndigits);
	/* t2 = y3' */
	vli_mod_sub(y1, t6, y1, curve_prime, ndigits);

	vli_set(x1, t7, ndigits);
}

/* Point addition.
 * Add 2 distinct points on elliptic curve to get a new point.
 *
 * P = (x1,y1)and Q = (x2, y2) then P + Q = (x3,y3) where
 * x3 = ((y2-y1)/(x2-x1))^2 - x1 - x2
 * y3 = ((y2-y1)/(x2-x1))(x1-x3) - y1
 *
 * Q => P + Q
 */
void ecc_point_add(u64 *x1, u64 *y1, u64 *x2, u64 *y2, u64 *curve_prime,
		   unsigned int ndigits)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u64 t5[ndigits];
	u64 t6[ndigits];
	u64 t7[ndigits];

	/* t6 = x2 - x1 */
	vli_mod_sub(t6, x2, x1, curve_prime, ndigits);
	/* t6 = (x2 - x1)^2 = A */
	vli_mod_square_fast(t6, t6, curve_prime, ndigits);
	vli_mod_inv(t7, t6, curve_prime, ndigits);
	/* t5 = x2 - x1 */
	vli_mod_sub(t5, x2, x1, curve_prime, ndigits);
	/* t5 = (x2 - x1)^2 = A */
	vli_mod_square_fast(t5, t5, curve_prime, ndigits);
	/* t1 = x1*A = B = x1*(x2-x1)^2*/
	vli_mod_mult_fast(x1, x1, t5, curve_prime, ndigits);
	/* t3 = x2*A = C = x2*(x2-x1)^2*/
	vli_mod_mult_fast(x2, x2, t5, curve_prime, ndigits);
	/* t4 = y2 - y1 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);
	/* t5 = (y2 - y1)^2 = D */
	vli_mod_square_fast(t5, y2, curve_prime, ndigits);

	/* t5 = D - B = (y2 - y1)^2 - x1*(x2-x1)^2 */
	vli_mod_sub(t5, t5, x1, curve_prime, ndigits);
	/* t5 = D - B - C = x3 = (y2 - y1)^2 - x1*(x2-x1)^2 - x2*(x2-x1)^2*/
	vli_mod_sub(t5, t5, x2, curve_prime, ndigits);

	/* t3 = C - B = x2*(x2-x1)^2 - x1*(x2-x1)^2 */
	vli_mod_sub(x2, x2, x1, curve_prime, ndigits);
	/* t2 = y1*(C - B) = y1*(x2*(x2-x1)^2 - x1*(x2-x1)^2)*/
	vli_mod_mult_fast(y1, y1, x2, curve_prime, ndigits);
	/* t3 = B - x3 = x1*(x2-x1)^2 - x3*/
	vli_mod_sub(x2, x1, t5, curve_prime, ndigits);
	/* t4 = (y2 - y1)*(B - x3)  = (y2 - y1)*(x1*(x2-x1)^2 - x3)*/
	vli_mod_mult_fast(y2, y2, x2, curve_prime, ndigits);
	/* t4 = y3 = ((y2 - y1)*(x1*(x2-x1)^2 - x3)) - y1*/
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	vli_mod_mult_fast(t5, t5, t7,  curve_prime, ndigits);
	vli_set(x2, t5, ndigits);
}
EXPORT_SYMBOL_GPL(ecc_point_add);

void ecc_point_mult(struct ecc_point *result,
		    const struct ecc_point *point, const u64 *scalar,
		    u64 *initial_z, u64 *curve_prime,
		    unsigned int ndigits)
{
	/* R0 and R1 */
	u64 rx[2][ndigits];
	u64 ry[2][ndigits];
	u64 z[ndigits];
	int i, nb;
	int num_bits = vli_num_bits(scalar, ndigits);

	vli_set(rx[1], point->x, ndigits);
	vli_set(ry[1], point->y, ndigits);

	xycz_initial_double(rx[1], ry[1], rx[0], ry[0], initial_z, curve_prime,
			    ndigits);

	for (i = num_bits - 2; i > 0; i--) {
		nb = !vli_test_bit(scalar, i);
		xycz_add_c(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], curve_prime,
			   ndigits);
		xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], curve_prime,
			 ndigits);
	}

	nb = !vli_test_bit(scalar, 0);
	xycz_add_c(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], curve_prime,
		   ndigits);

	/* Find final 1/Z value. */
	/* X1 - X0 */
	vli_mod_sub(z, rx[1], rx[0], curve_prime, ndigits);
	/* Yb * (X1 - X0) */
	vli_mod_mult_fast(z, z, ry[1 - nb], curve_prime, ndigits);
	/* xP * Yb * (X1 - X0) */
	vli_mod_mult_fast(z, z, point->x, curve_prime, ndigits);

	/* 1 / (xP * Yb * (X1 - X0)) */
	vli_mod_inv(z, z, curve_prime, point->ndigits);

	/* yP / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, point->y, curve_prime, ndigits);
	/* Xb * yP / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, rx[1 - nb], curve_prime, ndigits);
	/* End 1/Z calculation */

	xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], curve_prime, ndigits);

	apply_z(rx[0], ry[0], z, curve_prime, ndigits);

	vli_set(result->x, rx[0], ndigits);
	vli_set(result->y, ry[0], ndigits);
}
EXPORT_SYMBOL_GPL(ecc_point_mult);

void ecc_swap_digits(const u64 *in, u64 *out, unsigned int ndigits)
{
	const __be64 *src = (__force __be64 *)in;
	int i;

	for (i = 0; i < ndigits; i++)
		out[i] = be64_to_cpu(src[ndigits - 1 - i]);
}
EXPORT_SYMBOL_GPL(ecc_swap_digits);

int ecc_is_key_valid(unsigned int curve_id, unsigned int ndigits,
		     const u8 *private_key, unsigned int private_key_len)
{
	int nbytes;
	const struct ecc_curve *curve = ecc_get_curve(curve_id);

	if (!private_key)
		return -EINVAL;

	nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;

	if (private_key_len != nbytes)
		return -EINVAL;

	if (vli_is_zero((const u64 *)&private_key[0], ndigits))
		return -EINVAL;

	/* Make sure the private key is in the range [1, n-1]. */
	if (vli_cmp(curve->n, (const u64 *)&private_key[0], ndigits) != 1)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(ecc_is_key_valid);

int ecc_is_pub_key_valid(unsigned int curve_id, unsigned int ndigits,
			 const u8 *pub_key, unsigned int pub_key_len)
{
	const struct ecc_curve *curve = ecc_get_curve(curve_id);
	int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	struct ecc_point p;

	if (!pub_key || pub_key_len != 2 * nbytes)
		return -EINVAL;

	p.x = (u64 *)pub_key;
	p.y = (u64 *)(pub_key + ECC_MAX_DIGIT_BYTES);
	p.ndigits = ndigits;

	if (vli_cmp(curve->p, p.x, ndigits) != 1 ||
	    vli_cmp(curve->p, p.y, ndigits) != 1)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(ecc_is_pub_key_valid);
