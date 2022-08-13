/*
 * ECDSA generic algorithm
 *
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/module.h>
#include <linux/scatterlist.h>
#include <crypto/rng.h>
#include <crypto/internal/akcipher.h>
#include <crypto/akcipher.h>
#include <crypto/ecdsa.h>

#include "ecc.h"

struct ecdsa_ctx {
	unsigned int curve_id;
	unsigned int ndigits;
	u64 private_key[ECC_MAX_DIGITS];
	u64 public_key[2 * ECC_MAX_DIGITS];
};

static inline struct ecdsa_ctx *ecdsa_get_ctx(struct crypto_akcipher *tfm)
{
	return akcipher_tfm_ctx(tfm);
}

int ecdsa_sign(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecdsa_ctx *ctx = ecdsa_get_ctx(tfm);
	unsigned int ndigits = ctx->ndigits;
	unsigned int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	unsigned int curve_id = ctx->curve_id;
	const struct ecc_curve *curve = ecc_get_curve(curve_id);
	struct ecc_point *x1y1 = NULL;
	u64 z[ndigits], d[ndigits];
	u64 k[ndigits], k_inv[ndigits];
	u64 r[ndigits], s[ndigits];
	u64 dr[ndigits], zdr[ndigits];
	u8 *r_ptr, *s_ptr;
	int err;

	if (req->dst_len < 2 * nbytes) {
		req->dst_len = 2 * nbytes;
		return -EINVAL;
	}

	if (!curve)
		return -EINVAL;

	ecdsa_parse_msg_hash(req, z, ndigits);

	/* d */
	vli_set(d, (const u64 *)ctx->private_key, ndigits);

	/* k */
	err = ecdsa_get_rnd_bytes((u8 *)k, nbytes);
	if (err)
		return err;

#if defined(CONFIG_CRYPTO_MANAGER2)
	if (req->info)
		vli_copy_from_buf(k, ndigits, req->info, nbytes);
#endif

	x1y1 = ecc_alloc_point(ndigits);
	if (!x1y1)
		return -ENOMEM;

	/* (x1, y1) = k x G */
	ecc_point_mult(x1y1, &curve->g, k, NULL, curve->p, ndigits);

	/* r = x1 mod n */
	vli_mod(r, x1y1->x, curve->n, ndigits);

	/* k^-1 */
	vli_mod_inv(k_inv, k, curve->n, ndigits);

	/* d . r mod n */
	vli_mod_mult(dr, d, r, curve->n, ndigits);

	/* z + dr mod n */
	vli_mod_add(zdr, z, dr, curve->n, ndigits);

	/* k^-1 . ( z + dr) mod n */
	vli_mod_mult(s, k_inv, zdr, curve->n, ndigits);

	/* write signature (r,s) in dst */
	r_ptr = sg_virt(req->dst);
	s_ptr = (u8 *)sg_virt(req->dst) + nbytes;

	vli_copy_to_buf(r_ptr, nbytes, r, ndigits);
	vli_copy_to_buf(s_ptr, nbytes, s, ndigits);

	req->dst_len = 2 * nbytes;

	ecc_free_point(x1y1);
	return 0;
}

int ecdsa_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecdsa_ctx *ctx = ecdsa_get_ctx(tfm);
	unsigned int ndigits = ctx->ndigits;
	unsigned int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	unsigned int curve_id = ctx->curve_id;
	const struct ecc_curve *curve = ecc_get_curve(curve_id);
	struct ecc_point *x1y1 = NULL, *x2y2 = NULL, *Q = NULL;
	u64 r[ndigits], s[ndigits], v[ndigits];
	u64 z[ndigits], w[ndigits];
	u64 u1[ndigits], u2[ndigits];
	u64 x1[ndigits], x2[ndigits];
	u64 y1[ndigits], y2[ndigits];
	u64 *ctx_qx, *ctx_qy;
	int ret;

	if (!curve)
		return -EINVAL;

	x1y1 = ecc_alloc_point(ndigits);
	x2y2 = ecc_alloc_point(ndigits);
	Q = ecc_alloc_point(ndigits);
	if (!x1y1 || !x2y2 || !Q) {
		ret = -ENOMEM;
		goto exit;
	}

	ecdsa_parse_msg_hash(req, z, ndigits);

	/* Signature r,s */
	vli_copy_from_buf(r, ndigits, sg_virt(&req->src[1]), nbytes);
	vli_copy_from_buf(s, ndigits, sg_virt(&req->src[2]), nbytes);

	/* w = s^-1 mod n */
	vli_mod_inv(w, s, curve->n, ndigits);

	/* u1 = zw mod n */
	vli_mod_mult(u1, z, w, curve->n, ndigits);

	/* u2 = rw mod n */
	vli_mod_mult(u2, r, w, curve->n, ndigits);

	/* u1 . G */
	ecc_point_mult(x1y1, &curve->g, u1, NULL, curve->p, ndigits);

	/* Q=(Qx,Qy) */
	ctx_qx = ctx->public_key;
	ctx_qy = ctx_qx + ECC_MAX_DIGITS;
	vli_set(Q->x, ctx_qx, ndigits);
	vli_set(Q->y, ctx_qy, ndigits);

	/* u2 x Q */
	ecc_point_mult(x2y2, Q, u2, NULL, curve->p, ndigits);

	vli_set(x1, x1y1->x, ndigits);
	vli_set(y1, x1y1->y, ndigits);
	vli_set(x2, x2y2->x, ndigits);
	vli_set(y2, x2y2->y, ndigits);

	/* x1y1 + x2y2 => P + Q; P + Q in x2 y2 */
	ecc_point_add(x1, y1, x2, y2, curve->p, ndigits);

	/* v = x mod n */
	vli_mod(v, x2, curve->n, ndigits);

	/* validate signature */
	ret = vli_cmp(v, r, ndigits) == 0 ? 0 : -EBADMSG;
 exit:
	ecc_free_point(x1y1);
	ecc_free_point(x2y2);
	ecc_free_point(Q);
	return ret;
}

int ecdsa_dummy_enc(struct akcipher_request *req)
{
	return -EINVAL;
}

int ecdsa_dummy_dec(struct akcipher_request *req)
{
	return -EINVAL;
}

int ecdsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
		      unsigned int keylen)
{
	struct ecdsa_ctx *ctx = ecdsa_get_ctx(tfm);
	struct ecdsa params;
	unsigned int ndigits;
	unsigned int nbytes;
	u8 *params_qx, *params_qy;
	u64 *ctx_qx, *ctx_qy;
	int err = 0;

	if (crypto_ecdsa_parse_pub_key(key, keylen, &params))
		return -EINVAL;

	ndigits = ecdsa_supported_curve(params.curve_id);
	if (!ndigits)
		return -EINVAL;

	err = ecc_is_pub_key_valid(params.curve_id, ndigits,
				   params.key, params.key_size);
	if (err)
		return err;

	ctx->curve_id = params.curve_id;
	ctx->ndigits = ndigits;
	nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;

	params_qx = params.key;
	params_qy = params_qx + ECC_MAX_DIGIT_BYTES;

	ctx_qx = ctx->public_key;
	ctx_qy = ctx_qx + ECC_MAX_DIGITS;

	vli_copy_from_buf(ctx_qx, ndigits, params_qx, nbytes);
	vli_copy_from_buf(ctx_qy, ndigits, params_qy, nbytes);

	memset(&params, 0, sizeof(params));
	return 0;
}

int ecdsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
		       unsigned int keylen)
{
	struct ecdsa_ctx *ctx = ecdsa_get_ctx(tfm);
	struct ecdsa params;
	unsigned int ndigits;
	unsigned int nbytes;

	if (crypto_ecdsa_parse_priv_key(key, keylen, &params))
		return -EINVAL;

	ndigits = ecdsa_supported_curve(params.curve_id);
	if (!ndigits)
		return -EINVAL;

	ctx->curve_id = params.curve_id;
	ctx->ndigits = ndigits;
	nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;

	if (ecc_is_key_valid(ctx->curve_id, ctx->ndigits,
			     (const u8 *)params.key, params.key_size) < 0)
		return -EINVAL;

	vli_copy_from_buf(ctx->private_key, ndigits, params.key, nbytes);

	memset(&params, 0, sizeof(params));
	return 0;
}

int ecdsa_max_size(struct crypto_akcipher *tfm)
{
	struct ecdsa_ctx *ctx = ecdsa_get_ctx(tfm);
	int nbytes = ctx->ndigits << ECC_DIGITS_TO_BYTES_SHIFT;

	/* For r,s */
	return 2 * nbytes;
}

int ecdsa_init_tfm(struct crypto_akcipher *tfm)
{
	return 0;
}

void ecdsa_exit_tfm(struct crypto_akcipher *tfm)
{
}

static struct akcipher_alg ecdsa_alg = {
	.sign		= ecdsa_sign,
	.verify		= ecdsa_verify,
	.encrypt	= ecdsa_dummy_enc,
	.decrypt	= ecdsa_dummy_dec,
	.set_priv_key	= ecdsa_set_priv_key,
	.set_pub_key	= ecdsa_set_pub_key,
	.max_size	= ecdsa_max_size,
	.init		= ecdsa_init_tfm,
	.exit		= ecdsa_exit_tfm,
	.base = {
		.cra_name	= "ecdsa",
		.cra_driver_name = "ecdsa-generic",
		.cra_priority	= 100,
		.cra_module	= THIS_MODULE,
		.cra_ctxsize	= sizeof(struct ecdsa_ctx),
	},
};

static int ecdsa_init(void)
{
	int ret;

	ret = crypto_register_akcipher(&ecdsa_alg);
	if (ret)
		pr_err("ecdsa alg register failed. err:%d\n", ret);
	return ret;
}

static void ecdsa_exit(void)
{
	crypto_unregister_akcipher(&ecdsa_alg);
}

module_init(ecdsa_init);
module_exit(ecdsa_exit);

MODULE_ALIAS_CRYPTO("ecdsa");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ECDSA Generic Algorithm");
MODULE_AUTHOR("NVIDIA Corporation");
