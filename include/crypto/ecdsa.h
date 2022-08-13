/*
 * ECC parameters for ECDSA
 *
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _CRYPTO_ECDSA_
#define _CRYPTO_ECDSA_

#include <crypto/ecc.h>
#include <crypto/akcipher.h>

/**
 * DOC: ECDSA Helper Functions
 *
 * To use ECDSA as a akcipher, following functions should be used
 * along with ECDSA private/public keys. The keys are mentioned as
 * a packet private-public key and can be set with API functions
 * crypto_akcipher_set_priv_key() & crypto_akcipher_set_pub_key().
 */

/**
 * struct ecdsa - define an ECDSA private or public key
 *
 * @curve_id:	ECC curve id the keys are based on
 * @key:	Private or public ECDSA key. Private key shall be a valid
 *		number as per curve's prime. Public key is expressed by
 *		valid affine coordinates Qx & Qy.
 * @key_size:	Size of ECDSA private/public key
 */
struct ecdsa {
	unsigned char curve_id;
	unsigned char key[2 * ECC_MAX_DIGIT_BYTES];
	unsigned short key_size;
};

/**
 * crypto_ecdsa_parse_pub_key() - parse and obtain ECDSA public key
 * @buf:	Buffer holding ECDDA packet key that should be parsed
 *		to get ECDSA public key
 * @len:	Length of the packet private-public key buffer
 * @params:	Buffer allocated by the caller that is filled with
 *		ECDSA public key
 *
 * This routine parses packet key from @buf and obtains version, curve id,
 * private key and public key. It checks for correct version and supported
 * curve id. It copies public key from the public key location in given
 * ECDSA packet key to @params.
 *
 * Return:	-EINVAL on errors, 0 on success
 */
int crypto_ecdsa_parse_pub_key(const char *buf, unsigned int len,
			       struct ecdsa *params);

/**
 * crypto_ecdsa_parse_priv_key() - parse and obtain ECDSA private key
 * @buf:	Buffer holding ECDDA packet key that should be parsed
 *		to get ECDSA private key
 * @len:	Length of the packet private-public key buffer
 * @params:	Buffer allocated by the caller that is filled with
 *		ECDSA private key
 *
 * Return:	-EINVAL on errors, 0 on success
 */
int crypto_ecdsa_parse_priv_key(const char *buf, unsigned int len,
				struct ecdsa *params);

/**
 * ecdsa_supported_curve() - check supported curve
 * @curve_id:	ECC curve id as defined by kernel
 *
 * Return:	0 for un-supported curve, ECC DIGITS for curve on success
 */
unsigned int ecdsa_supported_curve(unsigned int curve_id);

void ecdsa_parse_msg_hash(struct akcipher_request *req, u64 *msg,
			  unsigned int ndigits);
int ecdsa_get_rnd_bytes(u8 *rdata, unsigned int dlen);

#endif /* _CRYPTO_ECDSA_ */
