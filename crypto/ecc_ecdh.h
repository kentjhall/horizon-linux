/*
 * Copyright (c) 2013, Kenneth MacKay. All rights reserved.
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef _CRYPTO_ECC_ECDH_H
#define _CRYPTO_ECC_ECDH_H

#include "ecc.h"

/**
 * ecdh_make_pub_key() - Compute an ECC public key
 *
 * @curve_id:		id representing the curve to use
 * @private_key:	pregenerated private key for the given curve
 * @private_key_len:	length of private_key
 * @public_key:		buffer for storing the public key generated
 * @public_key_len:	length of the public_key buffer
 *
 * Returns 0 if the public key was generated successfully, a negative value
 * if an error occurred.
 */
int ecdh_make_pub_key(const unsigned int curve_id, unsigned int ndigits,
		      const u8 *private_key, unsigned int private_key_len,
		      u8 *public_key, unsigned int public_key_len);

/**
 * crypto_ecdh_shared_secret() - Compute a shared secret
 *
 * @curve_id:		id representing the curve to use
 * @private_key:	private key of part A
 * @private_key_len:	length of private_key
 * @public_key:		public key of counterpart B
 * @public_key_len:	length of public_key
 * @secret:		buffer for storing the calculated shared secret
 * @secret_len:		length of the secret buffer
 *
 * Note: It is recommended that you hash the result of crypto_ecdh_shared_secret
 * before using it for symmetric encryption or HMAC.
 *
 * Returns 0 if the shared secret was generated successfully, a negative value
 * if an error occurred.
 */
int crypto_ecdh_shared_secret(unsigned int curve_id, unsigned int ndigits,
		       const u8 *private_key, unsigned int private_key_len,
		       const u8 *public_key, unsigned int public_key_len,
		       u8 *secret, unsigned int secret_len);

#endif /* _CRYPTO_ECC_ECDH_H */
