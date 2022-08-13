/*
 * Quick & dirty crypto testing module.
 *
 * This will only exist until we have a better testing mechanism
 * (e.g. a char device).
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 * Copyright (c) 2017, NVIDIA Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#ifndef _CRYPTO_TCRYPT_H
#define _CRYPTO_TCRYPT_H

struct akcipher_speed_template {
	unsigned char *key;
	unsigned char *m;
	unsigned char *c;
	unsigned int key_len;
	unsigned int m_size;
	unsigned int c_size;
	bool public_key_vec;
};

struct cipher_speed_template {
	const char *key;
	unsigned int klen;
};

struct aead_speed_template {
	const char *key;
	unsigned int klen;
};

struct hash_speed {
	unsigned int blen;	/* buffer length */
	unsigned int plen;	/* per-update length */
	unsigned int klen;	/* key length */
};

/*
 * DES test vectors.
 */
#define DES3_SPEED_VECTORS	1

static struct cipher_speed_template des3_speed_template[] = {
	{
		.key	= "\x01\x23\x45\x67\x89\xab\xcd\xef"
			  "\x55\x55\x55\x55\x55\x55\x55\x55"
			  "\xfe\xdc\xba\x98\x76\x54\x32\x10",
		.klen	= 24,
	}
};

/*
 * ECDSA test vectors.
 */
#ifdef CONFIG_CRYPTO_FIPS
#define ECDSA_SPEED_VECTORS	1
#else
#define ECDSA_SPEED_VECTORS	2
#endif

static struct akcipher_speed_template ecdsa_speed_template[] = {
	{
#ifndef CONFIG_CRYPTO_FIPS
		/* [P-192,SHA-256] */
		.m =
		/* Msg / Hash */
		"\xd0\xd8\xc0\x99\xe0\xe2\xf7\xf8"
		"\x87\xe1\x6d\x11\xe1\xcc\x20\x43"
		"\xaf\xc0\x80\xdb\x47\x72\xfa\xe3"
		"\x95\xe5\xd1\x34\x7d\x31\xe8\x5a",
		.m_size = 32,
		.key =
		/* version */
		"\x01"
		/* curve_id */
		"\x01"
		/* d */
		"\x47\x7a\xf2\x5c\x86\xef\x09\x08"
		"\xa4\x9a\x47\x53\x06\xfc\x61\xbc"
		"\xa5\x6f\xdd\x7d\x2f\xd2\xed\x24"
		/* Qx */
		"\xdc\x14\xd4\xd8\x2e\x1e\x25\x2f"
		"\x66\x28\xaa\x80\xbc\x38\x6a\x07"
		"\x8a\x70\xb7\x74\x71\x2d\xf1\x9b"
		/* Qy */
		"\x98\x34\x57\x11\xb0\xdc\x3d\xff"
		"\xfc\xdc\xfe\xa2\x1c\x47\x9e\x4e"
		"\x82\x08\xfc\x7d\xd0\xc8\x54\x48",
		.key_len = 74,
		.c =
		/* k */
		"\x3e\x70\xc7\x86\xaf\xaa\x71\x7c"
		"\x68\x96\xc5\xc3\xec\xb8\x29\xa3"
		"\xfa\xf7\xa5\x36\xa2\x17\xc8\xa5"
		/* R */
		"\xf8\xef\x13\xa8\x86\xe6\x73\x85"
		"\xdf\x2e\x88\x99\x91\x9b\xc2\x90"
		"\xea\x1f\x36\xf4\xec\xba\x4a\x35"
		/* S */
		"\xc1\x82\x9e\x94\xb7\x58\x2c\x63"
		"\x8e\xd7\x15\x5a\x38\x47\x30\x9b"
		"\x1c\x11\x86\xac\x00\x00\xf5\x80",
		.c_size = 72,
	}, {
#endif
		/* [P-256,SHA-256] */
		.m =
		/* Msg / Hash */
		"\x56\xec\x33\xa1\xa6\xe7\xc4\xdb"
		"\x77\x03\x90\x1a\xfb\x2e\x1e\x4e"
		"\x50\x09\xfe\x04\x72\x89\xc5\xc2"
		"\x42\x13\x6c\xe3\xb7\xf6\xac\x44",
		.m_size = 32,
		.key =
		/* version */
		"\x01"
		/* curve_id */
		"\x02"
		/* d */
		"\x64\xb4\x72\xda\x6d\xa5\x54\xca"
		"\xac\x3e\x4e\x0b\x13\xc8\x44\x5b"
		"\x1a\x77\xf4\x59\xee\xa8\x4f\x1f"
		"\x58\x8b\x5f\x71\x3d\x42\x9b\x51"
		/* Qx */
		"\x83\xbf\x71\xc2\x46\xff\x59\x3c"
		"\x2f\xb1\xbf\x4b\xe9\x5d\x56\xd3"
		"\xcc\x8f\xdb\x48\xa2\xbf\x33\xf0"
		"\xf4\xc7\x5f\x07\x1c\xe9\xcb\x1c"
		/* Qy */
		"\xa9\x4c\x9a\xa8\x5c\xcd\x7c\xdc"
		"\x78\x4e\x40\xb7\x93\xca\xb7\x6d"
		"\xe0\x13\x61\x0e\x2c\xdb\x1f\x1a"
		"\xa2\xf9\x11\x88\xc6\x14\x40\xce",
		.key_len = 98,
		.c =
		/* k */
		"\xde\x68\x2a\x64\x87\x07\x67\xb9"
		"\x33\x5d\x4f\x82\x47\x62\x4a\x3b"
		"\x7f\x3c\xe9\xf9\x45\xf2\x80\xa2"
		"\x61\x6a\x90\x4b\xb1\xbb\xa1\x94"
		/* R */
		"\xac\xc2\xc8\x79\x6f\x5e\xbb\xca"
		"\x7a\x5a\x55\x6a\x1f\x6b\xfd\x2a"
		"\xed\x27\x95\x62\xd6\xe3\x43\x88"
		"\x5b\x79\x14\xb5\x61\x80\xac\xf3"
		/* S */
		"\x03\x89\x05\xcc\x2a\xda\xcd\x3c"
		"\x5a\x17\x6f\xe9\x18\xb2\x97\xef"
		"\x1c\x37\xf7\x2b\x26\x76\x6c\x78"
		"\xb2\xa6\x05\xca\x19\x78\xf7\x8b",
		.c_size = 96,
	},
};

/*
 * AKCipher speed tests
 */
#ifndef CONFIG_CRYPTO_FIPS
static u8 akc_speed_template_P192[] = {74, 0};
#endif
static u8 akc_speed_template_P256[] = {98, 0};

/*
 * Cipher speed tests
 */
static u8 speed_template_8[] = {8, 0};
static u8 speed_template_24[] = {24, 0};
static u8 speed_template_8_16[] = {8, 16, 0};
static u8 speed_template_8_32[] = {8, 32, 0};
static u8 speed_template_16_32[] = {16, 32, 0};
static u8 speed_template_16_24_32[] = {16, 24, 32, 0};
static u8 speed_template_20_28_36[] = {20, 28, 36, 0};
static u8 speed_template_32_40_48[] = {32, 40, 48, 0};
static u8 speed_template_32_48[] = {32, 48, 0};
static u8 speed_template_32_48_64[] = {32, 48, 64, 0};
static u8 speed_template_32_64[] = {32, 64, 0};
static u8 speed_template_32[] = {32, 0};

/*
 * AEAD speed tests
 */
static u8 aead_speed_template_19[] = {19, 0};
static u8 aead_speed_template_20[] = {20, 0};
static u8 aead_speed_template_36[] = {36, 0};

/*
 * Digest speed tests
 */
static struct hash_speed generic_hash_speed_template[] = {
	{ .blen = 16,	.plen = 16, },
	{ .blen = 64,	.plen = 16, },
	{ .blen = 64,	.plen = 64, },
	{ .blen = 256,	.plen = 16, },
	{ .blen = 256,	.plen = 64, },
	{ .blen = 256,	.plen = 256, },
	{ .blen = 1024,	.plen = 16, },
	{ .blen = 1024,	.plen = 256, },
	{ .blen = 1024,	.plen = 1024, },
	{ .blen = 2048,	.plen = 16, },
	{ .blen = 2048,	.plen = 256, },
	{ .blen = 2048,	.plen = 1024, },
	{ .blen = 2048,	.plen = 2048, },
	{ .blen = 4096,	.plen = 16, },
	{ .blen = 4096,	.plen = 256, },
	{ .blen = 4096,	.plen = 1024, },
	{ .blen = 4096,	.plen = 4096, },
	{ .blen = 8192,	.plen = 16, },
	{ .blen = 8192,	.plen = 256, },
	{ .blen = 8192,	.plen = 1024, },
	{ .blen = 8192,	.plen = 4096, },
	{ .blen = 8192,	.plen = 8192, },

	/* End marker */
	{  .blen = 0,	.plen = 0, }
};

static struct hash_speed hash_speed_template_16[] = {
	{ .blen = 16,	.plen = 16,	.klen = 16, },
	{ .blen = 64,	.plen = 16,	.klen = 16, },
	{ .blen = 64,	.plen = 64,	.klen = 16, },
	{ .blen = 256,	.plen = 16,	.klen = 16, },
	{ .blen = 256,	.plen = 64,	.klen = 16, },
	{ .blen = 256,	.plen = 256,	.klen = 16, },
	{ .blen = 1024,	.plen = 16,	.klen = 16, },
	{ .blen = 1024,	.plen = 256,	.klen = 16, },
	{ .blen = 1024,	.plen = 1024,	.klen = 16, },
	{ .blen = 2048,	.plen = 16,	.klen = 16, },
	{ .blen = 2048,	.plen = 256,	.klen = 16, },
	{ .blen = 2048,	.plen = 1024,	.klen = 16, },
	{ .blen = 2048,	.plen = 2048,	.klen = 16, },
	{ .blen = 4096,	.plen = 16,	.klen = 16, },
	{ .blen = 4096,	.plen = 256,	.klen = 16, },
	{ .blen = 4096,	.plen = 1024,	.klen = 16, },
	{ .blen = 4096,	.plen = 4096,	.klen = 16, },
	{ .blen = 8192,	.plen = 16,	.klen = 16, },
	{ .blen = 8192,	.plen = 256,	.klen = 16, },
	{ .blen = 8192,	.plen = 1024,	.klen = 16, },
	{ .blen = 8192,	.plen = 4096,	.klen = 16, },
	{ .blen = 8192,	.plen = 8192,	.klen = 16, },

	/* End marker */
	{  .blen = 0,	.plen = 0,	.klen = 0, }
};

static struct hash_speed poly1305_speed_template[] = {
	{ .blen = 96,	.plen = 16, },
	{ .blen = 96,	.plen = 32, },
	{ .blen = 96,	.plen = 96, },
	{ .blen = 288,	.plen = 16, },
	{ .blen = 288,	.plen = 32, },
	{ .blen = 288,	.plen = 288, },
	{ .blen = 1056,	.plen = 32, },
	{ .blen = 1056,	.plen = 1056, },
	{ .blen = 2080,	.plen = 32, },
	{ .blen = 2080,	.plen = 2080, },
	{ .blen = 4128,	.plen = 4128, },
	{ .blen = 8224,	.plen = 8224, },

	/* End marker */
	{  .blen = 0,	.plen = 0, }
};

#endif	/* _CRYPTO_TCRYPT_H */
