/*
 * This header provides constants for binding nvidia,swgroup ID
 *
 * Copyright (c) 2014-2017, NVIDIA CORPORATION, All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _DT_BINDINGS_MEMORY_TEGRA_SWGROUP_H
#define _DT_BINDINGS_MEMORY_TEGRA_SWGROUP_H

#define TEGRA_SWGROUP_INVALID	0xff	/* 0x238 */
#define TEGRA_SWGROUP_AFI	0	/* 0x238 */
#define TEGRA_SWGROUP_AVPC	1	/* 0x23c */
#define TEGRA_SWGROUP_DC	2	/* 0x240 */
#define TEGRA_SWGROUP_DCB	3	/* 0x244 */
#define TEGRA_SWGROUP_EPP	4	/* 0x248 */
#define TEGRA_SWGROUP_G2	5	/* 0x24c */
#define TEGRA_SWGROUP_HC	6	/* 0x250 */
#define TEGRA_SWGROUP_HDA	7	/* 0x254 */
#define TEGRA_SWGROUP_ISP	8	/* 0x258 */
#define TEGRA_SWGROUP_ISP2	8
#define TEGRA_SWGROUP_DC14	9	/* 0x490 *//* Exceptional non-linear */
#define TEGRA_SWGROUP_DC12	10	/* 0xa88 *//* Exceptional non-linear */
#define TEGRA_SWGROUP_MPE	11	/* 0x264 */
#define TEGRA_SWGROUP_MSENC	11
#define TEGRA_SWGROUP_NVENC	11
#define TEGRA_SWGROUP_NV	12	/* 0x268 */
#define TEGRA_SWGROUP_NV2	13	/* 0x26c */
#define TEGRA_SWGROUP_PPCS	14	/* 0x270 */
#define TEGRA_SWGROUP_SATA2	15	/* 0x274 */
#define TEGRA_SWGROUP_SATA	16	/* 0x278 */
#define TEGRA_SWGROUP_VDE	17	/* 0x27c */
#define TEGRA_SWGROUP_VI	18	/* 0x280 */
#define TEGRA_SWGROUP_VII2C	18	/* 0x280 */
#define TEGRA_SWGROUP_VIC	19	/* 0x284 */
#define TEGRA_SWGROUP_XUSB_HOST	20	/* 0x288 */
#define TEGRA_SWGROUP_XUSB_DEV	21	/* 0x28c */
#define TEGRA_SWGROUP_A9AVP	22	/* 0x290 */
#define TEGRA_SWGROUP_TSEC	23	/* 0x294 */
#define TEGRA_SWGROUP_PPCS1	24	/* 0x298 */
#define TEGRA_SWGROUP_SDMMC1A	25	/* 0xa94 *//* Linear shift again */
#define TEGRA_SWGROUP_SDMMC2A	26	/* 0xa98 */
#define TEGRA_SWGROUP_SDMMC3A	27	/* 0xa9c */
#define TEGRA_SWGROUP_SDMMC4A	28	/* 0xaa0 */
#define TEGRA_SWGROUP_ISP2B	29	/* 0xaa4 */
#define TEGRA_SWGROUP_GPU	30	/* 0xaa8, DO NOT USE THIS */
#define TEGRA_SWGROUP_GPUB	31	/* 0xaac */
#define TEGRA_SWGROUP_PPCS2	32	/* 0xab0 */
#define TEGRA_SWGROUP_NVDEC	33	/* 0xab4 */
#define TEGRA_SWGROUP_APE	34	/* 0xab8 */
#define TEGRA_SWGROUP_SE	35	/* 0xabc */
#define TEGRA_SWGROUP_NVJPG	36	/* 0xac0 */
#define TEGRA_SWGROUP_HC1	37	/* 0xac4 */
#define TEGRA_SWGROUP_SE1	38	/* 0xac8 */
#define TEGRA_SWGROUP_AXIAP	39	/* 0xacc */
#define TEGRA_SWGROUP_ETR	40	/* 0xad0 */
#define TEGRA_SWGROUP_TSECB	41	/* 0xad4 */
#define TEGRA_SWGROUP_TSEC1	42	/* 0xad8 */
#define TEGRA_SWGROUP_TSECB1	43	/* 0xadc */
#define TEGRA_SWGROUP_NVDEC1	44	/* 0xae0 */
/*	Reserved		45 */
#define TEGRA_SWGROUP_AXIS	46	/* 0xae8 */
#define TEGRA_SWGROUP_EQOS	47	/* 0xaec */
#define TEGRA_SWGROUP_UFSHC	48	/* 0xaf0 */
#define TEGRA_SWGROUP_NVDISPLAY	49	/* 0xaf4 */
#define TEGRA_SWGROUP_BPMP	50	/* 0xaf8 */
#define TEGRA_SWGROUP_AON	51	/* 0xafc */
#define TEGRA_SWGROUP_SMMU_TEST	52
/*	Reserved		50 */

#define TWO_U32_OF_U64(x)	((x) & 0xffffffff) ((x) >> 32)
#define TEGRA_SWGROUP_BIT(x)	(1ULL << TEGRA_SWGROUP_##x)
#define TEGRA_SWGROUP_CELLS(x)	TWO_U32_OF_U64(TEGRA_SWGROUP_BIT(x))

#define TEGRA_SWGROUP_CELLS2(x1, x2)	 \
				TWO_U32_OF_U64( TEGRA_SWGROUP_BIT(x1) | \
						TEGRA_SWGROUP_BIT(x2))
#define TEGRA_SWGROUP_CELLS3(x1, x2, x3)	 \
				TWO_U32_OF_U64( TEGRA_SWGROUP_BIT(x1) | \
						TEGRA_SWGROUP_BIT(x2) | \
						TEGRA_SWGROUP_BIT(x3))
#define TEGRA_SWGROUP_CELLS4(x1, x2, x3, x4)	 \
				TWO_U32_OF_U64( TEGRA_SWGROUP_BIT(x1) | \
						TEGRA_SWGROUP_BIT(x2) | \
						TEGRA_SWGROUP_BIT(x3) | \
						TEGRA_SWGROUP_BIT(x4))
#define TEGRA_SWGROUP_CELLS5(x1, x2, x3, x4, x5)	\
				TWO_U32_OF_U64( TEGRA_SWGROUP_BIT(x1) | \
						TEGRA_SWGROUP_BIT(x2) | \
						TEGRA_SWGROUP_BIT(x3) | \
						TEGRA_SWGROUP_BIT(x4) | \
						TEGRA_SWGROUP_BIT(x5))
#define TEGRA_SWGROUP_CELLS9(x1, x2, x3, x4, x5, x6, x7, x8, x9) \
				TWO_U32_OF_U64( TEGRA_SWGROUP_BIT(x1) | \
						TEGRA_SWGROUP_BIT(x2) | \
						TEGRA_SWGROUP_BIT(x3) | \
						TEGRA_SWGROUP_BIT(x4) | \
						TEGRA_SWGROUP_BIT(x5) | \
						TEGRA_SWGROUP_BIT(x6) | \
						TEGRA_SWGROUP_BIT(x7) | \
						TEGRA_SWGROUP_BIT(x8) | \
						TEGRA_SWGROUP_BIT(x9))
#define TEGRA_SWGROUP_CELLS12(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12) \
				TWO_U32_OF_U64( TEGRA_SWGROUP_BIT(x1) | \
						TEGRA_SWGROUP_BIT(x2) | \
						TEGRA_SWGROUP_BIT(x3) | \
						TEGRA_SWGROUP_BIT(x4) | \
						TEGRA_SWGROUP_BIT(x5) | \
						TEGRA_SWGROUP_BIT(x6) | \
						TEGRA_SWGROUP_BIT(x7) | \
						TEGRA_SWGROUP_BIT(x8) | \
						TEGRA_SWGROUP_BIT(x9) | \
						TEGRA_SWGROUP_BIT(x10)| \
						TEGRA_SWGROUP_BIT(x11)| \
						TEGRA_SWGROUP_BIT(x12))
#define TEGRA_SWGROUP_MAX	64

#define SWGIDS_ERROR_CODE	(~0ULL)
#define swgids_is_error(x)	((x) == SWGIDS_ERROR_CODE)

/*
 * The above definitions are for the older tegra chips using the Tegra SMMU. For
 * tegra chips using the ARM SMMU the following is used. The notion of bit maps
 * is removed since they are not very scalable.
 */

/* Host clients. */
#define TEGRA_SID_HC		0x1	/* 1 */
#define TEGRA_SID_VIC		0x3	/* 3 */
#define TEGRA_SID_VI		0x4	/* 4 */
#define TEGRA_SID_ISP		0x5	/* 5 */
#define TEGRA_SID_NVDEC		0x6	/* 6 */
#define TEGRA_SID_NVENC		0x7	/* 7 */
#define TEGRA_SID_NVJPG		0x8	/* 8 */
#define TEGRA_SID_NVDISPLAY	0x9	/* 9 */
#define TEGRA_SID_TSEC		0xa	/* 10 */
#define TEGRA_SID_TSECB		0xb	/* 11 */
#define TEGRA_SID_SE		0xc	/* 12 */
#define TEGRA_SID_SE1		0xd	/* 13 */

/* GPU clients. */
#define TEGRA_SID_GPUB		0x10	/* 16 */

/* Other SoC clients */
#define TEGRA_SID_AFI		0x11	/* 17 */
#define TEGRA_SID_HDA		0x12	/* 18 */
#define TEGRA_SID_ETR		0x13	/* 19 */
#define TEGRA_SID_EQOS		0x14	/* 20 */
#define TEGRA_SID_UFSHC		0x15	/* 21 */
#define TEGRA_SID_AON		0x16	/* 22 */
#define TEGRA_SID_SDMMC4A	0x17	/* 23 */
#define TEGRA_SID_SDMMC3A	0x18	/* 24 */
#define TEGRA_SID_SDMMC2A	0x19	/* 25 */
#define TEGRA_SID_SDMMC1A	0x1a	/* 26 */
#define TEGRA_SID_XUSB_HOST	0x1b	/* 27 */
#define TEGRA_SID_XUSB_DEV	0x1c	/* 28 */
#define TEGRA_SID_SATA2		0x1d	/* 29 */
#define TEGRA_SID_APE		0x1e	/* 30 */

/*
 * The BPMP has hard coded their SID value in their FW which is not built
 * in the normal Linux tree. As a result, changing the SID requires a
 * considerable amount of work.
 */
#define TEGRA_SID_BPMP		0x32	/* 50 */

/* For smmu tests */
#define TEGRA_SID_SMMU_TEST	0x33	/* 51 */

/*
 * This is the t18x specific component of the new SID dt-binding.
 */
#define TEGRA_SID_NVCSI		0x2	/* 2 */
#define TEGRA_SID_SE2		0xe	/* 14 */
#define TEGRA_SID_SE3		0xf	/* 15 */
#define TEGRA_SID_SCE		0x1f	/* 31 */

/* The GPC DMA clients. */
#define TEGRA_SID_GPCDMA_0	0x20	/* 32 */
#define TEGRA_SID_GPCDMA_1	0x21	/* 33 */
#define TEGRA_SID_GPCDMA_2	0x22	/* 34 */
#define TEGRA_SID_GPCDMA_3	0x23	/* 35 */
#define TEGRA_SID_GPCDMA_4	0x24	/* 36 */
#define TEGRA_SID_GPCDMA_5	0x25	/* 37 */
#define TEGRA_SID_GPCDMA_6	0x26	/* 38 */
#define TEGRA_SID_GPCDMA_7	0x27	/* 39 */

/* The APE DMA Clients. */
#define TEGRA_SID_APE_1		0x28	/* 40 */
#define TEGRA_SID_APE_2		0x29	/* 41 */

/* The Camera RTCPU running on SCE. */
#define TEGRA_SID_SCE_CAM	0x2a	/* 42 */
#define TEGRA_SID_SCE_CAM_1X	0x2b	/* 43 */

/* The APE DMA Clients. */
#define TEGRA_SID_APE_3		0x2c	/* 44 */

/* The Camera RTCPU running on APE */
#define TEGRA_SID_APE_CAM	0x2d	/* 45 */
#define TEGRA_SID_APE_CAM_1X	0x2e	/* 46 */

/* Host1x virtualization clients. */
#define TEGRA_SID_HOST1X_CTX0	0x38	/* 56 */
#define TEGRA_SID_HOST1X_CTX1	0x39	/* 57 */
#define TEGRA_SID_HOST1X_CTX2	0x3a	/* 58 */
#define TEGRA_SID_HOST1X_CTX3	0x3b	/* 59 */
#define TEGRA_SID_HOST1X_CTX4	0x3c	/* 60 */
#define TEGRA_SID_HOST1X_CTX5	0x3d	/* 61 */
#define TEGRA_SID_HOST1X_CTX6	0x3e	/* 62 */
#define TEGRA_SID_HOST1X_CTX7	0x3f	/* 63 */

/* Host1x command buffers */
#define TEGRA_SID_HC_VM0	0x40
#define TEGRA_SID_HC_VM1	0x41
#define TEGRA_SID_HC_VM2	0x42
#define TEGRA_SID_HC_VM3	0x43
#define TEGRA_SID_HC_VM4	0x44
#define TEGRA_SID_HC_VM5	0x45
#define TEGRA_SID_HC_VM6	0x46
#define TEGRA_SID_HC_VM7	0x47

/* SE data buffers */
#define TEGRA_SID_SE_VM0	0x48
#define TEGRA_SID_SE_VM1	0x49
#define TEGRA_SID_SE_VM2	0x4a
#define TEGRA_SID_SE_VM3	0x4b
#define TEGRA_SID_SE_VM4	0x4c
#define TEGRA_SID_SE_VM5	0x4d
#define TEGRA_SID_SE_VM6	0x4e
#define TEGRA_SID_SE_VM7	0x4f

/* Special clients */
#define TEGRA_SID_PASSTHROUGH	0x7f
#define TEGRA_SID_INVALID	0x0

/*
 * These macros will be removed once the bitmap problem is sorted out. Until
 * then this is equivalent to TEGRA_SWGROUP_CELLS() only with TEGRA_SID_*
 * instead of TEGRA_SWGROUP_*.
 */
#define TEGRA_SID(x) 		(TEGRA_SID_ ## x)

#endif /* _DT_BINDINGS_MEMORY_TEGRA_SWGROUP_H */
