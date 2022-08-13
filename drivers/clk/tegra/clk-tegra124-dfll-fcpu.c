/*
 * Tegra124 DFLL FCPU clock source driver
 *
 * Copyright (C) 2012-2014 NVIDIA Corporation.  All rights reserved.
 *
 * Aleksandr Frid <afrid@nvidia.com>
 * Paul Walmsley <pwalmsley@nvidia.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <soc/tegra/cvb.h>
#include <soc/tegra/fuse.h>

#include <dt-bindings/thermal/tegra210-dfll-trips.h>
#include <dt-bindings/thermal/tegra210b01-trips.h>

#include "clk.h"
#include "clk-dfll.h"

struct dfll_fcpu_data {
	const unsigned long *cpu_max_freq_table;
	unsigned int cpu_max_freq_table_size;
	const struct cvb_table *cpu_cvb_tables;
	unsigned int cpu_cvb_tables_size;
	const struct thermal_table *cpu_thermal_table;
};

/* Maximum CPU frequency, indexed by CPU speedo id */
static const unsigned long tegra124_cpu_max_freq_table[] = {
	[0] = 2014500000UL,
	[1] = 2320500000UL,
	[2] = 2116500000UL,
	[3] = 2524500000UL,
};

static const struct cvb_table tegra124_cpu_cvb_tables[] = {
	{
		.speedo_id = -1,
		.process_id = -1,
		.min_millivolts = 900,
		.max_millivolts = 1260,
		.alignment = {
			.step_uv = 10000, /* 10mV */
		},
		.speedo_scale = 100,
		.voltage_scale = 1000,
		.entries = {
			{  204000000UL, { 1112619, -29295, 402 } },
			{  306000000UL, { 1150460, -30585, 402 } },
			{  408000000UL, { 1190122, -31865, 402 } },
			{  510000000UL, { 1231606, -33155, 402 } },
			{  612000000UL, { 1274912, -34435, 402 } },
			{  714000000UL, { 1320040, -35725, 402 } },
			{  816000000UL, { 1366990, -37005, 402 } },
			{  918000000UL, { 1415762, -38295, 402 } },
			{ 1020000000UL, { 1466355, -39575, 402 } },
			{ 1122000000UL, { 1518771, -40865, 402 } },
			{ 1224000000UL, { 1573009, -42145, 402 } },
			{ 1326000000UL, { 1629068, -43435, 402 } },
			{ 1428000000UL, { 1686950, -44715, 402 } },
			{ 1530000000UL, { 1746653, -46005, 402 } },
			{ 1632000000UL, { 1808179, -47285, 402 } },
			{ 1734000000UL, { 1871526, -48575, 402 } },
			{ 1836000000UL, { 1936696, -49855, 402 } },
			{ 1938000000UL, { 2003687, -51145, 402 } },
			{ 2014500000UL, { 2054787, -52095, 402 } },
			{ 2116500000UL, { 2124957, -53385, 402 } },
			{ 2218500000UL, { 2196950, -54665, 402 } },
			{ 2320500000UL, { 2270765, -55955, 402 } },
			{ 2422500000UL, { 2346401, -57235, 402 } },
			{ 2524500000UL, { 2437299, -58535, 402 } },
			{          0UL, {       0,      0,   0 } },
		},
		.cpu_dfll_data = {
			.tune0_low = 0x005020ff,
			.tune0_high = 0x005040ff,
			.tune1_low = 0x00000060,
		}
	},
};

static const unsigned long tegra210_cpu_max_freq_table[] = {
	[0] = 1912500000UL,
	[1] = 1912500000UL,
	[2] = 2218500000UL,
	[3] = 1785000000UL,
	[4] = 1632000000UL,
	[5] = 1912500000UL,
	[6] = 2014500000UL,
	[7] = 1734000000UL,
	[8] = 1683000000UL,
	[9] = 1555500000UL,
	[10] = 1504500000UL,
};

#define CPU_CVB_TABLE \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		{204000000UL,	{1007452, -23865, 370} }, \
		{306000000UL,	{1052709, -24875, 370} }, \
		{408000000UL,	{1099069, -25895, 370} }, \
		{510000000UL,	{1146534, -26905, 370} }, \
		{612000000UL,	{1195102, -27915, 370} }, \
		{714000000UL,	{1244773, -28925, 370} }, \
		{816000000UL,	{1295549, -29935, 370} }, \
		{918000000UL,	{1347428, -30955, 370} }, \
		{1020000000UL,	{1400411, -31965, 370} }, \
		{1122000000UL,	{1454497, -32975, 370} }, \
		{1224000000UL,	{1509687, -33985, 370} }, \
		{1326000000UL,	{1565981, -35005, 370} }, \
		{1428000000UL,	{1623379, -36015, 370} }, \
		{1530000000UL,	{1681880, -37025, 370} }, \
		{1632000000UL,	{1741485, -38035, 370} }, \
		{1734000000UL,	{1802194, -39055, 370} }, \
		{1836000000UL,	{1864006, -40065, 370} }, \
		{1912500000UL,	{1910780, -40815, 370} }, \
		{2014500000UL,	{1227000,      0,   0} }, \
		{2218500000UL,	{1227000,      0,   0} }, \
		{0,           	{      0,      0,   0} }, \
	}

#define CPU_CVB_TABLE_XA \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		{204000000UL,	{1250024, -39785, 565} }, \
		{306000000UL,	{1297556, -41145, 565} }, \
		{408000000UL,	{1346718, -42505, 565} }, \
		{510000000UL,	{1397511, -43855, 565} }, \
		{612000000UL,	{1449933, -45215, 565} }, \
		{714000000UL,	{1503986, -46575, 565} }, \
		{816000000UL,	{1559669, -47935, 565} }, \
		{918000000UL,	{1616982, -49295, 565} }, \
		{1020000000UL,	{1675926, -50645, 565} }, \
		{1122000000UL,	{1736500, -52005, 565} }, \
		{1224000000UL,	{1798704, -53365, 565} }, \
		{1326000000UL,	{1862538, -54725, 565} }, \
		{1428000000UL,	{1928003, -56085, 565} }, \
		{1530000000UL,	{1995097, -57435, 565} }, \
		{1606500000UL,	{2046149, -58445, 565} }, \
		{1632000000UL,	{2063822, -58795, 565} }, \
		{0,           	{      0,      0,   0} }, \
	}

#define CPU_CVB_TABLE_EUCM1 \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		{204000000UL,	{734429, 0, 0} }, \
		{306000000UL,	{768191, 0, 0} }, \
		{408000000UL,	{801953, 0, 0} }, \
		{510000000UL,	{835715, 0, 0} }, \
		{612000000UL,	{869477, 0, 0} }, \
		{714000000UL,	{903239, 0, 0} }, \
		{816000000UL,	{937001, 0, 0} }, \
		{918000000UL,	{970763, 0, 0} }, \
		{1020000000UL,	{1004525, 0, 0} }, \
		{1122000000UL,	{1038287, 0, 0} }, \
		{1224000000UL,	{1072049, 0, 0} }, \
		{1326000000UL,	{1105811, 0, 0} }, \
		{1428000000UL,	{1130000, 0, 0} }, \
		{1555500000UL,	{1130000, 0, 0} }, \
		{1632000000UL,	{1170000, 0, 0} }, \
		{1734000000UL,	{1227500, 0, 0} }, \
		{0,           	{      0, 0, 0} }, \
	}

#define CPU_CVB_TABLE_EUCM2 \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		{204000000UL,	{742283, 0, 0} }, \
		{306000000UL,	{776249, 0, 0} }, \
		{408000000UL,	{810215, 0, 0} }, \
		{510000000UL,	{844181, 0, 0} }, \
		{612000000UL,	{878147, 0, 0} }, \
		{714000000UL,	{912113, 0, 0} }, \
		{816000000UL,	{946079, 0, 0} }, \
		{918000000UL,	{980045, 0, 0} }, \
		{1020000000UL,	{1014011, 0, 0} }, \
		{1122000000UL,	{1047977, 0, 0} }, \
		{1224000000UL,	{1081943, 0, 0} }, \
		{1326000000UL,	{1090000, 0, 0} }, \
		{1479000000UL,	{1090000, 0, 0} }, \
		{1555500000UL,	{1162000, 0, 0} }, \
		{1683000000UL,	{1195000, 0, 0} }, \
		{0,           	{      0, 0, 0} }, \
	}

#define CPU_CVB_TABLE_EUCM2_JOINT_RAIL \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		{204000000UL,	{742283, 0, 0} }, \
		{306000000UL,	{776249, 0, 0} }, \
		{408000000UL,	{810215, 0, 0} }, \
		{510000000UL,	{844181, 0, 0} }, \
		{612000000UL,	{878147, 0, 0} }, \
		{714000000UL,	{912113, 0, 0} }, \
		{816000000UL,	{946079, 0, 0} }, \
		{918000000UL,	{980045, 0, 0} }, \
		{1020000000UL,	{1014011, 0, 0} }, \
		{1122000000UL,	{1047977, 0, 0} }, \
		{1224000000UL,	{1081943, 0, 0} }, \
		{1326000000UL,	{1090000, 0, 0} }, \
		{1479000000UL,	{1090000, 0, 0} }, \
		{1504500000UL,	{1120000, 0, 0} }, \
		{0,           	{      0, 0, 0} }, \
	}

#define CPU_CVB_TABLE_ODN \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		{204000000UL,	{721094, 0, 0} }, \
		{306000000UL,	{754040, 0, 0} }, \
		{408000000UL,	{786986, 0, 0} }, \
		{510000000UL,	{819932, 0, 0} }, \
		{612000000UL,	{852878, 0, 0} }, \
		{714000000UL,	{885824, 0, 0} }, \
		{816000000UL,	{918770, 0, 0} }, \
		{918000000UL,	{915716, 0, 0} }, \
		{1020000000UL,	{984662, 0, 0} }, \
		{1122000000UL,	{1017608, 0, 0} }, \
		{1224000000UL,	{1050554, 0, 0} }, \
		{1326000000UL,	{1083500, 0, 0} }, \
		{1428000000UL,	{1116446, 0, 0} }, \
		{1581000000UL,	{1130000, 0, 0} }, \
		{1683000000UL,	{1168000, 0, 0} }, \
		{1785000000UL,	{1227500, 0, 0} }, \
		{0,           	{      0, 0, 0} }, \
	}

struct cvb_table tegra210_cpu_cvb_tables[] = {
	{
		.speedo_id = 10,
		.process_id = 0,
		.min_millivolts = 840,
		.max_millivolts = 1120,
		CPU_CVB_TABLE_EUCM2_JOINT_RAIL,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 10,
		.process_id = 1,
		.min_millivolts = 840,
		.max_millivolts = 1120,
		CPU_CVB_TABLE_EUCM2_JOINT_RAIL,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 9,
		.process_id = 0,
		.min_millivolts = 900,
		.max_millivolts = 1162,
		CPU_CVB_TABLE_EUCM2,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
		}
	},
	{
		.speedo_id = 9,
		.process_id = 1,
		.min_millivolts = 900,
		.max_millivolts = 1162,
		CPU_CVB_TABLE_EUCM2,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
		}
	},
	{
		.speedo_id = 8,
		.process_id = 0,
		.min_millivolts = 900,
		.max_millivolts = 1195,
		CPU_CVB_TABLE_EUCM2,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
		}
	},
	{
		.speedo_id = 8,
		.process_id = 1,
		.min_millivolts = 900,
		.max_millivolts = 1195,
		CPU_CVB_TABLE_EUCM2,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
		}
	},
	{
		.speedo_id = 7,
		.process_id = 0,
		.min_millivolts = 841,
		.max_millivolts = 1227,
		CPU_CVB_TABLE_EUCM1,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 7,
		.process_id = 1,
		.min_millivolts = 841,
		.max_millivolts = 1227,
		CPU_CVB_TABLE_EUCM1,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 6,
		.process_id = 0,
		.min_millivolts = 870,
		.max_millivolts = 1150,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune1_low = 0x20091d9,
		}
	},
	{
		.speedo_id = 6,
		.process_id = 1,
		.min_millivolts = 870,
		.max_millivolts = 1150,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune1_low = 0x25501d0,
		}
	},
	{
		.speedo_id = 5,
		.process_id = 0,
		.min_millivolts = 818,
		.max_millivolts = 1227,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 5,
		.process_id = 1,
		.min_millivolts = 818,
		.max_millivolts = 1227,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x25501d0,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 4,
		.process_id = -1,
		.min_millivolts = 918,
		.max_millivolts = 1113,
		CPU_CVB_TABLE_XA,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune1_low = 0x17711BD,
		}
	},
	{
		.speedo_id = 3,
		.process_id = 0,
		.min_millivolts = 825,
		.max_millivolts = 1227,
		CPU_CVB_TABLE_ODN,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 3,
		.process_id = 1,
		.min_millivolts = 825,
		.max_millivolts = 1227,
		CPU_CVB_TABLE_ODN,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x25501d0,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 2,
		.process_id = 0,
		.min_millivolts = 870,
		.max_millivolts = 1227,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune1_low = 0x20091d9,
		}
	},
	{
		.speedo_id = 2,
		.process_id = 1,
		.min_millivolts = 870,
		.max_millivolts = 1227,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune1_low = 0x25501d0,
		}
	},
	{
		.speedo_id = 1,
		.process_id = 0,
		.min_millivolts = 837,
		.max_millivolts = 1227,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 1,
		.process_id = 1,
		.min_millivolts = 837,
		.max_millivolts = 1227,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x25501d0,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 0,
		.process_id = 0,
		.min_millivolts = 850,
		.max_millivolts = 1170,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x20091d9,
			.tune_high_min_millivolts = 864,
		}
	},
	{
		.speedo_id = 0,
		.process_id = 1,
		.min_millivolts = 850,
		.max_millivolts = 1170,
		CPU_CVB_TABLE,
		.cpu_dfll_data = {
			.tune0_low = 0xffead0ff,
			.tune0_high = 0xffead0ff,
			.tune1_low = 0x25501d0,
			.tune_high_min_millivolts = 864,
		}
	},
};

static const unsigned long tegra210b01_cpu_max_freq_table[] = {
	[0] = 1963500000UL,
	[1] = 1963500000UL,
	[2] = 2091000000UL,
	[3] = 2014500000UL,
};

#define CPUB01_CVB_TABLE_SLT_B1 \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		/* f	                c0,       c1,       c2 */   \
		{  204000000UL, {   732856,   -17335,      113 } }, \
		{  306000000UL, {   760024,   -18195,      113 } }, \
		{  408000000UL, {   789258,   -19055,      113 } }, \
		{  510000000UL, {   820558,   -19915,      113 } }, \
		{  612000000UL, {   853926,   -20775,      113 } }, \
		{  714000000UL, {   889361,   -21625,      113 } }, \
		{  816000000UL, {   926862,   -22485,      113 } }, \
		{  918000000UL, {   966431,   -23345,      113 } }, \
		{ 1020000000UL, {  1008066,   -24205,      113 } }, \
		{ 1122000000UL, {  1051768,   -25065,      113 } }, \
		{ 1224000000UL, {  1097537,   -25925,      113 } }, \
		{ 1326000000UL, {  1145373,   -26785,      113 } }, \
		{ 1428000000UL, {  1195276,   -27645,      113 } }, \
		{ 1581000000UL, {  1274006,   -28935,      113 } }, \
		{ 1683000000UL, {  1329076,   -29795,      113 } }, \
		{ 1785000000UL, {  1386213,   -30655,      113 } }, \
		{ 1887000000UL, {  1445416,   -31515,      113 } }, \
		{ 1963500000UL, {  1490873,   -32155,      113 } }, \
		{ 2065500000UL, {  1553683,   -33015,      113 } }, \
		{ 2091000000UL, {  1580725,   -33235,      113 } }, \
		{ 0,	        { } }, \
	}, \
	.vmin_coefficients =	{   600000,        0,        0 }, \
	.cpu_dfll_data = {					  \
		.tune0_low  = 0x0000FFA0,			  \
		.tune0_high = 0x0000FFFF,			  \
		.tune1_low  = 0x21107FF,			  \
		.tune_high_min_millivolts = 850,		  \
		.tune_high_margin_millivolts = 38,		  \
		.dvco_calibration_max = ULONG_MAX,		  \
	}, \
	.cvb_version = "FCPU Table - p4v3-AggressiveSLT"

#define CPUB01_CVB_TABLE_SLT_B0 \
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		/* f	                c0,       c1,       c2 */   \
		{  204000000UL, {   732856,   -17335,      113 } }, \
		{  306000000UL, {   760024,   -18195,      113 } }, \
		{  408000000UL, {   789258,   -19055,      113 } }, \
		{  510000000UL, {   820558,   -19915,      113 } }, \
		{  612000000UL, {   853926,   -20775,      113 } }, \
		{  714000000UL, {   889361,   -21625,      113 } }, \
		{  816000000UL, {   926862,   -22485,      113 } }, \
		{  918000000UL, {   966431,   -23345,      113 } }, \
		{ 1020000000UL, {  1008066,   -24205,      113 } }, \
		{ 1122000000UL, {  1051768,   -25065,      113 } }, \
		{ 1224000000UL, {  1097537,   -25925,      113 } }, \
		{ 1326000000UL, {  1145373,   -26785,      113 } }, \
		{ 1428000000UL, {  1195276,   -27645,      113 } }, \
		{ 1581000000UL, {  1274006,   -28935,      113 } }, \
		{ 1683000000UL, {  1329076,   -29795,      113 } }, \
		{ 1785000000UL, {  1386213,   -30655,      113 } }, \
		{ 1887000000UL, {  1445416,   -31515,      113 } }, \
		{ 1963500000UL, {  1490873,   -32155,      113 } }, \
		{ 2065500000UL, {  1553683,   -33015,      113 } }, \
		{ 2091000000UL, {  1580725,   -33235,      113 } }, \
		{ 0,	        { } }, \
	}, \
	.vmin_coefficients =	{   600000,        0,        0 }, \
	.cpu_dfll_data = {					  \
		.tune0_low  = 0x0000FF90,			  \
		.tune0_high = 0x0000FFFF,			  \
		.tune1_low  = 0x21107FF,			  \
		.tune_high_min_millivolts = 850,		  \
		.tune_high_margin_millivolts = 38,		  \
		.dvco_calibration_max = ULONG_MAX,		  \
	}, \
	.cvb_version = "FCPU Table - p4v3-AggressiveSLT"

#define CPUB01_CVB_TABLE	\
	.speedo_scale = 100,	\
	.voltage_scale = 1000,	\
	.entries = {		\
		/* f	                c0,       c1,       c2 */   \
		{  204000000UL, {   721589,   -12695,       27 } }, \
		{  306000000UL, {   747134,   -14195,       27 } }, \
		{  408000000UL, {   776324,   -15705,       27 } }, \
		{  510000000UL, {   809160,   -17205,       27 } }, \
		{  612000000UL, {   845641,   -18715,       27 } }, \
		{  714000000UL, {   885768,   -20215,       27 } }, \
		{  816000000UL, {   929540,   -21725,       27 } }, \
		{  918000000UL, {   976958,   -23225,       27 } }, \
		{ 1020000000UL, {  1028021,   -24725,       27 } }, \
		{ 1122000000UL, {  1082730,   -26235,       27 } }, \
		{ 1224000000UL, {  1141084,   -27735,       27 } }, \
		{ 1326000000UL, {  1203084,   -29245,       27 } }, \
		{ 1428000000UL, {  1268729,   -30745,       27 } }, \
		{ 1581000000UL, {  1374032,   -33005,       27 } }, \
		{ 1683000000UL, {  1448791,   -34505,       27 } }, \
		{ 1785000000UL, {  1527196,   -36015,       27 } }, \
		{ 1887000000UL, {  1609246,   -37515,       27 } }, \
		{ 1963500000UL, {  1675751,   -38635,       27 } }, \
		{ 2014500000UL, {  1716501,   -39395,       27 } }, \
		{ 0,	        { } }, \
	}, \
	.vmin_coefficients =	{   620000,        0,        0 }, \
	.cpu_dfll_data = {					  \
		.tune0_low  = 0x0000FFCF,			  \
		.tune1_low  = 0x012207FF,			  \
		.tune1_high = 0x03FFF7FF,			  \
		.tune_high_min_millivolts = 850,		  \
		.tune_high_margin_millivolts = 38,		  \
		.dvco_calibration_max = ULONG_MAX,		  \
	}, \
	.cvb_version = "FCPU Table - p4v3"

struct cvb_table tegra210b01_cpu_cvb_tables[] = {
	{
		.speedo_id = 3,
		.process_id = -1,
		.max_millivolts = 1120,
		CPUB01_CVB_TABLE,
	},
	{
		.speedo_id = 2,
		.process_id = 1,
		.max_millivolts = 1120,
		CPUB01_CVB_TABLE_SLT_B1,
	},
	{
		.speedo_id = 2,
		.process_id = 0,
		.max_millivolts = 1120,
		CPUB01_CVB_TABLE_SLT_B0,
	},
	{
		.speedo_id = -1,
		.process_id = -1,
		.max_millivolts = 1120,
		CPUB01_CVB_TABLE,
	},
};

static struct thermal_tv tegra210_thermal_floor_table[] = {
	{TEGRA210_DFLL_THERMAL_FLOOR_0 / 1000, 950},
	{DFLL_THERMAL_FLOOR_NOFLOOR / 1000,    0},
};

static const struct thermal_tv tegra210_thermal_cap_table[] = {
	{DFLL_THERMAL_CAP_NOCAP / 1000,      INT_MAX},
	{TEGRA210_DFLL_THERMAL_CAP_0 / 1000, 1170},
	{TEGRA210_DFLL_THERMAL_CAP_1 / 1000, 1132},
};

static const struct thermal_tv tegra210_thermal_cap_ucm2_table[] = {
	{DFLL_THERMAL_CAP_NOCAP / 1000,      INT_MAX},
	{TEGRA210_DFLL_THERMAL_CAP_0 / 1000, 1162},
	{TEGRA210_DFLL_THERMAL_CAP_1 / 1000, 1090},
};

static const struct thermal_table tegra210_cpu_thermal_table = {
	.thermal_floor_table = tegra210_thermal_floor_table,
	.thermal_floor_table_size = ARRAY_SIZE(tegra210_thermal_floor_table),
	.coefficients = { {800000, 0, 0}, 0, 0, 0 },
	.speedo_scale = 100,
	.voltage_scale = 1000,
	.temp_scale = 10,
	.thermal_cap_table = tegra210_thermal_cap_table,
	.thermal_cap_table_size = ARRAY_SIZE(tegra210_thermal_cap_table),
	.thermal_cap_ucm2_table = tegra210_thermal_cap_ucm2_table,
	.thermal_cap_ucm2_table_size = ARRAY_SIZE(tegra210_thermal_cap_ucm2_table),
};

static struct thermal_tv tegra210b01_thermal_floor_table[] = {
	{TEGRA210B01_DFLL_THERMAL_FLOOR_0 / 1000, 800},
	{TEGRA210B01_DFLL_THERMAL_FLOOR_1 / 1000, 0},
	{DFLL_THERMAL_FLOOR_NOFLOOR / 1000,       0},
};

static const struct thermal_tv tegra210b01_thermal_cap_table[] = {
	{DFLL_THERMAL_CAP_NOCAP / 1000,         INT_MAX},
	{TEGRA210B01_DFLL_THERMAL_CAP_0 / 1000, 1060},
	{TEGRA210B01_DFLL_THERMAL_CAP_1 / 1000, 1010},
};

static const struct thermal_table tegra210b01_cpu_thermal_table = {
	.thermal_floor_table = tegra210b01_thermal_floor_table,
	.thermal_floor_table_size = ARRAY_SIZE(tegra210b01_thermal_floor_table),
	.speedo_scale = 100,
	.voltage_scale = 1000,
	.temp_scale = 10,
	.thermal_cap_table = tegra210b01_thermal_cap_table,
	.thermal_cap_table_size = ARRAY_SIZE(tegra210b01_thermal_cap_table),
	.thermal_cap_ucm2_table =  tegra210b01_thermal_cap_table,
	.thermal_cap_ucm2_table_size = ARRAY_SIZE(tegra210b01_thermal_cap_table)
};

static const struct dfll_fcpu_data tegra124_dfll_fcpu_data = {
	.cpu_max_freq_table = tegra124_cpu_max_freq_table,
	.cpu_max_freq_table_size = ARRAY_SIZE(tegra124_cpu_max_freq_table),
	.cpu_cvb_tables = tegra124_cpu_cvb_tables,
	.cpu_cvb_tables_size = ARRAY_SIZE(tegra124_cpu_cvb_tables)
};

static const struct dfll_fcpu_data tegra210_dfll_fcpu_data = {
	.cpu_max_freq_table = tegra210_cpu_max_freq_table,
	.cpu_max_freq_table_size = ARRAY_SIZE(tegra210_cpu_max_freq_table),
	.cpu_cvb_tables = tegra210_cpu_cvb_tables,
	.cpu_cvb_tables_size = ARRAY_SIZE(tegra210_cpu_cvb_tables),
	.cpu_thermal_table = &tegra210_cpu_thermal_table
};

static const struct dfll_fcpu_data tegra210b01_dfll_fcpu_data = {
	.cpu_max_freq_table = tegra210b01_cpu_max_freq_table,
	.cpu_max_freq_table_size = ARRAY_SIZE(tegra210b01_cpu_max_freq_table),
	.cpu_cvb_tables = tegra210b01_cpu_cvb_tables,
	.cpu_cvb_tables_size = ARRAY_SIZE(tegra210b01_cpu_cvb_tables),
	.cpu_thermal_table = &tegra210b01_cpu_thermal_table
};

static const struct of_device_id tegra124_dfll_fcpu_of_match[] = {
	{
		.compatible = "nvidia,tegra124-dfll",
		.data = &tegra124_dfll_fcpu_data,
	},
        {
		.compatible = "nvidia,tegra210-dfll",
		.data = &tegra210_dfll_fcpu_data
	},
	{
		.compatible = "nvidia,tegra210b01-dfll",
		.data = &tegra210b01_dfll_fcpu_data
	},
	{ },
};

static void get_alignment_from_dt(struct device *dev,
				  struct rail_alignment *align)
{
	align->step_uv = 0;
	align->offset_uv = 0;

	if (of_property_read_u32(dev->of_node, "nvidia,align-step-uv",
				  &align->step_uv))
		align->step_uv = 0;

	if (of_property_read_u32(dev->of_node,
				"nvidia,align-offset-uv", &align->offset_uv))
		align->offset_uv = 0;
}

static int get_alignment_from_regulator(struct device *dev,
					 struct rail_alignment *align)
{
	int min_uV, max_uV, n_voltages, ret;
	struct regulator *reg = devm_regulator_get(dev, "vdd-cpu");

	if (IS_ERR(reg))
		return PTR_ERR(reg);

	ret = regulator_get_constraint_voltages(reg, &min_uV, &max_uV);
	if (!ret)
		align->offset_uv = min_uV;

	align->step_uv = regulator_get_linear_step(reg);
	if (!align->step_uv && !ret) {
		n_voltages = regulator_count_voltages(reg);
		if (n_voltages > 1)
			align->step_uv = (max_uV - min_uV) / (n_voltages - 1);
	}
	devm_regulator_put(reg);

	return 0;
}

#define INIT_TUNE_PRAM(p) \
do {								\
	if (of_property_read_u32(pdev->dev.of_node,		\
			"nvidia,dfll-override-" #p, &soc->p))	\
		soc->p = soc->cvb->cpu_dfll_data.p;		\
} while (0)

static int tegra124_dfll_fcpu_probe(struct platform_device *pdev)
{
	int process_id, speedo_id, speedo_value, err;
	struct tegra_dfll_soc_data *soc;
	const struct of_device_id *of_id;
	const struct dfll_fcpu_data *fcpu_data;
	struct rail_alignment align;
	const struct thermal_table *thermal;
	unsigned long max_freq;
	u32 f;
	bool ucm2;

	of_id = of_match_device(tegra124_dfll_fcpu_of_match, &pdev->dev);
	fcpu_data = of_id->data;

	ucm2 = tegra_sku_info.ucm == TEGRA_UCM2;
	process_id = tegra_sku_info.cpu_process_id;
	speedo_id = tegra_sku_info.cpu_speedo_id;
	speedo_value = tegra_sku_info.cpu_speedo_value;

	if (speedo_id >= fcpu_data->cpu_max_freq_table_size) {
		dev_err(&pdev->dev, "unknown max CPU freq for speedo_id=%d\n",
			speedo_id);
		return -ENODEV;
	}
	max_freq = fcpu_data->cpu_max_freq_table[speedo_id];
	if (!of_property_read_u32(pdev->dev.of_node, "nvidia,dfll-max-freq-khz",
				  &f))
		max_freq = min(max_freq, f * 1000UL);

	soc = devm_kzalloc(&pdev->dev, sizeof(*soc), GFP_KERNEL);
	if (!soc)
		return -ENOMEM;

	soc->dev = get_cpu_device(0);
	if (!soc->dev) {
		dev_err(&pdev->dev, "no CPU0 device\n");
		return -ENODEV;
	}

	get_alignment_from_dt(&pdev->dev, &align);
	if (of_property_read_bool(pdev->dev.of_node, "nvidia,pwm-to-pmic")
		 && (!align.step_uv || !align.offset_uv)) {
		dev_info(&pdev->dev, "Missing required align data in DT");
		return -EINVAL;
	} else {
		if (!align.step_uv) {
			dev_info(&pdev->dev, "no align data in DT, try from vdd-cpu\n");
			err = get_alignment_from_regulator(&pdev->dev, &align);
			if (err == -EPROBE_DEFER) {
				dev_info(&pdev->dev, "defer probe to get vdd-cpu\n");
				return -EPROBE_DEFER;
			}
		}
	}

	if (!align.step_uv) {
		dev_err(&pdev->dev, "missing step uv\n");
		return -EINVAL;
	}

	soc->max_freq = max_freq;
	soc->cvb = tegra_cvb_add_opp_table(soc->dev, fcpu_data->cpu_cvb_tables,
					   fcpu_data->cpu_cvb_tables_size,
					   &align, process_id, speedo_id,
					   speedo_value, soc->max_freq,
					   &soc->min_millivolts);
	soc->alignment = align;

	if (IS_ERR(soc->cvb)) {
		dev_err(&pdev->dev, "couldn't add OPP table: %ld\n",
			PTR_ERR(soc->cvb));
		return PTR_ERR(soc->cvb);
	}

	INIT_TUNE_PRAM(tune0_low);
	INIT_TUNE_PRAM(tune0_high);
	INIT_TUNE_PRAM(tune1_low);
	INIT_TUNE_PRAM(tune1_high);
	INIT_TUNE_PRAM(tune_high_min_millivolts);
	INIT_TUNE_PRAM(tune_high_margin_millivolts);

	thermal = fcpu_data->cpu_thermal_table;
	err = tegra_cvb_build_thermal_table(thermal, speedo_value,
						soc->min_millivolts);
	if (err < 0) {
		pr_warn("couldn't build thermal floor table\n");
	} else {
		soc->thermal_floor_table = thermal->thermal_floor_table;
		soc->thermal_floor_table_size = thermal->thermal_floor_table_size;
	}

	if (thermal && thermal->thermal_cap_table && !ucm2) {
		soc->thermal_cap_table = thermal->thermal_cap_table;
		soc->thermal_cap_table_size = thermal->thermal_cap_table_size;
	} else if (thermal && thermal->thermal_cap_ucm2_table && ucm2) {
		soc->thermal_cap_table = thermal->thermal_cap_ucm2_table;
		soc->thermal_cap_table_size = thermal->thermal_cap_ucm2_table_size;
	} else {
		pr_warn("couldn't get thermal cap table\n");
	}

	err = tegra_dfll_register(pdev, soc);
	if (err < 0) {
		tegra_cvb_remove_opp_table(soc->dev, soc->cvb, soc->max_freq);
		return err;
	}

	return 0;
}

static int tegra124_dfll_fcpu_remove(struct platform_device *pdev)
{
	struct tegra_dfll_soc_data *soc;

	soc = tegra_dfll_unregister(pdev);
	if (IS_ERR(soc))
		dev_err(&pdev->dev, "failed to unregister DFLL: %ld\n",
			PTR_ERR(soc));

	tegra_cvb_remove_opp_table(soc->dev, soc->cvb, soc->max_freq);

	return 0;
}

static const struct dev_pm_ops tegra124_dfll_pm_ops = {
	SET_RUNTIME_PM_OPS(tegra_dfll_runtime_suspend,
			   tegra_dfll_runtime_resume, NULL)
	SET_LATE_SYSTEM_SLEEP_PM_OPS(NULL, tegra_dfll_resume_tuning)
};

static struct platform_driver tegra124_dfll_fcpu_driver = {
	.probe = tegra124_dfll_fcpu_probe,
	.remove = tegra124_dfll_fcpu_remove,
	.driver = {
		.name = "tegra124-dfll",
		.of_match_table = tegra124_dfll_fcpu_of_match,
		.pm = &tegra124_dfll_pm_ops,
	},
};
builtin_platform_driver(tegra124_dfll_fcpu_driver);
