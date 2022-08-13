/*
 * include/linux/irqchip/tegra-t18x-agic.h
 *
 * Header file for managing AGIC interrupt controller
 *
 * Copyright (C) 2015-2016 NVIDIA Corporation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _TEGRA_T18X_AGIC_H_
#define _TEGRA_T18X_AGIC_H_

/* INT_T18x_ADMA Channel End of Transfer Interrupt */
#define INT_T18x_AGIC_START			32
#define INT_T18x_ADMA_EOT0			32
#define INT_T18x_ADMA_EOT1			33
#define INT_T18x_ADMA_EOT2			34
#define INT_T18x_ADMA_EOT3			35
#define INT_T18x_ADMA_EOT4			36
#define INT_T18x_ADMA_EOT5			37
#define INT_T18x_ADMA_EOT6			38
#define INT_T18x_ADMA_EOT7			39
#define INT_T18x_ADMA_EOT8			40
#define INT_T18x_ADMA_EOT9			41
#define INT_T18x_ADMA_EOT10			42
#define INT_T18x_ADMA_EOT11			43
#define INT_T18x_ADMA_EOT12			44
#define INT_T18x_ADMA_EOT13			45
#define INT_T18x_ADMA_EOT14			46
#define INT_T18x_ADMA_EOT15			47
#define INT_T18x_ADMA_EOT16			48
#define INT_T18x_ADMA_EOT17			49
#define INT_T18x_ADMA_EOT18			50
#define INT_T18x_ADMA_EOT19			51
#define INT_T18x_ADMA_EOT20			52
#define INT_T18x_ADMA_EOT21			53
#define INT_T18x_ADMA_EOT22			54
#define INT_T18x_ADMA_EOT23			55
#define INT_T18x_ADMA_EOT24			56
#define INT_T18x_ADMA_EOT25			57
#define INT_T18x_ADMA_EOT26			58
#define INT_T18x_ADMA_EOT27			59
#define INT_T18x_ADMA_EOT28			60
#define INT_T18x_ADMA_EOT29			61
#define INT_T18x_ADMA_EOT30			62
#define INT_T18x_ADMA_EOT31			63

/* AMISC Mailbox Full Interrupts */
#define INT_T18x_AMISC_MBOX_FULL0		64
#define INT_T18x_AMISC_MBOX_FULL1		65
#define INT_T18x_AMISC_MBOX_FULL2		66
#define INT_T18x_AMISC_MBOX_FULL3		67
#define INT_T18x_AMISC_MBOX_FULL4		68
#define INT_T18x_AMISC_MBOX_FULL5		69
#define INT_T18x_AMISC_MBOX_FULL6		70
#define INT_T18x_AMISC_MBOX_FULL7		71

/* AMISC Mailbox Empty Interrupts */
#define INT_T18x_AMISC_MBOX_EMPTY0		72
#define INT_T18x_AMISC_MBOX_EMPTY1		73
#define INT_T18x_AMISC_MBOX_EMPTY2		74
#define INT_T18x_AMISC_MBOX_EMPTY3		75
#define INT_T18x_AMISC_MBOX_EMPTY4		76
#define INT_T18x_AMISC_MBOX_EMPTY5		77
#define INT_T18x_AMISC_MBOX_EMPTY6		78
#define INT_T18x_AMISC_MBOX_EMPTY7		79

/* AHSP SHARED INTERRUPT */
#define INT_T18x_AHSP_SHRD0			80
#define INT_T18x_AHSP_SHRD1			81
#define INT_T18x_AHSP_SHRD2			82
#define INT_T18x_AHSP_SHRD3			83
#define INT_T18x_AHSP_SHRD4			84

/* ADSP/PTM Performance Monitoring Unit Interrupt */
#define INT_T18x_ADSP_PMU			85

/* ADSP Watchdog Timer Reset Request */
#define INT_T18x_ADSP_WDT			86

/* ADSP L2 Cache Controller Interrupt */
#define	INT_T18x_ADSP_L2CC			87

/* AHUB Error Interrupt */
#define INT_T18x_AHUB_ERR			88

/* AMC Error Interrupt */
#define INT_T18x_AMC_ERR			89

/* INT_T18x_ADMA Error Interrupt */
#define INT_T18x_ADMA_ERR0			90
#define INT_T18x_ADMA_ERR1			91
#define INT_T18x_ADMA_ERR2			92
#define INT_T18x_ADMA_ERR3			93

/* ADSP Standby WFI.  ADSP in idle mode. Waiting for Interrupt */
#define INT_T18x_WFI				94

/* ADSP Standby WFE.  ADSP in idle mode. Waiting for Event */
#define INT_T18x_WFE				95

#define INT_T18x_ADSP_CTI			96

/* Activity monitoring on ADSP.  This interrupt is from AMISC */
#define INT_T18x_ADSP_ACTMON			97
#define INT_T18x_ADSP_ACTMON_RESERVED0	98
#define INT_T18x_ADSP_ACTMON_RESERVED1	99

/* LIC to APE Interrupts */
#define INT_T18x_LIC_TO_APE0			100
#define INT_T18x_LIC_TO_APE1			101

/* VI Notify High Interrupt */
#define INT_T18x_VI_NOTIFY_HIGH		102
#define INT_T18x_VI_NOTIFY_LOW		103

/* I2C {1,3,8} Interrupt */
#define INT_T18x_I2C_IRQ1			104
#define INT_T18x_I2C_IRQ3			105
#define INT_T18x_I2C_IRQ8			106

/* System Door Bell interrupt */
#define INT_T18x_SHSP2APE_DB			107

/* Top WDT FIQ interrupt */
#define INT_T18x_TOP_WDT_FIQ			108

/* Top WDT IRQ interrupt */
#define INT_T18x_TOP_WDT_IRQ			109

/* ATKE Timer IRQ interrupt */
#define INT_T18x_ATKE_TMR0			110
#define INT_T18x_ATKE_TMR1			111
#define INT_T18x_ATKE_TMR2			112
#define INT_T18x_ATKE_TMR3			113

/* ATKE WDT FIQ interrupt */
#define INT_T18x_ATKE_WDT_FIQ		114

/* ATKE WDT IRQ interrupt */
#define INT_T18x_ATKE_WDT_IRQ		115

/* ATKE WDT error interrupt */
#define INT_T18x_ATKE_WDT_ERR		116

/* UART interrupt to AGIC (In FPGA platform only) */
#define INT_T18x_UART_FPGA			117

#define INT_T18x_AGIC_END			117

#endif /* _TEGRA_T18X_AGIC_H_ */
