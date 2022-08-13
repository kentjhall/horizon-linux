/*
 * Copyright (c) 2010 Google, Inc
 * Copyright (c) 2014-2020, NVIDIA Corporation. All rights reserved.
 *
 * Author:
 *	Colin Cross <ccross@google.com>
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

#ifndef __SOC_TEGRA_PMC_H__
#define __SOC_TEGRA_PMC_H__

#include <linux/reboot.h>
#include <linux/usb/ch9.h>

#include <soc/tegra/pm.h>

struct clk;
struct reset_control;

#ifdef CONFIG_PM_SLEEP
enum tegra_suspend_mode tegra_pmc_get_suspend_mode(void);
void tegra_pmc_set_suspend_mode(enum tegra_suspend_mode mode);
void tegra_pmc_enter_suspend_mode(enum tegra_suspend_mode mode);
#endif /* CONFIG_PM_SLEEP */

#ifdef CONFIG_SMP
bool tegra_pmc_cpu_is_powered(int cpuid);
int tegra_pmc_cpu_power_on(int cpuid);
int tegra_pmc_cpu_remove_clamping(int cpuid);
#endif /* CONFIG_SMP */

/*
 * powergate and I/O rail APIs
 */

#ifndef CONFIG_TEGRA_POWERGATE
#define TEGRA_POWERGATE_CPU	0
#define TEGRA_POWERGATE_3D	1
#define TEGRA_POWERGATE_VENC	2
#define TEGRA_POWERGATE_PCIE	3
#define TEGRA_POWERGATE_VDEC	4
#define TEGRA_POWERGATE_L2	5
#define TEGRA_POWERGATE_MPE	6
#define TEGRA_POWERGATE_HEG	7
#define TEGRA_POWERGATE_SATA	8
#define TEGRA_POWERGATE_CPU1	9
#define TEGRA_POWERGATE_CPU2	10
#define TEGRA_POWERGATE_CPU3	11
#define TEGRA_POWERGATE_CELP	12
#define TEGRA_POWERGATE_3D1	13
#define TEGRA_POWERGATE_CPU0	14
#define TEGRA_POWERGATE_C0NC	15
#define TEGRA_POWERGATE_C1NC	16
#define TEGRA_POWERGATE_SOR	17
#define TEGRA_POWERGATE_DIS	18
#define TEGRA_POWERGATE_DISB	19
#define TEGRA_POWERGATE_XUSBA	20
#define TEGRA_POWERGATE_XUSBB	21
#define TEGRA_POWERGATE_XUSBC	22
#define TEGRA_POWERGATE_VIC	23
#define TEGRA_POWERGATE_IRAM	24
#define TEGRA_POWERGATE_NVDEC	25
#define TEGRA_POWERGATE_NVJPG	26
#define TEGRA_POWERGATE_AUD	27
#define TEGRA_POWERGATE_DFD	28
#define TEGRA_POWERGATE_VE2	29
#endif

#define TEGRA_POWERGATE_3D0	TEGRA_POWERGATE_3D

#define TEGRA_IO_RAIL_CSIA	0
#define TEGRA_IO_RAIL_CSIB	1
#define TEGRA_IO_RAIL_DSI	2
#define TEGRA_IO_RAIL_MIPI_BIAS	3
#define TEGRA_IO_RAIL_PEX_BIAS	4
#define TEGRA_IO_RAIL_PEX_CLK1	5
#define TEGRA_IO_RAIL_PEX_CLK2	6
#define TEGRA_IO_RAIL_USB0	9
#define TEGRA_IO_RAIL_USB1	10
#define TEGRA_IO_RAIL_USB2	11
#define TEGRA_IO_RAIL_USB_BIAS	12
#define TEGRA_IO_RAIL_NAND	13
#define TEGRA_IO_RAIL_UART	14
#define TEGRA_IO_RAIL_BB	15
#define TEGRA_IO_RAIL_AUDIO	17
#define TEGRA_IO_RAIL_HSIC	19
#define TEGRA_IO_RAIL_COMP	22
#define TEGRA_IO_RAIL_HDMI	28
#define TEGRA_IO_RAIL_PEX_CNTRL	32
#define TEGRA_IO_RAIL_SDMMC1	33
#define TEGRA_IO_RAIL_SDMMC3	34
#define TEGRA_IO_RAIL_SDMMC4	35
#define TEGRA_IO_RAIL_CAM	36
#define TEGRA_IO_RAIL_RES	37
#define TEGRA_IO_RAIL_HV	38
#define TEGRA_IO_RAIL_DSIB	39
#define TEGRA_IO_RAIL_DSIC	40
#define TEGRA_IO_RAIL_DSID	41
#define TEGRA_IO_RAIL_CSIE	44
#define TEGRA_IO_RAIL_LVDS	57
#define TEGRA_IO_RAIL_SYS_DDC	58

/* Define reboot-reset mode */
#define RECOVERY_MODE           BIT(31)
#define BOOTLOADER_MODE         BIT(30)
#define UPDATE_MODE             BIT(29)
#define FORCED_RECOVERY_MODE    BIT(1)

#ifndef CONFIG_TEGRA_POWERGATE
#if defined CONFIG_ARCH_TEGRA
int tegra_powergate_is_powered(int id);
int tegra_powergate_power_on(int id);
int tegra_powergate_power_off(int id);
int tegra_powergate_remove_clamping(int id);

/* Must be called with clk disabled, and returns with clk enabled */
int tegra_powergate_sequence_power_up(int id, struct clk *clk,
				      struct reset_control *rst);

#else
static inline int tegra_powergate_is_powered(int id)
{
	return -ENOSYS;
}

static inline int tegra_powergate_power_on(int id)
{
	return -ENOSYS;
}

static inline int tegra_powergate_power_off(int id)
{
	return -ENOSYS;
}

static inline int tegra_powergate_remove_clamping(int id)
{
	return -ENOSYS;
}

static inline int tegra_powergate_sequence_power_up(int id, struct clk *clk,
						    struct reset_control *rst)
{
	return -ENOSYS;
}

#endif /* CONFIG_ARCH_TEGRA */
#endif /* CONFIG_TEGRA_POWERGATE */

enum tegra_system_reset_reason {
	TEGRA_POWER_ON_RESET,	/* 0 */
	TEGRA_AO_WATCHDOG,	/* 1 */
	TEGRA_DENVER_WATCHDOG,	/* 2 */
	TEGRA_BPMP_WATCHDOG,	/* 3 */
	TEGRA_SCE_WATCHDOG,	/* 4 */
	TEGRA_SPE_WATCHDOG,	/* 5 */
	TEGRA_APE_WATCHDOG,	/* 6 */
	TEGRA_A57_WATCHDOG,	/* 7 */
	TEGRA_SENSOR,		/* 8 */
	TEGRA_AOTAG,		/* 9 */
	TEGRA_VFSENSOR,		/* 10 */
	TEGRA_SOFTWARE_RESET,	/* 11 */
	TEGRA_SC7,		/* 12 */
	TEGRA_HSM,		/* 13 */
	TEGRA_CSITE,		/* 14 */
	TEGRA_WATCHDOG,		/* 15, T210 */
	TEGRA_LP0,		/* 16, T210 */
	PMIC_WATCHDOG_POR,	/* 17 */
	TEGRA_RESET_REASON_MAX
};

enum tegra_system_reset_level {
	TEGRA_RESET_LEVEL_L0,
	TEGRA_RESET_LEVEL_L1,
	TEGRA_RESET_LEVEL_L2,
	TEGRA_RESET_LEVEL_MAX
};

int tegra_pmc_set_reboot_reason(u32 reboot_reason);
int tegra_pmc_clear_reboot_reason(u32 reboot_reason);

void tegra_pmc_write_bootrom_command(u32 command_offset, unsigned long val);
void tegra_pmc_reset_system(void);
enum tegra_system_reset_reason tegra_pmc_get_system_reset_reason(void);
enum tegra_system_reset_level tegra_pmc_get_system_reset_level(void);

#if defined(CONFIG_ARCH_TEGRA) && !defined(CONFIG_TEGRA186_PMC)
void tegra_pmc_io_dpd_clear(void);
int tegra_pmc_io_pad_low_power_enable(const char *pad_name);
int tegra_pmc_io_pad_low_power_disable(const char *pad_name);
int tegra_io_rail_power_on(int id);
int tegra_io_rail_power_off(int id);
int tegra_pmc_io_pad_set_voltage(const char *pad_name, unsigned int pad_uv);
int tegra_pmc_io_pad_get_voltage(const char *pad_name);
#else
static inline void tegra_pmc_io_dpd_clear(void)
{
}

static inline int tegra_pmc_io_pad_low_power_enable(const char *pad_name)
{
	return 0;
}

static inline int tegra_pmc_io_pad_low_power_disable(const char *pad_name)
{
	return 0;
}

static inline int tegra_io_rail_power_on(int id)
{
	return -ENOSYS;
}

static inline int tegra_io_rail_power_off(int id)
{
	return -ENOSYS;
}

static inline int tegra_pmc_io_pad_set_voltage(const char *pad_name,
					       unsigned int pad_uv)
{
	return -ENOSYS;
}

static inline int tegra_pmc_io_pad_get_voltage(const char *pad_name)
{
	return -ENOSYS;
}
#endif

int tegra_pmc_pwm_blink_enable(void);
int tegra_pmc_pwm_blink_disable(void);
int tegra_pmc_pwm_blink_config(int duty_ns, int period_ns);

int tegra_pmc_soft_led_blink_enable(void);
int tegra_pmc_soft_led_blink_disable(void);
int tegra_pmc_soft_led_blink_configure(int duty_cycle_ns, int ll_period_ns,
				       int ramp_time_ns);
int tegra_pmc_soft_led_blink_set_ramptime(int ramp_time_ns);
int tegra_pmc_soft_led_blink_set_short_period(int short_low_period_ns);

/* T210 USB2 SLEEPWALK APIs */
struct tegra_utmi_pad_config {
	u32 tctrl;
	u32 pctrl;
	u32 rpd_ctrl;
};
int tegra_pmc_utmi_phy_enable_sleepwalk(int port, enum usb_device_speed speed,
					struct tegra_utmi_pad_config *config);
int tegra_pmc_utmi_phy_disable_sleepwalk(int port);
int tegra_pmc_hsic_phy_enable_sleepwalk(int port);
int tegra_pmc_hsic_phy_disable_sleepwalk(int port);

void tegra_pmc_fuse_control_ps18_latch_set(void);
void tegra_pmc_fuse_control_ps18_latch_clear(void);
void tegra_pmc_fuse_disable_mirroring(void);
void tegra_pmc_fuse_enable_mirroring(void);
bool tegra_pmc_fuse_is_redirection_enabled(void);

/* Legacy APIs for IO DPD enable/disable */
/* Tegra io dpd entry - for each supported driver */
struct tegra_io_dpd {
        const char *name;       /* driver name */
        u8 io_dpd_reg_index;    /* io dpd register index */
        u8 io_dpd_bit;          /* bit position for driver in dpd register */
};

static inline void tegra_io_dpd_enable(struct tegra_io_dpd *hnd)
{
	tegra_pmc_io_pad_low_power_enable(hnd->name);
}

static inline void tegra_io_dpd_disable(struct tegra_io_dpd *hnd)
{
	tegra_pmc_io_pad_low_power_disable(hnd->name);
}

/**
 * struct tegra_thermtrip_pmic_data - PMIC shutdown command data
 * @poweroff_reg_data:	The data to write to turn the system off
 * @poweroff_reg_addr:	The PMU address of poweroff register
 * @reset_tegra:	Flag indicating whether or not the system
 *			will shutdown during a thermal trip.
 * @controller_type:	If this field is set to 0, the PMIC is
 *			connected via I2C. If it is set to 1,
 *			it is connected via SPI. If it is set to
 *			2, it is connected via GPIO.
 * @i2c_controller_id:	The i2c bus controller id
 * @pinmux:		An array index used to configure which pins
 *			on the chip are muxed to the I2C/SPI/GPIO
 *			controller that is in use. Contact NVIDIA
 *			for more information on what these index values
 *			mean for a given chip.
 * @pmu_16bit_ops:	If 0, sends three bytes from the PMC_SCRATCH54
 *			register to the PMIC to turn it off; if 1, sends
 *			four bytes from the PMC_SCRATCH54 register to the PMIC
 *			to turn it off, plus one other byte. Must be set to
 *			0 - the current code does not support 16 bit
 *			operations.
 * @pmu_i2c_addr:	The address of the PMIC on the I2C bus
 *
 * When the SoC temperature gets too high, the SOC_THERM hardware can
 * reset the SoC, and, by setting a bit in one of its registers, can
 * instruct the boot ROM to power off the Tegra SoC. This data
 * structure contains the information that the boot ROM needs to tell
 * the PMIC to shut down.
 *
 * @poweroff_reg_data and @poweroff_reg_addr are written to the PMC SCRATCH54
 * register.
 *
 * @reset_tegra, @controller_type, @i2c_controller_id, @pinmux, @pmu_16bit_ops
 * and @pmu_i2c_addr are written to the PMC SCRATCH55 register.
 */
struct tegra_thermtrip_pmic_data {
	u8 poweroff_reg_data;
	u8 poweroff_reg_addr;
	u8 reset_tegra;
	u8 controller_type;
	u8 i2c_controller_id;
	u8 pinmux;
	u8 pmu_16bit_ops;
	u8 pmu_i2c_addr;
};

void tegra_pmc_config_thermal_trip(struct tegra_thermtrip_pmic_data *data);
void tegra_pmc_enable_thermal_trip(void);
void tegra_pmc_lock_thermal_shutdown(void);

#if defined(CONFIG_PADCTRL_GENERIC_TEGRA_IO_PAD)
int tegra_io_pads_padctrl_init(struct device *dev);
#else
static inline int tegra_io_pads_padctrl_init(struct device *dev)
{
	return 0;
}
#endif

void tegra_pmc_ufs_pwrcntrl_update(unsigned long mask, unsigned long val);
unsigned long tegra_pmc_ufs_pwrcntrl_get(void);

int tegra_pmc_nvcsi_brick_getstatus(const char *pad_name);
int tegra_pmc_nvcsi_ab_brick_dpd_enable(void);
int tegra_pmc_nvcsi_cdef_brick_dpd_enable(void);
int tegra_pmc_nvcsi_ab_brick_dpd_disable(void);
int tegra_pmc_nvcsi_cdef_brick_dpd_disable(void);

bool tegra_pmc_is_halt_in_fiq(void);
void tegra_pmc_sata_pwrgt_update(unsigned long mask,
		unsigned long val);
unsigned long tegra_pmc_sata_pwrgt_get(void);
int tegra_pmc_save_se_context_buffer_address(u32 add);
u32 tegra_pmc_get_se_context_buffer_address(void);
void tegra_pmc_writel_relaxed(u32 value, unsigned long offset);
u32 tegra_pmc_readl(unsigned long offset);
void tegra_pmc_writel(u32 value, unsigned long offset);

#endif /* __SOC_TEGRA_PMC_H__ */
