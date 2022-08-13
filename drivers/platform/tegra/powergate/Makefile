#
# Makefile for linux/drivers/platform/tegra
# Tegra Platform-Specific Drivers
#

GCOV_PROFILE := y

subdir-ccflags-y += -Werror \
		    -I$(srctree)/arch/arm/mach-tegra
obj-$(CONFIG_TEGRA_POWERGATE) += powergate.o
ifeq ($(CONFIG_TEGRA_POWERGATE),y)
obj-$(CONFIG_ARCH_TEGRA_210_SOC)        += powergate-t21x.o
endif
