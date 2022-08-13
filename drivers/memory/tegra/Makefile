tegra-mc-y := mc.o

tegra-mc-$(CONFIG_ARCH_TEGRA_3x_SOC)  += tegra30.o
tegra-mc-$(CONFIG_ARCH_TEGRA_114_SOC) += tegra114.o
tegra-mc-$(CONFIG_ARCH_TEGRA_124_SOC) += tegra124.o
tegra-mc-$(CONFIG_ARCH_TEGRA_132_SOC) += tegra124.o
tegra-mc-$(CONFIG_ARCH_TEGRA_210_SOC) += tegra210.o

obj-n += tegra-mc.o

obj-$(CONFIG_TEGRA124_EMC) += tegra124-emc.o

obj-$(CONFIG_TEGRA210_EMC) += t210-emc.o
t210-emc-objs += tegra210-emc.o tegra210-emc-cc-r21015.o tegra210-emc-cc-r21012.o tegra210-emc-cc-r21021.o tegra210-dt-parse.o

