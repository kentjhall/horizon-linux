dts-dirs += al
dts-dirs += altera
dts-dirs += amd
dts-dirs += amlogic
dts-dirs += apm
dts-dirs += arm
dts-dirs += broadcom
dts-dirs += cavium
dts-dirs += exynos
dts-dirs += freescale
dts-dirs += hisilicon
dts-dirs += marvell
dts-dirs += mediatek
dts-dirs += qcom
dts-dirs += renesas
dts-dirs += rockchip
dts-dirs += socionext
dts-dirs += sprd
dts-dirs += xilinx
dts-dirs += lg
dts-dirs += zte

subdir-y	:= $(dts-dirs)

dtstree		:= $(srctree)/$(src)

dtb-$(CONFIG_OF_ALL_DTBS) := $(patsubst $(dtstree)/%.dts,%.dtb, $(foreach d,$(dts-dirs), $(wildcard $(dtstree)/$(d)/*.dts)))
dtbo-$(CONFIG_OF_ALL_DTBS) := $(patsubst $(dtstree)/%.dts,%.dtbo, $(foreach d,$(dts-dirs), $(wildcard $(dtstree)/$(d)/*.dts)))

always		:= $(dtb-y)

targets += dtbs

DTC_FLAGS := -i $(tegra-dtstree)/soc/tegra/kernel-include
DTC_FLAGS += -i $(tegra-dtstree)/platform/tegra/common/kernel-dts
DTCCPP_FLAGS := -I$(tegra-dtstree)/soc/tegra/kernel-include
DTCCPP_FLAGS += -I$(tegra-dtstree)/platform/tegra/common/kernel-dts
DTCCPP_FLAGS += -DLINUX_VERSION=409

ifeq ($(CONFIG_ARCH_TEGRA_210_SOC),y)
DTC_FLAGS += -i $(tegra-dtstree)/soc/t210/kernel-dts
DTC_FLAGS += -i $(tegra-dtstree)/platform/t210/common/kernel-dts
DTC_FLAGS += -i $(tegra-dtstree)/platform/t210b01/common/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t210/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/platform/t210/common/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/platform/t210b01/common/kernel-dts
endif

ifeq ($(CONFIG_ARCH_TEGRA_18x_SOC),y)
DTC_FLAGS += -i $(tegra-dtstree)/soc/t18x/kernel-include
DTC_FLAGS += -i $(tegra-dtstree)/soc/t18x/kernel-dts
DTC_FLAGS += -i $(tegra-dtstree)/platform/t18x/common/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t18x/kernel-include
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t18x/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/platform/t18x/common/kernel-dts
endif

ifeq ($(CONFIG_ARCH_TEGRA_19x_SOC),y)
DTC_FLAGS += -i $(tegra-dtstree)/soc/t19x/kernel-include
DTC_FLAGS += -i $(tegra-dtstree)/soc/t18x/kernel-include
DTC_FLAGS += -i $(tegra-dtstree)/soc/t19x/kernel-dts
DTC_FLAGS += -i $(tegra-dtstree)/platform/t19x/common/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t19x/kernel-include
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t18x/kernel-include
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t19x/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/platform/t19x/common/kernel-dts
endif

ifeq ($(CONFIG_ARCH_TEGRA_23x_SOC),y)
DTC_FLAGS += -i $(tegra-dtstree)/soc/t23x/kernel-include
DTC_FLAGS += -i $(tegra-dtstree)/soc/t23x/kernel-dts
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t23x/kernel-include
DTCCPP_FLAGS += -I$(tegra-dtstree)/soc/t23x/kernel-dts
endif

ifeq ($(CONFIG_ANDROID),y)
DTCCPP_FLAGS += -DCONFIG_ANDROID
endif

# dtb-list will contain all dtb-y
DTB_LIST := $(dtb-y)
DTBO_LIST := $(dtbo-y)
dtb-y :=
dts_makefile=$(foreach d,$(wildcard $1*), $(call dts_makefile,$(d)/,$(2)) $(if $(findstring Makefile,$(d)),$(d)))
dts_mfiles = $(call dts_makefile, $(tegra-dtstree)/platform/, Makefile)
ifneq ($(dts_mfiles),)
dts-include :=
include $(dts_mfiles)
dtb-y := $(addprefix $(tegra-rel-dtstree)/hardware/nvidia/,$(dtb-y))
dtbo-y := $(addprefix $(tegra-rel-dtstree)/hardware/nvidia/,$(dtbo-y))
ifneq ($(dts-include),)
DTC_FLAGS += $(addprefix -i $(tegra-dtstree)/,$(dts-include))
DTCCPP_FLAGS += $(addprefix -I$(tegra-dtstree)/,$(dts-include))
endif
endif
DTB_LIST += $(dtb-y)
DTB_NEW_RULE_LIST := $(dtb-y)
DTBO_LIST += $(dtbo-y)
DTBO_NEW_RULE_LIST := $(dtbo-y)

# Now save DTB_LIST to dtb-y
dtb-y := $(DTB_LIST)
dtbo-y := $(DTBO_LIST)

DTB_OBJS := $(addprefix $(obj)/,$(DTB_LIST))
DTBO_OBJS := $(addprefix $(obj)/,$(DTBO_LIST))
targets += $(DTB_LIST)

define _define_dtb_rule
$(obj)/$(call replace_ddot,$(1)): $(src)/$(patsubst %.dtb,%.dts,$(1)) FORCE
endef

$(foreach _dtb, $(DTB_NEW_RULE_LIST), $(eval $(call _define_dtb_rule,$(_dtb))))

DTB_OBJS := $(call replace_ddot,$(DTB_OBJS))
DTB_NEW_RULE_LIST := $(addprefix $(obj)/,$(DTB_NEW_RULE_LIST))
DTB_NEW_RULE_LIST := $(call replace_ddot,$(DTB_NEW_RULE_LIST))

$(DTB_NEW_RULE_LIST):
	$(call if_changed_dep,dtc)

define _define_dtbo_rule
$(obj)/$(call replace_ddot,$(1)): $(src)/$(patsubst %.dtbo,%.dts,$(1)) FORCE
endef

$(foreach _dtbo, $(DTBO_NEW_RULE_LIST), $(eval $(call _define_dtbo_rule,$(_dtbo))))

DTBO_OBJS := $(call replace_ddot,$(DTBO_OBJS))
DTBO_NEW_RULE_LIST := $(addprefix $(obj)/,$(DTBO_NEW_RULE_LIST))
DTBO_NEW_RULE_LIST := $(call replace_ddot,$(DTBO_NEW_RULE_LIST))

$(DTBO_NEW_RULE_LIST):
	$(call if_changed_dep,dtc)

dtbs: $(DTB_OBJS) $(DTBO_OBJS) FORCE
	cp -u $(DTB_OBJS) $(DTBO_OBJS) arch/arm64/boot/dts/

clean-files := dts/*.dtb *.dtb *.dtbo
clean-dirs := dts/_ddot_
