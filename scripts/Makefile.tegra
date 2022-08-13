#
# Copyright (c) 2016-2017, NVIDIA CORPORATION.  All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

define include_overlay
  subdir := $(if $(src),$(src),$(obj))
  ovl_file := $(if $(wildcard $(overlay)/$(subdir)/Kbuild),$(overlay)/$(subdir)/Kbuild,$(overlay)/$(subdir)/Makefile)
  -include $(ovl_file)
  EXTRA_CFLAGS += -I$(overlay)/include
endef
$(foreach overlay,$(KERNEL_OVERLAYS),$(eval $(value include_overlay)))
