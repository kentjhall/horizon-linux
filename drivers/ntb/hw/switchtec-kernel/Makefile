#
# By default, the build is done against the running linux kernel source.
# To build against a different kernel source tree, set KDIR:
#
#    make KDIR=/path/to/kernel/source

ifdef KDIR
 KERNEL_SOURCES	 = $(KDIR)
else
 KERNEL_UNAME	:= $(shell uname -r)
 KERNEL_SOURCES	 = /lib/modules/$(KERNEL_UNAME)/build
endif

default: modules
.PHONY: default
install: modules_install

.PHONY: install

%::
	$(MAKE) -C $(KERNEL_SOURCES) M=$$PWD $@

pahole64: pahole.c linux/switchtec_ioctl.h
	gcc -O0 -g -I. $< -o $@

pahole32: pahole.c linux/switchtec_ioctl.h
	gcc -O0 -g -I. $< -o $@ -m32

pahole: pahole64 pahole32
	pahole pahole32 > pahole32.txt
	pahole pahole64 > pahole64.txt
	@cmp pahole32.txt pahole64.txt && echo "Arches Match" || \
		echo "!!Arches don't match!!"

clean::
	rm -f pahole32 pahole64 pahole*.txt
	$(MAKE) -C $(KERNEL_SOURCES) M=$$PWD $@
