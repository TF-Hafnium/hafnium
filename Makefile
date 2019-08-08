# Copyright 2018 The Hafnium Authors.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# By default, assume this was checked out as a submodule of the Hafnium repo
# and that Linux was checked out along side that checkout. These paths can be
# overridden if that assumption is incorrect.
HAFNIUM_PATH ?= $(PWD)/../..

ifneq ($(KERNELRELEASE),)

obj-m += hafnium.o

hafnium-y += main.o
hafnium-y += hf_call.o

ccflags-y = -I$(HAFNIUM_PATH)/inc/vmapi -I$(PWD)/inc

else

KERNEL_PATH ?= $(HAFNIUM_PATH)/third_party/linux
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-
CHECKPATCH ?= $(KERNEL_PATH)/scripts/checkpatch.pl -q

all:
	make -C $(KERNEL_PATH) M=$(PWD) O=$(O) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) O=$(O) clean

checkpatch:
	$(CHECKPATCH) -f main.c hf_call.S

endif
