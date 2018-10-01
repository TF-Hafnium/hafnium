# By default, assume this was checked out as a submodule of the Hafnium repo
# and that Linux was checked out along side that checkout. These paths can be
# overridden if that assumption is incorrect.
HAFNIUM_PATH ?= $(PWD)/../..

ifneq ($(KERNELRELEASE),)

obj-m += hafnium.o

hafnium-y += main.o
hafnium-y += hf_call.o

ccflags-y = -I$(HAFNIUM_PATH)/inc/vmapi

else

KERNEL_PATH ?= $(HAFNIUM_PATH)/../linux
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

all:
	make -C $(KERNEL_PATH) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean

endif
