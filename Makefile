# By default, assume this was checked out as a submodule of the Hafnium repo
# and that Linux was checked out along side that checkout. These paths can be
# overridden if that assumption is incorrect.
HAFNIUM_PATH ?= $(PWD)/../..
KERNEL_PATH ?= $(HAFNIUM_PATH)/../linux

obj-m += hafnium.o

hafnium-y += main.o
hafnium-y += hf_call.o

ccflags-y = -I$(HAFNIUM_PATH)/inc/vmapi

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
