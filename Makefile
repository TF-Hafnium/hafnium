KERNEL_PATH ?= ../linux

obj-m += hafnium.o

hafnium-y += main.o
hafnium-y += hvc.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
