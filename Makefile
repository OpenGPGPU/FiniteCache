CONFIG_MODULE_SIG=n

ogpu-objs := \
	ogpu_drv.o \
	ogpu_device.o \
	ogpu_chardev.o \
	ogpu_compute.o \
	ogpu_process.o \
	ogpu_topology.o
#	ogpu_memory.o \

obj-m += ogpu.o

all:
	make -C /lib/modules/`uname -r`/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build/ M=$(PWD) clean
