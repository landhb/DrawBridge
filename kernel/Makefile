CONFIG_MODULE_SIG=n

obj-m += knock.o
knock-objs := xt_knock.o listen.o state.o crypto.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules


clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) -I $(PWD) clean