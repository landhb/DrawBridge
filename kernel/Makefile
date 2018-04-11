CONFIG_MODULE_SIG=n

obj-m += trigger.o
trigger-objs := xt_hook.o xt_listen.o xt_state.o xt_crypto.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules


clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) -I $(PWD) clean