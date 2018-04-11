CONFIG_MODULE_SIG=n

obj-m += trigger.o
trigger-objs := xt_hook.o xt_listen.o xt_state.o xt_crypto.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


default:
ifneq ("$(wildcard ./key.h)","")
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
endif


clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) -I $(PWD) clean