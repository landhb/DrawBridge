CONFIG_MODULE_SIG=n

obj-m += drawbridge.o
drawbridge-objs := xt_hook.o xt_listen.o xt_state.o xt_crypto.o utils.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS := -O2

release:
ifneq ("$(wildcard ./key.h)","")
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
endif

debug:
ifneq ("$(wildcard ./key.h)","")
	KCPPFLAGS="-DDEBUG" $(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
endif


clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
