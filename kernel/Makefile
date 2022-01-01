CONFIG_MODULE_SIG=n

TARGET=drawbridge
obj-m += $(TARGET).o
$(TARGET)-objs := xt_hook.o xt_listen.o xt_state.o xt_crypto.o utils.o parser.o validator.o

KERNEL := /lib/modules/$(shell uname -r)/build
KDIR := $(KERNEL)
PWD := $(shell pwd)
EXTRA_CFLAGS := -O2

debug:
ifneq ("$(wildcard ./key.h)","")
	KCPPFLAGS="-DDEBUG" $(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
	cp test.sh $(TARGET).ko_test
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
	exit 1
endif

release:
ifneq ("$(wildcard ./key.h)","")
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
	cp test.sh $(TARGET).ko_test
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
	exit 1
endif

clean:
	$(MAKE) -C $(KERNEL) M=$(PWD) clean
