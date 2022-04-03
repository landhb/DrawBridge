CONFIG_MODULE_SIG=n

TARGET=drawbridge
obj-m += $(TARGET).o
$(TARGET)-objs := src/xt_hook.o src/xt_listen.o src/xt_state.o src/xt_crypto.o src/utils.o src/parser.o src/validator.o
EXTRA_CFLAGS := -O2 -I$(PWD)/include

KERNEL := /lib/modules/$(shell uname -r)/build
KDIR := $(KERNEL)
PWD := $(shell pwd)
KBUILD_OUTPUT=$(PWD)/build

debug:
ifneq ("$(wildcard ./include/key.h)","")
	-mkdir $(PWD)/build/
	KCPPFLAGS="-DDEBUG" $(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in the include/ directory"
	exit 1
endif

release:
ifneq ("$(wildcard ./include/key.h)","")
	-mkdir $(PWD)/build/
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
	#cp test.sh $(TARGET).ko_test
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in the include/ directory"
	exit 1
endif

clean:
	$(MAKE) -C $(KERNEL) M=$(PWD) clean
