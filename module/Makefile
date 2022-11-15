CONFIG_MODULE_SIG=n

TARGET=drawbridge
obj-m += $(TARGET).o
$(TARGET)-objs := src/entrypoint.o src/listener.o src/state.o src/crypto.o src/utils.o src/parser.o src/validator.o src/sk_filter.o
EXTRA_CFLAGS := -O2 -I$(PWD)/include

KERNEL := /lib/modules/$(shell uname -r)/build
KDIR := $(KERNEL)
PWD := $(shell pwd)

# Set the new timeout if provided
# Timout Configuration - default 5 min = 300000 msec
ifdef STATE_TIMEOUT
KCPPFLAGS := -DSTATE_TIMEOUT=$(STATE_TIMEOUT)
else
KCPPFLAGS := -DSTATE_TIMEOUT=300000
endif

debug:
ifneq ("$(wildcard ./include/key.h)","")
	KCPPFLAGS="${KCPPFLAGS} -DDEBUG" $(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in the include/ directory"
	exit 1
endif

release:
ifneq ("$(wildcard ./include/key.h)","")
	KCPPFLAGS="${KCPPFLAGS}" $(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -fr *.o .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in the include/ directory"
	exit 1
endif

clean:
	$(MAKE) -C $(KERNEL) M=$(PWD) clean
