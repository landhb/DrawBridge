CONFIG_MODULE_SIG=n

obj-m += drawbridge.o
drawbridge-objs := xt_hook.o xt_listen.o xt_state.o xt_crypto.o libdb_packet_parser.a

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS := -O2

RUSTC := rustc

release: libdb_packet_parser.a
ifneq ("$(wildcard ./key.h)","")
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	rm -fr *.o *.a .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
endif

debug: libdb_packet_parser.a
ifneq ("$(wildcard ./key.h)","")
	KCPPFLAGS="-DDEBUG" $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	rm -fr *.o *.a .*.cmd Module.symvers modules.order drawbridge.mod.c
else
	@echo "[!] Please ensure you've generated a public key, and that key.h is in this directory"
endif


%.a: parser/lib.rs #$(wildcard *.rs)
	$(RUSTC) -O --target x86_64-unknown-linux-gnu --crate-type lib -o $@ --emit obj $<


clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) -I $(PWD) clean
