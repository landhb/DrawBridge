CC     = gcc
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer -Wno-format-security
ASAN_LIBS = -static-libasan
CFLAGS := -Wall -W -Werror --std=gnu99 -g3 


ARCH := $(shell uname)
ifneq ($(ARCH),Darwin)
  LDFLAGS += -lpthread -lssl -lcrypto 
endif

# default is to build without address sanitizer enabled
all: bridge

# the noasan version can be used with valgrind
all_asan: bridge_asan


bridge_asan: bridge.o crypto.o
	$(CC) -o $@ $(CFLAGS) $(ASAN_FLAGS) $^ $(LDFLAGS) $(ASAN_LIBS)

bridge: bridge_noasan.o crypto_noasan.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) 

install:
	if [ ! -f "/usr/bin/bridge" ]; then cp ./bridge /usr/bin/bridge; else echo "[-] /usr/bin/bridge exits. If you want to overwrite use 'make reinstall'"; fi

reinstall:
	mv ./bridge /usr/bin/bridge

%_noasan.o : %.c
	$(CC) -c -o $@ $(CFLAGS) $<

%.o : %.c
	$(CC) -c -o $@ $(CFLAGS) $(ASAN_FLAGS) $<

.PHONY: clean

clean:
	rm -fr *.o bridge bridge_noasan bridge.o

