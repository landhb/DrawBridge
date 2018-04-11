CC     = gcc
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer -Wno-format-security
ASAN_LIBS = -static-libasan
CFLAGS := -Wall -Werror --std=gnu99 -g3 


ARCH := $(shell uname)
ifneq ($(ARCH),Darwin)
  LDFLAGS += -lpthread -lssl -lcrypto 
endif

# default is to build with address sanitizer enabled
all: trigger

# the noasan version can be used with valgrind
all_noasan: trigger_noasan


trigger: trigger.o crypto.o
	$(CC) -o $@ $(CFLAGS) $(ASAN_FLAGS) $^ $(LDFLAGS) $(ASAN_LIBS)

trigger_noasan: trigger.o crypto.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) 


%_noasan.o : %.c
	$(CC) -c -o $@ $(CFLAGS) $<

%.o : %.c
	$(CC) -c -o $@ $(CFLAGS) $(ASAN_FLAGS) $<

.PHONY: clean

clean:
	rm -fr *.o trigger trigger_noasan trigger.o

