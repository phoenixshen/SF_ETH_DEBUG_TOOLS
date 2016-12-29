GCC_VENDOR=
CC=$(GCC_VENDOR)gcc
LD=$(GCC_VENDOR)ld
OD=$(GCC_VENDOR)objdump
OC=$(GCC_VENDOR)objcopy
SZ=$(GCC_VENDOR)size
AR=$(GCC_VENDOR)ar

APP_SOURCE_DIR=.

all: app

.PHONY: all

###################################################### build free rtos ###############################################################
APP_CSOURCES = \
	$(APP_SOURCE_DIR)/crc.c \
	$(APP_SOURCE_DIR)/ini2.c \
	$(APP_SOURCE_DIR)/udp_server.c

APP_TARGET = SF_ETH_DEBUG_TOOLS

APP_COBJECTS=${patsubst %.c, %.o, $(APP_CSOURCES)}

$(APP_COBJECTS):%o:%c
	$(CC) $(APP_CFLAGS) -o $@ -c $<

$(APP_TARGET): $(APP_COBJECTS)
	$(CC)  $(LINKER_FLAGS) $(APP_COBJECTS) -o $(APP_TARGET)

app: $(APP_TARGET)

clean:
	rm -rf $(APP_COBJECTS)
	rm -rf $(APP_TARGET)
