#
# Created on Thu Sep 02 2021
#
# Copyright (c) 2021 Peterson Yuhala, IIUN
# Custom makefile I created to build [custom] memcached
# Reason: automake very messy..Need to understand the internals
# Tested on Ubuntu 18.04 only
#

CC := gcc

SRC := .

INCLUDE_PATHS := -I$(SRC) -I$(SRC)/headers

COMPILE_FLAGS := $(INCLUDE_PATHS)

LD_FLAGS := -lpthread -lm -lssl -lcrypto -levent

HEADERS := $(wildcard ./*.h)
APP_C_FILES := $(wildcard ./*.c)
APP_OBJS := $(APP_C_FILES:.c=.o)


MCD_SERVER := memcached
MCD_CLIENT := cli



.PHONY: all clean

all: $(MCD_SERVER) $(MCD_CLIENT)

$(SRC)/%.o: $(SRC)/%.c $(HEADERS)
		$(CC) $(COMPILE_FLAGS) -c $< -o $@
		@echo "CC <= $<" 

$(MCD_SERVER): $(APP_OBJS)
		@$(CC) $^ -o $@ $(LD_FLAGS)
		@echo "LINK =>  $@"

$(MCD_CLIENT): client/client.c
		@$(CC) $^ -o $@ $(LD_FLAGS) -lmemcached
		@echo "LINK =>  $@"

clean:
	@rm memcached $(APP_OBJS) client.o cli
	