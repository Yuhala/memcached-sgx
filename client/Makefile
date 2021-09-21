#
# Created on Thu Sep 02 2021
#
# Copyright (c) 2021 Peterson Yuhala, IIUN
# Build client
#
#

CC := gcc

SRC := .

INCLUDE_PATHS := -I$(SRC) -I$(SRC)/headers

COMPILE_FLAGS := $(INCLUDE_PATHS)

LD_FLAGS := -lpthread -lm -lssl -lcrypto -lmemcached

HEADERS := $(wildcard ./*.h)
APP_C_FILES := $(wildcard ./*.c)
APP_OBJS := $(APP_C_FILES:.c=.o)

MCD_CLIENT := cli


.PHONY: all clean

all: $(MCD_CLIENT)

$(SRC)/%.o: $(SRC)/%.c $(HEADERS)
		$(CC) $(COMPILE_FLAGS) -c $< -o $@
		@echo "CC <= $<" 

$(MCD_CLIENT): $(APP_OBJS)
		@$(CC) $^ -o $@ $(LD_FLAGS) 
		@echo "LINK =>  $@"

clean:
	@rm  $(APP_OBJS) cli
	