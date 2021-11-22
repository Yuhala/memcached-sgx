#
# Created on Thu Sep 02 2021
#
# Copyright (c) 2021 Peterson Yuhala, IIUN
# Custom makefile I created to build [custom] memcached
# Reason: automake very messy..Need to understand the internals
# Tested on Ubuntu 18.04 only
#

CXX := g++

SRC := .

INCLUDE_PATHS := -I$(SRC) -I$(SRC)/headers

COMPILE_FLAGS := $(INCLUDE_PATHS)

LD_FLAGS :=  -lm -lssl -lcrypto -lpthread

HEADERS := $(wildcard ./*.h)
APP_CPP_FILES := $(wildcard ./*.cc)
APP_OBJS := $(APP_CPP_FILES:.cc=.o)


KYOTO := kyoto


.PHONY: all clean

all: $(KYOTO)

$(SRC)/%.o: $(SRC)/%.cc $(HEADERS)
		$(CXX) $(COMPILE_FLAGS) -c $< -o $@
		@echo "CC <= $<" 

$(KYOTO): $(APP_OBJS)
		@$(CXX) $^ -o $@ $(LD_FLAGS)
		@echo "LINK =>  $@"


clean:
	@rm kyoto $(APP_OBJS)
	