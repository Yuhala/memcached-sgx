
#
# Created on Wed Jul 15 2020
#
# Copyright (c) 2020 Peterson Yuhala, IIUN
#

#
# Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?=HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
#SGX_PRERELEASE = 1
DISABLE_WARNINGS = 1

CXX = g++
CC = gcc


ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

# pyuhala: show/disable warnings

ifeq ($(DISABLE_WARNINGS), 1)
        WARNINGS_FLAG = -w 
else
        WARNINGS_FLAG = -Wall
endif


#
SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls $(WARNINGS_FLAG)
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11



######## Graal SGX Settings #######

# Trusted objects from graal AoT compilation
Graal_Objects_In := $(wildcard Enclave/graalsgx/*.o)

# Static graal libs
Graal_Libs_Path := ./Common
Graal_Libs := #-lfdlibm -lffi -ljava -ljvm -llibchelper -lnet -lnio -lzip

# Untrusted objects from graal AoT compilation
Graal_Objects_Out := $(wildcard App/graalsgx/*.o)

# Graal cpp files
GraalSGX_Cpp_Files_In := $(wildcard Enclave/graalsgx/*/*.cpp)
GraalSGX_Cpp_FIles_Out := $(wildcard App/graalsgx/*/*.cpp)

# In-enclave graalsgx include paths
Graal_Include_Path := -IEnclave/graalsgx -IEnclave/graalsgx/include



########## Memcached Settings ########

# Memcached source
Memcached_Src_In := ./Enclave/memcached
Memcached_Src_Out := ./App/memcached

# Memcached c files
Memcached_C_Files_In := $(wildcard $(Memcached_Src_In)/*.c)
Memcached_C_Files_Out := $(wildcard $(Memcached_Src_Out)/*.c)

# Memcached headers
Memcached_Headers_In := $(wildcard $(Memcached_Src_In)/*.h)
Memcached_Headers_Out := $(wildcard $(Memcached_Src_Out)/*.h)

# Memcached objects
Memcached_Objs_In := $(Memcached_C_Files_In:.c=.o)
Memcached_Objs_Out := $(Memcached_C_Files_Out:.c=.o)

# Memcached libs
Memcached_Libs := -lpthread -lm -lssl -lcrypto -levent

# Memcached include paths
Memcached_Inc_Paths := -I$(Memcached_Src_In) 



########## Kyoto Settings ########

# Kyoto source
Kyoto_Src_In := ./Enclave/kyoto
Kyoto_Src_Out := ./App/kyoto

# Kyoto cc files
Kyoto_Cpp_Files_In := $(wildcard $(Kyoto_Src_In)/*.cc)
Kyoto_Cpp_Files_Out := $(wildcard $(Kyoto_Src_Out)/*.cc)

# Kyoto headers
Kyoto_Headers_In := $(wildcard $(Kyoto_Src_In)/*.h)
Kyoto_Headers_Out := $(wildcard $(Kyoto_Src_Out)/*.h)

# Kyoto objects
Kyoto_Objs_In := $(Kyoto_Cpp_Files_In:.cc=.o)
Kyoto_Objs_Out := $(Kyoto_Cpp_Files_Out:.cc=.o)

# Kyoto libs
Kyoto_Libs := -lpthread -lm -lssl -lcrypto

# Kyoto include paths
Kyoto_Inc_Paths := -I$(Kyoto_Src_In) 


########## Lmbench Settings ########

# lmbench source
Lmbench_Src_In := ./Enclave/lmbench


# lmbench c files
Lmbench_C_Files_In := $(wildcard $(Lmbench_Src_In)/*.c)


# lmbench headers
Lmbench_Headers_In := $(wildcard $(Lmbench_Src_In)/*.h)


# lmbench objects
Lmbench_Objs_In := $(Lmbench_C_Files_In:.c=.o)

# lmbench libs
Lmbench_Libs := -lpthread -lm -lssl -lcrypto

# lmbench include paths
Lmbench_Inc_Paths := -I$(Lmbench_Src_In) 


######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp  $(GraalSGX_Cpp_FIles_Out) $(wildcard App/*/*.cpp)
App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include -IEnclave/graalsgx/include -IApp/graalsgx 

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)

# Graal needs: -lpthread -ldl -lz -lrt 
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -L$(Graal_Libs_Path) \
				-Wl,--whole-archive  -lsgx_uswitchless -Wl,--no-whole-archive \
				-Wl,--start-group $(Graal_Libs) -Wl,--end-group -l$(Urts_Library_Name) $(Memcached_Libs) -lpthread -ldl -lz -lrt


App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := async-sgx

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto


Enclave_Cpp_Files := Enclave/Enclave.cpp $(GraalSGX_Cpp_Files_In) $(wildcard Enclave/*/*.cpp)
Enclave_Include_Paths := -IInclude -IEnclave $(Graal_Include_Path) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fno-stack-protector 
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	#Enclave_C_Flags += -fstack-protector
else
	#Enclave_C_Flags += -fstack-protector-strong
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -fpermissive #-nostdinc++ 

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L$(Graal_Libs_Path) \
	-Wl,--whole-archive -lsgx_tswitchless -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(Graal_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=Enclave/Enclave.lds 
	
Enclave_Cpp_Objects := $(sort $(Enclave_Cpp_Files:.cpp=.o))




Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."


else
target: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif

endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)



####### Build Memcached Objects ######

$(Memcached_Src_In)/%.o: $(Memcached_Src_In)/%.c $(Memcached_Headers_In)
		$(CC)  $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) $(Memcached_Inc_Paths) -c $< -o $@
		@echo "CC <= $<"

$(Memcached_Src_Out)/%.o: $(Memcached_Src_Out)/%.c $(Memcached_Headers_Out)
		$(CC)  $(SGX_COMMON_CFLAGS) $(App_C_Flags) -I$(Memcached_Src_Out) -c $< -o $@
		@echo "CC <= $<"


####### Build Kyoto Objects ######

$(Kyoto_Src_In)/%.o: $(Kyoto_Src_In)/%.cc $(Kyoto_Headers_In)
		$(CXX)  $(SGX_COMMON_CFLAGS) $(Enclave_Cpp_Flags) $(Kyoto_Inc_Paths) -c $< -o $@
		@echo "CXX <= $<"

$(Kyoto_Src_Out)/%.o: $(Kyoto_Src_Out)/%.cc $(Kyoto_Headers_Out)
		$(CXX)  $(SGX_COMMON_CFLAGS) $(App_Cpp_Flags) -I$(Kyoto_Src_Out) -c $< -o $@


####### Build Lmbench Objects ######

$(Lmbench_Src_In)/%.o: $(Lmbench_Src_In)/%.c $(Lmbench_Headers_In)
		$(CC)  $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) $(Lmbench_Inc_Paths) -c $< -o $@
		@echo "CXX <= $<"




######## App Objects ########

App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.c: App/Enclave_u.h

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp  App/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) $(Graal_Objects_Out) $(Memcached_Objs_Out) $(Kyoto_Objs_Out)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects #######

Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


#Enclave/graalsgx.o: $(Graal_Objects_In) Enclave/Enclave.o 

prot: $(Signed_Enclave_Name)

$(Enclave_Name): Enclave/Enclave_t.o  $(Enclave_Cpp_Objects) $(Graal_Objects_In) $(Memcached_Objs_In) $(Kyoto_Objs_In) $(Lmbench_Objs_In) 
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* \
	$(Memcached_Objs_In) $(Memcached_Objs_Out) $(Kyoto_Objs_In) $(Kyoto_Objs_Out) $(Lmbench_Objs_In) 
