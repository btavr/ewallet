######## SGX SDK Settings ########
SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_LIBDIR := $(SGX_SDK)/lib64

include $(SGX_SDK)/buildenv.mk

######## App Settings ########

APP_NAME   := ewallet
APP_DIR    := application
APP_SRCDIR := $(APP_DIR)/src
APP_INCDIR := $(APP_DIR)/inc
APP_OBJDIR := $(APP_DIR)/obj
APP_BINDIR := $(APP_DIR)/bin

App_C_Files := $(wildcard $(APP_SRCDIR)/*.c)
App_C_Objects := $(App_C_Files:$(APP_SRCDIR)/%.c=$(APP_OBJDIR)/%.o)
App_C_Objects += $(APP_OBJDIR)/enclave_u.o

Enclave_EDL := $(APP_DIR)/enclave/conf/enclave.edl
Enclave_EDL_U := $(APP_OBJDIR)/enclave_u.c
Enclave_EDL_U_H := $(APP_OBJDIR)/enclave_u.h

App_Include_Paths := -I$(APP_INCDIR) -I$(APP_OBJDIR) -I$(SGX_SDK)/include

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)
App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG

ifeq ($(SGX_MODE), HW)
	Urts_Library := sgx_urts
	Uae_Service_Library := sgx_uae_service
	Trts_Library := sgx_trts
	Service_Library := sgx_tservice
else
	Urts_Library := sgx_urts_sim
	Uae_Service_Library := sgx_uae_service_sim
	Trts_Library := sgx_trts_sim
	Service_Library := sgx_tservice_sim
endif
Trts_Library_Path := $(SGX_LIBDIR)/lib$(Trts_Library).a
Service_Library_Path := $(SGX_LIBDIR)/lib$(Service_Library).a
Tstdc_Library_Path := $(SGX_LIBDIR)/libsgx_tstdc.a
Tcxx_Library_Path := $(SGX_LIBDIR)/libsgx_tcxx.a
Tcrypto_Library_Path := $(SGX_LIBDIR)/libsgx_tcrypto.a

App_Link_Flags := -L$(SGX_LIBDIR) -L$(SGX_LIBRARY_PATH) -Wl,--no-as-needed -l$(Urts_Library) -l$(Uae_Service_Library) -lpthread -lm -ldl

######## Enclave Settings ########

ENCLAVE_DIR := $(APP_DIR)/enclave
ENCLAVE_SRCDIR := $(ENCLAVE_DIR)/src
ENCLAVE_INCDIR := $(ENCLAVE_DIR)/inc
ENCLAVE_CONFDIR := $(ENCLAVE_DIR)/conf
ENCLAVE_OBJDIR := $(ENCLAVE_DIR)/obj

Enclave_C_Files := $(wildcard $(ENCLAVE_SRCDIR)/*.c)
Enclave_C_Objects := $(Enclave_C_Files:$(ENCLAVE_SRCDIR)/%.c=$(ENCLAVE_OBJDIR)/%.o)

Enclave_Include_Paths := -I$(ENCLAVE_INCDIR) -I$(ENCLAVE_SRCDIR) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -Wa,--noexecstack $(Enclave_Include_Paths)
Enclave_C_Flags += -fno-builtin-printf -I.

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBDIR) -L$(SGX_LIBRARY_PATH) \
	-Wl,-Bsymbolic-functions -Bstatic \
	-Wl,--whole-archive $(Trts_Library_Path) -Wl,--no-whole-archive \
	-Wl,--start-group $(Tstdc_Library_Path) $(Tcxx_Library_Path) $(Tcrypto_Library_Path) $(Service_Library_Path) -Wl,--end-group \
	-Wl,-pie,-eenclave_entry \
	-Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,-z,noexecstack \
	-Wl,--version-script=$(ENCLAVE_CONFDIR)/enclave.lds

Enclave_Name := enclave.so
Enclave_Signed_Name := enclave.signed.so
Enclave_Config_File := $(ENCLAVE_CONFDIR)/enclave.config.xml
Enclave_Key := $(ENCLAVE_CONFDIR)/enclave_private.pem

SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign

.PHONY: all target run clean

all:
	@$(MAKE) target

target: $(Enclave_EDL_U_H) $(APP_BINDIR)/$(APP_NAME) $(ENCLAVE_DIR)/$(Enclave_Signed_Name)

run: all
	@cd $(APP_BINDIR) && ./$(APP_NAME)
	@echo "RUN  =>  $(APP_NAME) [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## EDL Compilation ########

EDGER8R := $(if $(SGX_EDGER8R),$(SGX_EDGER8R),$(SGX_SDK)/bin/x64/sgx_edger8r)

$(Enclave_EDL_U): $(Enclave_EDL)
	@mkdir -p $(APP_OBJDIR)
	@$(EDGER8R) --untrusted $(Enclave_EDL) \
		--search-path $(SGX_SDK)/include \
		--search-path $(ENCLAVE_CONFDIR) \
		--untrusted-dir $(APP_OBJDIR)
	@echo "EDL (U) => $@"

$(Enclave_EDL_U_H): $(Enclave_EDL_U)

$(APP_OBJDIR)/enclave_u.o: $(Enclave_EDL_U) $(Enclave_EDL_U_H)
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

######## App Objects ########

$(APP_OBJDIR)/%.o: $(APP_SRCDIR)/%.c $(Enclave_EDL_U_H)
	@mkdir -p $(APP_OBJDIR)
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(APP_BINDIR)/$(APP_NAME): $(App_C_Objects)
	@mkdir -p $(APP_BINDIR)
	$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Build ########

Enclave_EDL_T_C := $(ENCLAVE_SRCDIR)/enclave_t.c
Enclave_EDL_T_H := $(ENCLAVE_SRCDIR)/enclave_t.h

$(Enclave_EDL_T_C): $(Enclave_EDL)
	@mkdir -p $(ENCLAVE_SRCDIR)
	@$(EDGER8R) --trusted $(Enclave_EDL) \
		--search-path $(SGX_SDK)/include \
		--search-path $(ENCLAVE_CONFDIR) \
		--trusted-dir $(ENCLAVE_SRCDIR)
	@echo "EDL (T) => $@"

$(Enclave_EDL_T_H): $(Enclave_EDL_T_C)

$(ENCLAVE_OBJDIR)/enclave_t.o: $(Enclave_EDL_T_C)
	@mkdir -p $(ENCLAVE_OBJDIR)
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_OBJDIR)/%.o: $(ENCLAVE_SRCDIR)/%.c $(Enclave_EDL_T_H)
	@mkdir -p $(ENCLAVE_OBJDIR)
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/$(Enclave_Name): $(Enclave_C_Objects) $(ENCLAVE_OBJDIR)/enclave_t.o
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(ENCLAVE_DIR)/$(Enclave_Signed_Name): $(ENCLAVE_DIR)/$(Enclave_Name)
	@if [ ! -f $(Enclave_Key) ]; then openssl genrsa -out $(Enclave_Key) -3 3072; fi
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Key) -enclave $(ENCLAVE_DIR)/$(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

clean:
	@rm -f $(APP_BINDIR)/$(APP_NAME) $(App_C_Objects) $(APP_OBJDIR)/enclave_u.*
	@rm -f $(ENCLAVE_DIR)/$(Enclave_Name) $(ENCLAVE_DIR)/$(Enclave_Signed_Name) $(Enclave_C_Objects) $(ENCLAVE_OBJDIR)/enclave_t.* $(ENCLAVE_SRCDIR)/enclave_t.c $(ENCLAVE_SRCDIR)/enclave_t.h
	@echo "Cleanup complete!"