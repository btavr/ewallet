######## SGX SDK Settings ########
# ALTERAÇÃO 1: Configuração do SGX SDK
# Esta secção foi adicionada para configurar o ambiente SGX necessário para compilar

# SGX_SDK deve apontar para o diretório de instalação do Intel SGX SDK
# O operador ?= permite sobrescrever esta variável ao executar make (ex: make SGX_SDK=/outro/caminho)
SGX_SDK ?= /opt/sgxsdk
# SGX_MODE define o modo de execução: HW (hardware) ou SIM (simulação)
SGX_MODE ?= HW
# SGX_ARCH define a arquitetura: x64 (64-bit) ou x86 (32-bit)
SGX_ARCH ?= x64

# Inclui o Makefile comum do SGX SDK que define variáveis importantes como:
# - SGX_COMMON_CFLAGS: flags de compilação comuns
# - CC: compilador C
# - SGX_EDGER8R: compilador EDL
# - SGX_LIBRARY_PATH: caminho para as bibliotecas SGX
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
# ALTERAÇÃO 2.2: Adiciona o ficheiro objeto gerado pelo EDL à lista de objetos
# O ficheiro enclave_u.o contém as funções stub (ponteiros) para chamar o enclave
App_C_Objects += $(APP_OBJDIR)/enclave_u.o

# ALTERAÇÃO 2.1: EDL Settings - ficheiros gerados pelo compilador EDL
# O EDL (Enclave Definition Language) define a interface entre a aplicação e o enclave
Enclave_EDL := $(APP_DIR)/enclave/conf/enclave.edl  # Ficheiro fonte EDL
Enclave_EDL_U := $(APP_OBJDIR)/enclave_u.c         # Ficheiro C gerado (untrusted)
Enclave_EDL_U_H := $(APP_OBJDIR)/enclave_u.h       # Ficheiro header gerado (untrusted)

# ALTERAÇÃO 2.3: Adiciona o diretório de objetos aos paths de include
# Isto permite que o compilador encontre o ficheiro enclave_u.h gerado
App_Include_Paths := -I$(APP_INCDIR) -I$(APP_OBJDIR) -I$(SGX_SDK)/include

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Debug configuration mode - Macro DEBUG enabled
App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG

App_Cpp_Flags := $(App_C_Flags)

App_Link_Flags := -lm

.PHONY: all target run
all:
	@$(MAKE) target

target: $(APP_BINDIR)/$(APP_NAME)

run: all
	@cd $(APP_BINDIR) && ./$(APP_NAME)
	@echo "RUN  =>  $(APP_NAME) [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## EDL Compilation ########
# ALTERAÇÃO 2.4 e 2.5: Regras para compilar o EDL
# O compilador EDL (sgx_edger8r) gera código C a partir do ficheiro .edl

# ALTERAÇÃO 2.4: Gera os ficheiros untrusted (enclave_u.h e enclave_u.c) a partir do EDL
# --untrusted: gera código para a aplicação (untrusted side)
# --search-path: diretórios onde procurar ficheiros incluídos no EDL
# --untrusted-dir: diretório onde colocar os ficheiros gerados
$(Enclave_EDL_U): $(Enclave_EDL)
	@mkdir -p $(APP_OBJDIR)
	@$(SGX_EDGER8R) --untrusted $(Enclave_EDL) --search-path $(SGX_SDK)/include --search-path $(APP_DIR)/enclave/conf --untrusted-dir $(APP_OBJDIR)
	@echo "EDL  =>  $@"

# ALTERAÇÃO 2.5: Compila o ficheiro enclave_u.c gerado pelo EDL
# Este ficheiro contém as funções stub que permitem à aplicação chamar o enclave
$(APP_OBJDIR)/enclave_u.o: $(Enclave_EDL_U)
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

######## App Objects ########

# ALTERAÇÃO 2.6: Adiciona dependência de enclave_u.h
# Garante que o ficheiro enclave_u.h é gerado antes de compilar app.c
# Isto resolve o erro "enclave_u.h: No such file or directory"
$(APP_OBJDIR)/%.o: $(APP_SRCDIR)/%.c $(Enclave_EDL_U_H)
	@mkdir -p $(APP_OBJDIR)
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

# ALTERAÇÃO 2.7: Cria o diretório bin se não existir
$(APP_BINDIR)/$(APP_NAME): $(App_C_Objects)
	@mkdir -p $(APP_BINDIR)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean
clean:
	# ALTERAÇÃO 2.8: Remove também os ficheiros gerados pelo EDL durante a limpeza
	@rm -f $(APP_BINDIR)/$(APP_NAME) $(App_C_Objects) $(APP_OBJDIR)/enclave_u.*
	@echo "Cleanup complete!"
