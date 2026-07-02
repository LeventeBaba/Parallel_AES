ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
.SHELLFLAGS := /C
else
SHELL := /bin/sh
.SHELLFLAGS := -c
endif

BUILD_SUBDIR ?=
BUILD_ROOT := build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR),)
OBJ_DIR := $(BUILD_ROOT)/obj
BIN_DIR := $(BUILD_ROOT)/bin
LIB_DIR := $(BUILD_ROOT)/lib
BUILD_ROOT_WIN := $(subst /,\,$(BUILD_ROOT))
OBJ_DIR_WIN := $(subst /,\,$(OBJ_DIR))
BIN_DIR_WIN := $(subst /,\,$(BIN_DIR))
LIB_DIR_WIN := $(subst /,\,$(LIB_DIR))

ifeq ($(OS),Windows_NT)
MKDIR_BUILD := if not exist "$(BUILD_ROOT_WIN)" mkdir "$(BUILD_ROOT_WIN)"
MKDIR_OBJ := if not exist "$(OBJ_DIR_WIN)" mkdir "$(OBJ_DIR_WIN)"
MKDIR_BIN := if not exist "$(BIN_DIR_WIN)" mkdir "$(BIN_DIR_WIN)"
MKDIR_LIB := if not exist "$(LIB_DIR_WIN)" mkdir "$(LIB_DIR_WIN)"
RM_F := del /Q
RMDIR := rmdir /S /Q
EXE := .exe
SHARED_EXT := .dll
COPY_KERNELS := if not exist "$(BIN_DIR_WIN)\kernels" mkdir "$(BIN_DIR_WIN)\kernels"
COPY_KERNELS += & copy /Y kernels\*.cl "$(BIN_DIR_WIN)\kernels" >nul
else
MKDIR_BUILD := mkdir -p "$(BUILD_ROOT)"
MKDIR_OBJ := mkdir -p "$(OBJ_DIR)"
MKDIR_BIN := mkdir -p "$(BIN_DIR)"
MKDIR_LIB := mkdir -p "$(LIB_DIR)"
RM_F := rm -f
RMDIR := rm -rf
EXE :=
SHARED_EXT := .so
COPY_KERNELS := mkdir -p "$(BIN_DIR)/kernels" && cp -f kernels/*.cl "$(BIN_DIR)/kernels/"
endif

ifeq ($(origin CC),default)
CC := gcc
endif
AR ?= ar

PROF ?= 0
FAST ?= 0
STRICT ?= 0

OPENCL_LIBS ?= -lOpenCL
OPENCL_TARGET_VERSION ?= 120
OPENCL_CFLAGS ?= -DCL_TARGET_OPENCL_VERSION=$(OPENCL_TARGET_VERSION)

AESLIB_DIR := ../aeslib
KERNEL_LOADER_DIR := ../kernel_loader

CFLAGS_BASE := -std=c99 -O2 -Wall -Wextra -Iinclude -I$(AESLIB_DIR)/include -I$(KERNEL_LOADER_DIR)/include $(OPENCL_CFLAGS) -DCRYPTO_OPENCL_BUILD_DLL

ifeq ($(FAST),1)
MARCH ?= native
CFLAGS_BASE := -std=c99 -O3 -march=$(MARCH) -fomit-frame-pointer -funroll-loops -Wall -Wextra -Iinclude -I$(AESLIB_DIR)/include -I$(KERNEL_LOADER_DIR)/include $(OPENCL_CFLAGS) -DCRYPTO_OPENCL_BUILD_DLL
endif

ifeq ($(STRICT),1)
CFLAGS_BASE += -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
endif

LDFLAGS :=

ifeq ($(OS),Windows_NT)
LDFLAGS += -static-libgcc
endif

ifeq ($(PROF),1)
CFLAGS_BASE += -DCRYPTO_OCL_PROFILE
endif

ifeq ($(OS),Windows_NT)
PIC :=
else
PIC := -fPIC
endif

CFLAGS := $(CFLAGS_BASE) $(PIC)

ifeq ($(OS),Windows_NT)
DEPS_LD_DIRS := -L$(AESLIB_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/lib -L$(KERNEL_LOADER_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/lib
DEPS_LD_LIBS := -lcrypto_aes -lkernel_loader
AESLIB_DLL := $(AESLIB_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/bin/crypto_aes$(SHARED_EXT)
KERNEL_LOADER_DLL := $(KERNEL_LOADER_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/bin/kernel_loader$(SHARED_EXT)
AESLIB_DLL_WIN := $(subst /,\,$(AESLIB_DLL))
KERNEL_LOADER_DLL_WIN := $(subst /,\,$(KERNEL_LOADER_DLL))
IMPORT_LIB_WIN := $(subst /,\,$(LIB_DIR)/libcrypto_aes_opencl.dll.a)
RPATH_LDFLAGS :=
else
DEPS_LD_DIRS := -L$(AESLIB_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/bin -L$(KERNEL_LOADER_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/bin
DEPS_LD_LIBS := -lcrypto_aes -lkernel_loader
AESLIB_DLL := $(AESLIB_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/bin/libcrypto_aes$(SHARED_EXT)
KERNEL_LOADER_DLL := $(KERNEL_LOADER_DIR)/build$(if $(BUILD_SUBDIR),/$(BUILD_SUBDIR))/bin/libkernel_loader$(SHARED_EXT)
RPATH_LDFLAGS := -Wl,-rpath,'$$ORIGIN'
endif

DEPS_LDFLAGS := $(DEPS_LD_DIRS) $(DEPS_LD_LIBS) $(RPATH_LDFLAGS)

SRC := src/opencl_aes_ctr.c src/crypto_ffi_opencl.c src/crypto_ocl_profile.c
OBJ := $(OBJ_DIR)/opencl_aes_ctr.o $(OBJ_DIR)/crypto_ffi_opencl.o $(OBJ_DIR)/crypto_ocl_profile.o

LIB_STATIC := $(LIB_DIR)/libcrypto_aes_opencl.a

TEST_SRC := tests/test_opencl_aes.c
TEST_OBJ := $(OBJ_DIR)/test_opencl_aes.o
TEST_BIN := $(BIN_DIR)/test_opencl_aes$(EXE)

BENCH_SRC := tests/bench_opencl_aes.c
BENCH_OBJ := $(OBJ_DIR)/bench_opencl_aes.o
BENCH_BIN := $(BIN_DIR)/bench_opencl_aes$(EXE)

PROFILE_SRC := tests/profile_opencl_aes.c
PROFILE_OBJ := $(OBJ_DIR)/profile_opencl_aes.o
PROFILE_BIN := $(BIN_DIR)/profile_opencl_aes$(EXE)

ifeq ($(OS),Windows_NT)
SHARED_LIB := $(BIN_DIR)/crypto_aes_opencl$(SHARED_EXT)
IMPORT_LIB := $(LIB_DIR)/libcrypto_aes_opencl.dll.a
else
SHARED_LIB := $(BIN_DIR)/libcrypto_aes_opencl$(SHARED_EXT)
IMPORT_LIB :=
endif

.PHONY: all deps copy_deps lib shared test bench profile copy_kernels clean build_dirs

.NOTPARALLEL: all deps copy_deps lib shared test bench copy_kernels

ifeq ($(PROF),1)
PROFILE_TARGET := profile
else
PROFILE_TARGET :=
endif

all:
	$(MAKE) deps BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
	$(MAKE) lib BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
	$(MAKE) shared BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
	$(MAKE) test BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
	$(MAKE) bench BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
ifeq ($(PROF),1)
	$(MAKE) profile BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
endif
	$(MAKE) copy_kernels BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
	$(MAKE) copy_deps BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)

deps:
	$(MAKE) -C $(AESLIB_DIR) shared BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR)
	$(MAKE) -C $(KERNEL_LOADER_DIR) all BUILD_SUBDIR=$(BUILD_SUBDIR) CC=$(CC) AR=$(AR) OPENCL_CFLAGS="$(OPENCL_CFLAGS)" OPENCL_LIBS="$(OPENCL_LIBS)"

copy_deps: deps build_dirs

ifeq ($(OS),Windows_NT)
	if not exist "$(BIN_DIR_WIN)" mkdir "$(BIN_DIR_WIN)"
	if not exist "$(AESLIB_DLL_WIN)" (echo Missing dependency: $(AESLIB_DLL_WIN) & exit /b 1)
	if not exist "$(KERNEL_LOADER_DLL_WIN)" (echo Missing dependency: $(KERNEL_LOADER_DLL_WIN) & exit /b 1)
	copy /Y "$(AESLIB_DLL_WIN)" "$(BIN_DIR_WIN)\" >nul || exit /b 1
	copy /Y "$(KERNEL_LOADER_DLL_WIN)" "$(BIN_DIR_WIN)\" >nul || exit /b 1
else
	test -f $(AESLIB_DLL) || (echo "Missing dependency: $(AESLIB_DLL)"; exit 1)
	test -f $(KERNEL_LOADER_DLL) || (echo "Missing dependency: $(KERNEL_LOADER_DLL)"; exit 1)
	mkdir -p "$(BIN_DIR)"
	cp -f $(AESLIB_DLL) "$(BIN_DIR)/"
	cp -f $(KERNEL_LOADER_DLL) "$(BIN_DIR)/"
endif

build_dirs:
	$(MKDIR_BUILD)
	$(MKDIR_OBJ)
	$(MKDIR_BIN)
	$(MKDIR_LIB)

copy_kernels: build_dirs
	$(COPY_KERNELS)

lib: $(LIB_STATIC)

shared: deps $(SHARED_LIB) copy_kernels copy_deps

test: deps $(TEST_BIN) copy_kernels copy_deps

bench: deps $(BENCH_BIN) copy_kernels copy_deps

profile: deps $(PROFILE_BIN) copy_kernels copy_deps

$(LIB_STATIC): build_dirs $(OBJ)
	$(AR) rcs $(LIB_STATIC) $(OBJ)

$(OBJ_DIR)/%.o: src/%.c build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_OBJ): $(TEST_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(TEST_SRC) -o $(TEST_OBJ)

$(TEST_BIN): build_dirs $(LIB_STATIC) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) $(LIB_STATIC) -o $(TEST_BIN) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)

$(BENCH_OBJ): $(BENCH_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(BENCH_SRC) -o $(BENCH_OBJ)

$(BENCH_BIN): build_dirs $(LIB_STATIC) $(BENCH_OBJ)
	$(CC) $(CFLAGS) $(BENCH_OBJ) $(LIB_STATIC) -o $(BENCH_BIN) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)

$(PROFILE_OBJ): $(PROFILE_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(PROFILE_SRC) -o $(PROFILE_OBJ)

$(PROFILE_BIN): build_dirs $(LIB_STATIC) $(PROFILE_OBJ)
	$(CC) $(CFLAGS) $(PROFILE_OBJ) $(LIB_STATIC) -o $(PROFILE_BIN) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)

ifeq ($(OS),Windows_NT)
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) -Wl,--out-implib,$(IMPORT_LIB_WIN) -Wl,--export-all-symbols $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)
else
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)
endif

clean:
ifeq ($(OS),Windows_NT)
	-$(RM_F) "$(OBJ_DIR_WIN)\*.o" 2>nul
	-$(RM_F) "$(BIN_DIR_WIN)\*$(EXE)" 2>nul
	-$(RM_F) "$(BIN_DIR_WIN)\*.dll" 2>nul
	-$(RM_F) "$(LIB_DIR_WIN)\*.a" 2>nul
	-$(RMDIR) "$(BUILD_ROOT_WIN)" 2>nul
else
	-$(RM_F) $(OBJ_DIR)/*.o
	-$(RM_F) $(BIN_DIR)/*
	-$(RM_F) $(LIB_DIR)/*.a
	-$(RM_F) $(BIN_DIR)/*.so
	-$(RMDIR) $(BUILD_ROOT)
endif
