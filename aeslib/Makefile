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
else
MKDIR_BUILD := mkdir -p "$(BUILD_ROOT)"
MKDIR_OBJ := mkdir -p "$(OBJ_DIR)"
MKDIR_BIN := mkdir -p "$(BIN_DIR)"
MKDIR_LIB := mkdir -p "$(LIB_DIR)"
RM_F := rm -f
RMDIR := rm -rf
EXE :=
SHARED_EXT := .so
endif

ifeq ($(origin CC),default)
CC := gcc
endif
AR ?= ar

PROF ?= 0
GPROF ?= 0
FAST ?= 0
STRICT ?= 0

CFLAGS_BASE := -std=c99 -O2 -Wall -Wextra -Iinclude

ifeq ($(FAST),1)
MARCH ?= native
CFLAGS_BASE := -std=c99 -O3 -march=$(MARCH) -fomit-frame-pointer -funroll-loops -Wall -Wextra -Iinclude
endif

ifeq ($(STRICT),1)
CFLAGS_BASE += -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
endif

LDFLAGS :=

ifeq ($(OS),Windows_NT)
LDFLAGS += -static-libgcc
endif

ifeq ($(PROF),1)
CFLAGS_BASE += -DCRYPTO_PROFILE
endif

ifeq ($(GPROF),1)
CFLAGS_BASE += -pg
LDFLAGS += -pg
endif

ifeq ($(OS),Windows_NT)
PIC :=
else
PIC := -fPIC
endif

CFLAGS := $(CFLAGS_BASE) $(PIC)

SRC := src/aes.c src/aes_ctr.c src/aes_gcm.c src/cbc.c src/crypto_ctr_stream.c src/crypto_gcm_stream.c src/crypto_gf128.c src/crypto_padding.c src/crypto_timer.c src/crypto_profile.c src/crypto_ffi.c
OBJ := $(OBJ_DIR)/aes.o $(OBJ_DIR)/aes_ctr.o $(OBJ_DIR)/aes_gcm.o $(OBJ_DIR)/cbc.o $(OBJ_DIR)/crypto_ctr_stream.o $(OBJ_DIR)/crypto_gcm_stream.o $(OBJ_DIR)/crypto_gf128.o $(OBJ_DIR)/crypto_padding.o $(OBJ_DIR)/crypto_timer.o $(OBJ_DIR)/crypto_profile.o $(OBJ_DIR)/crypto_ffi.o

LIB_STATIC := $(LIB_DIR)/libcrypto_aes.a

TEST_SRC := tests/test_aes.c
TEST_OBJ := $(OBJ_DIR)/test_aes.o
TEST_BIN := $(BIN_DIR)/test_aes$(EXE)

BENCH_SRC := tests/bench_aes.c
BENCH_OBJ := $(OBJ_DIR)/bench_aes.o
BENCH_BIN := $(BIN_DIR)/bench_aes$(EXE)

PROFILE_SRC := tests/profile_aes.c
PROFILE_OBJ := $(OBJ_DIR)/profile_aes.o
PROFILE_BIN := $(BIN_DIR)/profile_aes$(EXE)

ifeq ($(OS),Windows_NT)
SHARED_LIB := $(BIN_DIR)/crypto_aes$(SHARED_EXT)
IMPORT_LIB := $(LIB_DIR)/libcrypto_aes.dll.a
IMPORT_LIB_WIN := $(subst /,\,$(IMPORT_LIB))
else
SHARED_LIB := $(BIN_DIR)/libcrypto_aes$(SHARED_EXT)
IMPORT_LIB :=
endif

.PHONY: all lib shared test bench profile clean build_dirs

ifeq ($(PROF),1)
PROFILE_TARGET := profile
else
PROFILE_TARGET :=
endif

all: lib shared test bench $(PROFILE_TARGET)

build_dirs:
	$(MKDIR_BUILD)
	$(MKDIR_OBJ)
	$(MKDIR_BIN)
	$(MKDIR_LIB)

lib: $(LIB_STATIC)

shared: $(SHARED_LIB)

test: $(TEST_BIN)

bench: $(BENCH_BIN)

profile: $(PROFILE_BIN)

$(LIB_STATIC): build_dirs $(OBJ)
	$(AR) rcs $(LIB_STATIC) $(OBJ)

$(OBJ_DIR)/%.o: src/%.c build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_OBJ): $(TEST_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(TEST_SRC) -o $(TEST_OBJ)

$(TEST_BIN): build_dirs $(LIB_STATIC) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) $(LIB_STATIC) -o $(TEST_BIN) $(LDFLAGS)

$(BENCH_OBJ): $(BENCH_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(BENCH_SRC) -o $(BENCH_OBJ)

$(BENCH_BIN): build_dirs $(LIB_STATIC) $(BENCH_OBJ)
	$(CC) $(CFLAGS) $(BENCH_OBJ) $(LIB_STATIC) -o $(BENCH_BIN) $(LDFLAGS)

$(PROFILE_OBJ): $(PROFILE_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(PROFILE_SRC) -o $(PROFILE_OBJ)

$(PROFILE_BIN): build_dirs $(LIB_STATIC) $(PROFILE_OBJ)
	$(CC) $(CFLAGS) $(PROFILE_OBJ) $(LIB_STATIC) -o $(PROFILE_BIN) $(LDFLAGS)

ifeq ($(OS),Windows_NT)
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) -Wl,--out-implib,$(IMPORT_LIB_WIN) -Wl,--export-all-symbols $(LDFLAGS)
else
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) $(LDFLAGS)
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
