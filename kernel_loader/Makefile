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
SHARED_EXT := .dll
else
MKDIR_BUILD := mkdir -p "$(BUILD_ROOT)"
MKDIR_OBJ := mkdir -p "$(OBJ_DIR)"
MKDIR_BIN := mkdir -p "$(BIN_DIR)"
MKDIR_LIB := mkdir -p "$(LIB_DIR)"
RM_F := rm -f
RMDIR := rm -rf
SHARED_EXT := .so
endif

ifeq ($(origin CC),default)
CC := gcc
endif
AR ?= ar

OPENCL_LIBS ?= -lOpenCL
OPENCL_TARGET_VERSION ?= 120
OPENCL_CFLAGS ?= -DCL_TARGET_OPENCL_VERSION=$(OPENCL_TARGET_VERSION)
STRICT ?= 0

ifeq ($(OS),Windows_NT)
PIC :=
else
PIC := -fPIC
endif

CFLAGS := -std=c99 -O2 -Wall -Wextra -Iinclude $(OPENCL_CFLAGS) -DKERNEL_LOADER_BUILD_DLL $(PIC)
ifeq ($(STRICT),1)
CFLAGS += -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
endif
LDFLAGS :=

ifeq ($(OS),Windows_NT)
LDFLAGS += -static-libgcc
endif

SRC := src/kernel_loader.c
OBJ := $(OBJ_DIR)/kernel_loader.o

LIB_STATIC := $(LIB_DIR)/libkernel_loader.a

ifeq ($(OS),Windows_NT)
SHARED_LIB := $(BIN_DIR)/kernel_loader$(SHARED_EXT)
IMPORT_LIB := $(LIB_DIR)/libkernel_loader.dll.a
IMPORT_LIB_WIN := $(subst /,\,$(IMPORT_LIB))
else
SHARED_LIB := $(BIN_DIR)/libkernel_loader$(SHARED_EXT)
IMPORT_LIB :=
endif

.PHONY: all shared lib clean build_dirs

all: lib shared

build_dirs:
	$(MKDIR_BUILD)
	$(MKDIR_OBJ)
	$(MKDIR_BIN)
	$(MKDIR_LIB)

$(OBJ_DIR)/%.o: src/%.c build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

lib: $(LIB_STATIC)

$(LIB_STATIC): build_dirs $(OBJ)
	$(AR) rcs $(LIB_STATIC) $(OBJ)

shared: $(SHARED_LIB)

ifeq ($(OS),Windows_NT)
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) -Wl,--out-implib,$(IMPORT_LIB_WIN) -Wl,--export-all-symbols $(LDFLAGS) $(OPENCL_LIBS)
else
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) $(LDFLAGS) $(OPENCL_LIBS)
endif

clean:
ifeq ($(OS),Windows_NT)
	-$(RM_F) "$(OBJ_DIR_WIN)\*.o" 2>nul
	-$(RM_F) "$(BIN_DIR_WIN)\*.dll" 2>nul
	-$(RM_F) "$(LIB_DIR_WIN)\*.a" 2>nul
	-$(RMDIR) "$(BUILD_ROOT_WIN)" 2>nul
else
	-$(RM_F) $(OBJ_DIR)/*.o
	-$(RM_F) $(BIN_DIR)/*
	-$(RM_F) $(LIB_DIR)/*.a
	-$(RMDIR) $(BUILD_ROOT)
endif
