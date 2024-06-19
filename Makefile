# SPDX-License-Identifier: MIT

CC := clang
CXX := clang++
LD := lld

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

SRC_DIR := src
SRCS := $(wildcard $(SRC_DIR)/*.cc)

BUILD_DIR := build
OBJS := $(SRCS:$(SRC_DIR)/%.cc=$(BUILD_DIR)/%.o)
BUILD_BIN := $(BUILD_DIR)/ebpf_objdump

SUBMODULE_DIR := submodule

LIBBPF_DIR := $(SUBMODULE_DIR)/libbpf
LIBBPF_SRC := $(LIBBPF_DIR)/src
LIBBPF_LIB := $(LIBBPF_DIR)/src

INCLUDES := -I$(SRC_DIR) -I$(LIBBPF_SRC)

CXXFLAGS := -O2 -Wall -std=c++23 -stdlib=libc++ $(INCLUDES)
LDFLAGS := -Wl,-rpath,$(ROOT_DIR)$(LIBBPF_LIB) -L$(LIBBPF_LIB) -lbpf -lelf -fuse-ld=$(LD)

.PHONY: all clean
all: $(BUILD_BIN)

clean:
	@rm -rf $(BUILD_DIR)

$(BUILD_BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cc
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<
