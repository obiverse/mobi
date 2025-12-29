# MobiNumber Protocol - Build System
# Copyright (c) 2024 OBIVERSE LLC

CC ?= cc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99 -O2
AR = ar
ARFLAGS = rcs

SRC_DIR = src
BUILD_DIR = build
LIB_NAME = libmobi.a

SRCS = $(SRC_DIR)/mobi.c
OBJS = $(BUILD_DIR)/mobi.o

.PHONY: all clean test

all: $(BUILD_DIR)/$(LIB_NAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/mobi.o: $(SRC_DIR)/mobi.c $(SRC_DIR)/mobi.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/$(LIB_NAME): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

# Test binary
$(BUILD_DIR)/test_mobi: test/test_mobi.c $(BUILD_DIR)/$(LIB_NAME) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -L$(BUILD_DIR) -lmobi -o $@

test: $(BUILD_DIR)/test_mobi
	./$(BUILD_DIR)/test_mobi

clean:
	rm -rf $(BUILD_DIR)

# Install to system (optional)
PREFIX ?= /usr/local
install: $(BUILD_DIR)/$(LIB_NAME)
	install -d $(PREFIX)/lib $(PREFIX)/include
	install -m 644 $(BUILD_DIR)/$(LIB_NAME) $(PREFIX)/lib/
	install -m 644 $(SRC_DIR)/mobi.h $(PREFIX)/include/
