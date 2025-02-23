CC = gcc
CFLAGS = -Wall -Wextra $(shell mariadb_config --cflags) -I. -Isrc
LDFLAGS = $(shell mariadb_config --libs) -lssl -lcrypto -lmicrohttpd -ljansson

# Directories
SRC_DIR = src
BUILD_DIR = build

# Source files (explicitly list all source files)
SRCS = src/main.c \
       src/infrastructure/database/mysql.c \
       src/infrastructure/auth/jwt.c \
       src/interfaces/http/server.c \
       src/interfaces/http/auth_handler.c

# Generate object files list
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Main target
TARGET = $(BUILD_DIR)/rest_api

.PHONY: all clean directories

all: directories $(TARGET)

directories:
	@mkdir -p $(BUILD_DIR)/infrastructure/database
	@mkdir -p $(BUILD_DIR)/infrastructure/auth
	@mkdir -p $(BUILD_DIR)/interfaces/http

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Pattern rule for object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
