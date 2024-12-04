.PHONY: all clean

CC := ntox86_64-gcc
CFLAGS := -g -Wall -Werror -O0

OUTPUT_DIR = build
OBJECTS := $(addprefix $(OUTPUT_DIR)/,$(patsubst %.c, %, $(wildcard *.c)))
INCLUDES := $(wildcard *.h) Makefile

all: $(OBJECTS)

clean:
	rm -rf $(OUTPUT_DIR)

$(OBJECTS): $(OUTPUT_DIR)/% : %.c $(INCLUDES) | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)
