CC = gcc
CFLAGS = -Wall -Wextra -pthread -I./include
TARGET = router
SRCDIR = src
OBJDIR = obj
TARGETDIR = bin

# SRCS = $(SRCDIR)/main.c \
#        $(SRCDIR)/routing_table.c \
#        $(SRCDIR)/arp.c \
#        $(SRCDIR)/checksum.c \
#        $(SRCDIR)/logger.c \
#        $(SRCDIR)/cli.c

SRCS:=$(wildcard $(SRCDIR)/*.c)

OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(TARGETDIR)
	$(CC) $(CFLAGS) -o $(TARGETDIR)/$@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGETDIR)$(TARGET) logs/*.log

.PHONY: all clean 