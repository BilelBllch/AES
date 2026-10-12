CFLAGS   = -std=c11 -Wextra -Wall -O2
CPPFLAGS = -Iinclude

SRCDIR = src
OBJDIR = obj
BINDIR = bin

TARGET = $(BINDIR)/aes

OBJS = $(OBJDIR)/main.o $(OBJDIR)/io.o $(OBJDIR)/mode.o $(OBJDIR)/key.o $(OBJDIR)/aes.o

all: $(TARGET)

# Édition des liens
$(TARGET): $(OBJS)
	gcc $(CFLAGS) -o $@ $^

# Compilation
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	gcc $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Nettoyage
clean:
	@rm -f $(OBJDIR)/*.o
	@rm -f $(TARGET)

help:
	@echo -e "Makefile pour compiler les sources d'AES"
	@echo -e "Usage:\n\t make all : compile tout le projet\n\t make clean : nettoie les fichiers de build"

.PHONY: all clean help