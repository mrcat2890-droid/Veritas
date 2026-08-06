# ============================================================
#  Veritas Edition v3.1 — C Build
#  CSA Nebula Attack Framework
# ============================================================

CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -pthread -std=c11
LDFLAGS  = -lpthread -lm
TARGET   = veritas
SRC      = veritas.c

# Debug build
DEBUG_CFLAGS = -Wall -Wextra -g -O0 -pthread -std=c11 -DDEBUG -fsanitize=address

.PHONY: all clean debug install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo ""
	@echo "  \033[38;5;51m◆ Build complete: ./$(TARGET)\033[0m"
	@echo "  \033[38;5;244mUsage: sudo ./$(TARGET)\033[0m"
	@echo "  \033[38;5;244m       sudo ./$(TARGET) --script config.json\033[0m"
	@echo ""

debug: $(SRC)
	$(CC) $(DEBUG_CFLAGS) -o $(TARGET)_dbg $< $(LDFLAGS) -lasan
	@echo ""
	@echo "  \033[38;5;226m◆ Debug build: ./$(TARGET)_dbg\033[0m"
	@echo ""

clean:
	rm -f $(TARGET) $(TARGET)_dbg
	@echo "  \033[38;5;196m◇ Cleaned.\033[0m"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo "  \033[38;5;51m◆ Installed to /usr/local/bin/$(TARGET)\033[0m"
