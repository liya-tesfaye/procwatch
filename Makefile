CC = gcc
CFLAGS = -Wall -Wextra -std=c11

TARGET = procwatch
SRC = src/proc_scanner.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
