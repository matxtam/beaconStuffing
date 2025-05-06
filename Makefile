CC = clang
CFLAGS = -Wall -Werror -O3
LDFLAGS = -lwifi -lpcap

# Default target
all: main

# Build the main executable by linking object files
main: main.o bcstf.o
	$(CC) $(CFLAGS) -o main main.o bcstf.o $(LDFLAGS)

# Compile main.o from main.c
main.o: ./src/main.c ./src/bcstf.h
	$(CC) $(CFLAGS) -c ./src/main.c -o main.o

# Compile bcstf.o from bcstf.c
bcstf.o: ./src/bcstf.c ./src/bcstf.h
	$(CC) $(CFLAGS) -c ./src/bcstf.c -o bcstf.o

# Clean built files
clean:
	rm -f main main.o bcstf.o
