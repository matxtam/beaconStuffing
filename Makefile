CC = clang
CFLAGS = -Wall -Werror -O3
LDFLAGS = -lwifi -lpcap

# Default target
all: send recv

send: send.o bcstf.o
	$(CC) $(CFLAGS) -o send send.o bcstf.o $(LDFLAGS)

recv: recv.o bcstf.o
	$(CC) $(CFLAGS) -o recv recv.o bcstf.o $(LDFLAGS)

send.o: ./src/send.c ./bcstf/bcstf.h
	$(CC) $(CFLAGS) -c ./src/send.c -o send.o

recv.o: ./src/recv.c ./bcstf/bcstf.h
	$(CC) $(CFLAGS) -c ./src/recv.c -o recv.o

# Compile bcstf.o from bcstf.c
bcstf.o: ./bcstf/bcstf.c ./bcstf/bcstf.h
	$(CC) $(CFLAGS) -c ./bcstf/bcstf.c -o bcstf.o

# Clean built files
clean:
	rm -f send recv *.o
