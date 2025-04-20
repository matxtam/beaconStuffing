CC=clang
CFLAGS=-Wall -Werror -O3 -o sender_a.out
LDFLAGS=-lwifi -lpcap

all: send.o
	$(CC) $(CFLAGS) ./src/send_clean.c $(LDFLAGS)
	
clean:
	rm send.o 
