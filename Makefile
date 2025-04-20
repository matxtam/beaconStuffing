CC=clang
CFLAGS=-Wall -Werror -O3 -o sender_a.out
LDFLAGS=-lwifi -lpcap

all: sender_a.out
	$(CC) $(CFLAGS) ./src/send_realframe.c $(LDFLAGS)
	
clean:
	rm sender_a.out 
