CC=clang
CFLAGS	 =-Wall -Werror -O3 -o send.o
CFLAGS_RX=-Wall -Werror -O3 -o sniff.o
LDFLAGS=-lwifi -lpcap

send: 
	$(CC) $(CFLAGS) ./src/send.c $(LDFLAGS)

sniff: 
	$(CC) $(CFLAGS_RX) ./src/sniffer.c $(LDFLAGS)
	
clean:
	rm send.o sniff.o
