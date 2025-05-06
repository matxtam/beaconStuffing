CC=clang
CFLAGS	 =-Wall -Werror -O3 -o main.o
LDFLAGS=-lwifi -lpcap

all:
	$(CC) $(CFLAGS) ./src/main.c $(LDFLAGS)
	
clean:
	rm main.o
