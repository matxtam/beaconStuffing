CC = clang
CFLAGS = -Wall -Werror -O3
LDFLAGS = -lwifi -lpcap

# Default target
all: main.o ./../bcstf/bcstf.o
	$(CC) $(CFLAGS) -o main main.o ./../bcstf/bcstf.o $(LDFLAGS)

main.o: ./main.c ./../bcstf/bcstf.h
	$(CC) $(CFLAGS) -c ./main.c -o main.o

./../bcstf/bcstf.o: ./../bcstf/bcstf.c ./../bcstf/bcstf.h
	$(CC) $(CFLAGS) -c ./../bcstf/bcstf.c -o ./../bcstf/bcstf.o

# Clean built files
clean:
	rm -f main *.o
