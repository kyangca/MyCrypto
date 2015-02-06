CC = g++
CFLAGS = -Wall -g

all: test

util.o: util.cpp util.hpp
	$(CC) $(CFLAGS) -c util.cpp

aes.o: aes.cpp aes.hpp util.hpp
	$(CC) $(CFLAGS) -c aes.cpp

test: test.o util.o aes.o
	$(CC) $(CFLAGS) -o test test.o util.o aes.o

test.o: test.cpp util.hpp aes.hpp
	$(CC) $(CFLAGS) -c test.cpp

clean:
	rm -f *.o *~ util aes test

redo: clean all
