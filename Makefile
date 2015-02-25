CC = g++
CFLAGS = -Wall -g

all: test aes-cl

util.o: util.cpp util.hpp
	$(CC) $(CFLAGS) -c util.cpp

aes.o: aes.cpp aes.hpp util.hpp
	$(CC) $(CFLAGS) -c aes.cpp

aes-cl.o: aes-cl.cpp aes.hpp util.hpp
	$(CC) $(CFLAGS) -c aes-cl.cpp

aes-cl: aes-cl.o util.o aes.o
	$(CC) $(CLFAGS) -o aes-cl aes-cl.o util.o aes.o

test: test.o util.o aes.o
	$(CC) $(CFLAGS) -o test test.o util.o aes.o

test.o: test.cpp util.hpp aes.hpp
	$(CC) $(CFLAGS) -c test.cpp

clean:
	rm -f *.o *~ util aes test aes-cl

redo: clean all
