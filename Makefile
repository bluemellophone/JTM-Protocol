	CC=g++
	CFLAGS=-m32

all:
	$(CC) atm.cpp -o atm $(CFLAGS)
	$(CC) proxy.cpp -o proxy -lpthread $(CFLAGS)
	$(CC) bank.cpp -o bank -lpthread $(CFLAGS)
