	CC=g++
	CFLAGS=-I./includes/cryptopp -L./includes/cryptopp -lcryptopp

all:
	$(CC) $(CFLAGS) atm.cpp -o atm
	$(CC) $(CFLAGS) proxy.cpp -o proxy -lpthread
	$(CC) $(CFLAGS) bank.cpp -o bank -lpthread