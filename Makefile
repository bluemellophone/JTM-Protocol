	CC=g++
	CFLAGS=-I./includes/cryptopp/ -L./includes/cryptopp/ -lcryptopp -m32

all:
	$(CC) atm.cpp $(CFLAGS) -o atm 
	$(CC) proxy.cpp $(CFLAGS) -o proxy -lpthread
	$(CC) bank.cpp $(CFLAGS) -o bank -lpthread
