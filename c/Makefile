CC=gcc
PARM=-Wall -l pcap -g
OUT_BIN=main

default:	clean build

build: main.c constants.h
	$(CC) $(PARM) *.h *.c -o main

clean:
	rm -rf main *.o

