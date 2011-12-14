CC=gcc
PARM= -Wall -pedantic
OUT_BIN=main

default:	clean build

build: main.c
	$(CC) $(PARM) main.c -o main

clean:
	rm -rf main *.o

