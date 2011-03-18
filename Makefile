
CC=gcc
CFLAGS=-Wall -g 
LDFLAGS=-lcrypto -lssl

daisyd: daisyd.o daisy.o err.o



clean:
	rm -f *.o daisyd


backup:
	tar cjf ${HOME}/backup/daisyd-`date +%s`.tbz2 *.[ch] Makefile && (ls -lrt ~/backup/daisyd-* | tail -1 )
