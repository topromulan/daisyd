
CC=gcc
CFLAGS=-Wall -O3 #-g 
LDFLAGS=-lcrypto -lssl

daisyd: daisyd.o daisy.o daisy_client.o daisy_catch_sigchld.o err.o



clean:
	rm -f *.o daisyd


backup:
	tar cjf ${HOME}/backup/daisyd-`date +%s`.tbz2 *.[ch] Makefile && (ls -lrt ~/backup/daisyd-* | tail -1 )
