CFLAGS = -g -Wall -Wno-unused-function -Werror
LDFLAGS =
LDLIBS = -lgmp

# Configuration for user-installed libgmp.
CFLAGS += -I$(HOME)/gmp/include
LDFLAGS += -L$(HOME)/gmp/lib

rsa: main.o rsa.o

main.o: main.c rsa.h
rsa.o: rsa.c rsa.h

clean:
	rm -f rsa *.o

.PHONY: clean
