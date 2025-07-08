CC ?= $(CROSS_COMPILE)gcc 
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -I/ -lpthread


all: aesdsocket

aesdsocket: aesdsocket.o

aesdsocket.o: aesdsocket.c

clean:
	rm -rf aesdsocket.o aesdsocket 
