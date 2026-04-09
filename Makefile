CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS    = -lssl -lcrypto

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LIBS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LIBS)

clean:
	rm -f server client logs.txt

.PHONY: all clean
