PROJ=cmuchac
CFLAGS=-std=gnu99 -Wall -Wextra
LDFLAGS=-lpcap
CC=gcc
RM=rm -f

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))

$(PROJ) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean :
	$(RM) *.o $(PROJ) 
