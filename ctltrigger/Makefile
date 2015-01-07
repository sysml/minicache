RM = rm -f
CC = gcc
LD = gcc
CFLAGS += -O3 -g -Wunused -Wtype-limits
LDFLAGS +=
LDLIBS += -lxenstore

default: all

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%: %.o
	$(LD) $(LDFLAGS) $^ $(LDLIBS) -o $@

ctltrigger: ctltrigger.o

all: ctltrigger

clean:
	$(RM) *.o core ctltrigger
