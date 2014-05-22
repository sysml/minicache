RM = rm -f
CC = gcc
LD = gcc
CFLAGS += -O0 -g -Wunused -Winline -Wtype-limits -Wcast-align
LDFLAGS +=
LDLIBS += -lxenstore

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%: %.o
	$(LD) $(LDFLAGS) $^ $(LDLIBS) -o $@

ctltrigger: ctltrigger.o

all: ctltrigger

clean:
	$(RM) *.o core ctltrigger
