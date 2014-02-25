RM = rm -f
CC = gcc
LD = gcc
CFLAGS += -O0 -g -Wunused -Winline -Wtype-limits -Wcast-align
LDFLAGS +=
LDLIBS += -luuid

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%: %.o
	$(LD) $(LDFLAGS) $^ $(LDLIBS) -o $@

shfs-mkfs: shfs-mkfs.o tools-common.o

all: shfs-mkfs

clean:
	$(RM) *.o *~ core shfs-mkfs
