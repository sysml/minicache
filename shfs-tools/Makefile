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

shfs_mkfs: shfs_mkfs.o tools_common.o

all: shfs_mkfs

clean:
	$(RM) *.o *~ core shfs_mkfs
