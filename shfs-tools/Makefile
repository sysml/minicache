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

shfs_admin: shfs_admin.o tools_common.o shfs_htable.o shfs_check.o

all: shfs_mkfs shfs_admin

clean:
	$(RM) *.o *~ core shfs_mkfs shfs_admin
