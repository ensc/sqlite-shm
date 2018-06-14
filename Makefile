CFLAGS = -std=gnu99 -Wall -W -Wno-unused-parameter

all:	libsqlite-shm.so

libsqlite-shm.so:	sqlite-shm.c md5.c md5.h
	$(CC) $(CFLAGS) ${LDFLAGS} -fPIC -shared  $(filter %.c,$^) -o $@ -ldl
