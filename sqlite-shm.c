/*	--*- c -*--
 * Copyright (C) 2015 Enrico Scholz <enrico.scholz@ensc.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <fnmatch.h>
#include <dlfcn.h>
#include <sys/socket.h>

#define open	_libc_open
#define open64	_libc_open64
#define fcntl	_libc_fcntl
#define fcntl64	_libc_fcntl64
#include <fcntl.h>
#undef open
#undef open64
#undef fcntl
#undef fcntl64

#include "md5.h"

#define ARRAY_SIZE(_a)	(sizeof(_a) / sizeof(_a)[0])

#define debug(fmt, ...) do {						\
		if (0)							\
			fprintf(stderr, "  %s:%u " fmt "\n",		\
				__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

#define trace(fmt, ...) do {						\
		if (0)							\
			fprintf(stderr, "%s(" fmt ")\n",		\
				__func__, ##__VA_ARGS__);		\
	} while (0)

static bool has_suffix(char const *s, char const *sfx)
{
	size_t		l_s = s ? strlen(s) : 0;
	size_t		l_sfx = strlen(sfx);

	return l_s >= l_sfx && strcmp(s + l_s - l_sfx, sfx) == 0;
}

#define HEX_CHAR	"0123456789abcdef"

static char const *rt_dir = NULL;

static inline bool run_unittests(void)
{
#ifdef NDEBUG
	return false;
#else
	return true;
#endif
}

static char const *translate_path(char const *pathname, char **free_buf,
				  bool *is_db_)
{
	*free_buf = NULL;

	if (!pathname || !rt_dir ||
	    (!has_suffix(pathname, ".sqlite") &&
	     !has_suffix(pathname, ".sqlite-shm") &&
	     !has_suffix(pathname, ".sqlite-wal")))
		return pathname;

	char const	*p = strrchr(pathname, '/');

	bool		is_db = has_suffix(pathname, ".sqlite");

	if (is_db_)
		*is_db_ = is_db;

	if (p)
		p += 1;
	else
		p  = pathname;

	size_t		sfx_len =
		(is_db ? sizeof(".sqlite") : sizeof(".sqlite-wal")) - 1u;
	char const	*suffix = p + strlen(p) - sfx_len;
	size_t		l = suffix - p;
	char		basename[l + 1];
	char		dirname[p - pathname + 1];
	char const	*abs_dir;

	memcpy(basename, p, l);
	basename[l] = '\0';

	memcpy(dirname, pathname, p - pathname);
	dirname[p - pathname] = '\0';

	abs_dir = realpath(dirname, NULL);
	if (!abs_dir)
		return NULL;

	MD5_CTX		ctx;
	unsigned char	hash[16];
	char		hash_str[strlen(rt_dir) + 1 + 2 * sizeof hash + 1
				 + strlen(suffix) + sizeof ".lock"];
	char		*out = hash_str;
	size_t		i;

	MD5_Init(&ctx);
	MD5_Update(&ctx, abs_dir, strlen(abs_dir));
	MD5_Update(&ctx, basename, strlen(basename));
	MD5_Final(hash, &ctx);

	free((void *)abs_dir);

	out = mempcpy(out, rt_dir, strlen(rt_dir));
	*out++ = '/';

	for (i = 0; i < sizeof hash; ++i) {

		*out++ = HEX_CHAR[(hash[i] >> 4) & 0x0f];
		*out++ = HEX_CHAR[(hash[i] >> 0) & 0x0f];
	}
	out = stpcpy(out, suffix);

	if (is_db)
		out = stpcpy(out, ".lock");

	*free_buf = strdup(hash_str);
	return *free_buf;
}

#define CALL(_type, _fn, _path, ...)					\
	({								\
		bool is_db = false;						\
		char *buf;						\
		char const *p = translate_path(_path, &buf, &is_db);	\
		debug("p='%s' => '%s'/%d", _path, p, is_db);		\
		_type rc = real_ ## _fn(is_db ? _path : p, ##__VA_ARGS__); \
		if (rc >= 0 && is_db)					\
			register_db(rc, _path, p);			\
		free(buf);						\
		rc; })

static int (*real_open)(const char *pathname, int flags, mode_t mode);

struct fake_db {
	int		fd;
};

static struct fake_db	g_dbs[0x10000];
static bool		g_active;

static void register_db(int fd, char const *orig_path, char const *xlate_path)
{
	int		fake_fd;

	debug("%d, %s, %s", fd, orig_path, xlate_path);

	if (g_dbs[fd].fd != -1) {
		fprintf(stderr, "internal error; fd already used\n");
		return;
	}

	g_active = true;
	fake_fd = real_open(xlate_path, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);

	if (__atomic_exchange_n(&g_dbs[fd].fd, fake_fd, __ATOMIC_SEQ_CST) != -1)
		fprintf(stderr, "race while registering database\n");

}

static int (*real_open)(const char *pathname, int flags, mode_t mode);
int open(const char *pathname, int flags, mode_t mode)
{
	int	rc;

	trace("%s, %x, %o", pathname, flags, mode);
	rc = CALL(int, open, pathname, flags | O_CLOEXEC, mode);

	return rc;
}

static int (*real_open64)(const char *pathname, int flags, mode_t mode);
int open64(const char *pathname, int flags, mode_t mode)
{
	int	rc;

	trace("%s, %x, %o", pathname, flags, mode);
	rc = CALL(int, open64, pathname, flags | O_CLOEXEC, mode);

	return rc;
}

static int (*real_socket)(int domain, int type, int protocol);
int socket(int domain, int type, int protocol)
{
	trace("%d, %d, %d", domain, type, protocol);

	if (domain == AF_INET || domain == AF_INET6)
		type |= SOCK_CLOEXEC;

	return real_socket(domain, type, protocol);
}

static int (*real_close)(int fd);
int close(int fd)
{
	int	db_fd;

	trace("%d", fd);

	if (fd >= 0 && (size_t)fd < ARRAY_SIZE(g_dbs))
		db_fd = __atomic_exchange_n(&g_dbs[fd].fd, -1, __ATOMIC_SEQ_CST);
	else
		db_fd = -1;

	if (db_fd != -1)
		real_close(db_fd);

	return real_close(fd);
}

static int (*real_lockf)(int fd, int cmd, off_t len);
int lockf(int fd, int cmd, off_t len)
{
	trace("%d,%d,%ld", fd, cmd, len);
	return real_lockf(fd, cmd, len);
}

static int (*real_lockf64)(int fd, int cmd, off_t len);
int lockf64(int fd, int cmd, off_t len)
{
	trace("%d,%d,%ld", fd, cmd, len);
	return real_lockf64(fd, cmd, len);
}

static int (*real_fcntl)(int fd, int cmd, uintptr_t arg);
int fcntl(int fd, int cmd, uintptr_t arg)
{
	switch (cmd) {
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		trace("%d, %d, %lx", fd, cmd, arg);

		if (fd >= 0 && (size_t)fd < ARRAY_SIZE(g_dbs) &&
		    g_dbs[fd].fd != -1)
			fd = g_dbs[fd].fd;
		break;
	}

	debug("%d,%d,%lx", fd, cmd, arg);

	return real_fcntl(fd, cmd, arg);
}

static int (*real_fcntl64)(int fd, int cmd, uintptr_t arg);
int fcntl64 (int fd, int cmd, uintptr_t arg)
{
	switch (cmd) {
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		trace("%d, %d, %lx", fd, cmd, arg);

		if (fd >= 0 && (size_t)fd < ARRAY_SIZE(g_dbs) &&
		    g_dbs[fd].fd != -1)
			fd = g_dbs[fd].fd;
		break;
	}

	debug("%d,%d,%lx", fd, cmd, arg);

	return real_fcntl(fd, cmd, arg);
}

static int (*real_stat)(const char *pathname, struct stat *statbuf);
int stat(const char *pathname, struct stat *statbuf)
{
	bool		is_db = false;
	char		*buf;
	char const	*p;
	int		rc;

	trace("%s, %p", pathname, statbuf);

	p  = translate_path(pathname, &buf, &is_db);
	rc = real_stat(is_db ? pathname : p, statbuf);
	free(buf);

	return rc;
}

static int (*real_unlink)(const char *pathname);
int unlink(const char *pathname)
{
	bool		is_db = false;
	char		*buf;
	char const	*p;
	int		rc;

	trace("%s", pathname);

	p  = translate_path(pathname, &buf, &is_db);
	rc = real_unlink(is_db ? pathname : p);
	free(buf);

	return rc;
}

#define MYSELF	"libsqlite-shm.so"
#define MYSELF_LEN (sizeof MYSELF - 1u)

static bool is_ld_delim(char c)
{
	return c == ':' || c == ' ';
}

static void strip_ld_preload(char *e)
{
	char	*in = e;

	debug("pre: '%s'", e);
	while (*in) {
		char	*next_col;
		char	*next_ws;
		char	*next;
		bool	strip_colon = false;

		while (is_ld_delim(*in))
			++in;

		next_col = strchr(in, ':');
		next_ws  = strchr(in, ' ');
		if (!next_col)
			next = next_ws;
		else if (!next_ws)
			next = next_col;
		else if (next_col < next_ws)
			next = next_col;
		else
			next = next_ws;

		if (next == NULL) {
			strip_colon = true;
			next = in + strlen(in);
		}

		if (next < in + MYSELF_LEN ||
		    memcmp(next - MYSELF_LEN, MYSELF, MYSELF_LEN) != 0 ||
		    (next != in + MYSELF_LEN &&
		     !is_ld_delim(next[-(MYSELF_LEN + 1)]) &&
		     next[-(MYSELF_LEN + 1)] != '/')) {
			in = next;
		} else {
			while (is_ld_delim(*next))
				++next;

			while (strip_colon && in > e && is_ld_delim(in[-1]))
				--in;

			memmove(in, next, strlen(next) + 1);
		}
	}
	debug("post: '%s'", e);
}

static void _test_strip_ld_preload(char const *buf, char const *exp)
{
	char	*ldpreload = strdup(buf);

	strip_ld_preload(ldpreload);
	assert(strcmp(ldpreload, exp) == 0);
}

static void unit_test_strip_ld_preload(void)
{

	_test_strip_ld_preload("", "");
	_test_strip_ld_preload(MYSELF, "");
	_test_strip_ld_preload("/" MYSELF, "");
	_test_strip_ld_preload("/foo/" MYSELF, "");
	_test_strip_ld_preload("a:b", "a:b");
	_test_strip_ld_preload("a b", "a b");
	_test_strip_ld_preload(MYSELF "x", MYSELF "x");
	_test_strip_ld_preload("x" MYSELF "x", "x" MYSELF "x");
	_test_strip_ld_preload("x" MYSELF, "x" MYSELF);
	_test_strip_ld_preload("a:" MYSELF, "a");
	_test_strip_ld_preload("a " MYSELF, "a");
	_test_strip_ld_preload("a:foo/" MYSELF, "a");
	_test_strip_ld_preload("a foo/" MYSELF, "a");
	_test_strip_ld_preload("a:" MYSELF ":", "a:");
	_test_strip_ld_preload("a " MYSELF ":", "a ");
	_test_strip_ld_preload("a " MYSELF " ", "a ");
	_test_strip_ld_preload("a:foo/" MYSELF ":", "a:");
	_test_strip_ld_preload("a:" MYSELF ":b", "a:b");
	_test_strip_ld_preload("a " MYSELF " b", "a b");
	_test_strip_ld_preload("a:foo/" MYSELF ":b", "a:b");
}

static int (*real_execve)(char const *, char * const [], char * const []);
int execve(char const *filename, char * const argv[], char *const envp[])
{
	char const	*prog = getenv("X_SQLITE_SHM_PROG");
	bool		do_disable = false;
	bool		passthrough = g_active;
	bool		is_prog;
	char const **	new_env;
	size_t		env_cnt = 0;
	char const **	out_env;
	int		rc;

	if (prog)
		is_prog = fnmatch(prog, filename, 0) == 0;
	else
		is_prog = false;

	if (g_active && is_prog)
		do_disable = true;
	else if (!g_active && is_prog)
		passthrough = true;

	for (char * const *e = &envp[0]; *e; ++e)
		++env_cnt;

	new_env = calloc(env_cnt+1, sizeof new_env[0]);
	if (!new_env)
		return -1;

	out_env = &new_env[0];

	for (char * const *e = &envp[0]; *e; ++e) {
		if (!passthrough) {
			if (strncmp(*e, "X_SQLITE_SHM_PROG=", 18) == 0 ||
			    strncmp(*e, "X_SQLITE_SHM_DISABLED=", 22) == 0) {
				;	/* noop; remove env */
			} else if (strncmp(*e, "LD_PRELOAD=", 11) == 0) {
				char	*tmp = strdup(*e);
				if (!tmp) {
					free(new_env);
					return -1;
				}

				strip_ld_preload(tmp + 11);

				if (tmp[11] != '\0')
					*out_env++ = tmp;
			} else {
				*out_env++ = *e;
			}
		} else if (strncmp(*e, "X_SQLITE_SHM_DISABLED=", 22) == 0) {
			if (do_disable)
				*out_env++ = "X_SQLITE_SHM_DISABLED=1";
			else
				*out_env++ = *e;
		} else {
			*out_env++ = *e;
		}

		debug("  | %p, '%s'", out_env, out_env[-1]);
	}

	*out_env++ = NULL;

	debug("%s, %s: %d, %d|%d", filename, argv[0],
		do_disable, passthrough, g_active);

	rc = real_execve(filename, argv, (char * const *)new_env);
	free(new_env);

	return rc;
}

static void  __attribute__((__constructor__)) init_sqlite_shm(void)
{
	size_t		i;
	char const	*disabled;

	trace("");

	if (run_unittests()) {
		unit_test_strip_ld_preload();
	}

	for (i = 0; i < sizeof g_dbs / sizeof g_dbs[0]; ++i)
		g_dbs[i].fd = -1;

	real_open = dlsym(RTLD_NEXT, "open");
	real_open64 = dlsym(RTLD_NEXT, "open64");
	real_lockf = dlsym(RTLD_NEXT, "lockf");
	real_lockf64 = dlsym(RTLD_NEXT, "lockf64");
	real_fcntl = dlsym(RTLD_NEXT, "fcntl");
	real_fcntl64 = dlsym(RTLD_NEXT, "fcntl64");
	real_close = dlsym(RTLD_NEXT, "close");
	real_execve = dlsym(RTLD_NEXT, "execve");
	real_socket = dlsym(RTLD_NEXT, "socket");
	real_stat = dlsym(RTLD_NEXT, "stat");
	real_unlink = dlsym(RTLD_NEXT, "unlink");

	rt_dir = getenv("XDG_RUNTIME_DIR");

	disabled = getenv("X_SQLITE_SHM_DISABLED");
	g_active = !disabled || *disabled == '0';

	if (!g_active) {
		char	*tmp = getenv("LD_PRELOAD");
		if (tmp) {
			tmp = strdup(tmp);
			strip_ld_preload(tmp);

			if (*tmp)
				setenv("LD_PRELOAD", tmp, 1);
			else
				unsetenv("LD_PRELOAD");

			debug("stripped LD_PRELOAD to '%s'", tmp);

			free(tmp);
		}
	}

	if (!disabled)
		setenv("X_SQLITE_SHM_DISABLED", "0", 0);
}
