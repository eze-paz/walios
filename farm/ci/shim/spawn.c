/* posix_spawn()/posix_spawnp() on walios' fork. musl's own runs the child with __clone(CLONE_VM|
   CLONE_VFORK), which this libc does not have: posix_spawn failed before any syscall, so did
   system() and popen() (both are built on it) -- ICU's pkgdata, run during ICU's install,
   got -1 from system("install ...") and the install stopped before its pkg-config files.
   Here the child is fork()'s (the vfork macro: the child branch runs in place until execve or
   _exit). Members of libwali-farm.a link ahead of -lc, so libc's system.o/popen.o take these. */
#include <spawn.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/wait.h>

/* musl's src/process/fdop.h */
struct fdop { struct fdop *next, *prev; int cmd, fd, srcfd, oflag; mode_t mode; char path[]; };
#define FDOP_CLOSE 1
#define FDOP_DUP2 2
#define FDOP_OPEN 3
#define FDOP_CHDIR 4
#define FDOP_FCHDIR 5

/* the program a PATH search finds, as execvp would (the in-place child's execve cannot report
   a missing file back: it may start the program concurrently and only then find it absent) */
static const char *find(const char *file, char *buf, char *const envp[])
{
	if (!*file || strchr(file, '/')) return file;
	const char *p = 0;
	for (char *const *e = envp; e && *e; e++) if (!strncmp(*e, "PATH=", 5)) { p = *e + 5; break; }
	if (!p) p = getenv("PATH");
	if (!p) p = "/usr/local/bin:/bin:/usr/bin";
	size_t l = strnlen(file, NAME_MAX + 1);
	if (l > NAME_MAX) return 0;
	for (const char *s = p; ; s++) {
		const char *z = strchrnul(s, ':');
		if ((size_t)(z - s) + l + 2 <= PATH_MAX) {
			memcpy(buf, s, z - s); buf[z - s] = '/';
			memcpy(buf + (z - s) + (z > s), file, l + 1);
			if (!access(buf, X_OK)) return buf;
		}
		if (!*z) break;
		s = z;
	}
	return 0;
}

static int spawn(pid_t *restrict res, const char *path, int search,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
	char *const argv[], char *const envp[])
{
	char buf[PATH_MAX], cwd[PATH_MAX];
	if (attr && attr->__fn) search = 1; /* musl's posix_spawnp reaching this posix_spawn */
	const char *prog = search ? find(path, buf, envp) : path;
	if (!prog) return ENOENT;
	if (search && access(prog, X_OK)) return errno;
	struct fdop *op = 0;
	int chdirs = 0;
	if (fa && fa->__actions) {
		for (op = fa->__actions; op->next; op = op->next);
		for (struct fdop *o = op; o; o = o->prev) chdirs |= o->cmd == FDOP_CHDIR || o->cmd == FDOP_FCHDIR;
	}
	if (chdirs && !getcwd(cwd, sizeof cwd)) chdirs = 0;
	volatile int ec = 0;
	pid_t pid = fork();
	if (pid < 0) return errno;
	if (pid == 0) {
		int r = 0;
		if (attr && (attr->__flags & POSIX_SPAWN_SETPGROUP)) setpgid(0, attr->__pgrp);
#ifdef POSIX_SPAWN_SETSID
		if (attr && (attr->__flags & POSIX_SPAWN_SETSID)) setsid();
#endif
		for (struct fdop *o = op; o && !r; o = o->prev) {
			int fd;
			switch (o->cmd) {
			case FDOP_CLOSE: close(o->fd); break;
			case FDOP_DUP2:
				if (o->srcfd == o->fd) { int f = fcntl(o->fd, F_GETFD); r = f < 0 || fcntl(o->fd, F_SETFD, f & ~FD_CLOEXEC) < 0; }
				else r = dup2(o->srcfd, o->fd) < 0;
				break;
			case FDOP_OPEN:
				fd = open(o->path, o->oflag, o->mode);
				if (fd < 0) { r = 1; break; }
				if (fd != o->fd) { r = dup2(fd, o->fd) < 0; close(fd); }
				break;
			case FDOP_CHDIR: r = chdir(o->path) < 0; break;
			case FDOP_FCHDIR: r = fchdir(o->fd) < 0; break;
			}
		}
		if (!r) execve(prog, argv, envp);
		ec = errno ? errno : ENOEXEC;
		_exit(127);
	}
	if (chdirs) chdir(cwd); /* the in-place child changed this process's directory */
	if (ec) { int st; waitpid(pid, &st, 0); return ec; }
	if (res) *res = pid;
	return 0;
}

int posix_spawn(pid_t *restrict res, const char *restrict path,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
	char *const argv[restrict], char *const envp[restrict])
{
	return spawn(res, path, 0, fa, attr, argv, envp);
}

int posix_spawnp(pid_t *restrict res, const char *restrict file,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
	char *const argv[restrict], char *const envp[restrict])
{
	return spawn(res, file, 1, fa, attr, argv, envp);
}
