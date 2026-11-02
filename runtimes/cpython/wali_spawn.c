/* posix_spawn/posix_spawnp over the walios kernel's own posix_spawn syscall.
 *
 * musl implements posix_spawn with __clone, which has no kernel behind it here, so
 * os.system(), os.posix_spawn(), C popen() and system() all failed (-1 / ENOSYS). The
 * kernel already spawns a NEW process directly -- it was added for node's child_process:
 *   SYS_posix_spawn(path, argv, envp, fdmap, fdmapLen) -> pid | -errno
 * where fdmap is fdmapLen pairs [childFd, parentFd] taken from the PARENT's table
 * (parentFd < 0 closes childFd), on top of the parent's non-cloexec fds.
 *
 * File actions are an ordered script run in the child, so replay them here into that
 * final mapping: dup2/close resolve through the mapping built so far, open opens in the
 * parent (O_CLOEXEC, so only the explicit mapping hands it over) and chdir/fchdir move
 * the parent's cwd for the duration of the call -- the kernel starts the child in it.
 * POSIX_SPAWN_SETPGROUP is applied with setpgid() on the new pid; POSIX_SPAWN_SETSID
 * rides in fdmapLen's high 16 bits (bit 0), which the kernel reads as flags. Everything
 * signal-related is ignored (a new image starts with default handlers and an empty
 * pending set either way). */
#include <spawn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((import_module("wali"), import_name("SYS_posix_spawn")))
long __wali_sys_posix_spawn(const char *path, char *const argv[], char *const envp[], const int *fdmap, int len);

struct fdop {                      /* musl src/process/fdop.h */
	struct fdop *next, *prev;
	int cmd, fd, srcfd, oflag;
	mode_t mode;
	char path[];
};
#define FDOP_CLOSE 1
#define FDOP_DUP2 2
#define FDOP_OPEN 3
#define FDOP_CHDIR 4
#define FDOP_FCHDIR 5

#define MAXMAP 64
struct fdmap { int n; int child[MAXMAP], parent[MAXMAP]; int opened[MAXMAP], nopened; };

static int lookup(const struct fdmap *m, int fd)
{
	for (int i = 0; i < m->n; i++) if (m->child[i] == fd) return m->parent[i];
	return fd;                     /* untouched: the child inherits the parent's fd */
}

static int set(struct fdmap *m, int fd, int parent)
{
	for (int i = 0; i < m->n; i++) if (m->child[i] == fd) { m->parent[i] = parent; return 0; }
	if (m->n == MAXMAP) return ENOMEM;
	m->child[m->n] = fd; m->parent[m->n] = parent; m->n++;
	return 0;
}

static int spawn(pid_t *restrict res, const char *restrict path,
                 const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
                 char *const argv[restrict], char *const envp[restrict], int search)
{
	struct fdmap m = { 0 };
	int cwdfd = -1, ret = 0;

	if (fa && fa->__actions) {
		struct fdop *op = fa->__actions;
		while (op->next) op = op->next;            /* list is newest-first: run oldest-first */
		for (; op && !ret; op = op->prev) {
			switch (op->cmd) {
			case FDOP_CLOSE: ret = set(&m, op->fd, -1); break;
			case FDOP_DUP2: {
				int p = lookup(&m, op->srcfd);
				if (p < 0 || fcntl(p, F_GETFD) < 0) { ret = EBADF; break; }
				ret = set(&m, op->fd, p); break; }
			case FDOP_OPEN: {
				int p = open(op->path, op->oflag | O_CLOEXEC, op->mode);
				if (p < 0) { ret = errno; break; }
				if (m.nopened < MAXMAP) m.opened[m.nopened++] = p;
				ret = set(&m, op->fd, p); break; }
			case FDOP_CHDIR: case FDOP_FCHDIR:
				if (cwdfd < 0 && (cwdfd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) { ret = errno; break; }
				if ((op->cmd == FDOP_CHDIR ? chdir(op->path) : fchdir(lookup(&m, op->fd))) < 0) ret = errno;
				break;
			default: ret = EINVAL;
			}
		}
	}

	int pairs[2 * MAXMAP];
	for (int i = 0; i < m.n; i++) { pairs[2 * i] = m.child[i]; pairs[2 * i + 1] = m.parent[i]; }
	int flags = (attr && (attr->__flags & POSIX_SPAWN_SETSID)) ? 1 << 16 : 0;

	long pid = -ENOENT;
	if (!ret) {
		if (!search || strchr(path, '/')) {
			pid = __wali_sys_posix_spawn(path, argv, envp, pairs, m.n | flags);
		} else {
			/* posix_spawnp: the caller's PATH, as execvp does */
			const char *p = getenv("PATH");
			if (!p) p = "/usr/local/bin:/bin:/usr/bin";
			size_t k = strlen(path);
			int seen_eacces = 0;
			for (;;) {
				const char *z = strchrnul(p, ':');
				size_t l = z - p;
				char buf[4096];
				if (l + 1 + k + 1 <= sizeof buf) {
					if (l) { memcpy(buf, p, l); buf[l] = '/'; memcpy(buf + l + 1, path, k + 1); }
					else memcpy(buf, path, k + 1);         /* empty PATH entry = cwd */
					pid = __wali_sys_posix_spawn(buf, argv, envp, pairs, m.n | flags);
					if (pid >= 0) break;
					if (pid == -EACCES) seen_eacces = 1;
					else if (pid != -ENOENT && pid != -ENOTDIR) break;
				}
				if (!*z) { if (seen_eacces) pid = -EACCES; break; }
				p = z + 1;
			}
		}
		if (pid < 0) ret = (int)-pid;
	}

	for (int i = 0; i < m.nopened; i++) close(m.opened[i]);   /* the child holds its own reference */
	if (cwdfd >= 0) { fchdir(cwdfd); close(cwdfd); }
	if (ret) return ret;

	if (attr && (attr->__flags & POSIX_SPAWN_SETPGROUP)) setpgid((pid_t)pid, attr->__pgrp);
	if (res) *res = (pid_t)pid;
	return 0;
}

int posix_spawn(pid_t *restrict res, const char *restrict path,
                const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
                char *const argv[restrict], char *const envp[restrict])
{
	return spawn(res, path, fa, attr, argv, envp, 0);
}

int posix_spawnp(pid_t *restrict res, const char *restrict file,
                 const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
                 char *const argv[restrict], char *const envp[restrict])
{
	return spawn(res, file, fa, attr, argv, envp, 1);
}
