/* openssl-shim.c -- walios' /bin/openssl, enough of `openssl s_client` for busybox wget.
 *
 * WHY: busybox is built with CONFIG_FEATURE_WGET_OPENSSL, so `wget https://...` does
 *   socketpair() -> vfork() -> dup2(sp[1],0), dup2(0,1) -> execvp("openssl",
 *     {"openssl","s_client","-quiet","-connect",HOST:PORT,"-servername",NAME})
 * and then speaks plaintext HTTP over the socketpair. Our job: be that helper. We do NOT
 * implement TLS -- we hand the socket to the WISP relay, which terminates TLS natively
 * (Node tls.connect: TLS 1.3, SNI, system-CA validation). See wisp.js conntype 0x03 and
 * wali-worker.js 'setsockopt' (level 0x5457 'WT' marks a socket TLS BEFORE connect).
 *
 * This must stay a real wasm BINARY, never a shell script: busybox execvp()s it from a
 * vfork child, and that path does not honour #! shebangs.
 *
 * Trust note: the relay sees plaintext. That is the same deal tlswrap has always had and
 * is the documented walios model; a client that wants end-to-end TLS links libssl itself
 * (curl, git, ssh, python's _ssl all do) and never comes through here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>

#define SOL_WALI_TLS 0x5457   /* 'WT' -- wali-worker.js setsockopt */

static void die(const char *what, const char *detail)
{
	fprintf(stderr, "openssl: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
	exit(1);
}

int main(int argc, char **argv)
{
	const char *connect_to = NULL, *servername = NULL;
	int i;

	/* argv[1] must be s_client. Anything else: fail LOUDLY rather than pretend. */
	if (argc < 2 || strcmp(argv[1], "s_client") != 0)
		die("this is walios' minimal openssl: only `s_client` is implemented", argc > 1 ? argv[1] : NULL);

	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-connect") && i + 1 < argc)          connect_to = argv[++i];
		else if (!strcmp(argv[i], "-servername") && i + 1 < argc)  servername = argv[++i];
		/* -quiet, -verify_return_error, -verify N, -no_check_cert ... : accepted, ignored.
		 * Certificate verification is the relay's job and is always on. */
	}
	if (!connect_to)
		die("s_client needs -connect HOST:PORT", NULL);

	/* Split HOST:PORT on the LAST colon (host may be a bracketed IPv6 literal). */
	char hostbuf[512];
	const char *colon = strrchr(connect_to, ':');
	if (!colon || colon == connect_to || (size_t)(colon - connect_to) >= sizeof(hostbuf))
		die("bad -connect (want HOST:PORT)", connect_to);
	memcpy(hostbuf, connect_to, colon - connect_to);
	hostbuf[colon - connect_to] = '\0';
	const char *port = colon + 1;
	if (!servername) servername = hostbuf;

	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;          /* the relay speaks v4; ipToName keys on it */
	hints.ai_socktype = SOCK_STREAM;
	int gai = getaddrinfo(hostbuf, port, &hints, &res);
	if (gai != 0 || !res)
		die(gai_strerror(gai), hostbuf);

	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0) die("socket", strerror(errno));

	/* MUST precede connect(): the kernel reads sock.tls when it builds the WISP
	 * CONNECT frame, so setting it afterwards silently gets you a plaintext pipe. */
	int one = 1;
	if (setsockopt(sock, SOL_WALI_TLS, 1, &one, sizeof one) != 0)
		die("this walios kernel has no TLS socket option (level 0x5457)", strerror(errno));

	if (connect(sock, res->ai_addr, res->ai_addrlen) != 0)
		die("connect", strerror(errno));
	freeaddrinfo(res);

	/* Pump: stdin -> socket, socket -> stdout, until the socket closes.
	 * NB shutdown() is a no-op in this kernel, so on stdin EOF we simply stop polling
	 * fd 0 and keep draining the socket -- which is all HTTP needs, since the server
	 * replies to the request headers without waiting for a half-close. */
	char buf[16384];
	int stdin_open = 1;
	for (;;) {
		struct pollfd p[2];
		int n = 0;
		p[n].fd = sock; p[n].events = POLLIN; n++;
		if (stdin_open) { p[n].fd = 0; p[n].events = POLLIN; n++; }

		if (poll(p, n, -1) < 0) {
			if (errno == EINTR) continue;
			die("poll", strerror(errno));
		}

		if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			ssize_t r = read(sock, buf, sizeof buf);
			if (r < 0 && errno == EINTR) continue;
			if (r <= 0) break;                       /* peer closed -> we are done */
			for (ssize_t off = 0; off < r; ) {
				ssize_t w = write(1, buf + off, r - off);
				if (w < 0) { if (errno == EINTR) continue; die("write stdout", strerror(errno)); }
				off += w;
			}
		}

		if (stdin_open && n > 1 && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
			ssize_t r = read(0, buf, sizeof buf);
			if (r < 0 && errno == EINTR) continue;
			if (r <= 0) { stdin_open = 0; continue; }  /* request sent; drain the reply */
			for (ssize_t off = 0; off < r; ) {
				ssize_t w = write(sock, buf + off, r - off);
				if (w < 0) { if (errno == EINTR) continue; die("write socket", strerror(errno)); }
				off += w;
			}
		}
	}
	return 0;
}
