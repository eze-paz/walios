/* tlswrap.c -- walios' /bin/tlswrap: a local plaintext port that speaks TLS upstream.
 *
 *     tlswrap -L LOCALPORT HOST PORT
 *
 * Listens on 127.0.0.1:LOCALPORT and, for each connection, opens a TLS connection to
 * HOST:PORT and pumps bytes both ways. It is what lets nc/telnet -- which are plaintext
 * only -- reach a TLS service, and the run_walios tool documents exactly this.
 *
 * WHY THIS FILE EXISTS. The previous tlswrap.wasm (93KB, no source anywhere in any repo or
 * on the build box) could not work at all: listen() used to hand the port to the WISP
 * relay, and since WISP is an OUTBOUND transport the relay refused every bind, so
 * `tlswrap -L` died with "listen: Address in use" on every port. Once loopback listeners
 * were served inside the kernel it got further -- it bound, and printed
 *     tlswrap: 127.0.0.1:9443 -> TLS example.com:443
 * -- but a proxied request then hung forever. The hang was NOT in the kernel: a proxy of
 * the identical shape, written in python and run in the same guest, worked first time
 * (accept -> TLS connect -> select pump -> 828 bytes of "HTTP/1.1 200 OK" back to nc). So
 * the fault was inside that binary, and with no source there was nothing to fix. This is a
 * replacement with the same interface.
 *
 * WE DO NOT IMPLEMENT TLS. The socket is marked with a private setsockopt level before
 * connect() and the WISP relay terminates TLS natively (Node tls.connect: TLS 1.3, SNI,
 * system-CA validation). Same mechanism openssl-shim.c uses; see wisp.js conntype 0x03 and
 * wali-worker.js 'setsockopt'.
 *
 * Trust note, unchanged from openssl-shim.c: the relay sees plaintext. That is the
 * documented walios model. A client wanting end-to-end TLS links libssl itself (curl, git,
 * ssh and python's _ssl all do) and never comes through here.
 *
 * Connections are served ONE AT A TIME, on purpose: the use this exists for is a script
 * making a sequence of requests through a port it opened earlier, and a sequential loop
 * cannot leak a process per connection. A second client simply waits its turn.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SOL_WALI_TLS 0x5457   /* 'WT' -- wali-worker.js setsockopt, must precede connect() */

static void die(const char *what, const char *detail)
{
	fprintf(stderr, "tlswrap: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "usage: tlswrap -L LOCALPORT HOST PORT\n"
	                "       listens on 127.0.0.1:LOCALPORT, forwards each connection to HOST:PORT over TLS\n");
	exit(2);
}

/* One outbound TLS connection. Returns the fd, or -1 having already complained. */
static int dial_tls(const char *host, const char *port)
{
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int gai = getaddrinfo(host, port, &hints, &res);
	if (gai != 0 || !res) { fprintf(stderr, "tlswrap: resolve %s: %s\n", host, gai_strerror(gai)); return -1; }

	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) { fprintf(stderr, "tlswrap: socket: %s\n", strerror(errno)); freeaddrinfo(res); return -1; }

	/* MUST precede connect(): the kernel reads sock.tls when it builds the WISP CONNECT,
	 * so marking it afterwards would open a plaintext stream and silently send the
	 * request in the clear. */
	int one = 1;
	if (setsockopt(fd, SOL_WALI_TLS, 1, &one, sizeof one) != 0) {
		fprintf(stderr, "tlswrap: this walios cannot do relay TLS (setsockopt: %s)\n", strerror(errno));
		close(fd); freeaddrinfo(res); return -1;
	}
	if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
		fprintf(stderr, "tlswrap: connect %s:%s: %s\n", host, port, strerror(errno));
		close(fd); freeaddrinfo(res); return -1;
	}
	freeaddrinfo(res);
	return fd;
}

/* Pump until the UPSTREAM closes. Not until the client closes: shutdown() is a no-op in
 * this kernel, so a half-close does not reach the far end, and a client that has sent its
 * request and stopped writing (printf | nc) would otherwise look finished before its
 * response arrived. Upstream EOF is the authoritative end of a request/response. */
static void pump(int cli, int up)
{
	char buf[16384];
	int cli_open = 1;
	long long sent = 0, got = 0;

	for (;;) {
		struct pollfd p[2];
		int n = 0;
		int icli = -1, iup;
		if (cli_open) { p[n].fd = cli; p[n].events = POLLIN; icli = n; n++; }
		p[n].fd = up; p[n].events = POLLIN; iup = n; n++;

		if (poll(p, n, 120000) <= 0) {
			fprintf(stderr, "tlswrap: connection idle for 120s, closing\n");
			return;
		}
		if (cli_open && (p[icli].revents & (POLLIN | POLLHUP))) {
			ssize_t r = read(cli, buf, sizeof buf);
			if (r > 0) {
				if (write(up, buf, (size_t)r) != r) { fprintf(stderr, "tlswrap: upstream write: %s\n", strerror(errno)); return; }
				sent += r;
			} else {
				/* Client stopped talking. Keep draining upstream: the reply is still coming. */
				cli_open = 0;
			}
		}
		if (p[iup].revents & (POLLIN | POLLHUP)) {
			ssize_t r = read(up, buf, sizeof buf);
			if (r > 0) {
				got += r;
				if (write(cli, buf, (size_t)r) != r) return;   /* client gone: done with this one */
			} else {
				/* Upstream EOF. Normally that is just the end of a request/response -- but
				 * if we forwarded bytes and NOTHING came back, the connection failed
				 * somewhere we cannot see and the client is about to read an empty reply
				 * with no explanation. getaddrinfo() cannot tell us: the relay resolves at
				 * connect time, so a bogus hostname sails through both getaddrinfo() and
				 * connect() here and only dies upstream. Say so rather than look fine. */
				if (sent > 0 && got == 0)
					fprintf(stderr, "tlswrap: upstream closed without a single byte "
					                "(bad hostname, refused, or TLS rejected) after %lld bytes sent\n", sent);
				return;
			}
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 5 || strcmp(argv[1], "-L") != 0) usage();

	const char *lport = argv[2], *host = argv[3], *rport = argv[4];
	int lp = atoi(lport);
	if (lp <= 0 || lp > 65535) die("bad LOCALPORT", lport);
	if (atoi(rport) <= 0) die("bad PORT", rport);

	int srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0) die("socket", strerror(errno));
	int one = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons((unsigned short)lp);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(srv, (struct sockaddr *)&sa, sizeof sa) != 0) die("bind", strerror(errno));
	if (listen(srv, 8) != 0) die("listen", strerror(errno));

	/* Unbuffered, and on stderr, so it is visible even when stdout is redirected and even
	 * when this is started in the background -- which is the normal way to use it. */
	setvbuf(stderr, NULL, _IONBF, 0);
	fprintf(stderr, "tlswrap: 127.0.0.1:%d -> TLS %s:%s\n", lp, host, rport);

	for (;;) {
		int cli = accept(srv, NULL, NULL);
		if (cli < 0) {
			if (errno == EINTR || errno == EAGAIN) continue;
			die("accept", strerror(errno));
		}
		int up = dial_tls(host, rport);
		if (up < 0) { close(cli); continue; }    /* already complained; keep serving */
		pump(cli, up);
		close(up);
		close(cli);
	}
	return 0;
}
