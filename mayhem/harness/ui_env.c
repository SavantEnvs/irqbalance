/* ui_env.c — see ui_env.h. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "ui_env.h"

static const char *setup_reply, *stats_reply, *pending;
static size_t setup_len, stats_len, pending_len;

void ui_env_set_replies(const char *setup, size_t slen, const char *stats, size_t tlen)
{
	setup_reply = setup;
	setup_len = slen;
	stats_reply = stats;
	stats_len = tlen;
}

int __wrap_socket(int domain, int type, int protocol)
{
	(void)domain; (void)type; (void)protocol;
	return open("/dev/null", O_RDWR);	/* a real fd for the UI's close() */
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	(void)fd; (void)addr; (void)len;
	return 0;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	size_t n = 0, i;
	(void)fd; (void)flags;

	pending = NULL;
	pending_len = 0;
	for (i = 0; i < (size_t)msg->msg_iovlen; i++)
		n += msg->msg_iov[i].iov_len;
	if (msg->msg_iovlen >= 1 && msg->msg_iov[0].iov_len >= 5) {
		if (!memcmp(msg->msg_iov[0].iov_base, "setup", 5)) {
			pending = setup_reply;
			pending_len = setup_len;
		} else if (!memcmp(msg->msg_iov[0].iov_base, "stats", 5)) {
			pending = stats_reply;
			pending_len = stats_len;
		}
	}
	return (ssize_t)n;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags)
{
	size_t n = pending_len;
	(void)fd; (void)flags;

	if (n > len)
		n = len;
	if (n)
		memcpy(buf, pending, n);
	return (ssize_t)n;
}
