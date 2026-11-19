/*
 * fuzz_sock_handle — the irqbalance daemon's UNIX control socket (sock_handle()).
 *
 * The input is up to MAX_MSGS messages from a root client, separated by NUL bytes
 * (the daemon only obeys uid 0, which the fake socket in fuzz_env.c supplies via
 * SCM_CREDENTIALS): "stats", "setup", "settings sleep <n>",
 * "settings ban irqs <n...>|NONE", "settings cpus <list>|NULL". Each message is its
 * own connection, delivered without a trailing NUL, as recvmsg() would.
 *
 * Per input: start the daemon on the fake topology; for each message, deliver it
 * and run the periodic scan() the daemon runs next (a "settings" command sets
 * need_rescan, so this re-reads the topology with the banned cpus/irqs it set);
 * then ask for "setup" and "stats" as irqbalance-ui does, and stop the daemon.
 * All state the messages can change (banned irqs, banned cpu list, sleep interval,
 * the receive buffer's stale bytes) is reset per input; the fake sysfs tree is
 * read-only after init.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "irqbalance.h"
#include "fuzz_env.h"

#define MAX_MSGS 4

gboolean scan(gpointer data);
gboolean sock_handle(gint fd, GIOCondition condition, gpointer user_data);

static void request(const char *msg, size_t len)
{
	fuzz_env_set_client_msg(msg, len);
	sock_handle(-1, G_IO_IN, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (fuzz_env_init())
		abort();

	fuzz_env_reset_daemon_globals();
	fuzz_env_daemon_start();

	{
		const uint8_t *p = data, *end = data + size, *nul;
		int i;

		for (i = 0; i < MAX_MSGS && p <= end; i++) {
			nul = memchr(p, 0, (size_t)(end - p));
			if (!nul)
				nul = end;
			request((const char *)p, (size_t)(nul - p));
			scan(NULL);
			p = nul + 1;
		}
	}
	request("setup", 5);
	request("stats", 5);

	fuzz_env_daemon_stop();
	return 0;
}
