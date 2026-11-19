/*
 * ui_env.h — a fake irqbalance daemon for irqbalance-ui (ui/irqbalance-ui.c).
 *
 * The UI objects are linked with -Wl,--wrap=socket,--wrap=connect,--wrap=sendmsg,--wrap=recv
 * so that get_data()'s connection to the daemon's control socket is answered
 * from memory: a "setup" request gets the setup reply, a "stats" request the
 * stats reply. recv() keeps SOCK_STREAM semantics (at most the buffer size).
 * Environment mock only; no irqbalance-ui code is replaced.
 */
#ifndef IRQBALANCE_UI_ENV_H
#define IRQBALANCE_UI_ENV_H
#include <stddef.h>
void ui_env_set_replies(const char *setup, size_t setup_len,
			const char *stats, size_t stats_len);
#endif
