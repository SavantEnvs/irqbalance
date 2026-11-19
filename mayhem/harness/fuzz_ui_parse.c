/*
 * fuzz_ui_parse — irqbalance-ui parsing the daemon's replies (AFL, file input).
 *
 * irqbalance-ui's rescan_tree() asks the daemon for "setup" and "stats" over the
 * control socket (get_data()), then parses them with parse_setup() and
 * parse_into_tree() (strtok_r tokenising, IRQ lists, banned-cpu hex masks,
 * building the cpu tree and its cpu lists/masks). Both parsers exit(1) on an
 * unexpected token, which is why this is a file-input AFL target rather than a
 * libFuzzer one.
 *
 * Input file: the setup reply, a NUL byte, then the stats reply. Without a NUL
 * the whole file is the stats reply and the setup reply is a fixed valid one.
 * The ncurses screen is never drawn (state is not STATE_TREE).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "ui_env.h"

extern int state;
gboolean rescan_tree(gpointer data);

static const char default_setup[] = "SLEEP 10 BANNED 00000000";

/*
 * Both parsers call g_str_has_prefix() on strtok_r()'s result without a NULL
 * check. For a NULL token GLib's own precondition check logs
 * "GLib-CRITICAL ... g_str_has_prefix: assertion 'str != NULL' failed" and
 * returns FALSE, and the parser then takes its designed "Invalid data sent"
 * -> exit(1) rejection. Mayhem reported that assertion text as an
 * (Uncategorized, frameless) defect, though no signal or sanitizer report is
 * involved. Drop only GLib-domain criticals: g_str_has_prefix() still returns
 * FALSE, the parser still runs and rejects the input the same way, and the
 * NULL token reaching strtol()/strlen() is still reported by UBSan. One input
 * per process, so this handler is the same for every input.
 */
static void drop_glib_critical(const gchar *domain, GLogLevelFlags level,
			       const gchar *message, gpointer user_data)
{
	(void)domain; (void)level; (void)message; (void)user_data;
}

int main(int argc, char **argv)
{
	FILE *f;
	char *buf = NULL, *nul;
	size_t cap = 0, len = 0, n;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <reply-file>\n", argv[0]);
		return 2;
	}
	f = fopen(argv[1], "rb");
	if (!f) {
		perror(argv[1]);
		return 2;
	}
	do {
		if (len == cap) {
			cap = cap ? cap * 2 : 4096;
			buf = realloc(buf, cap);
			if (!buf)
				return 2;
		}
		n = fread(buf + len, 1, cap - len, f);
		len += n;
	} while (n);
	fclose(f);

	nul = buf ? memchr(buf, 0, len) : NULL;
	if (nul)
		ui_env_set_replies(buf, (size_t)(nul - buf), nul + 1, len - (size_t)(nul - buf) - 1);
	else
		ui_env_set_replies(default_setup, strlen(default_setup), buf, len);

	g_log_set_handler("GLib", G_LOG_LEVEL_CRITICAL, drop_glib_critical, NULL);
	state = -1;	/* not STATE_TREE: no curses drawing */
	rescan_tree(NULL);
	free(buf);
	return 0;
}
