/*
 * fuzz_procinterrupts — the irqbalance daemon reading /proc/interrupts and /proc/stat.
 *
 * Input: the bytes up to the first NUL are served as /proc/interrupts; the bytes
 * after it (if there is a NUL) as /proc/stat, else a valid /proc/stat for the fake
 * 4-cpu topology (fuzz_env.c) is used.
 *
 * Per input it runs what the daemon does at start-up (main(): build the object
 * tree from the sysfs topology and rebuild_irq_db(), which tokenises every
 * /proc/interrupts line in collect_full_irq_list()/init_irq_class_and_type();
 * then parse_proc_interrupts() and parse_proc_stat()), followed by two periodic
 * scan() passes (re-parse, hotplug/rescan handling, migration, placement and
 * affinity activation, whose writes go to /dev/null), then frees the tree.
 *
 * State kept across inputs on purpose: the fake sysfs tree (read-only after
 * init) and procinterrupts.c's two "warned once about MSI" flags, which only
 * gate a log message.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "irqbalance.h"
#include "fuzz_env.h"

gboolean scan(gpointer data);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *nul;
	char *buf;
	size_t ilen;

	if (fuzz_env_init())
		abort();

	/* own copy: the fmemopen'd streams must stay valid for the whole input */
	buf = malloc(size + 1);
	if (!buf)
		return 0;
	memcpy(buf, data, size);
	buf[size] = 0;

	nul = memchr(data, 0, size);
	if (nul) {
		ilen = (size_t)(nul - data);
		fuzz_env_set_proc(buf, ilen, buf + ilen + 1, size - ilen - 1);
	} else {
		fuzz_env_set_proc(buf, size, fuzz_env_default_stat,
				  strlen(fuzz_env_default_stat));
	}

	fuzz_env_reset_daemon_globals();
	fuzz_env_daemon_start();
	scan(NULL);
	scan(NULL);
	fuzz_env_daemon_stop();

	free(buf);
	return 0;
}
