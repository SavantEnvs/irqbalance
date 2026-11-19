/*
 * selftest — known-answer checks of the irqbalance daemon, built with normal
 * flags for mayhem/test.sh. It drives the daemon on the fixed fake topology of
 * fuzz_env.c (4 cpus, L2 pairs {0,1} {2,3}, one package, node 0, SATA on IRQ 16,
 * NIC MSI-X IRQs 24-26) and prints "key: value" lines; test.sh compares each
 * against its expected value. Output never depends on directory-listing order.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "irqbalance.h"
#include "fuzz_env.h"

gboolean scan(gpointer data);
gboolean sock_handle(gint fd, GIOCondition condition, gpointer user_data);
extern int sleep_interval;

static const int known_irqs[] = { 0, 8, 9, 16, 24, 25, 26, 30 };
#define NKNOWN (sizeof(known_irqs) / sizeof(known_irqs[0]))

/* cpumask_scnprintf without the leading all-zero words */
static void print_mask(const char *key, cpumask_t m)
{
	char buf[2048];
	char *p;

	cpumask_scnprintf(buf, sizeof(buf), m);
	p = buf;
	while (!strncmp(p, "00000000,", 9))
		p += 9;
	printf("%s: %s weight=%d\n", key, p, cpus_weight(m));
}

static void request(const char *msg)
{
	fuzz_env_set_client_msg(msg, strlen(msg));
	sock_handle(-1, G_IO_IN, NULL);
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* "TYPE t NUMBER n" pairs of a stats reply, sorted, plus its IRQ count */
static void print_stats(const char *key, const char *reply)
{
	char *copy = strdup(reply), *save = NULL, *tok;
	char *objs[64];
	int nobj = 0, nirq = 0, i;

	for (tok = strtok_r(copy, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		if (!strcmp(tok, "TYPE") && nobj < 64) {
			char *t = strtok_r(NULL, " ", &save);
			char *nk = strtok_r(NULL, " ", &save);
			char *n = strtok_r(NULL, " ", &save);
			char *o = malloc(64);
			snprintf(o, 64, "%s/%s", t ? t : "?", (nk && n) ? n : "?");
			objs[nobj++] = o;
		} else if (!strcmp(tok, "IRQ")) {
			nirq++;
		}
	}
	qsort(objs, nobj, sizeof(objs[0]), cmp_str);
	printf("%s: objects=", key);
	for (i = 0; i < nobj; i++) {
		printf("%s%s", i ? "," : "", objs[i]);
		free(objs[i]);
	}
	printf(" irqs=%d\n", nirq);
	free(copy);
}

static void print_db(const char *prefix)
{
	size_t i;

	for (i = 0; i < NKNOWN; i++) {
		struct irq_info *info = get_irq_info(known_irqs[i]);
		if (!info) {
			printf("%s irq%d: absent\n", prefix, known_irqs[i]);
			continue;
		}
		printf("%s irq%d: type=%d class=%d level=%d count=%llu node=%d\n", prefix,
		       info->irq, info->type, info->class, info->level,
		       (unsigned long long)info->irq_count,
		       info->numa_node ? info->numa_node->number : -99);
	}
}

int main(void)
{
	cpumask_t m;
	GList *l, *irqs;
	char line[256];

	if (fuzz_env_init())
		return 1;

	/* --- bitmap.c parsers --- */
	cpus_clear(m);
	cpulist_parse("0-2,5", 5, m);
	print_mask("cpulist 0-2,5", m);
	cpus_clear(m);
	cpulist_parse("1,3,64-65", 9, m);
	print_mask("cpulist 1,3,64-65", m);
	cpus_clear(m);
	cpumask_parse_user("f0", 2, m);
	print_mask("cpumask f0", m);
	cpus_clear(m);
	cpumask_parse_user("1,00000002", 10, m);
	print_mask("cpumask 1,00000002", m);

	/* --- /proc/interrupts tokenising --- */
	fuzz_env_reset_daemon_globals();
	irqs = collect_full_irq_list();
	printf("collect count: %u\n", g_list_length(irqs));
	for (l = irqs; l; l = l->next) {
		struct irq_info *info = l->data;
		/* on x86 the kernel line's '\n' stays part of the last token */
		size_t nl = strcspn(info->name, "\n");
		printf("collect irq%d: type=%d class=%d name=%.*s%s\n", info->irq, info->type,
		       info->class, (int)nl, info->name, info->name[nl] ? "\\n" : "");
		free(info->name);
		free(info);
	}
	g_list_free(irqs);

	/* --- daemon start-up on the fake topology --- */
	fuzz_env_reset_daemon_globals();
	fuzz_env_daemon_start();
	printf("topology: nodes=%u packages=%u caches=%u cpus=%d online=%d\n",
	       g_list_length(numa_nodes), g_list_length(packages),
	       g_list_length(cache_domains), get_cpu_count(), num_online_cpus());
	print_db("start");
	scan(NULL);
	printf("scan cycle=%llu rescan=%d\n", cycle_count, need_rescan);

	/* --- control socket --- */
	request("setup");
	snprintf(line, sizeof(line), "%s", fuzz_env_last_reply());
	printf("sock setup: %s\n", line);
	request("stats");
	print_stats("sock stats", fuzz_env_last_reply());

	request("settings sleep 7");
	printf("sock sleep: %d\n", sleep_interval);
	request("settings sleep 0");
	printf("sock sleep 0 ignored: %d\n", sleep_interval);

	request("settings ban irqs 24 25");
	printf("sock ban rescan: %d banned=%u\n", need_rescan, g_list_length(cl_banned_irqs));
	scan(NULL);
	print_db("banned");
	request("setup");
	print_stats("sock setup banned", fuzz_env_last_reply());
	printf("sock setup banned prefix: %.8s\n", fuzz_env_last_reply());

	request("settings ban irqs NONE");
	printf("sock unban: banned=%u\n", g_list_length(cl_banned_irqs));
	scan(NULL);

	request("settings cpus 3");
	scan(NULL);
	print_mask("sock cpus 3 banned", banned_cpus);
	printf("sock cpus 3 cpus=%d\n", get_cpu_count());
	request("setup");
	{
		const char *r = fuzz_env_last_reply();
		const char *b = strstr(r, "BANNED ");
		size_t bl = b ? strlen(b) : 0;
		printf("sock cpus 3 setup tail: %s\n", bl > 8 ? b + bl - 8 : "?");
	}
	request("stats");
	print_stats("sock cpus 3 stats", fuzz_env_last_reply());

	request("settings cpus NULL");
	scan(NULL);
	printf("sock cpus NULL cpus=%d\n", get_cpu_count());

	fuzz_env_daemon_stop();
	printf("done\n");
	return 0;
}
