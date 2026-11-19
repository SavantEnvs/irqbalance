/*
 * ui_selftest — known-answer checks of irqbalance-ui's reply parsers, built with
 * normal flags for mayhem/test.sh. It answers get_data() with a fixed daemon
 * reply (ui_env.c), runs rescan_tree() and prints the parsed setup and cpu tree.
 */
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "irqbalance-ui.h"
#include "ui_env.h"

extern int state;
extern GList *tree;
extern setup_t setup;
gboolean rescan_tree(gpointer data);

static const char setup_reply[] =
	"SLEEP 7 IRQ 24 LOAD 10 DIFF 3 CLASS 4 IRQ 25 LOAD 0 DIFF 0 CLASS 4 BANNED 0000000c";
static const char stats_reply[] =
	"TYPE 3 NUMBER 0 LOAD 900 SAVE_MODE 0 "
	"TYPE 2 NUMBER 0 LOAD 900 SAVE_MODE 0 IRQ 16 LOAD 5 DIFF 300 CLASS 2 "
	"TYPE 1 NUMBER 0 LOAD 400 SAVE_MODE 0 "
	"TYPE 0 NUMBER 0 LOAD 200 SAVE_MODE 0 IRQ 24 LOAD 7 DIFF 6000 CLASS 4 "
	"TYPE 0 NUMBER 1 LOAD 200 SAVE_MODE 1 "
	"TYPE 1 NUMBER 1 LOAD 500 SAVE_MODE 0 "
	"TYPE 0 NUMBER 2 LOAD 250 SAVE_MODE 0 IRQ 25 LOAD 1 DIFF 3700 CLASS 4 IRQ 26 LOAD 1 DIFF 5 CLASS 4 "
	"TYPE 0 NUMBER 3 LOAD 250 SAVE_MODE 0 ";

static void dump(cpu_node_t *node, int depth)
{
	GList *l;
	printf("tree %*s type=%d number=%d load=%llu powersave=%d mask=%s cpus=",
	       depth * 2, "", node->type, node->number, (unsigned long long)node->load,
	       node->is_powersave, node->cpu_mask ? node->cpu_mask : "?");
	for (l = node->cpu_list; l; l = l->next)
		printf("%d%s", *(int *)l->data, l->next ? "," : "");
	printf(" irqs=");
	for (l = node->irqs; l; l = l->next) {
		irq_t *irq = l->data;
		printf("%d/%llu/%llu/%d/on%u%s", irq->vector, (unsigned long long)irq->load,
		       (unsigned long long)irq->diff, irq->class, g_list_length(irq->assigned_to),
		       l->next ? "," : "");
	}
	printf("\n");
	for (l = node->children; l; l = l->next)
		dump(l->data, depth + 1);
}

int main(void)
{
	GList *l;

	ui_env_set_replies(setup_reply, strlen(setup_reply), stats_reply, strlen(stats_reply));
	state = -1;
	rescan_tree(NULL);

	printf("setup sleep: %llu\n", (unsigned long long)setup.sleep);
	printf("setup banned irqs:");
	for (l = setup.banned_irqs; l; l = l->next) {
		irq_t *irq = l->data;
		printf(" %d/%llu/%llu/%d", irq->vector, (unsigned long long)irq->load,
		       (unsigned long long)irq->diff, irq->class);
	}
	printf("\nsetup banned cpus:");
	for (l = setup.banned_cpus; l; l = l->next)
		printf(" %llu", (unsigned long long)*(uint64_t *)l->data);
	printf("\ntree roots: %u\n", g_list_length(tree));
	for (l = tree; l; l = l->next)
		dump(l->data, 0);
	printf("done\n");
	return 0;
}
