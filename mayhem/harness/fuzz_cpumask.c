/*
 * fuzz_cpumask — irqbalance's cpumask / cpulist string parsers (bitmap.c).
 *
 * These parse every CPU-set string the daemon takes in: IRQBALANCE_BANNED_CPUS
 * (hex mask, cpumask_parse_user), IRQBALANCE_BANNED_CPULIST and the control
 * socket's "settings cpus" (cpulist_parse), and sysfs masks/lists
 * (local_cpus, shared_cpu_map, isolated, nohz_full).
 *
 * Input: byte 0 selects the parser (even: hex mask, odd: cpu list); the rest is
 * the string. The parsed mask is printed back with cpumask_scnprintf() and
 * re-parsed; the hex form is canonical, so print -> parse must round-trip to the
 * same mask (abort otherwise: a parser/printer disagreement is a real bug).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cpumask.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	cpumask_t mask, again;
	char out[NR_CPUS / 4 + NR_CPUS / 32 + 2];
	char *str;
	size_t len;

	if (size < 1)
		return -1;
	len = size - 1;
	str = malloc(len + 1);
	if (!str)
		return 0;
	memcpy(str, data + 1, len);
	str[len] = 0;

	cpus_clear(mask);
	if (data[0] & 1)
		cpulist_parse(str, len, mask);
	else
		cpumask_parse_user(str, len, mask);

	cpumask_scnprintf(out, sizeof(out), mask);
	cpus_clear(again);
	cpumask_parse_user(out, strlen(out), again);
	if (!cpus_equal(mask, again))
		abort();

	free(str);
	return 0;
}
