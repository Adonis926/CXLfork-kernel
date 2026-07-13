// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/cxlfork.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

_Static_assert(offsetof(struct cxlfork_litmus_v2, run_id) == 16,
	       "unexpected cxlfork_litmus_v2 layout");
_Static_assert(sizeof(struct cxlfork_litmus_v2) == 120,
	       "unexpected cxlfork_litmus_v2 size");

static uint64_t parse_u64(const char *value)
{
	char *end;
	uint64_t result;

	errno = 0;
	result = strtoull(value, &end, 0);
	if (errno || !*value || *end) {
		fprintf(stderr, "invalid integer: %s\n", value);
		exit(2);
	}
	return result;
}

static uint32_t parse_op(const char *value)
{
	if (!strcmp(value, "rmw"))
		return CXLFORK_LITMUS_RMW;
	if (!strcmp(value, "message"))
		return CXLFORK_LITMUS_MESSAGE;
	if (!strcmp(value, "pingpong"))
		return CXLFORK_LITMUS_PINGPONG;
	fprintf(stderr, "invalid operation: %s\n", value);
	exit(2);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage:\n"
		"  %s reset RUN_ID\n"
		"  %s query RUN_ID\n"
		"  %s run <rmw|message|pingpong> ROLE RUN_ID ITERATIONS TIMEOUT_MS\n",
		prog, prog, prog);
}

int main(int argc, char **argv)
{
	struct cxlfork_litmus_v2 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	int fd;

	if (argc == 3 && !strcmp(argv[1], "reset")) {
		op.op = CXLFORK_LITMUS_RESET;
		op.run_id = parse_u64(argv[2]);
	} else if (argc == 3 && !strcmp(argv[1], "query")) {
		op.op = CXLFORK_LITMUS_QUERY;
		op.run_id = parse_u64(argv[2]);
	} else if (argc == 7 && !strcmp(argv[1], "run")) {
		op.op = parse_op(argv[2]);
		op.role = (uint32_t)parse_u64(argv[3]);
		op.run_id = parse_u64(argv[4]);
		op.iterations = parse_u64(argv[5]);
		op.timeout_ns = parse_u64(argv[6]) * 1000000ULL;
	} else {
		usage(argv[0]);
		return 2;
	}

	fd = open(CXLFORK_DEVICE, O_RDWR);
	if (fd < 0) {
		perror("open /dev/cxlfork");
		return 1;
	}
	if (ioctl(fd, CXLFORK_LITMUS_V2, &op)) {
		perror("CXLFORK_LITMUS_V2");
		close(fd);
		return 1;
	}
	close(fd);
	printf("litmus op=%u role=%u run_id=%" PRIu64
	       " iterations=%" PRIu64 " counter=%" PRIu64
	       " completions=%" PRIu64 " errors=%" PRIu64
	       " sequence=%" PRIu64 " acknowledgement=%" PRIu64
	       " token=%" PRIu64 " verify=ok\n",
	       op.op, op.role, (uint64_t)op.run_id,
	       (uint64_t)op.iterations, (uint64_t)op.counter,
	       (uint64_t)op.completions, (uint64_t)op.errors,
	       (uint64_t)op.sequence, (uint64_t)op.acknowledgement,
	       (uint64_t)op.token);
	return 0;
}
