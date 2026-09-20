// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/cxlfork.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define ARENA_BASE ((void *)0x520000000000ULL)
#define MAX_TOUCH_PAGES 32768ULL

static uint64_t parse_u64(const char *s)
{
	char *end;
	uint64_t value;

	errno = 0;
	value = strtoull(s, &end, 0);
	if (errno || !*s || *end) {
		fprintf(stderr, "invalid integer: %s\n", s);
		exit(2);
	}
	return value;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts)) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int pin_cpu0(void)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static int open_device(void)
{
	return open(CXLFORK_DEVICE, O_RDWR | O_CLOEXEC);
}

static void fill_pages(unsigned char *p, uint64_t pages, size_t page_size,
		       uint64_t key)
{
	uint64_t i;

	for (i = 0; i < pages; i++) {
		p[i * page_size] = (unsigned char)(key + i * 131U);
		p[i * page_size + page_size - 1] =
			(unsigned char)((key >> 8) ^ i);
	}
}

static int prepare(uint64_t key, uint64_t pages)
{
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS] = {0};
	struct cxlfork_prepare_v2 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	size_t page_size = (size_t)getpagesize();
	size_t bytes;
	unsigned char *arena;
	int fd;

	if (!pages || pages > MAX_TOUCH_PAGES || pages > SIZE_MAX / page_size)
		return 2;
	bytes = (size_t)pages * page_size;
	arena = mmap(ARENA_BASE, bytes, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (arena == MAP_FAILED) {
		perror("mmap prepare arena");
		return 1;
	}
	if (madvise(arena, bytes, MADV_NOHUGEPAGE)) {
		perror("madvise");
		return 1;
	}
	fill_pages(arena, pages, page_size, key);
	op.scan_start = (uintptr_t)arena;
	op.scan_end = (uintptr_t)arena + bytes;
	fd = open_device();
	if (fd < 0 || ioctl(fd, CXLFORK_PREPARE_V2, &op)) {
		perror(fd < 0 ? "open /dev/cxlfork" : "PREPARE_V2");
		return 1;
	}
	printf("event=prepare key=%" PRIu64 " generation=%" PRIu64
	       " pages=%" PRIu64 " page_checksum=%" PRIu64
	       " prepare_ns=%" PRIu64 " verify=ok\n",
	       key, (uint64_t)op.generation, (uint64_t)op.total_pages,
	       (uint64_t)op.page_checksum, (uint64_t)op.stats.total_ns);
	close(fd);
	return 0;
}

static int get_stats(int fd, uint64_t key, uint64_t generation,
		     uint64_t restore_id, struct cxlfork_restore_stats_v3 *stats)
{
	struct cxlfork_call_stats_v3 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V3,
		.key = key,
		.generation = generation,
		.restore_id = restore_id,
	};

	if (ioctl(fd, CXLFORK_GET_CALL_STATS_V3, &op))
		return -1;
	*stats = op.stats;
	return 0;
}

static int run(uint64_t key, uint64_t generation, uint64_t touch_pages,
	       uint64_t stride_pages, uint64_t sample)
{
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS] = {0};
	struct cxlfork_resume_v2 resume = {
		.size = sizeof(resume),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.generation = generation,
		.flags = CXLFORK_F_SHARED_COW,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_restore_stats_v3 first, second;
	struct rusage before, after;
	volatile unsigned char sink = 0;
	unsigned char *arena;
	uint64_t i, required_pages, begin, read_ns, first_ns, second_ns;
	size_t page_size = (size_t)getpagesize();
	int fd;

	if (!touch_pages || touch_pages > MAX_TOUCH_PAGES || !stride_pages)
		return 2;
	required_pages = (touch_pages - 1) * stride_pages + 1;
	if (required_pages < touch_pages)
		return 2;
	if (pin_cpu0()) {
		perror("sched_setaffinity cpu0");
		return 1;
	}
	fd = open_device();
	if (fd < 0 || ioctl(fd, CXLFORK_RESUME_V2, &resume)) {
		perror(fd < 0 ? "open /dev/cxlfork" : "RESUME_V2");
		return 1;
	}
	if (resume.region_count != 1 || resume.total_pages < required_pages) {
		fprintf(stderr, "restored region too small\n");
		return 1;
	}
	arena = (unsigned char *)(uintptr_t)regions[0].start;
	begin = now_ns();
	for (i = 0; i < touch_pages; i++)
		sink ^= arena[i * stride_pages * page_size];
	read_ns = now_ns() - begin;
	getrusage(RUSAGE_SELF, &before);
	begin = now_ns();
	for (i = 0; i < touch_pages; i++)
		arena[i * stride_pages * page_size] ^= 0x5a;
	first_ns = now_ns() - begin;
	getrusage(RUSAGE_SELF, &after);
	if (get_stats(fd, key, generation, resume.restore_id, &first)) {
		perror("GET_CALL_STATS_V3 first");
		return 1;
	}
	begin = now_ns();
	for (i = 0; i < touch_pages; i++)
		arena[i * stride_pages * page_size] ^= 0xa5;
	second_ns = now_ns() - begin;
	if (get_stats(fd, key, generation, resume.restore_id, &second)) {
		perror("GET_CALL_STATS_V3 second");
		return 1;
	}
	if (first.local_copy_pages != touch_pages ||
	    second.local_copy_pages != first.local_copy_pages ||
	    second.leaf_copy_pages != first.leaf_copy_pages) {
		fprintf(stderr, "unexpected CoW counters data=%" PRIu64
			" leaf=%" PRIu64 " second_data=%" PRIu64 "\n",
			(uint64_t)first.local_copy_pages,
			(uint64_t)first.leaf_copy_pages,
			(uint64_t)second.local_copy_pages);
		return 1;
	}
	printf("cxlfork,kernel,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
	       ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
	       ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
	       ",%" PRIu64 ",%" PRIu64 ",%u,ok\n",
	       sample, touch_pages, stride_pages, (uint64_t)resume.stats.total_ns,
	       read_ns, first_ns, second_ns,
	       first_ns > second_ns ? first_ns - second_ns : 0,
	       (uint64_t)first.local_copy_pages,
	       (uint64_t)first.leaf_copy_pages,
	       (uint64_t)first.data_cow_ns,
	       (uint64_t)first.leaf_materialize_ns,
	       (uint64_t)(after.ru_minflt - before.ru_minflt),
	       (uint64_t)first.faults, (unsigned int)sink);
	for (i = 0; i < resume.region_count; i++)
		munmap((void *)(uintptr_t)regions[i].start, regions[i].length);
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "header")) {
		puts("system,counter_source,sample,touch_pages,stride_pages,restore_ns,read_ns,first_write_ns,second_write_ns,cow_increment_ns,data_cow_pages,leaf_cow_pages,data_cow_sum_ns,leaf_materialize_sum_ns,minor_faults,kernel_faults,sink,verify");
		return 0;
	}
	if (argc == 4 && !strcmp(argv[1], "prepare"))
		return prepare(parse_u64(argv[2]), parse_u64(argv[3]));
	if (argc == 7 && !strcmp(argv[1], "run"))
		return run(parse_u64(argv[2]), parse_u64(argv[3]),
			   parse_u64(argv[4]), parse_u64(argv[5]),
			   parse_u64(argv[6]));
	fprintf(stderr, "usage: %s header | prepare KEY ARENA_PAGES | "
		"run KEY GENERATION TOUCH_PAGES STRIDE_PAGES SAMPLE\n", argv[0]);
	return 2;
}
