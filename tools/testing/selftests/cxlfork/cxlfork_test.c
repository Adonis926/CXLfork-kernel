// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/cxlfork.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define KSFT_SKIP 4
#define TEST_BASE ((void *)0x500000000000ULL)
#define FNV_SEED 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL

static uint64_t fnv_bytes(uint64_t hash, const void *data, size_t bytes)
{
	const unsigned char *p = data;
	size_t i;

	for (i = 0; i < bytes; i++) {
		hash ^= p[i];
		hash *= FNV_PRIME;
	}
	return hash;
}

static int open_device(void)
{
	return open(CXLFORK_DEVICE, O_RDWR | O_CLOEXEC);
}

static int inspect_missing(int fd, uint64_t key);

static void tap(bool ok, unsigned int nr, const char *name)
{
	printf("%s %u - %s\n", ok ? "ok" : "not ok", nr, name);
}

static int run_abi_tests(void)
{
	struct cxlfork_query_caps_v2 caps = {
		.size = sizeof(caps),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	struct cxlfork_query_caps_v2 bad;
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	uint64_t required;
	uint64_t forbidden;
	unsigned int nr = 1;
	unsigned int failed = 0;
	bool ok;
	int fd;
	int ret;

	printf("TAP version 13\n");
	fd = open_device();
	if (fd < 0) {
		printf("1..0 # SKIP %s unavailable: %s\n",
		       CXLFORK_DEVICE, strerror(errno));
		return KSFT_SKIP;
	}
	printf("1..9\n");

	ret = ioctl(fd, CXLFORK_QUERY_CAPS_V2, &caps);
	ok = ret == 0;
	tap(ok, nr++, "QUERY_CAPS_V2 succeeds");
	failed += !ok;

	ok = caps.size == sizeof(caps) &&
		caps.abi_version == CXLFORK_ABI_VERSION_V2;
	tap(ok, nr++, "v2 size and version round trip");
	failed += !ok;

	required = CXLFORK_CAP_V2_ABI |
		CXLFORK_CAP_PTE_IMAGE_RECONSTRUCTION |
		CXLFORK_CAP_REAL_SHARED_PTE_LEAF |
		CXLFORK_CAP_VMA_IMAGE_RECONSTRUCTION |
		CXLFORK_CAP_CONSISTENT_SINGLE_THREAD |
		CXLFORK_CAP_RELIABLE_SLOT_GENERATION;
	ok = (caps.capabilities & required) == required;
	tap(ok, nr++, "image reconstruction capabilities are explicit");
	failed += !ok;

	forbidden = CXLFORK_CAP_PTE_LEAF_COW |
		CXLFORK_CAP_REAL_SHARED_VMA_LEAF |
		CXLFORK_CAP_FULL_PRIVATE_STATE |
		CXLFORK_CAP_A_BIT_HYBRID;
	ok = !(caps.capabilities & forbidden);
	tap(ok, nr++, "unimplemented paper mechanisms are not advertised");
	failed += !ok;

	ok = !(caps.capabilities & ~CXLFORK_CAP_KNOWN_MASK) &&
		caps.page_size == (uint32_t)getpagesize() && caps.max_slots > 0 &&
		caps.slot_bytes > caps.data_offset;
	tap(ok, nr++, "capability limits are sane");
	failed += !ok;

	bad = caps;
	bad.abi_version++;
	errno = 0;
	ret = ioctl(fd, CXLFORK_QUERY_CAPS_V2, &bad);
	ok = ret == -1 && errno == EPROTONOSUPPORT;
	tap(ok, nr++, "unknown ABI version returns EPROTONOSUPPORT");
	failed += !ok;

	bad = caps;
	bad.size = sizeof(struct cxlfork_v2_header);
	errno = 0;
	ret = ioctl(fd, CXLFORK_QUERY_CAPS_V2, &bad);
	ok = ret == -1 && errno == EINVAL;
	tap(ok, nr++, "short v2 structure returns EINVAL");
	failed += !ok;

	bad = caps;
	bad.reserved0 = 1;
	errno = 0;
	ret = ioctl(fd, CXLFORK_QUERY_CAPS_V2, &bad);
	ok = ret == -1 && errno == EINVAL;
	tap(ok, nr++, "nonzero v2 header reserved field returns EINVAL");
	failed += !ok;

	inspect.key = 0xf00d000000000000ULL ^ (uint64_t)getpid();
	errno = 0;
	ret = ioctl(fd, CXLFORK_INSPECT_V2, &inspect);
	ok = ret == -1 && errno == ENOENT;
	tap(ok, nr++, "INSPECT rejects an unknown key");
	failed += !ok;

	close(fd);
	return failed ? 1 : 0;
}

static void fill_region(unsigned char *p, size_t bytes, uint64_t key,
			unsigned int region)
{
	size_t i;

	for (i = 0; i < bytes; i++)
		p[i] = (unsigned char)(i * 131U + region * 17U + key);
}

static int prepare_snapshot(uint64_t key, size_t bytes)
{
	struct cxlfork_checkpoint op = { 0 };
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	unsigned char *first;
	unsigned char *second = NULL;
	size_t page = getpagesize();
	size_t first_bytes;
	size_t second_bytes;
	uintptr_t second_addr;
	uint64_t hash = FNV_SEED;
	int fd;

	bytes = (bytes + page - 1) & ~(page - 1);
	if (bytes < page)
		bytes = page;
	first_bytes = bytes < 2 * page ? bytes : (bytes / 2) & ~(page - 1);
	second_bytes = bytes - first_bytes;
	first = mmap(TEST_BASE, first_bytes, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (first == MAP_FAILED) {
		perror("mmap first");
		return 1;
	}
	fill_region(first, first_bytes, key, 0);
	hash = fnv_bytes(hash, first, first_bytes);
	if (second_bytes) {
		second_addr = (uintptr_t)TEST_BASE + first_bytes + page;
		second = mmap((void *)second_addr, second_bytes,
			      PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			      -1, 0);
		if (second == MAP_FAILED) {
			perror("mmap second");
			return 1;
		}
		fill_region(second, second_bytes, key, 1);
		hash = fnv_bytes(hash, second, second_bytes);
	}

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	op.key = key;
	op.scan_start = (uintptr_t)TEST_BASE;
	op.scan_end = (uintptr_t)TEST_BASE + first_bytes + page + second_bytes;
	if (ioctl(fd, CXLFORK_FORK_PREPARE, &op)) {
		perror("FORK_PREPARE");
		return 1;
	}
	if (ioctl(fd, CXLFORK_INSPECT_V2, &inspect)) {
		perror("INSPECT after prepare");
		return 1;
	}
	if (inspect.flags & CXLFORK_INSPECT_F_CHECKSUM_MISMATCH ||
	    inspect.page_checksum != hash ||
	    inspect.observed_page_checksum != hash) {
		fprintf(stderr, "checksum mismatch user=%" PRIu64
			" stored=%" PRIu64 " observed=%" PRIu64 "\n",
			hash, (uint64_t)inspect.page_checksum,
			(uint64_t)inspect.observed_page_checksum);
		return 1;
	}
	printf("prepare key=%" PRIu64 " slot=%u regions=%" PRIu64
	       " pages=%" PRIu64 " checksum=%" PRIu64 " image_bytes=%" PRIu64
	       " verify=ok\n", key, inspect.slot,
	       (uint64_t)inspect.nr_regions,
	       (uint64_t)inspect.total_pages, hash,
	       (uint64_t)inspect.image_bytes);
	close(fd);
	return 0;
}

static uint64_t hash_restored_regions(const struct cxlfork_restore *op)
{
	uint64_t hash = FNV_SEED;
	uint64_t i;

	for (i = 0; i < op->nr_regions; i++)
		hash = fnv_bytes(hash, (void *)(uintptr_t)op->regions[i].start,
				 op->regions[i].length);
	return hash;
}

static int restore_snapshot(uint64_t key, const char *policy)
{
	struct cxlfork_restore op = { .key = key };
	struct cxlfork_inspect_v2 before = {
		.size = sizeof(before),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	struct cxlfork_inspect_v2 after;
	struct cxlfork_inspect_v2 after_second;
	uint64_t hash;
	unsigned char *first;
	int fd;

	if (!strcmp(policy, "mow"))
		op.flags = CXLFORK_F_SHARED_COW;
	else if (!strcmp(policy, "moa"))
		op.flags = CXLFORK_F_PRIVATE_COW;
	else if (!strcmp(policy, "readonly"))
		op.flags = CXLFORK_F_MAP_READONLY;
	else {
		fprintf(stderr, "unknown policy: %s\n", policy);
		return 2;
	}
	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	if (ioctl(fd, CXLFORK_FORK_RESUME, &op)) {
		perror("FORK_RESUME");
		return 1;
	}
	hash = hash_restored_regions(&op);
	before.address = op.regions[0].start;
	if (ioctl(fd, CXLFORK_INSPECT_V2, &before)) {
		perror("INSPECT restored page");
		return 1;
	}
	if (hash != before.page_checksum) {
		fprintf(stderr, "restored checksum mismatch\n");
		return 1;
	}
	if (!strcmp(policy, "readonly")) {
		if (!(before.flags & CXLFORK_INSPECT_F_SHARED_LEAF_VALID) ||
		    !(before.flags & CXLFORK_INSPECT_F_CURRENT_PMD_VALID) ||
		    !before.shared_leaf_pfn ||
		    before.current_pmd_pfn != before.shared_leaf_pfn ||
		    before.current_pfn != before.shared_pfn) {
			fprintf(stderr, "readonly restore did not attach the shared CXL PTE leaf\n");
			return 1;
		}
	}
	after = before;
	after_second = before;
	if (strcmp(policy, "readonly")) {
		first = (void *)(uintptr_t)op.regions[0].start;
		first[0] ^= 0x5a;
		after.size = sizeof(after);
		after.abi_version = CXLFORK_ABI_VERSION_V2;
		after.reserved0 = 0;
		if (ioctl(fd, CXLFORK_INSPECT_V2, &after)) {
			perror("INSPECT after write");
			return 1;
		}
		if (after.observed_page_checksum != before.page_checksum) {
			fprintf(stderr, "%s write changed the shared checkpoint image\n",
				policy);
			return 1;
		}
		if (!strcmp(policy, "mow") &&
		    (after.current_pfn == before.current_pfn ||
		     after.current_pfn == after.shared_pfn)) {
			fprintf(stderr, "MoW write did not materialize a local PFN\n");
			return 1;
		}
		if (!strcmp(policy, "moa") &&
		    (before.current_pfn == before.shared_pfn ||
		     after.current_pfn != before.current_pfn)) {
			fprintf(stderr, "MoA did not retain its first-access local PFN\n");
			return 1;
		}
		first[0] ^= 0xa5;
		after_second = before;
		after_second.size = sizeof(after_second);
		after_second.abi_version = CXLFORK_ABI_VERSION_V2;
		after_second.reserved0 = 0;
		if (ioctl(fd, CXLFORK_INSPECT_V2, &after_second)) {
			perror("INSPECT after second write");
			return 1;
		}
		if (after_second.current_pfn != after.current_pfn) {
			fprintf(stderr, "%s repeated write changed PFN again\n",
				policy);
			return 1;
		}
		if (after_second.observed_page_checksum != before.page_checksum) {
			fprintf(stderr, "%s repeated write changed the shared checkpoint image\n",
				policy);
			return 1;
		}
	}
	printf("restore key=%" PRIu64 " policy=%s regions=%" PRIu64
	       " pages=%" PRIu64 " checksum=%" PRIu64
	       " shared_pfn=%" PRIu64 " before_pfn=%" PRIu64
	       " after_pfn=%" PRIu64 " second_pfn=%" PRIu64
	       " shared_leaf_pfn=%" PRIu64 " current_pmd_pfn=%" PRIu64
	       " verify=ok\n",
	       key, policy, (uint64_t)op.nr_regions, (uint64_t)op.total_pages,
	       hash, (uint64_t)before.shared_pfn,
	       (uint64_t)before.current_pfn, (uint64_t)after.current_pfn,
	       (uint64_t)after_second.current_pfn,
	       (uint64_t)before.shared_leaf_pfn,
	       (uint64_t)before.current_pmd_pfn);
	close(fd);
	return 0;
}

static int restore_conflict(uint64_t key, const char *policy)
{
	struct cxlfork_restore op = { .key = key };
	unsigned char *guard;
	size_t page = getpagesize();
	int fd;
	int ret;

	if (!strcmp(policy, "mow"))
		op.flags = CXLFORK_F_SHARED_COW;
	else if (!strcmp(policy, "moa"))
		op.flags = CXLFORK_F_PRIVATE_COW;
	else if (!strcmp(policy, "readonly"))
		op.flags = CXLFORK_F_MAP_READONLY;
	else {
		fprintf(stderr, "unknown policy: %s\n", policy);
		return 2;
	}

	guard = mmap(TEST_BASE, page, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (guard == MAP_FAILED) {
		perror("mmap conflict guard");
		return 1;
	}
	guard[0] = 0x7e;

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	errno = 0;
	ret = ioctl(fd, CXLFORK_FORK_RESUME, &op);
	if (ret != -1 || errno != EEXIST) {
		fprintf(stderr, "conflict restore: expected EEXIST got ret=%d errno=%d\n",
			ret, errno);
		close(fd);
		return 1;
	}
	if (guard[0] != 0x7e) {
		fprintf(stderr, "conflict restore replaced the existing mapping\n");
		close(fd);
		return 1;
	}

	printf("conflict key=%" PRIu64 " policy=%s errno=%d guard=ok verify=ok\n",
	       key, policy, EEXIST);
	close(fd);
	return 0;
}

static int inspect_snapshot(uint64_t key, uint64_t address)
{
	struct cxlfork_inspect_v2 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.address = address,
	};
	int fd = open_device();

	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_INSPECT_V2, &op)) {
		perror("INSPECT_V2");
		return 1;
	}
	printf("inspect key=%" PRIu64 " generation=%" PRIu64
	       " slot=%u state=%u readers=%u regions=%" PRIu64
	       " pages=%" PRIu64 " page_checksum=%" PRIu64
	       " observed_page_checksum=%" PRIu64 " leaf_checksum=%" PRIu64
	       " observed_leaf_checksum=%" PRIu64 " shared_pfn=%" PRIu64
	       " current_pfn=%" PRIu64 " shared_leaf_pfn=%" PRIu64
	       " current_pmd_pfn=%" PRIu64 " flags=%" PRIu64 "\n",
	       (uint64_t)op.key, (uint64_t)op.generation, op.slot, op.state,
	       op.reader_count, (uint64_t)op.nr_regions,
	       (uint64_t)op.total_pages, (uint64_t)op.page_checksum,
	       (uint64_t)op.observed_page_checksum, (uint64_t)op.leaf_checksum,
	       (uint64_t)op.observed_leaf_checksum, (uint64_t)op.shared_pfn,
	       (uint64_t)op.current_pfn, (uint64_t)op.shared_leaf_pfn,
	       (uint64_t)op.current_pmd_pfn, (uint64_t)op.flags);
	close(fd);
	return 0;
}

static int release_snapshot(uint64_t key)
{
	struct cxlfork_release op = { .key = key };
	int fd = open_device();

	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_RELEASE, &op)) {
		perror("RELEASE");
		return 1;
	}
	close(fd);
	return 0;
}

static int release_with_errno(int fd, uint64_t key, int expected_errno)
{
	struct cxlfork_release op = { .key = key };
	int ret;

	errno = 0;
	ret = ioctl(fd, CXLFORK_RELEASE, &op);
	if (expected_errno)
		return ret == -1 && errno == expected_errno ? 0 : -1;
	return ret == 0 ? 0 : -1;
}

static int prepare_existing_range(int fd, uint64_t key, void *addr,
				  size_t bytes)
{
	struct cxlfork_checkpoint op = {
		.key = key,
		.scan_start = (uintptr_t)addr,
		.scan_end = (uintptr_t)addr + bytes,
	};

	return ioctl(fd, CXLFORK_FORK_PREPARE, &op);
}

static int inspect_ready(int fd, uint64_t key, uint64_t *generation,
			 uint32_t *readers)
{
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};

	if (ioctl(fd, CXLFORK_INSPECT_V2, &inspect))
		return -1;
	if (inspect.state != CXLFORK_SLOT_READY || !inspect.generation)
		return -1;
	if (generation)
		*generation = inspect.generation;
	if (readers)
		*readers = inspect.reader_count;
	return 0;
}

static int hold_restore(uint64_t key, unsigned int seconds)
{
	struct cxlfork_restore op = {
		.key = key,
		.flags = CXLFORK_F_PRIVATE_COW,
	};
	volatile unsigned char *p;
	int fd;

	fd = open_device();
	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_FORK_RESUME, &op)) {
		perror("FORK_RESUME hold");
		close(fd);
		return 1;
	}
	p = (void *)(uintptr_t)op.regions[0].start;
	(void)*p;
	sleep(seconds);
	close(fd);
	return 0;
}

static int run_lifecycle_tests(uint64_t key)
{
	unsigned char *anon;
	size_t page = getpagesize();
	uint64_t generation_before = 0;
	uint64_t generation_after = 0;
	uint32_t readers = 0;
	pid_t child;
	int status;
	int fd;
	int failed = 0;

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	anon = mmap(TEST_BASE, page, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (anon == MAP_FAILED) {
		perror("mmap lifecycle");
		close(fd);
		return 1;
	}
	fill_region(anon, page, key, 0);
	if (prepare_existing_range(fd, key, anon, page)) {
		perror("lifecycle prepare");
		close(fd);
		return 1;
	}
	if (inspect_ready(fd, key, &generation_before, &readers) || readers) {
		fprintf(stderr, "lifecycle: initial inspect failed\n");
		failed++;
	}

	errno = 0;
	if (prepare_existing_range(fd, key + 16, anon, page) != -1 ||
	    errno != EEXIST) {
		fprintf(stderr, "lifecycle: same-slot collision did not EEXIST\n");
		failed++;
	}
	if (inspect_missing(fd, key + 16)) {
		fprintf(stderr, "lifecycle: collision key became visible\n");
		failed++;
	}
	if (inspect_ready(fd, key, &generation_after, NULL) ||
	    generation_after != generation_before) {
		fprintf(stderr, "lifecycle: original generation changed\n");
		failed++;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return 1;
	}
	if (!child) {
		munmap(anon, page);
		_exit(hold_restore(key, 3));
	}
	sleep(1);
	if (inspect_ready(fd, key, NULL, &readers) || !readers) {
		fprintf(stderr, "lifecycle: active restore reader not visible\n");
		failed++;
	}
	if (release_with_errno(fd, key, EBUSY)) {
		fprintf(stderr, "lifecycle: active release did not EBUSY\n");
		failed++;
	}
	waitpid(child, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "lifecycle: child restore failed\n");
		failed++;
	}
	if (release_with_errno(fd, key, 0)) {
		fprintf(stderr, "lifecycle: release after reader exit failed\n");
		failed++;
	}
	if (inspect_missing(fd, key)) {
		fprintf(stderr, "lifecycle: release left visible slot\n");
		failed++;
	}

	printf("lifecycle key=%" PRIu64 " generation=%" PRIu64
	       " verify=%s\n", key, generation_before,
	       failed ? "fail" : "ok");
	close(fd);
	return failed ? 1 : 0;
}

static int inspect_missing(int fd, uint64_t key)
{
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	int ret;

	errno = 0;
	ret = ioctl(fd, CXLFORK_INSPECT_V2, &inspect);
	return ret == -1 && errno == ENOENT ? 0 : -1;
}

static int expect_prepare_errno(int fd, struct cxlfork_checkpoint *op,
				int expected_errno, const char *name)
{
	int ret;

	errno = 0;
	ret = ioctl(fd, CXLFORK_FORK_PREPARE, op);
	if (ret != -1 || errno != expected_errno) {
		fprintf(stderr, "%s: expected errno %d got ret=%d errno=%d\n",
			name, expected_errno, ret, errno);
		return 1;
	}
	if (inspect_missing(fd, op->key)) {
		fprintf(stderr, "%s: failed prepare left a visible slot\n", name);
		return 1;
	}
	return 0;
}

static void *sleep_thread(void *arg)
{
	(void)arg;
	sleep(3);
	return NULL;
}

static int run_failure_tests(uint64_t key)
{
	struct cxlfork_checkpoint op = { 0 };
	unsigned char *anon;
	unsigned char *shared;
	unsigned char *filemap;
	size_t page = getpagesize();
	pthread_t thread;
	char template[] = "/tmp/cxlfork-filemap-XXXXXX";
	int tmpfd;
	int fd;
	int failed = 0;

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}

	anon = mmap(TEST_BASE, page, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (anon == MAP_FAILED) {
		perror("mmap anon");
		close(fd);
		return 1;
	}
	anon[0] = 0x5a;

	op.key = key++;
	op.flags = CXLFORK_F_FULL_PRIVATE_STATE;
	failed += expect_prepare_errno(fd, &op, EOPNOTSUPP,
				       "FULL_PRIVATE_STATE");

	memset(&op, 0, sizeof(op));
	op.key = key++;
	op.scan_start = (uintptr_t)anon;
	op.scan_end = (uintptr_t)anon + page;
	if (pthread_create(&thread, NULL, sleep_thread, NULL)) {
		perror("pthread_create");
		close(fd);
		return 1;
	}
	failed += expect_prepare_errno(fd, &op, EBUSY, "multithread");
	pthread_join(thread, NULL);

	shared = mmap((void *)((uintptr_t)TEST_BASE + 2 * page), page,
		      PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (shared == MAP_FAILED) {
		perror("mmap shared");
		close(fd);
		return 1;
	}
	shared[0] = 0xa5;
	memset(&op, 0, sizeof(op));
	op.key = key++;
	op.scan_start = (uintptr_t)shared;
	op.scan_end = (uintptr_t)shared + page;
	failed += expect_prepare_errno(fd, &op, EOPNOTSUPP,
				       "shared mapping");

	tmpfd = mkstemp(template);
	if (tmpfd < 0 || ftruncate(tmpfd, page)) {
		perror("file setup");
		close(fd);
		return 1;
	}
	unlink(template);
	filemap = mmap((void *)((uintptr_t)TEST_BASE + 4 * page), page,
		       PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_FIXED_NOREPLACE, tmpfd, 0);
	if (filemap == MAP_FAILED) {
		perror("mmap file");
		close(tmpfd);
		close(fd);
		return 1;
	}
	filemap[0] = 0x3c;
	memset(&op, 0, sizeof(op));
	op.key = key++;
	op.scan_start = (uintptr_t)filemap;
	op.scan_end = (uintptr_t)filemap + page;
	failed += expect_prepare_errno(fd, &op, EOPNOTSUPP,
				       "file mapping");
	close(tmpfd);

	printf("failure-tests key_base=%" PRIu64 " verify=%s\n",
	       key - 4, failed ? "fail" : "ok");
	close(fd);
	return failed ? 1 : 0;
}

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

int main(int argc, char **argv)
{
	uint64_t key;

	if (argc == 1 || !strcmp(argv[1], "abi"))
		return run_abi_tests();
	if (argc < 3) {
		fprintf(stderr, "usage: %s prepare KEY BYTES | restore KEY POLICY | "
			"inspect KEY [ADDRESS] | release KEY | failures KEY | "
			"lifecycle KEY | hold KEY SECONDS | conflict KEY POLICY\n",
			argv[0]);
		return 2;
	}
	key = parse_u64(argv[2]);
	if (!strcmp(argv[1], "hold") && argc == 4)
		return hold_restore(key, (unsigned int)parse_u64(argv[3]));
	if (!strcmp(argv[1], "failures") && argc == 3)
		return run_failure_tests(key);
	if (!strcmp(argv[1], "lifecycle") && argc == 3)
		return run_lifecycle_tests(key);
	if (!strcmp(argv[1], "prepare") && argc == 4)
		return prepare_snapshot(key, parse_u64(argv[3]));
	if (!strcmp(argv[1], "restore") && argc == 4)
		return restore_snapshot(key, argv[3]);
	if (!strcmp(argv[1], "conflict") && argc == 4)
		return restore_conflict(key, argv[3]);
	if (!strcmp(argv[1], "inspect") && (argc == 3 || argc == 4))
		return inspect_snapshot(key, argc == 4 ? parse_u64(argv[3]) : 0);
	if (!strcmp(argv[1], "release") && argc == 3)
		return release_snapshot(key);
	fprintf(stderr, "invalid arguments\n");
	return 2;
}
