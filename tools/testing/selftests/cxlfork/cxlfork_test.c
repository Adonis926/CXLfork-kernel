// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/cxlfork.h>
#include <pthread.h>
#include <signal.h>
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
#define THREADCTX_STACK_BASE ((void *)0x600000100000ULL)
#define THREADCTX_STACK_SIZE (64 * 1024)
#define X86_PTE_ACCESSED (1ULL << 5)
#define X86_PTE_DIRTY (1ULL << 6)
#define FNV_SEED 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL

_Static_assert(sizeof(struct cxlfork_prepare_v2) == 240,
	       "unexpected cxlfork_prepare_v2 size");
_Static_assert(sizeof(struct cxlfork_resume_v2) == 312,
	       "unexpected cxlfork_resume_v2 size");
_Static_assert(sizeof(struct cxlfork_release_v2) == 64,
	       "unexpected cxlfork_release_v2 size");
_Static_assert(sizeof(struct cxlfork_call_stats_v2) == 272,
	       "unexpected cxlfork_call_stats_v2 size");
_Static_assert(sizeof(struct cxlfork_query_caps_v2) == 128,
	       "unexpected cxlfork_query_caps_v2 size");
_Static_assert(sizeof(struct cxlfork_gup_probe_v2) == 56,
	       "unexpected cxlfork_gup_probe_v2 size");

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
	printf("1..11\n");

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
		CXLFORK_CAP_PTE_LEAF_COW |
		CXLFORK_CAP_VMA_IMAGE_RECONSTRUCTION |
		CXLFORK_CAP_CONSISTENT_SINGLE_THREAD |
		CXLFORK_CAP_RELIABLE_SLOT_GENERATION |
		CXLFORK_CAP_USER_THREAD_CONTEXT_RESUME |
		CXLFORK_CAP_GLOBAL_FILE_STATE |
		CXLFORK_CAP_A_BIT_HYBRID;
	ok = (caps.capabilities & required) == required;
	tap(ok, nr++, "image reconstruction capabilities are explicit");
	failed += !ok;

	forbidden = CXLFORK_CAP_FULL_PRIVATE_STATE |
		CXLFORK_CAP_REAL_SHARED_VMA_LEAF;
	ok = !(caps.capabilities & forbidden);
	tap(ok, nr++, "unimplemented paper mechanisms are not advertised");
	failed += !ok;

	bad = caps;
	bad.size = sizeof(bad) + 8;
	errno = 0;
	ret = ioctl(fd, CXLFORK_QUERY_CAPS_V2, &bad);
	ok = ret == -1 && errno == EINVAL;
	tap(ok, nr++, "oversized v2 structure returns EINVAL");
	failed += !ok;

	{
		struct cxlfork_release_v2 release = {
			.size = sizeof(release),
			.abi_version = CXLFORK_ABI_VERSION_V2,
			.key = 1,
			.generation = 1,
			.reserved1 = { 1 },
		};

		errno = 0;
		ret = ioctl(fd, CXLFORK_RELEASE_V2, &release);
		ok = ret == -1 && errno == EINVAL;
		tap(ok, nr++, "v2 operation rejects nonzero reserved tail");
		failed += !ok;
	}

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

static uint64_t query_max_slots_fd(int fd)
{
	struct cxlfork_query_caps_v2 caps = {
		.size = sizeof(caps),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};

	if (ioctl(fd, CXLFORK_QUERY_CAPS_V2, &caps) || !caps.max_slots)
		return 16;
	return caps.max_slots;
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
	if (!inspect.fd_table_offset || !inspect.region_table_offset ||
	    !inspect.pte_table_offset || !inspect.page_data_offset ||
	    inspect.region_table_entries != inspect.nr_regions ||
	    inspect.pte_table_entries != inspect.total_pages ||
	    inspect.page_data_bytes != inspect.total_pages * page ||
	    inspect.extent_bytes != page ||
	    inspect.allocated_extents * inspect.extent_bytes < inspect.image_bytes) {
		fprintf(stderr, "manifest mismatch regions=%" PRIu64 "/%" PRIu64
			" ptes=%" PRIu64 "/%" PRIu64
			" page_data=%" PRIu64 "/%" PRIu64
			" extent=%" PRIu64 " allocated=%" PRIu64 "\n",
			(uint64_t)inspect.region_table_entries,
			(uint64_t)inspect.nr_regions,
			(uint64_t)inspect.pte_table_entries,
			(uint64_t)inspect.total_pages,
			(uint64_t)inspect.page_data_bytes,
			(uint64_t)inspect.total_pages * page,
			(uint64_t)inspect.extent_bytes,
			(uint64_t)inspect.allocated_extents);
		return 1;
	}
	printf("prepare key=%" PRIu64 " slot=%u regions=%" PRIu64
	       " pages=%" PRIu64 " checksum=%" PRIu64 " image_bytes=%" PRIu64
	       " region_table_bytes=%" PRIu64 " pte_table_bytes=%" PRIu64
	       " extents=%" PRIu64
	       " verify=ok\n", key, inspect.slot,
	       (uint64_t)inspect.nr_regions,
	       (uint64_t)inspect.total_pages, hash,
	       (uint64_t)inspect.image_bytes,
	       (uint64_t)inspect.region_table_bytes,
	       (uint64_t)inspect.pte_table_bytes,
	       (uint64_t)inspect.allocated_extents);
	close(fd);
	return 0;
}

__attribute__((noinline, noreturn))
static void threadctx_resume_entry(void)
{
	static const char msg[] = "threadctx-resume verify=ok\n";

	(void)!write(STDOUT_FILENO, msg, sizeof(msg) - 1);
	_exit(0);
}

static int map_threadctx_stack(void)
{
	void *stack;

	stack = mmap(THREADCTX_STACK_BASE, THREADCTX_STACK_SIZE,
		     PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (stack == MAP_FAILED) {
		perror("mmap threadctx stack");
		return 1;
	}
	return 0;
}

static int prepare_threadctx_snapshot(uint64_t key, size_t bytes)
{
	struct cxlfork_checkpoint op = { 0 };
	unsigned char *first;
	size_t page = getpagesize();
	uint64_t hash = FNV_SEED;
	uintptr_t stack_top = (uintptr_t)THREADCTX_STACK_BASE + THREADCTX_STACK_SIZE;
	int fd;

	bytes = (bytes + page - 1) & ~(page - 1);
	if (bytes < page)
		bytes = page;
	first = mmap(TEST_BASE, bytes, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (first == MAP_FAILED) {
		perror("mmap threadctx data");
		return 1;
	}
	fill_region(first, bytes, key, 8);
	hash = fnv_bytes(hash, first, bytes);

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	op.key = key;
	op.scan_start = (uintptr_t)TEST_BASE;
	op.scan_end = (uintptr_t)TEST_BASE + bytes;
	op.flags = CXLFORK_F_USER_THREAD_STATE;
	op.thread_state.ip = (uintptr_t)threadctx_resume_entry;
	op.thread_state.sp = stack_top - 8;
	op.thread_state.flags = 0x202;
	if (ioctl(fd, CXLFORK_FORK_PREPARE, &op)) {
		perror("FORK_PREPARE threadctx");
		return 1;
	}
	printf("threadctx-prepare key=%" PRIu64 " ip=%" PRIx64
	       " sp=%" PRIx64 " pages=%" PRIu64 " checksum=%" PRIu64
	       " verify=ok\n",
	       key, (uint64_t)op.thread_state.ip,
	       (uint64_t)op.thread_state.sp, (uint64_t)op.total_pages, hash);
	close(fd);
	return 0;
}

static int restore_threadctx_snapshot(uint64_t key, const char *policy)
{
	struct cxlfork_restore op = { .key = key };
	int fd;

	if (!strcmp(policy, "readonly"))
		op.flags = CXLFORK_F_MAP_READONLY;
	else if (!strcmp(policy, "mow"))
		op.flags = CXLFORK_F_SHARED_COW;
	else if (!strcmp(policy, "moa"))
		op.flags = CXLFORK_F_PRIVATE_COW;
	else {
		fprintf(stderr, "unknown policy: %s\n", policy);
		return 2;
	}
	op.flags |= CXLFORK_F_APPLY_THREAD_STATE;
	if (map_threadctx_stack())
		return 1;
	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	if (ioctl(fd, CXLFORK_FORK_RESUME, &op)) {
		perror("FORK_RESUME threadctx");
		return 1;
	}
	fprintf(stderr, "threadctx restore returned without jumping to saved IP\n");
	return 1;
}

static int prepare_fdglobal_snapshot(uint64_t key, size_t bytes)
{
	struct cxlfork_checkpoint op = { 0 };
	unsigned char *first;
	size_t page = getpagesize();
	char path[128];
	sigset_t set;
	int filefd;
	int fd;

	bytes = (bytes + page - 1) & ~(page - 1);
	if (bytes < page)
		bytes = page;
	first = mmap(TEST_BASE, bytes, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (first == MAP_FAILED) {
		perror("mmap fdglobal data");
		return 1;
	}
	fill_region(first, bytes, key, 9);

	snprintf(path, sizeof(path), "/tmp/cxlfork-fdglobal-%" PRIu64, key);
	filefd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_APPEND, 0600);
	if (filefd < 0) {
		perror("open fdglobal file");
		return 1;
	}
	if (write(filefd, "cxlfork-fd-global\n", 18) != 18 ||
	    lseek(filefd, 11, SEEK_SET) != 11) {
		perror("setup fdglobal file");
		return 1;
	}
	if (filefd != 7) {
		if (dup2(filefd, 7) != 7) {
			perror("dup2 fdglobal file");
			return 1;
		}
		close(filefd);
		filefd = 7;
	}
	if (chdir("/tmp")) {
		perror("chdir /tmp");
		return 1;
	}
	umask(0027);
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &set, NULL)) {
		perror("sigprocmask block");
		return 1;
	}

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	op.key = key;
	op.scan_start = (uintptr_t)TEST_BASE;
	op.scan_end = (uintptr_t)TEST_BASE + bytes;
	op.flags = CXLFORK_F_REOPEN_FDS;
	if (ioctl(fd, CXLFORK_FORK_PREPARE, &op)) {
		perror("FORK_PREPARE fdglobal");
		return 1;
	}
	printf("fdglobal-prepare key=%" PRIu64 " fd=7 pos=11 flags=append"
	       " cwd=/tmp umask=027 sigusr1=blocked fds=%" PRIu64
	       " verify=ok\n",
	       key, (uint64_t)op.nr_fds);
	close(fd);
	close(filefd);
	return 0;
}

static int restore_fdglobal_snapshot(uint64_t key, const char *policy)
{
	struct cxlfork_restore op = { .key = key };
	char cwd[256];
	sigset_t set;
	mode_t old_umask;
	int flags;
	int devnull;
	int fd;
	int failed = 0;

	if (!strcmp(policy, "readonly"))
		op.flags = CXLFORK_F_MAP_READONLY;
	else if (!strcmp(policy, "mow"))
		op.flags = CXLFORK_F_SHARED_COW;
	else if (!strcmp(policy, "moa"))
		op.flags = CXLFORK_F_PRIVATE_COW;
	else {
		fprintf(stderr, "unknown policy: %s\n", policy);
		return 2;
	}
	op.flags |= CXLFORK_F_REOPEN_FDS | CXLFORK_F_APPLY_GLOBAL_STATE;

	devnull = open("/dev/null", O_RDONLY);
	if (devnull < 0 || dup2(devnull, 7) != 7) {
		perror("setup conflicting fd 7");
		return 1;
	}
	close(devnull);
	if (chdir("/")) {
		perror("chdir /");
		return 1;
	}
	umask(0002);
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (sigprocmask(SIG_UNBLOCK, &set, NULL)) {
		perror("sigprocmask unblock");
		return 1;
	}

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	if (ioctl(fd, CXLFORK_FORK_RESUME, &op)) {
		perror("FORK_RESUME fdglobal");
		return 1;
	}
	if (op.nr_fds != 1 || op.nr_fds_restored != 1) {
		fprintf(stderr, "fdglobal: expected one restored fd, got nr=%"
			PRIu64 " restored=%" PRIu64 "\n",
			(uint64_t)op.nr_fds, (uint64_t)op.nr_fds_restored);
		failed++;
	}
	if (lseek(7, 0, SEEK_CUR) != 11) {
		perror("fdglobal restored offset");
		failed++;
	}
	flags = fcntl(7, F_GETFL);
	if (flags < 0 || !(flags & O_APPEND)) {
		fprintf(stderr, "fdglobal: O_APPEND not restored\n");
		failed++;
	}
	if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/tmp")) {
		fprintf(stderr, "fdglobal: cwd not restored, got %s\n",
			cwd[0] ? cwd : "<none>");
		failed++;
	}
	old_umask = umask(0002);
	umask(old_umask);
	if (old_umask != 0027) {
		fprintf(stderr, "fdglobal: umask not restored, got %03o\n",
			old_umask);
		failed++;
	}
	if (sigprocmask(SIG_SETMASK, NULL, &set) ||
	    !sigismember(&set, SIGUSR1)) {
		fprintf(stderr, "fdglobal: SIGUSR1 mask not restored\n");
		failed++;
	}
	printf("fdglobal-restore key=%" PRIu64 " policy=%s fd=7 pos=11"
	       " flags=append cwd=/tmp umask=027 sigusr1=blocked verify=%s\n",
	       key, policy, failed ? "fail" : "ok");
	close(fd);
	return failed ? 1 : 0;
}

static int mark_self_pte_range(int fd, void *addr, size_t len, uint64_t flags)
{
	struct cxlfork_pte_mark_v2 mark = {
		.size = sizeof(mark),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.start = (uintptr_t)addr,
		.length = len,
		.flags = flags,
	};

	if (ioctl(fd, CXLFORK_PTE_MARK_V2, &mark)) {
		perror("PTE_MARK_V2");
		return 1;
	}
	return 0;
}

static int prepare_hybrid_snapshot(uint64_t key)
{
	struct cxlfork_checkpoint op = { 0 };
	unsigned char *p;
	size_t page = getpagesize();
	int fd;

	p = mmap(TEST_BASE, 3 * page, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (p == MAP_FAILED) {
		perror("mmap hybrid");
		return 1;
	}
	fill_region(p, 3 * page, key, 10);

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	if (mark_self_pte_range(fd, p, 3 * page,
				CXLFORK_PTE_MARK_CLEAR_ACCESSED |
				CXLFORK_PTE_MARK_CLEAR_DIRTY) ||
	    mark_self_pte_range(fd, p, page, CXLFORK_PTE_MARK_SET_ACCESSED) ||
	    mark_self_pte_range(fd, p + 2 * page, page,
				CXLFORK_PTE_MARK_SET_DIRTY)) {
		close(fd);
		return 1;
	}
	op.key = key;
	op.scan_start = (uintptr_t)p;
	op.scan_end = (uintptr_t)p + 3 * page;
	if (ioctl(fd, CXLFORK_FORK_PREPARE, &op)) {
		perror("FORK_PREPARE hybrid");
		return 1;
	}
	printf("hybrid-prepare key=%" PRIu64 " pages=%" PRIu64
	       " verify=ok\n", key, (uint64_t)op.total_pages);
	close(fd);
	return 0;
}

static int inspect_addr(int fd, uint64_t key, uint64_t addr,
			struct cxlfork_inspect_v2 *out)
{
	memset(out, 0, sizeof(*out));
	out->size = sizeof(*out);
	out->abi_version = CXLFORK_ABI_VERSION_V2;
	out->key = key;
	out->address = addr;
	return ioctl(fd, CXLFORK_INSPECT_V2, out);
}

static int restore_hybrid_snapshot(uint64_t key)
{
	struct cxlfork_restore op = {
		.key = key,
		.flags = CXLFORK_F_HYBRID_TIERING,
	};
	struct cxlfork_inspect_v2 hot, cold, dirty;
	size_t page = getpagesize();
	volatile unsigned char sink;
	unsigned char *base = TEST_BASE;
	int fd;
	int failed = 0;

	fd = open_device();
	if (fd < 0) {
		perror("open cxlfork");
		return KSFT_SKIP;
	}
	if (ioctl(fd, CXLFORK_FORK_RESUME, &op)) {
		perror("FORK_RESUME hybrid");
		return 1;
	}
	if (op.dirty_prefault_pages != 1 || !op.dirty_prefault_ns) {
		fprintf(stderr, "hybrid: dirty-prefault breakdown invalid pages=%" PRIu64
			" ns=%" PRIu64 "\n",
			(uint64_t)op.dirty_prefault_pages,
			(uint64_t)op.dirty_prefault_ns);
		return 1;
	}
	if (inspect_addr(fd, key, (uintptr_t)base, &hot) ||
	    inspect_addr(fd, key, (uintptr_t)base + page, &cold) ||
	    inspect_addr(fd, key, (uintptr_t)base + 2 * page, &dirty)) {
		perror("INSPECT hybrid before access");
		return 1;
	}
	if (!(hot.flags & CXLFORK_INSPECT_F_ORIG_PTE_VALID) ||
	    !(cold.flags & CXLFORK_INSPECT_F_ORIG_PTE_VALID) ||
	    !(dirty.flags & CXLFORK_INSPECT_F_ORIG_PTE_VALID)) {
		fprintf(stderr, "hybrid: orig PTE not reported\n");
		return 1;
	}
	if (!(hot.orig_pte & X86_PTE_ACCESSED) ||
	    (cold.orig_pte & X86_PTE_ACCESSED) ||
	    !(dirty.orig_pte & X86_PTE_DIRTY)) {
		fprintf(stderr, "hybrid: unexpected checkpoint A/D bits"
			" hot=%" PRIx64 " cold=%" PRIx64 " dirty=%" PRIx64 "\n",
			(uint64_t)hot.orig_pte, (uint64_t)cold.orig_pte,
			(uint64_t)dirty.orig_pte);
		return 1;
	}
	if (dirty.current_pfn == dirty.shared_pfn) {
		fprintf(stderr, "hybrid: dirty page was not prefaulted local\n");
		failed++;
	}
	sink = base[0];
	(void)sink;
	sink = base[page];
	(void)sink;
	if (inspect_addr(fd, key, (uintptr_t)base, &hot) ||
	    inspect_addr(fd, key, (uintptr_t)base + page, &cold)) {
		perror("INSPECT hybrid after access");
		return 1;
	}
	if (hot.current_pfn == hot.shared_pfn) {
		fprintf(stderr, "hybrid: A=1 page did not copy local\n");
		failed++;
	}
	if (cold.current_pfn != cold.shared_pfn) {
		fprintf(stderr, "hybrid: A=0 page did not remain shared\n");
		failed++;
	}
	printf("hybrid-restore key=%" PRIu64
	       " hot_orig=%" PRIx64 " cold_orig=%" PRIx64
	       " dirty_orig=%" PRIx64 " hot_pfn=%" PRIu64
	       " cold_pfn=%" PRIu64 " dirty_pfn=%" PRIu64
	       " dirty_prefault_pages=%" PRIu64
	       " verify=%s\n",
	       key, (uint64_t)hot.orig_pte, (uint64_t)cold.orig_pte,
	       (uint64_t)dirty.orig_pte, (uint64_t)hot.current_pfn,
	       (uint64_t)cold.current_pfn, (uint64_t)dirty.current_pfn,
	       (uint64_t)op.dirty_prefault_pages,
	       failed ? "fail" : "ok");
	close(fd);
	return failed ? 1 : 0;
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
	size_t page = getpagesize();
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
	if ((!strcmp(policy, "readonly") || !strcmp(policy, "mow")) &&
	    (!op.shared_leaf_attach_ns ||
	     !op.shared_leaf_attach_pages ||
	     op.shared_leaf_attach_pages > op.total_pages ||
	     !op.direct_pte_install_ns ||
	     op.direct_pte_install_pages != op.total_pages)) {
		fprintf(stderr, "%s restore missing shared-leaf/direct-install breakdown"
			" shared_leaf_ns=%" PRIu64 " shared_leaf_pages=%" PRIu64
			" direct_ns=%" PRIu64 " direct_pages=%" PRIu64 "\n",
			policy, (uint64_t)op.shared_leaf_attach_ns,
			(uint64_t)op.shared_leaf_attach_pages,
			(uint64_t)op.direct_pte_install_ns,
			(uint64_t)op.direct_pte_install_pages);
		return 1;
	}
	if (!strcmp(policy, "mow") &&
	    (!op.pte_image_reconstruct_ns ||
	     op.pte_image_reconstruct_pages != op.total_pages ||
	     op.pte_attach_ns != op.pte_image_reconstruct_ns ||
	     op.pte_attach_pages != op.pte_image_reconstruct_pages)) {
		fprintf(stderr, "MoW restore missing PTE-image reconstruction breakdown"
			" reconstruct_ns=%" PRIu64 " reconstruct_pages=%" PRIu64
			" legacy_ns=%" PRIu64 " legacy_pages=%" PRIu64 "\n",
			(uint64_t)op.pte_image_reconstruct_ns,
			(uint64_t)op.pte_image_reconstruct_pages,
			(uint64_t)op.pte_attach_ns,
			(uint64_t)op.pte_attach_pages);
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
	if (!(before.flags & CXLFORK_INSPECT_F_VMA_IMAGE_LOOKUP_VALID) ||
	    !before.vma_image_root_offset ||
	    !before.vma_image_nodes ||
	    before.vma_image_lookup_start > op.regions[0].start ||
	    before.vma_image_lookup_end < op.regions[0].start + page) {
		fprintf(stderr, "%s restore did not attach a CXL Maple VMA node\n",
			policy);
		return 1;
	}
	if (!strcmp(policy, "readonly") || !strcmp(policy, "mow")) {
		if (!(before.flags & CXLFORK_INSPECT_F_SHARED_LEAF_VALID) ||
		    !(before.flags & CXLFORK_INSPECT_F_CURRENT_PMD_VALID) ||
		    !before.shared_leaf_pfn ||
		    before.current_pmd_pfn != before.shared_leaf_pfn ||
		    before.current_pfn != before.shared_pfn) {
			fprintf(stderr, "%s restore did not attach the shared CXL PTE leaf\n",
				policy);
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
		if (!strcmp(policy, "mow") &&
		    (!(after.flags & CXLFORK_INSPECT_F_CURRENT_PMD_VALID) ||
		     after.current_pmd_pfn == before.shared_leaf_pfn)) {
			fprintf(stderr, "MoW write did not materialize a local PTE leaf\n");
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
		if (!strcmp(policy, "mow") &&
		    after_second.current_pmd_pfn != after.current_pmd_pfn) {
			fprintf(stderr, "MoW repeated write changed PTE leaf again\n");
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
	       " after_pmd_pfn=%" PRIu64 " second_pmd_pfn=%" PRIu64
	       " vma_image_root=%" PRIx64 " vma_image_nodes=%" PRIu64
	       " vma_image_lookup=%" PRIx64 "-%" PRIx64
	       " direct_pages=%" PRIu64 " shared_leaf_pages=%" PRIu64
	       " reconstruct_pages=%" PRIu64
	       " verify=ok\n",
	       key, policy, (uint64_t)op.nr_regions, (uint64_t)op.total_pages,
	       hash, (uint64_t)before.shared_pfn,
	       (uint64_t)before.current_pfn, (uint64_t)after.current_pfn,
	       (uint64_t)after_second.current_pfn,
	       (uint64_t)before.shared_leaf_pfn,
	       (uint64_t)before.current_pmd_pfn,
	       (uint64_t)after.current_pmd_pfn,
	       (uint64_t)after_second.current_pmd_pfn,
	       (uint64_t)before.vma_image_root_offset,
	       (uint64_t)before.vma_image_nodes,
	       (uint64_t)before.vma_image_lookup_start,
	       (uint64_t)before.vma_image_lookup_end,
	       (uint64_t)op.direct_pte_install_pages,
	       (uint64_t)op.shared_leaf_attach_pages,
	       (uint64_t)op.pte_image_reconstruct_pages);
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
	       " current_pmd_pfn=%" PRIu64 " vma_image_root=%" PRIx64
	       " vma_image_nodes=%" PRIu64 " vma_image_lookup=%" PRIx64 "-%" PRIx64
	       " flags=%" PRIu64 "\n",
	       (uint64_t)op.key, (uint64_t)op.generation, op.slot, op.state,
	       op.reader_count, (uint64_t)op.nr_regions,
	       (uint64_t)op.total_pages, (uint64_t)op.page_checksum,
	       (uint64_t)op.observed_page_checksum, (uint64_t)op.leaf_checksum,
	       (uint64_t)op.observed_leaf_checksum, (uint64_t)op.shared_pfn,
	       (uint64_t)op.current_pfn, (uint64_t)op.shared_leaf_pfn,
	       (uint64_t)op.current_pmd_pfn, (uint64_t)op.vma_image_root_offset,
	       (uint64_t)op.vma_image_nodes,
	       (uint64_t)op.vma_image_lookup_start,
	       (uint64_t)op.vma_image_lookup_end,
	       (uint64_t)op.flags);
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

static int hold_restore_after_close(uint64_t key, unsigned int seconds)
{
	struct cxlfork_restore op = {
		.key = key,
		.flags = CXLFORK_F_PRIVATE_COW,
	};
	volatile unsigned char *p;
	uint64_t i;
	int fd;

	fd = open_device();
	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_FORK_RESUME, &op)) {
		perror("FORK_RESUME hold-close");
		close(fd);
		return 1;
	}
	close(fd);
	for (i = 0; i < op.nr_regions; i++) {
		p = (void *)(uintptr_t)op.regions[i].start;
		p[0] ^= 0x3c;
	}
	sleep(seconds);
	printf("hold-close key=%" PRIu64 " regions=%" PRIu64
	       " verify=ok\n", key, (uint64_t)op.nr_regions);
	return 0;
}

static int v2_expect_errno(int fd, unsigned long request, void *op,
			   int expected, const char *name)
{
	int ret;

	errno = 0;
	ret = ioctl(fd, request, op);
	if (ret != -1 || errno != expected) {
		fprintf(stderr, "%s: expected errno=%d got ret=%d errno=%d\n",
			name, expected, ret, errno);
		return 1;
	}
	return 0;
}

static int run_v2_lifecycle_tests(uint64_t key)
{
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS];
	struct cxlfork_prepare_v2 prepare = {
		.size = sizeof(prepare),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_resume_v2 resume = {
		.size = sizeof(resume),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.flags = CXLFORK_F_PRIVATE_COW,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_call_stats_v2 stats = {
		.size = sizeof(stats),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	struct cxlfork_release_v2 release = {
		.size = sizeof(release),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	unsigned char *anon;
	uint64_t generation1;
	uint64_t restore_id;
	size_t page = getpagesize();
	uint32_t i;
	int fd;
	int failed = 0;

	memset(regions, 0, sizeof(regions));
	anon = mmap(TEST_BASE, page, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (anon == MAP_FAILED) {
		perror("v2 lifecycle mmap");
		return 1;
	}
	fill_region(anon, page, key, 0);
	prepare.scan_start = (uintptr_t)anon;
	prepare.scan_end = (uintptr_t)anon + page;
	fd = open_device();
	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_PREPARE_V2, &prepare)) {
		perror("PREPARE_V2");
		return 1;
	}
	if (!prepare.generation || prepare.region_count != 1 ||
	    prepare.total_pages != 1 || !prepare.page_checksum) {
		fprintf(stderr, "PREPARE_V2 outputs invalid\n");
		return 1;
	}
	generation1 = prepare.generation;
	resume.generation = generation1;
	if (munmap(anon, page)) {
		perror("v2 lifecycle source munmap");
		return 1;
	}
	if (ioctl(fd, CXLFORK_RESUME_V2, &resume)) {
		perror("RESUME_V2");
		return 1;
	}
	if (!resume.restore_id || resume.region_count != 1 ||
	    resume.total_pages != 1) {
		fprintf(stderr, "RESUME_V2 outputs invalid\n");
		return 1;
	}
	restore_id = resume.restore_id;
	close(fd);
	((volatile unsigned char *)(uintptr_t)regions[0].start)[0] ^= 0x55;

	fd = open_device();
	if (fd < 0)
		return 1;
	stats.generation = generation1;
	stats.restore_id = restore_id;
	if (ioctl(fd, CXLFORK_GET_CALL_STATS_V2, &stats)) {
		perror("GET_CALL_STATS_V2 after fd close");
		return 1;
	}
	if (!stats.stats.faults || !stats.stats.local_copy_pages) {
		fprintf(stderr, "per-call fault stats missing after fd close\n");
		failed++;
	}
	if (ioctl(fd, CXLFORK_INSPECT_V2, &inspect) ||
	    inspect.reader_count != 1) {
		fprintf(stderr, "V2 restore context reader not retained\n");
		failed++;
	}
	release.generation = generation1;
	failed += v2_expect_errno(fd, CXLFORK_RELEASE_V2, &release, EBUSY,
				  "active V2 release");
	for (i = 0; i < resume.region_count; i++)
		if (munmap((void *)(uintptr_t)regions[i].start, regions[i].length))
			failed++;
	if (ioctl(fd, CXLFORK_RELEASE_V2, &release)) {
		perror("RELEASE_V2 after unmap");
		failed++;
	}

	anon = mmap(TEST_BASE, page, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (anon == MAP_FAILED)
		return 1;
	fill_region(anon, page, key, 1);
	memset(&prepare.stats, 0, sizeof(prepare.stats));
	prepare.generation = 0;
	prepare.region_count = 0;
	prepare.total_pages = 0;
	prepare.page_checksum = 0;
	if (ioctl(fd, CXLFORK_PREPARE_V2, &prepare)) {
		perror("second PREPARE_V2");
		return 1;
	}
	if (prepare.generation == generation1) {
		fprintf(stderr, "generation did not advance\n");
		failed++;
	}
	resume.generation = generation1;
	resume.restore_id = 0;
	resume.region_count = 0;
	failed += v2_expect_errno(fd, CXLFORK_RESUME_V2, &resume, ESTALE,
				  "stale V2 resume");
	release.generation = generation1;
	failed += v2_expect_errno(fd, CXLFORK_RELEASE_V2, &release, ESTALE,
				  "stale V2 release");
	release.generation = prepare.generation;
	if (ioctl(fd, CXLFORK_RELEASE_V2, &release)) {
		perror("current generation RELEASE_V2");
		failed++;
	}
	munmap(anon, page);
	close(fd);
	printf("v2-lifecycle key=%" PRIu64 " generation1=%" PRIu64
	       " generation2=%" PRIu64 " restore_id=%" PRIu64
	       " verify=%s\n", key, generation1,
	       (uint64_t)prepare.generation, restore_id,
	       failed ? "fail" : "ok");
	return failed ? 1 : 0;
}

static int run_v2_rollback_tests(uint64_t key)
{
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS] = { 0 };
	struct cxlfork_prepare_v2 prepare = {
		.size = sizeof(prepare),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_resume_v2 resume = {
		.size = sizeof(resume),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.flags = CXLFORK_F_PRIVATE_COW |
			 CXLFORK_F_TEST_FAIL_AFTER_FIRST_REGION,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	struct cxlfork_release_v2 release = {
		.size = sizeof(release),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	unsigned char *first;
	unsigned char *second;
	void *probe0;
	void *probe1;
	size_t page = getpagesize();
	int fd;
	int failed = 0;

	first = mmap(TEST_BASE, page, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	second = mmap((char *)TEST_BASE + 2 * page, page,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (first == MAP_FAILED || second == MAP_FAILED) {
		perror("rollback source mmap");
		return 1;
	}
	fill_region(first, page, key, 0);
	fill_region(second, page, key, 1);
	prepare.scan_start = (uintptr_t)first;
	prepare.scan_end = (uintptr_t)second + page;
	fd = open_device();
	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_PREPARE_V2, &prepare)) {
		perror("rollback PREPARE_V2");
		return 1;
	}
	if (prepare.region_count != 2) {
		fprintf(stderr, "rollback snapshot expected two regions, got %u\n",
			prepare.region_count);
		return 1;
	}
	resume.generation = prepare.generation;
	release.generation = prepare.generation;
	if (munmap(first, page) || munmap(second, page)) {
		perror("rollback source munmap");
		return 1;
	}
	failed += v2_expect_errno(fd, CXLFORK_RESUME_V2, &resume, EIO,
				  "injected second-region restore failure");
	probe0 = mmap((void *)(uintptr_t)regions[0].start, regions[0].length,
		      PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS |
		      MAP_FIXED_NOREPLACE, -1, 0);
	probe1 = mmap((void *)(uintptr_t)regions[1].start, regions[1].length,
		      PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS |
		      MAP_FIXED_NOREPLACE, -1, 0);
	if (probe0 == MAP_FAILED || probe1 == MAP_FAILED) {
		perror("rollback left a partial mapping");
		failed++;
	}
	if (probe0 != MAP_FAILED)
		munmap(probe0, regions[0].length);
	if (probe1 != MAP_FAILED)
		munmap(probe1, regions[1].length);
	if (ioctl(fd, CXLFORK_INSPECT_V2, &inspect) || inspect.reader_count) {
		fprintf(stderr, "rollback retained slot reader=%u\n",
			inspect.reader_count);
		failed++;
	}
	if (ioctl(fd, CXLFORK_RELEASE_V2, &release)) {
		perror("rollback RELEASE_V2");
		failed++;
	}
	close(fd);
	printf("v2-rollback key=%" PRIu64 " regions=2 verify=%s\n",
	       key, failed ? "fail" : "ok");
	return failed ? 1 : 0;
}

static int run_v2_fastpath_tests(uint64_t key, size_t bytes)
{
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS] = { 0 };
	struct cxlfork_prepare_v2 prepare = {
		.size = sizeof(prepare),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_resume_v2 resume = {
		.size = sizeof(resume),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.flags = CXLFORK_F_MAP_READONLY,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_release_v2 release = {
		.size = sizeof(release),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	unsigned char *anon;
	void *mapped;
	size_t page = getpagesize();
	uint64_t fast_ns;
	uint64_t full_ns;
	uint64_t pages;
	int fd;
	int failed = 0;

	bytes = (bytes + page - 1) & ~(page - 1);
	if (bytes < 2 * 1024 * 1024)
		bytes = 2 * 1024 * 1024;
	anon = mmap(TEST_BASE, bytes, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (anon == MAP_FAILED) {
		perror("fastpath source mmap");
		return 1;
	}
	fill_region(anon, bytes, key, 0);
	prepare.scan_start = (uintptr_t)anon;
	prepare.scan_end = (uintptr_t)anon + bytes;
	fd = open_device();
	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_PREPARE_V2, &prepare) ||
	    munmap(anon, bytes)) {
		perror("fastpath prepare");
		return 1;
	}
	pages = prepare.total_pages;
	resume.generation = prepare.generation;
	release.generation = prepare.generation;
	if (ioctl(fd, CXLFORK_RESUME_V2, &resume)) {
		perror("fastpath resume");
		return 1;
	}
	fast_ns = resume.stats.validation_ns;
	if (!(resume.stats.path_mask & CXLFORK_RESTORE_PATH_FAST) ||
	    resume.stats.validated_ptes ||
	    !(resume.stats.path_mask & CXLFORK_RESTORE_PATH_SHARED_LEAF)) {
		fprintf(stderr, "fast path mask/validated_ptes mismatch\n");
		failed++;
	}
	mapped = (void *)(uintptr_t)regions[0].start;
	if (munmap(mapped, regions[0].length))
		failed++;
	resume.flags = CXLFORK_F_MAP_READONLY | CXLFORK_F_VALIDATE_FULL;
	resume.restore_id = 0;
	resume.region_count = 0;
	memset(&resume.stats, 0, sizeof(resume.stats));
	if (ioctl(fd, CXLFORK_RESUME_V2, &resume)) {
		perror("full-validation resume");
		return 1;
	}
	full_ns = resume.stats.validation_ns;
	if (!(resume.stats.path_mask & CXLFORK_RESTORE_PATH_FULL_VALIDATION) ||
	    resume.stats.validated_ptes != pages ||
	    !(resume.stats.path_mask & CXLFORK_RESTORE_PATH_SHARED_LEAF)) {
		fprintf(stderr, "full path mask/validated_ptes mismatch\n");
		failed++;
	}
	if (munmap((void *)(uintptr_t)regions[0].start, regions[0].length))
		failed++;
	if (ioctl(fd, CXLFORK_RELEASE_V2, &release)) {
		perror("fastpath release");
		failed++;
	}
	close(fd);
	printf("v2-fastpath key=%" PRIu64 " pages=%" PRIu64
	       " fast_validation_ns=%" PRIu64 " full_validation_ns=%" PRIu64
	       " verify=%s\n", key, pages, fast_ns, full_ns,
	       failed ? "fail" : "ok");
	return failed ? 1 : 0;
}

static int run_mm_failfast_tests(uint64_t key)
{
	const uint64_t expected_mask = CXLFORK_MM_FAILFAST_MPROTECT |
		CXLFORK_MM_FAILFAST_FORK | CXLFORK_MM_FAILFAST_GUP |
		CXLFORK_MM_FAILFAST_PARTIAL_MUNMAP |
		CXLFORK_MM_FAILFAST_MREMAP;
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS] = { 0 };
	struct cxlfork_prepare_v2 prepare = {
		.size = sizeof(prepare),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_resume_v2 resume = {
		.size = sizeof(resume),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.flags = CXLFORK_F_PRIVATE_COW,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct cxlfork_release_v2 release = {
		.size = sizeof(release),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	struct cxlfork_query_caps_v2 caps = {
		.size = sizeof(caps),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	struct cxlfork_gup_probe_v2 probe = {
		.size = sizeof(probe),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	unsigned char *anon;
	void *base;
	size_t bytes = 2 * getpagesize();
	pid_t child;
	int fd;
	int failed = 0;
	unsigned int i;
	const uint64_t gup_modes[] = {
		0,
		CXLFORK_GUP_PROBE_WRITE,
		CXLFORK_GUP_PROBE_LONGTERM,
		CXLFORK_GUP_PROBE_WRITE | CXLFORK_GUP_PROBE_LONGTERM,
	};

	anon = mmap(TEST_BASE, bytes, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (anon == MAP_FAILED) {
		perror("mm failfast source mmap");
		return 1;
	}
	fill_region(anon, bytes, key, 0);
	prepare.scan_start = (uintptr_t)anon;
	prepare.scan_end = (uintptr_t)anon + bytes;
	fd = open_device();
	if (fd < 0)
		return KSFT_SKIP;
	if (ioctl(fd, CXLFORK_PREPARE_V2, &prepare)) {
		perror("mm failfast PREPARE_V2");
		return 1;
	}
	resume.generation = prepare.generation;
	release.generation = prepare.generation;
	if (munmap(anon, bytes) || ioctl(fd, CXLFORK_RESUME_V2, &resume)) {
		perror("mm failfast RESUME_V2");
		return 1;
	}
	base = (void *)(uintptr_t)regions[0].start;
	errno = 0;
	if (mprotect(base, bytes, PROT_READ) != -1 || errno != EOPNOTSUPP) {
		fprintf(stderr, "mprotect fail-fast ret/errno mismatch: %d\n", errno);
		failed++;
	}
	errno = 0;
	if (munmap(base, getpagesize()) != -1 || errno != EOPNOTSUPP) {
		fprintf(stderr, "partial munmap fail-fast ret/errno mismatch: %d\n",
			errno);
		failed++;
	}
	errno = 0;
	if (mremap(base, bytes, bytes + getpagesize(), MREMAP_MAYMOVE) !=
	    MAP_FAILED || errno != EOPNOTSUPP) {
		fprintf(stderr, "mremap fail-fast ret/errno mismatch: %d\n", errno);
		failed++;
	}
	errno = 0;
	child = fork();
	if (child != -1 || errno != EOPNOTSUPP) {
		fprintf(stderr, "fork fail-fast ret=%d errno=%d\n", child, errno);
		failed++;
		if (!child)
			_exit(1);
		if (child > 0)
			waitpid(child, NULL, 0);
	}
	probe.address = (uintptr_t)base;
	for (i = 0; i < sizeof(gup_modes) / sizeof(gup_modes[0]); i++) {
		probe.flags = gup_modes[i];
		failed += v2_expect_errno(fd, CXLFORK_GUP_PROBE_V2, &probe,
					  EOPNOTSUPP, "restored VMA GUP");
	}
	if (ioctl(fd, CXLFORK_QUERY_CAPS_V2, &caps) ||
	    caps.mm_failfast_mask != expected_mask) {
		fprintf(stderr, "MM fail-fast capability mismatch: 0x%" PRIx64 "\n",
			(uint64_t)caps.mm_failfast_mask);
		failed++;
	}
	if (munmap(base, bytes)) {
		perror("full restored VMA munmap");
		failed++;
	}
	if (ioctl(fd, CXLFORK_RELEASE_V2, &release)) {
		perror("mm failfast RELEASE_V2");
		failed++;
	}
	close(fd);
	printf("mm-failfast key=%" PRIu64 " mask=0x%" PRIx64 " verify=%s\n",
	       key, expected_mask, failed ? "fail" : "ok");
	return failed ? 1 : 0;
}

static int run_lifecycle_tests(uint64_t key)
{
	unsigned char *anon;
	size_t page = getpagesize();
	uint64_t generation_before = 0;
	uint64_t generation_after = 0;
	uint64_t same_slot_key;
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
	same_slot_key = key + query_max_slots_fd(fd);
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
	if (prepare_existing_range(fd, same_slot_key, anon, page) != -1 ||
	    errno != EEXIST) {
		fprintf(stderr, "lifecycle: same-slot collision did not EEXIST\n");
		failed++;
	}
	if (inspect_missing(fd, same_slot_key)) {
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
	int pipefd[2] = { -1, -1 };
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

	if (pipe(pipefd)) {
		perror("pipe");
		close(fd);
		return 1;
	}
	memset(&op, 0, sizeof(op));
	op.key = key++;
	op.flags = CXLFORK_F_REOPEN_FDS;
	op.scan_start = (uintptr_t)anon;
	op.scan_end = (uintptr_t)anon + page;
	failed += expect_prepare_errno(fd, &op, EOPNOTSUPP,
				       "strict fd pipe");
	close(pipefd[0]);
	close(pipefd[1]);

	printf("failure-tests key_base=%" PRIu64 " verify=%s\n",
	       key - 5, failed ? "fail" : "ok");
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
			"threadctx-prepare KEY BYTES | threadctx-restore KEY POLICY | "
			"fdglobal-prepare KEY BYTES | fdglobal-restore KEY POLICY | "
			"hybrid-prepare KEY | hybrid-restore KEY | "
			"inspect KEY [ADDRESS] | release KEY | failures KEY | "
			"lifecycle KEY | hold KEY SECONDS | hold-close KEY SECONDS | "
			"v2-lifecycle KEY | v2-rollback KEY | v2-fastpath KEY BYTES | "
			"mm-failfast KEY | "
			"conflict KEY POLICY\n",
			argv[0]);
		return 2;
	}
	key = parse_u64(argv[2]);
	if (!strcmp(argv[1], "hold") && argc == 4)
		return hold_restore(key, (unsigned int)parse_u64(argv[3]));
	if (!strcmp(argv[1], "hold-close") && argc == 4)
		return hold_restore_after_close(key,
						(unsigned int)parse_u64(argv[3]));
	if (!strcmp(argv[1], "failures") && argc == 3)
		return run_failure_tests(key);
	if (!strcmp(argv[1], "lifecycle") && argc == 3)
		return run_lifecycle_tests(key);
	if (!strcmp(argv[1], "v2-lifecycle") && argc == 3)
		return run_v2_lifecycle_tests(key);
	if (!strcmp(argv[1], "v2-rollback") && argc == 3)
		return run_v2_rollback_tests(key);
	if (!strcmp(argv[1], "v2-fastpath") && argc == 4)
		return run_v2_fastpath_tests(key, parse_u64(argv[3]));
	if (!strcmp(argv[1], "mm-failfast") && argc == 3)
		return run_mm_failfast_tests(key);
	if (!strcmp(argv[1], "prepare") && argc == 4)
		return prepare_snapshot(key, parse_u64(argv[3]));
	if (!strcmp(argv[1], "threadctx-prepare") && argc == 4)
		return prepare_threadctx_snapshot(key, parse_u64(argv[3]));
	if (!strcmp(argv[1], "threadctx-restore") && argc == 4)
		return restore_threadctx_snapshot(key, argv[3]);
	if (!strcmp(argv[1], "fdglobal-prepare") && argc == 4)
		return prepare_fdglobal_snapshot(key, parse_u64(argv[3]));
	if (!strcmp(argv[1], "fdglobal-restore") && argc == 4)
		return restore_fdglobal_snapshot(key, argv[3]);
	if (!strcmp(argv[1], "hybrid-prepare") && argc == 3)
		return prepare_hybrid_snapshot(key);
	if (!strcmp(argv[1], "hybrid-restore") && argc == 3)
		return restore_hybrid_snapshot(key);
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
