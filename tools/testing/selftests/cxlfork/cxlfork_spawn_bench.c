// SPDX-License-Identifier: GPL-2.0
/*
 * Restricted CXLfork spawn benchmark.
 *
 * This is intentionally separate from MapReduce, HydraRPC, CXLporter and
 * OpenWhisk.  VM0 prepares a cooperative V4 capsule once.  A target-local
 * fork server in VM1 creates a fresh child for every request; that child
 * either consumes normal fork-inherited state (local) or resumes the V4
 * capsule and continues from its saved stack (cxlfork).
 *
 * It is not an arbitrary-process transparent remote fork benchmark.  It is a
 * controlled measurement of the process-creation and activation path that
 * the current, restricted CXLfork implementation actually supports.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/cxlfork.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define CAPSULE_BASE ((void *)0x480000000000ULL)
#define CAPSULE_BYTES (4UL * 1024 * 1024)
#define CAPSULE_STACK_BYTES (1024UL * 1024)
#define ACTIVATION_BASE ((void *)0x500000000000ULL)
#define ACTIVATION_BYTES (64UL * 1024)
#define CAPSULE_MAGIC 0x4358535041574e34ULL
#define CAPSULE_VERSION 1U
#define CAPSULE_QUIESCENT 1U
#define CAPSULE_RESUMED 2U
#define SOURCE_INVOCATIONS 16U
#define TARGET_INVOCATION 17U
#define PAYLOAD_WORDS 4096U
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL
#define MARKER_R12 0xc012c012c012c012ULL
#define MARKER_R13 0xc013c013c013c013ULL
#define MARKER_R14 0xc014c014c014c014ULL
#define MARKER_R15 0xc015c015c015c015ULL

#define WIRE_MAGIC 0x43585350U
#define WIRE_VERSION 1U
#define MODE_LOCAL 1U
#define MODE_CXLFORK 2U
#define MODE_CONTROL 3U
#define REQ_DEBUG_PROOF (1U << 0)
#define REQ_MINIMAL (1U << 1)
#define REQ_DETAILED (1U << 2)
#define MAX_OPS_PER_SECOND_PER_LANE 20000ULL
#define U64(value) ((uint64_t)(value))

#define SHM_MAGIC 0x4358534dU
#define SHM_VERSION 1U
#define SHM_STATE_READY 1U
#define SHM_STATE_STOPPING 2U
#define SHM_CACHELINE 64U
#define SHM_MAX_LANES 1024U
#define SHM_READY_TIMEOUT_NS (30ULL * 1000000000ULL)
#define SHM_COMPLETION_DETAILED (1U << 0)
#define SHM_LITMUS_MAGIC 0x43584c4dU
#define SHM_LITMUS_READY 1U
#define SHM_LITMUS_RMW 2U
#define SHM_LITMUS_COMPLETE 3U

struct capsule_ctx {
	uint64_t r15, r14, r13, r12, rbx, rbp, rsp, rip;
};

struct capsule_state {
	uint64_t magic;
	uint32_t version;
	uint32_t stage;
	uint64_t key;
	uint64_t source_pid;
	uint64_t source_initializations;
	uint64_t invocation;
	uint64_t accumulator;
	uint64_t business_checksum;
	uint64_t continuation_cookie;
	uint64_t source_stack_pointer;
	uint64_t target_stack_pointer;
	uint64_t target_pid;
	uint64_t marker_r12, marker_r13, marker_r14, marker_r15;
	struct capsule_ctx continuation;
	uint64_t payload[PAYLOAD_WORDS];
};

struct wire_request {
	uint32_t magic;
	uint16_t version;
	uint16_t mode;
	uint32_t flags;
	uint32_t reserved;
	uint64_t request_id;
	uint64_t key;
	uint64_t generation;
	uint64_t expected_checksum;
};

struct child_result {
	int32_t status;
	int32_t error_no;
	uint64_t child_pid;
	uint64_t source_pid;
	uint64_t restore_id;
	uint64_t input_checksum;
	uint64_t output_checksum;
	uint64_t child_begin_ns;
	uint64_t restore_begin_ns;
	uint64_t restore_end_ns;
	uint64_t proof_end_ns;
	uint64_t shared_leaf_pfn;
	uint64_t current_pmd_pfn;
	uint64_t shared_data_pfn;
	uint64_t current_data_pfn;
	struct cxlfork_restore_stats_v4 stats;
};

struct wire_response {
	uint32_t magic;
	uint16_t version;
	uint16_t mode;
	int32_t status;
	int32_t error_no;
	uint64_t request_id;
	uint64_t target_total_ns;
	uint64_t request_dispatch_ns;
	uint64_t activation_ns;
	uint64_t exit_wait_ns;
	uint64_t fork_parent_return_ns;
	uint64_t fork_to_child_ns;
	uint64_t child_setup_ns;
	uint64_t restore_wall_ns;
	uint64_t continuation_ns;
	struct child_result child;
};

struct sample {
	uint64_t request_id;
	uint64_t rtt_ns;
	struct wire_response response;
};

/*
 * Each lane is single-producer/single-consumer in each direction.  The
 * request and completion sequence counters deliberately occupy different
 * cache lines.  A producer fills the payload first and publishes the new
 * sequence with release ordering; the consumer observes it with acquire
 * ordering before reading the payload.
 */
struct shm_request_slot {
	uint64_t sequence;
	struct wire_request request;
	uint8_t padding[SHM_CACHELINE - sizeof(uint64_t) -
			sizeof(struct wire_request)];
} __attribute__((aligned(SHM_CACHELINE)));

struct shm_completion_line {
	uint64_t sequence;
	uint64_t request_id;
	int32_t status;
	int32_t error_no;
	uint32_t flags;
	uint32_t reserved;
	uint64_t target_total_ns;
	uint8_t padding[SHM_CACHELINE - 40];
} __attribute__((aligned(SHM_CACHELINE)));

struct shm_lane {
	struct shm_request_slot request;
	struct shm_completion_line completion;
	struct wire_response detail __attribute__((aligned(SHM_CACHELINE)));
} __attribute__((aligned(SHM_CACHELINE)));

struct shm_header {
	uint32_t magic;
	uint16_t version;
	uint16_t mode;
	uint32_t lanes;
	uint32_t state;
	uint64_t epoch;
	uint64_t key;
	uint64_t generation;
	uint64_t checksum;
	uint64_t stop;
	uint8_t padding[SHM_CACHELINE - 56];
} __attribute__((aligned(SHM_CACHELINE)));

struct shm_layout {
	struct shm_header header;
	struct shm_lane lane[];
};

struct shm_mapping {
	int fd;
	void *address;
	size_t bytes;
	struct shm_layout *layout;
};

struct shm_litmus {
	uint32_t magic;
	uint32_t version;
	uint64_t iterations;
	uint64_t phase;
	uint64_t sequence;
	uint64_t payload;
	uint64_t counter;
	uint64_t server_done;
	uint64_t client_done;
	uint8_t padding[4096 - 64];
};

_Static_assert(sizeof(struct shm_litmus) == 4096,
	       "shared-memory litmus must occupy one page");

_Static_assert(sizeof(struct capsule_state) < CAPSULE_BYTES -
	       CAPSULE_STACK_BYTES, "capsule state overlaps function stack");
_Static_assert(sizeof(struct wire_request) == 48,
	       "shared request cache-line layout changed");
_Static_assert(sizeof(struct shm_request_slot) == SHM_CACHELINE,
	       "shared request slot is not one cache line");
_Static_assert(sizeof(struct shm_completion_line) == SHM_CACHELINE,
	       "shared completion line is not one cache line");

static struct capsule_ctx control_ctx;
static struct capsule_ctx activation_ctx;
static struct cxlfork_resume_capsule_v4 resume_result;
static struct cxlfork_region resume_regions[CXLFORK_MAX_REGIONS];
static struct child_result current_child;
static int restore_device_fd = -1;
static int child_result_fd = -1;
static bool child_debug_proof;
static bool child_minimal;
static bool activation_stack_ready;
static volatile sig_atomic_t server_stop;
static volatile sig_atomic_t client_stop;

/* Equality tokens for the fixed benchmark binary/configuration. */
static const uint8_t runtime_sha256[CXLFORK_CAPSULE_DIGEST_BYTES] = {
	0x31, 0x8a, 0x5c, 0x01, 0x87, 0x41, 0x2a, 0x90,
	0xa1, 0x93, 0x71, 0x08, 0xc3, 0x12, 0x55, 0x40,
	0x99, 0x23, 0x12, 0x76, 0x41, 0xdd, 0x6e, 0x20,
	0x12, 0x09, 0xfe, 0x82, 0x42, 0x37, 0x9c, 0x01,
};
static const uint8_t image_sha256[CXLFORK_CAPSULE_DIGEST_BYTES] = {
	0x42, 0x01, 0x9e, 0x11, 0x29, 0x5b, 0xd2, 0x61,
	0x93, 0x77, 0x4a, 0x81, 0x33, 0xc0, 0x6f, 0xa1,
	0x01, 0x65, 0xac, 0xc2, 0x2b, 0x50, 0x18, 0x31,
	0xc4, 0x63, 0x32, 0x91, 0x10, 0xed, 0x72, 0x44,
};

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts))
		_exit(120);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static const char *mode_name(uint16_t mode)
{
	switch (mode) {
	case MODE_LOCAL:
		return "local";
	case MODE_CXLFORK:
		return "cxlfork";
	case MODE_CONTROL:
		return "control";
	default:
		return "invalid";
	}
}

static uint64_t load_acquire_u64(const uint64_t *value)
{
	return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static void store_release_u64(uint64_t *value, uint64_t new_value)
{
	__atomic_store_n(value, new_value, __ATOMIC_RELEASE);
}

static uint32_t load_acquire_u32(const uint32_t *value)
{
	return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static void store_release_u32(uint32_t *value, uint32_t new_value)
{
	__atomic_store_n(value, new_value, __ATOMIC_RELEASE);
}

static void cpu_relax(void)
{
	__asm__ volatile("pause" ::: "memory");
}

static size_t shm_layout_bytes(unsigned int lanes)
{
	size_t bytes = offsetof(struct shm_layout, lane) +
		lanes * sizeof(struct shm_lane);
	long page_size = sysconf(_SC_PAGESIZE);

	if (page_size <= 0)
		page_size = 4096;
	return (bytes + page_size - 1) & ~((size_t)page_size - 1);
}

static int map_shm(const char *path, uint64_t offset, unsigned int lanes,
		   struct shm_mapping *mapping)
{
	long page_size = sysconf(_SC_PAGESIZE);

	memset(mapping, 0, sizeof(*mapping));
	mapping->fd = -1;
	if (!lanes || lanes > SHM_MAX_LANES || page_size <= 0 ||
	    offset % (uint64_t)page_size) {
		errno = EINVAL;
		return -1;
	}
	mapping->bytes = shm_layout_bytes(lanes);
	mapping->fd = open(path, O_RDWR | O_CLOEXEC | O_SYNC);
	if (mapping->fd < 0)
		return -1;
	mapping->address = mmap(NULL, mapping->bytes, PROT_READ | PROT_WRITE,
				MAP_SHARED, mapping->fd, (off_t)offset);
	if (mapping->address == MAP_FAILED) {
		close(mapping->fd);
		mapping->fd = -1;
		return -1;
	}
	mapping->layout = mapping->address;
	return 0;
}

static void unmap_shm(struct shm_mapping *mapping)
{
	if (mapping->address && mapping->address != MAP_FAILED)
		munmap(mapping->address, mapping->bytes);
	if (mapping->fd >= 0)
		close(mapping->fd);
	memset(mapping, 0, sizeof(*mapping));
	mapping->fd = -1;
}

__attribute__((noreturn))
static void benchmark_child_exit(int code)
{
	if (child_minimal)
		exit(code);
	_exit(code);
}

static struct capsule_state *capsule(void)
{
	return CAPSULE_BASE;
}

static uint64_t fnv_u64(uint64_t hash, uint64_t value)
{
	unsigned int byte;

	for (byte = 0; byte < sizeof(value); byte++) {
		hash ^= value & 0xff;
		hash *= FNV_PRIME;
		value >>= 8;
	}
	return hash;
}

static uint64_t business_checksum(const struct capsule_state *state)
{
	uint64_t hash = FNV_OFFSET;
	unsigned int i;

	hash = fnv_u64(hash, state->invocation);
	hash = fnv_u64(hash, state->accumulator);
	for (i = 0; i < PAYLOAD_WORDS; i++)
		hash = fnv_u64(hash, state->payload[i]);
	return hash;
}

static uint64_t continuation_cookie(const struct capsule_state *state)
{
	uint64_t hash = FNV_OFFSET;

	hash = fnv_u64(hash, state->magic);
	hash = fnv_u64(hash, state->version);
	hash = fnv_u64(hash, state->key);
	hash = fnv_u64(hash, state->source_pid);
	hash = fnv_u64(hash, state->source_initializations);
	hash = fnv_u64(hash, state->invocation);
	hash = fnv_u64(hash, state->business_checksum);
	hash = fnv_u64(hash, state->continuation.rsp);
	hash = fnv_u64(hash, state->continuation.rip);
	return hash;
}

__attribute__((naked, noinline))
static void capsule_swap(struct capsule_ctx *out __attribute__((unused)),
			 const struct capsule_ctx *in __attribute__((unused)))
{
	__asm__ volatile(
		"movq %r15, 0(%rdi)\n\t" "movq %r14, 8(%rdi)\n\t"
		"movq %r13, 16(%rdi)\n\t" "movq %r12, 24(%rdi)\n\t"
		"movq %rbx, 32(%rdi)\n\t" "movq %rbp, 40(%rdi)\n\t"
		"movq %rsp, 48(%rdi)\n\t" "leaq 1f(%rip), %rax\n\t"
		"movq %rax, 56(%rdi)\n\t" "movq 56(%rsi), %rax\n\t"
		"movq 0(%rsi), %r15\n\t" "movq 8(%rsi), %r14\n\t"
		"movq 16(%rsi), %r13\n\t" "movq 24(%rsi), %r12\n\t"
		"movq 32(%rsi), %rbx\n\t" "movq 40(%rsi), %rbp\n\t"
		"movq 48(%rsi), %rsp\n\t" "jmp *%rax\n\t" "1:\n\t" "ret\n\t");
}

__attribute__((naked, noinline))
static void capsule_yield_with_markers(
	struct capsule_ctx *out __attribute__((unused)),
	const struct capsule_ctx *control __attribute__((unused)))
{
	__asm__ volatile(
		"movabsq $0xc012c012c012c012, %r12\n\t"
		"movabsq $0xc013c013c013c013, %r13\n\t"
		"movabsq $0xc014c014c014c014, %r14\n\t"
		"movabsq $0xc015c015c015c015, %r15\n\t"
		"jmp capsule_swap\n\t");
}

static void read_markers(struct capsule_state *state)
{
	__asm__ volatile(
		"movq %%r12, %0\n\t" "movq %%r13, %1\n\t"
		"movq %%r14, %2\n\t" "movq %%r15, %3\n\t"
		: "=m"(state->marker_r12), "=m"(state->marker_r13),
		  "=m"(state->marker_r14), "=m"(state->marker_r15)
		: : "memory");
}

static void run_invocation(struct capsule_state *state, uint64_t invocation)
{
	uint64_t mix = 0x9e3779b97f4a7c15ULL ^ invocation;
	unsigned int i;

	for (i = 0; i < PAYLOAD_WORDS; i++) {
		mix ^= mix << 13;
		mix ^= mix >> 7;
		mix ^= mix << 17;
		state->payload[i] = (state->payload[i] + mix + invocation + i) ^
			(state->accumulator >> (i & 31));
		state->accumulator = (state->accumulator * 33) ^ state->payload[i];
	}
	state->invocation = invocation;
	state->business_checksum = business_checksum(state);
}

static int write_full(int fd, const void *buffer, size_t bytes)
{
	const char *cursor = buffer;

	while (bytes) {
		ssize_t done = write(fd, cursor, bytes);

		if (done < 0 && errno == EINTR)
			continue;
		if (done <= 0)
			return -1;
		cursor += done;
		bytes -= done;
	}
	return 0;
}

static int read_full(int fd, void *buffer, size_t bytes)
{
	char *cursor = buffer;

	while (bytes) {
		ssize_t done = read(fd, cursor, bytes);

		if (done < 0 && errno == EINTR)
			continue;
		if (done == 0)
			return 1;
		if (done < 0)
			return -1;
		cursor += done;
		bytes -= done;
	}
	return 0;
}

static int open_device(void)
{
	return open(CXLFORK_DEVICE, O_RDWR | O_CLOEXEC);
}

static int map_capsule_arena(void)
{
	void *mapping = mmap(CAPSULE_BASE, CAPSULE_BYTES,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

	if (mapping == MAP_FAILED)
		return -1;
	if (madvise(mapping, CAPSULE_BYTES, MADV_NOHUGEPAGE))
		return -1;
	memset(mapping, 0, CAPSULE_BYTES);
	return 0;
}

static int map_activation_stack(void)
{
	void *mapping = mmap(ACTIVATION_BASE, ACTIVATION_BYTES,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

	return mapping == MAP_FAILED ? -1 : 0;
}

__attribute__((noreturn))
static void send_child_and_exit(int code)
{
	if (child_result_fd >= 0)
		(void)write_full(child_result_fd, &current_child,
				 sizeof(current_child));
	benchmark_child_exit(code);
}

__attribute__((noreturn))
static void capsule_unexpected_return(void)
{
	current_child.status = -1;
	current_child.error_no = EPROTO;
	current_child.proof_end_ns = now_ns();
	send_child_and_exit(91);
}

__attribute__((noreturn, noinline))
static void capsule_entry(void)
{
	struct capsule_state *state = capsule();
	uint64_t local_stack_probe;
	uint64_t expected_cookie;
	uint64_t input_checksum;

	state->source_initializations++;
	state->source_pid = getpid();
	for (unsigned int invocation = 1;
	     invocation <= SOURCE_INVOCATIONS; invocation++)
		run_invocation(state, invocation);
	state->stage = CAPSULE_QUIESCENT;
	state->source_stack_pointer = (uintptr_t)&local_stack_probe;
	capsule_yield_with_markers(&state->continuation, &control_ctx);

	read_markers(state);
	expected_cookie = continuation_cookie(state);
	input_checksum = state->business_checksum;
	if (child_minimal) {
		if (state->magic != CAPSULE_MAGIC ||
		    state->version != CAPSULE_VERSION ||
		    state->stage != CAPSULE_QUIESCENT ||
		    state->source_initializations != 1 ||
		    state->invocation != SOURCE_INVOCATIONS ||
		    state->continuation_cookie != expected_cookie ||
		    state->marker_r12 != MARKER_R12 ||
		    state->marker_r13 != MARKER_R13 ||
		    state->marker_r14 != MARKER_R14 ||
		    state->marker_r15 != MARKER_R15) {
			current_child.status = -1;
			current_child.error_no = EILSEQ;
			if (child_result_fd >= 0)
				current_child.proof_end_ns = now_ns();
			send_child_and_exit(92);
		}
		if (child_result_fd >= 0) {
			current_child.child_pid = getpid();
			current_child.source_pid = state->source_pid;
			current_child.restore_id = resume_result.restore_id;
			current_child.input_checksum = input_checksum;
			current_child.output_checksum = input_checksum;
			current_child.stats = resume_result.stats;
			current_child.proof_end_ns = now_ns();
			current_child.status = 0;
		}
		send_child_and_exit(0);
	}
	if (state->magic != CAPSULE_MAGIC || state->version != CAPSULE_VERSION ||
	    state->stage != CAPSULE_QUIESCENT ||
	    state->source_initializations != 1 ||
	    state->invocation != SOURCE_INVOCATIONS ||
	    state->continuation_cookie != expected_cookie ||
	    state->business_checksum != business_checksum(state) ||
	    state->marker_r12 != MARKER_R12 || state->marker_r13 != MARKER_R13 ||
	    state->marker_r14 != MARKER_R14 || state->marker_r15 != MARKER_R15) {
		current_child.status = -1;
		current_child.error_no = EILSEQ;
		current_child.proof_end_ns = now_ns();
		send_child_and_exit(92);
	}
	state->target_stack_pointer = (uintptr_t)&local_stack_probe;
	state->target_pid = getpid();
	run_invocation(state, TARGET_INVOCATION);
	state->stage = CAPSULE_RESUMED;
	current_child.child_pid = getpid();
	current_child.source_pid = state->source_pid;
	current_child.restore_id = resume_result.restore_id;
	current_child.input_checksum = input_checksum;
	current_child.output_checksum = state->business_checksum;
	current_child.stats = resume_result.stats;
	current_child.proof_end_ns = now_ns();
	current_child.status = 0;
	send_child_and_exit(0);
}

__attribute__((noreturn, noinline))
static void capsule_restore_trampoline(void)
{
	struct capsule_state *state = capsule();

	if (child_result_fd >= 0)
		current_child.restore_end_ns = now_ns();
	if (state->magic != CAPSULE_MAGIC || state->version != CAPSULE_VERSION ||
	    state->stage != CAPSULE_QUIESCENT ||
	    state->continuation_cookie != continuation_cookie(state)) {
		current_child.status = -1;
		current_child.error_no = EILSEQ;
		current_child.proof_end_ns = now_ns();
		send_child_and_exit(93);
	}
	if (restore_device_fd >= 0) {
		close(restore_device_fd);
		restore_device_fd = -1;
	}
	if (child_debug_proof) {
		struct cxlfork_inspect_v2 inspect = {
			.size = sizeof(inspect),
			.abi_version = CXLFORK_ABI_VERSION_V2,
			.key = state->key,
			.address = (uintptr_t)CAPSULE_BASE,
		};
		int fd = open_device();

		if (fd < 0 || ioctl(fd, CXLFORK_INSPECT_V2, &inspect) ||
		    !(inspect.flags & CXLFORK_INSPECT_F_SHARED_LEAF_VALID) ||
		    !(inspect.flags & CXLFORK_INSPECT_F_CURRENT_PMD_VALID) ||
		    !(inspect.flags & CXLFORK_INSPECT_F_CURRENT_PTE_VALID) ||
		    inspect.current_pmd_pfn != inspect.shared_leaf_pfn ||
		    inspect.current_pfn != inspect.shared_pfn) {
			if (fd >= 0)
				close(fd);
			current_child.status = -1;
			current_child.error_no = EUCLEAN;
			current_child.proof_end_ns = now_ns();
			send_child_and_exit(95);
		}
		current_child.shared_leaf_pfn = inspect.shared_leaf_pfn;
		current_child.current_pmd_pfn = inspect.current_pmd_pfn;
		current_child.shared_data_pfn = inspect.shared_pfn;
		current_child.current_data_pfn = inspect.current_pfn;
		close(fd);
	}
	if (!child_minimal && resume_result.stats.total_ns !=
	    resume_result.stats.core.total_ns +
	    resume_result.stats.capsule_validate_ns +
	    resume_result.stats.activation_commit_ns) {
		current_child.status = -1;
		current_child.error_no = EDOM;
		current_child.proof_end_ns = now_ns();
		send_child_and_exit(96);
	}
	capsule_swap(&activation_ctx, &state->continuation);
	current_child.status = -1;
	current_child.error_no = EPROTO;
	current_child.proof_end_ns = now_ns();
	send_child_and_exit(94);
}

static int prepare_capsule(uint64_t key)
{
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS];
	struct cxlfork_prepare_capsule_v4 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V4,
		.regions_ptr = (uintptr_t)regions,
		.region_capacity = CXLFORK_MAX_REGIONS,
	};
	struct capsule_state *state;
	uintptr_t stack_top;
	int fd;

	if (map_capsule_arena()) {
		perror("mmap capsule arena");
		return 1;
	}
	state = capsule();
	state->magic = CAPSULE_MAGIC;
	state->version = CAPSULE_VERSION;
	state->key = key;
	state->accumulator = key ^ 0x43415053554c4530ULL;
	stack_top = (uintptr_t)CAPSULE_BASE + CAPSULE_BYTES - 16;
	stack_top &= ~0xfULL;
	stack_top -= 8;
	*(uintptr_t *)stack_top = (uintptr_t)capsule_unexpected_return;
	state->continuation.rsp = stack_top;
	state->continuation.rip = (uintptr_t)capsule_entry;
	capsule_swap(&control_ctx, &state->continuation);
	if (state->stage != CAPSULE_QUIESCENT ||
	    state->invocation != SOURCE_INVOCATIONS ||
	    state->source_initializations != 1)
		return 1;
	state->continuation_cookie = continuation_cookie(state);
	fd = open_device();
	if (fd < 0) {
		perror("open " CXLFORK_DEVICE);
		return 1;
	}
	op.key = key;
	op.scan_start = (uintptr_t)CAPSULE_BASE;
	op.scan_end = (uintptr_t)CAPSULE_BASE + CAPSULE_BYTES;
	op.manifest.manifest_version = CXLFORK_CAPSULE_MANIFEST_VERSION;
	op.manifest.flags = CXLFORK_CAPSULE_F_FIXED_CODE |
		CXLFORK_CAPSULE_F_FIXED_ARENA |
		CXLFORK_CAPSULE_F_COOPERATIVE_YIELD;
	memcpy(op.manifest.runtime_sha256, runtime_sha256,
	       sizeof(runtime_sha256));
	memcpy(op.manifest.image_sha256, image_sha256, sizeof(image_sha256));
	op.manifest.context_va = (uintptr_t)&state->continuation;
	op.manifest.trampoline_ip = (uintptr_t)capsule_restore_trampoline;
	op.manifest.activation_sp =
		(uintptr_t)ACTIVATION_BASE + ACTIVATION_BYTES - 8;
	op.manifest.continuation_cookie = state->continuation_cookie;
	op.manifest.state_checksum = state->business_checksum;
	if (ioctl(fd, CXLFORK_PREPARE_CAPSULE_V4, &op)) {
		perror("PREPARE_CAPSULE_V4");
		close(fd);
		return 1;
	}
	printf("event=prepared key=%" PRIu64 " generation=%" PRIu64
	       " state_checksum=%016" PRIx64 " page_checksum=%016" PRIx64
	       " pages=%" PRIu64 " source_pid=%" PRIu64 " verify=ok\n",
	       key, U64(op.generation), state->business_checksum,
	       U64(op.page_checksum), U64(op.total_pages), state->source_pid);
	close(fd);
	return 0;
}

static int release_capsule(uint64_t key, uint64_t generation)
{
	struct cxlfork_release_v2 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
		.generation = generation,
	};
	int fd = open_device();

	if (fd < 0 || ioctl(fd, CXLFORK_RELEASE_V2, &op)) {
		perror("RELEASE_V2");
		if (fd >= 0)
			close(fd);
		return 1;
	}
	close(fd);
	printf("event=released key=%" PRIu64 " generation=%" PRIu64
	       " verify=ok\n", key, generation);
	return 0;
}

static int init_local_state(uint64_t key, uint64_t expected_checksum)
{
	struct capsule_state *state;

	if (map_capsule_arena())
		return -1;
	state = capsule();
	state->magic = CAPSULE_MAGIC;
	state->version = CAPSULE_VERSION;
	state->stage = CAPSULE_QUIESCENT;
	state->key = key;
	state->source_pid = getpid();
	state->source_initializations = 1;
	state->accumulator = key ^ 0x43415053554c4530ULL;
	for (unsigned int invocation = 1;
	     invocation <= SOURCE_INVOCATIONS; invocation++)
		run_invocation(state, invocation);
	if (state->business_checksum != expected_checksum) {
		errno = EILSEQ;
		return -1;
	}
	return 0;
}

static void control_child(uint64_t expected_checksum, int output_fd,
			  bool minimal)
{
	memset(&current_child, 0, sizeof(current_child));
	child_result_fd = output_fd;
	child_minimal = minimal;
	if (output_fd >= 0) {
		current_child.child_begin_ns = now_ns();
		current_child.restore_begin_ns = current_child.child_begin_ns;
		current_child.restore_end_ns = current_child.child_begin_ns;
		current_child.proof_end_ns = current_child.child_begin_ns;
		current_child.child_pid = getpid();
		current_child.source_pid = getppid();
		current_child.input_checksum = expected_checksum;
		current_child.output_checksum = expected_checksum;
		current_child.status = 0;
	}
	send_child_and_exit(0);
}

static void local_child(uint64_t expected_checksum, int output_fd,
			bool minimal)
{
	struct capsule_state *state = capsule();

	memset(&current_child, 0, sizeof(current_child));
	child_result_fd = output_fd;
	child_minimal = minimal;
	if (output_fd >= 0)
		current_child.child_begin_ns = now_ns();
	current_child.restore_begin_ns = current_child.child_begin_ns;
	current_child.restore_end_ns = current_child.child_begin_ns;
	current_child.child_pid = getpid();
	current_child.source_pid = state->source_pid;
	current_child.input_checksum = state->business_checksum;
	if (minimal) {
		if (state->magic != CAPSULE_MAGIC ||
		    state->stage != CAPSULE_QUIESCENT ||
		    state->business_checksum != expected_checksum) {
			current_child.status = -1;
			current_child.error_no = EILSEQ;
			if (output_fd >= 0)
				current_child.proof_end_ns = now_ns();
			send_child_and_exit(101);
		}
		if (output_fd >= 0) {
			current_child.output_checksum = state->business_checksum;
			current_child.proof_end_ns = now_ns();
			current_child.status = 0;
		}
		send_child_and_exit(0);
	}
	if (state->magic != CAPSULE_MAGIC ||
	    state->stage != CAPSULE_QUIESCENT ||
	    state->business_checksum != expected_checksum ||
	    state->business_checksum != business_checksum(state)) {
		current_child.status = -1;
		current_child.error_no = EILSEQ;
		current_child.proof_end_ns = now_ns();
		send_child_and_exit(101);
	}
	run_invocation(state, TARGET_INVOCATION);
	current_child.output_checksum = state->business_checksum;
	current_child.proof_end_ns = now_ns();
	current_child.status = 0;
	send_child_and_exit(0);
}

static void cxlfork_child(const struct wire_request *request, int output_fd)
{
	memset(&current_child, 0, sizeof(current_child));
	memset(&resume_result, 0, sizeof(resume_result));
	memset(resume_regions, 0, sizeof(resume_regions));
	child_result_fd = output_fd;
	child_debug_proof = request->flags & REQ_DEBUG_PROOF;
	child_minimal = request->flags & REQ_MINIMAL;
	if (output_fd >= 0)
		current_child.child_begin_ns = now_ns();
	if (!activation_stack_ready && map_activation_stack()) {
		current_child.status = -1;
		current_child.error_no = errno;
		current_child.proof_end_ns = now_ns();
		send_child_and_exit(102);
	}
	restore_device_fd = open_device();
	if (restore_device_fd < 0) {
		current_child.status = -1;
		current_child.error_no = errno;
		current_child.proof_end_ns = now_ns();
		send_child_and_exit(103);
	}
	resume_result.size = sizeof(resume_result);
	resume_result.abi_version = CXLFORK_ABI_VERSION_V4;
	resume_result.key = request->key;
	resume_result.generation = request->generation;
	resume_result.flags = CXLFORK_F_SHARED_COW;
	resume_result.regions_ptr = (uintptr_t)resume_regions;
	resume_result.region_capacity = CXLFORK_MAX_REGIONS;
	memcpy(resume_result.runtime_sha256, runtime_sha256,
	       sizeof(runtime_sha256));
	memcpy(resume_result.image_sha256, image_sha256,
	       sizeof(image_sha256));
	if (output_fd >= 0)
		current_child.restore_begin_ns = now_ns();
	if (ioctl(restore_device_fd, CXLFORK_RESUME_CAPSULE_V4,
		  &resume_result)) {
		current_child.status = -1;
		current_child.error_no = errno;
		if (output_fd >= 0)
			current_child.restore_end_ns = now_ns();
		current_child.proof_end_ns = current_child.restore_end_ns;
		close(restore_device_fd);
		restore_device_fd = -1;
		send_child_and_exit(104);
	}
	current_child.status = -1;
	current_child.error_no = EPROTO;
	current_child.proof_end_ns = now_ns();
	send_child_and_exit(105);
}

static uint64_t delta(uint64_t end, uint64_t begin)
{
	return end >= begin ? end - begin : 0;
}

static int build_detailed_response(struct wire_response *response,
				   uint16_t mode, uint64_t key,
				   uint64_t generation, uint64_t checksum,
				   const struct wire_request *request)
{
	int pipe_fd[2];
	uint64_t begin_ns, fork_begin_ns, fork_return_ns, wait_end_ns;
	pid_t child;
	pid_t waited;
	int status;
	int read_status;

	memset(response, 0, sizeof(*response));
	response->magic = WIRE_MAGIC;
	response->version = WIRE_VERSION;
	response->mode = mode;
	response->request_id = request->request_id;
	if (request->magic != WIRE_MAGIC || request->version != WIRE_VERSION ||
	    request->mode != mode || request->key != key ||
	    request->generation != generation ||
	    request->expected_checksum != checksum) {
		response->status = -1;
		response->error_no = EINVAL;
		return 0;
	}
	begin_ns = now_ns();
	if (pipe2(pipe_fd, O_CLOEXEC)) {
		response->status = -1;
		response->error_no = errno;
		return 0;
	}
	fork_begin_ns = now_ns();
	child = fork();
	if (child == 0) {
		close(pipe_fd[0]);
		if (mode == MODE_LOCAL)
			local_child(checksum, pipe_fd[1],
				    request->flags & REQ_MINIMAL);
		else if (mode == MODE_CONTROL)
			control_child(checksum, pipe_fd[1],
				      request->flags & REQ_MINIMAL);
		else
			cxlfork_child(request, pipe_fd[1]);
	}
	fork_return_ns = now_ns();
	close(pipe_fd[1]);
	if (child < 0) {
		response->status = -1;
		response->error_no = errno;
		close(pipe_fd[0]);
		return 0;
	}
	read_status = read_full(pipe_fd[0], &response->child,
				sizeof(response->child));
	close(pipe_fd[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	wait_end_ns = now_ns();
	response->target_total_ns = delta(wait_end_ns, begin_ns);
	response->request_dispatch_ns = delta(fork_begin_ns, begin_ns);
	response->fork_parent_return_ns = delta(fork_return_ns, fork_begin_ns);
	response->fork_to_child_ns =
		delta(response->child.child_begin_ns, fork_begin_ns);
	response->child_setup_ns = delta(response->child.restore_begin_ns,
					 response->child.child_begin_ns);
	response->restore_wall_ns = delta(response->child.restore_end_ns,
					 response->child.restore_begin_ns);
	response->continuation_ns = delta(response->child.proof_end_ns,
					 response->child.restore_end_ns);
	response->activation_ns = delta(response->child.proof_end_ns,
					fork_begin_ns);
	response->exit_wait_ns = delta(wait_end_ns,
				       response->child.proof_end_ns);
	if (read_status || waited != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) ||
	    response->child.status ||
	    response->child.input_checksum != checksum) {
		response->status = -1;
		response->error_no = response->child.error_no ?
			response->child.error_no : ECHILD;
	} else {
		response->status = 0;
	}
	return 0;
}

static void signal_stop(int signal_number __attribute__((unused)))
{
	server_stop = 1;
}

static void signal_client_stop(int signal_number __attribute__((unused)))
{
	client_stop = 1;
}

static int lane_handler(int socket_fd, uint16_t mode, uint64_t key,
			uint64_t generation, uint64_t checksum)
{
	struct wire_request request;
	int result;

	for (;;) {
		result = read_full(socket_fd, &request, sizeof(request));
		if (result == 1)
			return 0;
		if (result < 0)
			return 1;
		struct wire_response response;

		build_detailed_response(&response, mode, key, generation,
					checksum, &request);
		if (write_full(socket_fd, &response, sizeof(response)))
			return 1;
	}
}

static int parse_mode(const char *text, uint16_t *mode)
{
	if (!strcmp(text, "local"))
		*mode = MODE_LOCAL;
	else if (!strcmp(text, "cxlfork"))
		*mode = MODE_CXLFORK;
	else if (!strcmp(text, "control"))
		*mode = MODE_CONTROL;
	else
		return -1;
	return 0;
}

static bool request_matches(const struct wire_request *request,
			    uint16_t mode, uint64_t key,
			    uint64_t generation, uint64_t checksum)
{
	return request->magic == WIRE_MAGIC &&
		request->version == WIRE_VERSION && request->mode == mode &&
		request->key == key && request->generation == generation &&
		request->expected_checksum == checksum;
}

static void build_minimal_completion(struct shm_completion_line *completion,
				     uint16_t mode, uint64_t key,
				     uint64_t generation, uint64_t checksum,
				     const struct wire_request *request)
{
	pid_t child, waited;
	int status;

	completion->request_id = request->request_id;
	completion->status = -1;
	completion->error_no = 0;
	completion->flags = 0;
	completion->target_total_ns = 0;
	if (!request_matches(request, mode, key, generation, checksum) ||
	    !(request->flags & REQ_MINIMAL)) {
		completion->error_no = EINVAL;
		return;
	}
	child = fork();
	if (child == 0) {
		if (mode == MODE_CONTROL)
			control_child(checksum, -1, true);
		else if (mode == MODE_LOCAL)
			local_child(checksum, -1, true);
		else
			cxlfork_child(request, -1);
	}
	if (child < 0) {
		completion->error_no = errno;
		return;
	}
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
		completion->error_no = ECHILD;
		return;
	}
	completion->status = 0;
}

static int shm_lane_handler(struct shm_layout *layout, unsigned int lane,
			    uint16_t mode, uint64_t key,
			    uint64_t generation, uint64_t checksum)
{
	struct shm_lane *slot = &layout->lane[lane];
	uint64_t seen = 0;

	if (mode == MODE_CXLFORK) {
		if (map_activation_stack())
			return 1;
		activation_stack_ready = true;
	}
	while (!load_acquire_u64(&layout->header.stop)) {
		struct wire_request request;
		struct wire_response response;
		uint64_t sequence;

		do {
			sequence = load_acquire_u64(&slot->request.sequence);
			if (sequence != seen)
				break;
			cpu_relax();
		} while (!load_acquire_u64(&layout->header.stop));
		if (load_acquire_u64(&layout->header.stop))
			break;
		if (sequence != seen + 1) {
			slot->completion.request_id = 0;
			slot->completion.status = -1;
			slot->completion.error_no = EPROTO;
			slot->completion.flags = 0;
			store_release_u64(&slot->completion.sequence, sequence);
			return 1;
		}
		memcpy(&request, &slot->request.request, sizeof(request));
		if (request.flags & REQ_DETAILED) {
			build_detailed_response(&response, mode, key, generation,
						checksum, &request);
			memcpy(&slot->detail, &response, sizeof(response));
			slot->completion.request_id = request.request_id;
			slot->completion.status = response.status;
			slot->completion.error_no = response.error_no;
			slot->completion.flags = SHM_COMPLETION_DETAILED;
			slot->completion.target_total_ns = response.target_total_ns;
		} else {
			build_minimal_completion(&slot->completion, mode, key,
						 generation, checksum, &request);
		}
		store_release_u64(&slot->completion.sequence, sequence);
		seen = sequence;
	}
	return 0;
}

static int run_shm_server(uint16_t mode, const char *path, uint64_t offset,
			  unsigned int lanes, uint64_t key,
			  uint64_t generation, uint64_t checksum)
{
	struct sigaction action = { .sa_handler = signal_stop };
	struct shm_mapping mapping;
	pid_t *children;
	unsigned int started = 0;
	int failed = 0;

	if (mode == MODE_LOCAL && init_local_state(key, checksum)) {
		perror("initialize local state");
		return 1;
	}
	if (map_shm(path, offset, lanes, &mapping)) {
		perror("map shared mailbox");
		return 1;
	}
	children = calloc(lanes, sizeof(*children));
	if (!children) {
		unmap_shm(&mapping);
		return 1;
	}
	memset(mapping.address, 0, mapping.bytes);
	mapping.layout->header.magic = SHM_MAGIC;
	mapping.layout->header.version = SHM_VERSION;
	mapping.layout->header.mode = mode;
	mapping.layout->header.lanes = lanes;
	mapping.layout->header.epoch = now_ns() ^ (uint64_t)getpid();
	mapping.layout->header.key = key;
	mapping.layout->header.generation = generation;
	mapping.layout->header.checksum = checksum;
	store_release_u64(&mapping.layout->header.stop, 0);
	sigemptyset(&action.sa_mask);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	for (unsigned int lane = 0; lane < lanes; lane++) {
		children[lane] = fork();
		if (children[lane] == 0)
			_exit(shm_lane_handler(mapping.layout, lane, mode, key,
					       generation, checksum));
		if (children[lane] < 0) {
			failed = 1;
			break;
		}
		started++;
	}
	if (failed) {
		store_release_u64(&mapping.layout->header.stop, 1);
	} else {
		store_release_u32(&mapping.layout->header.state,
				  SHM_STATE_READY);
		printf("event=shm-server-ready mode=%s path=%s offset=%" PRIu64
		       " lanes=%u key=%" PRIu64 " generation=%" PRIu64
		       " checksum=%016" PRIx64 " bytes=%zu\n",
		       mode_name(mode), path, offset, lanes, key, generation,
		       checksum, mapping.bytes);
		fflush(stdout);
		while (!server_stop)
			pause();
		store_release_u32(&mapping.layout->header.state,
				  SHM_STATE_STOPPING);
		store_release_u64(&mapping.layout->header.stop, 1);
	}
	for (unsigned int lane = 0; lane < started; lane++) {
		int status;

		if (waitpid(children[lane], &status, 0) < 0 ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
	}
	free(children);
	unmap_shm(&mapping);
	return failed;
}

static uint64_t litmus_payload(uint64_t iteration)
{
	return 0x9e3779b97f4a7c15ULL * iteration ^
		0xd6e8feb86659fd93ULL;
}

static int wait_for_u64(const uint64_t *value, uint64_t expected,
			uint64_t timeout_ns)
{
	uint64_t begin_ns = now_ns();

	while (load_acquire_u64(value) != expected) {
		if (now_ns() - begin_ns > timeout_ns) {
			errno = ETIMEDOUT;
			return -1;
		}
		cpu_relax();
	}
	return 0;
}

static int run_shm_litmus_server(const char *path, uint64_t offset,
				 uint64_t iterations)
{
	struct shm_mapping mapping;
	struct shm_litmus *shared;
	uint64_t expected;

	if (map_shm(path, offset, 1, &mapping)) {
		perror("map shared-memory litmus");
		return 1;
	}
	shared = mapping.address;
	memset(shared, 0, sizeof(*shared));
	shared->magic = SHM_LITMUS_MAGIC;
	shared->version = SHM_VERSION;
	shared->iterations = iterations;
	store_release_u64(&shared->phase, SHM_LITMUS_READY);
	for (uint64_t i = 1; i <= iterations; i++) {
		expected = litmus_payload(i);
		shared->payload = expected;
		store_release_u64(&shared->sequence, i * 2 - 1);
		if (wait_for_u64(&shared->sequence, i * 2,
				  120ULL * 1000000000ULL) ||
		    shared->payload != ~expected) {
			perror("shared-memory release/acquire litmus");
			unmap_shm(&mapping);
			return 1;
		}
	}
	store_release_u64(&shared->phase, SHM_LITMUS_RMW);
	for (uint64_t i = 0; i < iterations; i++)
		__atomic_fetch_add(&shared->counter, 1, __ATOMIC_SEQ_CST);
	store_release_u64(&shared->server_done, 1);
	if (wait_for_u64(&shared->client_done, 1,
			 120ULL * 1000000000ULL) ||
	    load_acquire_u64(&shared->counter) != iterations * 2) {
		perror("shared-memory atomic RMW litmus");
		unmap_shm(&mapping);
		return 1;
	}
	store_release_u64(&shared->phase, SHM_LITMUS_COMPLETE);
	printf("event=shm-litmus role=server iterations=%" PRIu64
	       " counter=%" PRIu64 " release_acquire=ok atomic_rmw=ok "
	       "verify=ok\n", iterations,
	       load_acquire_u64(&shared->counter));
	unmap_shm(&mapping);
	return 0;
}

static int run_shm_litmus_client(const char *path, uint64_t offset,
				 uint64_t iterations)
{
	struct shm_mapping mapping;
	struct shm_litmus *shared;
	uint64_t expected;

	if (map_shm(path, offset, 1, &mapping)) {
		perror("map shared-memory litmus");
		return 1;
	}
	shared = mapping.address;
	if (wait_for_u64(&shared->phase, SHM_LITMUS_READY,
			 120ULL * 1000000000ULL) ||
	    shared->magic != SHM_LITMUS_MAGIC ||
	    shared->version != SHM_VERSION ||
	    shared->iterations != iterations) {
		perror("shared-memory litmus header");
		unmap_shm(&mapping);
		return 1;
	}
	for (uint64_t i = 1; i <= iterations; i++) {
		expected = litmus_payload(i);
		if (wait_for_u64(&shared->sequence, i * 2 - 1,
				  120ULL * 1000000000ULL) ||
		    shared->payload != expected) {
			perror("shared-memory release/acquire litmus");
			unmap_shm(&mapping);
			return 1;
		}
		shared->payload = ~expected;
		store_release_u64(&shared->sequence, i * 2);
	}
	if (wait_for_u64(&shared->phase, SHM_LITMUS_RMW,
			 120ULL * 1000000000ULL)) {
		perror("shared-memory RMW phase");
		unmap_shm(&mapping);
		return 1;
	}
	for (uint64_t i = 0; i < iterations; i++)
		__atomic_fetch_add(&shared->counter, 1, __ATOMIC_SEQ_CST);
	store_release_u64(&shared->client_done, 1);
	if (wait_for_u64(&shared->server_done, 1,
			 120ULL * 1000000000ULL) ||
	    wait_for_u64(&shared->phase, SHM_LITMUS_COMPLETE,
			 120ULL * 1000000000ULL) ||
	    load_acquire_u64(&shared->counter) != iterations * 2) {
		perror("shared-memory atomic RMW litmus");
		unmap_shm(&mapping);
		return 1;
	}
	printf("event=shm-litmus role=client iterations=%" PRIu64
	       " counter=%" PRIu64 " release_acquire=ok atomic_rmw=ok "
	       "verify=ok\n", iterations,
	       load_acquire_u64(&shared->counter));
	unmap_shm(&mapping);
	return 0;
}

static int run_server(uint16_t mode, const char *address, uint16_t port,
		      uint64_t key, uint64_t generation, uint64_t checksum)
{
	struct sockaddr_in bind_address = { .sin_family = AF_INET };
	struct sigaction action = { .sa_handler = signal_stop };
	int listener;
	int one = 1;

	if (mode == MODE_LOCAL && init_local_state(key, checksum)) {
		perror("initialize local state");
		return 1;
	}
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(listener, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	bind_address.sin_port = htons(port);
	if (inet_pton(AF_INET, address, &bind_address.sin_addr) != 1 ||
	    bind(listener, (struct sockaddr *)&bind_address,
		 sizeof(bind_address)) || listen(listener, 128)) {
		perror("server bind/listen");
		return 1;
	}
	sigemptyset(&action.sa_mask);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	signal(SIGCHLD, SIG_IGN);
	printf("event=server-ready mode=%s address=%s port=%u key=%" PRIu64
	       " generation=%" PRIu64 " checksum=%016" PRIx64 "\n",
	       mode_name(mode), address, port,
	       key, generation, checksum);
	fflush(stdout);
	while (!server_stop) {
		int connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
		pid_t child;

		if (connection < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			break;
		}
		setsockopt(connection, IPPROTO_TCP, TCP_NODELAY,
			   &one, sizeof(one));
		child = fork();
		if (child == 0) {
			int result;

			signal(SIGCHLD, SIG_DFL);
			close(listener);
			result = lane_handler(connection, mode, key,
					      generation, checksum);
			close(connection);
			_exit(result);
		}
		close(connection);
		if (child < 0)
			perror("fork lane handler");
	}
	close(listener);
	return 0;
}

static int connect_server(const char *address, uint16_t port)
{
	struct sockaddr_in peer = { .sin_family = AF_INET };
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int one = 1;

	if (fd < 0)
		return -1;
	peer.sin_port = htons(port);
	if (inet_pton(AF_INET, address, &peer.sin_addr) != 1 ||
	    connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
		close(fd);
		return -1;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return fd;
}

static int one_client_request(int fd, uint16_t mode, uint64_t request_id,
			      uint64_t key, uint64_t generation,
			      uint64_t checksum, bool debug,
			      struct sample *sample)
{
	struct wire_request request = {
		.magic = WIRE_MAGIC,
		.version = WIRE_VERSION,
		.mode = mode,
		.flags = debug ? REQ_DEBUG_PROOF : 0,
		.request_id = request_id,
		.key = key,
		.generation = generation,
		.expected_checksum = checksum,
	};
	uint64_t begin_ns = now_ns();

	if (write_full(fd, &request, sizeof(request)) ||
	    read_full(fd, &sample->response, sizeof(sample->response)))
		return -1;
	sample->rtt_ns = delta(now_ns(), begin_ns);
	sample->request_id = request_id;
	if (sample->response.magic != WIRE_MAGIC ||
	    sample->response.version != WIRE_VERSION ||
	    sample->response.mode != mode ||
	    sample->response.request_id != request_id ||
	    sample->response.status ||
	    sample->response.child.input_checksum != checksum ||
	    !sample->response.child.output_checksum)
		return -1;
	if (debug && mode == MODE_CXLFORK &&
	    (!sample->response.child.shared_leaf_pfn ||
	     sample->response.child.shared_leaf_pfn !=
		 sample->response.child.current_pmd_pfn ||
	     !sample->response.child.shared_data_pfn ||
	     sample->response.child.shared_data_pfn !=
		 sample->response.child.current_data_pfn))
		return -1;
	return 0;
}

static void csv_header(FILE *file)
{
	fputs("mode,lane,request_id,rtt_ns,cross_vm_residual_ns,target_total_ns,"
	      "request_dispatch_ns,activation_ns,exit_wait_ns,"
	      "fork_parent_return_ns,fork_to_child_ns,child_setup_ns,"
	      "restore_wall_ns,kernel_restore_ns,kernel_supported_mask,"
	      "kernel_valid_mask,kernel_path_mask,continuation_ns,"
	      "child_pid,source_pid,restore_id,input_checksum,output_checksum,"
	      "shared_leaf_pfn,current_pmd_pfn,shared_data_pfn,current_data_pfn,"
	      "kernel_core_ns,capsule_validate_ns,activation_commit_ns,"
	      "lock_wait_ns,lifecycle_ns,manifest_validate_ns,image_validate_ns,"
	      "checksum_validate_ns,address_conflict_ns,vma_create_ns,"
	      "upper_pt_alloc_ns,shared_leaf_attach_ns,pte_image_validate_ns,"
	      "direct_pte_install_ns,fallback_other_ns,dirty_prefault_ns,"
	      "global_restore_ns,kernel_other_ns,shared_leaf_count,"
	      "shared_data_pages,fallback_pages,validated_ptes\n", file);
}

static int write_samples(const char *prefix, uint16_t mode, unsigned int lane,
			 struct sample *samples, uint64_t count)
{
	char path[4096];
	FILE *file;

	if (snprintf(path, sizeof(path), "%s-lane-%u.csv", prefix, lane) >=
	    (int)sizeof(path))
		return -1;
	file = fopen(path, "w");
	if (!file)
		return -1;
	csv_header(file);
	for (uint64_t i = 0; i < count; i++) {
		const struct wire_response *r = &samples[i].response;
		const struct cxlfork_restore_stats_v4 *s = &r->child.stats;
		const struct cxlfork_restore_stats_v3 *c = &s->core;
		uint64_t residual = delta(samples[i].rtt_ns, r->target_total_ns);

		fprintf(file,
			"%s,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%016" PRIx64 ",%016" PRIx64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 "\n",
			mode_name(mode), lane,
			samples[i].request_id, samples[i].rtt_ns, residual,
			r->target_total_ns, r->request_dispatch_ns,
			r->activation_ns, r->exit_wait_ns,
			r->fork_parent_return_ns, r->fork_to_child_ns,
			r->child_setup_ns, r->restore_wall_ns, U64(s->total_ns),
			U64(s->core.supported_mask), U64(s->core.valid_mask),
			U64(s->core.path_mask), r->continuation_ns,
			r->child.child_pid,
			r->child.source_pid, r->child.restore_id,
			r->child.input_checksum, r->child.output_checksum,
			r->child.shared_leaf_pfn, r->child.current_pmd_pfn,
			r->child.shared_data_pfn, r->child.current_data_pfn,
			U64(c->total_ns), U64(s->capsule_validate_ns),
			U64(s->activation_commit_ns), U64(c->lock_wait_ns),
			U64(c->lifecycle_ns), U64(c->manifest_validate_ns),
			U64(c->image_validate_ns), U64(c->checksum_validate_ns),
			U64(c->address_conflict_ns), U64(c->vma_create_ns),
			U64(c->upper_pt_alloc_ns), U64(c->shared_leaf_attach_ns),
			U64(c->pte_image_validate_ns),
			U64(c->direct_pte_install_ns),
			U64(c->fallback_other_ns), U64(c->dirty_prefault_ns),
			U64(c->global_restore_ns), U64(c->other_ns),
			U64(c->shared_leaf_count), U64(c->shared_data_pages),
			U64(c->fallback_pages), U64(c->validated_ptes));
	}
	if (fclose(file))
		return -1;
	return 0;
}

struct shm_client_config {
	uint16_t mode;
	const char *path;
	uint64_t offset;
	unsigned int lanes;
	unsigned int warmup;
	unsigned int duration_seconds;
	uint64_t count;
	uint64_t key;
	uint64_t generation;
	uint64_t checksum;
	const char *prefix;
	bool detailed;
	int ready_write;
	int gate_read;
	uint64_t *counts;
};

static int shm_one_request(struct shm_layout *layout, unsigned int lane,
			   uint16_t mode, uint64_t *sequence,
			   uint64_t request_id, uint64_t key,
			   uint64_t generation, uint64_t checksum,
			   uint32_t flags, struct sample *sample)
{
	struct shm_lane *slot = &layout->lane[lane];
	struct wire_request request = {
		.magic = WIRE_MAGIC,
		.version = WIRE_VERSION,
		.mode = mode,
		.flags = flags,
		.request_id = request_id,
		.key = key,
		.generation = generation,
		.expected_checksum = checksum,
	};
	uint64_t begin_ns = sample ? now_ns() : 0;
	uint64_t expected = ++*sequence;
	uint64_t observed;
	uint64_t spin_begin_ns = begin_ns;
	unsigned int spins = 0;

	memcpy(&slot->request.request, &request, sizeof(request));
	store_release_u64(&slot->request.sequence, expected);
	for (;;) {
		observed = load_acquire_u64(&slot->completion.sequence);
		if (observed == expected)
			break;
		if (observed > expected ||
		    load_acquire_u64(&layout->header.stop)) {
			errno = EPROTO;
			return -1;
		}
		cpu_relax();
		if (!(++spins & ((1U << 20) - 1))) {
			uint64_t current = now_ns();

			if (!spin_begin_ns)
				spin_begin_ns = current;
			else if (current - spin_begin_ns > 10ULL * 1000000000ULL) {
				errno = ETIMEDOUT;
				return -1;
			}
		}
	}
	if (slot->completion.request_id != request_id ||
	    slot->completion.status) {
		errno = slot->completion.error_no ?
			slot->completion.error_no : EPROTO;
		return -1;
	}
	if (flags & REQ_DETAILED) {
		if (!(slot->completion.flags & SHM_COMPLETION_DETAILED) || !sample) {
			errno = EPROTO;
			return -1;
		}
		memcpy(&sample->response, &slot->detail,
		       sizeof(sample->response));
		sample->rtt_ns = delta(now_ns(), begin_ns);
		sample->request_id = request_id;
		if (sample->response.magic != WIRE_MAGIC ||
		    sample->response.version != WIRE_VERSION ||
		    sample->response.mode != mode ||
		    sample->response.request_id != request_id ||
		    sample->response.status ||
		    sample->response.child.input_checksum != checksum ||
		    !sample->response.child.output_checksum) {
			errno = EPROTO;
			return -1;
		}
		if ((flags & REQ_DEBUG_PROOF) && mode == MODE_CXLFORK &&
		    (!sample->response.child.shared_leaf_pfn ||
		     sample->response.child.shared_leaf_pfn !=
			 sample->response.child.current_pmd_pfn ||
		     !sample->response.child.shared_data_pfn ||
		     sample->response.child.shared_data_pfn !=
			 sample->response.child.current_data_pfn)) {
			errno = EUCLEAN;
			return -1;
		}
	}
	return 0;
}

static int validate_shm_header(const struct shm_header *header,
			       const struct shm_client_config *config)
{
	uint64_t begin_ns = now_ns();

	while (load_acquire_u32(&header->state) != SHM_STATE_READY) {
		if (now_ns() - begin_ns > SHM_READY_TIMEOUT_NS) {
			errno = ETIMEDOUT;
			return -1;
		}
		cpu_relax();
	}
	if (header->magic != SHM_MAGIC || header->version != SHM_VERSION ||
	    header->mode != config->mode || header->lanes != config->lanes ||
	    header->key != config->key ||
	    header->generation != config->generation ||
	    header->checksum != config->checksum ||
	    load_acquire_u64(&header->stop)) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int shm_client_lane(const struct shm_client_config *config,
			   unsigned int lane)
{
	struct sigaction action = { .sa_handler = signal_client_stop };
	struct shm_mapping mapping;
	struct sample *samples = NULL;
	uint64_t request_id = ((uint64_t)getpid() << 32) | lane;
	uint64_t sequence;
	uint64_t count = 0;
	char byte = 'R';

	if (map_shm(config->path, config->offset, config->lanes, &mapping) ||
	    validate_shm_header(&mapping.layout->header, config)) {
		perror("map/validate shared mailbox");
		(void)write_full(config->ready_write, "F", 1);
		return 1;
	}
	sequence = load_acquire_u64(
		&mapping.layout->lane[lane].completion.sequence);
	if (config->detailed) {
		samples = calloc(config->count, sizeof(*samples));
		if (!samples) {
			(void)write_full(config->ready_write, "F", 1);
			unmap_shm(&mapping);
			return 1;
		}
	}
	for (unsigned int i = 0; i < config->warmup; i++) {
		struct sample proof;
		uint32_t flags = REQ_MINIMAL;

		if (i == 0)
			flags |= REQ_DETAILED |
				(config->mode == MODE_CXLFORK ? REQ_DEBUG_PROOF : 0);
		if (shm_one_request(mapping.layout, lane, config->mode,
				    &sequence, ++request_id, config->key,
				    config->generation, config->checksum,
				    flags, i == 0 ? &proof : NULL)) {
			perror("shared mailbox warmup request");
			(void)write_full(config->ready_write, "F", 1);
			free(samples);
			unmap_shm(&mapping);
			return 1;
		}
		if (i == 0 && config->mode == MODE_CXLFORK) {
			printf("event=shared-pfn-proof transport=shm lane=%u "
			       "shared_leaf_pfn=%" PRIu64
			       " current_pmd_pfn=%" PRIu64
			       " shared_data_pfn=%" PRIu64
			       " current_data_pfn=%" PRIu64 " verify=ok\n",
			       lane, proof.response.child.shared_leaf_pfn,
			       proof.response.child.current_pmd_pfn,
			       proof.response.child.shared_data_pfn,
			       proof.response.child.current_data_pfn);
			fflush(stdout);
		}
	}
	if (write_full(config->ready_write, &byte, 1) ||
	    read_full(config->gate_read, &byte, 1)) {
		free(samples);
		unmap_shm(&mapping);
		return 1;
	}
	client_stop = 0;
	if (!config->detailed) {
		sigemptyset(&action.sa_mask);
		sigaction(SIGALRM, &action, NULL);
		alarm(config->duration_seconds);
	}
	while (config->detailed ? count < config->count : !client_stop) {
		uint32_t flags = REQ_MINIMAL |
			(config->detailed ? REQ_DETAILED : 0);
		struct sample *sample = config->detailed ? &samples[count] : NULL;

		if (shm_one_request(mapping.layout, lane, config->mode,
				    &sequence, ++request_id, config->key,
				    config->generation, config->checksum,
				    flags, sample)) {
			perror("shared mailbox request");
			free(samples);
			unmap_shm(&mapping);
			return 1;
		}
		count++;
	}
	alarm(0);
	config->counts[lane] = count;
	if (config->detailed &&
	    write_samples(config->prefix, config->mode, lane, samples, count)) {
		free(samples);
		unmap_shm(&mapping);
		return 1;
	}
	free(samples);
	unmap_shm(&mapping);
	return 0;
}

static int run_shm_client(struct shm_client_config *config)
{
	int ready_pipe[2], gate_pipe[2];
	pid_t *children;
	uint64_t total = 0;
	int failed = 0;
	char byte;

	children = calloc(config->lanes, sizeof(*children));
	config->counts = mmap(NULL, config->lanes * sizeof(*config->counts),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!children || config->counts == MAP_FAILED || pipe(ready_pipe) ||
	    pipe(gate_pipe))
		return 1;
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		children[lane] = fork();
		if (children[lane] == 0) {
			close(ready_pipe[0]);
			close(gate_pipe[1]);
			config->ready_write = ready_pipe[1];
			config->gate_read = gate_pipe[0];
			_exit(shm_client_lane(config, lane));
		}
		if (children[lane] < 0)
			return 1;
	}
	close(ready_pipe[1]);
	close(gate_pipe[0]);
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		if (read_full(ready_pipe[0], &byte, 1))
			return 1;
		if (byte != 'R')
			failed = 1;
	}
	close(ready_pipe[0]);
	for (unsigned int lane = 0; lane < config->lanes; lane++)
		if (write_full(gate_pipe[1], "G", 1))
			return 1;
	close(gate_pipe[1]);
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		int status;

		if (waitpid(children[lane], &status, 0) < 0 ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
		total += config->counts[lane];
	}
	printf("event=client-complete transport=shm mode=%s lanes=%u "
	       "operations=%" PRIu64 " duration_s=%u throughput_ops_s=%.3f "
	       "detailed=%s verify=%s\n",
	       mode_name(config->mode), config->lanes, total,
	       config->detailed ? 0 : config->duration_seconds,
	       config->detailed || !config->duration_seconds ? 0.0 :
		(double)total / config->duration_seconds,
	       config->detailed ? "yes" : "no", failed ? "fail" : "ok");
	munmap(config->counts, config->lanes * sizeof(*config->counts));
	free(children);
	return failed;
}

struct local_spawn_config {
	unsigned int lanes;
	unsigned int warmup;
	unsigned int duration_seconds;
	int ready_write;
	int gate_read;
	uint64_t *counts;
};

static int local_spawn_once(void)
{
	pid_t child, waited;
	int status;

	child = fork();
	if (child == 0)
		exit(0);
	if (child < 0)
		return -1;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	return waited == child && WIFEXITED(status) && !WEXITSTATUS(status) ?
		0 : -1;
}

static int local_spawn_lane(const struct local_spawn_config *config,
			    unsigned int lane)
{
	struct sigaction action = { .sa_handler = signal_client_stop };
	uint64_t count = 0;
	char byte = 'R';

	for (unsigned int i = 0; i < config->warmup; i++) {
		if (local_spawn_once()) {
			(void)write_full(config->ready_write, "F", 1);
			return 1;
		}
	}
	if (write_full(config->ready_write, &byte, 1) ||
	    read_full(config->gate_read, &byte, 1))
		return 1;
	client_stop = 0;
	sigemptyset(&action.sa_mask);
	sigaction(SIGALRM, &action, NULL);
	alarm(config->duration_seconds);
	while (!client_stop) {
		if (local_spawn_once())
			return 1;
		count++;
	}
	alarm(0);
	config->counts[lane] = count;
	return 0;
}

static int run_local_spawn(struct local_spawn_config *config)
{
	int ready_pipe[2], gate_pipe[2];
	pid_t *children;
	uint64_t total = 0;
	int failed = 0;
	char byte;

	children = calloc(config->lanes, sizeof(*children));
	config->counts = mmap(NULL, config->lanes * sizeof(*config->counts),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!children || config->counts == MAP_FAILED || pipe(ready_pipe) ||
	    pipe(gate_pipe))
		return 1;
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		children[lane] = fork();
		if (children[lane] == 0) {
			close(ready_pipe[0]);
			close(gate_pipe[1]);
			config->ready_write = ready_pipe[1];
			config->gate_read = gate_pipe[0];
			_exit(local_spawn_lane(config, lane));
		}
		if (children[lane] < 0)
			return 1;
	}
	close(ready_pipe[1]);
	close(gate_pipe[0]);
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		if (read_full(ready_pipe[0], &byte, 1))
			return 1;
		if (byte != 'R')
			failed = 1;
	}
	close(ready_pipe[0]);
	for (unsigned int lane = 0; lane < config->lanes; lane++)
		if (write_full(gate_pipe[1], "G", 1))
			return 1;
	close(gate_pipe[1]);
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		int status;

		if (waitpid(children[lane], &status, 0) < 0 ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
		total += config->counts[lane];
	}
	printf("event=client-complete transport=local mode=spawn lanes=%u "
	       "operations=%" PRIu64 " duration_s=%u throughput_ops_s=%.3f "
	       "verify=%s\n",
	       config->lanes, total, config->duration_seconds,
	       (double)total / config->duration_seconds,
	       failed ? "fail" : "ok");
	munmap(config->counts, config->lanes * sizeof(*config->counts));
	free(children);
	return failed;
}

struct client_config {
	uint16_t mode;
	const char *address;
	uint16_t port;
	unsigned int lanes;
	unsigned int warmup;
	uint64_t duration_ns;
	uint64_t count;
	uint64_t key;
	uint64_t generation;
	uint64_t checksum;
	const char *prefix;
	int ready_write;
	int gate_read;
	uint64_t *counts;
};

static int client_lane(const struct client_config *config, unsigned int lane)
{
	uint64_t capacity = config->count ? config->count :
		(config->duration_ns / 1000000000ULL + 1) *
		MAX_OPS_PER_SECOND_PER_LANE;
	struct sample *samples = calloc(capacity, sizeof(*samples));
	uint64_t request_id = ((uint64_t)getpid() << 32) | lane;
	uint64_t count = 0;
	uint64_t deadline;
	char byte = 'R';
	int fd;

	if (!samples) {
		(void)write_full(config->ready_write, "F", 1);
		return 1;
	}
	fd = connect_server(config->address, config->port);
	if (fd < 0) {
		(void)write_full(config->ready_write, "F", 1);
		return 1;
	}
	for (unsigned int i = 0; i < config->warmup; i++) {
		struct sample ignored;

		if (one_client_request(fd, config->mode, ++request_id,
				       config->key, config->generation,
				       config->checksum, i == 0, &ignored)) {
			(void)write_full(config->ready_write, "F", 1);
			return 1;
		}
		if (i == 0 && config->mode == MODE_CXLFORK) {
			printf("event=shared-pfn-proof lane=%u shared_leaf_pfn=%" PRIu64
			       " current_pmd_pfn=%" PRIu64
			       " shared_data_pfn=%" PRIu64
			       " current_data_pfn=%" PRIu64 " verify=ok\n",
			       lane, ignored.response.child.shared_leaf_pfn,
			       ignored.response.child.current_pmd_pfn,
			       ignored.response.child.shared_data_pfn,
			       ignored.response.child.current_data_pfn);
			fflush(stdout);
		}
	}
	if (write_full(config->ready_write, &byte, 1) ||
	    read_full(config->gate_read, &byte, 1))
		return 1;
	deadline = now_ns() + config->duration_ns;
	while ((config->count ? count < config->count : now_ns() < deadline)) {
		if (count == capacity) {
			fprintf(stderr, "lane %u sample capacity exhausted\n", lane);
			return 1;
		}
		if (one_client_request(fd, config->mode, ++request_id,
				       config->key, config->generation,
				       config->checksum, false,
				       &samples[count]))
			return 1;
		count++;
	}
	close(fd);
	config->counts[lane] = count;
	if (write_samples(config->prefix, config->mode, lane, samples, count))
		return 1;
	free(samples);
	return 0;
}

static int run_client(struct client_config *config)
{
	int ready_pipe[2], gate_pipe[2];
	pid_t *children;
	uint64_t total = 0;
	int failed = 0;
	char byte;

	children = calloc(config->lanes, sizeof(*children));
	config->counts = mmap(NULL, config->lanes * sizeof(*config->counts),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!children || config->counts == MAP_FAILED || pipe(ready_pipe) ||
	    pipe(gate_pipe))
		return 1;
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		children[lane] = fork();
		if (children[lane] == 0) {
			close(ready_pipe[0]);
			close(gate_pipe[1]);
			config->ready_write = ready_pipe[1];
			config->gate_read = gate_pipe[0];
			_exit(client_lane(config, lane));
		}
		if (children[lane] < 0)
			return 1;
	}
	close(ready_pipe[1]);
	close(gate_pipe[0]);
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		if (read_full(ready_pipe[0], &byte, 1))
			return 1;
		if (byte != 'R')
			failed = 1;
	}
	close(ready_pipe[0]);
	for (unsigned int lane = 0; lane < config->lanes; lane++)
		if (write_full(gate_pipe[1], "G", 1))
			return 1;
	close(gate_pipe[1]);
	for (unsigned int lane = 0; lane < config->lanes; lane++) {
		int status;

		if (waitpid(children[lane], &status, 0) < 0 ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
		total += config->counts[lane];
	}
	printf("event=client-complete mode=%s lanes=%u operations=%" PRIu64
	       " duration_s=%.3f throughput_ops_s=%.3f verify=%s\n",
	       mode_name(config->mode),
	       config->lanes, total, config->duration_ns / 1e9,
	       config->duration_ns ? total * 1e9 / config->duration_ns : 0.0,
	       failed ? "fail" : "ok");
	munmap(config->counts, config->lanes * sizeof(*config->counts));
	free(children);
	return failed;
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || !*text || *end)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage:\n"
		"  %s prepare KEY\n"
		"  %s release KEY GENERATION\n"
		"  %s server local|cxlfork|control IP PORT KEY GENERATION CHECKSUM\n"
		"  %s client local|cxlfork|control IP PORT LANES WARMUP DURATION_S "
		"KEY GENERATION CHECKSUM OUTPUT_PREFIX\n"
		"  %s client-count local|cxlfork|control IP PORT LANES REQUESTS "
		"KEY GENERATION CHECKSUM OUTPUT_PREFIX\n"
		"  %s shm-server control|cxlfork PATH OFFSET LANES KEY "
		"GENERATION CHECKSUM\n"
		"  %s shm-client control|cxlfork PATH OFFSET LANES WARMUP "
		"DURATION_S KEY GENERATION CHECKSUM\n"
		"  %s shm-client-count control|cxlfork PATH OFFSET LANES "
		"REQUESTS KEY GENERATION CHECKSUM OUTPUT_PREFIX\n"
		"  %s shm-litmus-server PATH OFFSET ITERATIONS\n"
		"  %s shm-litmus-client PATH OFFSET ITERATIONS\n"
		"  %s local-spawn LANES WARMUP DURATION_S\n",
		program, program, program, program, program, program, program,
		program, program, program, program);
}

int main(int argc, char **argv)
{
	struct client_config config = { 0 };
	struct shm_client_config shm_config = { 0 };
	struct local_spawn_config local_config = { 0 };
	uint64_t key, generation, checksum, temporary, offset, lanes;
	uint16_t mode, port;

	if (argc == 3 && !strcmp(argv[1], "prepare") &&
	    !parse_u64(argv[2], &key) && key)
		return prepare_capsule(key);
	if (argc == 4 && !strcmp(argv[1], "release") &&
	    !parse_u64(argv[2], &key) && !parse_u64(argv[3], &generation) &&
	    key && generation)
		return release_capsule(key, generation);
	if (argc == 8 && !strcmp(argv[1], "server") &&
	    !parse_mode(argv[2], &mode) && !parse_u64(argv[4], &temporary) &&
	    temporary && temporary <= UINT16_MAX &&
	    !parse_u64(argv[5], &key) && !parse_u64(argv[6], &generation) &&
	    !parse_u64(argv[7], &checksum) && key && checksum) {
		port = temporary;
		return run_server(mode, argv[3], port, key, generation, checksum);
	}
	if (argc == 9 && !strcmp(argv[1], "shm-server") &&
	    !parse_mode(argv[2], &mode) && mode != MODE_LOCAL &&
	    !parse_u64(argv[4], &offset) &&
	    !parse_u64(argv[5], &lanes) && lanes &&
	    lanes <= SHM_MAX_LANES && !parse_u64(argv[6], &key) && key &&
	    !parse_u64(argv[7], &generation) &&
	    !parse_u64(argv[8], &checksum) && checksum) {
		return run_shm_server(mode, argv[3], offset, lanes, key,
				      generation, checksum);
	}
	if (argc == 11 && !strcmp(argv[1], "shm-client") &&
	    !parse_mode(argv[2], &shm_config.mode) &&
	    shm_config.mode != MODE_LOCAL &&
	    !parse_u64(argv[4], &shm_config.offset) &&
	    !parse_u64(argv[5], &temporary) && temporary &&
	    temporary <= SHM_MAX_LANES && (shm_config.lanes = temporary) &&
	    !parse_u64(argv[6], &temporary) && temporary <= 1000 &&
	    (shm_config.warmup = temporary, true) &&
	    !parse_u64(argv[7], &temporary) && temporary &&
	    temporary <= 3600 && (shm_config.duration_seconds = temporary) &&
	    !parse_u64(argv[8], &shm_config.key) && shm_config.key &&
	    !parse_u64(argv[9], &shm_config.generation) &&
	    !parse_u64(argv[10], &shm_config.checksum) &&
	    shm_config.checksum) {
		shm_config.path = argv[3];
		return run_shm_client(&shm_config);
	}
	if (argc == 11 && !strcmp(argv[1], "shm-client-count") &&
	    !parse_mode(argv[2], &shm_config.mode) &&
	    shm_config.mode != MODE_LOCAL &&
	    !parse_u64(argv[4], &shm_config.offset) &&
	    !parse_u64(argv[5], &temporary) && temporary &&
	    temporary <= SHM_MAX_LANES && (shm_config.lanes = temporary) &&
	    !parse_u64(argv[6], &shm_config.count) && shm_config.count &&
	    !parse_u64(argv[7], &shm_config.key) && shm_config.key &&
	    !parse_u64(argv[8], &shm_config.generation) &&
	    !parse_u64(argv[9], &shm_config.checksum) &&
	    shm_config.checksum) {
		shm_config.path = argv[3];
		shm_config.prefix = argv[10];
		shm_config.warmup = 1;
		shm_config.detailed = true;
		return run_shm_client(&shm_config);
	}
	if (argc == 5 && !strcmp(argv[1], "shm-litmus-server") &&
	    !parse_u64(argv[3], &offset) &&
	    !parse_u64(argv[4], &temporary) && temporary)
		return run_shm_litmus_server(argv[2], offset, temporary);
	if (argc == 5 && !strcmp(argv[1], "shm-litmus-client") &&
	    !parse_u64(argv[3], &offset) &&
	    !parse_u64(argv[4], &temporary) && temporary)
		return run_shm_litmus_client(argv[2], offset, temporary);
	if (argc == 5 && !strcmp(argv[1], "local-spawn") &&
	    !parse_u64(argv[2], &temporary) && temporary &&
	    temporary <= SHM_MAX_LANES && (local_config.lanes = temporary) &&
	    !parse_u64(argv[3], &temporary) && temporary <= 1000 &&
	    (local_config.warmup = temporary, true) &&
	    !parse_u64(argv[4], &temporary) && temporary &&
	    temporary <= 3600 && (local_config.duration_seconds = temporary))
		return run_local_spawn(&local_config);
	if (argc == 12 && !strcmp(argv[1], "client") &&
	    !parse_mode(argv[2], &config.mode) &&
	    !parse_u64(argv[4], &temporary) && temporary <= UINT16_MAX &&
	    (config.port = temporary) && !parse_u64(argv[5], &temporary) &&
	    temporary && temporary <= 1024 && (config.lanes = temporary) &&
	    !parse_u64(argv[6], &temporary) && temporary <= 1000 &&
	    (config.warmup = temporary, true) &&
	    !parse_u64(argv[7], &temporary) && temporary && temporary <= 3600 &&
	    (config.duration_ns = temporary * 1000000000ULL) &&
	    !parse_u64(argv[8], &config.key) &&
	    !parse_u64(argv[9], &config.generation) &&
	    !parse_u64(argv[10], &config.checksum) && config.key &&
	    config.checksum) {
		config.address = argv[3];
		config.prefix = argv[11];
		return run_client(&config);
	}
	if (argc == 11 && !strcmp(argv[1], "client-count") &&
	    !parse_mode(argv[2], &config.mode) &&
	    !parse_u64(argv[4], &temporary) && temporary <= UINT16_MAX &&
	    (config.port = temporary) && !parse_u64(argv[5], &temporary) &&
	    temporary && temporary <= 1024 && (config.lanes = temporary) &&
	    !parse_u64(argv[6], &config.count) && config.count &&
	    !parse_u64(argv[7], &config.key) &&
	    !parse_u64(argv[8], &config.generation) &&
	    !parse_u64(argv[9], &config.checksum) && config.key &&
	    config.checksum) {
		config.address = argv[3];
		config.prefix = argv[10];
		config.warmup = 1;
		return run_client(&config);
	}
	usage(argv[0]);
	return 2;
}
