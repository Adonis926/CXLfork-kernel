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
#define REQ_DEBUG_PROOF (1U << 0)
#define MAX_OPS_PER_SECOND_PER_LANE 20000ULL
#define U64(value) ((uint64_t)(value))

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

_Static_assert(sizeof(struct capsule_state) < CAPSULE_BYTES -
	       CAPSULE_STACK_BYTES, "capsule state overlaps function stack");

static struct capsule_ctx control_ctx;
static struct capsule_ctx activation_ctx;
static struct cxlfork_resume_capsule_v4 resume_result;
static struct cxlfork_region resume_regions[CXLFORK_MAX_REGIONS];
static struct child_result current_child;
static int restore_device_fd = -1;
static int child_result_fd = -1;
static bool child_debug_proof;
static volatile sig_atomic_t server_stop;

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
	_exit(code);
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
	if (resume_result.stats.total_ns !=
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

static void local_child(uint64_t expected_checksum, int output_fd)
{
	struct capsule_state *state = capsule();

	memset(&current_child, 0, sizeof(current_child));
	child_result_fd = output_fd;
	current_child.child_begin_ns = now_ns();
	current_child.restore_begin_ns = current_child.child_begin_ns;
	current_child.restore_end_ns = current_child.child_begin_ns;
	current_child.child_pid = getpid();
	current_child.source_pid = state->source_pid;
	current_child.input_checksum = state->business_checksum;
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
	current_child.child_begin_ns = now_ns();
	if (map_activation_stack()) {
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
	current_child.restore_begin_ns = now_ns();
	if (ioctl(restore_device_fd, CXLFORK_RESUME_CAPSULE_V4,
		  &resume_result)) {
		current_child.status = -1;
		current_child.error_no = errno;
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

static int process_request(int socket_fd, uint16_t mode,
			   uint64_t key, uint64_t generation,
			   uint64_t checksum,
			   const struct wire_request *request)
{
	struct wire_response response;
	int pipe_fd[2];
	uint64_t begin_ns, fork_begin_ns, fork_return_ns, wait_end_ns;
	pid_t child;
	pid_t waited;
	int status;
	int read_status;

	memset(&response, 0, sizeof(response));
	response.magic = WIRE_MAGIC;
	response.version = WIRE_VERSION;
	response.mode = mode;
	response.request_id = request->request_id;
	if (request->magic != WIRE_MAGIC || request->version != WIRE_VERSION ||
	    request->mode != mode || request->key != key ||
	    request->generation != generation ||
	    request->expected_checksum != checksum) {
		response.status = -1;
		response.error_no = EINVAL;
		return write_full(socket_fd, &response, sizeof(response));
	}
	begin_ns = now_ns();
	if (pipe2(pipe_fd, O_CLOEXEC)) {
		response.status = -1;
		response.error_no = errno;
		return write_full(socket_fd, &response, sizeof(response));
	}
	fork_begin_ns = now_ns();
	child = fork();
	if (child == 0) {
		close(pipe_fd[0]);
		if (mode == MODE_LOCAL)
			local_child(checksum, pipe_fd[1]);
		else
			cxlfork_child(request, pipe_fd[1]);
	}
	fork_return_ns = now_ns();
	close(pipe_fd[1]);
	if (child < 0) {
		response.status = -1;
		response.error_no = errno;
		close(pipe_fd[0]);
		return write_full(socket_fd, &response, sizeof(response));
	}
	read_status = read_full(pipe_fd[0], &response.child,
				sizeof(response.child));
	close(pipe_fd[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	wait_end_ns = now_ns();
	response.target_total_ns = delta(wait_end_ns, begin_ns);
	response.request_dispatch_ns = delta(fork_begin_ns, begin_ns);
	response.fork_parent_return_ns = delta(fork_return_ns, fork_begin_ns);
	response.fork_to_child_ns =
		delta(response.child.child_begin_ns, fork_begin_ns);
	response.child_setup_ns = delta(response.child.restore_begin_ns,
					response.child.child_begin_ns);
	response.restore_wall_ns = delta(response.child.restore_end_ns,
					response.child.restore_begin_ns);
	response.continuation_ns = delta(response.child.proof_end_ns,
					response.child.restore_end_ns);
	response.activation_ns = delta(response.child.proof_end_ns,
					fork_begin_ns);
	response.exit_wait_ns = delta(wait_end_ns, response.child.proof_end_ns);
	if (read_status || waited != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) ||
	    response.child.status ||
	    response.child.input_checksum != checksum) {
		response.status = -1;
		response.error_no = response.child.error_no ?
			response.child.error_no : ECHILD;
	} else {
		response.status = 0;
	}
	return write_full(socket_fd, &response, sizeof(response));
}

static void signal_stop(int signal_number __attribute__((unused)))
{
	server_stop = 1;
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
		if (process_request(socket_fd, mode, key, generation,
				    checksum, &request))
			return 1;
	}
}

static int parse_mode(const char *text, uint16_t *mode)
{
	if (!strcmp(text, "local"))
		*mode = MODE_LOCAL;
	else if (!strcmp(text, "cxlfork"))
		*mode = MODE_CXLFORK;
	else
		return -1;
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
	       mode == MODE_LOCAL ? "local" : "cxlfork", address, port,
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
	fputs("mode,lane,request_id,rtt_ns,vm0_residual_ns,target_total_ns,"
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
			mode == MODE_LOCAL ? "local" : "cxlfork", lane,
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
	       config->mode == MODE_LOCAL ? "local" : "cxlfork",
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
		"  %s server local|cxlfork IP PORT KEY GENERATION CHECKSUM\n"
		"  %s client local|cxlfork IP PORT LANES WARMUP DURATION_S "
		"KEY GENERATION CHECKSUM OUTPUT_PREFIX\n"
		"  %s client-count local|cxlfork IP PORT LANES REQUESTS "
		"KEY GENERATION CHECKSUM OUTPUT_PREFIX\n",
		program, program, program, program, program);
}

int main(int argc, char **argv)
{
	struct client_config config = { 0 };
	uint64_t key, generation, checksum, temporary;
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
