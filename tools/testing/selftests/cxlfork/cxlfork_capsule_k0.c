// SPDX-License-Identifier: GPL-2.0
/*
 * CXLfork K0 cooperative function-capsule continuation test.
 *
 * This deliberately does not claim transparent process restoration.  The
 * source runs a single-threaded C function on a private anonymous stack,
 * yields at a quiescent point, and checkpoints the arena containing both the
 * function state and its saved userspace continuation.  The target maps a
 * small local activation stack, asks CXLfork to restore the arena, enters a
 * local trampoline, and resumes the saved function stack without rerunning
 * initialization.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/cxlfork.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define CAPSULE_BASE ((void *)0x480000000000ULL)
#define CAPSULE_BYTES (4UL * 1024 * 1024)
#define CAPSULE_STACK_BYTES (1024UL * 1024)
#define ACTIVATION_BASE ((void *)0x500000000000ULL)
#define ACTIVATION_BYTES (64UL * 1024)
#define CAPSULE_MAGIC 0x43584c4341505330ULL
#define CAPSULE_VERSION 1U
#define CAPSULE_QUIESCENT 1U
#define CAPSULE_RESUMED 2U
#define PAYLOAD_WORDS 4096U
#define SOURCE_INVOCATIONS 16U
#define TARGET_INVOCATION 17U
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL
#define MARKER_R12 0xc012c012c012c012ULL
#define MARKER_R13 0xc013c013c013c013ULL
#define MARKER_R14 0xc014c014c014c014ULL
#define MARKER_R15 0xc015c015c015c015ULL

struct capsule_ctx {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t rbx;
	uint64_t rbp;
	uint64_t rsp;
	uint64_t rip;
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
	uint64_t marker_r12;
	uint64_t marker_r13;
	uint64_t marker_r14;
	uint64_t marker_r15;
	struct capsule_ctx continuation;
	uint64_t payload[PAYLOAD_WORDS];
};

_Static_assert(sizeof(struct capsule_state) < CAPSULE_BYTES -
	       CAPSULE_STACK_BYTES, "capsule state overlaps function stack");

static struct capsule_ctx control_ctx;
static struct capsule_ctx activation_ctx;
static struct cxlfork_resume_capsule_v4 resume_result;
static struct cxlfork_region resume_regions[CXLFORK_MAX_REGIONS];
static int restore_device_fd = -1;
static const uint8_t runtime_sha256[CXLFORK_CAPSULE_DIGEST_BYTES] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};
static const uint8_t image_sha256[CXLFORK_CAPSULE_DIGEST_BYTES] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

static struct capsule_state *capsule(void)
{
	return CAPSULE_BASE;
}

static void log_line(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	int length;

	va_start(args, format);
	length = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	if (length < 0)
		return;
	if ((size_t)length >= sizeof(buffer))
		length = sizeof(buffer) - 1;
	(void)!write(STDOUT_FILENO, buffer, length);
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

/*
 * Save the current callee-saved context to %rdi and restore the context at
 * %rsi.  The local label is the continuation PC: restoring this context
 * executes ret using the saved stack, returning to the original caller.
 */
__attribute__((naked, noinline))
static void capsule_swap(struct capsule_ctx *out __attribute__((unused)),
			 const struct capsule_ctx *in __attribute__((unused)))
{
	__asm__ volatile(
		"movq %r15, 0(%rdi)\n\t"
		"movq %r14, 8(%rdi)\n\t"
		"movq %r13, 16(%rdi)\n\t"
		"movq %r12, 24(%rdi)\n\t"
		"movq %rbx, 32(%rdi)\n\t"
		"movq %rbp, 40(%rdi)\n\t"
		"movq %rsp, 48(%rdi)\n\t"
		"leaq 1f(%rip), %rax\n\t"
		"movq %rax, 56(%rdi)\n\t"
		"movq 56(%rsi), %rax\n\t"
		"movq 0(%rsi), %r15\n\t"
		"movq 8(%rsi), %r14\n\t"
		"movq 16(%rsi), %r13\n\t"
		"movq 24(%rsi), %r12\n\t"
		"movq 32(%rsi), %rbx\n\t"
		"movq 40(%rsi), %rbp\n\t"
		"movq 48(%rsi), %rsp\n\t"
		"jmp *%rax\n\t"
		"1:\n\t"
		"ret\n\t");
}

/*
 * Tail-jump into capsule_swap so its saved stack returns directly to the C
 * capsule function.  Fixed markers prove that callee-saved registers came
 * through the CXL-restored continuation rather than a fresh invocation.
 */
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
		"movq %%r12, %0\n\t"
		"movq %%r13, %1\n\t"
		"movq %%r14, %2\n\t"
		"movq %%r15, %3\n\t"
		: "=m"(state->marker_r12), "=m"(state->marker_r13),
		  "=m"(state->marker_r14), "=m"(state->marker_r15)
		:
		: "memory");
}

static void run_invocation(struct capsule_state *state, uint64_t invocation)
{
	uint64_t mix = 0x9e3779b97f4a7c15ULL ^ invocation;
	unsigned int i;

	for (i = 0; i < PAYLOAD_WORDS; i++) {
		mix ^= mix << 13;
		mix ^= mix >> 7;
		mix ^= mix << 17;
		state->payload[i] =
			(state->payload[i] + mix + invocation + i) ^
			(state->accumulator >> (i & 31));
		state->accumulator =
			(state->accumulator * 33) ^ state->payload[i];
	}
	state->invocation = invocation;
	state->business_checksum = business_checksum(state);
}

__attribute__((noreturn))
static void capsule_unexpected_return(void)
{
	log_line("capsule-k0 event=unexpected-return verify=fail\n");
	_exit(91);
}

__attribute__((noreturn, noinline))
static void capsule_entry(void)
{
	struct capsule_state *state = capsule();
	uint64_t local_stack_probe;
	uint64_t expected_cookie;
	unsigned int invocation;

	state->source_initializations++;
	state->source_pid = getpid();
	for (invocation = 1; invocation <= SOURCE_INVOCATIONS; invocation++)
		run_invocation(state, invocation);
	state->stage = CAPSULE_QUIESCENT;
	state->source_stack_pointer = (uintptr_t)&local_stack_probe;

	/*
	 * The cookie is computed after capsule_swap has filled the continuation,
	 * so the source control path seals it immediately after the yield.
	 */
	capsule_yield_with_markers(&state->continuation, &control_ctx);

	read_markers(state);
	expected_cookie = continuation_cookie(state);
	if (state->magic != CAPSULE_MAGIC ||
	    state->version != CAPSULE_VERSION ||
	    state->stage != CAPSULE_QUIESCENT ||
	    state->source_initializations != 1 ||
	    state->invocation != SOURCE_INVOCATIONS ||
	    state->continuation_cookie != expected_cookie ||
	    state->business_checksum != business_checksum(state) ||
	    state->marker_r12 != MARKER_R12 ||
	    state->marker_r13 != MARKER_R13 ||
	    state->marker_r14 != MARKER_R14 ||
	    state->marker_r15 != MARKER_R15) {
		log_line("capsule-k0 event=continuation-validate "
			 "source_inits=%" PRIu64 " invocation=%" PRIu64
			 " cookie=%016" PRIx64 " expected=%016" PRIx64
			 " verify=fail\n",
			 state->source_initializations, state->invocation,
			 state->continuation_cookie, expected_cookie);
		_exit(92);
	}

	state->target_stack_pointer = (uintptr_t)&local_stack_probe;
	state->target_pid = getpid();
	run_invocation(state, TARGET_INVOCATION);
	state->stage = CAPSULE_RESUMED;
	log_line("capsule-k0 event=target-continued source_pid=%" PRIu64
		 " target_pid=%" PRIu64 " source_inits=%" PRIu64
		 " invocation=%" PRIu64 " source_sp=%016" PRIx64
		 " target_sp=%016" PRIx64 " checksum=%016" PRIx64
		 " markers=ok verify=ok\n",
		 state->source_pid, state->target_pid,
		 state->source_initializations, state->invocation,
		 state->source_stack_pointer, state->target_stack_pointer,
		 state->business_checksum);
	_exit(0);
}

static int open_device(void)
{
	return open(CXLFORK_DEVICE, O_RDWR | O_CLOEXEC);
}

static int map_capsule_arena(void)
{
	void *mapping;

	mapping = mmap(CAPSULE_BASE, CAPSULE_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap capsule arena");
		return -1;
	}
	if (madvise(mapping, CAPSULE_BYTES, MADV_NOHUGEPAGE)) {
		perror("madvise capsule arena");
		return -1;
	}
	memset(mapping, 0, CAPSULE_BYTES);
	return 0;
}

static int map_activation_stack(void)
{
	void *mapping;

	mapping = mmap(ACTIVATION_BASE, ACTIVATION_BYTES,
		       PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap activation stack");
		return -1;
	}
	return 0;
}

__attribute__((noreturn, noinline))
static void capsule_restore_trampoline(void)
{
	struct capsule_state *state = capsule();
	struct cxlfork_inspect_v2 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.address = (uintptr_t)CAPSULE_BASE,
	};
	struct cxlfork_call_stats_v4 call_stats = {
		.size = sizeof(call_stats),
		.abi_version = CXLFORK_ABI_VERSION_V4,
	};
	int fd;

	if (state->magic != CAPSULE_MAGIC ||
	    state->version != CAPSULE_VERSION ||
	    state->stage != CAPSULE_QUIESCENT ||
	    state->continuation_cookie != continuation_cookie(state)) {
		log_line("capsule-k0 event=trampoline-validate verify=fail\n");
		_exit(93);
	}
	if (restore_device_fd >= 0) {
		close(restore_device_fd);
		restore_device_fd = -1;
	}
	inspect.key = state->key;
	fd = open_device();
	if (fd < 0 || ioctl(fd, CXLFORK_INSPECT_V2, &inspect) ||
	    !(inspect.flags & CXLFORK_INSPECT_F_SHARED_LEAF_VALID) ||
	    !(inspect.flags & CXLFORK_INSPECT_F_CURRENT_PMD_VALID) ||
	    !(inspect.flags & CXLFORK_INSPECT_F_CURRENT_PTE_VALID) ||
	    inspect.current_pmd_pfn != inspect.shared_leaf_pfn ||
	    inspect.current_pfn != inspect.shared_pfn) {
		log_line("capsule-k0 event=shared-leaf-proof key=%" PRIu64
			 " flags=%016" PRIx64 " shared_leaf_pfn=%" PRIu64
			 " current_pmd_pfn=%" PRIu64 " shared_pfn=%" PRIu64
			 " current_pfn=%" PRIu64 " verify=fail\n",
			 state->key, inspect.flags, inspect.shared_leaf_pfn,
			 inspect.current_pmd_pfn, inspect.shared_pfn,
			 inspect.current_pfn);
		if (fd >= 0)
			close(fd);
		_exit(95);
	}
	log_line("capsule-k0 event=shared-leaf-proof key=%" PRIu64
		 " generation=%" PRIu64 " shared_leaf_pfn=%" PRIu64
		 " current_pmd_pfn=%" PRIu64 " shared_pfn=%" PRIu64
		 " current_pfn=%" PRIu64 " verify=ok\n",
		 state->key, inspect.generation, inspect.shared_leaf_pfn,
		 inspect.current_pmd_pfn, inspect.shared_pfn,
		 inspect.current_pfn);
	call_stats.key = state->key;
	call_stats.generation = resume_result.generation;
	call_stats.restore_id = resume_result.restore_id;
	if (ioctl(fd, CXLFORK_GET_CALL_STATS_V4, &call_stats) ||
	    call_stats.stats.total_ns != resume_result.stats.total_ns) {
		log_line("capsule-k0 event=context-after-fd-close key=%" PRIu64
			 " restore_id=%" PRIu64 " verify=fail\n",
			 state->key, resume_result.restore_id);
		close(fd);
		_exit(97);
	}
	log_line("capsule-k0 event=context-after-fd-close key=%" PRIu64
		 " restore_id=%" PRIu64 " total_ns=%" PRIu64
		 " verify=ok\n",
		 state->key, resume_result.restore_id,
		 call_stats.stats.total_ns);
	close(fd);
	if (resume_result.stats.total_ns !=
	    resume_result.stats.core.total_ns +
	    resume_result.stats.capsule_validate_ns +
	    resume_result.stats.activation_commit_ns) {
		log_line("capsule-k0 event=v4-stats total_ns=%" PRIu64
			 " core_ns=%" PRIu64 " capsule_validate_ns=%" PRIu64
			 " activation_commit_ns=%" PRIu64 " verify=fail\n",
			 resume_result.stats.total_ns,
			 resume_result.stats.core.total_ns,
			 resume_result.stats.capsule_validate_ns,
			 resume_result.stats.activation_commit_ns);
		_exit(96);
	}
	log_line("capsule-k0 event=v4-stats restore_id=%" PRIu64
		 " total_ns=%" PRIu64 " core_ns=%" PRIu64
		 " capsule_validate_ns=%" PRIu64
		 " activation_commit_ns=%" PRIu64 " verify=ok\n",
		 resume_result.restore_id, resume_result.stats.total_ns,
		 resume_result.stats.core.total_ns,
		 resume_result.stats.capsule_validate_ns,
		 resume_result.stats.activation_commit_ns);
	capsule_swap(&activation_ctx, &state->continuation);
	log_line("capsule-k0 event=trampoline-returned verify=fail\n");
	_exit(94);
}

static int prepare_capsule(uint64_t key, bool corrupt_cookie)
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

	if (map_capsule_arena())
		return 1;
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
	    state->source_initializations != 1) {
		fprintf(stderr, "capsule did not reach its quiescent point\n");
		return 1;
	}
	state->continuation_cookie = continuation_cookie(state);
	if (corrupt_cookie)
		state->continuation_cookie ^= 0x1;

	fd = open_device();
	if (fd < 0) {
		perror("open " CXLFORK_DEVICE);
		return 4;
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
	op.manifest.trampoline_ip =
		(uintptr_t)capsule_restore_trampoline;
	op.manifest.activation_sp =
		(uintptr_t)ACTIVATION_BASE + ACTIVATION_BYTES - 8;
	op.manifest.continuation_cookie = state->continuation_cookie;
	op.manifest.state_checksum = state->business_checksum;
	if (ioctl(fd, CXLFORK_PREPARE_CAPSULE_V4, &op)) {
		perror("PREPARE_CAPSULE_V4");
		close(fd);
		return 1;
	}
	log_line("capsule-k0 event=source-prepared key=%" PRIu64
		 " source_pid=%" PRIu64 " source_inits=%" PRIu64
		 " invocation=%" PRIu64 " continuation_sp=%016" PRIx64
		 " continuation_ip=%016" PRIx64 " cookie=%016" PRIx64
		 " checksum=%016" PRIx64 " generation=%" PRIu64
		 " pages=%" PRIu64
		 " cookie_state=%s verify=ok\n",
		 key, state->source_pid, state->source_initializations,
		 state->invocation, state->continuation.rsp,
		 state->continuation.rip, state->continuation_cookie,
		 state->business_checksum, op.generation, op.total_pages,
		 corrupt_cookie ? "corrupt-for-negative-test" : "valid");
	close(fd);
	return 0;
}

static int restore_capsule(uint64_t key, bool expect_conflict,
			   bool runtime_mismatch, bool validate_full)
{
	struct cxlfork_inspect_capsule_v4 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V4,
		.key = key,
	};
	int fd;

	if (map_activation_stack())
		return 1;
	fd = open_device();
	if (fd < 0) {
		perror("open " CXLFORK_DEVICE);
		return 4;
	}
	if (ioctl(fd, CXLFORK_INSPECT_CAPSULE_V4, &inspect)) {
		perror("INSPECT_CAPSULE_V4");
		close(fd);
		return 1;
	}
	if (expect_conflict && map_capsule_arena()) {
		close(fd);
		return 1;
	}
	memset(&resume_result, 0, sizeof(resume_result));
	resume_result.size = sizeof(resume_result);
	resume_result.abi_version = CXLFORK_ABI_VERSION_V4;
	resume_result.key = key;
	resume_result.generation = inspect.generation;
	resume_result.flags = CXLFORK_F_SHARED_COW;
	if (validate_full)
		resume_result.flags |= CXLFORK_F_VALIDATE_FULL;
	resume_result.regions_ptr = (uintptr_t)resume_regions;
	resume_result.region_capacity = CXLFORK_MAX_REGIONS;
	memcpy(resume_result.runtime_sha256, runtime_sha256,
	       sizeof(runtime_sha256));
	memcpy(resume_result.image_sha256, image_sha256,
	       sizeof(image_sha256));
	if (runtime_mismatch)
		resume_result.runtime_sha256[0] ^= 0xff;
	restore_device_fd = fd;
	if (ioctl(fd, CXLFORK_RESUME_CAPSULE_V4, &resume_result)) {
		restore_device_fd = -1;
		if (expect_conflict && errno == EEXIST) {
			log_line("capsule-k0 event=address-conflict key=%" PRIu64
				 " errno=EEXIST verify=ok\n", key);
			close(fd);
			return 0;
		}
		if (runtime_mismatch && errno == ENOEXEC) {
			log_line("capsule-k0 event=runtime-mismatch key=%" PRIu64
				 " errno=ENOEXEC verify=ok\n", key);
			close(fd);
			return 0;
		}
		perror("RESUME_CAPSULE_V4");
		close(fd);
		return 1;
	}
	if (expect_conflict || runtime_mismatch) {
		fprintf(stderr, "capsule restore ignored a negative test\n");
		return 1;
	}
	fprintf(stderr, "capsule restore returned without entering trampoline\n");
	return 1;
}

static int release_capsule(uint64_t key)
{
	struct cxlfork_inspect_capsule_v4 inspect = {
		.size = sizeof(inspect),
		.abi_version = CXLFORK_ABI_VERSION_V4,
		.key = key,
	};
	struct cxlfork_release_v2 op = {
		.size = sizeof(op),
		.abi_version = CXLFORK_ABI_VERSION_V2,
		.key = key,
	};
	int fd;

	fd = open_device();
	if (fd < 0) {
		perror("open " CXLFORK_DEVICE);
		return 4;
	}
	if (ioctl(fd, CXLFORK_INSPECT_CAPSULE_V4, &inspect)) {
		perror("INSPECT_CAPSULE_V4 release");
		close(fd);
		return 1;
	}
	op.generation = inspect.generation;
	if (ioctl(fd, CXLFORK_RELEASE_V2, &op)) {
		perror("RELEASE_V2 capsule");
		close(fd);
		return 1;
	}
	close(fd);
	log_line("capsule-k0 event=released key=%" PRIu64 " verify=ok\n",
		 key);
	return 0;
}

static int parse_key(const char *text, uint64_t *key)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 0);
	if (errno || !*text || *end || !value)
		return -1;
	*key = value;
	return 0;
}

int main(int argc, char **argv)
{
	uint64_t key;

	if (argc != 3 || parse_key(argv[2], &key)) {
		fprintf(stderr,
			"usage: %s prepare|prepare-corrupt|restore|"
			"restore-full|restore-conflict|"
			"restore-runtime-mismatch|release KEY\n",
			argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "prepare"))
		return prepare_capsule(key, false);
	if (!strcmp(argv[1], "prepare-corrupt"))
		return prepare_capsule(key, true);
	if (!strcmp(argv[1], "restore"))
		return restore_capsule(key, false, false, false);
	if (!strcmp(argv[1], "restore-full"))
		return restore_capsule(key, false, false, true);
	if (!strcmp(argv[1], "restore-conflict"))
		return restore_capsule(key, true, false, false);
	if (!strcmp(argv[1], "restore-runtime-mismatch"))
		return restore_capsule(key, false, true, false);
	if (!strcmp(argv[1], "release"))
		return release_capsule(key);
	fprintf(stderr, "unknown operation: %s\n", argv[1]);
	return 2;
}
