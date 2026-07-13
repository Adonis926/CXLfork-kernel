/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CXLFORK_H
#define _UAPI_LINUX_CXLFORK_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * CXLfork 用户态 ABI：
 * - 用户程序通过 /dev/cxlfork 发起 prepare/resume/stats/release。
 * - VM0 通常执行 CXLFORK_FORK_PREPARE，把状态写到共享 CXL window。
 * - VM1 通常执行 CXLFORK_FORK_RESUME，把 CXL window 中的状态映射/恢复到本进程。
 */
#define CXLFORK_DEVICE "/dev/cxlfork"
#define CXLFORK_MAX_REGIONS 64
#define CXLFORK_MAX_FDS 32
#define CXLFORK_PATH_LEN 128
#define CXLFORK_MAX_RLIMITS 16
#define CXLFORK_SIGSET_WORDS 2

/* namespace/global state 的采集方式标记，用于说明哪些命名空间是序列化还是继承。 */
#define CXLFORK_NS_F_MOUNT_SERIALIZED 0x1U
#define CXLFORK_NS_F_PID_SERIALIZED 0x2U
#define CXLFORK_NS_F_NET_INHERITED 0x4U
#define CXLFORK_NS_F_CGROUP_INHERITED 0x8U

/*
 * restore/tiering flags：
 * - MAP_READONLY：只读映射 CXL 页面。
 * - PRIVATE_COW/MOA：访问时迁移到本地私有页。
 * - SHARED_COW/MOW：写时迁移，读路径保留共享 CXL 映射。
 * - APPLY_* / REOPEN_FDS：控制是否应用 mm/thread/global/fd 状态。
 */
#define CXLFORK_F_MAP_READONLY 0x1ULL
#define CXLFORK_F_PRIVATE_COW 0x2ULL
#define CXLFORK_F_SHARED_COW 0x4ULL
#define CXLFORK_F_APPLY_MM_STATE 0x8ULL
#define CXLFORK_F_REOPEN_FDS 0x10ULL
#define CXLFORK_F_USER_THREAD_STATE 0x20ULL
#define CXLFORK_F_APPLY_THREAD_STATE 0x40ULL
#define CXLFORK_F_APPLY_TLS_STATE 0x80ULL
#define CXLFORK_F_APPLY_GLOBAL_STATE 0x100ULL
#define CXLFORK_F_MIGRATE_ON_ACCESS CXLFORK_F_PRIVATE_COW
#define CXLFORK_F_MIGRATE_ON_WRITE CXLFORK_F_SHARED_COW
#define CXLFORK_F_HYBRID_TIERING 0x200ULL
#define CXLFORK_F_FULL_PRIVATE_STATE 0x400ULL
#define CXLFORK_F_VALIDATE_FULL 0x800ULL
/* Privileged fault injection; available only with CONFIG_CXLFORK_SELFTEST. */
#define CXLFORK_F_TEST_FAIL_AFTER_FIRST_REGION (1ULL << 63)
#define CXLFORK_COMM_LEN 16

#define CXLFORK_ABI_VERSION_V2 2U

/* QUERY_CAPS capability bits. Unset bits are deliberately unsupported. */
#define CXLFORK_CAP_V2_ABI (1ULL << 0)
#define CXLFORK_CAP_PTE_IMAGE_RECONSTRUCTION (1ULL << 1)
#define CXLFORK_CAP_REAL_SHARED_PTE_LEAF (1ULL << 2)
#define CXLFORK_CAP_PTE_LEAF_COW (1ULL << 3)
#define CXLFORK_CAP_VMA_IMAGE_RECONSTRUCTION (1ULL << 4)
#define CXLFORK_CAP_REAL_SHARED_VMA_LEAF (1ULL << 5)
#define CXLFORK_CAP_MOW_DATA_COW (1ULL << 6)
#define CXLFORK_CAP_MOA_DATA_COPY (1ULL << 7)
#define CXLFORK_CAP_CONSISTENT_SINGLE_THREAD (1ULL << 8)
#define CXLFORK_CAP_RELIABLE_SLOT_GENERATION (1ULL << 9)
#define CXLFORK_CAP_FULL_PRIVATE_STATE (1ULL << 10)
#define CXLFORK_CAP_A_BIT_HYBRID (1ULL << 11)
#define CXLFORK_CAP_USER_THREAD_CONTEXT_RESUME (1ULL << 12)
#define CXLFORK_CAP_GLOBAL_FILE_STATE (1ULL << 13)
#define CXLFORK_CAP_RESTORE_FAST_PATH (1ULL << 14)
#define CXLFORK_CAP_KNOWN_MASK ((1ULL << 15) - 1)

/* MM operations rejected by a tested kernel hook on restored VMAs. */
#define CXLFORK_MM_FAILFAST_MPROTECT (1ULL << 0)
#define CXLFORK_MM_FAILFAST_FORK (1ULL << 1)
#define CXLFORK_MM_FAILFAST_GUP (1ULL << 2)
#define CXLFORK_MM_FAILFAST_PARTIAL_MUNMAP (1ULL << 3)
#define CXLFORK_MM_FAILFAST_MREMAP (1ULL << 4)
#define CXLFORK_MM_FAILFAST_KNOWN_MASK ((1ULL << 5) - 1)

#define CXLFORK_INSPECT_F_PAGE_CHECKSUM_VALID (1ULL << 0)
#define CXLFORK_INSPECT_F_LEAF_CHECKSUM_VALID (1ULL << 1)
#define CXLFORK_INSPECT_F_CURRENT_PTE_VALID (1ULL << 2)
#define CXLFORK_INSPECT_F_CHECKSUM_MISMATCH (1ULL << 3)
#define CXLFORK_INSPECT_F_SHARED_LEAF_VALID (1ULL << 4)
#define CXLFORK_INSPECT_F_CURRENT_PMD_VALID (1ULL << 5)
#define CXLFORK_INSPECT_F_CXL_VMA_NODE_VALID (1ULL << 6)
#define CXLFORK_INSPECT_F_ORIG_PTE_VALID (1ULL << 7)
#define CXLFORK_INSPECT_F_VMA_IMAGE_LOOKUP_VALID (1ULL << 8)

#define CXLFORK_RESTORE_PATH_FAST (1ULL << 0)
#define CXLFORK_RESTORE_PATH_FULL_VALIDATION (1ULL << 1)
#define CXLFORK_RESTORE_PATH_SHARED_LEAF (1ULL << 2)
#define CXLFORK_RESTORE_PATH_FALLBACK_RECONSTRUCT (1ULL << 3)
#define CXLFORK_RESTORE_PATH_MOA (1ULL << 4)
#define CXLFORK_RESTORE_PATH_HYBRID (1ULL << 5)
#define CXLFORK_RESTORE_PATH_GLOBAL (1ULL << 6)
#define CXLFORK_RESTORE_PATH_THREAD (1ULL << 7)
#define CXLFORK_RESTORE_PATH_ROLLBACK (1ULL << 8)

/* Per-call measurement validity. A clear bit means the field is NA, not 0. */
#define CXLFORK_PREP_STAT_LOCK_WAIT     (1ULL << 0)
#define CXLFORK_PREP_STAT_LIFECYCLE     (1ULL << 1)
#define CXLFORK_PREP_STAT_VMA_PREFLIGHT (1ULL << 2)
#define CXLFORK_PREP_STAT_PTE_WALK      (1ULL << 3)
#define CXLFORK_PREP_STAT_GUP           (1ULL << 4)
#define CXLFORK_PREP_STAT_PAGE_COPY     (1ULL << 5)
#define CXLFORK_PREP_STAT_PTE_RECHECK   (1ULL << 6)
#define CXLFORK_PREP_STAT_METADATA      (1ULL << 7)
#define CXLFORK_PREP_STAT_CHECKSUM      (1ULL << 8)
#define CXLFORK_PREP_STAT_PUBLISH       (1ULL << 9)
#define CXLFORK_PREP_STAT_KNOWN_MASK    ((1ULL << 10) - 1)

#define CXLFORK_RESTORE_STAT_LOCK_WAIT  (1ULL << 0)
#define CXLFORK_RESTORE_STAT_LIFECYCLE  (1ULL << 1)
#define CXLFORK_RESTORE_STAT_VALIDATION (1ULL << 2)
#define CXLFORK_RESTORE_STAT_VMA_CREATE (1ULL << 3)
#define CXLFORK_RESTORE_STAT_UPPER_PT   (1ULL << 4)
#define CXLFORK_RESTORE_STAT_SHARED_LEAF (1ULL << 5)
#define CXLFORK_RESTORE_STAT_FALLBACK   (1ULL << 6)
#define CXLFORK_RESTORE_STAT_DIRTY_PREF (1ULL << 7)
#define CXLFORK_RESTORE_STAT_GLOBAL     (1ULL << 8)
#define CXLFORK_RESTORE_STAT_ROLLBACK   (1ULL << 9)
#define CXLFORK_RESTORE_STAT_FAULT_DISPATCH (1ULL << 10)
#define CXLFORK_RESTORE_STAT_LEAF_MATERIALIZE (1ULL << 11)
#define CXLFORK_RESTORE_STAT_DATA_COW   (1ULL << 12)
#define CXLFORK_RESTORE_STAT_CXL_COPY   (1ULL << 13)
#define CXLFORK_RESTORE_STAT_KNOWN_MASK ((1ULL << 14) - 1)

#define CXLFORK_PTE_MARK_CLEAR_ACCESSED (1ULL << 0)
#define CXLFORK_PTE_MARK_CLEAR_DIRTY (1ULL << 1)
#define CXLFORK_PTE_MARK_SET_ACCESSED (1ULL << 2)
#define CXLFORK_PTE_MARK_SET_DIRTY (1ULL << 3)
#define CXLFORK_PTE_MARK_KNOWN_MASK ((1ULL << 4) - 1)

/*
 * Test-only cross-VM memory ordering operations.  The kernel exposes this
 * interface only when CONFIG_CXLFORK_SELFTEST is enabled and requires
 * CAP_SYS_ADMIN.  It is not a checkpoint/restore feature capability.
 */
enum cxlfork_litmus_op_v2 {
	CXLFORK_LITMUS_RESET = 0,
	CXLFORK_LITMUS_RMW = 1,
	CXLFORK_LITMUS_MESSAGE = 2,
	CXLFORK_LITMUS_PINGPONG = 3,
	CXLFORK_LITMUS_QUERY = 4,
};

#define CXLFORK_LITMUS_ROLE_0 0U
#define CXLFORK_LITMUS_ROLE_1 1U
#define CXLFORK_LITMUS_PAYLOAD_WORDS 8U

enum cxlfork_slot_state_v2 {
	CXLFORK_SLOT_FREE = 0,
	CXLFORK_SLOT_WRITING = 1,
	CXLFORK_SLOT_READY = 2,
	CXLFORK_SLOT_RELEASING = 3,
};

struct cxlfork_v2_header {
	__u32 size;
	__u16 abi_version;
	__u16 reserved;
};

struct cxlfork_query_caps_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 capabilities;
	__u64 cxl_phys;
	__u64 cxl_size;
	__u64 slot_bytes;
	__u64 data_offset;
	__u32 page_size;
	__u32 max_slots;
	__u32 max_regions;
	__u32 max_ptes;
	__u32 descriptor_version;
	__u32 reserved1;
	__u64 mm_failfast_mask;
	__u64 shared_leaf_alignment;
	__u64 restore_policy_mask;
	__u64 reserved2[4];
};

/*
 * INSPECT is read-only. key and address are inputs; all other fields are
 * outputs. generation is zero until the reliable slot protocol is enabled.
 */
struct cxlfork_inspect_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 key;
	__u64 generation;
	__u64 address;
	__u64 flags;
	__u32 slot;
	__u32 state;
	__u32 reader_count;
	__u32 reserved;
	__u64 nr_regions;
	__u64 nr_ptes;
	__u64 total_pages;
	__u64 image_bytes;
	__u64 page_checksum;
	__u64 observed_page_checksum;
	__u64 leaf_checksum;
	__u64 observed_leaf_checksum;
	__u64 shared_pfn;
	__u64 current_pfn;
	__u64 current_pte;
	__u64 orig_pte;
	__u64 shared_map_pages;
	__u64 local_copy_pages;
	__u64 leaf_copy_pages;
	__u64 shared_leaf_pfn;
	__u64 current_pmd;
	__u64 current_pmd_pfn;
	__u64 vma_maple_root_pfn;
	__u64 vma_maple_nodes;
	__u64 vma_lookup_start;
	__u64 vma_lookup_end;
	__u64 vma_image_root_offset;
	__u64 vma_image_nodes;
	__u64 vma_image_lookup_start;
	__u64 vma_image_lookup_end;
	__u64 fd_table_offset;
	__u64 fd_table_entries;
	__u64 fd_table_bytes;
	__u64 region_table_offset;
	__u64 region_table_entries;
	__u64 region_table_bytes;
	__u64 pte_table_offset;
	__u64 pte_table_entries;
	__u64 pte_table_bytes;
	__u64 page_data_offset;
	__u64 page_data_bytes;
	__u64 extent_bytes;
	__u64 extent_count;
	__u64 extent_bitmap_words;
	__u64 allocated_extents;
};

struct cxlfork_pte_mark_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 start;
	__u64 length;
	__u64 flags;
	__u64 reserved1;
};

struct cxlfork_litmus_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u32 op;
	__u32 role;
	__u64 run_id;
	__u64 iterations;
	__u64 timeout_ns;
	__u64 counter;
	__u64 completions;
	__u64 errors;
	__u64 sequence;
	__u64 acknowledgement;
	__u64 token;
	__u64 reserved1[4];
};

#define CXLFORK_GUP_PROBE_WRITE (1ULL << 0)
#define CXLFORK_GUP_PROBE_LONGTERM (1ULL << 1)
#define CXLFORK_GUP_PROBE_KNOWN_MASK ((1ULL << 2) - 1)

struct cxlfork_gup_probe_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__aligned_u64 address;
	__u64 flags;
	__u64 reserved1[4];
};

struct cxlfork_prepare_stats_v2 {
	__u64 supported_mask;
	__u64 valid_mask;
	__u64 path_mask;
	__u64 total_ns;
	__u64 lock_wait_ns;
	__u64 lifecycle_ns;
	__u64 vma_preflight_ns;
	__u64 pte_walk_ns;
	__u64 gup_ns;
	__u64 page_copy_ns;
	__u64 pte_recheck_ns;
	__u64 metadata_build_ns;
	__u64 checksum_seal_ns;
	__u64 publish_ns;
	__u64 other_ns;
};

struct cxlfork_restore_stats_v2 {
	__u64 supported_mask;
	__u64 valid_mask;
	__u64 path_mask;
	__u64 total_ns;
	__u64 lock_wait_ns;
	__u64 lifecycle_ns;
	__u64 validation_ns;
	__u64 vma_create_ns;
	__u64 upper_pt_alloc_ns;
	__u64 shared_leaf_attach_ns;
	__u64 fallback_reconstruct_ns;
	__u64 dirty_prefault_ns;
	__u64 global_restore_ns;
	__u64 rollback_ns;
	__u64 other_ns;
	__u64 faults;
	__u64 fault_dispatch_ns;
	__u64 leaf_materialize_ns;
	__u64 data_cow_ns;
	__u64 cxl_to_local_copy_ns;
	__u64 shared_leaf_pages;
	__u64 fallback_pages;
	__u64 local_copy_pages;
	__u64 leaf_copy_pages;
	__u64 dirty_prefault_pages;
	__u64 validated_ptes;
};

struct cxlfork_prepare_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 key;
	__u64 scan_start;
	__u64 scan_end;
	__u64 flags;
	__aligned_u64 regions_ptr;
	__u32 region_capacity;
	__u32 region_count;
	__u64 generation;
	__u64 slot;
	__u64 total_pages;
	__u64 page_checksum;
	struct cxlfork_prepare_stats_v2 stats;
	__u64 reserved1[4];
};

struct cxlfork_resume_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 key;
	__u64 generation;
	__u64 flags;
	__aligned_u64 regions_ptr;
	__u32 region_capacity;
	__u32 region_count;
	__u64 restore_id;
	__u64 total_pages;
	__u64 page_checksum;
	struct cxlfork_restore_stats_v2 stats;
	__u64 reserved1[4];
};

struct cxlfork_release_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 key;
	__u64 generation;
	__u64 flags;
	__u64 reserved1[4];
};

struct cxlfork_call_stats_v2 {
	__u32 size;
	__u16 abi_version;
	__u16 reserved0;
	__u64 key;
	__u64 generation;
	__u64 restore_id;
	struct cxlfork_restore_stats_v2 stats;
	__u64 reserved1[4];
};

struct cxlfork_region {
	/* 对外暴露的 VMA/region 摘要，便于 benchmark 记录页分类。 */
	__u64 start;
	__u64 length;
	__u64 prot;
	__u64 flags;
	__u64 pages;
	__u64 anon_pages;
	__u64 clean_file_pages;
	__u64 dirty_file_pages;
};

struct cxlfork_mm_state {
	/* mm_struct 中和进程地址空间相关的可观测元数据。 */
	__u64 start_code;
	__u64 end_code;
	__u64 start_data;
	__u64 end_data;
	__u64 start_brk;
	__u64 brk;
	__u64 start_stack;
	__u64 arg_start;
	__u64 arg_end;
	__u64 env_start;
	__u64 env_end;
	__u64 saved_auxv[46];
	__u32 pid;
	__u32 tgid;
	__u8 comm[CXLFORK_COMM_LEN];
};


struct cxlfork_task_state {
	/* task/cred/capability 摘要，用来模拟跨 OS 任务状态迁移成本。 */
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 euid;
	__u32 egid;
	__u32 suid;
	__u32 sgid;
	__u32 fsuid;
	__u32 fsgid;
	__u32 exit_signal;
	__u32 policy;
	__u32 prio;
	__u32 static_prio;
	__u32 normal_prio;
	__u64 flags;
	__u64 personality;
	__u64 cap_inheritable;
	__u64 cap_permitted;
	__u64 cap_effective;
	__u64 cap_bset;
	__u64 cap_ambient;
	__u32 full_private_state;
	__u32 reserved;
	unsigned char comm[CXLFORK_COMM_LEN];
};

struct cxlfork_fd_state {
	/* 文件描述符快照；当前原型记录 path/pos/flag 并在 restore 时尝试重开。 */
	__u32 fd;
	__u32 flags;
	__u64 pos;
	__u64 inode;
	__u64 dev;
	__u8 path[CXLFORK_PATH_LEN];
};

struct cxlfork_thread_state {
	/* x86-64 线程寄存器/TLS 摘要，当前主要用于记录与可选 apply。 */
	__u64 ip;
	__u64 sp;
	__u64 flags;
	__u64 ax;
	__u64 bx;
	__u64 cx;
	__u64 dx;
	__u64 si;
	__u64 di;
	__u64 bp;
	__u64 fsbase;
	__u64 gsbase;
};

struct cxlfork_rlimit_state {
	/* rlimit 快照，属于 global state 的一部分。 */
	__u64 rlim_cur;
	__u64 rlim_max;
};

struct cxlfork_namespace_state {
	/* namespace 身份和序列化/继承标记。 */
	__u64 mnt_ns;
	__u64 pid_ns;
	__u64 net_ns;
	__u64 cgroup_ns;
	__u32 pid_ns_level;
	__u32 flags;
};

struct cxlfork_global_state {
	/* cwd/root/umask/signal/rlimit/namespace 等进程全局状态。 */
	__u32 umask;
	__u32 nr_rlimits;
	__u64 sas_ss_sp;
	__u64 sas_ss_size;
	__u32 sas_ss_flags;
	__u32 reserved;
	__u64 sig_blocked[CXLFORK_SIGSET_WORDS];
	struct cxlfork_rlimit_state rlimits[CXLFORK_MAX_RLIMITS];
	struct cxlfork_namespace_state ns_state;
	__u8 cwd[CXLFORK_PATH_LEN];
	__u8 root[CXLFORK_PATH_LEN];
};

struct cxlfork_checkpoint {
	/*
	 * prepare 输入/输出：
	 * 输入 key、scan_start/scan_end 和 flags；输出各类元数据构建耗时与页统计。
	 */
	__u64 key;
	__u64 scan_start;
	__u64 scan_end;
	__u64 flags;
	__u64 nr_regions;
	__u64 nr_ptes;
	__u64 total_pages;
	__u64 anon_pages;
	__u64 clean_file_pages;
	__u64 dirty_file_pages;
	__u64 checkpoint_ns;
	__u64 nr_fds;
	__u64 global_checkpoint_ns;
	__u64 pte_image_build_ns;
	__u64 pte_image_pages;
	__u64 pt_page_image_build_ns;
	__u64 pt_page_image_pages;
	__u64 pt_page_image_entries;
	__u64 vma_tree_build_ns;
	__u64 vma_tree_pages;
	__u64 vma_tree_nodes;
	__u64 state_image_build_ns;
	__u64 state_image_pages;
	__u64 private_rebase_ns;
	__u64 private_rebase_entries;
	__u64 private_rebase_pages;
	__u64 global_detach_ns;
	struct cxlfork_task_state task_state;
	struct cxlfork_mm_state mm_state;
	struct cxlfork_thread_state thread_state;
	struct cxlfork_global_state global_state;
	struct cxlfork_fd_state fds[CXLFORK_MAX_FDS];
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS];
};

struct cxlfork_restore {
	/*
	 * resume 输入/输出：
	 * 输入 key、flags 和 tiering_hot_stride_pages；输出 restore/attach/validate breakdown。
	 */
	__u64 key;
	__u64 flags;
	__u64 nr_regions;
	__u64 nr_ptes;
	__u64 total_pages;
	__u64 anon_pages;
	__u64 clean_file_pages;
	__u64 dirty_file_pages;
	__u64 restore_ns;
	__u64 nr_fds;
	__u64 nr_fds_restored;
	__u64 global_restore_ns;
	__u64 tiering_hot_stride_pages;
	__u64 pte_attach_ns;
	__u64 pte_attach_pages;
	__u64 direct_pte_install_ns;
	__u64 direct_pte_install_pages;
	__u64 pte_image_validate_ns;
	__u64 pte_image_build_ns;
	__u64 pte_image_pages;
	__u64 pt_page_image_validate_ns;
	__u64 pt_page_image_build_ns;
	__u64 pt_page_image_pages;
	__u64 pt_page_image_entries;
	__u64 vma_tree_validate_ns;
	__u64 vma_tree_build_ns;
	__u64 vma_tree_pages;
	__u64 vma_tree_nodes;
	__u64 state_image_validate_ns;
	__u64 state_image_build_ns;
	__u64 state_image_pages;
	__u64 private_rebase_validate_ns;
	__u64 private_rebase_ns;
	__u64 private_rebase_entries;
	__u64 private_rebase_pages;
	__u64 global_detach_ns;
	__u64 global_attach_ns;
	__u64 pte_image_reconstruct_ns;
	__u64 pte_image_reconstruct_pages;
	__u64 shared_leaf_attach_ns;
	__u64 shared_leaf_attach_pages;
	__u64 dirty_prefault_ns;
	__u64 dirty_prefault_pages;
	struct cxlfork_namespace_state restore_ns_state;
	struct cxlfork_task_state task_state;
	struct cxlfork_mm_state mm_state;
	struct cxlfork_thread_state thread_state;
	struct cxlfork_global_state global_state;
	struct cxlfork_fd_state fds[CXLFORK_MAX_FDS];
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS];
};

struct cxlfork_stats {
	/* 查询某个 key 对应 slot 的当前状态，faults 是 fault handler 累计计数。 */
	__u64 key;
	__u64 ready;
	__u64 slot;
	__u64 nr_regions;
	__u64 nr_ptes;
	__u64 total_pages;
	__u64 anon_pages;
	__u64 clean_file_pages;
	__u64 dirty_file_pages;
	__u64 faults;
};

struct cxlfork_release {
	/* 释放某个 key 对应 slot，下一轮 prepare 前通常先调用。 */
	__u64 key;
};

#define CXLFORK_IOC_MAGIC 'C'
/* CHECKPOINT/RESTORE 是通用接口；FORK_PREPARE/FORK_RESUME 是论文复现主路径使用的别名。 */
#define CXLFORK_CHECKPOINT _IOWR(CXLFORK_IOC_MAGIC, 1, struct cxlfork_checkpoint)
#define CXLFORK_RESTORE _IOWR(CXLFORK_IOC_MAGIC, 2, struct cxlfork_restore)
#define CXLFORK_STATS _IOWR(CXLFORK_IOC_MAGIC, 3, struct cxlfork_stats)
#define CXLFORK_RELEASE _IOW(CXLFORK_IOC_MAGIC, 4, struct cxlfork_release)
#define CXLFORK_FORK_PREPARE _IOWR(CXLFORK_IOC_MAGIC, 5, struct cxlfork_checkpoint)
#define CXLFORK_FORK_RESUME _IOWR(CXLFORK_IOC_MAGIC, 6, struct cxlfork_restore)
#define CXLFORK_QUERY_CAPS_V2 _IOWR(CXLFORK_IOC_MAGIC, 7, struct cxlfork_v2_header)
#define CXLFORK_PREPARE_V2 _IOWR(CXLFORK_IOC_MAGIC, 8, struct cxlfork_v2_header)
#define CXLFORK_RESUME_V2 _IOWR(CXLFORK_IOC_MAGIC, 9, struct cxlfork_v2_header)
#define CXLFORK_RELEASE_V2 _IOWR(CXLFORK_IOC_MAGIC, 10, struct cxlfork_v2_header)
#define CXLFORK_INSPECT_V2 _IOWR(CXLFORK_IOC_MAGIC, 11, struct cxlfork_v2_header)
#define CXLFORK_PTE_MARK_V2 _IOWR(CXLFORK_IOC_MAGIC, 12, struct cxlfork_v2_header)
#define CXLFORK_LITMUS_V2 _IOWR(CXLFORK_IOC_MAGIC, 13, struct cxlfork_v2_header)
#define CXLFORK_GET_CALL_STATS_V2 _IOWR(CXLFORK_IOC_MAGIC, 14, struct cxlfork_v2_header)
#define CXLFORK_GUP_PROBE_V2 _IOWR(CXLFORK_IOC_MAGIC, 15, struct cxlfork_v2_header)

#endif /* _UAPI_LINUX_CXLFORK_H */
