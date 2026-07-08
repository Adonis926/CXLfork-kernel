/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CXLFORK_H
#define _UAPI_LINUX_CXLFORK_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define CXLFORK_DEVICE "/dev/cxlfork"
#define CXLFORK_MAX_REGIONS 64
#define CXLFORK_MAX_FDS 32
#define CXLFORK_PATH_LEN 128
#define CXLFORK_MAX_RLIMITS 16
#define CXLFORK_SIGSET_WORDS 2

#define CXLFORK_NS_F_MOUNT_SERIALIZED 0x1U
#define CXLFORK_NS_F_PID_SERIALIZED 0x2U
#define CXLFORK_NS_F_NET_INHERITED 0x4U
#define CXLFORK_NS_F_CGROUP_INHERITED 0x8U

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
#define CXLFORK_COMM_LEN 16

struct cxlfork_region {
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
	__u32 fd;
	__u32 flags;
	__u64 pos;
	__u64 inode;
	__u64 dev;
	__u8 path[CXLFORK_PATH_LEN];
};

struct cxlfork_thread_state {
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
	__u64 rlim_cur;
	__u64 rlim_max;
};

struct cxlfork_namespace_state {
	__u64 mnt_ns;
	__u64 pid_ns;
	__u64 net_ns;
	__u64 cgroup_ns;
	__u32 pid_ns_level;
	__u32 flags;
};

struct cxlfork_global_state {
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
	struct cxlfork_namespace_state restore_ns_state;
	struct cxlfork_task_state task_state;
	struct cxlfork_mm_state mm_state;
	struct cxlfork_thread_state thread_state;
	struct cxlfork_global_state global_state;
	struct cxlfork_fd_state fds[CXLFORK_MAX_FDS];
	struct cxlfork_region regions[CXLFORK_MAX_REGIONS];
};

struct cxlfork_stats {
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
	__u64 key;
};

#define CXLFORK_IOC_MAGIC 'C'
#define CXLFORK_CHECKPOINT _IOWR(CXLFORK_IOC_MAGIC, 1, struct cxlfork_checkpoint)
#define CXLFORK_RESTORE _IOWR(CXLFORK_IOC_MAGIC, 2, struct cxlfork_restore)
#define CXLFORK_STATS _IOWR(CXLFORK_IOC_MAGIC, 3, struct cxlfork_stats)
#define CXLFORK_RELEASE _IOW(CXLFORK_IOC_MAGIC, 4, struct cxlfork_release)
#define CXLFORK_FORK_PREPARE _IOWR(CXLFORK_IOC_MAGIC, 5, struct cxlfork_checkpoint)
#define CXLFORK_FORK_RESUME _IOWR(CXLFORK_IOC_MAGIC, 6, struct cxlfork_restore)

#endif /* _UAPI_LINUX_CXLFORK_H */
