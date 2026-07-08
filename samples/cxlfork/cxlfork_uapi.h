/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _CXLFORK_SAMPLE_UAPI_H
#define _CXLFORK_SAMPLE_UAPI_H

#include <stdint.h>
#include <sys/ioctl.h>

/*
 * CXLfork 用户态 ABI 的 standalone 拷贝：
 * - 供 benchmark 在普通用户态环境直接编译，不依赖内核 UAPI include 路径。
 * - 字段布局需要和 include/uapi/linux/cxlfork.h 保持一致。
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
#define CXLFORK_COMM_LEN 16

struct cxlfork_region {
	/* 对外暴露的 VMA/region 摘要，便于 benchmark 记录页分类。 */
	uint64_t start;
	uint64_t length;
	uint64_t prot;
	uint64_t flags;
	uint64_t pages;
	uint64_t anon_pages;
	uint64_t clean_file_pages;
	uint64_t dirty_file_pages;
};

struct cxlfork_mm_state {
	/* mm_struct 中和进程地址空间相关的可观测元数据。 */
	uint64_t start_code;
	uint64_t end_code;
	uint64_t start_data;
	uint64_t end_data;
	uint64_t start_brk;
	uint64_t brk;
	uint64_t start_stack;
	uint64_t arg_start;
	uint64_t arg_end;
	uint64_t env_start;
	uint64_t env_end;
	uint64_t saved_auxv[46];
	uint32_t pid;
	uint32_t tgid;
	uint8_t comm[CXLFORK_COMM_LEN];
};


struct cxlfork_task_state {
	/* task/cred/capability 摘要，用来模拟跨 OS 任务状态迁移成本。 */
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t gid;
	uint32_t euid;
	uint32_t egid;
	uint32_t suid;
	uint32_t sgid;
	uint32_t fsuid;
	uint32_t fsgid;
	uint32_t exit_signal;
	uint32_t policy;
	uint32_t prio;
	uint32_t static_prio;
	uint32_t normal_prio;
	uint64_t flags;
	uint64_t personality;
	uint64_t cap_inheritable;
	uint64_t cap_permitted;
	uint64_t cap_effective;
	uint64_t cap_bset;
	uint64_t cap_ambient;
	uint32_t full_private_state;
	uint32_t reserved;
	unsigned char comm[CXLFORK_COMM_LEN];
};

struct cxlfork_fd_state {
	/* 文件描述符快照；当前原型记录 path/pos/flag 并在 restore 时尝试重开。 */
	uint32_t fd;
	uint32_t flags;
	uint64_t pos;
	uint64_t inode;
	uint64_t dev;
	uint8_t path[CXLFORK_PATH_LEN];
};

struct cxlfork_thread_state {
	/* x86-64 线程寄存器/TLS 摘要，当前主要用于记录与可选 apply。 */
	uint64_t ip;
	uint64_t sp;
	uint64_t flags;
	uint64_t ax;
	uint64_t bx;
	uint64_t cx;
	uint64_t dx;
	uint64_t si;
	uint64_t di;
	uint64_t bp;
	uint64_t fsbase;
	uint64_t gsbase;
};

struct cxlfork_rlimit_state {
	/* rlimit 快照，属于 global state 的一部分。 */
	uint64_t rlim_cur;
	uint64_t rlim_max;
};

struct cxlfork_namespace_state {
	/* namespace 身份和序列化/继承标记。 */
	uint64_t mnt_ns;
	uint64_t pid_ns;
	uint64_t net_ns;
	uint64_t cgroup_ns;
	uint32_t pid_ns_level;
	uint32_t flags;
};

struct cxlfork_global_state {
	/* cwd/root/umask/signal/rlimit/namespace 等进程全局状态。 */
	uint32_t umask;
	uint32_t nr_rlimits;
	uint64_t sas_ss_sp;
	uint64_t sas_ss_size;
	uint32_t sas_ss_flags;
	uint32_t reserved;
	uint64_t sig_blocked[CXLFORK_SIGSET_WORDS];
	struct cxlfork_rlimit_state rlimits[CXLFORK_MAX_RLIMITS];
	struct cxlfork_namespace_state ns_state;
	uint8_t cwd[CXLFORK_PATH_LEN];
	uint8_t root[CXLFORK_PATH_LEN];
};

struct cxlfork_checkpoint {
	/*
	 * prepare 输入/输出：
	 * 输入 key、scan_start/scan_end 和 flags；输出各类元数据构建耗时与页统计。
	 */
	uint64_t key;
	uint64_t scan_start;
	uint64_t scan_end;
	uint64_t flags;
	uint64_t nr_regions;
	uint64_t nr_ptes;
	uint64_t total_pages;
	uint64_t anon_pages;
	uint64_t clean_file_pages;
	uint64_t dirty_file_pages;
	uint64_t checkpoint_ns;
	uint64_t nr_fds;
	uint64_t global_checkpoint_ns;
	uint64_t pte_image_build_ns;
	uint64_t pte_image_pages;
	uint64_t pt_page_image_build_ns;
	uint64_t pt_page_image_pages;
	uint64_t pt_page_image_entries;
	uint64_t vma_tree_build_ns;
	uint64_t vma_tree_pages;
	uint64_t vma_tree_nodes;
	uint64_t state_image_build_ns;
	uint64_t state_image_pages;
	uint64_t private_rebase_ns;
	uint64_t private_rebase_entries;
	uint64_t private_rebase_pages;
	uint64_t global_detach_ns;
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
	uint64_t key;
	uint64_t flags;
	uint64_t nr_regions;
	uint64_t nr_ptes;
	uint64_t total_pages;
	uint64_t anon_pages;
	uint64_t clean_file_pages;
	uint64_t dirty_file_pages;
	uint64_t restore_ns;
	uint64_t nr_fds;
	uint64_t nr_fds_restored;
	uint64_t global_restore_ns;
	uint64_t tiering_hot_stride_pages;
	uint64_t pte_attach_ns;
	uint64_t pte_attach_pages;
	uint64_t direct_pte_install_ns;
	uint64_t direct_pte_install_pages;
	uint64_t pte_image_validate_ns;
	uint64_t pte_image_build_ns;
	uint64_t pte_image_pages;
	uint64_t pt_page_image_validate_ns;
	uint64_t pt_page_image_build_ns;
	uint64_t pt_page_image_pages;
	uint64_t pt_page_image_entries;
	uint64_t vma_tree_validate_ns;
	uint64_t vma_tree_build_ns;
	uint64_t vma_tree_pages;
	uint64_t vma_tree_nodes;
	uint64_t state_image_validate_ns;
	uint64_t state_image_build_ns;
	uint64_t state_image_pages;
	uint64_t private_rebase_validate_ns;
	uint64_t private_rebase_ns;
	uint64_t private_rebase_entries;
	uint64_t private_rebase_pages;
	uint64_t global_detach_ns;
	uint64_t global_attach_ns;
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
	uint64_t key;
	uint64_t ready;
	uint64_t slot;
	uint64_t nr_regions;
	uint64_t nr_ptes;
	uint64_t total_pages;
	uint64_t anon_pages;
	uint64_t clean_file_pages;
	uint64_t dirty_file_pages;
	uint64_t faults;
};

struct cxlfork_release {
	/* 释放某个 key 对应 slot，下一轮 prepare 前通常先调用。 */
	uint64_t key;
};

#define CXLFORK_IOC_MAGIC 'C'
/* CHECKPOINT/RESTORE 是通用接口；FORK_PREPARE/FORK_RESUME 是论文复现主路径使用的别名。 */
#define CXLFORK_CHECKPOINT _IOWR(CXLFORK_IOC_MAGIC, 1, struct cxlfork_checkpoint)
#define CXLFORK_RESTORE _IOWR(CXLFORK_IOC_MAGIC, 2, struct cxlfork_restore)
#define CXLFORK_STATS _IOWR(CXLFORK_IOC_MAGIC, 3, struct cxlfork_stats)
#define CXLFORK_RELEASE _IOW(CXLFORK_IOC_MAGIC, 4, struct cxlfork_release)
#define CXLFORK_FORK_PREPARE _IOWR(CXLFORK_IOC_MAGIC, 5, struct cxlfork_checkpoint)
#define CXLFORK_FORK_RESUME _IOWR(CXLFORK_IOC_MAGIC, 6, struct cxlfork_restore)

#endif /* _CXLFORK_SAMPLE_UAPI_H */
