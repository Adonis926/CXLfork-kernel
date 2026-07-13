/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CXLFORK_INTERNAL_H
#define _CXLFORK_INTERNAL_H

#include <linux/types.h>
#include "../../include/uapi/linux/cxlfork.h"

/*
 * CXLfork 内核内部格式说明：
 * - 每个 key 映射到共享 CXL window 中的一个 slot。
 * - slot 头部是 cxlfork_desc，后面顺序放置状态镜像、VMA/PTE 镜像和页面数据。
 * - 这些结构会被 VM0 checkpoint 写入，再由 VM1 restore 读取，因此字段布局要保持稳定。
 */
#define CXLFORK_NAME "cxlfork"
#define CXLFORK_DESC_MAGIC 0x43584c464f524b31ULL /* "CXLFORK1" */
#define CXLFORK_DESC_VERSION 1
#define CXLFORK_DATA_OFFSET SZ_2M          /* CXL window 前 2MB 预留，slot 从这里开始。 */
#define CXLFORK_LITMUS_OFFSET PAGE_SIZE    /* 预留区内的独立跨 VM memory-order test page。 */
#define CXLFORK_LITMUS_MAGIC 0x43584c4c49544d32ULL /* "CXLLITM2" */
#define CXLFORK_MAX_SLOTS 7                /* key%MAX_SLOTS 选择 slot，4G CXL window 下保留 7 个大 slot。 */
#define CXLFORK_SLOT_BYTES SZ_512M         /* 单个 checkpoint slot 的最大容量。 */
#define CXLFORK_EXTENT_SHIFT PAGE_SHIFT    /* Phase 12: slot 内 4KiB extent bitmap。 */
#define CXLFORK_EXTENT_BYTES (1UL << CXLFORK_EXTENT_SHIFT)
#define CXLFORK_EXTENTS_PER_SLOT (CXLFORK_SLOT_BYTES >> CXLFORK_EXTENT_SHIFT)
#define CXLFORK_EXTENT_BITMAP_WORDS (CXLFORK_EXTENTS_PER_SLOT / 64)
#define CXLFORK_MAX_REGIONS 64             /* legacy ioctl 当前最多回填的 VMA/region 数。 */
#define CXLFORK_MAX_PTES 131072            /* 一次 checkpoint 最多记录的叶子 PTE 数。 */
#define CXLFORK_MAX_PRIVATE_PTRS 12        /* rebase image 中可跟踪的内部指针数量。 */
#define CXLFORK_MAX_PT_PAGE_IMAGES 4096    /* 页表页镜像上限，用于直接 PTE attach 实验。 */
#define CXLFORK_PT_TREE_MAGIC 0x43584c5054545245ULL /* "CXLPTTRE" */
#define CXLFORK_VMA_TREE_MAGIC 0x43584c564d415452ULL /* "CXLVMATR" */

/* private_rebase_image 中的指针类型编号，restore 时用来定位 CXL 内部对象。 */
#define CXLFORK_PTR_STATE_IMAGE 1
#define CXLFORK_PTR_LEAF_PTE_IMAGE 2
#define CXLFORK_PTR_PAGE_DATA 3
#define CXLFORK_PTR_REGION_TABLE 4
#define CXLFORK_PTR_PTE_TABLE 5
#define CXLFORK_PTR_PT_PAGE_IMAGE 6
#define CXLFORK_PTR_PT_TREE_IMAGE 7
#define CXLFORK_PTR_REBASE_IMAGE 8
#define CXLFORK_PTR_VMA_TREE_IMAGE 9

struct cxlfork_region_desc {
	/* checkpointed VMA 的范围、权限和页分类统计。 */
	u64 start;
	u64 length;
	u64 prot;
	u64 flags;
	u64 pgoff_first;
	u64 pages;
	u64 anon_pages;
	u64 clean_file_pages;
	u64 dirty_file_pages;
};

struct cxlfork_pte_desc {
	/* 单个用户页的 VA、CXL 页面副本偏移，以及原始/CXL PTE 值。 */
	u64 va;
	u64 cxl_offset;
	u64 orig_pteval;
	u64 cxl_pteval;
};

struct cxlfork_leaf_pte_image {
	/* 扁平叶子 PTE 镜像，供 restore 端验证和 attach。 */
	u64 va;
	u64 cxl_offset;
	u64 orig_pteval;
	u64 cxl_pteval;
};

struct cxlfork_pt_page_image {
	/* 重建页表页的 CXL 镜像描述，用于衡量 direct PTE install 路径。 */
	u64 va_base;
	u64 pte_index_base;
	u64 nr_ptes;
	u64 pte_page_offset;
};


struct cxlfork_vma_node_image {
	/* 将 VMA 列表组织成可在 CXL 上遍历的二叉树节点。 */
	u64 start;
	u64 end;
	u64 prot;
	u64 flags;
	u64 pgoff_first;
	u64 pages;
	u64 anon_pages;
	u64 clean_file_pages;
	u64 dirty_file_pages;
	u64 region_index;
	u64 left_offset;
	u64 right_offset;
	u64 parent_offset;
};

struct cxlfork_vma_tree_image {
	/* VMA tree 的根对象，保存节点数组和 region table 的偏移。 */
	u64 magic;
	u64 version;
	u64 key;
	u64 root_offset;
	u64 nodes_offset;
	u64 nr_nodes;
	u64 region_table_offset;
};

struct cxlfork_pt_tree_image {
	/* 页表树根对象，保存 leaf PTE image、页表页镜像和原始 PTE table 的位置。 */
	u64 magic;
	u64 version;
	u64 key;
	u64 root_offset;
	u64 leaf_pte_image_offset;
	u64 pt_page_image_offset;
	u64 pte_table_offset;
	u64 nr_pages;
	u64 nr_leaf_ptes;
};

struct cxlfork_state_image {
	/* CXL 上的完整进程状态镜像；字段 offset 都是相对 CXL window 的偏移。 */
	u64 magic;
	u64 version;
	u64 key;
	u64 nr_regions;
	u64 nr_ptes;
	u64 total_pages;
	u64 anon_pages;
	u64 clean_file_pages;
	u64 dirty_file_pages;
	u64 nr_fds;
	u64 self_offset;
	u64 task_state_offset;
	u64 mm_state_offset;
	u64 thread_state_offset;
	u64 global_state_offset;
	u64 fd_table_offset;
	u64 region_table_offset;
	u64 vma_tree_image_offset;
	u64 vma_tree_root_offset;
	u64 pte_table_offset;
	u64 leaf_pte_image_offset;
	u64 pt_page_image_offset;
	u64 pt_tree_image_offset;
	u64 pt_tree_root_offset;
	u64 page_data_offset;
	u64 private_rebase_offset;
	struct cxlfork_task_state task_state;
	struct cxlfork_mm_state mm_state;
	struct cxlfork_thread_state thread_state;
	struct cxlfork_global_state global_state;
	struct cxlfork_fd_state fds[CXLFORK_MAX_FDS];
	struct cxlfork_region_desc regions[CXLFORK_MAX_REGIONS];
};

struct cxlfork_private_ptr {
	/* 一个需要在远端解释/重定位的内部对象指针。 */
	u64 id;
	u64 cxl_offset;
	u64 cxl_phys;
	u64 bytes;
	u64 entries;
};

struct cxlfork_private_rebase_image {
	/* 把 kernel 私有对象转换成 CXL offset/phys，模拟跨 OS restore 的 rebase 成本。 */
	u64 magic;
	u64 version;
	u64 key;
	u64 self_offset;
	u64 state_image_offset;
	u64 nr_ptrs;
	struct cxlfork_private_ptr ptrs[CXLFORK_MAX_PRIVATE_PTRS];
};

struct cxlfork_desc {
	/* 每个 slot 的主描述符；既是索引入口，也是 benchmark breakdown 的来源。 */
	u64 magic;
	u64 version;
	u64 key;
	u64 ready;
	u64 state;
	u64 generation;
	u64 reader_count;
	u64 slot;
	u64 nr_regions;
	u64 nr_ptes;
	u64 total_pages;
	u64 anon_pages;
	u64 clean_file_pages;
	u64 dirty_file_pages;
	u64 data_offset;
	u64 create_ns;
	u64 faults;
	u64 image_bytes;
	u64 page_checksum;
	u64 leaf_checksum;
	u64 shared_map_pages;
	u64 local_copy_pages;
	u64 leaf_copy_pages;
	u64 nr_fds;
	u64 global_checkpoint_ns;
	u64 pte_image_offset;
	u64 pte_image_entries;
	u64 pte_image_pages;
	u64 pte_image_build_ns;
	u64 pt_page_image_offset;
	u64 pt_page_image_entries;
	u64 pt_page_image_pages;
	u64 pt_page_image_build_ns;
	u64 pt_page_image_validate_ns;
	u64 pt_tree_image_offset;
	u64 pt_tree_root_offset;
	u64 pt_tree_pages;
	u64 pt_tree_entries;
	u64 direct_pte_install_ns;
	u64 direct_pte_install_pages;
	u64 state_image_offset;
	u64 state_image_pages;
	u64 state_image_build_ns;
	u64 private_rebase_offset;
	u64 private_rebase_entries;
	u64 private_rebase_pages;
	u64 private_rebase_ns;
	u64 private_rebase_validate_ns;
	u64 vma_tree_image_offset;
	u64 vma_tree_root_offset;
	u64 vma_tree_nodes;
	u64 vma_tree_pages;
	u64 vma_tree_build_ns;
	u64 vma_tree_validate_ns;
	u64 vma_maple_attach_ns;
	u64 vma_maple_nodes;
	u64 vma_maple_root_offset;
	u64 global_detach_ns;
	u64 global_attach_ns;
	u64 fd_table_offset;
	u64 fd_table_entries;
	u64 fd_table_bytes;
	u64 region_table_offset;
	u64 region_table_entries;
	u64 region_table_bytes;
	u64 pte_table_offset;
	u64 pte_table_entries;
	u64 pte_table_bytes;
	u64 extent_bytes;
	u64 extent_count;
	u64 extent_bitmap_words;
	u64 allocated_extents;
	u64 extent_bitmap[CXLFORK_EXTENT_BITMAP_WORDS];
	struct cxlfork_task_state task_state;
	struct cxlfork_mm_state mm_state;
	struct cxlfork_thread_state thread_state;
	struct cxlfork_global_state global_state;
};

#endif /* _CXLFORK_INTERNAL_H */
