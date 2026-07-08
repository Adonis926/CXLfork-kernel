/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CXLFORK_INTERNAL_H
#define _CXLFORK_INTERNAL_H

#include <linux/types.h>
#include "../../include/uapi/linux/cxlfork.h"

#define CXLFORK_NAME "cxlfork"
#define CXLFORK_DESC_MAGIC 0x43584c464f524b31ULL /* "CXLFORK1" */
#define CXLFORK_DESC_VERSION 1
#define CXLFORK_DATA_OFFSET SZ_2M
#define CXLFORK_MAX_SLOTS 16
#define CXLFORK_SLOT_BYTES SZ_128M
#define CXLFORK_MAX_REGIONS 64
#define CXLFORK_MAX_PTES 32768
#define CXLFORK_MAX_PRIVATE_PTRS 12
#define CXLFORK_MAX_PT_PAGE_IMAGES 1024
#define CXLFORK_PT_TREE_MAGIC 0x43584c5054545245ULL /* "CXLPTTRE" */
#define CXLFORK_VMA_TREE_MAGIC 0x43584c564d415452ULL /* "CXLVMATR" */

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
	u64 va;
	u64 cxl_offset;
	u64 orig_pteval;
	u64 cxl_pteval;
};

struct cxlfork_leaf_pte_image {
	u64 va;
	u64 cxl_offset;
	u64 orig_pteval;
	u64 cxl_pteval;
};

struct cxlfork_pt_page_image {
	u64 va_base;
	u64 pte_index_base;
	u64 nr_ptes;
	u64 pte_page_offset;
};


struct cxlfork_vma_node_image {
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
	u64 magic;
	u64 version;
	u64 key;
	u64 root_offset;
	u64 nodes_offset;
	u64 nr_nodes;
	u64 region_table_offset;
};

struct cxlfork_pt_tree_image {
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
	u64 id;
	u64 cxl_offset;
	u64 cxl_phys;
	u64 bytes;
	u64 entries;
};

struct cxlfork_private_rebase_image {
	u64 magic;
	u64 version;
	u64 key;
	u64 self_offset;
	u64 state_image_offset;
	u64 nr_ptrs;
	struct cxlfork_private_ptr ptrs[CXLFORK_MAX_PRIVATE_PTRS];
};

struct cxlfork_desc {
	u64 magic;
	u64 version;
	u64 key;
	u64 ready;
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
	u64 global_detach_ns;
	u64 global_attach_ns;
	struct cxlfork_task_state task_state;
	struct cxlfork_mm_state mm_state;
	struct cxlfork_thread_state thread_state;
	struct cxlfork_global_state global_state;
	struct cxlfork_fd_state fds[CXLFORK_MAX_FDS];
	struct cxlfork_region_desc regions[CXLFORK_MAX_REGIONS];
	struct cxlfork_pte_desc ptes[CXLFORK_MAX_PTES];
};

#endif /* _CXLFORK_INTERNAL_H */
