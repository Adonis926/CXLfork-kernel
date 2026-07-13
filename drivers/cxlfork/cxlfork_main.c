// SPDX-License-Identifier: GPL-2.0
#include <linux/cdev.h>
#include <linux/cgroup.h>
#include <linux/cxlfork_mm.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/maple_tree.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/pid_namespace.h>
#include <linux/pfn_t.h>
#include <linux/personality.h>
#include <linux/refcount.h>
#include <linux/resource.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <asm/fsgsbase.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <net/net_namespace.h>

#include "cxlfork.h"

/*
 * CXLfork 内核原型：
 * - 通过启动参数 cxlfork.cxl_phys/cxlfork.cxl_size 映射共享 CXL/NVDIMM 物理窗口。
 * - VM0 执行 prepare，把进程页面和 OS metadata 写入 CXL slot。
 * - VM1 执行 resume，从相同 slot 恢复 VMA/PTE/状态并运行 workload。
 */
#define CXLFORK_REGION_PGOFF_STEP (CXLFORK_SLOT_BYTES >> PAGE_SHIFT)
#define CXLFORK_VMA_MAPLE_SCRATCH_BYTES SZ_2M
#define CXLFORK_MAPLE_ROOT_NODE 0x02UL
#define CXLFORK_MAPLE_ENODE_NULL 0x04UL
#define CXLFORK_MAPLE_ENODE_TYPE_SHIFT 0x03UL
#define CXLFORK_MA_ROOT_PARENT 1UL
#define CXLFORK_MAPLE_PARENT_RANGE64 0x06UL
#define CXLFORK_MAPLE_PARENT_SLOT_SHIFT 3

/* 共享 CXL window 的物理参数，必须和 QEMU kernel cmdline 中的参数一致。 */
static phys_addr_t cxl_phys = 0x484000000ULL;
module_param(cxl_phys, ullong, 0444);
MODULE_PARM_DESC(cxl_phys, "base physical address of shared CXL memory");

static ulong cxl_size = 0xfb000000UL;
module_param(cxl_size, ulong, 0444);
MODULE_PARM_DESC(cxl_size, "size of shared CXL memory");

static dev_t cxlfork_devt;
static struct class *cxlfork_class;
static struct cdev cxlfork_cdev;
static void __iomem *cxlfork_cxl;
static DEFINE_MUTEX(cxlfork_lock);

static int key_to_slot(u64 key);
static struct cxlfork_desc *slot_desc(u64 slot);
static bool cxlfork_slot_has_room(u64 slot, u64 off, u64 bytes);
static const struct file_operations cxlfork_fops;
static const struct vm_operations_struct cxlfork_vm_ops;
static int cxlfork_find_shared_leaf_pfn(const struct cxlfork_desc *desc,
					unsigned long addr,
					unsigned long *pfn_out);

struct cxlfork_file_state {
	/* 每个打开的 /dev/cxlfork fd 保存一次 mmap/restore 的临时上下文。 */
	u64 mmap_key;
	u64 mmap_generation;
	u64 mmap_flags;
	u64 tiering_hot_stride_pages;
	u64 pte_image_validate_ns;
	u64 state_image_validate_ns;
	u64 direct_pte_install_ns;
	u64 direct_pte_install_pages;
	u64 dirty_prefault_ns;
	u64 dirty_prefault_pages;
};

struct cxlfork_restore_breakdown {
	/* 单次 restore 调用的 breakdown；不得写入共享 desc 作为累计值。 */
	u64 global_restore_ns;
	u64 pte_image_reconstruct_ns;
	u64 pte_image_reconstruct_pages;
	u64 shared_leaf_attach_ns;
	u64 shared_leaf_attach_pages;
	u64 direct_pte_install_ns;
	u64 direct_pte_install_pages;
	u64 pte_image_validate_ns;
	u64 pt_page_image_validate_ns;
	u64 vma_tree_validate_ns;
	u64 state_image_validate_ns;
	u64 private_rebase_validate_ns;
	u64 dirty_prefault_ns;
	u64 dirty_prefault_pages;
};

struct cxlfork_mapping {
	/* 绑定到用户 VMA 的状态，fault handler 用它定位 key、region 和 tiering policy。 */
	u64 key;
	u64 generation;
	u64 region_idx;
	u64 flags;
	u64 tiering_hot_stride_pages;
	bool holds_slot_reader;
	refcount_t refs;
};

static bool cxlfork_desc_key_ready(const struct cxlfork_desc *desc, u64 key)
{
	return desc && READ_ONCE(desc->magic) == CXLFORK_DESC_MAGIC &&
		READ_ONCE(desc->version) == CXLFORK_DESC_VERSION &&
		READ_ONCE(desc->key) == key &&
		READ_ONCE(desc->state) == CXLFORK_SLOT_READY &&
		READ_ONCE(desc->ready);
}

static bool cxlfork_desc_generation_matches(const struct cxlfork_desc *desc,
					    u64 generation)
{
	return READ_ONCE(desc->generation) == generation;
}

static int cxlfork_slot_get_reader_locked(struct cxlfork_desc *desc, u64 key,
					  u64 generation)
{
	u64 readers;

	if (!cxlfork_desc_key_ready(desc, key) ||
	    !cxlfork_desc_generation_matches(desc, generation))
		return -ENOENT;
	do {
		readers = READ_ONCE(desc->reader_count);
	} while (cmpxchg(&desc->reader_count, readers, readers + 1) != readers);
	return 0;
}

static void cxlfork_slot_put_reader_locked(struct cxlfork_desc *desc, u64 key,
					   u64 generation)
{
	u64 readers;

	if (!cxlfork_desc_key_ready(desc, key) ||
	    !cxlfork_desc_generation_matches(desc, generation))
		return;
	do {
		readers = READ_ONCE(desc->reader_count);
		if (!readers)
			return;
	} while (cmpxchg(&desc->reader_count, readers, readers - 1) != readers);
}

static void cxlfork_slot_put_reader(u64 key, u64 generation)
{
	struct cxlfork_desc *desc;
	int slot;

	slot = key_to_slot(key);
	if (slot < 0)
		return;
	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	cxlfork_slot_put_reader_locked(desc, key, generation);
	mutex_unlock(&cxlfork_lock);
}

static int cxlfork_slot_get_reader(u64 key, u64 generation)
{
	struct cxlfork_desc *desc;
	int slot;
	int ret;

	slot = key_to_slot(key);
	if (slot < 0)
		return slot;
	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	ret = cxlfork_slot_get_reader_locked(desc, key, generation);
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static void *cxl_ptr(u64 off)
{
	/* CXL 内部对象统一保存 offset，访问时再转换为内核虚拟地址。 */
	if (off >= cxl_size)
		return NULL;
	return (void __force *)((char __iomem *)cxlfork_cxl + off);
}

static bool cxl_range_valid(u64 off, u64 bytes)
{
	if (!bytes || off >= cxl_size || bytes > cxl_size - off)
		return false;
	return cxl_ptr(off) && cxl_ptr(off + bytes - 1);
}

static struct cxlfork_fd_state *cxlfork_desc_fds(const struct cxlfork_desc *desc)
{
	if (!desc || !desc->fd_table_offset || !desc->fd_table_bytes ||
	    !cxl_range_valid(desc->fd_table_offset, desc->fd_table_bytes))
		return NULL;
	return cxl_ptr(desc->fd_table_offset);
}

static struct cxlfork_region_desc *
cxlfork_desc_regions(const struct cxlfork_desc *desc)
{
	if (!desc || !desc->region_table_offset || !desc->region_table_bytes ||
	    !cxl_range_valid(desc->region_table_offset,
			     desc->region_table_bytes))
		return NULL;
	return cxl_ptr(desc->region_table_offset);
}

static struct cxlfork_pte_desc *cxlfork_desc_ptes(const struct cxlfork_desc *desc)
{
	if (!desc || !desc->pte_table_offset || !desc->pte_table_bytes ||
	    !cxl_range_valid(desc->pte_table_offset, desc->pte_table_bytes))
		return NULL;
	return cxl_ptr(desc->pte_table_offset);
}

static int cxlfork_alloc_table(u64 slot, u64 *data_off, u64 entries,
			       u64 elem_size, u64 *offset, u64 *bytes)
{
	u64 table_bytes;
	void *table;

	if (check_mul_overflow(entries, elem_size, &table_bytes))
		return -ENOSPC;
	table_bytes = PAGE_ALIGN(table_bytes);
	if (!table_bytes)
		return -EINVAL;
	if (!cxlfork_slot_has_room(slot, *data_off, table_bytes))
		return -ENOSPC;
	table = cxl_ptr(*data_off);
	if (!table)
		return -ENOSPC;
	memset(table, 0, table_bytes);
	*offset = *data_off;
	*bytes = table_bytes;
	*data_off += table_bytes;
	return 0;
}

static enum maple_type cxlfork_mte_type(const void *entry)
{
	return ((unsigned long)entry >> CXLFORK_MAPLE_ENODE_TYPE_SHIFT) &
		MAPLE_NODE_TYPE_MASK;
}

static struct maple_node *cxlfork_mte_node(const void *entry)
{
	return (struct maple_node *)((unsigned long)entry & ~MAPLE_NODE_MASK);
}

static void *cxlfork_mt_mk_node(const struct maple_node *node,
				enum maple_type type)
{
	return (void *)((unsigned long)node |
			((unsigned long)type << CXLFORK_MAPLE_ENODE_TYPE_SHIFT) |
			CXLFORK_MAPLE_ENODE_NULL);
}

static void *cxlfork_mte_mk_root(const void *node)
{
	return (void *)((unsigned long)node | CXLFORK_MAPLE_ROOT_NODE);
}

static bool cxlfork_mte_is_node(const void *entry)
{
	return entry && cxlfork_mte_type(entry) != maple_dense;
}

static void __rcu **cxlfork_ma_slots(struct maple_node *node, enum maple_type type)
{
	switch (type) {
	case maple_arange_64:
		return node->ma64.slot;
	case maple_range_64:
	case maple_leaf_64:
		return node->mr64.slot;
	default:
		return NULL;
	}
}

static unsigned int cxlfork_ma_slot_count(enum maple_type type)
{
	switch (type) {
	case maple_arange_64:
		return MAPLE_ARANGE64_SLOTS;
	case maple_range_64:
	case maple_leaf_64:
		return MAPLE_RANGE64_SLOTS;
	default:
		return 0;
	}
}

static void cxlfork_maple_set_root_parent(struct maple_tree *mt,
					  struct maple_node *node)
{
	node->parent = (struct maple_pnode *)((unsigned long)mt |
					     CXLFORK_MA_ROOT_PARENT);
}

static void cxlfork_maple_set_parent(struct maple_node *child,
				     const struct maple_node *parent,
				     unsigned int slot)
{
	unsigned long val = (unsigned long)parent;

	val &= ~MAPLE_NODE_MASK;
	val |= (slot << CXLFORK_MAPLE_PARENT_SLOT_SHIFT) |
		CXLFORK_MAPLE_PARENT_RANGE64;
	child->parent = (struct maple_pnode *)val;
}

struct cxlfork_maple_copy_ctx {
	u64 next;
	u64 end;
	u64 nodes;
};

static int cxlfork_copy_maple_node_to_cxl(struct cxlfork_maple_copy_ctx *ctx,
					  void *old_entry, void **new_entry,
					  struct maple_node *new_parent,
					  unsigned int parent_slot)
{
	struct maple_node *old_node = cxlfork_mte_node(old_entry);
	struct maple_node *new_node;
	enum maple_type type = cxlfork_mte_type(old_entry);
	void __rcu **slots;
	unsigned int i;
	u64 node_off;

	if (type != maple_leaf_64 && type != maple_range_64 &&
	    type != maple_arange_64)
		return -EOPNOTSUPP;
	if (ctx->next + sizeof(*new_node) > ctx->end)
		return -ENOSPC;
	node_off = ALIGN(ctx->next, MAPLE_NODE_MASK + 1);
	if (node_off + sizeof(*new_node) > ctx->end)
		return -ENOSPC;
	new_node = cxl_ptr(node_off);
	if (!new_node)
		return -ENOSPC;
	memcpy(new_node, old_node, sizeof(*new_node));
	ctx->next = node_off + sizeof(*new_node);
	ctx->nodes++;

	*new_entry = cxlfork_mt_mk_node(new_node, type);
	if (new_parent)
		cxlfork_maple_set_parent(new_node, new_parent, parent_slot);

	if (type == maple_leaf_64)
		return 0;

	slots = cxlfork_ma_slots(new_node, type);
	for (i = 0; i < cxlfork_ma_slot_count(type); i++) {
		void *child = rcu_dereference_protected(slots[i], true);
		void *new_child;
		int ret;

		if (!cxlfork_mte_is_node(child))
			continue;
		ret = cxlfork_copy_maple_node_to_cxl(ctx, child, &new_child,
						     new_node, i);
		if (ret)
			return ret;
		rcu_assign_pointer(slots[i], new_child);
	}
	return 0;
}

static bool cxlfork_phys_in_window(phys_addr_t phys)
{
	return phys >= cxl_phys && phys < cxl_phys + cxl_size;
}

bool cxlfork_pmd_is_shared_leaf(pmd_t pmd)
{
	phys_addr_t phys;

	if (!pmd_present(pmd) || pmd_leaf(pmd))
		return false;
	phys = (phys_addr_t)pmd_pfn(pmd) << PAGE_SHIFT;
	return cxlfork_phys_in_window(phys);
}

void cxlfork_zap_shared_leaf_pmd(struct mm_struct *mm, pmd_t *pmd,
				 unsigned long addr)
{
	unsigned long start = addr & PMD_MASK;

	pmd_clear(pmd);
	flush_tlb_mm_range(mm, start, start + PMD_SIZE, PAGE_SHIFT, true);
}

int cxlfork_materialize_shared_leaf_pmd(struct mm_struct *mm, pmd_t *pmd,
					unsigned long addr)
{
	unsigned long start = addr & PMD_MASK;
	pgtable_t new;
	spinlock_t *ptl;
	pmd_t old;
	phys_addr_t leaf_phys;
	void *src;
	void *dst;
	int ret = 0;

	old = READ_ONCE(*pmd);
	if (!cxlfork_pmd_is_shared_leaf(old))
		return 0;

	leaf_phys = (phys_addr_t)pmd_pfn(old) << PAGE_SHIFT;
	src = cxl_ptr(leaf_phys - cxl_phys);
	if (!src)
		return -EFAULT;

	new = pte_alloc_one(mm);
	if (!new)
		return -ENOMEM;
	dst = kmap_local_page(new);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_local(dst);

	ptl = pmd_lock(mm, pmd);
	if (!pmd_same(old, *pmd)) {
		if (!cxlfork_pmd_is_shared_leaf(*pmd))
			goto out_unlock;
		old = *pmd;
		leaf_phys = (phys_addr_t)pmd_pfn(old) << PAGE_SHIFT;
		src = cxl_ptr(leaf_phys - cxl_phys);
		if (!src) {
			ret = -EFAULT;
			goto out_unlock;
		}
		dst = kmap_local_page(new);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_local(dst);
	}
	pmd_clear(pmd);
	smp_wmb();
	pmd_populate(mm, pmd, new);
	new = NULL;
	flush_tlb_mm_range(mm, start, start + PMD_SIZE, PAGE_SHIFT, true);

out_unlock:
	spin_unlock(ptl);
	if (new)
		pte_free(mm, new);
	return ret;
}

static u64 slot_offset(u64 slot)
{
	return CXLFORK_DATA_OFFSET + slot * CXLFORK_SLOT_BYTES;
}

static u64 slot_payload_offset(u64 slot)
{
	return slot_offset(slot) + PAGE_ALIGN(sizeof(struct cxlfork_desc));
}

static struct cxlfork_desc *slot_desc(u64 slot)
{
	return cxl_ptr(slot_offset(slot));
}

static int key_to_slot(u64 key)
{
	/* 当前原型用 key 取模选择 slot，实验脚本需避免活跃 key 复用。 */
	u64 slot = key % CXLFORK_MAX_SLOTS;
	u64 off = slot_offset(slot);

	if (off + CXLFORK_SLOT_BYTES > cxl_size)
		return -ENOSPC;
	return slot;
}

#define CXLFORK_CHECKSUM_SEED 1469598103934665603ULL
#define CXLFORK_CHECKSUM_PRIME 1099511628211ULL

static bool cxlfork_slot_range_valid(const struct cxlfork_desc *desc,
				     u64 off, u64 bytes)
{
	u64 start;
	u64 end;

	if (!desc || desc->slot >= CXLFORK_MAX_SLOTS || !bytes)
		return false;
	start = slot_offset(desc->slot);
	end = start + CXLFORK_SLOT_BYTES;
	if (off < start || off >= end || bytes > end - off)
		return false;
	return cxl_range_valid(off, bytes);
}

static bool cxlfork_desc_matches_slot(const struct cxlfork_desc *desc,
				      u64 slot)
{
	if (!desc || slot >= CXLFORK_MAX_SLOTS)
		return false;
	if (READ_ONCE(desc->magic) == CXLFORK_DESC_MAGIC &&
	    READ_ONCE(desc->version) == CXLFORK_DESC_VERSION &&
	    READ_ONCE(desc->slot) == slot &&
	    READ_ONCE(desc->data_offset) >= slot_payload_offset(slot) &&
	    READ_ONCE(desc->data_offset) < slot_offset(slot) + CXLFORK_SLOT_BYTES &&
	    IS_ALIGNED(READ_ONCE(desc->data_offset), PAGE_SIZE))
		return true;
	return false;
}

static bool cxlfork_slot_has_room(u64 slot, u64 off, u64 bytes)
{
	u64 start;
	u64 end;

	if (slot >= CXLFORK_MAX_SLOTS || !bytes)
		return false;
	start = slot_offset(slot);
	end = start + CXLFORK_SLOT_BYTES;
	if (off < start || off >= end || bytes > end - off)
		return false;
	return cxl_range_valid(off, bytes);
}

static u64 cxlfork_checksum_bytes(u64 checksum, const void *data, u64 bytes)
{
	const u8 *p = data;
	u64 i;

	for (i = 0; i < bytes; i++) {
		checksum ^= READ_ONCE(p[i]);
		checksum *= CXLFORK_CHECKSUM_PRIME;
	}
	return checksum;
}

static int cxlfork_compute_checksums(const struct cxlfork_desc *desc,
				     u64 *page_checksum,
				     u64 *leaf_checksum)
{
	struct cxlfork_pte_desc *ptes = cxlfork_desc_ptes(desc);
	u64 page_hash = CXLFORK_CHECKSUM_SEED;
	u64 leaf_hash = CXLFORK_CHECKSUM_SEED;
	u64 leaf_bytes;
	u64 i;

	if (!desc || desc->slot >= CXLFORK_MAX_SLOTS ||
	    desc->nr_regions > CXLFORK_MAX_REGIONS ||
	    desc->nr_ptes > CXLFORK_MAX_PTES ||
	    desc->total_pages != desc->nr_ptes)
		return -EILSEQ;
	if (desc->nr_ptes && !ptes)
		return -EILSEQ;

	for (i = 0; i < desc->nr_ptes; i++) {
		const struct cxlfork_pte_desc *pte = &ptes[i];
		void *page;

		if (!IS_ALIGNED(pte->va, PAGE_SIZE) ||
		    !IS_ALIGNED(pte->cxl_offset, PAGE_SIZE) ||
		    !cxlfork_slot_range_valid(desc, pte->cxl_offset, PAGE_SIZE))
			return -EILSEQ;
		page = cxl_ptr(pte->cxl_offset);
		if (!page)
			return -EILSEQ;
		page_hash = cxlfork_checksum_bytes(page_hash, page, PAGE_SIZE);
	}

	if (desc->nr_ptes) {
		if (desc->pte_image_entries != desc->nr_ptes)
			return -EILSEQ;
		if (check_mul_overflow(desc->pte_image_entries,
				       (u64)sizeof(struct cxlfork_leaf_pte_image),
				       &leaf_bytes) ||
		    !cxlfork_slot_range_valid(desc, desc->pte_image_offset,
					      leaf_bytes))
			return -EILSEQ;
		leaf_hash = cxlfork_checksum_bytes(leaf_hash,
					     cxl_ptr(desc->pte_image_offset),
					     leaf_bytes);
	}

	*page_checksum = desc->nr_ptes ? page_hash : 0;
	*leaf_checksum = desc->nr_ptes ? leaf_hash : 0;
	return 0;
}

static pgprot_t prot_from_uapi(u64 prot, bool readonly)
{
	/* 把 checkpoint 记录的 PROT_* 转换成 restore/mmap 使用的 pgprot。 */
	pgprot_t pgprot = PAGE_READONLY;

	if (prot & PROT_EXEC)
		pgprot = PAGE_READONLY_EXEC;
	if ((prot & PROT_WRITE) && !readonly)
		pgprot = PAGE_SHARED;

	return pgprot;
}

static u64 prot_from_vma(struct vm_area_struct *vma)
{
	u64 prot = 0;

	if (vma->vm_flags & VM_READ)
		prot |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		prot |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		prot |= PROT_EXEC;
	return prot;
}

static u64 cxlfork_cap_to_u64(kernel_cap_t cap)
{
	return cap.val;
}

static void cxlfork_capture_task_state(struct cxlfork_task_state *st,
				       bool full_private_state)
{
	/* 采集 task_struct/cred/capability 摘要，模拟跨 OS task metadata 迁移。 */
	struct cxlfork_task_state tmp;
	const struct cred *cred;

	memset(&tmp, 0, sizeof(tmp));
	tmp.pid = task_pid_nr(current);
	tmp.tgid = task_tgid_nr(current);
	tmp.ppid = task_ppid_nr(current);
	tmp.flags = current->flags;
	tmp.personality = current->personality;
	tmp.exit_signal = current->exit_signal;
	tmp.policy = current->policy;
	tmp.prio = current->prio;
	tmp.static_prio = current->static_prio;
	tmp.normal_prio = current->normal_prio;
	tmp.full_private_state = full_private_state;
	memcpy(tmp.comm, current->comm, sizeof(tmp.comm));

	rcu_read_lock();
	cred = __task_cred(current);
	tmp.uid = from_kuid_munged(current_user_ns(), cred->uid);
	tmp.gid = from_kgid_munged(current_user_ns(), cred->gid);
	tmp.euid = from_kuid_munged(current_user_ns(), cred->euid);
	tmp.egid = from_kgid_munged(current_user_ns(), cred->egid);
	tmp.suid = from_kuid_munged(current_user_ns(), cred->suid);
	tmp.sgid = from_kgid_munged(current_user_ns(), cred->sgid);
	tmp.fsuid = from_kuid_munged(current_user_ns(), cred->fsuid);
	tmp.fsgid = from_kgid_munged(current_user_ns(), cred->fsgid);
	tmp.cap_inheritable = cxlfork_cap_to_u64(cred->cap_inheritable);
	tmp.cap_permitted = cxlfork_cap_to_u64(cred->cap_permitted);
	tmp.cap_effective = cxlfork_cap_to_u64(cred->cap_effective);
	tmp.cap_bset = cxlfork_cap_to_u64(cred->cap_bset);
	tmp.cap_ambient = cxlfork_cap_to_u64(cred->cap_ambient);
	rcu_read_unlock();

	memcpy(st, &tmp, sizeof(tmp));
}

static u64 cxlfork_make_cxl_pteval(u64 orig_pteval, u64 cxl_offset)
{
	/* 根据原始 PTE 权限构造指向 CXL 页面副本的新 PTE。 */
	unsigned long pfn = (cxl_phys + cxl_offset) >> PAGE_SHIFT;
	pte_t orig = __pte(orig_pteval);
	pte_t cxl = pfn_pte(pfn, __pgprot(pte_flags(orig)));

	/* CXLfork redirects the leaf PTE to the CXL replica and makes it immutable.
	 * Accessed/Dirty and the remaining protection bits are inherited from the
	 * checkpointed process page table.
	*/
	cxl = pte_wrprotect(cxl);
	cxl = pte_mkspecial(cxl);
	return pte_val(cxl);
}

static int cxlfork_read_pte_snapshot(struct mm_struct *mm, unsigned long addr,
				     u64 *pteval, unsigned long *pfn)
{
	/* checkpoint 阶段读取源进程叶子 PTE，用于构建 leaf PTE image。 */
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -EFAULT;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -EFAULT;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return -EFAULT;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return -EFAULT;
	if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd))
		return -EOPNOTSUPP;
	if (cxlfork_pmd_is_shared_leaf(*pmd)) {
		phys_addr_t phys = (phys_addr_t)pmd_pfn(*pmd) << PAGE_SHIFT;
		pte_t *ptes = cxl_ptr(phys - cxl_phys);
		pte_t pte;

		if (!ptes)
			return -EFAULT;
		pte = ptes[pte_index(addr)];
		if (!pte_present(pte))
			return -EFAULT;
		*pteval = pte_val(pte);
		if (pfn)
			*pfn = pte_pfn(pte);
		return 0;
	}

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!ptep)
		return -EFAULT;
	if (!pte_present(*ptep)) {
		pte_unmap_unlock(ptep, ptl);
		return -EFAULT;
	}
	*pteval = pte_val(*ptep);
	if (pfn)
		*pfn = pte_pfn(*ptep);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}

static int cxlfork_read_orig_pteval(struct mm_struct *mm, unsigned long addr,
				    u64 *pteval)
{
	return cxlfork_read_pte_snapshot(mm, addr, pteval, NULL);
}

static int cxlfork_read_pmd_snapshot(struct mm_struct *mm, unsigned long addr,
				     u64 *pmdval, unsigned long *pfn)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -EFAULT;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -EFAULT;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return -EFAULT;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return -EFAULT;
	*pmdval = pmd_val(*pmd);
	if (pfn)
		*pfn = pmd_pfn(*pmd);
	return 0;
}


static u64 cxlfork_pt_table_entry(u64 child_offset)
{
	/* 页表树内部节点条目：指向 CXL 中的下一级页表页镜像。 */
	unsigned long pfn = (cxl_phys + child_offset) >> PAGE_SHIFT;

	return pte_val(pfn_pte(pfn, __pgprot(_PAGE_TABLE)));
}

static int cxlfork_pt_tree_alloc_page(struct cxlfork_desc *desc, u64 slot,
				      u64 *data_off, u64 *page_off,
				      bool metadata)
{
	/* 从当前 slot 的线性 data_off 分配一页，作为页表树或元数据对象。 */
	void *page;

	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!cxlfork_slot_has_room(slot, *data_off, PAGE_SIZE))
		return -ENOSPC;
	page = cxl_ptr(*data_off);
	if (!page)
		return -ENOSPC;
	memset(page, 0, PAGE_SIZE);
	*page_off = *data_off;
	*data_off += PAGE_SIZE;
	if (!metadata)
		desc->pt_tree_pages++;
	return 0;
}

static int cxlfork_pt_tree_child(struct cxlfork_desc *desc, u64 slot,
				 u64 *data_off, u64 *parent, u64 idx,
				 u64 **child)
{
	u64 child_off;

	if (idx >= PTRS_PER_PTE)
		return -EINVAL;
	if (!parent[idx]) {
		int ret = cxlfork_pt_tree_alloc_page(desc, slot, data_off,
						     &child_off, false);

		if (ret)
			return ret;
		parent[idx] = cxlfork_pt_table_entry(child_off);
	} else {
		phys_addr_t child_phys = (phys_addr_t)pte_pfn(__pte(parent[idx])) << PAGE_SHIFT;

		if (child_phys < cxl_phys || child_phys >= cxl_phys + cxl_size)
			return -EINVAL;
		child_off = child_phys - cxl_phys;
	}
	*child = cxl_ptr(child_off);
	return *child ? 0 : -EINVAL;
}

static int cxlfork_pt_tree_insert_leaf(struct cxlfork_desc *desc, u64 slot,
				       u64 *data_off, unsigned long addr,
				       u64 leaf_pte_page_offset)
{
	/* 按 VA 页表索引在 CXL 上构建最小页表树，叶子指向 PTE page image。 */
	u64 *pgd = cxl_ptr(desc->pt_tree_root_offset);
	u64 *p4d, *pud, *pmd;
	u64 pgd_idx = pgd_index(addr);
	u64 p4d_idx = p4d_index(addr);
	u64 pud_idx = pud_index(addr);
	u64 pmd_idx = pmd_index(addr);
	int ret;

	if (!pgd)
		return -EINVAL;
	ret = cxlfork_pt_tree_child(desc, slot, data_off, pgd, pgd_idx, &p4d);
	if (ret)
		return ret;
	ret = cxlfork_pt_tree_child(desc, slot, data_off, p4d, p4d_idx, &pud);
	if (ret)
		return ret;
	ret = cxlfork_pt_tree_child(desc, slot, data_off, pud, pud_idx, &pmd);
	if (ret)
		return ret;
	if (pmd[pmd_idx] &&
	    (((phys_addr_t)pte_pfn(__pte(pmd[pmd_idx])) << PAGE_SHIFT) !=
	     cxl_phys + leaf_pte_page_offset))
		return -EINVAL;
	pmd[pmd_idx] = cxlfork_pt_table_entry(leaf_pte_page_offset);
	return 0;
}

static int cxlfork_pt_tree_walk(const struct cxlfork_desc *desc,
				unsigned long addr, u64 **pte_page)
{
	/* restore/fault 路径按 VA 在 CXL 页表树里查找对应的 PTE page image。 */
	u64 *pgd = cxl_ptr(desc->pt_tree_root_offset);
	u64 *p4d, *pud, *pmd;
	u64 raw;
	phys_addr_t phys;

	if (!pgd || !desc->pt_tree_root_offset)
		return -EINVAL;
	raw = pgd[pgd_index(addr)];
	if (!raw)
		return -ENOENT;
	phys = (phys_addr_t)pte_pfn(__pte(raw)) << PAGE_SHIFT;
	p4d = cxl_ptr(phys - cxl_phys);
	if (!p4d || phys < cxl_phys || phys >= cxl_phys + cxl_size)
		return -EINVAL;
	raw = p4d[p4d_index(addr)];
	if (!raw)
		return -ENOENT;
	phys = (phys_addr_t)pte_pfn(__pte(raw)) << PAGE_SHIFT;
	pud = cxl_ptr(phys - cxl_phys);
	if (!pud || phys < cxl_phys || phys >= cxl_phys + cxl_size)
		return -EINVAL;
	raw = pud[pud_index(addr)];
	if (!raw)
		return -ENOENT;
	phys = (phys_addr_t)pte_pfn(__pte(raw)) << PAGE_SHIFT;
	pmd = cxl_ptr(phys - cxl_phys);
	if (!pmd || phys < cxl_phys || phys >= cxl_phys + cxl_size)
		return -EINVAL;
	raw = pmd[pmd_index(addr)];
	if (!raw)
		return -ENOENT;
	phys = (phys_addr_t)pte_pfn(__pte(raw)) << PAGE_SHIFT;
	if (phys < cxl_phys || phys >= cxl_phys + cxl_size)
		return -EINVAL;
	*pte_page = cxl_ptr(phys - cxl_phys);
	return *pte_page ? 0 : -EINVAL;
}

static void cxlfork_capture_mm_state(struct cxlfork_mm_state *st,
				     struct mm_struct *mm)
{
	/* 采集 mm_struct 中的地址空间边界和 auxv，restore 可选择写回。 */
	struct cxlfork_mm_state tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.start_code = mm->start_code;
	tmp.end_code = mm->end_code;
	tmp.start_data = mm->start_data;
	tmp.end_data = mm->end_data;
	tmp.start_brk = mm->start_brk;
	tmp.brk = mm->brk;
	tmp.start_stack = mm->start_stack;
	tmp.arg_start = mm->arg_start;
	tmp.arg_end = mm->arg_end;
	tmp.env_start = mm->env_start;
	tmp.env_end = mm->env_end;
	memcpy(tmp.saved_auxv, mm->saved_auxv,
	       min(sizeof(tmp.saved_auxv), sizeof(mm->saved_auxv)));
	tmp.pid = task_pid_nr(current);
	tmp.tgid = task_tgid_nr(current);
	memcpy(tmp.comm, current->comm, sizeof(tmp.comm));
	memcpy(st, &tmp, sizeof(tmp));
}

static int cxlfork_capture_fd_state(struct cxlfork_desc *desc, bool strict)
{
	/* 遍历当前进程打开的 fd，记录 path/pos/flag；这是跨 OS 重开 fd 的模拟成本来源。 */
	struct cxlfork_fd_state *desc_fds = cxlfork_desc_fds(desc);
	struct file *files[CXLFORK_MAX_FDS];
	unsigned int fds[CXLFORK_MAX_FDS];
	struct cxlfork_fd_state *out;
	struct files_struct *files_struct = current->files;
	struct fdtable *fdt;
	char *path_buf;
	u64 nr_fds = 0;
	u64 i;

	memset(files, 0, sizeof(files));

	if (!desc_fds)
		return -EILSEQ;
	if (!files_struct) {
		desc->nr_fds = 0;
		memset(desc_fds, 0, desc->fd_table_bytes);
		return 0;
	}
	out = kvcalloc(CXLFORK_MAX_FDS, sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	spin_lock(&files_struct->file_lock);
	fdt = files_fdtable(files_struct);
	for (i = 0; i < fdt->max_fds && nr_fds < CXLFORK_MAX_FDS; i++) {
		struct file *file;
		u64 idx;

		if (i < 3)
			continue;
		file = rcu_dereference_check_fdtable(files_struct, fdt->fd[i]);
		if (!file)
			continue;
		if (file->f_op == &cxlfork_fops)
			continue;
		get_file(file);
		idx = nr_fds++;
		files[idx] = file;
		fds[idx] = i;
	}
	spin_unlock(&files_struct->file_lock);

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	for (i = 0; i < nr_fds; i++) {
		struct cxlfork_fd_state *st = &out[i];
		struct file *file = files[i];
		struct inode *inode = file_inode(file);
		umode_t mode = inode ? inode->i_mode : 0;

		st->fd = fds[i];
		st->flags = file->f_flags;
		st->pos = file->f_pos;
		if (!inode || !S_ISREG(mode)) {
			if (strict) {
				while (i < nr_fds)
					fput(files[i++]);
				if (path_buf)
					free_page((unsigned long)path_buf);
				desc->nr_fds = 0;
				memset(desc_fds, 0, desc->fd_table_bytes);
				kvfree(out);
				return -EOPNOTSUPP;
			}
			fput(file);
			memset(st, 0, sizeof(*st));
			continue;
		}
		if (inode) {
			st->inode = inode->i_ino;
			st->dev = inode->i_sb ? inode->i_sb->s_dev : 0;
		}
		if (path_buf) {
			char *path = d_path(&file->f_path, path_buf, PAGE_SIZE);

			if (!IS_ERR(path))
				strscpy((char *)st->path, path, sizeof(st->path));
		}
		fput(file);
	}
	if (path_buf)
		free_page((unsigned long)path_buf);
	desc->nr_fds = nr_fds;
	memset(desc_fds, 0, desc->fd_table_bytes);
	memcpy(desc_fds, out, CXLFORK_MAX_FDS * sizeof(*out));
	kvfree(out);
	return 0;
}

static void cxlfork_path_to_state(const struct path *path, u8 *dst, size_t len)
{
	/* 把 kernel path 解析成稳定字符串，写入 CXL state image。 */
	char *path_buf;
	char *resolved;

	if (!path || !dst || !len)
		return;
	dst[0] = '\0';
	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf)
		return;
	resolved = d_path(path, path_buf, PAGE_SIZE);
	if (!IS_ERR(resolved))
		strscpy((char *)dst, resolved, len);
	free_page((unsigned long)path_buf);
}

static void cxlfork_capture_namespace_state(struct cxlfork_namespace_state *st)
{
	/* namespace 这里只记录身份和策略；net/cgroup 在当前原型中视为继承。 */
	struct cxlfork_namespace_state tmp;
	struct nsproxy *nsproxy = current->nsproxy;
	struct pid_namespace *pid_ns;

	memset(&tmp, 0, sizeof(tmp));
	tmp.flags = CXLFORK_NS_F_MOUNT_SERIALIZED |
		    CXLFORK_NS_F_PID_SERIALIZED |
		    CXLFORK_NS_F_NET_INHERITED |
		    CXLFORK_NS_F_CGROUP_INHERITED;

	if (!nsproxy) {
		memcpy(st, &tmp, sizeof(tmp));
		return;
	}
	/*
	 * mnt_namespace is opaque to modules; cwd/root paths above are the
	 * portable mount-state representation for this module build.
	 */
	tmp.mnt_ns = 0;
	pid_ns = nsproxy->pid_ns_for_children;
	if (pid_ns) {
		tmp.pid_ns = pid_ns->ns.inum;
		tmp.pid_ns_level = pid_ns->level;
	}
	if (nsproxy->net_ns)
		tmp.net_ns = nsproxy->net_ns->ns.inum;
	if (nsproxy->cgroup_ns)
		tmp.cgroup_ns = nsproxy->cgroup_ns->ns.inum;
	memcpy(st, &tmp, sizeof(tmp));
}

static void cxlfork_capture_global_state(struct cxlfork_desc *desc)
{
	/* 采集 cwd/root/umask/rlimit/signal/namespace 等进程全局状态。 */
	struct cxlfork_global_state tmp;
	struct path path;
	unsigned int i;

	memset(&tmp, 0, sizeof(tmp));
	if (current->fs) {
		spin_lock(&current->fs->lock);
		tmp.umask = current->fs->umask;
		spin_unlock(&current->fs->lock);

		get_fs_pwd(current->fs, &path);
		cxlfork_path_to_state(&path, tmp.cwd, sizeof(tmp.cwd));
		path_put(&path);

		get_fs_root(current->fs, &path);
		cxlfork_path_to_state(&path, tmp.root, sizeof(tmp.root));
		path_put(&path);
	}
	cxlfork_capture_namespace_state(&tmp.ns_state);

	tmp.nr_rlimits = min_t(unsigned int, RLIM_NLIMITS, CXLFORK_MAX_RLIMITS);
	if (current->signal) {
		task_lock(current->group_leader);
		for (i = 0; i < tmp.nr_rlimits; i++) {
			tmp.rlimits[i].rlim_cur = current->signal->rlim[i].rlim_cur;
			tmp.rlimits[i].rlim_max = current->signal->rlim[i].rlim_max;
		}
		task_unlock(current->group_leader);
	}

	tmp.sig_blocked[0] = current->blocked.sig[0];
#if _NSIG_WORDS > 1
	tmp.sig_blocked[1] = current->blocked.sig[1];
#endif
	tmp.sas_ss_sp = current->sas_ss_sp;
	tmp.sas_ss_size = current->sas_ss_size;
	tmp.sas_ss_flags = current->sas_ss_flags;
	memcpy(&desc->global_state, &tmp, sizeof(tmp));
}

static void cxlfork_capture_thread_state(struct cxlfork_thread_state *st)
{
	/* 采集 x86-64 寄存器和 FS/GS base，主要用于记录和可选 TLS 恢复。 */
	struct cxlfork_thread_state tmp;
	struct pt_regs *regs = task_pt_regs(current);

	memset(&tmp, 0, sizeof(tmp));
	if (regs) {
		tmp.ip = regs->ip;
		tmp.sp = regs->sp;
		tmp.flags = regs->flags;
		tmp.ax = regs->ax;
		tmp.bx = regs->bx;
		tmp.cx = regs->cx;
		tmp.dx = regs->dx;
		tmp.si = regs->si;
		tmp.di = regs->di;
		tmp.bp = regs->bp;
	}
	tmp.fsbase = x86_fsbase_read_cpu();
	tmp.gsbase = current->thread.gsbase;
	memcpy(st, &tmp, sizeof(tmp));
}

static int cxlfork_validate_thread_state(const struct cxlfork_thread_state *st)
{
	unsigned long sp;

	if (!st->ip || !st->sp)
		return -EINVAL;
	if (st->ip >= TASK_SIZE_MAX || st->sp >= TASK_SIZE_MAX)
		return -EFAULT;
	sp = st->sp;
	if (sp < 8)
		return -EFAULT;
	if (!access_ok((void __user *)(unsigned long)st->ip, 1) ||
	    !access_ok((void __user *)(sp - 8), 8))
		return -EFAULT;
	return 0;
}

static int cxlfork_apply_thread_state(const struct cxlfork_desc *desc)
{
	/* 恢复用户寄存器；返回后必须从保存的用户 IP/SP 继续执行。 */
	struct pt_regs *regs = task_pt_regs(current);
	const struct cxlfork_thread_state *st = &desc->thread_state;
	int ret;

	if (!regs || !st->ip || !st->sp)
		return -EINVAL;
	ret = cxlfork_validate_thread_state(st);
	if (ret)
		return ret;

	regs->ip = st->ip;
	regs->sp = st->sp;
	regs->di = st->di;
	regs->si = st->si;
	regs->dx = st->dx;
	regs->cx = st->cx;
	regs->bx = st->bx;
	regs->bp = st->bp;
	regs->ax = 0;
	return 0;
}

static void cxlfork_apply_tls_state(const struct cxlfork_desc *desc)
{
	/* 可选恢复 TLS 的 FS base，模拟线程私有状态迁移。 */
	const struct cxlfork_thread_state *st = &desc->thread_state;

	if (!st->fsbase)
		return;
	current->thread.fsindex = 0;
	current->thread.fsbase = st->fsbase;
	x86_fsbase_write_cpu(st->fsbase);
}

static void cxlfork_copy_mm_state_to_checkpoint(struct cxlfork_checkpoint *op,
						const struct cxlfork_desc *desc)
{
	/* 把 desc 内部统计回填给用户态 prepare 结构，脚本据此写 CSV。 */
	struct cxlfork_fd_state *fds = cxlfork_desc_fds(desc);

	op->task_state = desc->task_state;
	op->mm_state = desc->mm_state;
	op->thread_state = desc->thread_state;
	op->global_state = desc->global_state;
	op->nr_fds = desc->nr_fds;
	op->global_checkpoint_ns = desc->global_checkpoint_ns;
	op->pte_image_build_ns = desc->pte_image_build_ns;
	op->pte_image_pages = desc->pte_image_pages;
	op->pt_page_image_build_ns = desc->pt_page_image_build_ns;
	op->pt_page_image_pages = desc->pt_page_image_pages;
	op->pt_page_image_entries = desc->pt_page_image_entries;
	op->vma_tree_build_ns = desc->vma_tree_build_ns;
	op->vma_tree_pages = desc->vma_tree_pages;
	op->vma_tree_nodes = desc->vma_tree_nodes;
	op->state_image_build_ns = desc->state_image_build_ns;
	op->state_image_pages = desc->state_image_pages;
	op->private_rebase_ns = desc->private_rebase_ns;
	op->private_rebase_entries = desc->private_rebase_entries;
	op->private_rebase_pages = desc->private_rebase_pages;
	op->global_detach_ns = desc->global_detach_ns;
	if (fds)
		memcpy(op->fds, fds, min_t(size_t, sizeof(op->fds),
					   desc->fd_table_bytes));
}

static void cxlfork_copy_mm_state_to_restore(struct cxlfork_restore *op,
					     const struct cxlfork_desc *desc)
{
	/* 把 desc 内部统计回填给用户态 restore 结构，脚本据此写 CSV。 */
	struct cxlfork_fd_state *fds = cxlfork_desc_fds(desc);

	op->task_state = desc->task_state;
	op->mm_state = desc->mm_state;
	op->thread_state = desc->thread_state;
	op->global_state = desc->global_state;
	op->nr_fds = desc->nr_fds;
	op->pte_image_build_ns = desc->pte_image_build_ns;
	op->pte_image_pages = desc->pte_image_pages;
	op->pt_page_image_build_ns = desc->pt_page_image_build_ns;
	op->pt_page_image_pages = desc->pt_page_image_pages;
	op->pt_page_image_entries = desc->pt_page_image_entries;
	op->vma_tree_build_ns = desc->vma_tree_build_ns;
	op->vma_tree_pages = desc->vma_tree_pages;
	op->vma_tree_nodes = desc->vma_tree_nodes;
	op->state_image_build_ns = desc->state_image_build_ns;
	op->state_image_pages = desc->state_image_pages;
	op->private_rebase_ns = desc->private_rebase_ns;
	op->private_rebase_entries = desc->private_rebase_entries;
	op->private_rebase_pages = desc->private_rebase_pages;
	op->global_detach_ns = desc->global_detach_ns;
	if (fds)
		memcpy(op->fds, fds, min_t(size_t, sizeof(op->fds),
					   desc->fd_table_bytes));
}

static void cxlfork_apply_mm_state(const struct cxlfork_desc *desc)
{
	/* 根据 flags 可选写回 mm_struct 的可观测字段。 */
	struct mm_struct *mm = current->mm;
	const struct cxlfork_mm_state *st = &desc->mm_state;

	if (!mm)
		return;

	mmap_write_lock(mm);
	mm->start_code = st->start_code;
	mm->end_code = st->end_code;
	mm->start_data = st->start_data;
	mm->end_data = st->end_data;
	mm->start_brk = st->start_brk;
	mm->brk = st->brk;
	mm->start_stack = st->start_stack;
	mm->arg_start = st->arg_start;
	mm->arg_end = st->arg_end;
	mm->env_start = st->env_start;
	mm->env_end = st->env_end;
	memcpy(mm->saved_auxv, st->saved_auxv,
	       min(sizeof(mm->saved_auxv), sizeof(st->saved_auxv)));
	mmap_write_unlock(mm);

	task_lock(current);
	memcpy(current->comm, st->comm, sizeof(current->comm));
	current->comm[sizeof(current->comm) - 1] = '\0';
	task_unlock(current);
}

static void cxlfork_apply_global_fs_state(const struct cxlfork_global_state *st)
{
	/* 尝试把 cwd/root/umask 应用到当前进程，失败时保持当前环境。 */
	struct path path;

	if (!current->fs)
		return;
	if (st->root[0] == '/' &&
	    !kern_path((const char *)st->root, LOOKUP_FOLLOW, &path)) {
		struct path old_root;

		path_get(&path);
		spin_lock(&current->fs->lock);
		write_seqcount_begin(&current->fs->seq);
		old_root = current->fs->root;
		current->fs->root = path;
		write_seqcount_end(&current->fs->seq);
		spin_unlock(&current->fs->lock);
		if (old_root.dentry)
			path_put(&old_root);
		path_put(&path);
	}
	if (st->cwd[0] == '/' &&
	    !kern_path((const char *)st->cwd, LOOKUP_FOLLOW, &path)) {
		struct path old_pwd;

		path_get(&path);
		spin_lock(&current->fs->lock);
		write_seqcount_begin(&current->fs->seq);
		old_pwd = current->fs->pwd;
		current->fs->pwd = path;
		write_seqcount_end(&current->fs->seq);
		spin_unlock(&current->fs->lock);
		if (old_pwd.dentry)
			path_put(&old_pwd);
		path_put(&path);
	}
	spin_lock(&current->fs->lock);
	current->fs->umask = st->umask;
	spin_unlock(&current->fs->lock);
}

static void cxlfork_apply_global_state(const struct cxlfork_desc *desc)
{
	/* 应用 rlimit/signal/fs 等全局状态，作为 FULL_PRIVATE_STATE 的一部分。 */
	const struct cxlfork_global_state *st = &desc->global_state;
	unsigned int i;

	cxlfork_apply_global_fs_state(st);

	if (current->signal) {
		unsigned int nr = min_t(unsigned int, st->nr_rlimits, RLIM_NLIMITS);

		task_lock(current->group_leader);
		for (i = 0; i < nr; i++) {
			current->signal->rlim[i].rlim_cur = st->rlimits[i].rlim_cur;
			current->signal->rlim[i].rlim_max = st->rlimits[i].rlim_max;
		}
		task_unlock(current->group_leader);
	}

	current->blocked.sig[0] = st->sig_blocked[0];
#if _NSIG_WORDS > 1
	current->blocked.sig[1] = st->sig_blocked[1];
#endif
	recalc_sigpending();
	current->sas_ss_sp = st->sas_ss_sp;
	current->sas_ss_size = st->sas_ss_size;
	current->sas_ss_flags = st->sas_ss_flags;
}

static int cxlfork_reopen_fd_state(const struct cxlfork_desc *desc,
				   u64 *restored)
{
	/* 严格恢复普通文件 fd：原 fd number、offset、flags 和 inode/dev 必须匹配。 */
	struct cxlfork_fd_state *fds = cxlfork_desc_fds(desc);
	u64 i;

	*restored = 0;
	if (desc->nr_fds && !fds)
		return -EILSEQ;
	for (i = 0; i < desc->nr_fds; i++) {
		const struct cxlfork_fd_state *st = &fds[i];
		struct file *file;
		struct inode *inode;
		int fd;
		int flags;
		int ret;

		if (!st->path[0] || st->path[0] != '/')
			return -EILSEQ;
		if (st->fd < 3)
			return -EOPNOTSUPP;

		flags = st->flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_LARGEFILE);
		file = filp_open((const char *)st->path, flags, 0);
		if (IS_ERR(file))
			return PTR_ERR(file);
		inode = file_inode(file);
		if (!inode || !S_ISREG(inode->i_mode) ||
		    inode->i_ino != st->inode ||
		    (inode->i_sb ? inode->i_sb->s_dev : 0) != st->dev) {
			fput(file);
			return -ESTALE;
		}
		if (st->pos)
			if (vfs_llseek(file, st->pos, SEEK_SET) < 0) {
				fput(file);
				return -EINVAL;
			}

		fd = st->fd;
		ret = replace_fd(fd, file, st->flags & O_CLOEXEC);
		if (ret < 0) {
			fput(file);
			return ret;
		}
		fput(file);
		(*restored)++;
	}
	return 0;
}

static int cxlfork_checkpoint_vma_supported(struct vm_area_struct *vma,
					    const struct cxlfork_checkpoint *op)
{
	/* Phase 2 strict model: private anonymous 4 KiB VMAs only. */
	if (!(vma->vm_flags & VM_READ))
		return -EOPNOTSUPP;
	if (vma->vm_file || (vma->vm_flags & VM_SHARED))
		return -EOPNOTSUPP;
	if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_HUGETLB | VM_DONTDUMP |
			     VM_DONTCOPY | VM_MIXEDMAP | VM_UFFD_MISSING |
			     VM_UFFD_WP))
		return -EOPNOTSUPP;
	return 0;
}

static int cxlfork_preflight_checkpoint(struct mm_struct *mm,
					const struct cxlfork_checkpoint *op,
					u64 slot)
{
	struct vm_area_struct *vma;
	unsigned long scan_start = op->scan_start;
	unsigned long scan_end = op->scan_end;
	u64 regions = 0;
	u64 pages = 0;
	u64 pmd_groups = 0;
	u64 bytes;
	u64 tmp;

	VMA_ITERATOR(vmi, mm, scan_start);
	for_each_vma_range(vmi, vma, scan_end) {
		unsigned long start;
		unsigned long end;
		u64 vma_pages;

		int ret = cxlfork_checkpoint_vma_supported(vma, op);

		if (ret)
			return ret;
		start = max(vma->vm_start, scan_start);
		end = min(vma->vm_end, scan_end);
		start = PAGE_ALIGN(start);
		end &= PAGE_MASK;
		if (start >= end)
			continue;

		if (++regions > CXLFORK_MAX_REGIONS)
			return -ENOSPC;
		vma_pages = (end - start) >> PAGE_SHIFT;
		if (check_add_overflow(pages, vma_pages, &pages) ||
		    pages > CXLFORK_MAX_PTES)
			return -ENOSPC;
		pmd_groups += DIV_ROUND_UP(end - start, PMD_SIZE);
		if (pmd_groups > CXLFORK_MAX_PT_PAGE_IMAGES)
			return -ENOSPC;
	}

	bytes = slot_payload_offset(slot) - slot_offset(slot);
	if (check_add_overflow(bytes,
			       (u64)PAGE_ALIGN(CXLFORK_MAX_FDS *
			       sizeof(struct cxlfork_fd_state)), &bytes) ||
	    check_add_overflow(bytes,
			       (u64)PAGE_ALIGN(CXLFORK_MAX_REGIONS *
			       sizeof(struct cxlfork_region_desc)), &bytes) ||
	    check_add_overflow(bytes,
			       (u64)PAGE_ALIGN(CXLFORK_MAX_PTES *
			       sizeof(struct cxlfork_pte_desc)), &bytes))
		return -ENOSPC;
	if (check_mul_overflow(pages, (u64)PAGE_SIZE, &tmp) ||
	    check_add_overflow(bytes, tmp, &bytes))
		return -ENOSPC;
	if (check_mul_overflow(pages,
			       (u64)sizeof(struct cxlfork_leaf_pte_image),
			       &tmp) ||
	    check_add_overflow(bytes, PAGE_ALIGN(tmp), &bytes))
		return -ENOSPC;
	if (check_mul_overflow(pmd_groups,
			       (u64)sizeof(struct cxlfork_pt_page_image),
			       &tmp) ||
	    check_add_overflow(bytes, PAGE_ALIGN(tmp), &bytes))
		return -ENOSPC;
	if (check_add_overflow(bytes, (pmd_groups + 8) * (u64)PAGE_SIZE, &bytes))
		return -ENOSPC;
	tmp = PAGE_ALIGN(sizeof(struct cxlfork_vma_tree_image)) +
	      PAGE_ALIGN(regions * sizeof(struct cxlfork_vma_node_image));
	if (check_add_overflow(bytes, tmp, &bytes) ||
	    check_add_overflow(bytes,
			       (u64)PAGE_ALIGN(sizeof(struct cxlfork_state_image)),
			       &bytes) ||
	    check_add_overflow(bytes,
			       (u64)PAGE_ALIGN(sizeof(struct cxlfork_private_rebase_image)),
			       &bytes))
		return -ENOSPC;
	if (bytes > CXLFORK_SLOT_BYTES || bytes > cxl_size - slot_offset(slot))
		return -ENOSPC;
	return pages ? 0 : -EINVAL;
}

static int cxlfork_copy_page_to_cxl(unsigned long addr, u64 cxl_off,
				    struct vm_area_struct *vma,
				    struct cxlfork_region_desc *r,
				    struct cxlfork_desc *desc,
				    struct mm_struct *mm,
				    u64 *orig_pteval)
{
	/* Copy one page only if its PTE/PFN stays stable across the copy. */
	struct page *page = NULL;
	unsigned long pfn_before;
	unsigned long pfn_after;
	u64 pte_before;
	u64 pte_after;
	void *src;
	void *dst;
	int ret;

	ret = cxlfork_read_pte_snapshot(mm, addr, &pte_before, &pfn_before);
	if (ret)
		return ret;
	if (!pte_present(__pte(pte_before)))
		return -EFAULT;

	ret = get_user_pages_fast(addr, 1, 0, &page);
	if (ret != 1)
		return -EFAULT;
	if (!PageAnon(page) || page_maybe_dma_pinned(page)) {
		put_page(page);
		return -EOPNOTSUPP;
	}
	if (page_to_pfn(page) != pfn_before) {
		put_page(page);
		return -EBUSY;
	}

	dst = cxl_ptr(cxl_off);
	if (!dst) {
		put_page(page);
		return -ENOSPC;
	}

	src = kmap_local_page(page);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_local(src);

	ret = cxlfork_read_pte_snapshot(mm, addr, &pte_after, &pfn_after);
	if (ret) {
		put_page(page);
		return ret;
	}
	if (pte_after != pte_before || pfn_after != pfn_before ||
	    page_to_pfn(page) != pfn_after) {
		put_page(page);
		return -EBUSY;
	}

	r->anon_pages++;
	desc->anon_pages++;
	*orig_pteval = pte_before;
	put_page(page);
	return 0;
}

static int cxlfork_build_leaf_pte_image(struct cxlfork_desc *desc, u64 slot,
					u64 *data_off)
{
	/* 将 desc->ptes 扁平化到 CXL，供 restore 端验证和 fault 查找。 */
	struct cxlfork_pte_desc *ptes = cxlfork_desc_ptes(desc);
	struct cxlfork_leaf_pte_image *image;
	u64 image_bytes;
	u64 i;

	if (!desc->nr_ptes)
		return 0;
	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!ptes)
		return -EILSEQ;

	image_bytes = PAGE_ALIGN(desc->nr_ptes * sizeof(*image));
	if (!cxlfork_slot_has_room(slot, *data_off, image_bytes))
		return -ENOSPC;
	image = cxl_ptr(*data_off);
	if (!image)
		return -ENOSPC;

	memset(image, 0, image_bytes);
	for (i = 0; i < desc->nr_ptes; i++) {
		const struct cxlfork_pte_desc *pte = &ptes[i];

		image[i].va = pte->va;
		image[i].cxl_offset = pte->cxl_offset;
		image[i].orig_pteval = pte->orig_pteval;
		image[i].cxl_pteval = pte->cxl_pteval;
	}

	desc->pte_image_offset = *data_off;
	desc->pte_image_entries = desc->nr_ptes;
	desc->pte_image_pages = image_bytes >> PAGE_SHIFT;
	*data_off += image_bytes;
	return 0;
}


static u64 cxlfork_vma_node_offset(u64 nodes_offset, u64 index)
{
	return nodes_offset + index * sizeof(struct cxlfork_vma_node_image);
}

static void cxlfork_vma_tree_link(struct cxlfork_vma_node_image *nodes,
					  u64 nodes_offset, long lo, long hi,
					  long parent, u64 *root_offset)
{
	/* 把按地址排序的 VMA 数组连成平衡二叉树，方便 restore 端按 VA 校验/查找。 */
	long mid;
	struct cxlfork_vma_node_image *node;

	if (lo > hi)
		return;
	mid = lo + (hi - lo) / 2;
	node = &nodes[mid];
	if (parent >= 0) {
		struct cxlfork_vma_node_image *parent_node = &nodes[parent];
		u64 off = cxlfork_vma_node_offset(nodes_offset, mid);

		node->parent_offset = cxlfork_vma_node_offset(nodes_offset, parent);
		if (mid < parent)
			parent_node->left_offset = off;
		else
			parent_node->right_offset = off;
	} else {
		*root_offset = cxlfork_vma_node_offset(nodes_offset, mid);
	}
	cxlfork_vma_tree_link(nodes, nodes_offset, lo, mid - 1, mid, root_offset);
	cxlfork_vma_tree_link(nodes, nodes_offset, mid + 1, hi, mid, root_offset);
}

static int cxlfork_build_vma_tree_image(struct cxlfork_desc *desc, u64 slot,
					u64 *data_off)
{
	/* 在 CXL 中生成 VMA tree image，是论文中 OS metadata 序列化的一部分。 */
	struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);
	struct cxlfork_vma_tree_image *tree;
	struct cxlfork_vma_node_image *nodes;
	u64 tree_offset;
	u64 nodes_offset;
	u64 bytes;
	u64 i;

	if (!desc->nr_regions)
		return 0;
	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!regions)
		return -EILSEQ;
	bytes = PAGE_ALIGN(sizeof(*tree)) +
		PAGE_ALIGN(desc->nr_regions * sizeof(*nodes));
	if (!cxlfork_slot_has_room(slot, *data_off, bytes))
		return -ENOSPC;
	tree_offset = *data_off;
	tree = cxl_ptr(tree_offset);
	if (!tree)
		return -ENOSPC;
	memset(tree, 0, bytes);
	nodes_offset = tree_offset + PAGE_ALIGN(sizeof(*tree));
	nodes = cxl_ptr(nodes_offset);
	if (!nodes)
		return -ENOSPC;

	for (i = 0; i < desc->nr_regions; i++) {
		const struct cxlfork_region_desc *r = &regions[i];
		struct cxlfork_vma_node_image *node = &nodes[i];

		node->start = r->start;
		node->end = r->start + r->length;
		node->prot = r->prot;
		node->flags = r->flags;
		node->pgoff_first = r->pgoff_first;
		node->pages = r->pages;
		node->anon_pages = r->anon_pages;
		node->clean_file_pages = r->clean_file_pages;
		node->dirty_file_pages = r->dirty_file_pages;
		node->region_index = i;
	}

	tree->magic = CXLFORK_VMA_TREE_MAGIC;
	tree->version = CXLFORK_DESC_VERSION;
	tree->key = desc->key;
	tree->nodes_offset = nodes_offset;
	tree->nr_nodes = desc->nr_regions;
	tree->region_table_offset = desc->region_table_offset;
	cxlfork_vma_tree_link(nodes, nodes_offset, 0, desc->nr_regions - 1, -1,
				&tree->root_offset);

	desc->vma_tree_image_offset = tree_offset;
	desc->vma_tree_root_offset = tree->root_offset;
	desc->vma_tree_nodes = desc->nr_regions;
	desc->vma_tree_pages = bytes >> PAGE_SHIFT;
	*data_off += bytes;
	return 0;
}

static int cxlfork_validate_vma_tree_node(const struct cxlfork_desc *desc,
					  const struct cxlfork_vma_tree_image *tree,
					  u64 node_offset, u64 min_start,
					  u64 max_start, u64 parent_offset,
					  u64 *visited)
{
	/* restore 端递归校验 VMA tree 与 region table 是否一致。 */
	const struct cxlfork_vma_node_image *node;
	struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);
	const struct cxlfork_region_desc *r;

	if (!regions)
		return -EINVAL;
	if (!node_offset)
		return 0;
	if (!cxl_range_valid(node_offset, sizeof(*node)))
		return -EINVAL;
	node = cxl_ptr(node_offset);
	if (!node || node->region_index >= desc->nr_regions ||
	    node->parent_offset != parent_offset)
		return -EINVAL;
	if (node->start < min_start || node->start >= max_start)
		return -EINVAL;
	r = &regions[node->region_index];
	if (node->start != r->start || node->end != r->start + r->length ||
	    node->prot != r->prot || node->flags != r->flags ||
	    node->pgoff_first != r->pgoff_first || node->pages != r->pages ||
	    node->anon_pages != r->anon_pages ||
	    node->clean_file_pages != r->clean_file_pages ||
	    node->dirty_file_pages != r->dirty_file_pages)
		return -EINVAL;
	(*visited)++;
	if (node->left_offset && cxlfork_validate_vma_tree_node(desc, tree,
			node->left_offset, min_start, node->start, node_offset, visited))
		return -EINVAL;
	if (node->right_offset && cxlfork_validate_vma_tree_node(desc, tree,
			node->right_offset, node->start + 1, max_start, node_offset, visited))
		return -EINVAL;
	return 0;
}

static int cxlfork_validate_vma_tree_image(const struct cxlfork_desc *desc,
					   u64 *validate_ns)
{
	/* 统计 VMA tree 校验时间，对应 CSV 的 vma_tree_validate_ns。 */
	const struct cxlfork_vma_tree_image *tree;
	u64 start_ns = ktime_get_ns();
	u64 visited = 0;
	int ret;

	if (!desc->vma_tree_image_offset || !desc->vma_tree_root_offset ||
	    !desc->vma_tree_nodes || !desc->vma_tree_pages ||
	    !cxl_range_valid(desc->vma_tree_image_offset,
			     desc->vma_tree_pages * PAGE_SIZE))
		return -EINVAL;
	tree = cxl_ptr(desc->vma_tree_image_offset);
	if (!tree)
		return -EINVAL;
	if (tree->magic != CXLFORK_VMA_TREE_MAGIC ||
	    tree->version != CXLFORK_DESC_VERSION || tree->key != desc->key ||
	    tree->root_offset != desc->vma_tree_root_offset ||
	    tree->nodes_offset != desc->vma_tree_image_offset + PAGE_ALIGN(sizeof(*tree)) ||
	    tree->nr_nodes != desc->nr_regions ||
	    tree->region_table_offset != desc->region_table_offset)
		return -EINVAL;
	ret = cxlfork_validate_vma_tree_node(desc, tree, tree->root_offset, 0,
					       TASK_SIZE, 0, &visited);
	if (ret || visited != desc->nr_regions)
		return -EINVAL;
	if (validate_ns)
		*validate_ns += ktime_get_ns() - start_ns;
	return 0;
}

static int cxlfork_build_state_image(struct cxlfork_desc *desc, u64 slot,
				     u64 *data_off)
{
	/* 构建完整 state image：task/mm/thread/global/fd/region 的 CXL 常驻副本。 */
	struct cxlfork_fd_state *fds = cxlfork_desc_fds(desc);
	struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);
	struct cxlfork_state_image *image;
	u64 image_bytes = PAGE_ALIGN(sizeof(*image));
	u64 image_off = *data_off;

	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!fds || !regions)
		return -EILSEQ;
	if (!cxlfork_slot_has_room(slot, *data_off, image_bytes))
		return -ENOSPC;
	image = cxl_ptr(image_off);
	if (!image)
		return -ENOSPC;

	memset(image, 0, image_bytes);
	desc->state_image_offset = image_off;
	desc->state_image_pages = image_bytes >> PAGE_SHIFT;
	image->magic = CXLFORK_DESC_MAGIC;
	image->version = CXLFORK_DESC_VERSION;
	image->key = desc->key;
	image->nr_regions = desc->nr_regions;
	image->nr_ptes = desc->nr_ptes;
	image->total_pages = desc->total_pages;
	image->anon_pages = desc->anon_pages;
	image->clean_file_pages = desc->clean_file_pages;
	image->dirty_file_pages = desc->dirty_file_pages;
	image->nr_fds = desc->nr_fds;
	image->self_offset = image_off;
	image->task_state_offset = image_off + offsetof(struct cxlfork_state_image, task_state);
	image->mm_state_offset = image_off + offsetof(struct cxlfork_state_image, mm_state);
	image->thread_state_offset = image_off + offsetof(struct cxlfork_state_image, thread_state);
	image->global_state_offset = image_off + offsetof(struct cxlfork_state_image, global_state);
	image->fd_table_offset = image_off + offsetof(struct cxlfork_state_image, fds);
	image->region_table_offset = image_off + offsetof(struct cxlfork_state_image, regions);
	image->vma_tree_image_offset = desc->vma_tree_image_offset;
	image->vma_tree_root_offset = desc->vma_tree_root_offset;
	image->pte_table_offset = desc->pte_table_offset;
	image->leaf_pte_image_offset = desc->pte_image_offset;
	image->pt_page_image_offset = desc->pt_page_image_offset;
	image->pt_tree_image_offset = desc->pt_tree_image_offset;
	image->pt_tree_root_offset = desc->pt_tree_root_offset;
	image->page_data_offset = desc->data_offset;
	image->private_rebase_offset = 0;
	image->task_state = desc->task_state;
	image->mm_state = desc->mm_state;
	image->thread_state = desc->thread_state;
	image->global_state = desc->global_state;
	memcpy(image->fds, fds, min_t(size_t, sizeof(image->fds),
				      desc->fd_table_bytes));
	memcpy(image->regions, regions, min_t(size_t, sizeof(image->regions),
					      desc->region_table_bytes));

	*data_off += image_bytes;
	return 0;
}

static void cxlfork_patch_state_image_rebase_offset(struct cxlfork_desc *desc)
{
	/* rebase image 在 state image 之后生成，这里回填其 offset。 */
	struct cxlfork_state_image *image;

	if (!desc->state_image_offset || !desc->private_rebase_offset)
		return;
	image = cxl_ptr(desc->state_image_offset);
	if (!image)
		return;
	image->private_rebase_offset = desc->private_rebase_offset;
}

static int cxlfork_validate_state_image(const struct cxlfork_desc *desc,
					u64 *validate_ns)
{
	/* restore 端校验 state image 的 magic、offset 和 region 内容。 */
	const struct cxlfork_state_image *image;
	struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);
	u64 start_ns = ktime_get_ns();
	u64 state_bytes = desc->state_image_pages * PAGE_SIZE;
	u64 i;

	if (!desc->state_image_offset || !desc->state_image_pages ||
	    !cxl_range_valid(desc->state_image_offset, state_bytes))
		return -EINVAL;
	image = cxl_ptr(desc->state_image_offset);
	if (!image)
		return -EINVAL;

	if (image->magic != CXLFORK_DESC_MAGIC ||
	    image->version != CXLFORK_DESC_VERSION ||
	    image->key != desc->key ||
	    image->nr_regions != desc->nr_regions ||
	    image->nr_ptes != desc->nr_ptes ||
	    image->total_pages != desc->total_pages ||
	    image->anon_pages != desc->anon_pages ||
	    image->clean_file_pages != desc->clean_file_pages ||
	    image->dirty_file_pages != desc->dirty_file_pages ||
	    image->nr_fds != desc->nr_fds)
		return -EINVAL;
	if (image->self_offset != desc->state_image_offset ||
	    image->task_state_offset != desc->state_image_offset + offsetof(struct cxlfork_state_image, task_state) ||
	    image->mm_state_offset != desc->state_image_offset + offsetof(struct cxlfork_state_image, mm_state) ||
	    image->thread_state_offset != desc->state_image_offset + offsetof(struct cxlfork_state_image, thread_state) ||
	    image->global_state_offset != desc->state_image_offset + offsetof(struct cxlfork_state_image, global_state) ||
	    image->fd_table_offset != desc->state_image_offset + offsetof(struct cxlfork_state_image, fds) ||
	    image->region_table_offset != desc->state_image_offset + offsetof(struct cxlfork_state_image, regions) ||
	    image->vma_tree_image_offset != desc->vma_tree_image_offset ||
	    image->vma_tree_root_offset != desc->vma_tree_root_offset ||
	    image->pte_table_offset != desc->pte_table_offset ||
	    image->leaf_pte_image_offset != desc->pte_image_offset ||
	    image->pt_page_image_offset != desc->pt_page_image_offset ||
	    image->pt_tree_image_offset != desc->pt_tree_image_offset ||
	    image->pt_tree_root_offset != desc->pt_tree_root_offset ||
	    image->page_data_offset != desc->data_offset ||
	    image->private_rebase_offset != desc->private_rebase_offset)
		return -EINVAL;
	if (!cxl_range_valid(image->task_state_offset, sizeof(image->task_state)) ||
	    !cxl_range_valid(image->mm_state_offset, sizeof(image->mm_state)) ||
	    !cxl_range_valid(image->thread_state_offset, sizeof(image->thread_state)) ||
	    !cxl_range_valid(image->global_state_offset, sizeof(image->global_state)) ||
	    !cxl_range_valid(image->fd_table_offset, sizeof(image->fds)) ||
	    !cxl_range_valid(image->region_table_offset, sizeof(image->regions)) ||
	    !cxl_range_valid(image->vma_tree_image_offset, desc->vma_tree_pages * PAGE_SIZE) ||
	    !cxl_range_valid(image->vma_tree_root_offset, sizeof(struct cxlfork_vma_node_image)) ||
	    !cxl_range_valid(image->pte_table_offset, desc->pte_table_bytes) ||
	    !cxl_range_valid(image->leaf_pte_image_offset, desc->pte_image_pages * PAGE_SIZE) ||
	    !cxl_range_valid(image->pt_page_image_offset, desc->pt_page_image_pages * PAGE_SIZE) ||
	    !cxl_range_valid(image->pt_tree_image_offset, (desc->pt_tree_pages + 1) * PAGE_SIZE) ||
	    !cxl_range_valid(image->pt_tree_root_offset, PAGE_SIZE) ||
	    !cxl_range_valid(image->page_data_offset, desc->total_pages * PAGE_SIZE) ||
	    !cxl_range_valid(image->private_rebase_offset, desc->private_rebase_pages * PAGE_SIZE))
		return -EINVAL;
	if (desc->nr_regions && !regions)
		return -EINVAL;
	for (i = 0; i < desc->nr_regions; i++) {
		const struct cxlfork_region_desc *a = &image->regions[i];
		const struct cxlfork_region_desc *b = &regions[i];

		if (a->start != b->start || a->length != b->length ||
		    a->prot != b->prot || a->flags != b->flags ||
		    a->pgoff_first != b->pgoff_first || a->pages != b->pages ||
		    a->anon_pages != b->anon_pages ||
		    a->clean_file_pages != b->clean_file_pages ||
		    a->dirty_file_pages != b->dirty_file_pages)
			return -EINVAL;
	}
	if (validate_ns)
		*validate_ns += ktime_get_ns() - start_ns;
	return 0;
}

static void cxlfork_private_ptr_set(struct cxlfork_private_rebase_image *image,
                                    u64 *idx, u64 id, u64 cxl_offset,
                                    u64 bytes, u64 entries)
{
	/* 记录一个 CXL 内部对象的 offset/phys/长度，模拟远端重定位表。 */
	struct cxlfork_private_ptr *ptr;

	if (*idx >= CXLFORK_MAX_PRIVATE_PTRS || !bytes)
		return;
	ptr = &image->ptrs[(*idx)++];
	ptr->id = id;
	ptr->cxl_offset = cxl_offset;
	ptr->cxl_phys = cxl_phys + cxl_offset;
	ptr->bytes = bytes;
	ptr->entries = entries;
}

static int cxlfork_build_pt_page_image(struct cxlfork_desc *desc, u64 slot,
				       u64 *data_off)
{
	/* 把 leaf PTE 合并成按 PMD 覆盖的页表页镜像，供 restore/fault 快速 attach。 */
	struct cxlfork_pte_desc *pte_table = cxlfork_desc_ptes(desc);
	struct cxlfork_pt_page_image *meta;
	struct cxlfork_pt_tree_image *tree;
	u64 meta_bytes;
	u64 tree_offset;
	u64 i = 0;
	u64 nr_pages = 0;
	int ret;

	if (!desc->nr_ptes)
		return 0;
	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!pte_table)
		return -EILSEQ;
	while (i < desc->nr_ptes) {
		u64 va_base = pte_table[i].va & PMD_MASK;

		nr_pages++;
		do {
			i++;
		} while (i < desc->nr_ptes &&
			 (pte_table[i].va & PMD_MASK) == va_base);
	}
	if (nr_pages > CXLFORK_MAX_PT_PAGE_IMAGES)
		return -ENOSPC;

	meta_bytes = PAGE_ALIGN(nr_pages * sizeof(*meta));
	if (!cxlfork_slot_has_room(slot, *data_off,
				   meta_bytes + PAGE_SIZE * 2))
		return -ENOSPC;
	meta = cxl_ptr(*data_off);
	if (!meta)
		return -ENOSPC;
	memset(meta, 0, meta_bytes);

	desc->pt_page_image_offset = *data_off;
	desc->pt_page_image_entries = nr_pages;
	*data_off += meta_bytes;

	ret = cxlfork_pt_tree_alloc_page(desc, slot, data_off, &tree_offset,
					 true);
	if (ret)
		return ret;
	tree = cxl_ptr(tree_offset);
	if (!tree)
		return -ENOSPC;
	tree->magic = CXLFORK_PT_TREE_MAGIC;
	tree->version = CXLFORK_DESC_VERSION;
	tree->key = desc->key;
	desc->pt_tree_image_offset = tree_offset;

	ret = cxlfork_pt_tree_alloc_page(desc, slot, data_off,
					  &desc->pt_tree_root_offset, false);
	if (ret)
		return ret;
	tree->root_offset = desc->pt_tree_root_offset;
	tree->leaf_pte_image_offset = desc->pte_image_offset;
	tree->pt_page_image_offset = desc->pt_page_image_offset;
	tree->pte_table_offset = desc->pte_table_offset;
	tree->nr_leaf_ptes = desc->nr_ptes;

	i = 0;
	nr_pages = 0;
	while (i < desc->nr_ptes) {
		u64 va_base = pte_table[i].va & PMD_MASK;
		u64 pte_index_base = i;
		u64 page_off;
		u64 *ptes;

		ret = cxlfork_pt_tree_alloc_page(desc, slot, data_off, &page_off,
						 false);
		if (ret)
			return ret;
		ptes = cxl_ptr(page_off);
		if (!ptes)
			return -ENOSPC;
		meta[nr_pages].va_base = va_base;
		meta[nr_pages].pte_index_base = pte_index_base;
		meta[nr_pages].pte_page_offset = page_off;
		ret = cxlfork_pt_tree_insert_leaf(desc, slot, data_off, va_base,
						  page_off);
		if (ret)
			return ret;
		do {
			const struct cxlfork_pte_desc *pte = &pte_table[i];
			u64 slot = pte_index(pte->va);

			ptes[slot] = pte->cxl_pteval;
			i++;
			meta[nr_pages].nr_ptes++;
			desc->pt_tree_entries++;
		} while (i < desc->nr_ptes &&
			 (pte_table[i].va & PMD_MASK) == va_base);
		nr_pages++;
	}
	tree = cxl_ptr(desc->pt_tree_image_offset);
	if (!tree)
		return -EINVAL;
	tree->nr_pages = desc->pt_tree_pages;
	desc->pt_page_image_pages = (*data_off - desc->pt_page_image_offset) >> PAGE_SHIFT;
	return 0;
}

static int cxlfork_validate_pt_page_image(const struct cxlfork_desc *desc,
						  u64 *validate_ns)
{
	/* 校验 PTE page image 和 CXL 页表树，对应 CSV 的 pt_page_image_validate_ns。 */
	struct cxlfork_pte_desc *pte_table = cxlfork_desc_ptes(desc);
	const struct cxlfork_pt_page_image *meta;
	const struct cxlfork_pt_tree_image *tree;
	u64 start_ns = ktime_get_ns();
	u64 m;

	if (!desc->pt_page_image_offset || !desc->pt_page_image_entries ||
	    !desc->pt_tree_image_offset || !desc->pt_tree_root_offset)
		return -EINVAL;
	if (!pte_table)
		return -EINVAL;
	meta = cxl_ptr(desc->pt_page_image_offset);
	tree = cxl_ptr(desc->pt_tree_image_offset);
	if (!meta || !tree)
		return -EINVAL;
	if (tree->magic != CXLFORK_PT_TREE_MAGIC ||
	    tree->version != CXLFORK_DESC_VERSION || tree->key != desc->key ||
	    tree->root_offset != desc->pt_tree_root_offset ||
	    tree->leaf_pte_image_offset != desc->pte_image_offset ||
	    tree->pt_page_image_offset != desc->pt_page_image_offset ||
	    tree->pte_table_offset != desc->pte_table_offset ||
	    tree->nr_pages != desc->pt_tree_pages ||
	    tree->nr_leaf_ptes != desc->nr_ptes)
		return -EINVAL;
	for (m = 0; m < desc->pt_page_image_entries; m++) {
		const struct cxlfork_pt_page_image *img = &meta[m];
		const u64 *ptes = cxl_ptr(img->pte_page_offset);
		u64 *tree_ptes;
		u64 i;
		int ret;

		if (!img->nr_ptes || img->pte_index_base + img->nr_ptes > desc->nr_ptes ||
		    !ptes)
			return -EINVAL;
		ret = cxlfork_pt_tree_walk(desc, img->va_base, &tree_ptes);
		if (ret || tree_ptes != ptes)
			return -EINVAL;
		for (i = 0; i < img->nr_ptes; i++) {
			const struct cxlfork_pte_desc *pte =
				&pte_table[img->pte_index_base + i];
			u64 slot = pte_index(pte->va);
			u64 expected = pte->cxl_pteval;

			if ((pte->va & PMD_MASK) != img->va_base || slot >= PTRS_PER_PTE)
				return -EINVAL;
			if (ptes[slot] != expected || tree_ptes[slot] != expected)
				return -EINVAL;
			if (pte_write(__pte(expected)))
				return -EINVAL;
			if (pte_young(__pte(pte->orig_pteval)) !=
			    pte_young(__pte(expected)))
				return -EINVAL;
			if (pte_dirty(__pte(pte->orig_pteval)) !=
			    pte_dirty(__pte(expected)))
				return -EINVAL;
		}
	}
	if (validate_ns)
		*validate_ns += ktime_get_ns() - start_ns;
	return 0;
}

static int cxlfork_build_private_rebase_image(struct cxlfork_desc *desc,
					      u64 slot, u64 *data_off)
{
	/* 构建 private rebase image，用于量化跨 OS 恢复时需要重定位的内部对象集合。 */
	struct cxlfork_private_rebase_image *image;
	u64 image_bytes = PAGE_ALIGN(sizeof(*image));
	u64 idx = 0;

	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!cxlfork_slot_has_room(slot, *data_off, image_bytes))
		return -ENOSPC;
	image = cxl_ptr(*data_off);
	if (!image)
		return -ENOSPC;

	memset(image, 0, image_bytes);
	image->magic = CXLFORK_DESC_MAGIC;
	image->version = CXLFORK_DESC_VERSION;
	image->key = desc->key;
	image->self_offset = *data_off;
	image->state_image_offset = desc->state_image_offset;
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_PAGE_DATA,
				desc->data_offset, desc->total_pages * PAGE_SIZE,
				desc->total_pages);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_LEAF_PTE_IMAGE,
				desc->pte_image_offset,
				desc->pte_image_pages * PAGE_SIZE,
				desc->pte_image_entries);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_STATE_IMAGE,
				desc->state_image_offset,
				desc->state_image_pages * PAGE_SIZE, 1);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_REGION_TABLE,
				desc->region_table_offset,
				desc->nr_regions *
				(u64)sizeof(struct cxlfork_region_desc),
				desc->nr_regions);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_PTE_TABLE,
				desc->pte_table_offset,
				desc->nr_ptes *
				(u64)sizeof(struct cxlfork_pte_desc),
				desc->nr_ptes);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_PT_PAGE_IMAGE,
				desc->pt_page_image_offset,
				desc->pt_page_image_pages * PAGE_SIZE,
				desc->pt_page_image_entries);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_PT_TREE_IMAGE,
				desc->pt_tree_image_offset,
				(desc->pt_tree_pages + 1) * PAGE_SIZE,
				desc->pt_tree_entries);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_VMA_TREE_IMAGE,
				desc->vma_tree_image_offset,
				desc->vma_tree_pages * PAGE_SIZE,
				desc->vma_tree_nodes);
	cxlfork_private_ptr_set(image, &idx, CXLFORK_PTR_REBASE_IMAGE,
				*data_off, image_bytes, 1);
	image->nr_ptrs = idx;

	desc->private_rebase_offset = *data_off;
	desc->private_rebase_entries = idx;
	desc->private_rebase_pages = image_bytes >> PAGE_SHIFT;
	*data_off += image_bytes;
	return 0;
}

static int cxlfork_validate_private_rebase_image(const struct cxlfork_desc *desc,
                                                 u64 *validate_ns)
{
	/* 校验 rebase 表中每个对象仍落在合法 CXL window 内。 */
	const struct cxlfork_private_rebase_image *image;
	u64 start_ns = ktime_get_ns();
	u64 i;

	if (!desc->private_rebase_offset || !desc->private_rebase_entries)
		return -EINVAL;
	image = cxl_ptr(desc->private_rebase_offset);
	if (!image)
		return -EINVAL;
	if (image->magic != CXLFORK_DESC_MAGIC ||
	    image->version != CXLFORK_DESC_VERSION || image->key != desc->key ||
	    image->self_offset != desc->private_rebase_offset ||
	    image->state_image_offset != desc->state_image_offset ||
	    image->nr_ptrs != desc->private_rebase_entries ||
	    image->nr_ptrs > CXLFORK_MAX_PRIVATE_PTRS)
		return -EINVAL;
	for (i = 0; i < image->nr_ptrs; i++) {
		const struct cxlfork_private_ptr *ptr = &image->ptrs[i];

		if (!ptr->bytes || ptr->cxl_phys != cxl_phys + ptr->cxl_offset ||
		    !cxl_range_valid(ptr->cxl_offset, ptr->bytes))
			return -EINVAL;
	}
	if (validate_ns)
		*validate_ns += ktime_get_ns() - start_ns;
	return 0;
}

static int cxlfork_ioctl_checkpoint(struct cxlfork_checkpoint __user *uarg)
{
	/* prepare 主路径：扫描 VMA -> 复制页面 -> 构建 PTE/VMA/state/rebase 镜像 -> ready。 */
	struct cxlfork_checkpoint *op;
	struct cxlfork_desc *desc;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u64 data_off;
	u64 slot;
	u64 start_ns;
	int ret = 0;
	bool reopen_fds;

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return -ENOMEM;
	if (copy_from_user(op, uarg, sizeof(*op))) {
		ret = -EFAULT;
		goto out_free;
	}
	if (!op->key || (!(op->flags & CXLFORK_F_FULL_PRIVATE_STATE) &&
			op->scan_start >= op->scan_end)) {
		ret = -EINVAL;
		goto out_free;
	}
	if (op->flags & CXLFORK_F_FULL_PRIVATE_STATE) {
		ret = -EOPNOTSUPP;
		goto out_free;
	}
	if (get_nr_threads(current) != 1) {
		ret = -EBUSY;
		goto out_free;
	}
	reopen_fds = op->flags & CXLFORK_F_REOPEN_FDS;
	op->flags &= ~CXLFORK_F_REOPEN_FDS;

	ret = key_to_slot(op->key);
	if (ret < 0)
		goto out_free;
	slot = ret;
	desc = slot_desc(slot);
	if (!desc) {
		ret = -ENOSPC;
		goto out_free;
	}
	ret = 0;

	mutex_lock(&cxlfork_lock);
	if (cmpxchg(&desc->state, (u64)CXLFORK_SLOT_FREE,
		    (u64)CXLFORK_SLOT_WRITING) != CXLFORK_SLOT_FREE) {
		ret = -EEXIST;
		goto out_unlock;
	}
	{
		u64 generation = READ_ONCE(desc->generation) + 1;

	memset_after(desc, 0, reader_count);
	desc->magic = CXLFORK_DESC_MAGIC;
	desc->version = CXLFORK_DESC_VERSION;
	desc->key = op->key;
	desc->state = CXLFORK_SLOT_WRITING;
	desc->generation = generation ?: 1;
	desc->slot = slot;
	desc->data_offset = slot_payload_offset(slot);
	}
	data_off = desc->data_offset;
	start_ns = ktime_get_ns();

	mm = get_task_mm(current);
	if (!mm) {
		ret = -EINVAL;
		goto out_unlock;
	}

	mmap_read_lock(mm);
	ret = cxlfork_preflight_checkpoint(mm, op, slot);
	if (ret)
		goto out_mmap_unlock;
	ret = cxlfork_alloc_table(slot, &data_off, CXLFORK_MAX_FDS,
				  sizeof(struct cxlfork_fd_state),
				  &desc->fd_table_offset,
				  &desc->fd_table_bytes);
	if (ret)
		goto out_mmap_unlock;
	ret = cxlfork_alloc_table(slot, &data_off, CXLFORK_MAX_REGIONS,
				  sizeof(struct cxlfork_region_desc),
				  &desc->region_table_offset,
				  &desc->region_table_bytes);
	if (ret)
		goto out_mmap_unlock;
	ret = cxlfork_alloc_table(slot, &data_off, CXLFORK_MAX_PTES,
				  sizeof(struct cxlfork_pte_desc),
				  &desc->pte_table_offset,
				  &desc->pte_table_bytes);
	if (ret)
		goto out_mmap_unlock;
	desc->data_offset = data_off;
	cxlfork_capture_task_state(&desc->task_state,
				   op->flags & CXLFORK_F_FULL_PRIVATE_STATE);
	cxlfork_capture_mm_state(&desc->mm_state, mm);
	if (op->flags & CXLFORK_F_USER_THREAD_STATE)
		desc->thread_state = op->thread_state;
	else
		cxlfork_capture_thread_state(&desc->thread_state);
	{
		u64 global_start = ktime_get_ns();

		cxlfork_capture_global_state(desc);
		ret = cxlfork_capture_fd_state(desc, reopen_fds);
		if (ret)
			goto out_mmap_unlock;
		desc->global_checkpoint_ns = ktime_get_ns() - global_start;
		desc->global_detach_ns = desc->global_checkpoint_ns;
	}
	{
		unsigned long scan_start = op->scan_start;
		unsigned long scan_end = op->scan_end;
		struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);
		struct cxlfork_pte_desc *ptes = cxlfork_desc_ptes(desc);

		if (!regions || !ptes) {
			ret = -EILSEQ;
			goto out_mmap_unlock;
		}
		VMA_ITERATOR(vmi, mm, scan_start);
		for_each_vma_range(vmi, vma, scan_end) {
		unsigned long addr, start, end;
		struct cxlfork_region_desc *r;

		ret = cxlfork_checkpoint_vma_supported(vma, op);
		if (ret)
			break;
		if (desc->nr_regions >= CXLFORK_MAX_REGIONS) {
			ret = -ENOSPC;
			break;
		}

		start = max(vma->vm_start, scan_start);
		end = min(vma->vm_end, scan_end);
		start = PAGE_ALIGN(start);
		end &= PAGE_MASK;
		if (start >= end)
			continue;

		r = &regions[desc->nr_regions++];
		r->start = start;
		r->length = end - start;
		r->prot = prot_from_vma(vma);
		r->flags = vma->vm_flags;
		r->pgoff_first = desc->nr_ptes;

		for (addr = start; addr < end; addr += PAGE_SIZE) {
			struct cxlfork_pte_desc *pte;

			if (desc->nr_ptes >= CXLFORK_MAX_PTES) {
				ret = -ENOSPC;
				break;
			}
			if (data_off + PAGE_SIZE > slot_offset(slot) + CXLFORK_SLOT_BYTES) {
				ret = -ENOSPC;
				break;
			}
			pte = &ptes[desc->nr_ptes];
			pte->va = addr;
			pte->cxl_offset = data_off;
			ret = cxlfork_copy_page_to_cxl(addr, data_off, vma, r,
						       desc, mm,
						       &pte->orig_pteval);
			if (ret)
				break;
			pte->cxl_pteval = cxlfork_make_cxl_pteval(pte->orig_pteval,
								 pte->cxl_offset);
			desc->nr_ptes++;
			data_off += PAGE_SIZE;
			r->pages++;
			desc->total_pages++;
		}
		if (ret)
			break;
		}
	}
out_mmap_unlock:
	mmap_read_unlock(mm);
	mmput(mm);

	if (!ret) {
		u64 pte_image_start = ktime_get_ns();

		ret = cxlfork_build_leaf_pte_image(desc, slot, &data_off);
		desc->pte_image_build_ns = ktime_get_ns() - pte_image_start;
	}
	if (!ret) {
		u64 pt_page_start = ktime_get_ns();

		ret = cxlfork_build_pt_page_image(desc, slot, &data_off);
		desc->pt_page_image_build_ns = ktime_get_ns() - pt_page_start;
	}
	if (!ret) {
		u64 vma_tree_start = ktime_get_ns();

		ret = cxlfork_build_vma_tree_image(desc, slot, &data_off);
		desc->vma_tree_build_ns = ktime_get_ns() - vma_tree_start;
	}
	if (!ret) {
		u64 state_image_start = ktime_get_ns();

		ret = cxlfork_build_state_image(desc, slot, &data_off);
		desc->state_image_build_ns = ktime_get_ns() - state_image_start;
	}
	if (!ret) {
		u64 rebase_start = ktime_get_ns();

		ret = cxlfork_build_private_rebase_image(desc, slot, &data_off);
		if (!ret)
			cxlfork_patch_state_image_rebase_offset(desc);
		desc->private_rebase_ns = ktime_get_ns() - rebase_start;
	}
	if (!ret) {
		if (!cxlfork_desc_matches_slot(desc, slot)) {
			ret = -EILSEQ;
			goto out_unlock;
		}
		desc->image_bytes = data_off - slot_offset(slot);
		ret = cxlfork_compute_checksums(desc, &desc->page_checksum,
						&desc->leaf_checksum);
	}

	if (!ret) {
		int i;
		struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);

		desc->create_ns = ktime_get_ns() - start_ns;
		smp_wmb();
		WRITE_ONCE(desc->ready, 1);
		WRITE_ONCE(desc->state, CXLFORK_SLOT_READY);
		memset(op, 0, sizeof(*op));
		op->key = desc->key;
		op->nr_regions = desc->nr_regions;
		op->nr_ptes = desc->nr_ptes;
		op->total_pages = desc->total_pages;
		op->anon_pages = desc->anon_pages;
		op->clean_file_pages = desc->clean_file_pages;
		op->dirty_file_pages = desc->dirty_file_pages;
		op->checkpoint_ns = desc->create_ns;
		cxlfork_copy_mm_state_to_checkpoint(op, desc);
		for (i = 0; i < desc->nr_regions; i++) {
			op->regions[i].start = regions[i].start;
			op->regions[i].length = regions[i].length;
			op->regions[i].prot = regions[i].prot;
			op->regions[i].flags = regions[i].flags;
			op->regions[i].pages = regions[i].pages;
			op->regions[i].anon_pages = regions[i].anon_pages;
			op->regions[i].clean_file_pages = regions[i].clean_file_pages;
			op->regions[i].dirty_file_pages = regions[i].dirty_file_pages;
		}
		if (copy_to_user(uarg, op, sizeof(*op)))
			ret = -EFAULT;
	}

out_unlock:
	if (ret && desc && !desc->ready) {
		u64 generation = desc->generation;

		memset(desc, 0, sizeof(*desc));
		desc->generation = generation;
	}
	mutex_unlock(&cxlfork_lock);
out_free:
	kfree(op);
	return ret;
}

static int cxlfork_map_region(struct cxlfork_desc *desc,
			      struct cxlfork_region_desc *r,
			      bool readonly,
			      struct cxlfork_restore_breakdown *bd)
{
	/* 非 COW 路径：直接把 CXL 物理页 remap 到目标进程地址。 */
	struct cxlfork_pte_desc *pte_table = cxlfork_desc_ptes(desc);
	struct cxlfork_mapping *mapping;
	unsigned long addr = r->start;
	unsigned long mapped;
	u64 install_start;
	u64 i;
	int ret;

	if (!pte_table)
		return -EILSEQ;
	mapped = vm_mmap(NULL, r->start, r->length,
			 PROT_READ | ((r->prot & PROT_EXEC) ? PROT_EXEC : 0),
			 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0);
	if (IS_ERR_VALUE(mapped)) {
		if (mapped != -EEXIST)
			pr_warn("cxlfork: vm_mmap start=%llx len=%llx ret=%ld\n",
				r->start, r->length, mapped);
		return (int)mapped;
	}
	if (mapped != r->start) {
		pr_warn("cxlfork: vm_mmap returned %lx expected=%llx\n",
			mapped, r->start);
		return -EINVAL;
	}

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
		return -ENOMEM;
	mapping->key = desc->key;
	mapping->generation = desc->generation;
	mapping->flags = readonly ? CXLFORK_F_MAP_READONLY : 0;
	mapping->holds_slot_reader = true;
	refcount_set(&mapping->refs, 1);
	ret = cxlfork_slot_get_reader(mapping->key, mapping->generation);
	if (ret) {
		kfree(mapping);
		return ret;
	}

	addr = r->start;
	mmap_write_lock(current->mm);
	install_start = ktime_get_ns();
	for (i = 0; i < r->pages; i++, addr += PAGE_SIZE) {
		struct vm_area_struct *vma;
		struct cxlfork_pte_desc *pte = &pte_table[r->pgoff_first + i];
		unsigned long pfn = (cxl_phys + pte->cxl_offset) >> PAGE_SHIFT;

		vma = find_vma(current->mm, addr);
		if (!vma || vma->vm_start > addr) {
			pr_warn("cxlfork: no vma for addr=%lx start=%llx len=%llx\n",
				addr, r->start, r->length);
			mmap_write_unlock(current->mm);
			cxlfork_slot_put_reader(mapping->key,
						mapping->generation);
			kfree(mapping);
			return -EFAULT;
		}
		vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
		ret = io_remap_pfn_range(vma, addr, pfn, PAGE_SIZE,
					 prot_from_uapi(r->prot, readonly));
		if (ret) {
			pr_warn("cxlfork: remap addr=%lx pfn=%lx ret=%d\n",
				addr, pfn, ret);
			if (bd)
				bd->direct_pte_install_ns +=
					ktime_get_ns() - install_start;
			mmap_write_unlock(current->mm);
			cxlfork_slot_put_reader(mapping->key,
						mapping->generation);
			kfree(mapping);
			return ret;
		}
		if (bd)
			bd->direct_pte_install_pages++;
	}
	if (bd)
		bd->direct_pte_install_ns += ktime_get_ns() - install_start;
	{
		struct vm_area_struct *vma = find_vma(current->mm, r->start);

		if (!vma || vma->vm_start != r->start ||
		    vma->vm_end != r->start + r->length) {
			mmap_write_unlock(current->mm);
			cxlfork_slot_put_reader(mapping->key,
						mapping->generation);
			kfree(mapping);
			return -EFAULT;
		}
		vma->vm_ops = &cxlfork_vm_ops;
		vma->vm_private_data = mapping;
	}
	mmap_write_unlock(current->mm);

	return 0;
}

static int cxlfork_install_shared_leaf_pmd(struct mm_struct *mm,
					   unsigned long addr,
					   unsigned long leaf_pfn)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	if (!pmd_none(*pmd))
		return -EEXIST;
	set_pmd(pmd, __pmd(pte_val(pfn_pte(leaf_pfn, __pgprot(_PAGE_TABLE)))));
	mm_inc_nr_ptes(mm);
	return 0;
}

static int cxlfork_map_region_shared_leaf(struct cxlfork_desc *desc,
					  struct cxlfork_region_desc *r,
					  u64 mapping_flags,
					  bool writable_vma,
					  struct cxlfork_restore_breakdown *bd)
{
	/*
	 * Shared leaf gate: PMD-aligned, full-PMD regions only.
	 * The CPU page walker consumes the CXL PTE page directly. Core-MM
	 * materializes the leaf before software PTE mutation.
	 */
	struct cxlfork_mapping *mapping;
	struct vm_area_struct *vma;
	unsigned long mapped;
	unsigned long addr;
	unsigned long prot = PROT_READ | ((r->prot & PROT_EXEC) ? PROT_EXEC : 0);
	unsigned long mmap_flags = (writable_vma ? MAP_PRIVATE : MAP_SHARED) |
		MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
	int ret = 0;
	u64 attach_start;

	if (!IS_ALIGNED(r->start, PMD_SIZE) || !IS_ALIGNED(r->length, PMD_SIZE))
		return -EOPNOTSUPP;
	if (writable_vma && (r->prot & PROT_WRITE))
		prot |= PROT_WRITE;

	mapped = vm_mmap(NULL, r->start, r->length,
			 prot, mmap_flags, 0);
	if (IS_ERR_VALUE(mapped))
		return (int)mapped;
	if (mapped != r->start) {
		vm_munmap(mapped, r->length);
		return -EINVAL;
	}

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping) {
		vm_munmap(r->start, r->length);
		return -ENOMEM;
	}
	mapping->key = desc->key;
	mapping->generation = desc->generation;
	mapping->flags = mapping_flags;
	mapping->holds_slot_reader = true;
	refcount_set(&mapping->refs, 1);
	ret = cxlfork_slot_get_reader(mapping->key, mapping->generation);
	if (ret) {
		kfree(mapping);
		vm_munmap(r->start, r->length);
		return ret;
	}

	mmap_write_lock(current->mm);
	vma = find_vma(current->mm, r->start);
	if (!vma || vma->vm_start != r->start ||
	    vma->vm_end != r->start + r->length) {
		ret = -EFAULT;
		goto out_unlock;
	}
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &cxlfork_vm_ops;
	vma->vm_private_data = mapping;

	attach_start = ktime_get_ns();
	for (addr = r->start; addr < r->start + r->length; addr += PMD_SIZE) {
		unsigned long leaf_pfn;

		ret = cxlfork_find_shared_leaf_pfn(desc, addr, &leaf_pfn);
		if (ret)
			goto out_unlock;
		ret = cxlfork_install_shared_leaf_pmd(current->mm, addr, leaf_pfn);
		if (ret)
			goto out_unlock;
		if (bd) {
			bd->direct_pte_install_pages += PMD_SIZE >> PAGE_SHIFT;
			bd->shared_leaf_attach_pages += PMD_SIZE >> PAGE_SHIFT;
		}
		desc->shared_map_pages += PMD_SIZE >> PAGE_SHIFT;
	}
	if (bd) {
		u64 elapsed = ktime_get_ns() - attach_start;

		bd->direct_pte_install_ns += elapsed;
		bd->shared_leaf_attach_ns += elapsed;
	}

out_unlock:
	mmap_write_unlock(current->mm);
	if (ret)
		vm_munmap(r->start, r->length);
	return ret;
}

static int cxlfork_probe_cxl_vma_maple(struct cxlfork_desc *desc,
				       unsigned long address,
				       struct cxlfork_inspect_v2 *inspect)
{
	struct cxlfork_maple_copy_ctx ctx;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	void *old_root;
	void *new_root;
	unsigned int old_flags;
	bool attached = false;
	u64 start_ns = ktime_get_ns();
	u64 scratch = slot_offset(desc->slot) + CXLFORK_SLOT_BYTES -
		CXLFORK_VMA_MAPLE_SCRATCH_BYTES;
	u64 used_end = slot_offset(desc->slot) + desc->image_bytes;
	int ret;

	if (used_end > scratch)
		return -ENOSPC;
	if (!cxl_range_valid(scratch, CXLFORK_VMA_MAPLE_SCRATCH_BYTES))
		return -ENOSPC;

	memset(cxl_ptr(scratch), 0, CXLFORK_VMA_MAPLE_SCRATCH_BYTES);
	ctx.next = scratch;
	ctx.end = slot_offset(desc->slot) + CXLFORK_SLOT_BYTES;
	ctx.nodes = 0;

	mmap_write_lock(mm);
	mtree_lock(&mm->mm_mt);
	old_root = rcu_dereference_protected(mm->mm_mt.ma_root, true);
	old_flags = mm->mm_mt.ma_flags;
	if (old_flags & MT_FLAGS_CXLFORK_CXL_NODES) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!old_root || !((unsigned long)old_root & CXLFORK_MAPLE_ROOT_NODE)) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	ret = cxlfork_copy_maple_node_to_cxl(&ctx,
					     (void *)((unsigned long)old_root &
						      ~CXLFORK_MAPLE_ROOT_NODE),
					     &new_root, NULL, 0);
	if (ret)
		goto out_unlock;
	cxlfork_maple_set_root_parent(&mm->mm_mt, cxlfork_mte_node(new_root));
	rcu_assign_pointer(mm->mm_mt.ma_root, cxlfork_mte_mk_root(new_root));
	mm->mm_mt.ma_flags = old_flags | MT_FLAGS_CXLFORK_CXL_NODES;
	attached = true;
	mtree_unlock(&mm->mm_mt);

	vma = find_vma(mm, address);

	mtree_lock(&mm->mm_mt);
	rcu_assign_pointer(mm->mm_mt.ma_root, old_root);
	mm->mm_mt.ma_flags = old_flags;
	desc->vma_maple_nodes = ctx.nodes;
	desc->vma_maple_root_offset =
		(char *)cxlfork_mte_node(new_root) - (char *)cxl_ptr(0);
	desc->vma_maple_attach_ns = ktime_get_ns() - start_ns;
	inspect->vma_maple_root_pfn =
		(cxl_phys + desc->vma_maple_root_offset) >> PAGE_SHIFT;
	inspect->vma_maple_nodes = desc->vma_maple_nodes;
	if (vma) {
		inspect->vma_lookup_start = vma->vm_start;
		inspect->vma_lookup_end = vma->vm_end;
	}
	inspect->flags |= CXLFORK_INSPECT_F_CXL_VMA_NODE_VALID;
	ret = 0;

out_unlock:
	if (attached) {
		rcu_assign_pointer(mm->mm_mt.ma_root, old_root);
		mm->mm_mt.ma_flags = old_flags;
	}
	mtree_unlock(&mm->mm_mt);
	mmap_write_unlock(mm);
	return ret;
}

static int cxlfork_map_region_cow(struct file *file,
				  const struct cxlfork_region_desc *r,
				  u64 region_idx, bool private_cow)
{
	/* COW/tiering 路径：先 mmap /dev/cxlfork，后续 fault 决定共享还是复制。 */
	unsigned long mapped;
	unsigned long flags = (private_cow ? MAP_SHARED : MAP_PRIVATE) |
		MAP_FIXED_NOREPLACE;

	mapped = vm_mmap(file, r->start, r->length,
			 PROT_READ | ((r->prot & PROT_WRITE) ? PROT_WRITE : 0),
			 flags,
			 (region_idx * CXLFORK_REGION_PGOFF_STEP) << PAGE_SHIFT);
	if (IS_ERR_VALUE(mapped)) {
		if (mapped != -EEXIST)
			pr_warn("cxlfork: cow vm_mmap start=%llx len=%llx ret=%ld\n",
				r->start, r->length, mapped);
		return (int)mapped;
	}
	if (mapped != r->start)
		return -EINVAL;
	return 0;
}

static vm_fault_t cxlfork_insert_shared_cxl(struct vm_fault *vmf,
					   struct cxlfork_pte_desc *pte,
					   unsigned long addr)
{
	/*
	 * CXLfork's default policy is migrate-on-write: reads share the
	 * immutable CXL snapshot, while stores trigger the core MM COW path.
	 */
	return vmf_insert_mixed(vmf->vma, addr,
				phys_to_pfn_t(cxl_phys + pte->cxl_offset, 0));
}

static int cxlfork_find_pt_page_pfn(const struct cxlfork_desc *desc,
					    unsigned long addr,
					    unsigned long *pfn_out)
{
	/* 通过 CXL 页表树找到某个 VA 对应的 CXL PFN。 */
	u64 *ptes;
	u64 raw;
	int ret;

	ret = cxlfork_pt_tree_walk(desc, addr, &ptes);
	if (ret)
		return ret;
	raw = ptes[pte_index(addr)];
	if (!raw)
		return -ENOENT;
	*pfn_out = pte_pfn(__pte(raw));
	return 0;
}

static int cxlfork_find_shared_leaf_pfn(const struct cxlfork_desc *desc,
					unsigned long addr,
					unsigned long *pfn_out)
{
	const struct cxlfork_pt_page_image *meta;
	u64 i;

	if (!desc->pt_page_image_offset || !desc->pt_page_image_entries)
		return -EINVAL;
	meta = cxl_ptr(desc->pt_page_image_offset);
	if (!meta)
		return -EINVAL;
	addr &= PMD_MASK;
	for (i = 0; i < desc->pt_page_image_entries; i++) {
		if (meta[i].va_base != addr)
			continue;
		if (!cxl_range_valid(meta[i].pte_page_offset, PAGE_SIZE))
			return -EINVAL;
		*pfn_out = (cxl_phys + meta[i].pte_page_offset) >> PAGE_SHIFT;
		return 0;
	}
	return -ENOENT;
}

static int cxlfork_prefault_shared_cxl(struct vm_area_struct *vma,
				       struct cxlfork_desc *desc,
				       const struct cxlfork_region_desc *r,
				       struct cxlfork_file_state *state)
{
	/* MoW 读共享路径：先校验 PTE image，再批量安装只读 CXL PFN 映射。 */
	struct cxlfork_pte_desc *pte_table = cxlfork_desc_ptes(desc);
	const struct cxlfork_leaf_pte_image *image;
	u64 validate_start = ktime_get_ns();
	u64 install_start;
	u64 i;
	int ret;

	if (!r->pages)
		return 0;
	if (!pte_table)
		return -EILSEQ;
	if (!desc->pte_image_offset ||
	    desc->pte_image_entries < r->pgoff_first + r->pages)
		return -EINVAL;
	image = cxl_ptr(desc->pte_image_offset);
	if (!image)
		return -EINVAL;
	for (i = 0; i < r->pages; i++) {
		const struct cxlfork_pte_desc *pte = &pte_table[r->pgoff_first + i];
		const struct cxlfork_leaf_pte_image *img = &image[r->pgoff_first + i];
		unsigned long pfn;

		if (pte->va != r->start + i * PAGE_SIZE || !cxl_ptr(pte->cxl_offset))
			return -EINVAL;
		if (img->va != pte->va || img->cxl_offset != pte->cxl_offset ||
		    img->orig_pteval != pte->orig_pteval ||
		    img->cxl_pteval != pte->cxl_pteval)
			return -EINVAL;
		if (pte_write(__pte(pte->cxl_pteval)))
			return -EINVAL;
		if (pte_young(__pte(pte->orig_pteval)) !=
		    pte_young(__pte(pte->cxl_pteval)))
			return -EINVAL;
		if (pte_dirty(__pte(pte->orig_pteval)) !=
		    pte_dirty(__pte(pte->cxl_pteval)))
			return -EINVAL;
		ret = cxlfork_find_pt_page_pfn(desc, pte->va, &pfn);
		if (ret || pfn != ((cxl_phys + pte->cxl_offset) >> PAGE_SHIFT))
			return -EINVAL;
	}
	if (state)
		state->pte_image_validate_ns += ktime_get_ns() - validate_start;

	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	install_start = ktime_get_ns();
	i = 0;
	while (i < r->pages) {
		const struct cxlfork_pte_desc *first = &pte_table[r->pgoff_first + i];
		unsigned long run_start = first->va;
		unsigned long run_pfn;
		u64 run_pages = 1;

		ret = cxlfork_find_pt_page_pfn(desc, first->va, &run_pfn);
		if (ret)
			return ret;
		while (i + run_pages < r->pages) {
			const struct cxlfork_pte_desc *pte =
				&pte_table[r->pgoff_first + i + run_pages];
			unsigned long pfn;

			if (pte->va != run_start + run_pages * PAGE_SIZE)
				break;
			ret = cxlfork_find_pt_page_pfn(desc, pte->va, &pfn);
			if (ret)
				return ret;
			if (pfn != run_pfn + run_pages)
				break;
			run_pages++;
		}
		ret = io_remap_pfn_range(vma, run_start, run_pfn,
					 run_pages * PAGE_SIZE,
					 prot_from_uapi(r->prot, true));
		if (ret)
			return ret;
		if (state)
			state->direct_pte_install_pages += run_pages;
		desc->shared_map_pages += run_pages;
		i += run_pages;
	}
	if (state)
		state->direct_pte_install_ns += ktime_get_ns() - install_start;
	return 0;
}

static int cxlfork_prefault_dirty_local(struct vm_area_struct *vma,
					struct cxlfork_desc *desc,
					const struct cxlfork_region_desc *r,
					struct cxlfork_file_state *state)
{
	struct cxlfork_pte_desc *pte_table = cxlfork_desc_ptes(desc);
	u64 start_ns = ktime_get_ns();
	u64 i;

	if (!pte_table)
		return -EILSEQ;
	for (i = 0; i < r->pages; i++) {
		struct cxlfork_pte_desc *pte = &pte_table[r->pgoff_first + i];
		struct page *page;
		void *dst;
		void *src;
		int ret;

		if (!pte_dirty(__pte(pte->orig_pteval)))
			continue;
		if (pte->va != r->start + i * PAGE_SIZE ||
		    !cxl_ptr(pte->cxl_offset))
			return -EINVAL;
		page = alloc_page(GFP_HIGHUSER);
		if (!page)
			return -ENOMEM;
		dst = kmap_local_page(page);
		src = cxl_ptr(pte->cxl_offset);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_local(dst);
		flush_dcache_page(page);
		ret = vm_insert_page(vma, pte->va, page);
		put_page(page);
		if (ret)
			return ret;
		desc->local_copy_pages++;
		if (state)
			state->dirty_prefault_pages++;
	}
	if (state)
		state->dirty_prefault_ns += ktime_get_ns() - start_ns;
	return 0;
}

static vm_fault_t cxlfork_fault(struct vm_fault *vmf)
{
	/* COW/tiering fault 主路径：MoW 读共享、MoA 首次访问复制、hybrid 按热页/写入复制。 */
	struct cxlfork_mapping *mapping = vmf->vma->vm_private_data;
	struct cxlfork_desc *desc;
	struct cxlfork_region_desc *regions;
	struct cxlfork_pte_desc *ptes;
	struct cxlfork_region_desc *r;
	struct cxlfork_pte_desc *pte;
	struct page *page;
	unsigned long addr;
	void *dst;
	void *src;
	u64 page_idx;
	int slot;

	if (!mapping)
		return VM_FAULT_SIGBUS;

	slot = key_to_slot(mapping->key);
	if (slot < 0)
		return VM_FAULT_SIGBUS;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != mapping->key ||
	    desc->state != CXLFORK_SLOT_READY ||
	    desc->generation != mapping->generation || !desc->ready ||
	    mapping->region_idx >= desc->nr_regions) {
		mutex_unlock(&cxlfork_lock);
		return VM_FAULT_SIGBUS;
	}

	regions = cxlfork_desc_regions(desc);
	ptes = cxlfork_desc_ptes(desc);
	if (!regions || !ptes) {
		mutex_unlock(&cxlfork_lock);
		return VM_FAULT_SIGBUS;
	}
	r = &regions[mapping->region_idx];
	addr = vmf->address & PAGE_MASK;
	if (addr < r->start || addr >= r->start + r->length) {
		mutex_unlock(&cxlfork_lock);
		return VM_FAULT_SIGBUS;
	}
	page_idx = (addr - r->start) >> PAGE_SHIFT;
	if (page_idx >= r->pages || r->pgoff_first + page_idx >= desc->nr_ptes) {
		mutex_unlock(&cxlfork_lock);
		return VM_FAULT_SIGBUS;
	}
	pte = &ptes[r->pgoff_first + page_idx];
	if (pte->va != addr || !cxl_ptr(pte->cxl_offset)) {
		mutex_unlock(&cxlfork_lock);
		return VM_FAULT_SIGBUS;
	}

	if (mapping->flags & CXLFORK_F_HYBRID_TIERING) {
		pte_t orig = __pte(pte->orig_pteval);

		if ((vmf->flags & FAULT_FLAG_WRITE) || pte_young(orig) ||
		    pte_dirty(orig))
			goto copy_local;
	}

	if (mapping->flags & (CXLFORK_F_SHARED_COW | CXLFORK_F_HYBRID_TIERING)) {
		vm_fault_t ret;

		ret = cxlfork_insert_shared_cxl(vmf, pte, addr);
		if (!(ret & VM_FAULT_ERROR)) {
			desc->faults++;
			desc->shared_map_pages++;
		}
		mutex_unlock(&cxlfork_lock);
		return ret;
	}

	/*
	 * Private COW/MoA mode: the child receives a local private copy on
	 * first access instead of sharing the CXL snapshot for reads.
	 */
copy_local:
	page = alloc_page(GFP_HIGHUSER);
	if (!page) {
		mutex_unlock(&cxlfork_lock);
		return VM_FAULT_OOM;
	}

	dst = kmap_local_page(page);
	src = cxl_ptr(pte->cxl_offset);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_local(dst);
	flush_dcache_page(page);
	desc->faults++;
	desc->local_copy_pages++;
	mutex_unlock(&cxlfork_lock);

	{
		vm_fault_t ret = vmf_insert_page(vmf->vma, addr, page);

		put_page(page);
		return ret;
	}
}

static void cxlfork_vma_open(struct vm_area_struct *vma)
{
	/* VMA 被复制/拆分时维护 mapping 引用计数。 */
	struct cxlfork_mapping *mapping = vma->vm_private_data;

	if (mapping)
		refcount_inc(&mapping->refs);
}

static void cxlfork_vma_close(struct vm_area_struct *vma)
{
	/* 最后一个 VMA 关闭时释放 mapping 上下文。 */
	struct cxlfork_mapping *mapping = vma->vm_private_data;

	if (!mapping)
		return;
	if (!refcount_dec_and_test(&mapping->refs))
		return;
	if (mapping->holds_slot_reader)
		cxlfork_slot_put_reader(mapping->key, mapping->generation);
	kfree(mapping);
}

static const struct vm_operations_struct cxlfork_vm_ops = {
	.open = cxlfork_vma_open,
	.fault = cxlfork_fault,
	.close = cxlfork_vma_close,
};

static int cxlfork_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* restore 时由 vm_mmap(file, ...) 进入；vm_pgoff 编码 region_idx。 */
	struct cxlfork_file_state *state = file->private_data;
	struct cxlfork_desc *desc;
	struct cxlfork_region_desc *regions;
	struct cxlfork_region_desc *r;
	struct cxlfork_mapping *mapping;
	u64 region_idx = vma->vm_pgoff / CXLFORK_REGION_PGOFF_STEP;
	u64 expected_pgoff = region_idx * CXLFORK_REGION_PGOFF_STEP;
	unsigned long len = vma->vm_end - vma->vm_start;
	int slot;
	int ret = 0;

	if (!state || !state->mmap_key)
		return -EINVAL;
	if (vma->vm_pgoff != expected_pgoff)
		return -EINVAL;

	slot = key_to_slot(state->mmap_key);
	if (slot < 0)
		return slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != state->mmap_key ||
	    desc->state != CXLFORK_SLOT_READY ||
	    desc->generation != state->mmap_generation ||
	    !desc->ready || region_idx >= desc->nr_regions) {
		ret = -ENOENT;
		goto out_unlock;
	}

	regions = cxlfork_desc_regions(desc);
	if (!regions) {
		ret = -EILSEQ;
		goto out_unlock;
	}
	r = &regions[region_idx];
	if (len != r->length || vma->vm_start != r->start) {
		ret = -EINVAL;
		goto out_unlock;
	}

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	mapping->key = state->mmap_key;
	mapping->generation = state->mmap_generation;
	mapping->region_idx = region_idx;
	mapping->flags = state->mmap_flags;
	mapping->tiering_hot_stride_pages = state->tiering_hot_stride_pages;
	refcount_set(&mapping->refs, 1);
	ret = cxlfork_slot_get_reader_locked(desc, mapping->key,
					     mapping->generation);
	if (ret) {
		kfree(mapping);
		goto out_unlock;
	}
	mapping->holds_slot_reader = true;

	if (mapping->flags & CXLFORK_F_SHARED_COW)
		ret = cxlfork_prefault_shared_cxl(vma, desc, r, state);
	else {
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP);
		if (mapping->flags & CXLFORK_F_HYBRID_TIERING)
			ret = cxlfork_prefault_dirty_local(vma, desc, r, state);
	}
	if (ret) {
		if (mapping->holds_slot_reader)
			cxlfork_slot_put_reader_locked(desc, mapping->key,
						       mapping->generation);
		kfree(mapping);
		goto out_unlock;
	}
	vma->vm_ops = &cxlfork_vm_ops;
	vma->vm_private_data = mapping;

out_unlock:
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static int cxlfork_ioctl_restore(struct file *file,
				 struct cxlfork_restore __user *uarg)
{
	/* resume 主路径：校验 CXL 镜像 -> mmap regions -> 可选应用 OS metadata -> 回填 breakdown。 */
	struct cxlfork_restore *op;
	struct cxlfork_file_state *state = file->private_data;
	struct cxlfork_desc *desc = NULL;
	u64 start_ns;
	bool readonly;
	bool private_cow;
	bool shared_cow;
	bool hybrid_tiering;
	bool apply_mm_state;
	bool reopen_fds;
	bool apply_global_state;
	bool apply_thread_state;
	bool apply_tls_state;
	struct cxlfork_restore_breakdown bd = {};
	struct cxlfork_region_desc *regions;
	u64 nr_fds_restored = 0;
	u64 generation = 0;
	bool restore_reader = false;
	int slot;
	int ret = 0;
	int i;

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return -ENOMEM;
	if (copy_from_user(op, uarg, sizeof(*op))) {
		ret = -EFAULT;
		goto out_free;
	}
	if (!op->key) {
		ret = -EINVAL;
		goto out_free;
	}

	slot = key_to_slot(op->key);
	if (slot < 0) {
		ret = slot;
		goto out_free;
	}

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != op->key ||
	    desc->state != CXLFORK_SLOT_READY || !desc->ready) {
		ret = -ENOENT;
		goto out_unlock;
	}
	generation = desc->generation;
	ret = cxlfork_slot_get_reader_locked(desc, op->key, generation);
	if (ret)
		goto out_unlock;
	restore_reader = true;

	start_ns = ktime_get_ns();
	readonly = op->flags & CXLFORK_F_MAP_READONLY;
	private_cow = op->flags & CXLFORK_F_PRIVATE_COW;
	shared_cow = op->flags & CXLFORK_F_SHARED_COW;
	hybrid_tiering = op->flags & CXLFORK_F_HYBRID_TIERING;
	apply_mm_state = op->flags & CXLFORK_F_APPLY_MM_STATE;
	reopen_fds = op->flags & CXLFORK_F_REOPEN_FDS;
	apply_global_state = op->flags & CXLFORK_F_APPLY_GLOBAL_STATE;
	apply_thread_state = op->flags & CXLFORK_F_APPLY_THREAD_STATE;
	apply_tls_state = op->flags & CXLFORK_F_APPLY_TLS_STATE;
	if ((private_cow + shared_cow + hybrid_tiering) > 1) {
		ret = -EINVAL;
		goto out_unlock;
	}
	ret = cxlfork_validate_vma_tree_image(desc, &bd.vma_tree_validate_ns);
	if (ret)
		goto out_unlock;
	ret = cxlfork_validate_state_image(desc, &bd.state_image_validate_ns);
	if (ret)
		goto out_unlock;
	ret = cxlfork_validate_pt_page_image(desc,
					       &bd.pt_page_image_validate_ns);
	if (ret)
		goto out_unlock;
	ret = cxlfork_validate_private_rebase_image(desc,
						   &bd.private_rebase_validate_ns);
	if (ret)
		goto out_unlock;
	regions = cxlfork_desc_regions(desc);
	if (!regions) {
		ret = -EILSEQ;
		goto out_unlock;
	}
	if ((private_cow || shared_cow || hybrid_tiering) && state) {
		state->mmap_key = desc->key;
		state->mmap_generation = generation;
		state->mmap_flags = op->flags;
		state->tiering_hot_stride_pages = op->tiering_hot_stride_pages;
		state->pte_image_validate_ns = 0;
		state->state_image_validate_ns = bd.state_image_validate_ns;
		state->direct_pte_install_ns = 0;
		state->direct_pte_install_pages = 0;
		state->dirty_prefault_ns = 0;
		state->dirty_prefault_pages = 0;
	}
	mutex_unlock(&cxlfork_lock);
	for (i = 0; i < desc->nr_regions; i++) {
		u64 map_start = ktime_get_ns();

		if (shared_cow) {
			ret = cxlfork_map_region_shared_leaf(desc, &regions[i],
							     CXLFORK_F_SHARED_COW,
							     true, &bd);
			if (ret == -EOPNOTSUPP)
				ret = cxlfork_map_region_cow(file, &regions[i],
							     i, false);
		} else if (private_cow || hybrid_tiering) {
			ret = cxlfork_map_region_cow(file, &regions[i], i,
						     private_cow);
		} else if (readonly) {
			ret = cxlfork_map_region_shared_leaf(desc, &regions[i],
							     CXLFORK_F_MAP_READONLY,
							     false, &bd);
			if (ret == -EOPNOTSUPP)
				ret = cxlfork_map_region(desc, &regions[i],
							 readonly, &bd);
		} else {
			ret = cxlfork_map_region(desc, &regions[i],
						 readonly, &bd);
		}
		if (!ret && shared_cow) {
			bd.pte_image_reconstruct_ns += ktime_get_ns() - map_start;
			bd.pte_image_reconstruct_pages += regions[i].pages;
		}
		if (ret)
			break;
	}
	mutex_lock(&cxlfork_lock);
	if ((private_cow || shared_cow || hybrid_tiering) && state) {
		bd.pte_image_validate_ns += state->pte_image_validate_ns;
		bd.direct_pte_install_ns += state->direct_pte_install_ns;
		bd.direct_pte_install_pages += state->direct_pte_install_pages;
		bd.dirty_prefault_ns += state->dirty_prefault_ns;
		bd.dirty_prefault_pages += state->dirty_prefault_pages;
		state->mmap_key = 0;
		state->mmap_generation = 0;
		state->mmap_flags = 0;
		state->tiering_hot_stride_pages = 0;
		state->pte_image_validate_ns = 0;
		state->direct_pte_install_ns = 0;
		state->direct_pte_install_pages = 0;
		state->dirty_prefault_ns = 0;
		state->dirty_prefault_pages = 0;
	}
	if (ret)
		goto out_unlock;
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != op->key ||
	    desc->state != CXLFORK_SLOT_READY ||
	    desc->generation != generation || !desc->ready) {
		ret = -ENOENT;
		goto out_unlock;
	}
	if (apply_mm_state)
		cxlfork_apply_mm_state(desc);
	if (apply_global_state || reopen_fds) {
		u64 global_start = ktime_get_ns();

		if (apply_global_state)
			cxlfork_apply_global_state(desc);
		if (reopen_fds) {
			ret = cxlfork_reopen_fd_state(desc, &nr_fds_restored);
			if (ret)
				goto out_unlock;
		}
		bd.global_restore_ns = ktime_get_ns() - global_start;
	}
	memset(op, 0, sizeof(*op));
	op->key = desc->key;
	op->nr_regions = desc->nr_regions;
	op->nr_ptes = desc->nr_ptes;
	op->total_pages = desc->total_pages;
	op->anon_pages = desc->anon_pages;
	op->clean_file_pages = desc->clean_file_pages;
	op->dirty_file_pages = desc->dirty_file_pages;
	op->restore_ns = ktime_get_ns() - start_ns;
	cxlfork_copy_mm_state_to_restore(op, desc);
	op->nr_fds_restored = nr_fds_restored;
	op->global_restore_ns = bd.global_restore_ns;
	op->global_attach_ns = bd.global_restore_ns;
	op->pte_attach_ns = bd.pte_image_reconstruct_ns;
	op->pte_attach_pages = bd.pte_image_reconstruct_pages;
	op->direct_pte_install_ns = bd.direct_pte_install_ns;
	op->direct_pte_install_pages = bd.direct_pte_install_pages;
	op->pte_image_validate_ns = bd.pte_image_validate_ns;
	op->pt_page_image_validate_ns = bd.pt_page_image_validate_ns;
	op->vma_tree_validate_ns = bd.vma_tree_validate_ns;
	op->state_image_validate_ns = bd.state_image_validate_ns;
	op->private_rebase_validate_ns = bd.private_rebase_validate_ns;
	op->pte_image_reconstruct_ns = bd.pte_image_reconstruct_ns;
	op->pte_image_reconstruct_pages = bd.pte_image_reconstruct_pages;
	op->shared_leaf_attach_ns = bd.shared_leaf_attach_ns;
	op->shared_leaf_attach_pages = bd.shared_leaf_attach_pages;
	op->dirty_prefault_ns = bd.dirty_prefault_ns;
	op->dirty_prefault_pages = bd.dirty_prefault_pages;
	cxlfork_capture_namespace_state(&op->restore_ns_state);
	for (i = 0; i < desc->nr_regions; i++) {
		op->regions[i].start = regions[i].start;
		op->regions[i].length = regions[i].length;
		op->regions[i].prot = regions[i].prot;
		op->regions[i].flags = regions[i].flags;
		op->regions[i].pages = regions[i].pages;
	}
	if (copy_to_user(uarg, op, sizeof(*op))) {
		ret = -EFAULT;
		goto out_unlock;
	}
	if (apply_thread_state) {
		ret = cxlfork_validate_thread_state(&desc->thread_state);
		if (ret)
			goto out_unlock;
	}
	if (apply_tls_state)
		cxlfork_apply_tls_state(desc);
	if (apply_thread_state)
		ret = cxlfork_apply_thread_state(desc);

out_unlock:
	if (restore_reader && desc && cxlfork_desc_key_ready(desc, op->key) &&
	    desc->generation == generation)
		cxlfork_slot_put_reader_locked(desc, op->key, generation);
	mutex_unlock(&cxlfork_lock);
out_free:
	kfree(op);
	return ret;
}

static int cxlfork_check_v2_header(const void __user *uarg, size_t min_size)
{
	const struct cxlfork_v2_header __user *header = uarg;
	u32 size;
	u16 version;
	u16 reserved;

	if (get_user(size, &header->size) ||
	    get_user(version, &header->abi_version) ||
	    get_user(reserved, &header->reserved))
		return -EFAULT;
	if (size < min_size)
		return -EINVAL;
	if (version != CXLFORK_ABI_VERSION_V2)
		return -EPROTONOSUPPORT;
	if (reserved)
		return -EINVAL;
	return 0;
}

static int cxlfork_ioctl_query_caps_v2(struct cxlfork_query_caps_v2 __user *uarg)
{
	struct cxlfork_query_caps_v2 caps;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(caps));
	if (ret)
		return ret;
	memset(&caps, 0, sizeof(caps));
	caps.size = sizeof(caps);
	caps.abi_version = CXLFORK_ABI_VERSION_V2;
	caps.capabilities = CXLFORK_CAP_V2_ABI |
		CXLFORK_CAP_PTE_IMAGE_RECONSTRUCTION |
		CXLFORK_CAP_REAL_SHARED_PTE_LEAF |
		CXLFORK_CAP_PTE_LEAF_COW |
		CXLFORK_CAP_VMA_IMAGE_RECONSTRUCTION |
		CXLFORK_CAP_REAL_SHARED_VMA_LEAF |
		CXLFORK_CAP_MOW_DATA_COW |
		CXLFORK_CAP_MOA_DATA_COPY |
		CXLFORK_CAP_CONSISTENT_SINGLE_THREAD |
		CXLFORK_CAP_RELIABLE_SLOT_GENERATION |
		CXLFORK_CAP_USER_THREAD_CONTEXT_RESUME |
		CXLFORK_CAP_GLOBAL_FILE_STATE |
		CXLFORK_CAP_A_BIT_HYBRID;
	caps.cxl_phys = cxl_phys;
	caps.cxl_size = cxl_size;
	caps.slot_bytes = CXLFORK_SLOT_BYTES;
	caps.data_offset = CXLFORK_DATA_OFFSET;
	caps.page_size = PAGE_SIZE;
	caps.max_slots = CXLFORK_MAX_SLOTS;
	caps.max_regions = CXLFORK_MAX_REGIONS;
	caps.max_ptes = CXLFORK_MAX_PTES;
	caps.descriptor_version = CXLFORK_DESC_VERSION;
	return copy_to_user(uarg, &caps, sizeof(caps)) ? -EFAULT : 0;
}

static int cxlfork_mark_one_pte(struct mm_struct *mm, unsigned long addr,
				u64 flags)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t pte;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -EFAULT;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -EFAULT;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return -EFAULT;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_trans_huge(*pmd))
		return -EOPNOTSUPP;
	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!ptep)
		return -EFAULT;
	pte = *ptep;
	if (!pte_present(pte)) {
		pte_unmap_unlock(ptep, ptl);
		return -EFAULT;
	}
	if (flags & CXLFORK_PTE_MARK_CLEAR_ACCESSED)
		pte = pte_mkold(pte);
	if (flags & CXLFORK_PTE_MARK_CLEAR_DIRTY)
		pte = pte_mkclean(pte);
	if (flags & CXLFORK_PTE_MARK_SET_ACCESSED)
		pte = pte_mkyoung(pte);
	if (flags & CXLFORK_PTE_MARK_SET_DIRTY)
		pte = pte_mkdirty(pte);
	set_pte_at(mm, addr, ptep, pte);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}

static int cxlfork_ioctl_pte_mark_v2(struct cxlfork_pte_mark_v2 __user *uarg)
{
	struct cxlfork_pte_mark_v2 mark;
	unsigned long start;
	unsigned long end;
	unsigned long addr;
	int ret = 0;

	ret = cxlfork_check_v2_header(uarg, sizeof(mark));
	if (ret)
		return ret;
	if (copy_from_user(&mark, uarg, sizeof(mark)))
		return -EFAULT;
	if (mark.reserved1 || (mark.flags & ~CXLFORK_PTE_MARK_KNOWN_MASK))
		return -EINVAL;
	if (!mark.length || !PAGE_ALIGNED(mark.start) ||
	    !PAGE_ALIGNED(mark.length))
		return -EINVAL;
	if (check_add_overflow((unsigned long)mark.start,
			       (unsigned long)mark.length, &end) ||
	    end <= mark.start)
		return -EINVAL;
	start = (unsigned long)mark.start;

	mmap_write_lock(current->mm);
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		ret = cxlfork_mark_one_pte(current->mm, addr, mark.flags);
		if (ret)
			break;
	}
	flush_tlb_mm_range(current->mm, start, end, PAGE_SHIFT, false);
	mmap_write_unlock(current->mm);
	return ret;
}

static int cxlfork_ioctl_inspect_v2(struct cxlfork_inspect_v2 __user *uarg)
{
	struct cxlfork_inspect_v2 inspect;
	struct cxlfork_desc *desc;
	u64 key;
	u64 address;
	u64 observed_page = 0;
	u64 observed_leaf = 0;
	u64 current_pte = 0;
	struct cxlfork_pte_desc *ptes;
	u64 i;
	int slot;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(inspect));
	if (ret)
		return ret;
	if (copy_from_user(&inspect, uarg, sizeof(inspect)))
		return -EFAULT;
	key = inspect.key;
	address = inspect.address & PAGE_MASK;
	if (!key)
		return -EINVAL;
	slot = key_to_slot(key);
	if (slot < 0)
		return slot;

	memset(&inspect, 0, sizeof(inspect));
	inspect.size = sizeof(inspect);
	inspect.abi_version = CXLFORK_ABI_VERSION_V2;
	inspect.key = key;
	inspect.address = address;
	inspect.slot = slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!cxlfork_desc_key_ready(desc, key)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	inspect.state = READ_ONCE(desc->state);
	inspect.generation = READ_ONCE(desc->generation);
	inspect.reader_count = READ_ONCE(desc->reader_count);
	smp_rmb();
	if (desc->slot != slot || desc->nr_regions > CXLFORK_MAX_REGIONS ||
	    desc->nr_ptes > CXLFORK_MAX_PTES ||
	    desc->image_bytes > CXLFORK_SLOT_BYTES) {
		ret = -EILSEQ;
		goto out_unlock;
	}
	ret = cxlfork_compute_checksums(desc, &observed_page, &observed_leaf);
	if (ret)
		goto out_unlock;
	ptes = cxlfork_desc_ptes(desc);
	if (desc->nr_ptes && !ptes) {
		ret = -EILSEQ;
		goto out_unlock;
	}

	inspect.nr_regions = desc->nr_regions;
	inspect.nr_ptes = desc->nr_ptes;
	inspect.total_pages = desc->total_pages;
	inspect.image_bytes = desc->image_bytes;
	inspect.page_checksum = desc->page_checksum;
	inspect.observed_page_checksum = observed_page;
	inspect.leaf_checksum = desc->leaf_checksum;
	inspect.observed_leaf_checksum = observed_leaf;
	inspect.shared_map_pages = desc->shared_map_pages;
	inspect.local_copy_pages = desc->local_copy_pages;
	inspect.leaf_copy_pages = desc->leaf_copy_pages;
	if (desc->nr_ptes) {
		inspect.flags |= CXLFORK_INSPECT_F_PAGE_CHECKSUM_VALID |
			CXLFORK_INSPECT_F_LEAF_CHECKSUM_VALID;
	}
	if (desc->page_checksum != observed_page ||
	    desc->leaf_checksum != observed_leaf)
		inspect.flags |= CXLFORK_INSPECT_F_CHECKSUM_MISMATCH;

	if (address) {
		unsigned long leaf_pfn;
		unsigned long current_pmd_pfn;

		for (i = 0; i < desc->nr_ptes; i++) {
			const struct cxlfork_pte_desc *pte = &ptes[i];

			if (pte->va != address)
				continue;
			inspect.shared_pfn =
				(cxl_phys + pte->cxl_offset) >> PAGE_SHIFT;
			inspect.orig_pte = pte->orig_pteval;
			inspect.flags |= CXLFORK_INSPECT_F_ORIG_PTE_VALID;
			break;
		}
		if (!cxlfork_find_shared_leaf_pfn(desc, address, &leaf_pfn)) {
			inspect.shared_leaf_pfn = leaf_pfn;
			inspect.flags |= CXLFORK_INSPECT_F_SHARED_LEAF_VALID;
		}
		cxlfork_probe_cxl_vma_maple(desc, address, &inspect);
		mmap_read_lock(current->mm);
		ret = cxlfork_read_pmd_snapshot(current->mm, address,
						&inspect.current_pmd,
						&current_pmd_pfn);
		if (!ret) {
			inspect.current_pmd_pfn = current_pmd_pfn;
			inspect.flags |= CXLFORK_INSPECT_F_CURRENT_PMD_VALID;
		}
		ret = cxlfork_read_orig_pteval(current->mm, address, &current_pte);
		mmap_read_unlock(current->mm);
		if (!ret) {
			inspect.current_pte = current_pte;
			inspect.current_pfn = pte_pfn(__pte(current_pte));
			inspect.flags |= CXLFORK_INSPECT_F_CURRENT_PTE_VALID;
		}
		ret = 0;
	}

	ret = copy_to_user(uarg, &inspect, sizeof(inspect)) ? -EFAULT : 0;

out_unlock:
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static int cxlfork_ioctl_stats(struct cxlfork_stats __user *uarg)
{
	/* benchmark 用它读取 faults 计数，比较 MoW/MoA/hybrid 的访问行为。 */
	struct cxlfork_stats st;
	struct cxlfork_desc *desc;
	int slot;

	if (copy_from_user(&st, uarg, sizeof(st)))
		return -EFAULT;
	slot = key_to_slot(st.key);
	if (slot < 0)
		return slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!cxlfork_desc_key_ready(desc, st.key)) {
		mutex_unlock(&cxlfork_lock);
		return -ENOENT;
	}
	st.ready = desc->ready;
	st.slot = desc->slot;
	st.nr_regions = desc->nr_regions;
	st.nr_ptes = desc->nr_ptes;
	st.total_pages = desc->total_pages;
	st.anon_pages = desc->anon_pages;
	st.clean_file_pages = desc->clean_file_pages;
	st.dirty_file_pages = desc->dirty_file_pages;
	st.faults = desc->faults;
	mutex_unlock(&cxlfork_lock);

	return copy_to_user(uarg, &st, sizeof(st)) ? -EFAULT : 0;
}

static int cxlfork_ioctl_release(struct cxlfork_release __user *uarg)
{
	/* 清空指定 key 的 slot，下一次 prepare 会重新写入完整镜像。 */
	struct cxlfork_release rel;
	struct cxlfork_desc *desc;
	int slot;

	if (copy_from_user(&rel, uarg, sizeof(rel)))
		return -EFAULT;
	slot = key_to_slot(rel.key);
	if (slot < 0)
		return slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (cxlfork_desc_key_ready(desc, rel.key)) {
		u64 generation = desc->generation;

		if (cmpxchg(&desc->state, (u64)CXLFORK_SLOT_READY,
			    (u64)CXLFORK_SLOT_RELEASING) != CXLFORK_SLOT_READY) {
			mutex_unlock(&cxlfork_lock);
			return -EBUSY;
		}
		if (desc->reader_count) {
			WRITE_ONCE(desc->state, CXLFORK_SLOT_READY);
			mutex_unlock(&cxlfork_lock);
			return -EBUSY;
		}
		memset(desc, 0, sizeof(*desc));
		desc->generation = generation;
	}
	mutex_unlock(&cxlfork_lock);
	return 0;
}

static int cxlfork_open(struct inode *inode, struct file *file)
{
	/* 为每个 fd 分配 restore/mmap 临时状态。 */
	struct cxlfork_file_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	file->private_data = state;
	return 0;
}

#if 0 /* retained only as an audit diff while the duplicate prototype is removed */
static int cxlfork_ioctl_inspect_v2_unused(struct cxlfork_inspect_v2 __user *uarg)
{
	struct cxlfork_inspect_v2 inspect;
	struct cxlfork_desc *desc;
	u64 key;
	u64 address;
	u64 observed_page = 0;
	u64 observed_leaf = 0;
	u64 current_pte = 0;
	struct cxlfork_pte_desc *ptes;
	u64 i;
	int slot;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(inspect));
	if (ret)
		return ret;
	if (copy_from_user(&inspect, uarg, sizeof(inspect)))
		return -EFAULT;
	key = inspect.key;
	address = inspect.address & PAGE_MASK;
	if (!key)
		return -EINVAL;
	slot = key_to_slot(key);
	if (slot < 0)
		return slot;

	memset(&inspect, 0, sizeof(inspect));
	inspect.size = sizeof(inspect);
	inspect.abi_version = CXLFORK_ABI_VERSION_V2;
	inspect.key = key;
	inspect.address = address;
	inspect.slot = slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!desc || READ_ONCE(desc->magic) != CXLFORK_DESC_MAGIC ||
	    READ_ONCE(desc->version) != CXLFORK_DESC_VERSION ||
	    READ_ONCE(desc->key) != key) {
		mutex_unlock(&cxlfork_lock);
		return -ENOENT;
	}
	inspect.state = READ_ONCE(desc->ready) ? CXLFORK_SLOT_READY :
		CXLFORK_SLOT_WRITING;
	if (inspect.state != CXLFORK_SLOT_READY) {
		mutex_unlock(&cxlfork_lock);
		return -EAGAIN;
	}
	smp_rmb();
	if (desc->slot != slot || desc->nr_regions > CXLFORK_MAX_REGIONS ||
	    desc->nr_ptes > CXLFORK_MAX_PTES ||
	    desc->image_bytes > CXLFORK_SLOT_BYTES) {
		mutex_unlock(&cxlfork_lock);
		return -EILSEQ;
	}
	ret = cxlfork_compute_checksums(desc, &observed_page, &observed_leaf);
	if (ret) {
		mutex_unlock(&cxlfork_lock);
		return ret;
	}
	ptes = cxlfork_desc_ptes(desc);
	if (desc->nr_ptes && !ptes) {
		mutex_unlock(&cxlfork_lock);
		return -EILSEQ;
	}

	inspect.nr_regions = desc->nr_regions;
	inspect.nr_ptes = desc->nr_ptes;
	inspect.total_pages = desc->total_pages;
	inspect.image_bytes = desc->image_bytes;
	inspect.page_checksum = desc->page_checksum;
	inspect.observed_page_checksum = observed_page;
	inspect.leaf_checksum = desc->leaf_checksum;
	inspect.observed_leaf_checksum = observed_leaf;
	inspect.shared_map_pages = desc->shared_map_pages;
	inspect.local_copy_pages = desc->local_copy_pages;
	inspect.leaf_copy_pages = desc->leaf_copy_pages;
	if (desc->nr_ptes)
		inspect.flags |= CXLFORK_INSPECT_F_PAGE_CHECKSUM_VALID |
			CXLFORK_INSPECT_F_LEAF_CHECKSUM_VALID;
	if (desc->page_checksum != observed_page ||
	    desc->leaf_checksum != observed_leaf)
		inspect.flags |= CXLFORK_INSPECT_F_CHECKSUM_MISMATCH;

	if (address) {
		unsigned long leaf_pfn;
		unsigned long current_pmd_pfn;

		for (i = 0; i < desc->nr_ptes; i++) {
			const struct cxlfork_pte_desc *pte = &ptes[i];

			if (pte->va != address)
				continue;
			inspect.shared_pfn =
				(cxl_phys + pte->cxl_offset) >> PAGE_SHIFT;
			break;
		}
		if (!cxlfork_find_shared_leaf_pfn(desc, address, &leaf_pfn)) {
			inspect.shared_leaf_pfn = leaf_pfn;
			inspect.flags |= CXLFORK_INSPECT_F_SHARED_LEAF_VALID;
		}
		cxlfork_probe_cxl_vma_maple(desc, address, &inspect);
		mmap_read_lock(current->mm);
		ret = cxlfork_read_pmd_snapshot(current->mm, address,
						&inspect.current_pmd,
						&current_pmd_pfn);
		if (!ret) {
			inspect.current_pmd_pfn = current_pmd_pfn;
			inspect.flags |= CXLFORK_INSPECT_F_CURRENT_PMD_VALID;
		}
		ret = cxlfork_read_orig_pteval(current->mm, address, &current_pte);
		mmap_read_unlock(current->mm);
		if (!ret) {
			inspect.current_pte = current_pte;
			inspect.current_pfn = pte_pfn(__pte(current_pte));
			inspect.flags |= CXLFORK_INSPECT_F_CURRENT_PTE_VALID;
		}
	}

	mutex_unlock(&cxlfork_lock);
	return copy_to_user(uarg, &inspect, sizeof(inspect)) ? -EFAULT : 0;
}
#endif

static int cxlfork_release_file(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	file->private_data = NULL;
	return 0;
}

static long cxlfork_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* ioctl 分发：FORK_PREPARE/FORK_RESUME 是当前复现主线使用的接口。 */
	switch (cmd) {
	case CXLFORK_CHECKPOINT:
	case CXLFORK_FORK_PREPARE:
		return cxlfork_ioctl_checkpoint((void __user *)arg);
	case CXLFORK_RESTORE:
	case CXLFORK_FORK_RESUME:
		return cxlfork_ioctl_restore(file, (void __user *)arg);
	case CXLFORK_STATS:
		return cxlfork_ioctl_stats((void __user *)arg);
	case CXLFORK_RELEASE:
		return cxlfork_ioctl_release((void __user *)arg);
	case CXLFORK_QUERY_CAPS_V2:
		return cxlfork_ioctl_query_caps_v2((void __user *)arg);
	case CXLFORK_INSPECT_V2:
		return cxlfork_ioctl_inspect_v2((void __user *)arg);
	case CXLFORK_PTE_MARK_V2:
		return cxlfork_ioctl_pte_mark_v2((void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations cxlfork_fops = {
	.owner = THIS_MODULE,
	.open = cxlfork_open,
	.release = cxlfork_release_file,
	.unlocked_ioctl = cxlfork_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.mmap = cxlfork_mmap,
};

static int __init cxlfork_init(void)
{
	/* 模块初始化：映射共享 CXL window，并注册 /dev/cxlfork 字符设备。 */
	int ret;

	if (cxl_size < (u64)CXLFORK_DATA_OFFSET +
		       (u64)CXLFORK_MAX_SLOTS * (u64)CXLFORK_SLOT_BYTES)
		return -EINVAL;

	cxlfork_cxl = ioremap_cache(cxl_phys, cxl_size);
	if (!cxlfork_cxl)
		return -ENOMEM;

	ret = alloc_chrdev_region(&cxlfork_devt, 0, 1, CXLFORK_NAME);
	if (ret)
		goto out_unmap;

	cdev_init(&cxlfork_cdev, &cxlfork_fops);
	ret = cdev_add(&cxlfork_cdev, cxlfork_devt, 1);
	if (ret)
		goto out_chrdev;

	cxlfork_class = class_create(CXLFORK_NAME);
	if (IS_ERR(cxlfork_class)) {
		ret = PTR_ERR(cxlfork_class);
		goto out_cdev;
	}
	device_create(cxlfork_class, NULL, cxlfork_devt, NULL, CXLFORK_NAME);
	pr_info("cxlfork: mapped CXL phys=%pa size=%lu\n", &cxl_phys, cxl_size);
	return 0;

out_cdev:
	cdev_del(&cxlfork_cdev);
out_chrdev:
	unregister_chrdev_region(cxlfork_devt, 1);
out_unmap:
	iounmap(cxlfork_cxl);
	return ret;
}

static void __exit cxlfork_exit(void)
{
	device_destroy(cxlfork_class, cxlfork_devt);
	class_destroy(cxlfork_class);
	cdev_del(&cxlfork_cdev);
	unregister_chrdev_region(cxlfork_devt, 1);
	iounmap(cxlfork_cxl);
}

module_init(cxlfork_init);
module_exit(cxlfork_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CXLfork shared CXL checkpoint/restore prototype");
