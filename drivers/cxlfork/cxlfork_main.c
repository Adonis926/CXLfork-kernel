// SPDX-License-Identifier: GPL-2.0
#include <linux/cdev.h>
#include <linux/capability.h>
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
#include <linux/kref.h>
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
#include <linux/xarray.h>
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
static DEFINE_XARRAY(cxlfork_restore_contexts);
static atomic64_t cxlfork_next_restore_id = ATOMIC64_INIT(0);

#ifdef CONFIG_CXLFORK_SELFTEST
struct cxlfork_litmus_shared {
	u64 magic;
	u64 run_id;
	u64 counter;
	u64 completions;
	u64 errors;
	u64 sequence;
	u64 acknowledgement;
	u64 token;
	u64 payload[CXLFORK_LITMUS_PAYLOAD_WORDS];
};
#endif

static int key_to_slot(u64 key);
static struct cxlfork_desc *slot_desc(u64 slot);
static bool cxlfork_slot_has_room(u64 slot, u64 off, u64 bytes);
static int cxlfork_slot_mark_alloc(struct cxlfork_desc *desc, u64 off, u64 bytes);
static const struct file_operations cxlfork_fops;
static const struct vm_operations_struct cxlfork_vm_ops;
static int cxlfork_find_shared_leaf_pfn(const struct cxlfork_desc *desc,
					unsigned long addr,
					unsigned long *pfn_out);

#define CXLFORK_LIFECYCLE_STATE_MASK 0xffULL
#define CXLFORK_LIFECYCLE_READER_SHIFT 8
#define CXLFORK_LIFECYCLE_READER_ONE (1ULL << CXLFORK_LIFECYCLE_READER_SHIFT)
#define CXLFORK_LIFECYCLE_MAX_READERS (U64_MAX >> CXLFORK_LIFECYCLE_READER_SHIFT)

static u64 cxlfork_lifecycle_pack(u32 state, u64 readers)
{
	return (readers << CXLFORK_LIFECYCLE_READER_SHIFT) | state;
}

static u32 cxlfork_lifecycle_state(u64 lifecycle)
{
	return lifecycle & CXLFORK_LIFECYCLE_STATE_MASK;
}

static u64 cxlfork_lifecycle_readers(u64 lifecycle)
{
	return lifecycle >> CXLFORK_LIFECYCLE_READER_SHIFT;
}

static void cxlfork_desc_reset_free(struct cxlfork_desc *desc, u64 generation)
{
	size_t state_off = offsetof(struct cxlfork_desc, state);
	size_t after_state = state_off + sizeof(desc->state);

	/* Keep RELEASING/WRITING visible until every other field is reset. */
	memset(desc, 0, state_off);
	memset((char *)desc + after_state, 0, sizeof(*desc) - after_state);
	desc->generation = generation;
	smp_store_release(&desc->state,
			  cxlfork_lifecycle_pack(CXLFORK_SLOT_FREE, 0));
}

struct cxlfork_checkpoint_sizing {
	u64 regions;
	u64 pages;
	u64 pmd_groups;
	u64 fd_table_bytes;
	u64 region_table_bytes;
	u64 pte_table_bytes;
	u64 estimated_bytes;
};

struct cxlfork_restore_ctx {
	struct kref ref;
	spinlock_t lock;
	u64 restore_id;
	u64 key;
	u64 generation;
	atomic_t mappings;
	bool reader_held;
	bool registered;
	atomic64_t faults;
	atomic64_t shared_map_pages;
	atomic64_t local_copy_pages;
	atomic64_t leaf_copy_pages;
	atomic64_t fault_dispatch_ns;
	atomic64_t leaf_materialize_ns;
	atomic64_t data_cow_ns;
	atomic64_t cxl_to_local_copy_ns;
	struct cxlfork_restore_stats_v2 stats;
	struct cxlfork_restore_stats_v3 stats_v3;
	struct cxlfork_restore_stats_v4 stats_v4;
};

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
	struct cxlfork_restore_ctx *mmap_ctx;
	struct cxlfork_restore_ctx *last_ctx;
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
	u64 manifest_validate_ns;
	u64 checksum_validate_ns;
	u64 address_conflict_ns;
	u64 lock_wait_ns;
	u64 lifecycle_ns;
	u64 vma_create_ns;
	u64 upper_pt_alloc_ns;
	u64 shared_leaf_count;
	u64 fallback_other_ns;
	u64 rollback_ns;
};

struct cxlfork_mapping {
	/* 绑定到用户 VMA 的状态，fault handler 用它定位 key、region 和 tiering policy。 */
	u64 key;
	u64 generation;
	u64 region_idx;
	u64 flags;
	u64 tiering_hot_stride_pages;
	refcount_t refs;
	struct cxlfork_restore_ctx *ctx;
};

static bool cxlfork_desc_key_ready(const struct cxlfork_desc *desc, u64 key)
{
	u64 lifecycle;

	if (!desc)
		return false;
	lifecycle = smp_load_acquire(&desc->state);
	return desc && READ_ONCE(desc->magic) == CXLFORK_DESC_MAGIC &&
		READ_ONCE(desc->version) == CXLFORK_DESC_VERSION &&
		READ_ONCE(desc->key) == key &&
		cxlfork_lifecycle_state(lifecycle) == CXLFORK_SLOT_READY &&
		READ_ONCE(desc->ready);
}

static bool cxlfork_desc_generation_matches(const struct cxlfork_desc *desc,
					    u64 generation)
{
	return READ_ONCE(desc->generation) == generation;
}

static void cxlfork_slot_put_reader_locked(struct cxlfork_desc *desc, u64 key,
					   u64 generation);

static int cxlfork_slot_get_reader_locked(struct cxlfork_desc *desc, u64 key,
					  u64 generation)
{
	u64 lifecycle;
	u64 readers;

	for (;;) {
		if (!cxlfork_desc_key_ready(desc, key))
			return -ENOENT;
		if (!cxlfork_desc_generation_matches(desc, generation))
			return -ESTALE;
		lifecycle = smp_load_acquire(&desc->state);
		if (cxlfork_lifecycle_state(lifecycle) != CXLFORK_SLOT_READY)
			return -EBUSY;
		readers = cxlfork_lifecycle_readers(lifecycle);
		if (readers == CXLFORK_LIFECYCLE_MAX_READERS)
			return -EOVERFLOW;
		if (cmpxchg(&desc->state, lifecycle,
			    lifecycle + CXLFORK_LIFECYCLE_READER_ONE) != lifecycle)
			continue;
		/* READY cannot be released while our packed reader is present. */
		if (likely(cxlfork_desc_generation_matches(desc, generation) &&
			   READ_ONCE(desc->key) == key))
			return 0;
		cxlfork_slot_put_reader_locked(desc, key, generation);
		return -ESTALE;
	}
}

static void cxlfork_slot_put_reader_locked(struct cxlfork_desc *desc, u64 key,
					   u64 generation)
{
	u64 lifecycle;
	u64 readers;

	if (!desc || READ_ONCE(desc->key) != key ||
	    !cxlfork_desc_generation_matches(desc, generation))
		return;
	for (;;) {
		lifecycle = READ_ONCE(desc->state);
		if (cxlfork_lifecycle_state(lifecycle) != CXLFORK_SLOT_READY)
			return;
		readers = cxlfork_lifecycle_readers(lifecycle);
		if (!readers)
			return;
		if (cmpxchg(&desc->state, lifecycle,
			    lifecycle - CXLFORK_LIFECYCLE_READER_ONE) == lifecycle)
			return;
	}
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

static void cxlfork_restore_ctx_free(struct kref *ref)
{
	struct cxlfork_restore_ctx *ctx =
		container_of(ref, struct cxlfork_restore_ctx, ref);

	kfree(ctx);
}

static void cxlfork_restore_ctx_get(struct cxlfork_restore_ctx *ctx)
{
	kref_get(&ctx->ref);
}

static void cxlfork_restore_ctx_put(struct cxlfork_restore_ctx *ctx)
{
	if (ctx)
		kref_put(&ctx->ref, cxlfork_restore_ctx_free);
}

static void cxlfork_restore_ctx_release_reader(struct cxlfork_restore_ctx *ctx)
{
	unsigned long flags;
	bool release = false;

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->reader_held) {
		ctx->reader_held = false;
		release = true;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	if (release)
		cxlfork_slot_put_reader(ctx->key, ctx->generation);
}

static struct cxlfork_restore_ctx *
cxlfork_restore_ctx_create(u64 key, u64 generation)
{
	struct cxlfork_restore_ctx *ctx;
	u64 restore_id;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);
	kref_init(&ctx->ref);
	spin_lock_init(&ctx->lock);
	ctx->key = key;
	ctx->generation = generation;
	ctx->reader_held = true;
	atomic_set(&ctx->mappings, 0);
	atomic64_set(&ctx->faults, 0);
	atomic64_set(&ctx->shared_map_pages, 0);
	atomic64_set(&ctx->local_copy_pages, 0);
	atomic64_set(&ctx->leaf_copy_pages, 0);
	atomic64_set(&ctx->fault_dispatch_ns, 0);
	atomic64_set(&ctx->leaf_materialize_ns, 0);
	atomic64_set(&ctx->data_cow_ns, 0);
	atomic64_set(&ctx->cxl_to_local_copy_ns, 0);
	restore_id = atomic64_inc_return(&cxlfork_next_restore_id);
	if (!restore_id)
		restore_id = atomic64_inc_return(&cxlfork_next_restore_id);
	ctx->restore_id = restore_id;

	/* The xarray owns a reference until slot release or failed restore. */
	cxlfork_restore_ctx_get(ctx);
	ret = xa_err(xa_store(&cxlfork_restore_contexts,
			      (unsigned long)restore_id, ctx, GFP_KERNEL));
	if (ret) {
		cxlfork_restore_ctx_put(ctx);
		cxlfork_restore_ctx_put(ctx);
		return ERR_PTR(ret);
	}
	ctx->registered = true;
	return ctx;
}

static void cxlfork_restore_ctx_unregister(struct cxlfork_restore_ctx *ctx)
{
	unsigned long flags;
	bool unregister = false;

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->registered) {
		ctx->registered = false;
		unregister = true;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	if (unregister) {
		xa_erase(&cxlfork_restore_contexts,
			 (unsigned long)ctx->restore_id);
		cxlfork_restore_ctx_put(ctx);
	}
}

static void cxlfork_restore_ctx_mapping_get(struct cxlfork_restore_ctx *ctx)
{
	cxlfork_restore_ctx_get(ctx);
	atomic_inc(&ctx->mappings);
}

static void cxlfork_restore_ctx_mapping_put(struct cxlfork_restore_ctx *ctx)
{
	if (atomic_dec_and_test(&ctx->mappings))
		cxlfork_restore_ctx_release_reader(ctx);
	cxlfork_restore_ctx_put(ctx);
}

static void cxlfork_file_set_restore_ctx(struct cxlfork_file_state *state,
					 struct cxlfork_restore_ctx *ctx)
{
	struct cxlfork_restore_ctx *old = state->last_ctx;

	if (ctx)
		cxlfork_restore_ctx_get(ctx);
	state->last_ctx = ctx;
	if (old)
		cxlfork_restore_ctx_put(old);
}

static void cxlfork_restore_ctx_purge(u64 key, u64 generation)
{
	struct cxlfork_restore_ctx *ctx;
	unsigned long index;

	xa_for_each(&cxlfork_restore_contexts, index, ctx) {
		if (ctx->key == key && ctx->generation == generation)
			cxlfork_restore_ctx_unregister(ctx);
	}
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

static int cxlfork_alloc_table(struct cxlfork_desc *desc, u64 slot, u64 *data_off, u64 entries,
			       u64 elem_size, u64 *offset, u64 *bytes)
{
	u64 table_bytes;
	void *table;
	int ret;

	if (check_mul_overflow(entries, elem_size, &table_bytes))
		return -ENOSPC;
	table_bytes = PAGE_ALIGN(table_bytes);
	if (!table_bytes)
		return -EINVAL;
	if (!cxlfork_slot_has_room(slot, *data_off, table_bytes))
		return -ENOSPC;
	ret = cxlfork_slot_mark_alloc(desc, *data_off, table_bytes);
	if (ret)
		return ret;
	table = cxl_ptr(*data_off);
	if (!table)
		return -ENOSPC;
	memset(table, 0, table_bytes);
	*offset = *data_off;
	*bytes = table_bytes;
	*data_off += table_bytes;
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

static u32 cxlfork_nr_slots(void)
{
	u64 available;
	u64 slots;

	if (cxl_size <= CXLFORK_DATA_OFFSET)
		return 0;
	available = cxl_size - CXLFORK_DATA_OFFSET;
	slots = available / CXLFORK_SLOT_BYTES;
	return min_t(u64, slots, CXLFORK_MAX_SLOTS);
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
	u32 nr_slots = cxlfork_nr_slots();
	u64 slot;
	u64 off;

	if (!nr_slots)
		return -ENOSPC;
	slot = key % nr_slots;
	off = slot_offset(slot);
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

	if (!desc || desc->slot >= cxlfork_nr_slots() || !bytes)
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
	if (!desc || slot >= cxlfork_nr_slots())
		return false;
	if (READ_ONCE(desc->magic) == CXLFORK_DESC_MAGIC &&
	    READ_ONCE(desc->version) == CXLFORK_DESC_VERSION &&
	    READ_ONCE(desc->slot) == slot &&
	    READ_ONCE(desc->extent_bytes) == CXLFORK_EXTENT_BYTES &&
	    READ_ONCE(desc->extent_count) == CXLFORK_EXTENTS_PER_SLOT &&
	    READ_ONCE(desc->extent_bitmap_words) == CXLFORK_EXTENT_BITMAP_WORDS &&
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

	if (slot >= cxlfork_nr_slots() || !bytes)
		return false;
	start = slot_offset(slot);
	end = start + CXLFORK_SLOT_BYTES;
	if (off < start || off >= end || bytes > end - off)
		return false;
	return cxl_range_valid(off, bytes);
}

static bool cxlfork_slot_extent_range(u64 slot, u64 off, u64 bytes,
				       u64 *first, u64 *count)
{
	u64 start;
	u64 rel;
	u64 end_rel;

	if (!cxlfork_slot_has_room(slot, off, bytes) ||
	    !IS_ALIGNED(off, CXLFORK_EXTENT_BYTES))
		return false;
	start = slot_offset(slot);
	rel = off - start;
	if (check_add_overflow(rel, bytes, &end_rel))
		return false;
	*first = rel >> CXLFORK_EXTENT_SHIFT;
	*count = DIV_ROUND_UP(end_rel, (u64)CXLFORK_EXTENT_BYTES) - *first;
	if (!*count || *first >= CXLFORK_EXTENTS_PER_SLOT ||
	    *count > CXLFORK_EXTENTS_PER_SLOT - *first)
		return false;
	return true;
}

static int cxlfork_slot_mark_alloc(struct cxlfork_desc *desc, u64 off, u64 bytes)
{
	u64 first;
	u64 count;
	u64 i;

	if (!desc || desc->extent_bytes != CXLFORK_EXTENT_BYTES ||
	    desc->extent_count != CXLFORK_EXTENTS_PER_SLOT ||
	    desc->extent_bitmap_words != CXLFORK_EXTENT_BITMAP_WORDS)
		return -EILSEQ;
	if (!cxlfork_slot_extent_range(desc->slot, off, bytes, &first, &count))
		return -ENOSPC;
	for (i = 0; i < count; i++) {
		u64 bit = first + i;
		u64 mask = BIT_ULL(bit & 63);

		if (desc->extent_bitmap[bit >> 6] & mask)
			return -EILSEQ;
	}
	for (i = 0; i < count; i++) {
		u64 bit = first + i;

		desc->extent_bitmap[bit >> 6] |= BIT_ULL(bit & 63);
	}
	desc->allocated_extents += count;
	return 0;
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

	if (!desc || desc->slot >= cxlfork_nr_slots() ||
	    desc->nr_regions > desc->region_table_entries ||
	    desc->nr_ptes > desc->pte_table_entries ||
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
	int ret;

	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!cxlfork_slot_has_room(slot, *data_off, PAGE_SIZE))
		return -ENOSPC;
	ret = cxlfork_slot_mark_alloc(desc, *data_off, PAGE_SIZE);
	if (ret)
		return ret;
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
					u64 slot,
					struct cxlfork_checkpoint_sizing *sizing)
{
	struct vm_area_struct *vma;
	unsigned long scan_start = op->scan_start;
	unsigned long scan_end = op->scan_end;
	u64 regions = 0;
	u64 pages = 0;
	u64 pmd_groups = 0;
	u64 bytes;
	u64 tmp;

	memset(sizing, 0, sizeof(*sizing));

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
	sizing->regions = regions;
	sizing->pages = pages;
	sizing->pmd_groups = pmd_groups;
	sizing->fd_table_bytes = PAGE_ALIGN(CXLFORK_MAX_FDS *
					    sizeof(struct cxlfork_fd_state));
	sizing->region_table_bytes = PAGE_ALIGN(regions *
						sizeof(struct cxlfork_region_desc));
	sizing->pte_table_bytes = PAGE_ALIGN(pages *
					     sizeof(struct cxlfork_pte_desc));
	if (check_add_overflow(bytes, sizing->fd_table_bytes, &bytes) ||
	    check_add_overflow(bytes, sizing->region_table_bytes, &bytes) ||
	    check_add_overflow(bytes, sizing->pte_table_bytes, &bytes))
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
	sizing->estimated_bytes = bytes;
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

	{
		u64 t = ktime_get_ns();

		ret = cxlfork_read_pte_snapshot(mm, addr, &pte_before,
						&pfn_before);
		desc->pte_walk_ns += ktime_get_ns() - t;
	}
	if (ret)
		return ret;
	if (!pte_present(__pte(pte_before)))
		return -EFAULT;

	{
		u64 t = ktime_get_ns();

		ret = get_user_pages_fast(addr, 1, 0, &page);
		desc->gup_ns += ktime_get_ns() - t;
	}
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

	{
		u64 t = ktime_get_ns();

		src = kmap_local_page(page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_local(src);
		desc->page_copy_ns += ktime_get_ns() - t;
	}

	{
		u64 t = ktime_get_ns();

		ret = cxlfork_read_pte_snapshot(mm, addr, &pte_after,
						&pfn_after);
		desc->pte_recheck_ns += ktime_get_ns() - t;
	}
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
	int ret;

	if (!desc->nr_ptes)
		return 0;
	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!ptes)
		return -EILSEQ;

	image_bytes = PAGE_ALIGN(desc->nr_ptes * sizeof(*image));
	if (!cxlfork_slot_has_room(slot, *data_off, image_bytes))
		return -ENOSPC;
	ret = cxlfork_slot_mark_alloc(desc, *data_off, image_bytes);
	if (ret)
		return ret;
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
	int ret;

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
	ret = cxlfork_slot_mark_alloc(desc, *data_off, bytes);
	if (ret)
		return ret;
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
	int ret;

	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!fds || !regions)
		return -EILSEQ;
	if (!cxlfork_slot_has_room(slot, *data_off, image_bytes))
		return -ENOSPC;
	ret = cxlfork_slot_mark_alloc(desc, *data_off, image_bytes);
	if (ret)
		return ret;
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
	ret = cxlfork_slot_mark_alloc(desc, *data_off, meta_bytes);
	if (ret)
		return ret;
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
	int ret;

	if (!cxlfork_desc_matches_slot(desc, slot))
		return -EILSEQ;
	if (!cxlfork_slot_has_room(slot, *data_off, image_bytes))
		return -ENOSPC;
	ret = cxlfork_slot_mark_alloc(desc, *data_off, image_bytes);
	if (ret)
		return ret;
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

/* Fast restore admission: validate only the sealed manifest and its bounds. */
static int cxlfork_validate_restore_manifest(const struct cxlfork_desc *desc)
{
	u64 bytes;

	if (!desc || !cxlfork_desc_matches_slot(desc, desc->slot) ||
	    !desc->key || !desc->generation || !desc->ready ||
	    cxlfork_lifecycle_state(smp_load_acquire(&desc->state)) !=
		CXLFORK_SLOT_READY ||
	    desc->nr_regions == 0 || desc->nr_regions > CXLFORK_MAX_REGIONS ||
	    desc->nr_ptes == 0 || desc->total_pages != desc->nr_ptes ||
	    desc->region_table_entries != desc->nr_regions ||
	    desc->pte_table_entries != desc->nr_ptes ||
	    !desc->region_table_bytes || !desc->pte_table_bytes ||
	    check_mul_overflow(desc->total_pages, (u64)PAGE_SIZE, &bytes) ||
	    !desc->data_offset || !cxlfork_slot_range_valid(desc,
							 desc->data_offset, bytes) ||
	    check_mul_overflow(desc->nr_regions,
				       (u64)sizeof(struct cxlfork_region_desc), &bytes) ||
	    desc->region_table_bytes < PAGE_ALIGN(bytes) ||
	    !cxlfork_slot_range_valid(desc, desc->region_table_offset,
					       desc->region_table_bytes) ||
	    check_mul_overflow(desc->nr_ptes,
				       (u64)sizeof(struct cxlfork_pte_desc), &bytes) ||
	    desc->pte_table_bytes < PAGE_ALIGN(bytes) ||
	    !cxlfork_slot_range_valid(desc, desc->pte_table_offset,
					       desc->pte_table_bytes) ||
	    desc->pte_image_entries != desc->nr_ptes ||
	    !desc->pte_image_pages ||
	    !cxlfork_slot_range_valid(desc, desc->pte_image_offset,
					       desc->pte_image_pages * PAGE_SIZE) ||
	    !desc->pt_page_image_entries || !desc->pt_page_image_pages ||
	    !cxlfork_slot_range_valid(desc, desc->pt_page_image_offset,
					       desc->pt_page_image_pages * PAGE_SIZE) ||
	    !desc->pt_tree_image_offset || !desc->pt_tree_pages ||
	    !cxlfork_slot_range_valid(desc, desc->pt_tree_image_offset,
					       (desc->pt_tree_pages + 1) * PAGE_SIZE) ||
	    !desc->pt_tree_root_offset ||
	    !cxlfork_slot_range_valid(desc, desc->pt_tree_root_offset,
					       PAGE_SIZE) ||
	    !desc->vma_tree_image_offset || !desc->vma_tree_nodes ||
	    !desc->vma_tree_pages ||
	    !cxlfork_slot_range_valid(desc, desc->vma_tree_image_offset,
					       desc->vma_tree_pages * PAGE_SIZE) ||
	    !desc->vma_tree_root_offset ||
	    !cxlfork_slot_range_valid(desc, desc->vma_tree_root_offset,
					       sizeof(struct cxlfork_vma_node_image)) ||
	    !desc->state_image_offset || !desc->state_image_pages ||
	    !cxlfork_slot_range_valid(desc, desc->state_image_offset,
					       desc->state_image_pages * PAGE_SIZE) ||
	    !desc->private_rebase_offset || !desc->private_rebase_pages ||
	    !cxlfork_slot_range_valid(desc, desc->private_rebase_offset,
					       desc->private_rebase_pages * PAGE_SIZE) ||
	    !desc->image_bytes ||
	    desc->image_bytes > CXLFORK_SLOT_BYTES ||
	    !desc->page_checksum || !desc->leaf_checksum)
		return -EILSEQ;

	return 0;
}

static int cxlfork_do_checkpoint(struct cxlfork_checkpoint *op,
				 struct cxlfork_checkpoint __user *legacy_uarg,
				 struct cxlfork_prepare_v2 *v2,
				 struct cxlfork_prepare_v2 __user *v2_uarg,
				 const struct cxlfork_capsule_manifest_v4 *capsule)
{
	/* prepare 主路径：扫描 VMA -> 复制页面 -> 构建 PTE/VMA/state/rebase 镜像 -> ready。 */
	struct cxlfork_desc *desc;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct cxlfork_checkpoint_sizing sizing;
	u64 data_off;
	u64 slot;
	u64 start_ns;
	u64 lock_start;
	u64 lifecycle_start;
	int ret = 0;
	bool reopen_fds;

	if (!op->key || (!(op->flags & CXLFORK_F_FULL_PRIVATE_STATE) &&
			op->scan_start >= op->scan_end)) {
		ret = -EINVAL;
		goto out_return;
	}
	if (op->flags & CXLFORK_F_FULL_PRIVATE_STATE) {
		ret = -EOPNOTSUPP;
		goto out_return;
	}
	if (get_nr_threads(current) != 1) {
		ret = -EBUSY;
		goto out_return;
	}
	reopen_fds = op->flags & CXLFORK_F_REOPEN_FDS;
	op->flags &= ~CXLFORK_F_REOPEN_FDS;

	ret = key_to_slot(op->key);
	if (ret < 0)
		goto out_return;
	slot = ret;
	desc = slot_desc(slot);
	if (!desc) {
		ret = -ENOSPC;
		goto out_return;
	}
	ret = 0;

	start_ns = ktime_get_ns();
	lock_start = ktime_get_ns();
	mutex_lock(&cxlfork_lock);
	/* The checkpoint slot transition and descriptor initialization are the
	 * lifecycle portion; lock wait is kept separate. */
	lifecycle_start = ktime_get_ns();
	if (cmpxchg(&desc->state,
		    cxlfork_lifecycle_pack(CXLFORK_SLOT_FREE, 0),
		    cxlfork_lifecycle_pack(CXLFORK_SLOT_WRITING, 0)) !=
	    cxlfork_lifecycle_pack(CXLFORK_SLOT_FREE, 0)) {
		ret = -EEXIST;
		goto out_unlock;
	}
	{
		u64 generation = READ_ONCE(desc->generation) + 1;

	memset_after(desc, 0, reader_count);
	desc->magic = CXLFORK_DESC_MAGIC;
	desc->version = CXLFORK_DESC_VERSION;
	desc->key = op->key;
	desc->state = cxlfork_lifecycle_pack(CXLFORK_SLOT_WRITING, 0);
	desc->reader_count = 0;
	desc->generation = generation ?: 1;
	desc->slot = slot;
	desc->extent_bytes = CXLFORK_EXTENT_BYTES;
	desc->extent_count = CXLFORK_EXTENTS_PER_SLOT;
	desc->extent_bitmap_words = CXLFORK_EXTENT_BITMAP_WORDS;
	if (capsule) {
		desc->capsule_manifest = *capsule;
		desc->capsule_manifest_valid = 1;
	}
	ret = cxlfork_slot_mark_alloc(desc, slot_offset(slot),
				      slot_payload_offset(slot) - slot_offset(slot));
	if (ret)
		goto out_unlock;
	desc->data_offset = slot_payload_offset(slot);
	}
	data_off = desc->data_offset;
	desc->lock_wait_ns = ktime_get_ns() - lock_start;
	desc->lifecycle_ns = ktime_get_ns() - lifecycle_start;

	mm = get_task_mm(current);
	if (!mm) {
		ret = -EINVAL;
		goto out_unlock;
	}

	mmap_read_lock(mm);
	{
		u64 preflight_start = ktime_get_ns();

		ret = cxlfork_preflight_checkpoint(mm, op, slot, &sizing);
		desc->vma_preflight_ns = ktime_get_ns() - preflight_start;
	}
	if (ret)
		goto out_mmap_unlock;
	ret = cxlfork_alloc_table(desc, slot, &data_off, CXLFORK_MAX_FDS,
				  sizeof(struct cxlfork_fd_state),
				  &desc->fd_table_offset,
				  &desc->fd_table_bytes);
	if (ret)
		goto out_mmap_unlock;
	desc->fd_table_entries = CXLFORK_MAX_FDS;
	ret = cxlfork_alloc_table(desc, slot, &data_off, sizing.regions,
				  sizeof(struct cxlfork_region_desc),
				  &desc->region_table_offset,
				  &desc->region_table_bytes);
	if (ret)
		goto out_mmap_unlock;
	desc->region_table_entries = sizing.regions;
	ret = cxlfork_alloc_table(desc, slot, &data_off, sizing.pages,
				  sizeof(struct cxlfork_pte_desc),
				  &desc->pte_table_offset,
				  &desc->pte_table_bytes);
	if (ret)
		goto out_mmap_unlock;
	desc->pte_table_entries = sizing.pages;
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

		if (!regions || !ptes ||
		    desc->region_table_entries != sizing.regions ||
		    desc->pte_table_entries != sizing.pages) {
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
		if (desc->nr_regions >= desc->region_table_entries) {
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

			if (desc->nr_ptes >= desc->pte_table_entries) {
				ret = -ENOSPC;
				break;
			}
			if (data_off + PAGE_SIZE > slot_offset(slot) + CXLFORK_SLOT_BYTES) {
				ret = -ENOSPC;
				break;
			}
			ret = cxlfork_slot_mark_alloc(desc, data_off, PAGE_SIZE);
			if (ret)
				break;
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
		desc->metadata_build_ns = desc->pte_image_build_ns +
			desc->pt_page_image_build_ns + desc->vma_tree_build_ns +
			desc->state_image_build_ns + desc->private_rebase_ns;
	}
	if (!ret) {
		u64 checksum_start = ktime_get_ns();

		if (!cxlfork_desc_matches_slot(desc, slot)) {
			ret = -EILSEQ;
			goto out_unlock;
		}
		desc->image_bytes = data_off - slot_offset(slot);
		ret = cxlfork_compute_checksums(desc, &desc->page_checksum,
						&desc->leaf_checksum);
		desc->checksum_seal_ns = ktime_get_ns() - checksum_start;
	}

	if (!ret) {
		u64 i;
		u64 nr_out_regions;
		struct cxlfork_region_desc *regions = cxlfork_desc_regions(desc);

		desc->create_ns = ktime_get_ns() - start_ns;
		if (!regions) {
			ret = -EILSEQ;
			goto out_unlock;
		}
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
		nr_out_regions = min_t(u64, desc->nr_regions, CXLFORK_MAX_REGIONS);
		for (i = 0; i < nr_out_regions; i++) {
			op->regions[i].start = regions[i].start;
			op->regions[i].length = regions[i].length;
			op->regions[i].prot = regions[i].prot;
			op->regions[i].flags = regions[i].flags;
			op->regions[i].pages = regions[i].pages;
			op->regions[i].anon_pages = regions[i].anon_pages;
			op->regions[i].clean_file_pages = regions[i].clean_file_pages;
			op->regions[i].dirty_file_pages = regions[i].dirty_file_pages;
		}
		if (legacy_uarg && copy_to_user(legacy_uarg, op, sizeof(*op))) {
			ret = -EFAULT;
			goto out_unlock;
		}
		if (v2) {
			v2->region_count = nr_out_regions;
			v2->generation = desc->generation;
			v2->slot = desc->slot;
			v2->total_pages = desc->total_pages;
			v2->page_checksum = desc->page_checksum;
			v2->stats.total_ns = desc->create_ns;
			v2->stats.supported_mask = CXLFORK_PREP_STAT_KNOWN_MASK;
			v2->stats.valid_mask = CXLFORK_PREP_STAT_LOCK_WAIT |
				CXLFORK_PREP_STAT_LIFECYCLE |
				CXLFORK_PREP_STAT_VMA_PREFLIGHT |
				CXLFORK_PREP_STAT_PTE_WALK |
				CXLFORK_PREP_STAT_GUP |
				CXLFORK_PREP_STAT_PAGE_COPY |
				CXLFORK_PREP_STAT_PTE_RECHECK |
				CXLFORK_PREP_STAT_METADATA |
				CXLFORK_PREP_STAT_CHECKSUM |
				CXLFORK_PREP_STAT_PUBLISH;
			v2->stats.lock_wait_ns = desc->lock_wait_ns;
			v2->stats.lifecycle_ns = desc->lifecycle_ns;
			v2->stats.vma_preflight_ns = desc->vma_preflight_ns;
			v2->stats.pte_walk_ns = desc->pte_walk_ns;
			v2->stats.gup_ns = desc->gup_ns;
			v2->stats.page_copy_ns = desc->page_copy_ns;
			v2->stats.pte_recheck_ns = desc->pte_recheck_ns;
			v2->stats.metadata_build_ns = desc->metadata_build_ns;
			v2->stats.checksum_seal_ns = desc->checksum_seal_ns;
			if (nr_out_regions &&
			    copy_to_user(u64_to_user_ptr(v2->regions_ptr),
					 op->regions,
					 nr_out_regions * sizeof(op->regions[0]))) {
				ret = -EFAULT;
				goto out_unlock;
			}
			if (v2_uarg &&
			    copy_to_user(v2_uarg, v2, sizeof(*v2))) {
				ret = -EFAULT;
				goto out_unlock;
			}
		}
		{
			u64 publish_start = ktime_get_ns();

			smp_wmb();
		WRITE_ONCE(desc->ready, 1);
		smp_store_release(&desc->state,
				  cxlfork_lifecycle_pack(CXLFORK_SLOT_READY, 0));
			desc->publish_ns = ktime_get_ns() - publish_start;
			if (v2) {
				v2->stats.publish_ns = desc->publish_ns;
				if (v2_uarg &&
				    copy_to_user(v2_uarg, v2, sizeof(*v2)))
					pr_warn("cxlfork: prepare stats publish copy failed\n");
			}
		}
	}

out_unlock:
	if (ret && desc && !desc->ready) {
		u64 generation = desc->generation;

		cxlfork_desc_reset_free(desc, generation);
	}
	mutex_unlock(&cxlfork_lock);
out_return:
	return ret;
}

static int cxlfork_ioctl_checkpoint(struct cxlfork_checkpoint __user *uarg)
{
	struct cxlfork_checkpoint *op;
	int ret;

	op = memdup_user(uarg, sizeof(*op));
	if (IS_ERR(op))
		return PTR_ERR(op);
	ret = cxlfork_do_checkpoint(op, uarg, NULL, NULL, NULL);
	kfree(op);
	return ret;
}

static int cxlfork_map_region(struct cxlfork_desc *desc,
			      struct cxlfork_region_desc *r,
			      bool readonly,
			      struct cxlfork_restore_breakdown *bd,
			      struct cxlfork_restore_ctx *ctx)
{
	/* 非 COW 路径：直接把 CXL 物理页 remap 到目标进程地址。 */
	struct cxlfork_pte_desc *pte_table = cxlfork_desc_ptes(desc);
	struct cxlfork_mapping *mapping;
	unsigned long addr = r->start;
	unsigned long mapped;
	u64 install_start;
	u64 vma_start;
	u64 i;
	int ret;

	if (!pte_table)
		return -EILSEQ;
	vma_start = ktime_get_ns();
	mapped = vm_mmap(NULL, r->start, r->length,
			 PROT_READ | ((r->prot & PROT_EXEC) ? PROT_EXEC : 0),
			 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0);
	if (bd)
		bd->vma_create_ns += ktime_get_ns() - vma_start;
	if (IS_ERR_VALUE(mapped)) {
		if (mapped != -EEXIST)
			pr_warn("cxlfork: vm_mmap start=%llx len=%llx ret=%ld\n",
				r->start, r->length, mapped);
		return (int)mapped;
	}
	if (mapped != r->start) {
		pr_warn("cxlfork: vm_mmap returned %lx expected=%llx\n",
			mapped, r->start);
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
	mapping->flags = readonly ? CXLFORK_F_MAP_READONLY : 0;
	refcount_set(&mapping->refs, 1);
	mapping->ctx = ctx;
	cxlfork_restore_ctx_mapping_get(ctx);

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
			ret = -EFAULT;
			goto out_unmap;
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
			goto out_unmap;
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
			ret = -EFAULT;
			goto out_unmap;
		}
		vma->vm_ops = &cxlfork_vm_ops;
		vma->vm_private_data = mapping;
	}
	mmap_write_unlock(current->mm);

	return 0;

out_unmap:
	mmap_write_unlock(current->mm);
	cxlfork_restore_ctx_mapping_put(mapping->ctx);
	kfree(mapping);
	vm_munmap(r->start, r->length);
	return ret;
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
					  struct cxlfork_restore_breakdown *bd,
					  struct cxlfork_restore_ctx *ctx)
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
	u64 vma_start;
	bool attached = false;

	if (!IS_ALIGNED(r->start, PMD_SIZE) || !IS_ALIGNED(r->length, PMD_SIZE))
		return -EOPNOTSUPP;
	if (writable_vma && (r->prot & PROT_WRITE))
		prot |= PROT_WRITE;

	vma_start = ktime_get_ns();
	mapped = vm_mmap(NULL, r->start, r->length,
			 prot, mmap_flags, 0);
	if (bd)
		bd->vma_create_ns += ktime_get_ns() - vma_start;
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
	refcount_set(&mapping->refs, 1);
	mapping->ctx = ctx;
	cxlfork_restore_ctx_mapping_get(ctx);

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
	attached = true;

	attach_start = ktime_get_ns();
	for (addr = r->start; addr < r->start + r->length; addr += PMD_SIZE) {
		unsigned long leaf_pfn;
		u64 upper_start;

		ret = cxlfork_find_shared_leaf_pfn(desc, addr, &leaf_pfn);
		if (ret)
			goto out_unlock;
		upper_start = ktime_get_ns();
		ret = cxlfork_install_shared_leaf_pmd(current->mm, addr, leaf_pfn);
		if (bd && !ret)
			bd->upper_pt_alloc_ns += ktime_get_ns() - upper_start;
		if (ret)
			goto out_unlock;
		if (bd) {
			bd->shared_leaf_attach_pages += PMD_SIZE >> PAGE_SHIFT;
			bd->shared_leaf_count++;
		}
		desc->shared_map_pages += PMD_SIZE >> PAGE_SHIFT;
	}
	if (bd) {
		u64 elapsed = ktime_get_ns() - attach_start;

		bd->shared_leaf_attach_ns += elapsed;
	}

out_unlock:
	mmap_write_unlock(current->mm);
	if (ret && attached)
		vm_munmap(r->start, r->length);
	else if (ret) {
		cxlfork_restore_ctx_mapping_put(mapping->ctx);
		kfree(mapping);
		vm_munmap(r->start, r->length);
	}
	return ret;
}

static int cxlfork_inspect_vma_image(const struct cxlfork_desc *desc,
				     unsigned long address,
				     struct cxlfork_inspect_v2 *inspect)
{
	u64 node_offset = desc->vma_tree_root_offset;
	u64 visited = 0;

	while (node_offset && visited++ < desc->vma_tree_nodes) {
		const struct cxlfork_vma_node_image *node;

		if (!cxlfork_slot_range_valid(desc, node_offset, sizeof(*node)))
			return -EILSEQ;
		node = cxl_ptr(node_offset);
		if (!node)
			return -EILSEQ;
		if (address < node->start)
			node_offset = node->left_offset;
		else if (address >= node->end)
			node_offset = node->right_offset;
		else {
			inspect->vma_image_root_offset =
				desc->vma_tree_root_offset;
			inspect->vma_image_nodes = desc->vma_tree_nodes;
			inspect->vma_image_lookup_start = node->start;
			inspect->vma_image_lookup_end = node->end;
			inspect->flags |=
				CXLFORK_INSPECT_F_VMA_IMAGE_LOOKUP_VALID;
			return 0;
		}
	}
	return -ENOENT;
}

static int cxlfork_map_region_cow(struct file *file,
				  const struct cxlfork_region_desc *r,
				  u64 region_idx, bool private_cow,
				  struct cxlfork_restore_breakdown *bd,
				  struct cxlfork_file_state *state)
{
	/* COW/tiering 路径：先 mmap /dev/cxlfork，后续 fault 决定共享还是复制。 */
	unsigned long mapped;
	unsigned long flags = (private_cow ? MAP_SHARED : MAP_PRIVATE) |
		MAP_FIXED_NOREPLACE;
	u64 validate_before = state ? state->pte_image_validate_ns : 0;
	u64 install_before = state ? state->direct_pte_install_ns : 0;
	u64 prefault_before = state ? state->dirty_prefault_ns : 0;
	u64 begin = ktime_get_ns();
	u64 elapsed;
	u64 nested = 0;

	mapped = vm_mmap(file, r->start, r->length,
			 PROT_READ | ((r->prot & PROT_WRITE) ? PROT_WRITE : 0),
			 flags,
			 (region_idx * CXLFORK_REGION_PGOFF_STEP) << PAGE_SHIFT);
	elapsed = ktime_get_ns() - begin;
	if (state) {
		nested += state->pte_image_validate_ns - validate_before;
		nested += state->direct_pte_install_ns - install_before;
		nested += state->dirty_prefault_ns - prefault_before;
	}
	if (bd)
		bd->vma_create_ns += elapsed > nested ? elapsed - nested : 0;
	if (IS_ERR_VALUE(mapped)) {
		if (mapped != -EEXIST)
			pr_warn("cxlfork: cow vm_mmap start=%llx len=%llx ret=%ld\n",
				r->start, r->length, mapped);
		return (int)mapped;
	}
	if (mapped != r->start) {
		vm_munmap(mapped, r->length);
		return -EINVAL;
	}
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
	u64 *ptes;
	u64 offset;
	int ret;

	ret = cxlfork_pt_tree_walk(desc, addr & PMD_MASK, &ptes);
	if (ret)
		return ret;
	offset = (char *)ptes - (char *)cxl_ptr(0);
	if (!cxlfork_slot_range_valid(desc, offset, PAGE_SIZE))
		return -EILSEQ;
	*pfn_out = (cxl_phys + offset) >> PAGE_SHIFT;
	return 0;
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

static void cxlfork_fault_dispatch_done(struct cxlfork_restore_ctx *ctx,
						u64 start_ns)
{
	if (ctx)
		atomic64_add(ktime_get_ns() - start_ns, &ctx->fault_dispatch_ns);
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
	u64 fault_start = ktime_get_ns();
	u64 copy_start;
	int slot;

	if (!mapping)
		return VM_FAULT_SIGBUS;

	slot = key_to_slot(mapping->key);
	if (slot < 0) {
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
		return VM_FAULT_SIGBUS;
	}

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != mapping->key ||
		cxlfork_lifecycle_state(READ_ONCE(desc->state)) !=
		CXLFORK_SLOT_READY ||
		desc->generation != mapping->generation || !desc->ready ||
		mapping->region_idx >= desc->nr_regions) {
		mutex_unlock(&cxlfork_lock);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
		return VM_FAULT_SIGBUS;
	}

	regions = cxlfork_desc_regions(desc);
	ptes = cxlfork_desc_ptes(desc);
	if (!regions || !ptes) {
		mutex_unlock(&cxlfork_lock);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
		return VM_FAULT_SIGBUS;
	}
	r = &regions[mapping->region_idx];
	addr = vmf->address & PAGE_MASK;
	if (addr < r->start || addr >= r->start + r->length) {
		mutex_unlock(&cxlfork_lock);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
		return VM_FAULT_SIGBUS;
	}
	page_idx = (addr - r->start) >> PAGE_SHIFT;
	if (page_idx >= r->pages || r->pgoff_first + page_idx >= desc->nr_ptes) {
		mutex_unlock(&cxlfork_lock);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
		return VM_FAULT_SIGBUS;
	}
	pte = &ptes[r->pgoff_first + page_idx];
	if (pte->va != addr || !cxl_ptr(pte->cxl_offset)) {
		mutex_unlock(&cxlfork_lock);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
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
			if (mapping->ctx) {
				atomic64_inc(&mapping->ctx->faults);
				atomic64_inc(&mapping->ctx->shared_map_pages);
			}
		}
		mutex_unlock(&cxlfork_lock);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
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
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
		return VM_FAULT_OOM;
	}

	copy_start = ktime_get_ns();
	dst = kmap_local_page(page);
	src = cxl_ptr(pte->cxl_offset);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_local(dst);
	flush_dcache_page(page);
	if (mapping->ctx)
		atomic64_add(ktime_get_ns() - copy_start,
				     &mapping->ctx->cxl_to_local_copy_ns);
	desc->faults++;
	desc->local_copy_pages++;
	if (mapping->ctx) {
		atomic64_inc(&mapping->ctx->faults);
		atomic64_inc(&mapping->ctx->local_copy_pages);
	}
	mutex_unlock(&cxlfork_lock);

	{
		vm_fault_t ret = vmf_insert_page(vmf->vma, addr, page);

		put_page(page);
		cxlfork_fault_dispatch_done(mapping->ctx, fault_start);
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
	if (mapping->ctx)
		cxlfork_restore_ctx_mapping_put(mapping->ctx);
	kfree(mapping);
}

bool cxlfork_vma_is_restored(const struct vm_area_struct *vma)
{
	return vma && vma->vm_ops == &cxlfork_vm_ops;
}

int cxlfork_gup_check_range(struct mm_struct *mm, unsigned long start,
			    unsigned long end)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, start);
	int ret = 0;

	if (start >= end)
		return 0;
	mmap_read_lock(mm);
	for_each_vma_range(vmi, vma, end) {
		if (cxlfork_vma_is_restored(vma)) {
			ret = -EOPNOTSUPP;
			break;
		}
	}
	mmap_read_unlock(mm);
	return ret;
}

int cxlfork_fork_check_mm(struct mm_struct *mm)
{
	return cxlfork_gup_check_range(mm, 0, TASK_SIZE_MAX);
}

static int cxlfork_vma_may_split(struct vm_area_struct *vma,
				 unsigned long addr)
{
	return -EOPNOTSUPP;
}

static int cxlfork_vma_mremap(struct vm_area_struct *vma)
{
	return -EOPNOTSUPP;
}

static int cxlfork_vma_mprotect(struct vm_area_struct *vma,
				unsigned long start, unsigned long end,
				unsigned long newflags)
{
	return -EOPNOTSUPP;
}

static const struct vm_operations_struct cxlfork_vm_ops = {
	.open = cxlfork_vma_open,
	.fault = cxlfork_fault,
	.close = cxlfork_vma_close,
	.may_split = cxlfork_vma_may_split,
	.mremap = cxlfork_vma_mremap,
	.mprotect = cxlfork_vma_mprotect,
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

	if (!state || !state->mmap_key || !state->mmap_ctx)
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
	    cxlfork_lifecycle_state(READ_ONCE(desc->state)) !=
		CXLFORK_SLOT_READY ||
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
	mapping->ctx = state->mmap_ctx;
	cxlfork_restore_ctx_mapping_get(mapping->ctx);

	if (mapping->flags & CXLFORK_F_SHARED_COW)
		ret = cxlfork_prefault_shared_cxl(vma, desc, r, state);
	else {
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP);
		if (mapping->flags & CXLFORK_F_HYBRID_TIERING)
			ret = cxlfork_prefault_dirty_local(vma, desc, r, state);
	}
	if (ret) {
		cxlfork_restore_ctx_mapping_put(mapping->ctx);
		kfree(mapping);
		goto out_unlock;
	}
	vma->vm_ops = &cxlfork_vm_ops;
	vma->vm_private_data = mapping;

out_unlock:
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static int cxlfork_do_restore(struct file *file, struct cxlfork_restore *op,
			      struct cxlfork_restore __user *legacy_uarg,
			      struct cxlfork_resume_v2 *v2,
			      struct cxlfork_resume_v2 __user *v2_uarg,
			      u64 *activation_commit_ns,
			      bool sealed_capsule)
{
	/* resume 主路径：校验 CXL 镜像 -> mmap regions -> 可选应用 OS metadata -> 回填 breakdown。 */
	struct cxlfork_file_state *state = file->private_data;
	struct cxlfork_desc *desc = NULL;
	u64 start_ns;
	u64 lock_start;
	u64 lifecycle_start;
	bool readonly;
	bool private_cow;
	bool shared_cow;
	bool hybrid_tiering;
	bool apply_mm_state;
	bool reopen_fds;
	bool apply_global_state;
	bool apply_thread_state;
	bool apply_tls_state;
	bool full_validation;
	bool test_fail_after_first = false;
	struct cxlfork_restore_breakdown bd = {};
	struct cxlfork_region_desc *regions;
	u64 nr_fds_restored = 0;
	u64 generation = 0;
	struct cxlfork_restore_ctx *ctx = NULL;
	bool file_ctx_attached = false;
	int slot;
	int ret = 0;
	int i;
	int mapped_regions = 0;

	if (activation_commit_ns)
		*activation_commit_ns = 0;
	if (!op->key) {
		ret = -EINVAL;
		goto out_return;
	}

	slot = key_to_slot(op->key);
	if (slot < 0) {
		ret = slot;
		goto out_return;
	}

	start_ns = ktime_get_ns();
	lock_start = ktime_get_ns();
	mutex_lock(&cxlfork_lock);
	bd.lock_wait_ns += ktime_get_ns() - lock_start;
	lifecycle_start = ktime_get_ns();
	desc = slot_desc(slot);
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != op->key ||
	    cxlfork_lifecycle_state(smp_load_acquire(&desc->state)) !=
		CXLFORK_SLOT_READY || !desc->ready) {
		ret = -ENOENT;
		goto out_unlock;
	}
	generation = desc->generation;
	if (v2 && generation != v2->generation) {
		ret = -ESTALE;
		goto out_unlock;
	}
	if (v2 && v2->region_capacity < desc->nr_regions) {
		v2->region_count = desc->nr_regions;
		ret = -ENOSPC;
		goto out_unlock;
	}
	ret = cxlfork_slot_get_reader_locked(desc, op->key, generation);
	if (ret)
		goto out_unlock;
	ctx = cxlfork_restore_ctx_create(op->key, generation);
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		ctx = NULL;
		cxlfork_slot_put_reader_locked(desc, op->key, generation);
		goto out_unlock;
	}
	bd.lifecycle_ns += ktime_get_ns() - lifecycle_start;
	readonly = op->flags & CXLFORK_F_MAP_READONLY;
	private_cow = op->flags & CXLFORK_F_PRIVATE_COW;
	shared_cow = op->flags & CXLFORK_F_SHARED_COW;
	hybrid_tiering = op->flags & CXLFORK_F_HYBRID_TIERING;
	apply_mm_state = op->flags & CXLFORK_F_APPLY_MM_STATE;
	reopen_fds = op->flags & CXLFORK_F_REOPEN_FDS;
	apply_global_state = op->flags & CXLFORK_F_APPLY_GLOBAL_STATE;
	apply_thread_state = op->flags & CXLFORK_F_APPLY_THREAD_STATE;
	apply_tls_state = op->flags & CXLFORK_F_APPLY_TLS_STATE;
	full_validation = !v2 || (op->flags & CXLFORK_F_VALIDATE_FULL) ||
		apply_mm_state || apply_global_state || reopen_fds ||
		(apply_thread_state && !sealed_capsule) || apply_tls_state;
	if (v2)
		test_fail_after_first =
			v2->flags & CXLFORK_F_TEST_FAIL_AFTER_FIRST_REGION;
	if ((private_cow + shared_cow + hybrid_tiering) > 1) {
		ret = -EINVAL;
		goto out_unlock;
	}
	{
		u64 validation_start = ktime_get_ns();

		ret = cxlfork_validate_restore_manifest(desc);
		bd.manifest_validate_ns = ktime_get_ns() - validation_start;
	}
	if (ret)
		goto out_unlock;
	if (full_validation) {
		ret = cxlfork_validate_vma_tree_image(desc,
					       &bd.vma_tree_validate_ns);
		if (ret)
			goto out_unlock;
		ret = cxlfork_validate_state_image(desc,
					       &bd.state_image_validate_ns);
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
		{
			u64 observed_page;
			u64 observed_leaf;
			u64 checksum_start = ktime_get_ns();

			ret = cxlfork_compute_checksums(desc, &observed_page,
							&observed_leaf);
			bd.checksum_validate_ns += ktime_get_ns() - checksum_start;
			if (ret || observed_page != desc->page_checksum ||
			    observed_leaf != desc->leaf_checksum) {
				ret = -EILSEQ;
				goto out_unlock;
			}
		}
	}
	regions = cxlfork_desc_regions(desc);
	if (!regions) {
		ret = -EILSEQ;
		goto out_unlock;
	}
	/* Reject address conflicts before creating any VMA. MAP_FIXED fallback is forbidden. */
	{
		u64 conflict_start = ktime_get_ns();

		mmap_read_lock(current->mm);
		for (i = 0; i < desc->nr_regions; i++) {
			if (find_vma_intersection(current->mm, regions[i].start,
						  regions[i].start + regions[i].length)) {
				ret = -EEXIST;
				break;
			}
		}
		mmap_read_unlock(current->mm);
		bd.address_conflict_ns += ktime_get_ns() - conflict_start;
	}
	if (ret)
		goto out_unlock;
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
		state->mmap_ctx = ctx;
	}
	mutex_unlock(&cxlfork_lock);
	for (i = 0; i < desc->nr_regions; i++) {
		if (shared_cow) {
			ret = cxlfork_map_region_shared_leaf(desc, &regions[i],
							     CXLFORK_F_SHARED_COW,
							     true, &bd, ctx);
			if (ret == -EOPNOTSUPP) {
				u64 fallback_start = ktime_get_ns();
				u64 vma_before = bd.vma_create_ns;
				u64 validate_before = state ?
					state->pte_image_validate_ns : 0;
				u64 install_before = state ?
					state->direct_pte_install_ns : 0;
				u64 prefault_before = state ?
					state->dirty_prefault_ns : 0;

				ret = cxlfork_map_region_cow(file, &regions[i],
							     i, false, &bd, state);
				if (!ret) {
					u64 elapsed = ktime_get_ns() - fallback_start;
					u64 nested = bd.vma_create_ns - vma_before;

					if (state) {
						nested += state->pte_image_validate_ns -
							validate_before;
						nested += state->direct_pte_install_ns -
							install_before;
						nested += state->dirty_prefault_ns -
							prefault_before;
					}
					bd.pte_image_reconstruct_ns += elapsed;
					bd.fallback_other_ns += elapsed > nested ?
						elapsed - nested : 0;
					bd.pte_image_reconstruct_pages += regions[i].pages;
				}
			}
		} else if (private_cow || hybrid_tiering) {
			ret = cxlfork_map_region_cow(file, &regions[i], i,
						     private_cow, &bd, state);
		} else if (readonly) {
			ret = cxlfork_map_region_shared_leaf(desc, &regions[i],
							     CXLFORK_F_MAP_READONLY,
							     false, &bd, ctx);
			if (ret == -EOPNOTSUPP)
				ret = cxlfork_map_region(desc, &regions[i],
							 readonly, &bd, ctx);
		} else {
			ret = cxlfork_map_region(desc, &regions[i],
							 readonly, &bd, ctx);
		}
		if (ret)
			break;
		mapped_regions++;
		if (test_fail_after_first && mapped_regions == 1) {
			ret = -EIO;
			break;
		}
	}
	lock_start = ktime_get_ns();
	mutex_lock(&cxlfork_lock);
	bd.lock_wait_ns += ktime_get_ns() - lock_start;
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
		state->mmap_ctx = NULL;
	}
	if (ret)
		goto out_unlock;
	if (!desc || desc->magic != CXLFORK_DESC_MAGIC ||
	    desc->version != CXLFORK_DESC_VERSION || desc->key != op->key ||
	    cxlfork_lifecycle_state(READ_ONCE(desc->state)) !=
		CXLFORK_SLOT_READY ||
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
	for (i = 0; i < min_t(u64, desc->nr_regions, CXLFORK_MAX_REGIONS); i++) {
		op->regions[i].start = regions[i].start;
		op->regions[i].length = regions[i].length;
		op->regions[i].prot = regions[i].prot;
		op->regions[i].flags = regions[i].flags;
		op->regions[i].pages = regions[i].pages;
	}
	if (ctx) {
		unsigned long stats_flags;
		u64 accounted;
		u64 exclusive_accounted;
		u64 image_validate_ns;
		u64 shared_leaf_exclusive_ns;
		u64 path_mask = full_validation ?
			CXLFORK_RESTORE_PATH_FULL_VALIDATION : CXLFORK_RESTORE_PATH_FAST;

		if (bd.shared_leaf_attach_pages)
			path_mask |= CXLFORK_RESTORE_PATH_SHARED_LEAF;
		if (bd.pte_image_reconstruct_pages)
			path_mask |= CXLFORK_RESTORE_PATH_FALLBACK_RECONSTRUCT;
		if (private_cow)
			path_mask |= CXLFORK_RESTORE_PATH_MOA;
		if (hybrid_tiering)
			path_mask |= CXLFORK_RESTORE_PATH_HYBRID;
		if (apply_global_state || reopen_fds)
			path_mask |= CXLFORK_RESTORE_PATH_GLOBAL;
		if (apply_thread_state || apply_tls_state)
			path_mask |= CXLFORK_RESTORE_PATH_THREAD;

		spin_lock_irqsave(&ctx->lock, stats_flags);
		ctx->stats.supported_mask = CXLFORK_RESTORE_STAT_KNOWN_MASK &
			~(CXLFORK_RESTORE_STAT_LEAF_MATERIALIZE |
			  CXLFORK_RESTORE_STAT_DATA_COW);
		ctx->stats.valid_mask = CXLFORK_RESTORE_STAT_LOCK_WAIT |
			CXLFORK_RESTORE_STAT_LIFECYCLE |
			CXLFORK_RESTORE_STAT_VALIDATION;
		if (bd.vma_create_ns)
			ctx->stats.valid_mask |= CXLFORK_RESTORE_STAT_VMA_CREATE;
		if (bd.upper_pt_alloc_ns)
			ctx->stats.valid_mask |= CXLFORK_RESTORE_STAT_UPPER_PT;
		if (bd.shared_leaf_attach_pages)
			ctx->stats.valid_mask |= CXLFORK_RESTORE_STAT_SHARED_LEAF;
		if (bd.pte_image_reconstruct_pages)
			ctx->stats.valid_mask |= CXLFORK_RESTORE_STAT_FALLBACK;
		if (bd.dirty_prefault_pages)
			ctx->stats.valid_mask |= CXLFORK_RESTORE_STAT_DIRTY_PREF;
		if (bd.global_restore_ns)
			ctx->stats.valid_mask |= CXLFORK_RESTORE_STAT_GLOBAL;
		ctx->stats.total_ns = op->restore_ns;
		ctx->stats.lock_wait_ns = bd.lock_wait_ns;
		ctx->stats.lifecycle_ns = bd.lifecycle_ns;
		ctx->stats.path_mask = path_mask;
		ctx->stats.validation_ns = bd.manifest_validate_ns +
			bd.pte_image_validate_ns +
			bd.pt_page_image_validate_ns + bd.vma_tree_validate_ns +
			bd.state_image_validate_ns +
			bd.private_rebase_validate_ns + bd.checksum_validate_ns;
		ctx->stats.vma_create_ns = bd.vma_create_ns;
		ctx->stats.upper_pt_alloc_ns = bd.upper_pt_alloc_ns;
		ctx->stats.shared_leaf_attach_ns = bd.shared_leaf_attach_ns;
		ctx->stats.fallback_reconstruct_ns =
			bd.pte_image_reconstruct_ns;
		ctx->stats.dirty_prefault_ns = bd.dirty_prefault_ns;
		ctx->stats.global_restore_ns = bd.global_restore_ns;
		ctx->stats.shared_leaf_pages = bd.shared_leaf_attach_pages;
		ctx->stats.fallback_pages = bd.pte_image_reconstruct_pages;
		ctx->stats.dirty_prefault_pages = bd.dirty_prefault_pages;
		ctx->stats.validated_ptes = full_validation ? desc->nr_ptes : 0;
		accounted = ctx->stats.lock_wait_ns + ctx->stats.lifecycle_ns +
			ctx->stats.validation_ns + ctx->stats.vma_create_ns +
			ctx->stats.upper_pt_alloc_ns +
			ctx->stats.shared_leaf_attach_ns +
			ctx->stats.fallback_reconstruct_ns +
			ctx->stats.dirty_prefault_ns + ctx->stats.global_restore_ns;
		ctx->stats.other_ns = op->restore_ns > accounted ?
			op->restore_ns - accounted : 0;

		image_validate_ns = bd.pt_page_image_validate_ns +
			bd.vma_tree_validate_ns + bd.state_image_validate_ns +
			bd.private_rebase_validate_ns;
		shared_leaf_exclusive_ns =
			bd.shared_leaf_attach_ns > bd.upper_pt_alloc_ns ?
			bd.shared_leaf_attach_ns - bd.upper_pt_alloc_ns : 0;
		memset(&ctx->stats_v3, 0, sizeof(ctx->stats_v3));
		ctx->stats_v3.supported_mask = CXLFORK_RESTORE_V3_KNOWN_MASK &
			~(CXLFORK_RESTORE_V3_LEAF_MATERIALIZE |
			  CXLFORK_RESTORE_V3_DATA_COW);
		ctx->stats_v3.valid_mask = CXLFORK_RESTORE_V3_LOCK_WAIT |
			CXLFORK_RESTORE_V3_LIFECYCLE |
			CXLFORK_RESTORE_V3_MANIFEST |
			CXLFORK_RESTORE_V3_ADDR_CONFLICT |
			CXLFORK_RESTORE_V3_OTHER;
		if (full_validation)
			ctx->stats_v3.valid_mask |=
				CXLFORK_RESTORE_V3_IMAGE_VALIDATE |
				CXLFORK_RESTORE_V3_CHECKSUM;
		if (mapped_regions)
			ctx->stats_v3.valid_mask |= CXLFORK_RESTORE_V3_VMA_CREATE;
		if (bd.shared_leaf_count)
			ctx->stats_v3.valid_mask |= CXLFORK_RESTORE_V3_UPPER_PT |
				CXLFORK_RESTORE_V3_SHARED_LEAF;
		if (bd.pte_image_validate_ns)
			ctx->stats_v3.valid_mask |= CXLFORK_RESTORE_V3_PTE_VALIDATE;
		if (bd.direct_pte_install_pages)
			ctx->stats_v3.valid_mask |= CXLFORK_RESTORE_V3_PTE_INSTALL;
		if (bd.pte_image_reconstruct_pages)
			ctx->stats_v3.valid_mask |=
				CXLFORK_RESTORE_V3_FALLBACK_OTHER;
		if (bd.dirty_prefault_pages)
			ctx->stats_v3.valid_mask |= CXLFORK_RESTORE_V3_DIRTY_PREFAULT;
		if (bd.global_restore_ns)
			ctx->stats_v3.valid_mask |= CXLFORK_RESTORE_V3_GLOBAL;
		ctx->stats_v3.path_mask = path_mask;
		ctx->stats_v3.total_ns = op->restore_ns;
		ctx->stats_v3.lock_wait_ns = bd.lock_wait_ns;
		ctx->stats_v3.lifecycle_ns = bd.lifecycle_ns;
		ctx->stats_v3.manifest_validate_ns = bd.manifest_validate_ns;
		ctx->stats_v3.image_validate_ns = image_validate_ns;
		ctx->stats_v3.checksum_validate_ns = bd.checksum_validate_ns;
		ctx->stats_v3.address_conflict_ns = bd.address_conflict_ns;
		ctx->stats_v3.vma_create_ns = bd.vma_create_ns;
		ctx->stats_v3.upper_pt_alloc_ns = bd.upper_pt_alloc_ns;
		ctx->stats_v3.shared_leaf_attach_ns = shared_leaf_exclusive_ns;
		ctx->stats_v3.pte_image_validate_ns = bd.pte_image_validate_ns;
		ctx->stats_v3.direct_pte_install_ns = bd.direct_pte_install_ns;
		ctx->stats_v3.fallback_other_ns = bd.fallback_other_ns;
		ctx->stats_v3.dirty_prefault_ns = bd.dirty_prefault_ns;
		ctx->stats_v3.global_restore_ns = bd.global_restore_ns;
		ctx->stats_v3.shared_leaf_count = bd.shared_leaf_count;
		ctx->stats_v3.shared_data_pages = bd.shared_leaf_attach_pages;
		ctx->stats_v3.fallback_pages = bd.pte_image_reconstruct_pages;
		ctx->stats_v3.direct_pte_install_pages =
			bd.direct_pte_install_pages;
		ctx->stats_v3.dirty_prefault_pages = bd.dirty_prefault_pages;
		ctx->stats_v3.validated_ptes = full_validation ? desc->nr_ptes : 0;
		exclusive_accounted = ctx->stats_v3.lock_wait_ns +
			ctx->stats_v3.lifecycle_ns +
			ctx->stats_v3.manifest_validate_ns +
			ctx->stats_v3.image_validate_ns +
			ctx->stats_v3.checksum_validate_ns +
			ctx->stats_v3.address_conflict_ns +
			ctx->stats_v3.vma_create_ns +
			ctx->stats_v3.upper_pt_alloc_ns +
			ctx->stats_v3.shared_leaf_attach_ns +
			ctx->stats_v3.pte_image_validate_ns +
			ctx->stats_v3.direct_pte_install_ns +
			ctx->stats_v3.fallback_other_ns +
			ctx->stats_v3.dirty_prefault_ns +
			ctx->stats_v3.global_restore_ns;
		ctx->stats_v3.other_ns = op->restore_ns > exclusive_accounted ?
			op->restore_ns - exclusive_accounted : 0;
		spin_unlock_irqrestore(&ctx->lock, stats_flags);
	}
	if (legacy_uarg && copy_to_user(legacy_uarg, op, sizeof(*op))) {
		ret = -EFAULT;
		goto out_unlock;
	}
	if (v2) {
		v2->region_count = op->nr_regions;
		v2->restore_id = ctx ? ctx->restore_id : 0;
		v2->total_pages = op->total_pages;
		v2->page_checksum = desc->page_checksum;
		if (ctx) {
			unsigned long stats_flags;

			spin_lock_irqsave(&ctx->lock, stats_flags);
			v2->stats = ctx->stats;
			spin_unlock_irqrestore(&ctx->lock, stats_flags);
		}
		if (op->nr_regions &&
		    copy_to_user(u64_to_user_ptr(v2->regions_ptr), op->regions,
				 op->nr_regions * sizeof(op->regions[0]))) {
			ret = -EFAULT;
			goto out_unlock;
		}
		if (v2_uarg &&
		    copy_to_user(v2_uarg, v2, sizeof(*v2))) {
			ret = -EFAULT;
			goto out_unlock;
		}
	}
	if (state) {
		cxlfork_file_set_restore_ctx(state, ctx);
		file_ctx_attached = true;
	}
	if (apply_thread_state || apply_tls_state) {
		u64 activation_start = ktime_get_ns();

		if (apply_thread_state)
			ret = cxlfork_validate_thread_state(&desc->thread_state);
		if (!ret && apply_tls_state)
			cxlfork_apply_tls_state(desc);
		if (!ret && apply_thread_state)
			ret = cxlfork_apply_thread_state(desc);
		if (activation_commit_ns)
			*activation_commit_ns =
				ktime_get_ns() - activation_start;
	}

out_unlock:
	mutex_unlock(&cxlfork_lock);
	if (ret && mapped_regions) {
		u64 rollback_start = ktime_get_ns();

		while (mapped_regions--) {
			int unmap_ret = vm_munmap(regions[mapped_regions].start,
						  regions[mapped_regions].length);

			if (unmap_ret)
				pr_warn("cxlfork: restore rollback start=%llx len=%llx ret=%d\n",
					regions[mapped_regions].start,
					regions[mapped_regions].length, unmap_ret);
		}
		if (ctx) {
			unsigned long stats_flags;

			spin_lock_irqsave(&ctx->lock, stats_flags);
			ctx->stats.rollback_ns += ktime_get_ns() - rollback_start;
			spin_unlock_irqrestore(&ctx->lock, stats_flags);
		}
	}
	if (ctx) {
		if (!atomic_read(&ctx->mappings)) {
			cxlfork_restore_ctx_release_reader(ctx);
			cxlfork_restore_ctx_unregister(ctx);
		}
		if (ret && file_ctx_attached && state)
			cxlfork_file_set_restore_ctx(state, NULL);
		cxlfork_restore_ctx_put(ctx);
	}
out_return:
	return ret;
}

static int cxlfork_ioctl_restore(struct file *file,
				 struct cxlfork_restore __user *uarg)
{
	struct cxlfork_restore *op;
	int ret;

	op = memdup_user(uarg, sizeof(*op));
	if (IS_ERR(op))
		return PTR_ERR(op);
	ret = cxlfork_do_restore(file, op, uarg, NULL, NULL, NULL, false);
	kfree(op);
	return ret;
}

static int cxlfork_check_header(const void __user *uarg, size_t expected_size,
				u16 expected_version)
{
	const struct cxlfork_v2_header __user *header = uarg;
	u32 size;
	u16 version;
	u16 reserved;

	if (get_user(size, &header->size) ||
	    get_user(version, &header->abi_version) ||
	    get_user(reserved, &header->reserved))
		return -EFAULT;
	if (size != expected_size)
		return -EINVAL;
	if (version != expected_version)
		return -EPROTONOSUPPORT;
	if (reserved)
		return -EINVAL;
	return 0;
}

static int cxlfork_check_v2_header(const void __user *uarg, size_t expected_size)
{
	return cxlfork_check_header(uarg, expected_size,
				    CXLFORK_ABI_VERSION_V2);
}

static bool cxlfork_digest_is_zero(const u8 *digest)
{
	u32 i;

	for (i = 0; i < CXLFORK_CAPSULE_DIGEST_BYTES; i++)
		if (digest[i])
			return false;
	return true;
}

static int
cxlfork_validate_capsule_manifest(const struct cxlfork_capsule_manifest_v4 *m,
				  u64 scan_start, u64 scan_end)
{
	u32 i;

	if (m->manifest_version != CXLFORK_CAPSULE_MANIFEST_VERSION ||
	    !m->flags || (m->flags & ~CXLFORK_CAPSULE_F_KNOWN_MASK) ||
	    !(m->flags & CXLFORK_CAPSULE_F_COOPERATIVE_YIELD) ||
	    cxlfork_digest_is_zero(m->runtime_sha256) ||
	    cxlfork_digest_is_zero(m->image_sha256) ||
	    !m->context_va || !m->trampoline_ip || !m->activation_sp ||
	    !m->continuation_cookie || !m->state_checksum)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(m->reserved); i++)
		if (m->reserved[i])
			return -EINVAL;
	if (m->context_va < scan_start || m->context_va >= scan_end ||
	    m->context_va >= TASK_SIZE_MAX ||
	    m->trampoline_ip >= TASK_SIZE_MAX ||
	    m->activation_sp >= TASK_SIZE_MAX ||
	    (m->activation_sp & 0xf) != 8)
		return -EFAULT;
	if (!access_ok((void __user *)(unsigned long)m->context_va, 1) ||
	    !access_ok((void __user *)(unsigned long)m->trampoline_ip, 1) ||
	    !access_ok((void __user *)(unsigned long)(m->activation_sp - 8), 8))
		return -EFAULT;
	return 0;
}

static int
cxlfork_validate_capsule_identity(u64 key, u64 generation,
				  const u8 *runtime_sha256,
				  const u8 *image_sha256)
{
	struct cxlfork_desc *desc;
	int slot;
	int ret = 0;

	slot = key_to_slot(key);
	if (slot < 0)
		return slot;
	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!cxlfork_desc_key_ready(desc, key)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	if (desc->generation != generation) {
		ret = -ESTALE;
		goto out_unlock;
	}
	if (!desc->capsule_manifest_valid ||
	    cxlfork_validate_capsule_manifest(&desc->capsule_manifest,
					     desc->capsule_manifest.context_va,
					     desc->capsule_manifest.context_va + 1)) {
		ret = -EILSEQ;
		goto out_unlock;
	}
	if (memcmp(desc->capsule_manifest.runtime_sha256, runtime_sha256,
		   CXLFORK_CAPSULE_DIGEST_BYTES) ||
	    memcmp(desc->capsule_manifest.image_sha256, image_sha256,
		   CXLFORK_CAPSULE_DIGEST_BYTES))
		ret = -ENOEXEC;

out_unlock:
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static bool cxlfork_catalog_name_valid(const u8 *name, size_t size)
{
	size_t length;
	size_t i;

	length = strnlen((const char *)name, size);
	if (!length || length == size)
		return false;
	for (i = length + 1; i < size; i++)
		if (name[i])
			return false;
	return true;
}

static u64 cxlfork_catalog_identity_hash(
	const struct cxlfork_catalog_record_v4 *record)
{
	const u64 fnv_offset = 1469598103934665603ULL;
	const u64 fnv_prime = 1099511628211ULL;
	const u8 *parts[] = {
		record->owner,
		record->function,
		record->version,
	};
	const size_t sizes[] = {
		CXLFORK_CATALOG_OWNER_LEN,
		CXLFORK_CATALOG_FUNCTION_LEN,
		CXLFORK_CATALOG_VERSION_LEN,
	};
	u64 hash = fnv_offset;
	u32 part;
	size_t i;

	for (part = 0; part < ARRAY_SIZE(parts); part++)
		for (i = 0; i < sizes[part]; i++) {
			hash ^= parts[part][i];
			hash *= fnv_prime;
		}
	return hash ?: 1;
}

static bool cxlfork_catalog_identity_equal(
	const struct cxlfork_catalog_record_v4 *left,
	const struct cxlfork_catalog_record_v4 *right)
{
	return !memcmp(left->owner, right->owner,
		       CXLFORK_CATALOG_OWNER_LEN) &&
		!memcmp(left->function, right->function,
			CXLFORK_CATALOG_FUNCTION_LEN) &&
		!memcmp(left->version, right->version,
			CXLFORK_CATALOG_VERSION_LEN);
}

static int cxlfork_catalog_validate_identity(
	const struct cxlfork_catalog_record_v4 *record)
{
	if (!cxlfork_catalog_name_valid(record->owner,
					 CXLFORK_CATALOG_OWNER_LEN) ||
	    !cxlfork_catalog_name_valid(record->function,
					 CXLFORK_CATALOG_FUNCTION_LEN) ||
	    !cxlfork_catalog_name_valid(record->version,
					 CXLFORK_CATALOG_VERSION_LEN))
		return -EINVAL;
	return 0;
}

static struct cxlfork_catalog_shared *cxlfork_catalog_get(void)
{
	struct cxlfork_catalog_shared *catalog;
	u64 magic;
	u64 deadline;

	if (!cxl_range_valid(CXLFORK_CATALOG_OFFSET, sizeof(*catalog)))
		return ERR_PTR(-ENOSPC);
	catalog = cxl_ptr(CXLFORK_CATALOG_OFFSET);
	magic = smp_load_acquire(&catalog->magic);
	if (magic == CXLFORK_CATALOG_MAGIC_READY) {
		if (READ_ONCE(catalog->version) != CXLFORK_CATALOG_VERSION)
			return ERR_PTR(-EPROTONOSUPPORT);
		return catalog;
	}
	if (!magic &&
	    cmpxchg(&catalog->magic, 0, CXLFORK_CATALOG_MAGIC_INIT) == 0) {
		memset((u8 *)catalog + sizeof(catalog->magic), 0,
		       sizeof(*catalog) - sizeof(catalog->magic));
		WRITE_ONCE(catalog->version, CXLFORK_CATALOG_VERSION);
		smp_store_release(&catalog->magic,
				  CXLFORK_CATALOG_MAGIC_READY);
		return catalog;
	}
	deadline = ktime_get_ns() + NSEC_PER_SEC;
	do {
		magic = smp_load_acquire(&catalog->magic);
		if (magic == CXLFORK_CATALOG_MAGIC_READY) {
			if (READ_ONCE(catalog->version) !=
			    CXLFORK_CATALOG_VERSION)
				return ERR_PTR(-EPROTONOSUPPORT);
			return catalog;
		}
		if (magic != CXLFORK_CATALOG_MAGIC_INIT)
			return ERR_PTR(-EILSEQ);
		cpu_relax();
		cond_resched();
	} while (ktime_get_ns() < deadline);
	return ERR_PTR(-ETIMEDOUT);
}

static u64
cxlfork_catalog_next_generation(struct cxlfork_catalog_shared *catalog)
{
	u64 old;
	u64 next;

	do {
		old = READ_ONCE(catalog->next_generation);
		next = old + 1;
		if (!next)
			next = 1;
	} while (cmpxchg(&catalog->next_generation, old, next) != old);
	return next;
}

static int cxlfork_catalog_wait_entry(
	struct cxlfork_catalog_entry *entry, u64 *state)
{
	u64 deadline = ktime_get_ns() + NSEC_PER_SEC;

	do {
		*state = smp_load_acquire(&entry->state);
		if (*state != CXLFORK_CATALOG_ENTRY_WRITING)
			return 0;
		cpu_relax();
		cond_resched();
	} while (ktime_get_ns() < deadline);
	return -ETIMEDOUT;
}

static int cxlfork_catalog_validate_slot(
	struct cxlfork_catalog_record_v4 *record, bool fill)
{
	struct cxlfork_desc *desc;
	int slot;
	int ret = 0;

	slot = key_to_slot(record->key);
	if (slot < 0)
		return slot;
	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!cxlfork_desc_key_ready(desc, record->key) ||
	    desc->generation != record->slot_generation) {
		ret = -ESTALE;
		goto out_unlock;
	}
	if (!desc->capsule_manifest_valid) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	if (memcmp(desc->capsule_manifest.runtime_sha256,
		   record->runtime_sha256, CXLFORK_CAPSULE_DIGEST_BYTES) ||
	    memcmp(desc->capsule_manifest.image_sha256,
		   record->image_sha256, CXLFORK_CAPSULE_DIGEST_BYTES) ||
	    desc->capsule_manifest.state_checksum !=
		    record->state_checksum ||
	    (record->image_bytes &&
	     record->image_bytes != desc->image_bytes) ||
	    (record->page_checksum &&
	     record->page_checksum != desc->page_checksum)) {
		ret = -EILSEQ;
		goto out_unlock;
	}
	if (fill) {
		record->image_bytes = desc->image_bytes;
		record->page_checksum = desc->page_checksum;
	}

out_unlock:
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static int cxlfork_ioctl_prepare_v2(struct cxlfork_prepare_v2 __user *uarg)
{
	const u64 known_flags = CXLFORK_F_REOPEN_FDS |
		CXLFORK_F_USER_THREAD_STATE | CXLFORK_F_FULL_PRIVATE_STATE;
	struct cxlfork_checkpoint *legacy;
	struct cxlfork_prepare_v2 op;
	u32 i;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(op));
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.regions_ptr ||
	    op.region_capacity < CXLFORK_MAX_REGIONS ||
	    (op.flags & ~known_flags))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;

	legacy = kzalloc(sizeof(*legacy), GFP_KERNEL);
	if (!legacy)
		return -ENOMEM;
	legacy->key = op.key;
	legacy->scan_start = op.scan_start;
	legacy->scan_end = op.scan_end;
	legacy->flags = op.flags;
	memset(&op.stats, 0, sizeof(op.stats));
	op.region_count = 0;
	op.generation = 0;
	op.slot = 0;
	op.total_pages = 0;
	op.page_checksum = 0;
	ret = cxlfork_do_checkpoint(legacy, NULL, &op, uarg, NULL);
	kfree(legacy);
	return ret;
}

static int cxlfork_ioctl_resume_v2(struct file *file,
				   struct cxlfork_resume_v2 __user *uarg)
{
	const u64 known_flags = CXLFORK_F_MAP_READONLY |
		CXLFORK_F_PRIVATE_COW | CXLFORK_F_SHARED_COW |
		CXLFORK_F_APPLY_MM_STATE | CXLFORK_F_REOPEN_FDS |
		CXLFORK_F_APPLY_THREAD_STATE | CXLFORK_F_APPLY_TLS_STATE |
		CXLFORK_F_APPLY_GLOBAL_STATE | CXLFORK_F_HYBRID_TIERING |
		CXLFORK_F_VALIDATE_FULL |
		CXLFORK_F_TEST_FAIL_AFTER_FIRST_REGION;
	struct cxlfork_restore *legacy;
	struct cxlfork_resume_v2 op;
	u32 i;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(op));
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.generation || !op.regions_ptr ||
	    !op.region_capacity || (op.flags & ~known_flags))
		return -EINVAL;
	if (op.flags & CXLFORK_F_TEST_FAIL_AFTER_FIRST_REGION) {
		if (!IS_ENABLED(CONFIG_CXLFORK_SELFTEST))
			return -EOPNOTSUPP;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
	}
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;

	legacy = kzalloc(sizeof(*legacy), GFP_KERNEL);
	if (!legacy)
		return -ENOMEM;
	legacy->key = op.key;
	legacy->flags = op.flags & ~CXLFORK_F_TEST_FAIL_AFTER_FIRST_REGION;
	memset(&op.stats, 0, sizeof(op.stats));
	op.region_count = 0;
	op.restore_id = 0;
	op.total_pages = 0;
	op.page_checksum = 0;
	ret = cxlfork_do_restore(file, legacy, NULL, &op, uarg, NULL, false);
	kfree(legacy);
	return ret;
}

static int
cxlfork_ioctl_prepare_capsule_v4(
	struct cxlfork_prepare_capsule_v4 __user *uarg)
{
	struct cxlfork_prepare_capsule_v4 op;
	struct cxlfork_prepare_v2 v2 = {
		.size = sizeof(v2),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	struct cxlfork_checkpoint *legacy;
	u32 i;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || op.flags || !op.regions_ptr ||
	    op.region_capacity < CXLFORK_MAX_REGIONS)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;
	ret = cxlfork_validate_capsule_manifest(&op.manifest,
						op.scan_start,
						op.scan_end);
	if (ret)
		return ret;

	legacy = kzalloc(sizeof(*legacy), GFP_KERNEL);
	if (!legacy)
		return -ENOMEM;
	legacy->key = op.key;
	legacy->scan_start = op.scan_start;
	legacy->scan_end = op.scan_end;
	legacy->flags = CXLFORK_F_USER_THREAD_STATE;
	legacy->thread_state.ip = op.manifest.trampoline_ip;
	legacy->thread_state.sp = op.manifest.activation_sp;
	legacy->thread_state.flags = 0x202;
	v2.key = op.key;
	v2.scan_start = op.scan_start;
	v2.scan_end = op.scan_end;
	v2.flags = CXLFORK_F_USER_THREAD_STATE;
	v2.regions_ptr = op.regions_ptr;
	v2.region_capacity = op.region_capacity;
	ret = cxlfork_do_checkpoint(legacy, NULL, &v2, NULL,
				    &op.manifest);
	kfree(legacy);
	if (ret)
		return ret;

	op.region_count = v2.region_count;
	op.generation = v2.generation;
	op.slot = v2.slot;
	op.total_pages = v2.total_pages;
	op.page_checksum = v2.page_checksum;
	op.stats = v2.stats;
	memset(op.reserved1, 0, sizeof(op.reserved1));
	return copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;
}

static int
cxlfork_ioctl_resume_capsule_v4(
	struct file *file, struct cxlfork_resume_capsule_v4 __user *uarg)
{
	const u64 policy_mask = CXLFORK_F_MAP_READONLY |
		CXLFORK_F_PRIVATE_COW | CXLFORK_F_SHARED_COW |
		CXLFORK_F_HYBRID_TIERING;
	const u64 known_flags = policy_mask | CXLFORK_F_VALIDATE_FULL;
	struct cxlfork_file_state *state = file->private_data;
	struct cxlfork_resume_capsule_v4 op;
	struct cxlfork_resume_v2 v2 = {
		.size = sizeof(v2),
		.abi_version = CXLFORK_ABI_VERSION_V2,
	};
	struct cxlfork_restore *legacy;
	struct cxlfork_restore_ctx *ctx;
	unsigned long stats_flags;
	u64 capsule_start;
	u64 capsule_validate_ns;
	u64 activation_commit_ns;
	u32 i;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.generation || !op.regions_ptr ||
	    !op.region_capacity || (op.flags & ~known_flags) ||
	    hweight64(op.flags & policy_mask) != 1 ||
	    cxlfork_digest_is_zero(op.runtime_sha256) ||
	    cxlfork_digest_is_zero(op.image_sha256))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;

	capsule_start = ktime_get_ns();
	ret = cxlfork_validate_capsule_identity(op.key, op.generation,
					       op.runtime_sha256,
					       op.image_sha256);
	capsule_validate_ns = ktime_get_ns() - capsule_start;
	if (ret)
		return ret;

	legacy = kzalloc(sizeof(*legacy), GFP_KERNEL);
	if (!legacy)
		return -ENOMEM;
	legacy->key = op.key;
	legacy->flags = op.flags | CXLFORK_F_APPLY_THREAD_STATE;
	v2.key = op.key;
	v2.generation = op.generation;
	v2.flags = legacy->flags;
	v2.regions_ptr = op.regions_ptr;
	v2.region_capacity = op.region_capacity;
	ret = cxlfork_do_restore(file, legacy, NULL, &v2, NULL,
				 &activation_commit_ns, true);
	kfree(legacy);
	if (ret)
		return ret;

	ctx = state ? state->last_ctx : NULL;
	if (!ctx)
		return -EIO;
	memset(&op.stats, 0, sizeof(op.stats));
	spin_lock_irqsave(&ctx->lock, stats_flags);
	op.stats.core = ctx->stats_v3;
	spin_unlock_irqrestore(&ctx->lock, stats_flags);
	op.stats.supported_mask = CXLFORK_RESTORE_V4_KNOWN_MASK;
	op.stats.valid_mask = CXLFORK_RESTORE_V4_CAPSULE_VALIDATE |
		CXLFORK_RESTORE_V4_ACTIVATION_COMMIT;
	op.stats.path_mask = op.stats.core.path_mask;
	op.stats.capsule_validate_ns = capsule_validate_ns;
	op.stats.activation_commit_ns = activation_commit_ns;
	op.stats.total_ns = op.stats.core.total_ns +
		op.stats.capsule_validate_ns + op.stats.activation_commit_ns;
	spin_lock_irqsave(&ctx->lock, stats_flags);
	ctx->stats_v4 = op.stats;
	spin_unlock_irqrestore(&ctx->lock, stats_flags);

	op.region_count = v2.region_count;
	op.restore_id = v2.restore_id;
	op.total_pages = v2.total_pages;
	op.page_checksum = v2.page_checksum;
	memset(op.reserved1, 0, sizeof(op.reserved1));
	return copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;
}

static int
cxlfork_ioctl_inspect_capsule_v4(
	struct cxlfork_inspect_capsule_v4 __user *uarg)
{
	struct cxlfork_inspect_capsule_v4 op;
	struct cxlfork_desc *desc;
	u64 lifecycle;
	int slot;
	int ret = 0;
	u32 i;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;
	slot = key_to_slot(op.key);
	if (slot < 0)
		return slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!cxlfork_desc_key_ready(desc, op.key)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	if (!desc->capsule_manifest_valid) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	lifecycle = smp_load_acquire(&desc->state);
	op.generation = desc->generation;
	op.state = cxlfork_lifecycle_state(lifecycle);
	op.reader_count = cxlfork_lifecycle_readers(lifecycle);
	op.total_pages = desc->total_pages;
	op.page_checksum = desc->page_checksum;
	op.manifest = desc->capsule_manifest;
	memset(op.reserved1, 0, sizeof(op.reserved1));

out_unlock:
	mutex_unlock(&cxlfork_lock);
	if (ret)
		return ret;
	return copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;
}

static int cxlfork_catalog_record_reserved_zero(
	const struct cxlfork_catalog_record_v4 *record)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(record->reserved); i++)
		if (record->reserved[i])
			return -EINVAL;
	return 0;
}

static int
cxlfork_ioctl_catalog_register_v4(
	struct cxlfork_catalog_register_v4 __user *uarg)
{
	const u64 policy_mask = CXLFORK_F_MAP_READONLY |
		CXLFORK_F_PRIVATE_COW | CXLFORK_F_SHARED_COW |
		CXLFORK_F_HYBRID_TIERING;
	struct cxlfork_catalog_register_v4 op;
	struct cxlfork_catalog_shared *catalog;
	struct cxlfork_catalog_entry *entry;
	struct cxlfork_catalog_record_v4 record;
	u64 hash;
	u64 state;
	u32 probe;
	u32 index;
	int free_index;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	record = op.record;
	ret = cxlfork_catalog_validate_identity(&record);
	if (ret)
		return ret;
	if (!record.key || !record.slot_generation ||
	    !record.state_checksum ||
	    cxlfork_digest_is_zero(record.runtime_sha256) ||
	    cxlfork_digest_is_zero(record.image_sha256) ||
	    hweight64(record.policy & policy_mask) != 1 ||
	    (record.policy & ~policy_mask) ||
	    record.catalog_generation || record.index || record.flags)
		return -EINVAL;
	ret = cxlfork_catalog_record_reserved_zero(&record);
	if (ret)
		return ret;
	ret = cxlfork_catalog_validate_slot(&record, true);
	if (ret)
		return ret;
	catalog = cxlfork_catalog_get();
	if (IS_ERR(catalog))
		return PTR_ERR(catalog);
	hash = cxlfork_catalog_identity_hash(&record);

rescan:
	free_index = -1;
	for (probe = 0; probe < CXLFORK_CATALOG_MAX_ENTRIES; probe++) {
		index = (hash + probe) % CXLFORK_CATALOG_MAX_ENTRIES;
		entry = &catalog->entries[index];
retry:
		state = smp_load_acquire(&entry->state);
		if (state == CXLFORK_CATALOG_ENTRY_WRITING) {
			ret = cxlfork_catalog_wait_entry(entry, &state);
			if (ret)
				return ret;
			goto retry;
		}
		if (state == CXLFORK_CATALOG_ENTRY_READY) {
			if (READ_ONCE(entry->identity_hash) == hash &&
			    cxlfork_catalog_identity_equal(&entry->record,
							   &record))
				return -EEXIST;
			continue;
		}
		if (state != CXLFORK_CATALOG_ENTRY_FREE)
			return -EILSEQ;
		if (free_index < 0)
			free_index = index;
	}
	if (free_index < 0)
		return -ENOSPC;
	entry = &catalog->entries[free_index];
	if (cmpxchg(&entry->state, CXLFORK_CATALOG_ENTRY_FREE,
		    CXLFORK_CATALOG_ENTRY_WRITING) !=
	    CXLFORK_CATALOG_ENTRY_FREE)
		goto rescan;

	record.catalog_generation = cxlfork_catalog_next_generation(catalog);
	record.index = free_index;
	record.flags = CXLFORK_CATALOG_RECORD_F_READY;
	memset(record.reserved, 0, sizeof(record.reserved));
	WRITE_ONCE(entry->identity_hash, hash);
	memcpy(&entry->record, &record, sizeof(record));
	smp_store_release(&entry->state, CXLFORK_CATALOG_ENTRY_READY);
	op.record = record;
	if (copy_to_user(uarg, &op, sizeof(op))) {
		if (cmpxchg(&entry->state, CXLFORK_CATALOG_ENTRY_READY,
			    CXLFORK_CATALOG_ENTRY_WRITING) ==
		    CXLFORK_CATALOG_ENTRY_READY) {
			memset(&entry->record, 0, sizeof(entry->record));
			WRITE_ONCE(entry->identity_hash, 0);
			smp_store_release(&entry->state,
					  CXLFORK_CATALOG_ENTRY_FREE);
		}
		return -EFAULT;
	}
	return 0;
}

static int
cxlfork_ioctl_catalog_lookup_v4(
	struct cxlfork_catalog_lookup_v4 __user *uarg)
{
	struct cxlfork_catalog_lookup_v4 op;
	struct cxlfork_catalog_shared *catalog;
	struct cxlfork_catalog_entry *entry;
	struct cxlfork_catalog_record_v4 identity;
	struct cxlfork_catalog_record_v4 record;
	u64 hash;
	u64 state;
	u32 probe;
	u32 index;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	identity = op.record;
	ret = cxlfork_catalog_validate_identity(&identity);
	if (ret)
		return ret;
	if (identity.key || identity.slot_generation || identity.image_bytes ||
	    identity.page_checksum || identity.state_checksum ||
	    identity.policy || identity.catalog_generation || identity.index ||
	    identity.flags || !cxlfork_digest_is_zero(identity.runtime_sha256) ||
	    !cxlfork_digest_is_zero(identity.image_sha256))
		return -EINVAL;
	ret = cxlfork_catalog_record_reserved_zero(&identity);
	if (ret)
		return ret;
	catalog = cxlfork_catalog_get();
	if (IS_ERR(catalog))
		return PTR_ERR(catalog);
	hash = cxlfork_catalog_identity_hash(&identity);

	for (probe = 0; probe < CXLFORK_CATALOG_MAX_ENTRIES; probe++) {
		index = (hash + probe) % CXLFORK_CATALOG_MAX_ENTRIES;
		entry = &catalog->entries[index];
retry:
		state = smp_load_acquire(&entry->state);
		if (state == CXLFORK_CATALOG_ENTRY_WRITING) {
			ret = cxlfork_catalog_wait_entry(entry, &state);
			if (ret)
				return ret;
			goto retry;
		}
		if (state == CXLFORK_CATALOG_ENTRY_FREE)
			continue;
		if (state != CXLFORK_CATALOG_ENTRY_READY)
			return -EILSEQ;
		if (READ_ONCE(entry->identity_hash) != hash)
			continue;
		memcpy(&record, &entry->record, sizeof(record));
		smp_rmb();
		if (smp_load_acquire(&entry->state) !=
			    CXLFORK_CATALOG_ENTRY_READY ||
		    READ_ONCE(entry->record.catalog_generation) !=
			    record.catalog_generation)
			goto retry;
		if (!cxlfork_catalog_identity_equal(&record, &identity))
			continue;
		ret = cxlfork_catalog_validate_slot(&record, false);
		if (ret)
			return ret;
		op.record = record;
		return copy_to_user(uarg, &op, sizeof(op)) ?
			-EFAULT : 0;
	}
	return -ENOENT;
}

static int
cxlfork_ioctl_catalog_evict_v4(
	struct cxlfork_catalog_evict_v4 __user *uarg)
{
	struct cxlfork_catalog_evict_v4 op;
	struct cxlfork_catalog_record_v4 identity = {};
	struct cxlfork_catalog_shared *catalog;
	struct cxlfork_catalog_entry *entry;
	u64 hash;
	u64 state;
	u32 probe;
	u32 index;
	u32 i;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	memcpy(identity.owner, op.owner, sizeof(identity.owner));
	memcpy(identity.function, op.function, sizeof(identity.function));
	memcpy(identity.version, op.version, sizeof(identity.version));
	ret = cxlfork_catalog_validate_identity(&identity);
	if (ret)
		return ret;
	if (!op.catalog_generation)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;
	catalog = cxlfork_catalog_get();
	if (IS_ERR(catalog))
		return PTR_ERR(catalog);
	hash = cxlfork_catalog_identity_hash(&identity);

	for (probe = 0; probe < CXLFORK_CATALOG_MAX_ENTRIES; probe++) {
		index = (hash + probe) % CXLFORK_CATALOG_MAX_ENTRIES;
		entry = &catalog->entries[index];
retry:
		state = smp_load_acquire(&entry->state);
		if (state == CXLFORK_CATALOG_ENTRY_WRITING) {
			ret = cxlfork_catalog_wait_entry(entry, &state);
			if (ret)
				return ret;
			goto retry;
		}
		if (state == CXLFORK_CATALOG_ENTRY_FREE)
			continue;
		if (state != CXLFORK_CATALOG_ENTRY_READY)
			return -EILSEQ;
		if (READ_ONCE(entry->identity_hash) != hash ||
		    !cxlfork_catalog_identity_equal(&entry->record, &identity))
			continue;
		if (READ_ONCE(entry->record.catalog_generation) !=
		    op.catalog_generation)
			return -ESTALE;
		if (cmpxchg(&entry->state, CXLFORK_CATALOG_ENTRY_READY,
			    CXLFORK_CATALOG_ENTRY_WRITING) !=
		    CXLFORK_CATALOG_ENTRY_READY)
			goto retry;
		memset(&entry->record, 0, sizeof(entry->record));
		WRITE_ONCE(entry->identity_hash, 0);
		smp_store_release(&entry->state,
				  CXLFORK_CATALOG_ENTRY_FREE);
		return 0;
	}
	return -ENOENT;
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
		CXLFORK_CAP_MOW_DATA_COW |
		CXLFORK_CAP_MOA_DATA_COPY |
		CXLFORK_CAP_CONSISTENT_SINGLE_THREAD |
		CXLFORK_CAP_RELIABLE_SLOT_GENERATION |
		CXLFORK_CAP_USER_THREAD_CONTEXT_RESUME |
		CXLFORK_CAP_GLOBAL_FILE_STATE |
		CXLFORK_CAP_RESTORE_FAST_PATH |
		CXLFORK_CAP_A_BIT_HYBRID |
		CXLFORK_CAP_EXCLUSIVE_RESTORE_STATS |
		CXLFORK_CAP_COOPERATIVE_FUNCTION_CONTINUATION |
		CXLFORK_CAP_SHARED_CAPSULE_CATALOG;
	caps.cxl_phys = cxl_phys;
	caps.cxl_size = cxl_size;
	caps.slot_bytes = CXLFORK_SLOT_BYTES;
	caps.data_offset = CXLFORK_DATA_OFFSET;
	caps.page_size = PAGE_SIZE;
	caps.max_slots = cxlfork_nr_slots();
	caps.max_regions = CXLFORK_MAX_REGIONS;
	caps.max_ptes = CXLFORK_MAX_PTES;
	caps.descriptor_version = CXLFORK_DESC_VERSION;
	caps.mm_failfast_mask = CXLFORK_MM_FAILFAST_MPROTECT |
		CXLFORK_MM_FAILFAST_FORK | CXLFORK_MM_FAILFAST_GUP |
		CXLFORK_MM_FAILFAST_PARTIAL_MUNMAP |
		CXLFORK_MM_FAILFAST_MREMAP;
	caps.shared_leaf_alignment = PMD_SIZE;
	caps.restore_policy_mask = CXLFORK_F_MAP_READONLY |
		CXLFORK_F_PRIVATE_COW | CXLFORK_F_SHARED_COW |
		CXLFORK_F_HYBRID_TIERING;
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
	{
		u64 lifecycle = smp_load_acquire(&desc->state);

		inspect.state = cxlfork_lifecycle_state(lifecycle);
		inspect.reader_count = cxlfork_lifecycle_readers(lifecycle);
	}
	inspect.generation = READ_ONCE(desc->generation);
	smp_rmb();
	if (desc->slot != slot ||
	    desc->nr_regions > desc->region_table_entries ||
	    desc->nr_ptes > desc->pte_table_entries ||
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
	inspect.fd_table_offset = desc->fd_table_offset;
	inspect.fd_table_entries = desc->fd_table_entries;
	inspect.fd_table_bytes = desc->fd_table_bytes;
	inspect.region_table_offset = desc->region_table_offset;
	inspect.region_table_entries = desc->region_table_entries;
	inspect.region_table_bytes = desc->region_table_bytes;
	inspect.pte_table_offset = desc->pte_table_offset;
	inspect.pte_table_entries = desc->pte_table_entries;
	inspect.pte_table_bytes = desc->pte_table_bytes;
	inspect.page_data_offset = desc->data_offset;
	inspect.page_data_bytes = desc->total_pages << PAGE_SHIFT;
	inspect.extent_bytes = desc->extent_bytes;
	inspect.extent_count = desc->extent_count;
	inspect.extent_bitmap_words = desc->extent_bitmap_words;
	inspect.allocated_extents = desc->allocated_extents;
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
		cxlfork_inspect_vma_image(desc, address, &inspect);
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

static int cxlfork_do_release(u64 key, u64 expected_generation,
			      bool require_generation)
{
	struct cxlfork_desc *desc;
	int slot;
	int ret = 0;

	slot = key_to_slot(key);
	if (slot < 0)
		return slot;

	mutex_lock(&cxlfork_lock);
	desc = slot_desc(slot);
	if (!cxlfork_desc_key_ready(desc, key)) {
		ret = require_generation ? -ENOENT : 0;
		goto out_unlock;
	}
	if (require_generation && desc->generation != expected_generation) {
		ret = -ESTALE;
		goto out_unlock;
	}
	{
		u64 generation = desc->generation;
		u64 lifecycle = smp_load_acquire(&desc->state);

		if (cxlfork_lifecycle_state(lifecycle) != CXLFORK_SLOT_READY ||
		    cxlfork_lifecycle_readers(lifecycle)) {
			ret = -EBUSY;
			goto out_unlock;
		}
		if (cmpxchg(&desc->state, lifecycle,
			    cxlfork_lifecycle_pack(CXLFORK_SLOT_RELEASING, 0)) !=
		    lifecycle) {
			ret = -EBUSY;
			goto out_unlock;
		}
		cxlfork_restore_ctx_purge(key, generation);
		cxlfork_desc_reset_free(desc, generation);
	}

out_unlock:
	mutex_unlock(&cxlfork_lock);
	return ret;
}

static int cxlfork_ioctl_release(struct cxlfork_release __user *uarg)
{
	struct cxlfork_release rel;

	if (copy_from_user(&rel, uarg, sizeof(rel)))
		return -EFAULT;
	return cxlfork_do_release(rel.key, 0, false);
}

static int cxlfork_ioctl_release_v2(struct cxlfork_release_v2 __user *uarg)
{
	struct cxlfork_release_v2 op;
	u32 i;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(op));
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.generation || op.flags)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;
	return cxlfork_do_release(op.key, op.generation, true);
}

static int
cxlfork_ioctl_get_call_stats_v2(struct cxlfork_call_stats_v2 __user *uarg)
{
	struct cxlfork_call_stats_v2 op;
	struct cxlfork_restore_ctx *ctx;
	unsigned long flags;
	u32 i;
	int ret;

	ret = cxlfork_check_v2_header(uarg, sizeof(op));
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.generation || !op.restore_id)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;

	xa_lock(&cxlfork_restore_contexts);
	ctx = xa_load(&cxlfork_restore_contexts,
		      (unsigned long)op.restore_id);
	if (ctx && !kref_get_unless_zero(&ctx->ref))
		ctx = NULL;
	xa_unlock(&cxlfork_restore_contexts);
	if (!ctx)
		return -ENOENT;
	if (ctx->key != op.key) {
		ret = -ENOENT;
		goto out_put;
	}
	if (ctx->generation != op.generation) {
		ret = -ESTALE;
		goto out_put;
	}

	spin_lock_irqsave(&ctx->lock, flags);
	op.stats = ctx->stats;
	spin_unlock_irqrestore(&ctx->lock, flags);
	op.stats.faults = atomic64_read(&ctx->faults);
	/*
	 * shared_leaf_pages is the number of data pages covered by CXL PTE
	 * leaves attached during RESUME_V2.  shared_map_pages counts a different
	 * event (4 KiB CXL mappings inserted by the fault path), so it must not
	 * overwrite the per-call attach breakdown copied above.
	 */
	op.stats.local_copy_pages = atomic64_read(&ctx->local_copy_pages);
	op.stats.leaf_copy_pages = atomic64_read(&ctx->leaf_copy_pages);
	op.stats.fault_dispatch_ns = atomic64_read(&ctx->fault_dispatch_ns);
	op.stats.leaf_materialize_ns = atomic64_read(&ctx->leaf_materialize_ns);
	op.stats.data_cow_ns = atomic64_read(&ctx->data_cow_ns);
	op.stats.cxl_to_local_copy_ns =
		atomic64_read(&ctx->cxl_to_local_copy_ns);
	if (op.stats.faults)
		op.stats.valid_mask |= CXLFORK_RESTORE_STAT_FAULT_DISPATCH;
	if (op.stats.cxl_to_local_copy_ns)
		op.stats.valid_mask |= CXLFORK_RESTORE_STAT_CXL_COPY;
	memset(op.reserved1, 0, sizeof(op.reserved1));
	ret = copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;

out_put:
	cxlfork_restore_ctx_put(ctx);
	return ret;
}

static int
cxlfork_ioctl_get_call_stats_v3(struct cxlfork_call_stats_v3 __user *uarg)
{
	struct cxlfork_call_stats_v3 op;
	struct cxlfork_restore_ctx *ctx;
	unsigned long flags;
	u32 i;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op), CXLFORK_ABI_VERSION_V3);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.generation || !op.restore_id)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;

	xa_lock(&cxlfork_restore_contexts);
	ctx = xa_load(&cxlfork_restore_contexts,
		      (unsigned long)op.restore_id);
	if (ctx && !kref_get_unless_zero(&ctx->ref))
		ctx = NULL;
	xa_unlock(&cxlfork_restore_contexts);
	if (!ctx)
		return -ENOENT;
	if (ctx->key != op.key) {
		ret = -ENOENT;
		goto out_put;
	}
	if (ctx->generation != op.generation) {
		ret = -ESTALE;
		goto out_put;
	}

	spin_lock_irqsave(&ctx->lock, flags);
	op.stats = ctx->stats_v3;
	spin_unlock_irqrestore(&ctx->lock, flags);
	op.stats.faults = atomic64_read(&ctx->faults);
	op.stats.local_copy_pages = atomic64_read(&ctx->local_copy_pages);
	op.stats.leaf_copy_pages = atomic64_read(&ctx->leaf_copy_pages);
	op.stats.fault_dispatch_ns = atomic64_read(&ctx->fault_dispatch_ns);
	op.stats.leaf_materialize_ns = atomic64_read(&ctx->leaf_materialize_ns);
	op.stats.data_cow_ns = atomic64_read(&ctx->data_cow_ns);
	op.stats.cxl_to_local_copy_ns =
		atomic64_read(&ctx->cxl_to_local_copy_ns);
	if (op.stats.faults)
		op.stats.valid_mask |= CXLFORK_RESTORE_V3_FAULT_DISPATCH;
	if (op.stats.cxl_to_local_copy_ns)
		op.stats.valid_mask |= CXLFORK_RESTORE_V3_CXL_COPY;
	memset(op.reserved1, 0, sizeof(op.reserved1));
	ret = copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;

out_put:
	cxlfork_restore_ctx_put(ctx);
	return ret;
}

static int
cxlfork_ioctl_get_call_stats_v4(struct cxlfork_call_stats_v4 __user *uarg)
{
	struct cxlfork_call_stats_v4 op;
	struct cxlfork_restore_ctx *ctx;
	unsigned long flags;
	u32 i;
	int ret;

	ret = cxlfork_check_header(uarg, sizeof(op),
				   CXLFORK_ABI_VERSION_V4);
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.key || !op.generation || !op.restore_id)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;

	xa_lock(&cxlfork_restore_contexts);
	ctx = xa_load(&cxlfork_restore_contexts,
		      (unsigned long)op.restore_id);
	if (ctx && !kref_get_unless_zero(&ctx->ref))
		ctx = NULL;
	xa_unlock(&cxlfork_restore_contexts);
	if (!ctx)
		return -ENOENT;
	if (ctx->key != op.key) {
		ret = -ENOENT;
		goto out_put;
	}
	if (ctx->generation != op.generation) {
		ret = -ESTALE;
		goto out_put;
	}

	spin_lock_irqsave(&ctx->lock, flags);
	op.stats = ctx->stats_v4;
	spin_unlock_irqrestore(&ctx->lock, flags);
	if (!op.stats.supported_mask) {
		ret = -EOPNOTSUPP;
		goto out_put;
	}
	op.stats.core.faults = atomic64_read(&ctx->faults);
	op.stats.core.local_copy_pages =
		atomic64_read(&ctx->local_copy_pages);
	op.stats.core.leaf_copy_pages =
		atomic64_read(&ctx->leaf_copy_pages);
	op.stats.core.fault_dispatch_ns =
		atomic64_read(&ctx->fault_dispatch_ns);
	op.stats.core.leaf_materialize_ns =
		atomic64_read(&ctx->leaf_materialize_ns);
	op.stats.core.data_cow_ns = atomic64_read(&ctx->data_cow_ns);
	op.stats.core.cxl_to_local_copy_ns =
		atomic64_read(&ctx->cxl_to_local_copy_ns);
	if (op.stats.core.faults)
		op.stats.core.valid_mask |=
			CXLFORK_RESTORE_V3_FAULT_DISPATCH;
	if (op.stats.core.cxl_to_local_copy_ns)
		op.stats.core.valid_mask |= CXLFORK_RESTORE_V3_CXL_COPY;
	memset(op.reserved1, 0, sizeof(op.reserved1));
	ret = copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;

out_put:
	cxlfork_restore_ctx_put(ctx);
	return ret;
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

#ifdef CONFIG_CXLFORK_SELFTEST
static struct cxlfork_litmus_shared *cxlfork_litmus_shared(void)
{
	if (!cxl_range_valid(CXLFORK_LITMUS_OFFSET,
			     sizeof(struct cxlfork_litmus_shared)))
		return NULL;
	return cxl_ptr(CXLFORK_LITMUS_OFFSET);
}

static u64 cxlfork_litmus_payload(u64 run_id, u64 sequence, u32 word)
{
	return run_id ^ (sequence * 0x9e3779b97f4a7c15ULL) ^
		((u64)(word + 1) * 0xd6e8feb86659fd93ULL);
}

static void cxlfork_litmus_atomic_inc(u64 *value)
{
	u64 old;

	do {
		old = READ_ONCE(*value);
	} while (cmpxchg(value, old, old + 1) != old);
}

static int cxlfork_litmus_wait_acquire(u64 *value, u64 expected,
				       u64 deadline)
{
	u64 spins = 0;

	for (;;) {
		if (smp_load_acquire(value) == expected)
			return 0;
		if (ktime_get_ns() >= deadline)
			return -ETIMEDOUT;
		cpu_relax();
		if (!(++spins & 0xffff) && need_resched())
			cond_resched();
	}
}

static int cxlfork_litmus_validate_run(struct cxlfork_litmus_shared *shared,
				       u64 run_id)
{
	if (READ_ONCE(shared->magic) != CXLFORK_LITMUS_MAGIC)
		return -ENOENT;
	if (smp_load_acquire(&shared->run_id) != run_id)
		return -ESTALE;
	return 0;
}

static int cxlfork_litmus_rmw(struct cxlfork_litmus_shared *shared,
			      const struct cxlfork_litmus_v2 *op)
{
	u64 i;

	for (i = 0; i < op->iterations; i++)
		cxlfork_litmus_atomic_inc(&shared->counter);
	cxlfork_litmus_atomic_inc(&shared->completions);
	return 0;
}

static int cxlfork_litmus_message(struct cxlfork_litmus_shared *shared,
				  const struct cxlfork_litmus_v2 *op,
				  u64 deadline)
{
	u64 sequence;
	u32 word;
	int ret;

	if (op->role == CXLFORK_LITMUS_ROLE_0) {
		for (sequence = 1; sequence <= op->iterations; sequence++) {
			ret = cxlfork_litmus_wait_acquire(
				&shared->acknowledgement, sequence - 1, deadline);
			if (ret)
				return ret;
			for (word = 0; word < CXLFORK_LITMUS_PAYLOAD_WORDS; word++)
				WRITE_ONCE(shared->payload[word],
					   cxlfork_litmus_payload(op->run_id,
								   sequence, word));
			smp_store_release(&shared->sequence, sequence);
		}
		ret = cxlfork_litmus_wait_acquire(&shared->acknowledgement,
						  op->iterations, deadline);
	} else {
		for (sequence = 1; sequence <= op->iterations; sequence++) {
			ret = cxlfork_litmus_wait_acquire(&shared->sequence,
							  sequence, deadline);
			if (ret)
				return ret;
			for (word = 0; word < CXLFORK_LITMUS_PAYLOAD_WORDS; word++) {
				u64 expected = cxlfork_litmus_payload(op->run_id,
								       sequence, word);

				if (READ_ONCE(shared->payload[word]) != expected)
					cxlfork_litmus_atomic_inc(&shared->errors);
			}
			smp_store_release(&shared->acknowledgement, sequence);
		}
		ret = 0;
	}
	if (!ret)
		cxlfork_litmus_atomic_inc(&shared->completions);
	return ret;
}

static int cxlfork_litmus_pingpong(struct cxlfork_litmus_shared *shared,
				   const struct cxlfork_litmus_v2 *op,
				   u64 deadline)
{
	u64 sequence;
	int ret;

	for (sequence = 1; sequence <= op->iterations; sequence++) {
		if (op->role == CXLFORK_LITMUS_ROLE_0) {
			ret = cxlfork_litmus_wait_acquire(&shared->token, 0,
							  deadline);
			if (ret)
				return ret;
			WRITE_ONCE(shared->payload[0],
				   cxlfork_litmus_payload(op->run_id, sequence, 0));
			smp_store_release(&shared->token, 1);
		} else {
			u64 expected;

			ret = cxlfork_litmus_wait_acquire(&shared->token, 1,
							  deadline);
			if (ret)
				return ret;
			expected = cxlfork_litmus_payload(op->run_id, sequence, 0);
			if (READ_ONCE(shared->payload[0]) != expected)
				cxlfork_litmus_atomic_inc(&shared->errors);
			smp_store_release(&shared->token, 0);
		}
	}
	if (op->role == CXLFORK_LITMUS_ROLE_0) {
		ret = cxlfork_litmus_wait_acquire(&shared->token, 0, deadline);
		if (ret)
			return ret;
	}
	cxlfork_litmus_atomic_inc(&shared->completions);
	return 0;
}

static int cxlfork_ioctl_litmus_v2(struct cxlfork_litmus_v2 __user *uarg)
{
	struct cxlfork_litmus_shared *shared;
	struct cxlfork_litmus_v2 op;
	u64 deadline;
	int ret = 0;
	u32 i;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (op.size != sizeof(op))
		return -EINVAL;
	if (op.abi_version != CXLFORK_ABI_VERSION_V2)
		return -EPROTONOSUPPORT;
	if (op.reserved0)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;
	if (op.op > CXLFORK_LITMUS_QUERY ||
	    op.role > CXLFORK_LITMUS_ROLE_1)
		return -EINVAL;
	shared = cxlfork_litmus_shared();
	if (!shared)
		return -ENOSPC;

	if (op.op == CXLFORK_LITMUS_RESET) {
		if (!op.run_id)
			return -EINVAL;
		memset(shared, 0, sizeof(*shared));
		WRITE_ONCE(shared->magic, CXLFORK_LITMUS_MAGIC);
		smp_store_release(&shared->run_id, op.run_id);
		goto out_copy;
	}

	ret = cxlfork_litmus_validate_run(shared, op.run_id);
	if (ret)
		return ret;
	if (op.op == CXLFORK_LITMUS_QUERY)
		goto out_copy;
	if (!op.iterations || op.iterations > 10000000ULL ||
	    !op.timeout_ns || op.timeout_ns > 60000000000ULL)
		return -EINVAL;
	if (check_add_overflow(ktime_get_ns(), op.timeout_ns, &deadline))
		return -EINVAL;

	switch (op.op) {
	case CXLFORK_LITMUS_RMW:
		ret = cxlfork_litmus_rmw(shared, &op);
		break;
	case CXLFORK_LITMUS_MESSAGE:
		ret = cxlfork_litmus_message(shared, &op, deadline);
		break;
	case CXLFORK_LITMUS_PINGPONG:
		ret = cxlfork_litmus_pingpong(shared, &op, deadline);
		break;
	default:
		ret = -EINVAL;
	}
	if (ret)
		return ret;

out_copy:
	op.counter = READ_ONCE(shared->counter);
	op.completions = READ_ONCE(shared->completions);
	op.errors = READ_ONCE(shared->errors);
	op.sequence = READ_ONCE(shared->sequence);
	op.acknowledgement = READ_ONCE(shared->acknowledgement);
	op.token = READ_ONCE(shared->token);
	return copy_to_user(uarg, &op, sizeof(op)) ? -EFAULT : 0;
}

static int cxlfork_ioctl_gup_probe_v2(struct cxlfork_gup_probe_v2 __user *uarg)
{
	struct cxlfork_gup_probe_v2 op;
	struct page *page = NULL;
	unsigned int gup_flags = 0;
	int ret;
	u32 i;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	ret = cxlfork_check_v2_header(uarg, sizeof(op));
	if (ret)
		return ret;
	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;
	if (!op.address || !IS_ALIGNED(op.address, PAGE_SIZE) ||
	    (op.flags & ~CXLFORK_GUP_PROBE_KNOWN_MASK))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(op.reserved1); i++)
		if (op.reserved1[i])
			return -EINVAL;
	if (op.flags & CXLFORK_GUP_PROBE_WRITE)
		gup_flags |= FOLL_WRITE;
	if (op.flags & CXLFORK_GUP_PROBE_LONGTERM)
		gup_flags |= FOLL_LONGTERM;
	ret = pin_user_pages_fast(op.address, 1, gup_flags, &page);
	if (ret == 1) {
		unpin_user_page(page);
		return 0;
	}
	return ret;
}
#endif

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
	if (desc->slot != slot ||
	    desc->nr_regions > desc->region_table_entries ||
	    desc->nr_ptes > desc->pte_table_entries ||
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
	inspect.fd_table_offset = desc->fd_table_offset;
	inspect.fd_table_entries = desc->fd_table_entries;
	inspect.fd_table_bytes = desc->fd_table_bytes;
	inspect.region_table_offset = desc->region_table_offset;
	inspect.region_table_entries = desc->region_table_entries;
	inspect.region_table_bytes = desc->region_table_bytes;
	inspect.pte_table_offset = desc->pte_table_offset;
	inspect.pte_table_entries = desc->pte_table_entries;
	inspect.pte_table_bytes = desc->pte_table_bytes;
	inspect.page_data_offset = desc->data_offset;
	inspect.page_data_bytes = desc->total_pages << PAGE_SHIFT;
	inspect.extent_bytes = desc->extent_bytes;
	inspect.extent_count = desc->extent_count;
	inspect.extent_bitmap_words = desc->extent_bitmap_words;
	inspect.allocated_extents = desc->allocated_extents;
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
		cxlfork_inspect_vma_image(desc, address, &inspect);
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
	struct cxlfork_file_state *state = file->private_data;

	if (state) {
		if (state->last_ctx)
			cxlfork_restore_ctx_put(state->last_ctx);
		kfree(state);
	}
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
	case CXLFORK_PREPARE_V2:
		return cxlfork_ioctl_prepare_v2((void __user *)arg);
	case CXLFORK_RESUME_V2:
		return cxlfork_ioctl_resume_v2(file, (void __user *)arg);
	case CXLFORK_RELEASE_V2:
		return cxlfork_ioctl_release_v2((void __user *)arg);
	case CXLFORK_INSPECT_V2:
		return cxlfork_ioctl_inspect_v2((void __user *)arg);
	case CXLFORK_PTE_MARK_V2:
		return cxlfork_ioctl_pte_mark_v2((void __user *)arg);
#ifdef CONFIG_CXLFORK_SELFTEST
	case CXLFORK_LITMUS_V2:
		return cxlfork_ioctl_litmus_v2((void __user *)arg);
	case CXLFORK_GUP_PROBE_V2:
		return cxlfork_ioctl_gup_probe_v2((void __user *)arg);
#endif
	case CXLFORK_GET_CALL_STATS_V2:
		return cxlfork_ioctl_get_call_stats_v2((void __user *)arg);
	case CXLFORK_GET_CALL_STATS_V3:
		return cxlfork_ioctl_get_call_stats_v3((void __user *)arg);
	case CXLFORK_PREPARE_CAPSULE_V4:
		return cxlfork_ioctl_prepare_capsule_v4((void __user *)arg);
	case CXLFORK_RESUME_CAPSULE_V4:
		return cxlfork_ioctl_resume_capsule_v4(file,
						       (void __user *)arg);
	case CXLFORK_INSPECT_CAPSULE_V4:
		return cxlfork_ioctl_inspect_capsule_v4((void __user *)arg);
	case CXLFORK_GET_CALL_STATS_V4:
		return cxlfork_ioctl_get_call_stats_v4((void __user *)arg);
	case CXLFORK_CATALOG_REGISTER_V4:
		return cxlfork_ioctl_catalog_register_v4((void __user *)arg);
	case CXLFORK_CATALOG_LOOKUP_V4:
		return cxlfork_ioctl_catalog_lookup_v4((void __user *)arg);
	case CXLFORK_CATALOG_EVICT_V4:
		return cxlfork_ioctl_catalog_evict_v4((void __user *)arg);
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

	if (!cxlfork_nr_slots())
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
