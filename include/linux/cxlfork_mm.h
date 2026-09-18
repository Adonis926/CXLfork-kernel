/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CXLFORK_MM_H
#define _LINUX_CXLFORK_MM_H

#include <linux/mm_types.h>

#ifdef CONFIG_CXLFORK
bool cxlfork_pmd_is_shared_leaf(pmd_t pmd);
bool cxlfork_vma_is_restored(const struct vm_area_struct *vma);
int cxlfork_gup_check_range(struct mm_struct *mm, unsigned long start,
			    unsigned long end);
int cxlfork_fork_check_mm(struct mm_struct *mm);
void cxlfork_zap_shared_leaf_pmd(struct mm_struct *mm, pmd_t *pmd,
				 unsigned long addr);
int cxlfork_materialize_shared_leaf_pmd(struct vm_area_struct *vma,
					pmd_t *pmd, unsigned long addr);
void cxlfork_account_data_cow(struct vm_area_struct *vma, u64 start_ns);
#else
static inline bool cxlfork_pmd_is_shared_leaf(pmd_t pmd)
{
	return false;
}

static inline bool cxlfork_vma_is_restored(const struct vm_area_struct *vma)
{
	return false;
}

static inline int cxlfork_gup_check_range(struct mm_struct *mm,
				   unsigned long start, unsigned long end)
{
	return 0;
}

static inline int cxlfork_fork_check_mm(struct mm_struct *mm)
{
	return 0;
}

static inline void cxlfork_zap_shared_leaf_pmd(struct mm_struct *mm,
					       pmd_t *pmd,
					       unsigned long addr)
{
}

static inline int cxlfork_materialize_shared_leaf_pmd(struct vm_area_struct *vma,
						      pmd_t *pmd,
						      unsigned long addr)
{
	return 0;
}

static inline void cxlfork_account_data_cow(struct vm_area_struct *vma,
					     u64 start_ns)
{
}
#endif

#endif /* _LINUX_CXLFORK_MM_H */
