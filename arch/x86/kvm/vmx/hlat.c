#include <asm/kvm_hlat.h>
#include <asm/kvm_host.h>
#include <asm/kvm_page_track.h>
#include <asm/vmx.h>

#include "hlat.h"
#include "mmu.h"
#include "vmx.h"

/* Activate/deactivate a tracking mode for a guest page */
static void kvm_set_pat_one(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot, gfn_t gfn,
			   enum kvm_page_track_mode mode, bool set)
{
	/* KVM guest page tracking is protected by slots_lock and mmu_lock */
	mutex_lock(&vcpu->kvm->slots_lock);
	write_lock(&vcpu->kvm->mmu_lock);
	if (!(kvm_page_track_is_active(vcpu, gfn, mode) ^ set))
		goto unlock;

	if (set)
		kvm_slot_page_track_add_page(vcpu->kvm, slot, gfn, mode);
	else
		kvm_slot_page_track_remove_page(vcpu->kvm, slot, gfn, mode);

	/* Zap spte to flush stale entries */
	kvm_zap_gfn_range_locked(vcpu->kvm, gfn, gfn + 1);
unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	mutex_unlock(&vcpu->kvm->slots_lock);
}

/* Set PAT for a guest page */
static int kvm_set_clr_pat(struct kvm_vcpu *vcpu, gfn_t gfn, unsigned long pat, bool set)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	if (!slot)
		return -EFAULT;

	if (pat & KVM_PAT_RO)
		kvm_set_pat_one(vcpu, slot, gfn, KVM_PAGE_TRACK_GUEST_RO, set);
	if (pat & KVM_PAT_PW)
		kvm_set_pat_one(vcpu, slot, gfn, KVM_PAGE_TRACK_GUEST_PW, set);
	if (pat & KVM_PAT_VPW)
		kvm_set_pat_one(vcpu, slot, gfn, KVM_PAGE_TRACK_GUEST_VPW, set);

	return 0;
}

static inline int kvm_set_pat(struct kvm_vcpu *vcpu, gfn_t gfn, unsigned long pat)
{
	return kvm_set_clr_pat(vcpu, gfn, pat, 1);
}

static inline int kvm_clear_pat(struct kvm_vcpu *vcpu, gfn_t gfn, unsigned long pat)
{
	return kvm_set_clr_pat(vcpu, gfn, pat, 0);
}

static int kvm_hlat_set_root(struct kvm_vcpu *vcpu, bool enable,
			     unsigned long hlatp, unsigned long plr)
{
	if (enable) {
		if (plr > vmx_hlat_plr_max_prefix())
			return -E2BIG;

		vcpu->arch.hlat_pointer = hlatp;
		vmcs_write64(HLAT_POINTER, hlatp);
		vmcs_write16(HLAT_PLR_PREFIX_SIZE, (u16)plr);

		tertiary_exec_controls_set(to_vmx(vcpu),
			tertiary_exec_controls_get(to_vmx(vcpu)) | TERTIARY_EXEC_HLAT);
	} else {
		tertiary_exec_controls_set(to_vmx(vcpu),
			tertiary_exec_controls_get(to_vmx(vcpu)) & ~TERTIARY_EXEC_HLAT);

		vcpu->arch.hlat_pointer = 0;
		vmcs_write64(HLAT_POINTER, 0);
		vmcs_write16(HLAT_PLR_PREFIX_SIZE, 0);
	}

	return 0;
}

static int kvm_clear_pat_all(struct kvm_vcpu *vcpu, unsigned long pat)
{
	int i, ret = 0;
	gfn_t gfn;
	struct kvm_memory_slot *slot;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
		kvm_for_each_memslot(slot, __kvm_memslots(vcpu->kvm, i))
			for (gfn = slot->base_gfn; gfn < slot->npages + slot->base_gfn; gfn++)
				ret |= kvm_clear_pat(vcpu, gfn, pat);

	return ret;
}

static int kvm_hlat_reset_pat(struct kvm_vcpu *vcpu)
{
	/* Clear VPW first, then RO and PW, to avoid VPW violation */
	kvm_clear_pat_all(vcpu, KVM_PAT_VPW);
	kvm_clear_pat_all(vcpu, KVM_PAT_RO | KVM_PAT_PW);

	return 0;
}

static int kvm_hlat_set_ept_pw(struct kvm_vcpu *vcpu, unsigned long gfn)
{
	return kvm_set_pat(vcpu, gfn, KVM_PAT_PW);
}

static int kvm_hlat_create_pgtable(struct kvm_vcpu *vcpu, unsigned long page_gpa)
{
	u64 pxd_gpa = page_gpa;
	u64 pxd = _PAGE_PRESENT | _PAGE_RESTART;
	int ret = 0;

	/* set restart and present bits on all pxes */
	while (pxd_gpa < page_gpa + PAGE_SIZE) {
		ret |= kvm_vcpu_write_guest(vcpu, pxd_gpa, &pxd, sizeof(pxd));
		pxd_gpa += sizeof(pxd);
	}

	kvm_set_pat(vcpu, gpa_to_gfn(page_gpa), KVM_PAT_RO | KVM_PAT_PW);

	return ret;
}

static int kvm_hlat_create_pxd(struct kvm_vcpu *vcpu, unsigned long pxd_gpa, unsigned long page_gpa)
{
	u64 pxd;

	/* if pxd gpa is 0, just create a new page table at page gpa */
	if (pxd_gpa == 0)
		return kvm_hlat_create_pgtable(vcpu, page_gpa);

	if (kvm_vcpu_read_guest(vcpu, pxd_gpa, &pxd, sizeof(pxd)) != 0)
		return -EFAULT;

	/* only create pxd mapping when pxe is empty */
	if (!(pxd & _PAGE_RESTART))
		return -EINVAL;

	if (kvm_hlat_create_pgtable(vcpu, page_gpa) != 0)
		return -EFAULT;

	pxd = __phys_to_pfn(page_gpa) << PAGE_SHIFT | _PAGE_PRESENT | _PAGE_RW;
	return kvm_vcpu_write_guest(vcpu, pxd_gpa, &pxd, sizeof(pxd));
}

static int kvm_hlat_map(struct kvm_vcpu *vcpu, unsigned long pte_gpa,
			unsigned long pteval)
{
	pte_t pte;

	if (kvm_vcpu_read_guest(vcpu, pte_gpa, &pte, sizeof(pte)) != 0)
		return -EFAULT;

	if (!(pte_val(pte) & _PAGE_RESTART) && pte_pfn(__pte(pteval)) != pte_pfn(pte))
		return -EPERM;

	pte = __pte(pteval);
	kvm_set_pat(vcpu, pte_pfn(pte), KVM_PAT_VPW);
	return kvm_vcpu_write_guest(vcpu, pte_gpa, &pte, sizeof(pte));
}

static int kvm_hlat_unmap(struct kvm_vcpu *vcpu, unsigned long pte_gpa)
{
	pte_t pte;

	if (kvm_vcpu_read_guest(vcpu, pte_gpa, &pte, sizeof(pte)) != 0)
		return -EFAULT;

	/* The hlat entry isn't mapped */
	if (pte_val(pte) & _PAGE_RESTART)
		return 0;

	kvm_clear_pat(vcpu, pte_pfn(pte), KVM_PAT_VPW);
	pte = __pte(_PAGE_PRESENT | _PAGE_RESTART);
	return kvm_vcpu_write_guest(vcpu, pte_gpa, &pte, sizeof(pte));
}

int kvm_hlat_handle_hypercall(struct kvm_vcpu *vcpu, unsigned long subop,
			      unsigned long arg1, unsigned long arg2,
			      unsigned long arg3)
{
	int ret;

	switch (subop) {
	case KVM_HLAT_SET_ROOT:
		return kvm_hlat_set_root(vcpu, arg1, arg2, arg3);
	case KVM_HLAT_RESET_PAT:
		return kvm_hlat_reset_pat(vcpu);
	case KVM_HLAT_CREATE_PXD:
		return kvm_hlat_create_pxd(vcpu, arg1, arg2);
	case KVM_HLAT_MAP:
		return kvm_hlat_map(vcpu, arg1, arg2);
	case KVM_HLAT_UNMAP:
		return kvm_hlat_unmap(vcpu, arg1);
	case KVM_HLAT_SET_EPT_PW:
		return kvm_hlat_set_ept_pw(vcpu, arg1);
	default:
		ret = -EOPNOTSUPP;
	}

	return ret;
}


#ifdef CONFIG_KVM_INTEL_HLAT_DEBUG
#include "../cpuid.h"

spinlock_t printk_lock;

static void dump_guest_pagetable(struct kvm_vcpu *vcpu, gpa_t base_gpa, gva_t gva, bool restart)
{
	gpa_t pgd_gpa, p4d_gpa, pud_gpa, pmd_gpa, pte_gpa, page_gpa;
	pgd_t pgd;
	p4d_t p4d;
	pud_t pud;
	pmd_t pmd;
	pte_t pte;

	if (restart)
		pr_info("... HLATP: %llx ...\n", base_gpa);
	else
		pr_info("... CR3: %llx ...\n", base_gpa);

	kvm_mmu_dump_gpa(vcpu, base_gpa);

	pgd_gpa = base_gpa + pgd_index(gva) * sizeof(pgd);
	kvm_vcpu_read_guest(vcpu, pgd_gpa, &pgd, sizeof(pgd));
	pr_info("PGD %lx at %llx\n", pgd_val(pgd), pgd_gpa);
	kvm_mmu_dump_gpa(vcpu, pgd_gpa);
	if (!pgd_present(pgd) || (restart && pgd_restart(pgd)))
		return;

	p4d_gpa = kvm_cpu_cap_get(X86_FEATURE_LA57) ?
			((pgd_pfn(pgd) << PAGE_SHIFT) + p4d_index(gva) * sizeof(p4d)) : pgd_gpa;
	kvm_vcpu_read_guest(vcpu, p4d_gpa, &p4d, sizeof(p4d));
	pr_info("P4D %lx at %llx\n", p4d_val(p4d), p4d_gpa);
	kvm_mmu_dump_gpa(vcpu, p4d_gpa);
	if (!p4d_present(p4d) || p4d_large(p4d) || (restart && p4d_restart(p4d)))
		return;

	pud_gpa = (p4d_pfn(p4d) << PAGE_SHIFT) + pud_index(gva) * sizeof(pud);
	kvm_vcpu_read_guest(vcpu, pud_gpa, &pud, sizeof(pud));
	pr_info("PUD %lx at %llx\n", pud_val(pud), pud_gpa);
	kvm_mmu_dump_gpa(vcpu, pud_gpa);
	if (!pud_present(pud) || pud_large(pud) || (restart && pud_restart(pud)))
		return;

	pmd_gpa = (pud_pfn(pud) << PAGE_SHIFT) + pmd_index(gva) * sizeof(pmd);
	kvm_vcpu_read_guest(vcpu, pmd_gpa, &pmd, sizeof(pmd));
	pr_info("PMD %lx at %llx\n", pmd_val(pmd), pmd_gpa);
	kvm_mmu_dump_gpa(vcpu, pmd_gpa);
	if (!pmd_present(pmd) || pmd_large(pmd) || (restart && pmd_restart(pmd)))
		return;

	pte_gpa = (pmd_pfn(pmd) << PAGE_SHIFT) + pte_index(gva) * sizeof(pte);
	kvm_vcpu_read_guest(vcpu, pte_gpa, &pte, sizeof(pte));
	pr_info("PTE %lx at %llx\n", pte_val(pte), pte_gpa);
	kvm_mmu_dump_gpa(vcpu, pte_gpa);
	if (!pte_present(pte) || (restart && pte_restart(pte)))
		return;

	page_gpa = pte_pfn(pte) << PAGE_SHIFT;
	pr_info("PAGE at %llx\n", page_gpa);
	kvm_mmu_dump_gpa(vcpu, page_gpa);
}

int debug_vpw_violation(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	gva_t gva = vmcs_readl(GUEST_LINEAR_ADDRESS);
	gpa_t hlatp = vcpu->arch.hlat_pointer;
	gpa_t cr3 = (kvm_read_cr3(vcpu) >> PAGE_SHIFT) << PAGE_SHIFT;

	spin_lock(&printk_lock);

	pr_info("*** VPW violation when accessing GVA %lx GPA %llx ***\n", gva, gpa);
	kvm_mmu_dump_gpa(vcpu, gpa);
	dump_guest_pagetable(vcpu, hlatp, gva, 1);
	dump_guest_pagetable(vcpu, cr3, gva, 0);

	spin_unlock(&printk_lock);

	return 1;
}

#endif
