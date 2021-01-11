#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/mm.h>
#include <linux/syscore_ops.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/text-patching.h>
#include <asm/set_memory.h>
#include <asm/kvm_hlat.h>

static bool hlat_enable __initdata = true;

static int __init parse_nohlat(char *p)
{
	hlat_enable = 0;
	return 0;
}
early_param("nohlat", parse_nohlat);

struct page *hlat_root;

unsigned long hlat_root_va(void)
{
	return (unsigned long)page_address(hlat_root);
}

static inline long kvm_hc_hlat_setup_root(unsigned long hlatp, unsigned long plr)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_SET_ROOT, true, hlatp, plr);
}

static inline long kvm_hc_hlat_reset_root(void)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_SET_ROOT, false, 0, 0);
}

static inline long kvm_hc_hlat_reset_pat(void)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_RESET_PAT, 0, 0, 0);
}

static inline long kvm_hc_hlat_set_ept_pw(unsigned long pfn)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_SET_EPT_PW, pfn, 0, 0);
}

static inline long kvm_hc_hlat_create_pxd(void *pxd, struct page *page)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_CREATE_PXD,
			pxd ? __pa(pxd) : 0, __pfn_to_phys(page_to_pfn(page)), 0);
}

static inline long kvm_hc_hlat_map_pte(pte_t *pte, pteval_t pteval)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_MAP, __pa(pte), pteval, 0);
}

static inline long kvm_hc_hlat_unmap_pte(pte_t *pte)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_UNMAP, __pa(pte), 0, 0);
}

static int hlat_alloc_pages(struct page **pages, int nr)
{
	int i;

	if (!pages || !nr)
		return -EINVAL;
	for (i = 0; i < nr; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i])
			goto fail;
	}
	return 0;

fail:
	for (i--; i >= 0; i--) {
		free_page((unsigned long)page_address(pages[i]));
		pages[i] = NULL;
	}
	return -ENOMEM;
}

/*
 * get a page table entry from hlat page table
 * create its parent if not exist
 * also unprotect its related paging table
 */
static pte_t *hlat_get_pte(unsigned long address, bool alloc)
{
	struct page *pts[4];
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	int i = 0;

	if (alloc)
		if (hlat_alloc_pages(pts, 4))
			panic("No memory for hlat page table\n");

	pgd = (pgd_t *)page_address(hlat_root) + pgd_index(address);
	if (pgd_restart(*pgd)) {
		if (!alloc)
			goto out;
		kvm_hc_hlat_create_pxd(pgd, pts[i]);
		pts[i++] = NULL;
	}

	p4d = p4d_offset(pgd, address);
	if (p4d_restart(*p4d)) {
		if (!alloc)
			goto out;
		kvm_hc_hlat_create_pxd(p4d, pts[i]);
		pts[i++] = NULL;
	}

	pud = pud_offset(p4d, address);
	if (pud_restart(*pud)) {
		if (!alloc)
			goto out;
		kvm_hc_hlat_create_pxd(pud, pts[i]);
		pts[i++] = NULL;
	}

	pmd = pmd_offset(pud, address);
	if (pmd_restart(*pmd)) {
		if (!alloc)
			goto out;
		kvm_hc_hlat_create_pxd(pmd, pts[i]);
		pts[i++] = NULL;
	}

	return pte_offset_kernel(pmd, address);

out:
	if (alloc) {
		for (i = 0; i < 4; i++) {
			if (pts[i])
				free_page((unsigned long)page_address(pts[i]));
		}
	}

	return NULL;
}

static int hlat_attr_set_clr_one(unsigned long addr, pgprot_t mask_set, pgprot_t mask_clr)
{
	pte_t *pte, *cr3_pte = NULL;
	unsigned long pfn;
	pgprot_t prot;
	unsigned int level;

	pte = hlat_get_pte(addr, true);
	WARN_ON(pte == NULL);

	/* copy pte from cr3 if restart bit is set, also read prot from it */
	if (pgprot_val(pte_pgprot(*pte)) & _PAGE_RESTART) {
retry:
		cr3_pte = lookup_address(addr, &level);
		if (!cr3_pte || pte_none(*cr3_pte))
			return -EEXIST;

		if (level != PG_LEVEL_4K) {
			set_memory_4k(addr, 1);
			goto retry;
		}

		pfn = pte_pfn(*cr3_pte);
		prot = pte_pgprot(*cr3_pte);
	} else {
		pfn = pte_pfn(*pte);
		prot = pte_pgprot(*pte);
	}

	mask_set = canon_pgprot(mask_set);
	pgprot_val(prot) &= ~pgprot_val(mask_clr);
	pgprot_val(prot) |= pgprot_val(mask_set);

	return kvm_hc_hlat_map_pte(pte, pte_val(pfn_pte(pfn, prot)));
}

static int hlat_attr_set_clr(unsigned long addr, int numpages, pgprot_t mask_set, pgprot_t mask_clr)
{
	int ret = 0;

	if (!hlat_root)
		return 0;

	for (; numpages > 0; numpages--, addr += PAGE_SIZE)
		ret |= hlat_attr_set_clr_one(addr, mask_set, mask_clr);

	return ret;
}

static inline int hlat_attr_set(unsigned long addr, int numpages, pgprot_t mask)
{
	return hlat_attr_set_clr(addr, numpages, mask, __pgprot(0));
}

static inline int hlat_attr_clear(unsigned long addr, int numpages, pgprot_t mask)
{
	return hlat_attr_set_clr(addr, numpages, __pgprot(0), mask);
}

int hlat_set_ro(unsigned long addr, int numpages)
{
	return hlat_attr_clear(addr, numpages, __pgprot(_PAGE_RW));
}

int hlat_set_rw(unsigned long addr, int numpages)
{
	return hlat_attr_set(addr, numpages, __pgprot(_PAGE_RW));
}

int hlat_set_x(unsigned long addr, int numpages)
{
	return hlat_attr_clear(addr, numpages, __pgprot(_PAGE_NX));
}

int hlat_set_nx(unsigned long addr, int numpages)
{
	return hlat_attr_set(addr, numpages, __pgprot(_PAGE_NX));
}

static int hlat_unmap_one(unsigned long addr)
{
	pte_t *pte = hlat_get_pte(addr, false);

	/* if not in hlat page table, simply ignore it */
	if (!pte)
		return 0;

	return kvm_hc_hlat_unmap_pte(pte);
}

int hlat_unmap(unsigned long addr, int numpages)
{
	if (!hlat_root)
		return 0;

	for (; numpages > 0; numpages--, addr += PAGE_SIZE)
		hlat_unmap_one(addr);

	return 0;
}

/* Set PW bit on all poking page table pages to prevent VPW violation */
static void hlat_poking_workaround(void)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	kvm_hc_hlat_set_ept_pw(__phys_to_pfn(__pa((unsigned long)poking_mm->pgd)));

	pgd = pgd_offset(poking_mm, poking_addr);
	kvm_hc_hlat_set_ept_pw(pgd_pfn(*pgd));

	p4d = p4d_offset(pgd, poking_addr);
	kvm_hc_hlat_set_ept_pw(p4d_pfn(*p4d));

	pud = pud_offset(p4d, poking_addr);
	kvm_hc_hlat_set_ept_pw(pud_pfn(*pud));

	pmd = pmd_offset(pud, poking_addr);
	kvm_hc_hlat_set_ept_pw(pmd_pfn(*pmd));

	pr_info("kvm_hlat: poking workaround done\n");
}

static void kvm_hlat_reset_root(void *data)
{
	kvm_hc_hlat_reset_root();
}

static void kvm_hlat_reset(void)
{
	kvm_hc_hlat_reset_pat();
	kvm_hlat_reset_root(NULL);
	smp_call_function(kvm_hlat_reset_root, NULL, 1);
}

static struct syscore_ops kvm_hlat_syscore_ops = {
	.shutdown = kvm_hlat_reset,
};

static void kvm_hlat_init_percpu(void *data)
{
	int ret;

	ret = kvm_hc_hlat_setup_root(__pfn_to_phys(page_to_pfn(hlat_root)), 0);
	if (ret)
		pr_info("kvm_hlat: failed to setup hlat on CPU %d.\n", smp_processor_id());
}

static int __init kvm_hlat_init(void)
{
	u64 msr_ctls3 = 0;

	if (!hlat_enable) {
		pr_info("kvm_hlat: disabled\n");
		return 0;
	}

	if (!kvm_para_has_feature(KVM_FEATURE_HLAT))
		goto unsupported;

	rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS3, msr_ctls3);
	if (!(msr_ctls3 & (MSR_CTLS3_HLAT_BIT | MSR_CTLS3_PW_BIT | MSR_CTLS3_VPW_BIT)))
		goto unsupported;

	pr_info("kvm_hlat: host hlat support detected");

	hlat_root = alloc_page(GFP_KERNEL);
	if (!hlat_root) {
		pr_info("kvm_hlat: failed to allocate hlat root page table\n");
		return -ENOMEM;
	}

	register_syscore_ops(&kvm_hlat_syscore_ops);
	hlat_poking_workaround();

	/* setup hlat root page table page */
	kvm_hc_hlat_create_pxd(NULL, hlat_root);

	kvm_hlat_init_percpu(NULL);
	smp_call_function(kvm_hlat_init_percpu, NULL, 1);
	pr_info("kvm_hlat: hlat enabled, root pfn: %lx\n", page_to_pfn(hlat_root));

	return 0;

unsupported:
	pr_info("kvm_hlat: host does not support hlat\n");
	return 0;
}

arch_initcall(kvm_hlat_init);

struct vdso_image_entry {
	struct list_head node;
	const struct vdso_image *image;
};

LIST_HEAD(vdso_images);

void hlat_vdso_workaround_prepare(const struct vdso_image *image)
{
	struct vdso_image_entry *entry;

	if (!hlat_root)
		return;

	list_for_each_entry(entry, &vdso_images, node)
		if (entry->image == image)
			return;

	entry = kmalloc(sizeof(struct vdso_image_entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->image = image;
	list_add_tail(&entry->node, &vdso_images);

	pr_info("kvm_hlat: vdso_workaround: added vdso image at pa %lx, size: %lu\n",
		__pa(image->data), image->size);
}

void hlat_vdso_workaround_apply(void)
{
	struct vdso_image_entry *entry, *temp;

	if (!hlat_root)
		return;

	list_for_each_entry_safe(entry, temp, &vdso_images, node) {
		/* unprotect vdso images in hlat */
		hlat_unmap((unsigned long)entry->image->data, (entry->image->size) >> PAGE_SHIFT);

		list_del(&entry->node);
		kfree(entry);
	}

	pr_info("kvm_hlat: vdso workaround done\n");
}
