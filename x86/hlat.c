#include "libcflat.h"
#include "alloc_page.h"
#include "alloc.h"
#include "vmalloc.h"
#include "asm/io.h"
#include "x86/desc.h"
#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/vm.h"

#define KVM_PAT_RO      1ULL
#define KVM_PAT_PW      2ULL
#define KVM_PAT_VPW     4ULL

#define KVM_HYPERCALL ".byte 0x0f,0x01,0xc1"

static inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
				  unsigned long p2, unsigned long p3,
				  unsigned long p4)
{
	long ret;
	asm volatile(KVM_HYPERCALL
		     : "=a"(ret)
		     : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4)
		     : "memory");
	return ret;
}

#define KVM_HC_HLAT			12

#define KVM_VMX_SET_HLAT		0x00
#define KVM_HLAT_RESET_PAT		0x01
#define KVM_VMX_SET_EPT_PW		0x02
#define KVM_HLAT_CREATE_PXD		0x11
#define KVM_HLAT_MAP			0x12
#define KVM_HLAT_UNMAP			0x13

static inline long kvm_hc_hlat_create_pxd(phys_addr_t pxd_pa, phys_addr_t page_pa)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_CREATE_PXD, pxd_pa, page_pa, 0);
}

static inline long kvm_hc_hlat_reset_pat(void)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_RESET_PAT, 0, 0, 0);
}

static inline long kvm_hc_vmx_set_ept_pw(phys_addr_t pa)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_VMX_SET_EPT_PW, pa >> PAGE_SHIFT, 0, 0);
}

static inline long kvm_hc_hlat_map_pte(phys_addr_t pte_pa, pteval_t pteval)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_MAP, pte_pa, pteval, 0);
}

static inline long kvm_hc_hlat_unmap_pte(phys_addr_t pte_pa)
{
	return kvm_hypercall4(KVM_HC_HLAT, KVM_HLAT_UNMAP, pte_pa, 0, 0);
}

struct wav_data {
	u64 *addr;
	u64 data;
};

static bool write_and_verify(void *wav_data)
{
	u64 *addr = ((struct wav_data *)wav_data)->addr;
	u64 val = ((struct wav_data *)wav_data)->data;

	*addr = val;

	return (*(volatile u64*)addr == val);
}

static inline void _write_and_verify(void* wav_data)
{
	write_and_verify(wav_data);
}

static bool initial_pgtable_valid(u64* page)
{
	u64* ptr;

	for (ptr = page; ptr < page + PAGE_SIZE; ptr++) {
		if (!(*ptr | PT_RESTART_MASK)) {
			return false;
		}
	}

	return true;
}

static void test1(void)
{
	u64* page = alloc_page();
	u64* child = alloc_page();
	u64* pxd = page + 1;

	struct wav_data wav = {
		.addr = page,
		.data = 0xdeadbeefbadc0ffe,
	};

	force_4k_page(page);
	force_4k_page(child);

	printf("=== test 1: create pxd & ept ro & reset pat ===\n");

	report(write_and_verify(&wav), "write non ept ro page");

	report(!kvm_hc_hlat_create_pxd(0, virt_to_phys(page)), "create root pgtable");

	report(initial_pgtable_valid(page), "page table entries (all reset bits are set)");

	report(test_for_exception(VE_VECTOR, _write_and_verify, &wav), "write ept ro page");

	report(!kvm_hc_hlat_create_pxd(virt_to_phys(pxd), virt_to_phys(child)), "create 2nd level pgtable");

	report(!(*pxd & PT_RESTART_MASK), "pxd restart bit cleared");

	report(((*pxd & PAGE_MASK) >> PAGE_SHIFT) == (virt_to_phys(child) >> PAGE_SHIFT), "pxd entry address");

	report(kvm_hc_hlat_create_pxd(virt_to_phys(pxd), virt_to_phys(child)), "deny create pxd on second time");

	report(!kvm_hc_hlat_reset_pat(), "reset pat hypercall");

	report(write_and_verify(&wav), "write after pat reset");

	free_page(page);
	free_page(child);
}

static void test2(void)
{
	u64* page = alloc_page();
	u64* pgtable = alloc_page();
	u64* pte = pgtable;
	pteval_t pteval = virt_to_phys(page) | PT_PRESENT_MASK | PT_USER_MASK | PT_WRITABLE_MASK;

	force_4k_page(page);
	force_4k_page(pgtable);

	printf("=== test 2: pte map/unmap ===\n");

	assert(!kvm_hc_hlat_create_pxd(0, virt_to_phys(pgtable)));

	report(kvm_hc_hlat_map_pte(0xffffffff00000000, pteval), "modify pte at invalid address");

	report(!kvm_hc_hlat_map_pte(virt_to_phys(pte), pteval), "map pte");

	report(!(*pte & PT_RESTART_MASK) && (*pte == pteval), "pte value after map");

	report(kvm_hc_hlat_map_pte(virt_to_phys(pte), 0xc0ffe007), "deny update pte with different gfn");

	report(!kvm_hc_hlat_map_pte(virt_to_phys(pte), pteval | PT64_NX_MASK), "update pte with different prot");

	report(*pte == (pteval | PT64_NX_MASK), "pte value after update");

	report(!kvm_hc_hlat_unmap_pte(virt_to_phys(pte)), "unmap pte");

	report(*pte & PT_RESTART_MASK, "pte value after unmap");

	kvm_hc_hlat_reset_pat();
	free_page(page);
	free_page(pgtable);
}

static void test3(void)
{
	u64* page = alloc_page();
	u64* pgtable = alloc_page();
	u64* pte = pgtable, *pxd;
	pteval_t pteval = virt_to_phys(page) | PT_PRESENT_MASK | PT_USER_MASK | PT_WRITABLE_MASK;

	struct wav_data wav = {
		.addr = page,
		.data = 0xbadc0ffe,
	};

	force_4k_page(page);
	force_4k_page(pgtable);

	printf("=== test 3: ept pw ===\n");

	report(write_and_verify(&wav), "write non-ept pw/vpw page");

	report(!kvm_hc_vmx_set_ept_pw(virt_to_phys(page)), "set ept pw on page (hypercall)");

	report(write_and_verify(&wav), "write ept pw page");

	kvm_hc_hlat_reset_pat();

	assert(!kvm_hc_hlat_create_pxd(0, virt_to_phys(pgtable)));
	assert(!kvm_hc_hlat_map_pte(virt_to_phys(pte), pteval));

	report(test_for_exception(VE_VECTOR, _write_and_verify, &wav), "write ept vpw page");

	assert(!kvm_hc_hlat_unmap_pte(virt_to_phys(pte)));

	wav.data = 0xdeadbeef;
	report(write_and_verify(&wav), "write page after unmapping");

	// set page's page table pw, then try write it
	assert(!kvm_hc_hlat_map_pte(virt_to_phys(pte), pteval));

	report(test_for_exception(VE_VECTOR, _write_and_verify, &wav), "write ept vpw page");

	report(!kvm_hc_vmx_set_ept_pw(read_cr3()), "set ept pw on cr3 root page table");
	for (int i = 4; i >= 1; i--) {
		pxd = get_pte_level(current_page_table(), page, i);
		if (pxd) {
			report(!kvm_hc_vmx_set_ept_pw(*pxd & PT_ADDR_MASK), "set ept pw on level %d page table", i);
		}
	}

	report(write_and_verify(&wav), "write vpw page after setting pw on its page tables");

	kvm_hc_hlat_reset_pat();
	free_page(page);
	free_page(pgtable);
}

int main(int ac, char **av)
{
	u64 msr_ctls3, msr_vpid;

	setup_vm();

	if (!this_cpu_has(X86_FEATURE_KVM_HLAT)) {
		printf("cpuid: hypervisor HLAT support not detected\n");
		return 0;
	}
	printf("cpuid: hypervisor HLAT support detected\n");

	msr_ctls3 = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS3);
	msr_vpid = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	printf("MSR_IA32_VMX_PROCBASED_CTLS3: 0x%016lx, MSR_IA32_VMX_EPT_VPID_CAP %016lx\n", msr_ctls3, msr_vpid);
	printf("  HLAT   : %s\n", msr_ctls3 & MSR_CTLS3_HLAT_BIT ? "supported" : "unsupported");
	printf("  EPT PW : %s\n", msr_ctls3 & MSR_CTLS3_PW_BIT ? "supported" : "unsupported");
	printf("  EPT VPW: %s\n", msr_ctls3 & MSR_CTLS3_VPW_BIT ? "supported" : "unsupported");
	printf("  MAX PLR: %lu\n", (msr_vpid >> 48) & 0x3f);

	if (!(msr_ctls3 & (MSR_CTLS3_HLAT_BIT | MSR_CTLS3_PW_BIT | MSR_CTLS3_VPW_BIT))) {
		printf("msr: hlat unsupported, exit\n");
		return 0;
	}

	test1();
	test2();
	test3();

	return 0;
}
