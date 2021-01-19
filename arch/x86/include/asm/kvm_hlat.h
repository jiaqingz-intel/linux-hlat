#ifndef _ASM_X86_KVM_HLAT_H
#define _ASM_X86_KVM_HLAT_H

#include <asm/kvm_para.h>
#include <asm/vdso.h>
#include <uapi/linux/kvm_para.h>

#define KVM_PAT_RO		1ULL
#define KVM_PAT_PW		2ULL
#define KVM_PAT_VPW		4ULL

#define KVM_HLAT_SET_ROOT	0x00
#define KVM_HLAT_RESET_PAT	0x01
#define KVM_HLAT_SET_EPT_PW	0x02
#define KVM_HLAT_CREATE_PXD	0x11
#define KVM_HLAT_MAP		0x12
#define KVM_HLAT_UNMAP		0x13

#define MSR_CTLS3_HLAT_BIT	(1ull << 1)
#define MSR_CTLS3_PW_BIT	(1ull << 2)
#define MSR_CTLS3_VPW_BIT	(1ull << 3)

#ifdef CONFIG_KVM_GUEST_HLAT
void kvm_hlat_reset(void);
unsigned long hlat_root_va(void);
void hlat_vdso_workaround_prepare(const struct vdso_image *image);
void hlat_vdso_workaround_apply(void);
int hlat_set_ro(unsigned long addr, int numpages);
int hlat_set_rw(unsigned long addr, int numpages);
int hlat_set_x(unsigned long addr, int numpages);
int hlat_set_nx(unsigned long addr, int numpages);
int hlat_unmap(unsigned long addr, int numpages);
#else
static inline unsigned long hlat_root_va(void) { return 0; }
static inline int hlat_set_ro(unsigned long addr, int numpages) { return 0; }
static inline int hlat_set_rw(unsigned long addr, int numpages) { return 0; }
static inline int hlat_set_x(unsigned long addr, int numpages) { return 0; }
static inline int hlat_set_nx(unsigned long addr, int numpages) { return 0; }
static inline int hlat_unmap(unsigned long addr, int numpages) { return 0; }
#endif

#endif /* _ASM_X86_KVM_HLAT_H */
