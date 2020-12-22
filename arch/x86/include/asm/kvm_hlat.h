#ifndef _ASM_X86_KVM_HLAT_H
#define _ASM_X86_KVM_HLAT_H

#include <asm/kvm_para.h>
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

#endif /* _ASM_X86_KVM_HLAT_H */
