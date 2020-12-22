#ifndef __KVM_X86_VMX_HLAT_H
#define __KVM_X86_VMX_HLAT_H

int kvm_hlat_handle_hypercall(struct kvm_vcpu *vcpu, unsigned long subop,
			      unsigned long arg1, unsigned long arg2,
			      unsigned long arg3);

#endif /* __KVM_X86_VMX_HLAT_H */
