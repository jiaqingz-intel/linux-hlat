# HLAT - How To

## Build kernel

### 1. Get source code

```bash
# 5.10
git clone -b 5.10-hlat https://github.com/jiaqingz-intel/linux-hlat.git
# 5.12
git clone -b 5.12-hlat https://github.com/jiaqingz-intel/linux-hlat.git
# 5.13
git clone -b 5.13-hlat https://github.com/jiaqingz-intel/linux-hlat.git
```


### 2. Enable HLAT-related kernel configs

* `CONFIG_KVM_GUEST_HLAT=y` Enable guest HLAT support.
* `CONFIG_KVM_INTEL_HLAT=y` Enable KVM HLAT support.
* `CONFIG_KVM_INTEL_HLAT_DEBUG=y` Dump page table in host when VPW violation occurs.

Host and guest can use the same kernel if all the configs above are enabled.

It is suggested to add a custom kernel version string in `CONFIG_LOCALVERSION`. e.g. "-hlat".


### 3. Compile and install

1. Compile the kernel using `make -j($nproc)`.
2. Install with `make INSTALL_MOD_STRIP=1 modules_install && make install`.
3. If needed, update grub menu entry with `update-grub` on Debian/Ubuntu or `grub2-mkconfig -o "$(readlink -e /etc/grub2-efi.cfg)"` on CentOS/Fedora.
4. Reboot to the new kernel.

After reboot, run `dmesg | grep hlat` and check if one of these line exists:

```
[    0.655544] kvm_hlat: host does not support hlat
[    2.596225] kvm_hlat: host hlat support detected
```

HLAT feature will automatically enabled when host support detected. You can disable it by adding `nohlat` to kernel boot parameters.

## Build kvm-unit-tests

1. Get source code with `git clone -b kvm-unit-tests https://github.com/jiaqingz-intel/linux-hlat.git`.
2. Build with `make -j($nproc)`.
3. Run `run_hlat_tests.sh`


## More tests

### Test on page table conflict

1. Download [hlat-page-table-conflict-test.patch](./tests/hlat-page-table-conflict-test.patch)
2. Apply it to your kernel with `git apply hlat-page-table-conflict-test.patch`.
3. Re-build and install the kernel in your guest.
4. In your guest, run `modprobe test_hlat_pat` or `modprobe test_hlat_remap`.

If HLAT is working, you will see something like:

```
$ modprobe test_hlat_pat
[  314.594467] Set ffff93891853c000 to ro in CR3 PT
[  314.614140] Set ffff93891853c000 to ro in HLAT PT
[  314.634739] Set ffff93891853c000 to rw in CR3 PT
[  314.656215] Trying to write ffff93891853c000, it should panic here
[  314.684911] BUG: unable to handle page fault for address: ffff93891853c000
[  314.721057] #PF: supervisor write access in kernel mode
[  314.747410] #PF: error_code(0x0003) - permissions violation
$ modprobe test_hlat_remap
[  323.854308] Page1 at ffff93890df8f000 values 114514. Page2 at ffff93891d0160 values 1919810
[  323.874752] Set page 1 and page 2 to rw in both CR3 and HLAT PT
[  323.888816] Page 1 pteval 800000010df8f163. Page 2 pteval 800000011d016163
[  323.904886] Write pte2 with pte1's pfn
[  323.904897] Page 1 pteval 800000010df8f163. Page 2 pteval 800000010df8f163
[  323.929874] Page1 at ffff93890df8f000 values 114514. Page2 at ffff93891d0160 values 1919810
[  323.949210] Page 2 is PROTECTED
```

Otherwise, it looks like:

```
$ modprobe test_hlat_pat
[   18.342941] Set ffff8d210bc01000 to ro in CR3 PT
[   18.353614] Set ffff8d210bc01000 to ro in HLAT PT
[   18.364046] Set ffff8d210bc01000 to rw in CR3 PT
[   18.374525] Trying to write ffff8d210bc01000, it should panic here
[   18.387781] Test fail!!!
$ modprobe test_hlat_remap
[   27.662137] Page1 at ffff8d210bc27000 values 114514. Page2 at ffff8d21097c2000 values 1919810
[   27.680489] Set page 1 and page 2 to rw in both CR3 and HLAT PT
[   27.693169] Page 1 pteval 800000010bc27163. Page 2 pteval 80000001097c2163
[   27.707068] Write pte2 with pte1's pfn
[   27.707071] Page 1 pteval 800000010bc27163. Page 2 pteval 800000010bc27163
[   27.725076] Page1 at ffff8d210bc27000 values 114514. Page2 at ffff8d21097c2000 values 114514
[   27.738730] Page 2 is UNPROTECTED
```


### Test on alias mapping

This test checks if PW/VPW bits can prevent alias mappings utilizing kernel's vDSO feature. vDSO is a shared object file located in kernel's rodata section and linked to almost every userspace applications. This is achieved by mapping the vDSO image in user applications' page tables.

Our implemention will not protect the vDSO image as a workaround. If we protect these pages, VPW violations should be triggered.

To test this, please follow these steps.

1. Download [hlat-alias-mapping-test.patch](./tests/hlat-alias-mapping-test.patch)
2. Apply it to your kernel with `git apply hlat-alias-mapping-test.patch`.
3. Re-build and install the kernel in your guest.
4. If your guest fails to boot due to VPW violation, then it works.
