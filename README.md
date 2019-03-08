Tiny Linux
==========

Tiny Linux bootable with QEMU.

Instructions
------------

- Create a symlink to bzImage for kernel to boot.

		ln -s /path/to/kernel/output/arch/x86/boot/bzImage .

- Copy any files you want to initramfs/opt/  <--! Remember to statically link binaries -->

- Run `make-initramfs.sh`

- Boot with `boot-qemu.sh` (see `boot-qemu --help` for boot options).

- For bonus points boot in a new terminal then you can just kill the whole thing
  on oops.

		terminator -f -t './boot-qemu.sh'

References
----------

Thanks goes to:

- https://unix.stackexchange.com/questions/67462/linux-kernel-is-not-finding-the-initrd-correctly
- http://lockett.altervista.org/linuxboot/linuxboot.html