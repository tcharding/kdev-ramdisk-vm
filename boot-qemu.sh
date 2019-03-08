#!/bin/bash
#
# Boot kernel with QEMU

numa=0

if [[ $# == 1 ]]; then
    if [ $1 == "-n" ] || [ $1 == "--numa" ]; then
	numa=1
    fi
fi

options="--enable-kvm -kernel bzImage -initrd initramfs.gz -nographic -m 4G"

if [ $numa -eq 1 ]; then
    qemu-system-x86_64 $options -append 'root=/dev/sda console=ttyS0 slub_debug numa=fake=4' -smp 4
else
    qemu-system-x86_64 $options -append 'root=/dev/sda console=ttyS0 slub_debug'
fi

    

