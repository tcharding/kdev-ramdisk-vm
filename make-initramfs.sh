#!/bin/bash
#
# Make the initramfs file from everything in initramfs/

cd initramfs
find . | cpio -oHnewc | gzip > ../initramfs.gz
