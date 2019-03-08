#!/bin/sh
#
# Initialize the VM

MODULE=/opt/slub_defrag.ko
DEBUGFS_DIR=/sys/kernel/debug

insmod $MODULE
mount -t debugfs none $DEBUGFS_DIR

# echo 'test' > /sys/kernel/debug/smo/callfn
