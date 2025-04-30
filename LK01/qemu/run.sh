#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 kpti=1 kaslr" \
    -no-reboot \
    -cpu kvm64,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd initramfs.cpio.gz \
    -net nic,model=virtio \
    -net user \
    -s \
    # -initrd rootfs.cpio \
    #-append "console=ttyS0 loglevel=3 oops=panic panic=-1 nopti nokaslr" \
    #-cpu qemu64 \