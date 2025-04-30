from pwn import *
elf = ELF('./vmlinux')
print(hex(next(elf.search(b'/sbin/modprobe\x00'))))