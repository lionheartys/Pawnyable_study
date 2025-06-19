#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

int main() {
  fd = open("/dev/angus", O_RDWR);

  if (mmap(0, 0x1000, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1,
           0) != NULL) // 在地址0处映射一块内存
  {
    perror("mmap failed");
  }

  char buf[0x10];
  AAR(buf, "hello, world!", 13);
  printf("AAR try to read buf: %s\n", buf);
  AAW(buf, "this is a test", 14);
  printf("AAW try to write buf:%s\n", buf);

  close(fd);

  return 0;
}