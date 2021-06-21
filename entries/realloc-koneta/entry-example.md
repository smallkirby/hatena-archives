keywords
heap, tcache, realloc, double free, size confusion, 小ネタ

# イントロ
最近、CTFを完全に辞めて、競プロをやることにしました。前から競プロできるひとかっこいいなぁと思っていたのですが、直接の動機はこの前のHITCONの問題でした。ここでダイクストラを使ったカーネルモジュールが出題されたのですが、アルゴリズム全然知らんマンなのでやる気がなくなってコードが読めませんでした。もともと数学は誇張抜きに小学3年生くらいしかできない(小学校は大部分行ってなかったので実質幼稚園並にしかできない)ので、それを克服するためにも頑張りたいです。
さてさて、ということで、今回は**realloc**を使った **tcache** double-freeに関する小さいお話を少し。**かなり古いネタ**ですが備忘録的に書き残しておきます。
また、最近 **glibc** にちょっとしたパッチを送ったのを契機にglibcのメーリスを読むようになったので、そこで議論になっていたtcacheの小ネタを書きます。
(今までブログは丹精込めてHTMLをベタ書きしていたのですが、流石にめんどくさくなったので今回からブログのCSS似合うようなMD->HTMLコンバータを作ってMDで書いています。)


# 概要
小学校で既に教わっていると思いますが、**glibc 2.29** 以降では **tcaceh** に **key** というメンバが加わっています。
*malloc()* する際にはここに *tcache*(*tcache_per_thread*構造体の方) の値が書き込まれ、*free()* 時にこのアドレスに *tcache* のアドレスが入っていればmemory corruptionとしてエラーにするというやつですね。というわけで最近のglibcにおいては単純に二回続けて *free()* することでdouble-freeを起こすということはできなくなっています。

但し、*realloc()* の場合には条件が揃うと簡単にtcacheを用いてmemory corruptionを引き起こすことができます。具体的には、以下の2つのことができます。
1. 複数のchunkを異なるサイズのtcacheに繋ぐことができる。(**size-confusion**)
2. 1を用いて隣接するchunkをoverwriteできる。 (**memory corruption**)

# realloc復習
そもそもに**realloc**がどういう挙動をするのか少し復習してみましょう。reallocの処理は、*__libc_realloc()* と *_int_realloc()* に大別されます。malloc/freeと異なり、*__libc_realloc()* の方でも割とガッツリ処理が行われます。
*__libc_realloc()* においては、まず *__realloc_hook* を確認します。最初の段階ではここには *realloc_hook_ini()* のアドレスが入っており、内部でtcacheの初期化及びフックの初期化を行います。(因みに、ここでは *__realloc_hook* だけでなく *__malloc_hook* もクリアされます)。
そのあとで、要求された*size*が0である場合には *__libc_free()* を呼びます。普通にfree()を呼んだ時と挙動の違いは全くありません。また、渡されたポインタがNULLであった場合には *__libc_malloc()* を呼びます。これも、通常通りmallocを呼ぶのとdiffは全くありません。マルチスレッドである場合には、このあと同一関数内で全ての処理を行ってしまいます。シングルスレッドの場合には *_int_realloc()* に進みます。
*_int_realloc()* では要求されたサイズと現在のchunkのサイズに応じて処理が分岐します。
現在のサイズよりも要求サイズが大きい場合には、まず *top* から不足分を切り出そうと試みます。*top* に隣接している場合には *top* を下げるだけで終わりです。また、隣接chunkと合併できるなら合併します。それもできない場合には、新たに *_int_malloc()* を読んで内容を *memcpy()* した後古い方のchunkを *_int_free()* します。合併を行った場合に要求サイズよりも大きくなってしまった場合は、残りのchunkにヘッダをつけて *_int_free()* を呼び出します。尚、残りのchunkのサイズが *MINSIZE* を下回る場合には新たなchunkにできないため諦めてヘッダだけつけて終わります。(つまり、どのbinにも繋がれず、topにも含まれていない完全に浮いたchunkができあがります、合ってるよね??)。
要求サイズが以前のchunkよりも小さい(若しくは等しい)場合には、単純にヘッダを書き換えた後、残りのchunkを上と同様にして再利用を試みます。
細かい分岐はありますが、概ねreallocの処理はこんな感じです。

# どうやるか
本題(といっても小さい話だけど)。
ここでは、任意サイズのchunkを *realloc()* できるような状況を考えてみましょう。加えて *free()* もできるがフリーの後は保持しているポインタがクリアされて参照できなくなってしまうとします。(edit機能はなくてもいいです。あったら楽になります。というか、この方法をわざわざ使うまでもなくtcache-poisoningして終わりです。)
このような状況のときには、*realloc(ptr, 0)* とすることでポインタをクリアすることなく *free()* ができるというのはすぐに思いつくと思います。UAFができあがるため、double-freeもできますが、した瞬間に最初に述べた *key* による検知で死んでしまいます。
さて、最初に「*free()* 時に *key* にtcacheのアドレスが入っていると死ぬ」と言いましたがあれは嘘です。実際には *key* にtcacheのアドレスが入っていることを検知するとtcacheのlinked-listの全探索が始まります。この中に現在freeしようとしているchunkが既に入っていた場合に限ってabortされることになります。重要なこととして、この *key* による**double-free検知の全探索は同一サイズのchunkにしか行われません**。そのため、**一度freeしたchunkを別のサイズとしてfreeした場合には全探索の結果として正常と判断されエラーが発生しません**。
実際の操作の例としては、最初に0x80のchunkを *realloc()* した後 *realloc(0)* をすることでポインタを保持したまま *free* をします(UAF)。これによってchunkは0x90のtcacheに繋がれます。このあと、同一chunkに対して *realloc(0x20)* をします。すると、上述した処理によってchunkは0x30サイズのものと0x60サイズのものに分割されます。この際、保持しているポインタが指すchunkの方のヘッダは0x90から0x30に書き換えられます。この後で *realloc(0)* 若しくは *free()* を行うと、保持していたchunkが0x30のtcacheに繋がれます。このときには *key* の値に0x90としてfreeした時に書き込まれた値が残っているためtcacheの全探索が始まりますが、このchunkは0x90のtcacheには繋がれているものの0x30には繋がれていないためエラーは発生しません。これで、同一のchunkが0x90と0x30の両方のtcacheに繋がれたことになります。
しかも、実際のメモリのレイアウト的にはこのchunkは0x30のchunkです。このあとで0x90サイズのchunkをとると、**0x30サイズのchunkを0x90として取ったことになり**、alloc時の書き込み機能が有るならばコレによって隣接するchunkに対して0x60分だけoverwriteすることができるようになります。

以上!!!


# tcacheのfree時のinfinite-loop
小話。せっかくtcacheのfreeにおける全探索の話が出たので。
もともとtcacheはユーザランドにおける小さなメモリ領域の利用を高速化するためにglibc2.27で実装されたもので、速さのためにセキュリティチェックを甘くしてあります。これによって一昔前のCTFではtcacheにUAFさえあればもう終わりみたいな強力なものになっていました。最近では、上述したdouble-freeチェックや、glibc2.32から実装されるlinked-list encryption(**safe unlinking**)によりちょっとずつexploitの難易度が増してきています。
上の全探索はその経緯で実装されたものであり、一見すると同一サイズのリストだけでなく全サイズを探索してしまえば良いように思えますが、tcacheが実装された目的である速度のオーバーヘッドのために同一サイズだけをチェックしているという経緯があります。
さて、この全探索ですが、**探索の終わりの基準が「次のchunkへのポインタ(fd)がNULLである」ということしかありません**。これが何を意味するかと言うと、仮に**tcacheのlinked-list内にcircular linked-listが出来上がっていた場合、探索が終わることがなくinfinite-loopに陥ってしまいます**。
このようなendless-loopを引き起こすようなPoCは以下のとおりです。(ver 2.32用にポインタをencryptしています.)
```infinite-loop.c
#include<stdio.h>
#include<stdlib.h>

unsigned long protect_ptr(unsigned long pos, unsigned long ptr){
  return (pos>>12) ^ (ptr);
}

int main(void)
{
  char *a,*b,*c;
  a = malloc(0x50);
  b = malloc(0x50);
  c = malloc(0x50);
  free(a);
  free(b);

  *(unsigned long*)(b) = (unsigned long*)protect_ptr(b, b);
  ((unsigned long*)c)[1] = ((unsigned long*)a)[1];
  free(c);

  return 0;
}
```
これを実行すると最後のfreeにおいてtcacheの全探索が走り、永遠に同じchunkを回り続けるためプログラムがハングします。
tcacheは管理構造体(*tcache_per_thread*)において現在保持しているtcacheの個数をカウントしていますが、**これはtcacheからchunkを取れるかどうかと、tcacheにchunkをputできるかどうかという判定にしか使われていない**ため、chunkの最大保持数(7)を超えてもループは回り続けます。

考えてみれば当たり前のことではあります。しかし、僕がある日競プロの問題を解いていて後少しでシェルが取れるという時にこのハングが起こりました。すぐにはこのループが原因であることが思いつかずに、他の原因を探して30分ほど無駄にしてしまいました。これはあってはならないことです。
というわけで、全探索のループに上限を定めるようにglibcにパッチを送りました。そもそもにこのようなことが起きるのは既にmemory corruptionが発生した後であり、影響としてもプログラムが止まるだけなので大した影響はありません。しかし、30分を浪費したことが許せなかったため、DoS attackに繋がり得るという理由をでっちあげてBugzillaにファイリングし、MLという面倒くさい手続きを踏んで修正しました。(たかだか数行のパッチになんでこんなにめんどいねん)

というわけで、修正後の現在のmasterにおいては上のプログラムを実行すると以下のようになります。
[image]
なんと分かりやすいエラーメッセージ!!!
これで次から競プロ中に思わぬmemory corruptionでループが発生して時間を費やす時間がなくなったね！



# tcacheの更なる強化
そんなこんなでglibcのMLに目を通すことが日課になったのですが、そのなかで以下のようなtcacheの強化がリクエストされていました。
https://sourceware.org/pipermail/libc-alpha/2020-December/120653.html
以下引用です。
[引用にする]
Hmm... OK, I think I get it.  It's not the 'e' we know, its the 'e' from
the previous call to tcache_get().

So basically, when we remove a chunk from the tcache, we want to
validate the pointer we're leaving behind?
```patch.patch
 static __always_inline void *
 tcache_get (size_t tc_idx)
 {
   tcache_entry *e = tcache->entries[tc_idx];
   if (__glibc_unlikely (!aligned_OK (e)))
     malloc_printerr ("malloc(): unaligned tcache chunk detected");
   tcache->entries[tc_idx] = REVEAL_PTR (e->next);
+  /* Validate the pointer we're leaving behind, while we still know
+     where it came from, in case a use-after-free corrupted it.  */
+  if (tcache->entries[tc_idx])
+    * (volatile char **) tcache->entries[tc_idx];
   --(tcache->counts[tc_idx]);
   e->key = NULL;
   return (void *) e;
 }
```

代入するわけでもなく、変更するわけでもなく、ただtcacheにアクセスするだけの行が *tcache_get()* に追加されています。端的に言うと、このパッチが当てられると **tcacheからchunkを取る時に、取る対象のtcacheだけでなく、その次のtcacheのアドレスも関なものでなくてはならない**ようになります。
これが迷惑になる例としては、例えば**leak-less**な状況で**tcache-poisoning**によって *stdout* を書き換えたいというようなときに、*stdout* 直上にchunkを取った後のlinked-listには *stodut.flag* の値が入ります。この時使ったchunkと同じサイズのchunkをどうしても使いたいという場合には同一サイズのchunkをfreeして繋いだ後もう一回allocすることに鳴ると思いますが、このとき取得するchunkの次のchunk(つまり取得するchunkのfd)は *stdout->flag* の値(*0xFBAD2084*とか)であり大抵のプロセスの場合不正なアドレスであるため、死ぬことになってしまいます。


まぁ、これ自体は大した変更ではないし害になるようなものではないですね。けど、tcacheが速さ目的で実装されたもののはずなのに、どんどんセキュリティ機構をもりもりにしていっています。だったらtcache辞めちゃえばいいのにね。嘘です。ごめんね。


# アウトロ
というわけで、realloc-baseのsize-confusionの話と、tcache周りの小話でした。
tcacheに限らず、どんどんheap周りのexploitは難しくなっています。
**だから僕は、pwnを、辞めた。** (ヨルシカ風)

# 参考
ニルギリ
https://www.youtube.com/watch?v=yvUvamhYPHw
勘ぐれい
https://www.youtube.com/watch?v=ugpywe34_30
ほのぼの
https://blog.hideo54.com/archives/1020
