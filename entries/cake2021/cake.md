# CakeCTF 2021

いつぞや開催された**CakeCTF 2021**。始まってから初めてzer0pts主催だということを知りました。InterKosenもzer0ptsもCakeもやって、やばいですね。ところで、ここ2ヶ月ぱそこんを触っていなかったため、ぱそこんの立ち上げ方もブログの書き方も忘れてしまいました。もちろんpwnもすべて忘れました。よって、このエントリはwriteupではなく、チームの人(主に[moraさん](https://www.youtube.com/watch?v=oitn3AiP6bM&t=14898s)が)が解いているのをBIGカツを食べながら見ていた感想になります。


# hwdbg
`/dev/mem`への任意のwriteができるため、物理アドレスに対して直で書き込みができるよという問題。2ヶ月ぶりのkernel問(実際は、semi-kernel問)だったため、色々と思い出しながら問題を見ました。いくつかの実験の後に、シンボルの物理アドレスは(少なくともkernellandのシンボルに関しては)実行毎に不変であるという確証が持てたため、下のどれかの作戦で行こうと思いました。

- kernellandのデータ領域(`modprobe_path`)を書き換え、rootで任意スクリプトを動かす。
- kernellandのstackを書き換え、制御を奪う。
- kernellandのUIDの変更を行う関数のcodeを書き換え、任意プロセスがrootになれるようにする。
- kernellandのcodeを書き換えshellcodeを入れる。
- hwdbgのコードを書き換え、shellcodeを入れる。

AAWのため色々と候補はありますが、`/dev/mem`への書き込みが任意に出来るだけならこのデバイスファイルの権限を変えるだけの問題でも良いはずで、おそらくsuidがhwdbgバイナリについてることが本質で、hwdbg自体のコードを書き換えるのが想定解なのかなぁと思いました。但し、ユーザランドのプロセスは実行された順番によって物理アドレスが多少変わると思うので、多少のbruteforceが必要な気がしたので、ぼくはkernellandの方で解きたいと思っていました。が、その間に[moraさん](https://twitter.com/moratorium08/status/992973579108081666?s=20)がhwdbgの書き換えによって解いたので無職になりました。

しかし、時間がかかったのにはいくつか理由があって:

- `modprobe_path`が見つからなかった。`kallsyms`で見えなくて、`nm`でも見えなかったため見つからなかった。多分存在はしていたと思うけど、`CONFIG_KALLSYMS_ALL`が無効になっていたのか、textシンボルしか見れなかった。あれ、こういう場合ってシンボルのオフセット探す方法どうやるんでしたっけ、教えてください。いい感じの関数でbreakして頑張って探すしかない?
- `modprobe_path`はconstにすることができるため、今回はその設定だと思った。こういう時に、どのシンボルを書き換えると楽にLPEできるか知らなかった。
- ktext領域への書き込みでフォルトが起きる。

とりわけ、ktextへの書き込みでフォルトが起こるのがよく分からずに時間を溶かしてしまいました。ぼくの認識では物理アドレスへのアクセスはページテーブルとかを介さないため、よってアクセス権限もフォルトも無縁の世界と思っていました。

```fault.txt
/ # cat /proc/iomem
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
0009fc00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c99ff : Video ROM
000ca000-000cadff : Adapter ROM
000cb000-000cb5ff : Adapter ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-03fdffff : System RAM
  02600000-03000c36 : Kernel code
  03200000-033b3fff : Kernel rodata
  03400000-034e137f : Kernel data
  035de000-037fffff : Kernel bss
03fe0000-03ffffff : Reserved
04000000-febfffff : PCI Bus 0000:00
  fd000000-fdffffff : 0000:00:02.0
    fd000000-fdffffff : bochs-drm
  fe000000-fe003fff : 0000:00:03.0
    fe000000-fe003fff : virtio-pci-modern
  feb00000-feb7ffff : 0000:00:03.0
  feb90000-feb90fff : 0000:00:02.0
    feb90000-feb90fff : bochs-drm
  feb91000-feb91fff : 0000:00:03.0
fec00000-fec003ff : IOAPIC 0
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fee00000-fee00fff : Local APIC
fffc0000-ffffffff : Reserved
100000000-17fffffff : PCI Bus 0000:00
/ # hwdbg mw 8 2600000
AAAAAAAA
BUG: unable to handle page fault for address: ffff938c42600000
#PF: supervisor write access in kernel mode
#PF: error_code(0x0003) - permissions violation
PGD 3801067 P4D 3801067 PUD 3802067 PMD 80000000026000e1
Oops: 0003 [#1] SMP PTI
CPU: 0 PID: 144 Comm: hwdbg Not tainted 5.10.7 #2
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
RIP: 0010:memset_orig+0x72/0xb0
Code: 47 28 48 89 47 30 48 89 47 38 48 8d 7f 40 75 d8 0f 1f 84 00 00 00 00 00 89 d1 83 e1 38 74 14 c1 e91
RSP: 0018:ffffa33780453e30 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
RDX: 0000000000000008 RSI: 0000000000000000 RDI: ffff938c42600000
RBP: ffffa33780453e50 R08: 4141414141414141 R09: 0000000000000000
R10: ffff938c42600000 R11: 0000000000000000 R12: ffff938c42600000
R13: 0000000000000008 R14: ffff938c41e92100 R15: 0000000000000008
FS:  00000000004076d8(0000) GS:ffff938c42400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffff938c42600000 CR3: 0000000001e7a000 CR4: 00000000003006f0
Call Trace:
 ? _copy_from_user+0x70/0x80
 write_mem+0x96/0x140
 vfs_write+0xc2/0x250
 ksys_write+0x53/0xd0
 __x64_sys_write+0x15/0x20
 do_syscall_64+0x38/0x50
 entry_SYSCALL_64_after_hwframe+0x44/0xa9
RIP: 0033:0x403744
Code: 07 48 89 47 08 48 29 d1 48 01 d7 eb df f3 0f 1e fa 48 89 f8 4d 89 c2 48 89 f7 4d 89 c8 48 89 d6 4c0
RSP: 002b:00007ffec3e615a8 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
RAX: ffffffffffffffda RBX: 000000000040136a RCX: 0000000000403744
RDX: 0000000000000008 RSI: 00007ffec3e61600 RDI: 0000000000000003
RBP: 00007ffec3e62610 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffec3e62688
R13: 00007ffec3e626b0 R14: 0000000000000000 R15: 0000000000000000
Modules linked in:
CR2: ffff938c42600000
---[ end trace afbab88ef6185423 ]---
RIP: 0010:memset_orig+0x72/0xb0
Code: 47 28 48 89 47 30 48 89 47 38 48 8d 7f 40 75 d8 0f 1f 84 00 00 00 00 00 89 d1 83 e1 38 74 14 c1 e91
RSP: 0018:ffffa33780453e30 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
RDX: 0000000000000008 RSI: 0000000000000000 RDI: ffff938c42600000
RBP: ffffa33780453e50 R08: 4141414141414141 R09: 0000000000000000
R10: ffff938c42600000 R11: 0000000000000000 R12: ffff938c42600000
R13: 0000000000000008 R14: ffff938c41e92100 R15: 0000000000000008
FS:  00000000004076d8(0000) GS:ffff938c42400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffff938c42600000 CR3: 0000000001e7a000 CR4: 00000000003006f0
Kernel panic - not syncing: Fatal exception
Kernel Offset: 0xa800000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbffffff)
```

これを見ると、そもそもに書き込みたいところ以外でフォルトが起きていて、意図しないマッピングになっている感じがします(というか、物理に直接書いてるのにマッピングって何よ)。

自前kernelでデバッグしてみようとしたところ、以下の感じになりました。

```not-write.txt
/ # cat /proc/iomem
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
0009fc00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c99ff : Video ROM
000ca000-000cadff : Adapter ROM
000cb000-000cb5ff : Adapter ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-03fdffff : System RAM
  01000000-01e037d6 : Kernel code
  02000000-02378fff : Kernel rodata
  02400000-026b807f : Kernel data
  02c67000-02dfffff : Kernel bss
03fe0000-03ffffff : Reserved
04000000-febfffff : PCI Bus 0000:00
  fd000000-fdffffff : 0000:00:02.0
  fe000000-fe003fff : 0000:00:03.0
  feb00000-feb7ffff : 0000:00:03.0
  feb90000-feb90fff : 0000:00:02.0
  feb91000-feb91fff : 0000:00:03.0
fec00000-fec003ff : IOAPIC 0
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fee00000-fee00fff : Local APIC
fffc0000-ffffffff : Reserved
100000000-17fffffff : PCI Bus 0000:00
/ # hwdbg mw 8 1000000
AAAAAAAA
/ # QEMU 4.2.1 monitor - type 'help' for more information
(qemu) xp/gx 0x1000000
0000000001000000: 0x4801403f51258d48
```

自前kernelだとフォルトこそ置きていませんが、最後のQEMU monitorの結果からもわかるように、書き込みがおきていません。kernelを読んでみます。`/dev/mem`へのwriteは、`write_mem()@/drivers/char/mem.c`が呼ばれ、書き込みのチェックが行われます。いくら`/dev/mem`への書き込みとはいえ、本当にどこにでも書き込めるわけではなく、ある程度のチェックは行われるようです。この中で`page_is_allowed()`から`devmem_is_allowed()@/arch/x86/mm/init.c`が呼ばれるのですが、なんかこいつがcodeセクションへのwriteを拒否してきます。因みにdataセクションの場合でも同じでした。
理由は今のところ分かっていませんが、あとでもうちょっと深堀してなんか書きます。

というわけで、配布kernelだとフォルトが起きて、かつ自前だとハンドラ内でアクセスが拒否されるため、kernelコードの書き換えができませんでした。理由が分かってないのでちゃんと調べたいですね。多分すごく初歩的な勘違いをしているような気がするんですが。
まぁ何はともあれmoraさんが解いてくれたのでOKです。

author's writeupによると、`core_pattern`を書き換えてcrashさせることで`modprob_path`と同様にいけるらしいです。知らなかったので勉強になりました。ところでこいつのオフセットを楽に知るにはどうしたら良いんでしたっけ。


# JIT4B
ある関数において変数の値が追跡されるため、ごまかしてOOBアクセスさせたら勝ちの問題です。ebpfのverifierみたいなだなぁと思いました。ebpfだとシフトやand/xor等にこれまでバグが見つかっていましたが、今回は四則演算とmin/maxのみの演算になっているので関係なさそうです。1個ずつ`abstract.hpp`のrange処理を見ていき、おおよそバグがないように見えましたが、除算のところだけ気になりました。

```abstract.hpp
  /* Abstract divition */
  Range& operator/=(const int& rhs) {
    if (rhs < 0)
      *this *= -1; // This swaps min and max properly
    // There's no function named "__builtin_sdiv_overflow"
    // (Integer overflow never happens by integer division!)
    min /= abs(rhs);
    max /= abs(rhs);
    return *this;
  }
```

ぼくはrangeの下限が負に最大だとrangeを入れ替えた時に上限でoverflowするんじゃないかと疑ってしまいましたが、除算内で呼ばれる掛け算ではちゃんとoverflowの処理がされており、ちゃんと追跡不能でマークされていました。ここらへんでmoraさんが問題を見始めたんですが、一瞬でabs内では同様のoverflowが実現できると気づいたため、瞬殺されました。range内にだけ(つまり被除数にだけ)気を取られていて、除数の方でoverflowが起きることに気づかなかったのが反省点です。因みに、コメントを大量に入れているところはCTFの文脈において本当にバグがないからココはあんまり見ても意味ないことを伝えている場合と、ただのフリでコメントがあるところにバグがある場合があるのですが、今回は後者寄りでした(厳密には同じところではないけど同じ関数内)。


それにしても、2ヶ月ぶりのCTFで、moraさんが問題を解くのも久々に見たんですが、異常に早いですね。まじで無職で、あまりにもお腹が減ったので皆が取っておいたwarmupを貰ってしまいました。


# アウトロ
ぼくは何もしていませんが、他の人が強かったためTSGは3位だったみたいです。ところでチーム登録をする時に間違えてぼく個人のG-mailで登録してしまったため、swag関係のメールが個人宛のメールに来てしまいます。ptrさんからメールが来るなんてきゅんきゅんしちゃいますよね。頑張って好きな犬種は何か聞き出そうと思います。因みにぼくは柴とスピッツとハスキーです。猫よりも犬派です。


# 参考
パン人間
https://twitter.com/moratorium08/status/992973579108081666?s=20

