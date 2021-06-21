keywords
a

# イントロ/DISCLAIMER
間違いを沢山指摘できた人の勝ちです。
DISCLAIMER: 言葉の定義は基本的にここだけのもので、主に上辺で見える処理・カーネルの実装に主眼をおいてあり、詳解Linux日本語版と妄想に主に準拠しています。
厳密な定義にこだわる人は、Intelマニュアルに書いてあることだけを信じるか、CPU解剖してください。
(数学屋さんに言葉の定義はしっかりしろというもっともなお叱りを受けたので、以下に書いてあることは全部適当ということを宣言しときます。但し誤りの指摘やお叱りは大歓迎です。激しい場合には土下座しながら警察にLINEして通話繋ぎながら寝落ちするっていう女子高生ムーブかまします)

参照kernel: Linux 5.9.11

# 割り込みと例外
CPU内部由来のやつを**例外**、CPU外部由来のやつを**割り込み**という。前者は1命令の実行直後に発生し(すると、思ってる)、後者はクロックに対して任意のタイミングで発生する(と、思ってる)。
	割り込み: タイマとIOのみが発生させる(SWIを加えるならその限りでない、詳しくはDISCLAIMER)
		Maskable: CPUのINTRピンに送る。FLAGSレジスタによって禁止可能(IO)
		Non-Maskable: CPUのNMIピンに送る。マスク不可。致命的エラー等。
	例外: それ以外全部
		フォルト: IPはフォルトさせた命令を指す。復旧できた場合はそのアドレスから再開。
		トラップ: IPはフォルとさせたアドレスの次を指す。
		アボート: もうむりぽ。
DISCLAIMER: Intel定義ではIRQ割り込み・ソフトウェア割り込み・例外の3つ。IRQは外部信号由来、SWI・例外は内部由来。厳密な定義は知りません、Intelマニュアル読むかCPU分解してください。ここでいう「割り込み」はCPU制御でレジスタの退避及びハンドラへのIP移項をする処理のことを指します。厳密な区分に関しては、まじでどっちでもいいです。
割り込みは例外に割り込むこともあるが、例外ハンドラは割り込みハンドラを中断させることはない。例外は最大2つまでしか積まれない(2回フォルトで#DF、3回フォルトで死ぬ)

# ハンドラ
**IDT**にハンドラが登録される。ハンドラはプロセスではなく飽くまでもカーネルパス。基本のレジスタの退避はCPUが勝手にやってくれる。LinuxではIDTは2種類ある(割り込みゲートは使用されていない)
	システムゲート: Intelの言うトラップゲート(は？)。ベクタ3,4,5,0x80(int3, Overflow, Bounds, syscall)。
	トラップゲート: Intelの言うトラップゲート。それ以外の全ベクタ。
大事なことだから繰り返すが、割り込みも例外もCPUが発生させるもの。CPUは例外を発生させるとIPを退避させてIDTからハンドラを探し、それを呼び出す。(見つからない場合は泣きながら#GP。つまりハンドラが全然ない場合は一個目のハンドラがみつけられず#GPを出し、#GPのハンドラがみつけられずTFで泣きながら消えていく)

# コードベース
例として#PF(Page Fault)を見てみる。
`idt_setup_apic_and_irq_gates()@arch/x86/kernel/idt.c`において初期化される.
```idt.c
 	for_each_clear_bit_from(i, system_vectors, FIRST_SYSTEM_VECTOR) {
 		entry = irq_entries_start + 8 * (i - FIRST_EXTERNAL_VECTOR);
 		set_intr_gate(i, entry);
 	}
```
ここで`irq_entries_start`は`arch/x86/include/asm/idtentry.h`において定義されている。
```idtentry.h
 SYM_CODE_START(irq_entries_start)
 (snipped...)
 DECLARE_IDTENTRY_RAW_ERRORCODE(X86_TRAP_PF,	exc_page_fault);
```

ハンドラは`arch/x86/mm/fault.c`で定義される`exc_page_fault()`であることがわかる。
```fault.c
 DEFINE_IDTENTRY_RAW_ERRORCODE(exc_page_fault)
 {
 	unsigned long address = read_cr2();
 	irqentry_state_t state;
 (snipped...)
```
ここで`handle_page_fault()`が呼ばれ、処理は[* faultを起こした命令アドレスによって分岐]する。
```handle_page_fault.c
 	if (unlikely(fault_in_kernel_space(address))) {
 		do_kern_addr_fault(regs, error_code, address);
 	} else {
 		do_user_addr_fault(regs, error_code, address);
 		local_irq_disable();
 	}
```
ここで`fault_in_kernel_space()`は単純にIPがcanonical addrの上か下かだけで判断している.
```fault.c
 static int fault_in_kernel_space(unsigned long address)
 {
 	if (IS_ENABLED(CONFIG_X86_64) && is_vsyscall_vaddr(address))
 		return false;
 	return address >= TASK_SIZE_MAX;
 }
(`TASK_SIZE_MAX`はページディクトリの段数によって47か56関わるが、3-levelなら47。また、**カーネルランドの中でもユーザランドに直接マッピングされているvDSOについてはユーザランドにおけるフォルトと見做す**ため、ifで分岐している)
```

フォルトがユーザランドで起きた場合、`do_user_addr_fault()`においてこれがほんとに不正なのか、それともページの遅延ロード(`mmap`とかのアレ)で発生したものなのかを判断する。
```fault.c
 	vma = find_vma(mm, address);
 	if (unlikely(!vma)) {
 		bad_area(regs, hw_error_code, address);
 		return;
 	}
 	if (likely(vma->vm_start <= address))
 		goto good_area;
 	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
 		bad_area(regs, hw_error_code, address);
 		return;
 	}
 	if (unlikely(expand_stack(vma, address))) {
 		bad_area(regs, hw_error_code, address);
 		return;
 	}
```
不正かどうかは`find_vma()`においてPTEを確認するだけだけ。それ以外の場合は`bad_area()`から`__bad_area_nosemaphore()`に飛ぶ。この関数内では、ユーザモードならば即刻セグフォで殺されることになる(よく見るアレ)。ユーザモードかどうかはCR3を見れば分かる。
```fault.c
 	if (user_mode(regs) && (error_code & X86_PF_US
 		local_irq_enable();
 		(nispped...)
 		force_sig_fault(SIGSEGV, si_code, (void __user *)address);
 		local_irq_disable();
 		return;
 	}
```

フォルトがカーネルランドで起きた場合、処理は`do_kern_addr_fault()`に飛ぶ。これも基本的にはすぐ`bad_area_nosemaphore()`に飛ぶ。そしてユーザモードの場合と異なり`no_context()`を呼ぶ。ここでは、フォルトを扱うためのハンドラを`fixup_exception()`において探そうと試みて、無かった場合には流れに流れて`oops`ラベルにたどり着くことになる。このラベルは名前の通りでOopsメッセージを出した(`show_fault_oops()`)あとに`__die()`する。
```dumpstack.c
 int __die(const char *str, struct pt_regs *regs, long err)
 {
 	__die_header(str, regs, err);
 	return __die_body(str, regs, err);
 }
 NOKPROBE_SYMBOL(__die);
```
前半(header)はレジスタ情報の表示、後半はSIGSEGVとともに`notify_die()`する。結果、以下のようなメッセージが出力されて、実行中だったプロセスは殺される。
```oops_die.sh
 /home # ./test
 [    3.026215][   T74] hoge_open() is called
 [    3.026876][   T74] BUG: unable to handle page fault for address: ffffffffff0c4500
 [    3.027314][   T74] #PF: supervisor read access in kernel mode
 [    3.027488][   T74] #PF: error_code(0x0000) - not-present page
 [    3.027714][   T74] PGD 240d067 P4D 240d067 PUD 240f067 PMD 0
 [    3.028047][   T74] Oops: 0000 [#1] SMP NOPTI
 [    3.028373][   T74] CPU: 0 PID: 74 Comm: test Tainted: G           O      5.9.16 #1
 [    3.028599][   T74] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/04
 [    3.029154][   T74] RIP: 0010:hoge_ioctl.cold+0x0/0x19 [hoge]
 [    3.029499][   T74] Code: 26 00 00 00 48 c7 c0 e7 ff ff ff c3 48 c7 c7 3c 10 00 c0 e8 3f 00 b2 c1 31 c1
 [    3.030033][   T74] RSP: 0018:ffffc900001a7f10 EFLAGS: 00000246
 [    3.030217][   T74] RAX: ffffffffc0000000 RBX: ffff88800e0c4200 RCX: 0000000000000000
 [    3.030432][   T74] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff88800e0c4200
 [    3.030631][   T74] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
 [    3.030851][   T74] R10: ffffc900001a7ef0 R11: 0000000000000000 R12: 0000000000000003
 [    3.031061][   T74] R13: 0000000000000000 R14: ffff88800e0c4200 R15: 0000000000000000
 [    3.031314][   T74] FS:  00000000014d2880(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
 [    3.031521][   T74] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
 [    3.031674][   T74] CR2: ffffffffff0c4500 CR3: 000000000e102000 CR4: 00000000000006f0
 [    3.031922][   T74] Call Trace:
 [    3.032553][   T74]  __x64_sys_ioctl+0x7e/0xb0
```

# カーネル内でPFを起こしてみよう
特に意味はないけど、デバッグする時とか役に立つよ。あとkernelランドではページの遅延ロードは無いっていう認識で、あってんのかな？？？ 誰か教えてください。

まずは以下のようなLKMを作る。
```hoge.c
 #include<linux/errno.h>
 #include<linux/file.h>
 #include<linux/fs.h>
 #include<linux/miscdevice.h>
 #include<linux/module.h>


 static int hoge_open(struct inode *inode, struct file *filp)
 {
 	printk("hoge_open() is called");
 	return 0;
 }

 static int hoge_release(struct inode *inode, struct file *filp)
 {
 	printk("hoge_release is called");
 	return 0;
 }

 static long hoge_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
 {
 	unsigned long *mora = 0xffffffffff0c4500;
 	//unsigned long *mora = 0x32764531e1e217f8;
 	switch(cmd){
 		case 0:
 			printk("hoge_ioctl(): %lx", *mora);
 			break;
 		default:
 		return -ENOTTY;
 	};
 }

 static const struct file_operations hoge_fops = {
 	.owner = THIS_MODULE,
 	.open = hoge_open,
 	.release = hoge_release,
 	.unlocked_ioctl = hoge_ioctl,
 };

 static struct miscdevice hoge_device = {
 	.minor = MISC_DYNAMIC_MINOR,
 	.name = "hoge",
 	.fops = &hoge_fops,
 };

 static int __init hoge_init(void)
 {
 	printk("Module hoge is installed.");
 	return misc_register(&hoge_device);
 }

 static void __exit hoge_exit(void)
 {
 	misc_deregister(&hoge_device);
 }

 module_init(hoge_init);
 module_exit(hoge_exit);
 MODULE_AUTHOR("NIRUGIRI");
 MODULE_LICENSE("GPL");
```

そしたらこのMakefileでmakeする。
```Makefile.txt
 obj-m += hoge.o
 all:
 	make -C /home/wataru/buildroot-2020.11.2/output/build/linux-5.9.16/ M=$(PWD) modules
 	EXTRA_CFLAGS="-g DDEBUG"
 clean:
 	make -C /home/wataru/buildroot-2020.11.2/output/build/linux-5.9.16/ M=$(PWD) clean
```

あとはサンプルプログラムを作る。
```test.c
 #include <assert.h>
 #include <fcntl.h>
 #include <stdio.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
 #include <unistd.h>

 #define DEV_PATH "/dev/hoge"

 int main(int argc, char *argv[]) {
 	int fd = open(DEV_PATH, O_RDONLY);
 	assert(fd>0);
 	assert(ioctl(fd, 0, 0) == 0);
     close(fd);
 	return 0;
 }
```

これを実行させると、カーネルランドで#PFが起きてOopsされる。


# え、PFじゃなくてGPF出るんだけど
上の`hoge.c`内の`hoge_ioctl()`においてアドレスを`0xffffffffff0c4500`じゃなくて`0x32764531e1e217f8`とかにすると、以下のようなメッセージが出る。
```gpf_error.sh
 [   24.559795][   T75] hoge_open() is called
 [   24.559896][   T75] general protection fault, probably for non-canonical address 0x32764531e1e217f8: 0I
 [   24.560202][   T75] CPU: 0 PID: 75 Comm: test Tainted: G      D    O      5.9.16 #1
 [   24.560388][   T75] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/04
 [   24.560711][   T75] RIP: 0010:hoge_ioctl.cold+0xa/0x1e [hoge]
 [   24.560858][   T75] Code: ff c3 48 c7 c7 3c 10 00 c0 e8 3f 00 b2 c1 31 c0 c3 48 c7 c7 53 10 00 c0 e8 37
 [   24.561297][   T75] RSP: 0018:ffffc900001a7f10 EFLAGS: 00000246
 [   24.561439][   T75] RAX: 32764531e1e217f8 RBX: ffff88800e0c4400 RCX: 0000000000000000
 [   24.561616][   T75] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff88800e0c4400
 [   24.561799][   T75] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
 [   24.561983][   T75] R10: ffffc900001a7ef0 R11: 0000000000000000 R12: 0000000000000003
 [   24.562166][   T75] R13: 0000000000000000 R14: ffff88800e0c4400 R15: 0000000000000000
 [   24.562351][   T75] FS:  0000000000743880(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
 [   24.562557][   T75] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
 [   24.562713][   T75] CR2: 00000000004b1050 CR3: 000000000e0d8000 CR4: 00000000000006f0
 [   24.562892][   T75] Call Trace:
 [   24.562993][   T75]  __x64_sys_ioctl+0x7e/0xb0
```

これは、#PFではなく#GPFである。
理由は簡単で、アドレス`0x32764531e1e217f8`はx64の定めるアドレスの規約に反したアドレス(non-canonical addr)だから、MMUがページテーブルを見る前に#GPFを出す。よってそもそもに呼ばれるハンドラが違う。
(僕は錯乱して、#PFのハンドラから#GPFが発行されてこうなったんじゃないかと勘違いして時間を無駄にしたけど、そもそも#PFハンドラで#GPFが出たら#DFになって、そこから#GPFが出たりしたらTFで死ぬので、そんなことは絶対に無い。皆は時間を無駄にしないようにね!)

# CTF的には
単純なUAFがある場合、特にdungling-pointerが生成される場合を考えると、嘗てポインタを保持していた構造体がフリーされて別のデータが書き込まれたあと、UAFでそのポインタがde-referenceされたりすると、大体non-canonical addrになっているから、上に述べたように#GPFが出る。すると、`exc_general_protection()`の中で直接エラーメッセージが生成されて出力される。これによってKASLRリークができる。

なんかkernel landでページフォルト起きると直ぐ死ぬみたいな勝手なイメージが脳内にあったけど、ただの勘違いだから#GPF起こしてdmesgでKASLR leakっていう手法は、ちゃんと覚えておこうと思いました。まる。
はい、それだけです。これをメモしておきたかっただけです、すいませんでした。

