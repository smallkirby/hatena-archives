

**注意: 本記事に書いてあることを実際に試して環境がぶっ壊れてもなんの責任も負いません。**



大学院の募集が始まり研究計画書が書けないということでイライラすることはよくあると思います。

イライラしたときに、aptのデバッグをするためにソースからビルドして、それを間違えて環境にインストールしてしまうこともよくあると思います。
そうすると、おそらく以下のように`/etc/apt`ではなく`/usr/local/etc/apt`を見に行くようになってしまい、余計イライラが蓄積していきます。
```.sh
W: Unable to read /usr/local/etc/apt/apt.conf.d/ - DirectoryExists (2: No such file or directory)
W: Unable to read /usr/local/etc/apt/sources.list.d/ - DirectoryExists (2: No such file or directory)
W: Unable to read /usr/local/etc/apt/sources.list - RealFileExists (2: No such file or directory)
W: Unable to read /usr/local/etc/apt/preferences.d/ - DirectoryExists (2: No such file or directory)
```

apt自体は異常な量のconfig名前空間を持っており、それを指定することで一時的にetcディレクトリを指定することはできます。例えば`sudo apt -oDir::Etc=/etc/apt install hoge`とすることでetcを指定することができます。それにしたってinstall時に以下のようなエラーが出ます。
```.sh
After this operation, 120 MB of additional disk space will be used.
Do you want to continue? [Y/n] Y
E: Cannot get debconf version. Is debconf installed?
debconf: apt-extracttemplates failed: No such file or directory
Extracting templates from packages: 30%E: Cannot get debconf version. Is debconf installed?
debconf: apt-extracttemplates failed: No such file or directory
Extracting templates from packages: 61%E: Cannot get debconf version. Is debconf installed?
debconf: apt-extracttemplates failed: No such file or directory
Extracting templates from packages: 91%E: Cannot get debconf version. Is debconf installed?
debconf: apt-extracttemplates failed: No such file or directory
Extracting templates from packages: 100%
Could not exec dpkg!
E: Sub-process /usr/local/bin/dpkg returned an error code (100)
```

ここまで来ると、およそ大抵の人はイライラが蓄積し、aptをリインストールすることになると思います。しかし、aptだけリインストールしても上の症状は全く変わりません。
そうするとほとんどの人はそのイライラから以下のようなコマンドを打つことになると思います。
```.sh
wataru@skbpc:~: 20:43:34 Thu Jun 03
$ sudo rm /usr/bin/dpkg
wataru@skbpc:~: 20:43:50 Thu Jun 03
$ sudo rm /usr/bin/apt
```

ここで、1分くらい絶望に暮れましょう。


## dpkgのリインストール
多分、UbuntuのISOイメージに入ってるaptとdpkgを使ってやるのが最もクリーンだと思いますが、以下ではちょっとdirtyかもしれない方法を使います。ISO入ったCD-ROMって、なくしがちだもんね。
やることは、aptがやってくれることを手動でやるだけです。
まずはIndexファイルを取ってきます。
```.sh
$ wget http://security.ubuntu.com/ubuntu/dists/focal/main/binary-adm64/Packages.gz
--2021-06-03 21:39:20--  http://security.ubuntu.com/ubuntu/dists/focal/main/binary-adm64/Packages.gz
Resolving security.ubuntu.com (security.ubuntu.com)... 2001:67c:1562::15, 2001:67c:1562::18, 91.189.91.39, ...
Connecting to security.ubuntu.com (security.ubuntu.com)|2001:67c:1562::15|:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2021-06-03 21:39:21 ERROR 404: Not Found.

$ wget http://security.ubuntu.com/ubuntu/dists/focal/main/binary-amd64/Packages.gz
--2021-06-03 21:39:34--  http://security.ubuntu.com/ubuntu/dists/focal/main/binary-amd64/Packages.gz
Resolving security.ubuntu.com (security.ubuntu.com)... 2001:67c:1562::15, 2001:67c:1562::18, 91.189.91.39, ...
Connecting to security.ubuntu.com (security.ubuntu.com)|2001:67c:1562::15|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1274738 (1.2M) [application/x-gzip]
Saving to: ‘Packages.gz’

Packages.gz            100%[==========================>]   1.21M   916KB/s    in 1.4s

2021-06-03 21:39:36 (916 KB/s) - ‘Packages.gz’ saved [1274738/1274738]

$ gunzip ./Packages.gz
```
ここで一回`binary-amd64`を`binary-adm64`とtypoすることが重要です。distroとarchとcomponentは自分が使っているものに合わせてください。そしたら、そのIndexファイルを見てdpkgを探します。
```.sh
Package: dpkg
Architecture: amd64
Version: 1.19.7ubuntu3
Multi-Arch: foreign
Priority: required
Essential: yes
Section: admin
Origin: Ubuntu
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Original-Maintainer: Dpkg Developers <debian-dpkg@lists.debian.org>
Bugs: https://bugs.launchpad.net/ubuntu/+filebug
Installed-Size: 6740
Pre-Depends: libbz2-1.0, libc6 (>= 2.15), liblzma5 (>= 5.2.2), libselinux1 (>= 2.3), libzstd1 (>= 1.3.2), zlib1g (>= 1:1.1.4)
Depends: tar (>= 1.28-1)
Suggests: apt, debsig-verify
Breaks: acidbase (<= 1.4.5-4), amule (<< 2.3.1+git1a369e47-3), beep (<< 1.3-4), im (<< 1:151-4), libapt-pkg5.0 (<< 1.7~b), libdpkg-perl (<< 1.18.11), lsb-base (<< 10.2019031300), netselect (<< 0.3.ds1-27), pconsole (<< 1.0-12), phpgacl (<< 3.3.7-7.3), pure-ftpd (<< 1.0.43-1), systemtap (<< 2.8-1), terminatorx (<< 4.0.1-1), xvt (<= 2.1-20.1)
Filename: pool/main/d/dpkg/dpkg_1.19.7ubuntu3_amd64.deb
Size: 1127856
MD5sum: f595c79475d3c2ac808eaac389071c35
SHA1: b9cb6b292865ec85bca1021085bc0e81e160e676
SHA256: 76132be95c7199f902767fb329e0f33210ac5b5b1816746543bc75f795d9a37c
Homepage: https://wiki.debian.org/Teams/Dpkg
Description: Debian package management system
Task: minimal
Description-md5: 2f156c6a30cc39895ad3487111e8c190
```
`Filename`を見ると、バイナリの場所が書いてあるのでそれを取ってきます。
```.sh
$ wget http://security.ubuntu.com/ubuntu/pool/main/d/dpkg/dpkg_1.19.7ubuntu3_amd64.deb
```

dpkgがないため、バイナリなくてやばいなり、という渾身のギャグを一発かました後、直接extractしてバイナリを取り出します。
```.sh
mkdir nirugiri && cd nirugiri
ar x ../dpkg_1.19.7ubuntu3_amd64.deb
unxz ./data.tar.xz && tar xvf ./data.tar
sudo cp ./usr/bin/dpkg /usr/bin/
```

これでdpkgのリインストールは終わり。

## aptのリインストール
apt自体は、上の方法で同様にやればOK。しかも今回はdpkgを使えます。ありがて〜〜〜。
aptのインストールが終わったら念の為dpkgをaptからリインストールするといいって実家を出る時にばあちゃんが言ってました。

## 古いaptを消す
これでやっと振り出しに戻りますが、以前aptは`/usr/local/etc/apt`を見続けます。ストーカー並みに見続けます。
なので、straceして何が悪さをしているかを見ます。
```.sh
openat(AT_FDCWD, "/usr/local/lib/libapt-private.so.0.0", O_RDONLY|O_CLOEXEC) = 3
```
この辺ですね。抹消します。
```.sh
sudo mv /usr/local/lib/libapt-private.so.0.0 /usr/local/lib/libapt-private.so.0.0.kasu
sudo mv /usr/local/lib/libapt-pkg.so /usr/local/lib/libapt-pkg.so.kasu
```
恨みを込めて、拡張子はkasuにしておくのがおすすめです。


# アウトロ
いかがだったでしょうか？


晩御飯はいつ食べても美味しいことが知られています。



# 参考
ニルギリ
https://youtu.be/yvUvamhYPHw

