# 突如現れるbash欲と犬とリシテアとファイアーエムブレムとYoutubeShort

keywords
This article is not about pwn.


# イントロ

最近、本当に朝が起きられずに困っています。理由を考えたところ、冬だから朝の日光の量が少ないという結論に至りました。僕は悪くありません。


# 突如襲ってくるBashスクリプト書きたい欲

***「なんかBashスクリプトを書きてぇ」***
きっと皆さんも半年に一回くらい思うことがあるでしょう。僕も思いました。特にBashの構文が好きとかではないし、寧ろBash全然分からん民なのですが、知らないからこそ半年に一回くらいちゃんとしたスクリプトを書きたくなります。
Bashの一番いいところは、結局半年後には構文含めて全部忘れることです。好きな小説を、もう一度読む前の新鮮な気持ちで読み直したいというのは、人類誰もが思ったことがあるでしょう。僕もノルウェイの森は18歳に戻って何度でも読み直したい衝動に駆られます。でもそれはできません。既に何回も読んでしまったし、なによりもう20歳を超えてしまっています。ノルウェイの森は、18歳で読むべき本であり、今読み返しても当時以上の気持ちを抱くことは出来ないでしょう。対して、Bashは何度でも忘れて何度でも新鮮な気持ちで書くことの出来る唯一の言語です。書こうと思う度に、新しいBashに出会えます。
さて、問題は何を書くかです。普段からちょっとしたワンライナーくらいなら書くことはあるけど、今回はそれなりに規模のあるものを書きたい。ということで、以下に続きます。


# リシテアのお話

最近、あまりCTFのkernel問題を解いていません。この前久しぶりにBsidesなんちゃらCTFの`shared knote`という問題をやったけどぼろぼろぼろでした。特にひどかったのが、必ずクラッシュしてレース成功しねぇ〜〜〜〜と8億年くらい嘆いていたら、exploit中でレース後に処理を止めずにそのままexitしていたため、不正なfdをそのまま全部閉じていてそのせいで落ちていただけというのがありました。それに気づくまでかなりの時間を消耗したので、とてもぽよぽよになりました。
その問題では`/proc/sys/vm/mmap_min_addr`が0になっているというところに気付けるかどうかが大きかったのですが、これは僕の"kernel問で最初にやることリスト"に入っていなかったため見逃してました。そもそもにリストに入っていたとしても、リストの中身を全部チェックするのは結構面倒くさいため多分気づいていなかったと思います。
ということで、今回はココらへんの自動化を目的としてBashスクリプトを書くことにしました。わーい、わーい。題材見つかったよ〜〜。

書いたやつはGithubに置いときました。まだ工事中だけど。
https://github.com/smallkirby/lysithea


## 試行錯誤の自動ログ

kernelpwnしてる時って、exploit書いてはQEMU立ち上げて走らせて出力見て泣いて、またexploit書き直して...の繰り返しです。問題は途中で方針転換したりした時で、まぁ大抵うまく行きません。取り敢えず一旦うまくいったところまで戻って書き直そうとしたときにはもう遅い、どこまでがうまくいってたやつか分からなくなっています。戻しては実行し、戻しては実行し、最終的には乾パンを買いに行ったっきり二度と問題を解かなくなること間違いなしです。
どうしたらいいか、答えは簡単。QEMUを動かす度にexploitのスナップショットを取れば良いんです。但しexploitだけではどの時点までうまく行っていたか分かりません。QEMUの出力も一緒に保存してしまいましょう。
git使えばいいだけですね。実行する度にcommitするのはめんどいですね。スクリプトの出番ですね。

![](https://i.imgur.com/u5P6Un8.png)

戻りたいときは、一旦log一覧を確認して。
![](https://i.imgur.com/3DLYJ0s.png)

これだと思うものを指定すれば、そのときのQEMU出力が見れます。これで、どこまでうまく行ってたのか分かりやすいね！わ〜〜い、わ〜〜〜い。

![](https://i.imgur.com/Auilzb1.png)


当時のexploitも簡単に確認できないとね。これで方針転換しほうだいだ！やった〜〜〜、やった〜〜〜〜。
![](https://i.imgur.com/HuQ9mv6.png)


## コンフィグチェッカー

https://github.com/smallkirby/lysithea/tree/master/drothea

さてさて、先程話にも出た、確認すべきkernelのコンフィグの話。これも、まとめてしまいましょう。これは大体`/proc`以下のファイルをcatするだけなので適当にBash書いときゃOKですね。但しbusyboxのシェルは`ash`なので、Bash-specificな機能なしのPOSIX準拠で書かなくちゃね。あと、`userfaultfd`が存在しているかどうかとかはCプログラム中で確認しなきゃなので、純Bashで確認できないところはCにおまかせしています。

但し、これを実行するのに手間がかかるとめんどくさくて、結局確認しないまま問題を解き始めて崩壊するのが目に見えていますね。そして解けなくて乾パン買いに行くのも目に見えています。人間の怠惰をなめてはいけません。これも自動化しましょう。

![](https://i.imgur.com/peJG5IE.png)

やった〜〜〜。これで問題を解き始める前に1コマンドをホストで叩くだけでチェックリストを確認できますね。テスト群自体はまだ殆どモックしか無いけど、まぁそれはこれからやります(やらない未来が見えているけどね)。


## あとはスニペットをちょちょいと混ぜて

今までは、ファイルシステム展開したり圧縮したりexploitをビルドしたりするスニペットを別で管理していましたが、これも混ぜ混ぜしました。名前覚えるのめんどいしね。これでワークスペースのセットアップも1コマンドで済むね、わ〜〜〜〜いわ〜〜〜〜〜い。乾パンを買いに行ける時間が増えて嬉しいです。

![](https://i.imgur.com/EJY5z0l.png)


## 飽きた

ここまで書いてBashに飽きたので、もう一生書きません。Pythonが試行だってカーニハンとリッチーが言ってました。



# わんちゃんワンちゃん飼いたい

理念と目標を一切持たないことで知られる僕ですが、人生に対してただ一つだけ目標を持っています。

***犬を、飼いたい。***

これだけが、僕の人生の唯一の目標です。今すぐにでも、飼いたい。そして、愛でたい。散歩したい。
僕の実家は犬を室内飼いするのに反対な家族がいたため、犬を飼うことは出来ませんでした。外で飼うのは、僕の信念に反します。家族だから一緒の部屋で過ごしたい。よって飼うのをずっと我慢してきました。
さて、大学生になり一人暮らしになりましたが。じゃあ今すぐ犬と過ごせるかと言うと、否です。問題は金銭面ではありません。それはまぁなんとかすればなんとかなるでしょう。
問題は、大学生は研究室によく行くので家を空ける時間が多いということ。犬は人間なので、ずっと一人だと寂しくなってしまいます。不規則に且つ長時間家を空けることが多い現在は、飼うことはできません。できないというか、まぁできるはできるだろうけど、僕の犬信念に反します。


なので今は犬の画像を眺めることで我慢しましょう。以下、僕の好きな犬リストです。永久保存版です。


## 柴犬

一番好き、すごく好き。地元にいる時に、近所で柴犬を飼っている人がいたので頻繁に訪れて散歩させてもらっていました。あの素朴な可愛さは何よりもたまりません。小さすぎないのも可愛いです。ぼくは小さすぎる生物(チワワとか)を虫と同じレイヤーで認識してしまいがちなので、柴犬のサイズはぼくのストライクゾーンど真ん中です。あのしっぽをマフラーにしたいです。
![](https://i.imgur.com/uRSd7Ym.jpg)



## シベリアンハスキー

狼っぽいのが好き。ハスキーを好きになったのは大学生になってからなんですが、あの大きさで体を擦り寄せてきた時には、そのまま持って帰ってしまおうかと思いましたね。

![](https://i.imgur.com/m0h7VM5.jpg)


## スピッツ(日本スピッツ)

やや小さめの犬種の中で唯一のランクイン。スピッツは、僕が猛烈に犬を飼いたかった小学生時代に、犬種図鑑みたいなのを眺めていた中で一目惚れした犬種です。尚、一回も実物を触ったことはありません。顔が好きです。

![](https://i.imgur.com/EUBNlMU.jpg)


## 秋田犬

やっぱり日本の犬こそ至高。もふもふなので最早わたあめ。わたあめに埋もれたいという良くはないけど、秋田犬に埋もれたい気持ちは人類の三大き欲求の内の2つを占める。

![](https://i.imgur.com/Z2KixH8.jpg)


## たぬき

犬以外から、堂々のランクイン。実家にたまに出現していたんですが、なんとも愛くるしい姿をしています。まるまる太ったたぬきは、もはやたぬきを超えてキツネと言っても過言ではないでしょう。

![](https://i.imgur.com/U0cgItz.jpg)



## 乾パン

非生物から、堂々のランクイン。僕も2年ほど前まではこいつを犬とは思っていなかったけれども、素朴な佇まい・愛くるしいフォルム・媚び具合、どれをとっても柴犬のそれと同じ。相違点を見つけることができなかかったため、犬として判断、ランク入り。

![](https://i.imgur.com/5eizxPB.jpg)



# Youtube Shorts

さてさて、自分に肩書きをつけるとしたら、最初は大学4年生になるでしょう。それでは他に何か肩書きをつけるとしたら、それは間違いなく"Youtube Shortsアンチ代表"になります。
僕はYoutubeで犬の動画(そして泣く泣く猫の動画)を見ることが好きなのですが、そのYoutubeに最近Shortsという機能が実装されました。これはほぼTiktokで、神聖なるYoutubeには到底許される機能ではありません。
まず、シーケンスバーが無い。意味がわからない。時間戻しが出来ない。どうなってんねん。ダブルタップが勝手にLikeになる。自分のLikedVideosにshortsが気づかずに入っていた日には、その日はずっと嫌な気分のままです。それから、次の動画がわからない。これが一番最悪。shortsには、犬の動画が多くあります。スワイプする度に可愛い犬が出てくるため、コレ自体はまぁいいです。但し、次の動画が予測できない(学習されてるっぽいけど)ため、見たくもない動画が目に入ることが多いです。一番最悪だったのは、犬の動画を見ていてスワイプしたら、Gの動画だったときです。あの日から僕はYoutubeShortsアンチ世界代表になりました。
そして、最近はshortsが存在するYoutubeが嫌になったためスマホからYoutubeを消しました。さようなら。shortsが消えたら、また会おう。



# ファイアーエムブレム

最近ちょっとした時間にゲームをするためにファイアーエムブレム風花雪月を買いました。いわゆるマスゲーとかSRPGとかいわれる種類のゲームです。院試期間中にこの上なくciv6にどハマリしたので、何らかのシミュレーションゲームを探していたところ、スマブラにも出てくるからという理由で風花雪月を買いました。
結果、とても好きです。ルールをよく知らないうちは、劣化版シミュレーションゲームじゃんとか思っていたけど、ちゃんと各ステータスの意味を調べている内に、ちゃんと考えてプレイできるゲームなんだと認識しました。純シミュレーションと異なり、キャラの育成要素もあるのが特長です。強いて言えば、僕は育成ゲームでは徹底的に育成しまくって、周回しまくって、ラスボスをこてんぱんに蹂躙するのが好きなのですが、本ゲームでは行動回数が制限されていたり、周回時にキャラを引き継げなかったりと育成に制限が有るため、その部分だけが少し不満です。あとキャラごとに支援値に制限が有るのも、少し不満。
既に1周して今2周目なのですが、今回はゲームを始める前にどのキャラをどう育てるかをまとめてから始めたので、1周目とは比較にならないぐらいつよつよなパーティが出来ています。空、飛び放題です。

先程のBashスクリプトで出てきたlysitheaとかdrotheaとかは風花雪月のキャラから取りました、意味はないけどね。リシテア、めちゃめちゃ強いです。火力がやばい。射程2の魔法しか覚えないのはあれだけど、杖持たせればいいだけです。ボスも大抵こいつでワンパンです。強い。



# アウトロ

***いかがだったでしょうか???***

カス記事を書くのはいつだって楽しいことが知られています。


# 参考
lysithea
https://github.com/smallkirby/lysithea
ニルギリ
https://youtu.be/yvUvamhYPHw

