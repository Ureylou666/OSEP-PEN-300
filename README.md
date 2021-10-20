# OSEP_PEN 300 考试攻略

被大佬忽悠报了名，2021给自己一点压力，由于是新课程，资料实在太少，开个荒。
感谢thanks delethead 提供的syllabus
https://github.com/deletehead/pen_300_osep_prep 

![image](https://user-images.githubusercontent.com/75350727/138061431-1ed20864-fd04-4b06-a43d-2c7cff4604e5.png)

https://www.t00ls.com/thread-62781-1-1.html

最近刚刚通过了OSEP的认证，整个备考过程中遇到不少问题，通过与小伙伴交流和自己的摸索终于通关。网上对于OSEP认证的中文介绍很少，也没看到详细攻略，由于是新课程，国内的资料实在太少，给坛子里红队大佬们，做个抛砖引玉，开个荒。
也欢迎师傅加Discord Ureylou#4733沟通交流~


最大的一个感想， 就是好好看教材，了解原理，减少依赖一键提权一键rce工具，知其然，知其所以然。

一、OSEP是啥，适合谁

Offsec这两年做了很多改版，做了一些细分，好多人戏称‘商业化’日渐浓重，其实个人觉得挺好的，可以在一个领域深挖。
当前分为三个分支，penetration test / web application / Exploit Development.
- 第一个分支为渗透测试，偏实战，大家熟知的OSCP就在这个分支，现在叫PEN-200；  Pen-210 是 wireless test，为无线安全渗透。
OSEP是在OSCP基础上的进阶版认证，也叫Pen-300，主要是在OSCP基础上，新增了免杀及内网渗透。
- 第二个分支为web安全测试，也叫OSWE或Web-300，主要为代码审计课程。
- 第三个分支主要为逆向，OSED即EXP-301，内容为 ；前两天新出的macos渗透课程，OSMR即EXP-312，当然还有OSEE即EXP-401.


可以看到初级为200课程，进阶为300课程，终极是400课程。

所以建议通过OSCP或有一定红队经验的师傅报名。

二、考试难度 / 过程

考试这个其实和OSCP大致差不多，一样的全程开启摄像头视频监考。当然考试商业版产品是不能用的，如Cobalt Strike、Burp Pro等。nishang、empire啥的可以用， 当然，我是觉得msf是真的很好用...

考试时间：考试为47小时45分，当然你可以选择休息，吃饭，睡觉，提前告知即可；

考试环境：考试环境为模拟一个企业环境，会有几个’外网‘（连上vpn后可以直接访问的,不是公网）。内网一般划分有三个互相信任的域。

考试题目：有两种方式通过考试，一种为获得指定内网机器的secret.txt，会有两条路径可以获得这个flag，这个点很关键，当一条路卡主了，换一条路说不定就通了，不用硬怼。
另一种是获取10个flag。OSEP这边local.txt和proof.txt都是10分，一台机器上可能有两个flag，可能只有一个。
另外，考试规定flag的截图必须为交互式shell，所以rdp这种就不行了，这个要注意。

考试过程：当时不知道自己怎么想的，预约了晚上10点开始考试，直接第一天上来就熬夜。这是个不好的例子，加上水平太菜，导致基本48小时就眯了3、4个小时，对体力是个巨大考验。
外网入口基本非常显然，dvwa medium难度吧...主要这个考试重点不是web。首发t00ls 谢绝恶意转载。
获得foothold后，会需要用到课程中的一些免杀，如inject,hollow和bypass技巧如amsi,clmbypass，applocker等，这个建议可以提前准备，考试时直接将生成的shellcode贴入项目生成exe就好了。
提权，在提权上卡了很久，主要还是需要知道原理，如printspoofer提权，机器都做了patch，直接使用脚本是无法提权的。
横向，横向主要使用powerview和教程中的技巧，这块建议多做几遍lab，加深对如LAPS、三种委派攻击、mssql提权RCE的理解。别像我考试时候再翻pdf学习mssql - -！。仔细观察域用户、域用户组、域机器，提示还是蛮明显的。

三、LAB

LAB有6道challenge，前三个为专项练习
challenge1：office钓鱼攻击
challenge2：mssql渗透
challenge3：linux/devops渗透
后三个为综合练习，如果准备参加考试的话，记得特别把后三个challenge多做几遍。

嗯

你懂得，不能再说了。


人不知而不学，不亦土逼乎

加油！Try Harder！

附件为challenge4 writeup，有兴趣的可以参考看看~

