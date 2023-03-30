# tools-note

# C2
https://github.com/HavocFramework/Havoc
### 跨平台重构了Cobaltstrike Beacon，适配了大部分Beacon的功能，行为对国内主流杀软免杀，支持4.1以上的版本。
https://github.com/H4de5-7/geacon_pro
### Custom Command and Control (C3). 
https://github.com/WithSecureLabs/C3
### 一个无法检测到的 C2 服务器，它通过 Google SMTP 进行通信以逃避防病毒保护和网络流量限制。
https://github.com/machine1337/gmailc2
### Gh0st2023远控RAT、重写大灰狼远控RAT核心功能与组件模块、免杀主流防病毒软件
https://github.com/SecurityNo1/Gh0st2023
### Supershell C2 远控平台，基于反向SSH隧道获取完全交互式Shell
https://github.com/tdragon6/Supershell

# 内网
## 横向
### 密码凭证收集
https://github.com/AlessandroZ/LaZagne
### 内网渗透辅助工具集
https://github.com/sairson/Yasso
### fscan平替，自行编译，过卡巴（cube优于aopo）
https://github.com/JKme/cube
https://github.com/ExpLangcn/Aopo
### netspy是一款快速探测内网可达网段工具
https://github.com/shmilylty/netspy
### SharpHostInfo是一款快速探测内网主机信息工具
https://github.com/shmilylty/SharpHostInfo
### powershell横向脚本
https://github.com/samratashok/nishang
### 免杀横向移动命令执行测试工具(无需445端口)
https://github.com/rootclay/WMIHACKER
### RequestTemplate是一款两端并用的红队渗透工具以及甲方自查工具
https://github.com/1n7erface/RequestTemplate
### UAC bypass for x64 Windows 7 - 11
https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
### 研究利用golang各种姿势bypassAV
https://github.com/safe6Sec/GolangBypassAV

## 域渗透
### CrackMapExec是一款针对Windows活动目录(AD)进行渗透测试的精巧工具集。项目组成该项目采用了Impacket项目里很多有用的网络协议类。
https://github.com/Porchetta-Industries/CrackMapExec



## hash抓取（arp投毒）
https://github.com/SpiderLabs/Responder
https://github.com/lgandx/Responder

## 文件传输
https://github.com/dutchcoders/transfer.sh

## 域渗透工具包
https://github.com/fortra/impacket








# 外网

## 漏扫框架、poc
https://github.com/projectdiscovery/nuclei-templates
https://github.com/projectdiscovery/nuclei
https://github.com/hktalent/scan4all

## 隧道工具
### http隧道工具
https://github.com/sensepost/reGeorg
https://github.com/L-codes/Neo-reGeorg

### 毒刺(pystinger)通过webshell实现内网SOCK4代理,端口映射
https://github.com/FunnyWolf/pystinger

### 一款高性能 HTTP 代理隧道工具
https://github.com/zema1/suo5

### SPP is a simple and powerful proxy
https://github.com/esrrhs/spp

### 一款基于命令行实现的功能强大的TCP流量转发工具，用于在后渗透中的横向越权时使用，该工具可定向转发数据包，打破内外网屏障。
https://github.com/lyshark/FlowForward

### GoProxy是一款轻量级、功能强大、高性能的http代理、https代理、socks5代理、内网穿透代理服务器、ss代理
https://github.com/snail007/goproxy

### HTTP/2协议的go语言http隧道
https://github.com/mmatczuk/go-http-tunnel

### EarthWorm是一款跨平台用于开启 SOCKS v5 代理服务的工具
https://github.com/idlefire/ew

### 一款lcx在golang下的实现, 可用于内网穿透, 建立TCP反弹隧道用以绕过防火墙入站限制等
https://github.com/cw1997/NATBypass

### hoaxshell是一款功能强大的非传统Windows反向Shell
https://github.com/t3l3machus/hoaxshell


### icmp隧道
https://github.com/esrrhs/pingtunnel

### dns隧道
https://github.com/iagox86/dnscat2

### icmp shell
https://github.com/bdamele/icmpsh










# 免杀
### powershell混淆免杀
https://github.com/danielbohannon/Invoke-Obfuscation
https://github.com/H4de5-7/powershell-bypass
### 一种用来生成Metasploit payload的工具，可绕过常见的防病毒解决方案和应用程序白名单解决方案。
https://github.com/GreatSCT/GreatSCT
### ShellCode_Loader - Msf&CobaltStrike免杀ShellCode加载器、Shellcode_encryption - 免杀Shellcode加密生成工具，目前测试免杀360&火绒&电脑管家&Windows Defender
https://github.com/Axx8/ShellCode_Loader
### Golang免杀马生成工具，
https://github.com/piiperxyz/AniYa
### 一个免杀生成器模板，目前可以过国内主流杀毒。
https://github.com/Arks7/Go_Bypass
### Invoke PS-Image 是一种使用 LSB 隐写术将恶意 Powershell 脚本注入图像的工具
https://github.com/INotGreen/Invoke-PSImage
### ScareCrow - Payload creation framework designed around EDR bypass.
https://github.com/optiv/ScareCrow
### Mangle is a tool that manipulates aspects of compiled executables (.exe or DLL) to avoid detection from EDRs
https://github.com/optiv/Mangle
### 掩日 - 适用于红队的综合免杀工具
https://github.com/1y0n/AV_Evasion_Tool
### 一款可以过国内所有杀软可以过云查杀的shellcode loader
https://github.com/Avienma/Gobypass
### golang免杀捆绑器
https://github.com/Yihsiwei/GoFileBinder
### 利用golang各种姿势bypassAV
https://github.com/safe6Sec/GolangBypassAV
### 被选入LOLBAS项目的文件或脚本必须满足以下三个条件：
    是Microsoft签名的文件，可以是操作系统本身的文件，也可以是从Microsoft下载的文件。
    具有额外的”意外”功能。
    拥有对APT团队以及红队有用的功能。
https://github.com/LOLBAS-Project/LOLBAS


# 提权
## 土豆系列
https://github.com/decoder-it/LocalPotato
https://github.com/zcgonvh/DCOMPotato
https://github.com/bugch3ck/SharpEfsPotato
https://github.com/antonioCoco/JuicyPotatoNG
https://github.com/wh0amitz/PetitPotato

## windows 提权
### Windows 平台提权漏洞大合集，长期收集各种提权漏洞利用工具
https://github.com/lyshark/Windows-exploits

# 文章
### 收集整理各种数据库的利用姿势
https://github.com/safe6Sec/PentestDB
### 命令行的用法
https://github.com/jlevy/the-art-of-command-line
### 后渗透记录
https://github.com/ybdt/post-hub
### powershell攻击
https://github.com/rootclay/Powershell-Attack-Guide
### axis2 shell
https://github.com/Svti/Axis2Shell
### 远控免杀系列文章及配套工具
https://github.com/TideSec/BypassAntiVirus
### 红队知识库
https://github.com/guchangan1/All-Defense-Tool
https://github.com/Threekiii/Awesome-Redteam




# 工具
## burp插件
### 根据自定义来达到对数据包的处理（适用于加解密、爆破等）
https://github.com/wafinfo/autoDecoder
https://github.com/f0ng/autoDecoder
### 一个用于前端加密Fuzz的Burp Suite插件
https://github.com/c0ny1/jsEncrypter
### 服务端配置错误情况下用于伪造ip地址进行测试的Burp Suite插件
https://github.com/TheKingOfDuck/burpFakeIP
### api接口探测
https://github.com/API-Security/APIKit

## 摄像头漏洞
https://github.com/zzheff/FATSuite

## app检查
https://github.com/kelvinBen/AppInfoScanner


## 用户名全网搜索
https://github.com/soxoj/maigret

## 云环境利用
https://github.com/teamssix/cf
七牛云查看
https://github.com/qiniu/kodo-browser

## jndi注入工具
https://github.com/exp1orer/JNDI-Inject-Exploit
https://github.com/Mr-xn/JNDIExploit-1
https://github.com/WhiteHSBG/JNDIExploit

## weblogic\jdbc.xml解密
https://github.com/TideSec/Decrypt_Weblogic_Password



### 适用于weblogic和Tomcat的无文件的内存马(memshell)
https://github.com/keven1z/weblogic_memshell

### 若依懒人利用
https://github.com/G0mini/PyBy2

























