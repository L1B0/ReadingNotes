[TOC]



# AllMemPro - HYPERVISOR-BASED ACTIVE DATA PROTECTION FOR INTEGRITY AND CONFIDENTIALITY OF DYNAMICALLY ALLOCATED MEMORY IN WINDOWS KERNEL（2018）

## 1. 介绍

### 出发点

- 存在的问题：
  - Windows内置的安全性和现有的方法只提供内核模块代码部分的完整性，并检查系统链表的完整性；
  - 不提供第三方驱动程序分配内存的**完整性和机密性**。

- 已知的漏洞
  - VBoxDrv.sys(Kirda,2015): 被Turla rootkit利用，向任意内核内存写入任意值；
- 第三方驱动的漏洞才是真正的利用点，因为其运行在与Windows内核相同的特权级；并且在内核模式，没有内置的Windows安全控制功能来防止非法恶意软件的访问。

### 威胁模型

- 入侵者可以绕过所有的预防措施，安装内核模式的malware
- malware driver可以找到内存敏感数据和代码；
- malware driver读写windows内核以及任何第三方驱动分配的内存；
- malware读写内核模块的代码部分；

### 现有工作

#### 2009 - Kernel Data Integrity Protection via Memory Access Control . Srivastava

使用hypervisor协调试图写受保护的内核数据的指令的执行。

只保护系统关键数据：处理特权升级的凭证，并检测从链表中非法删除结构。

#### 2017 - HACS: A Hypervisor-Based Access Control Strategy to Protect Security-Critical Kernel Data. by Wang

HACS包含一个模块的白名单，只有白名单的模块可以修改受保护的区域。

如果一个受信任的驱动程序被破坏，HACS无法防止非法的内存访问。

#### 2017 - DADE by Yi

提供内核完整性，定期扫描不变属性并检查内核函数调用的回溯。

有概率被绕过，并且不保护第三方驱动的内存，

### 本文工作

提出了一个内存访问规则来处理内核模式的恶意软件，它有以下主要原则：

- 陷入每个内存访问，赋予这个驱动自己所分配的内存的全部权限；
- 预防其它驱动对内存甚至是一个字节的非法访问；
- 保护分配数据的完整性和机密性；
- 在内存被修改后恢复；

规则是实时调整的：

- 为每个内核模式驱动程序单独的内存访问规则;
- 当新的驱动加载或模块分配和回收时，更新规则；

## 2. 研究背景

### Windows 10 1709集成的安全功能

- Device Guard
  - Kernel Mode Code Integrity(KMCI)：预防对内核内存的可执行页面的修改；
  - “Driver compatibility with Device Guard in Windows 10” - 内存页和内存段不能同时可写可执行，可执行代码不能直接修改
- Credential Guard
- UEFI Secure Boot
- updated Kernel Patch Protection (PatchGuard)
  - 保护Windows内核中的关键结构不被未知代码修改，存储并定期验证特定区域的校验和，不匹配则蓝屏；
  - 对于链表，PatchGuard只检查结构之间链接的完整性，有4种不同类型的BSOD (Marshall, 2017)，不阻止结构修改。
- Supervisor  Mode  Execution Prevention (SMEP)
- Early Launch Antimalware (ELAM)
- Windows Defender Exploit Guard (WDEG) 

总结，保护以下完整性：

- 内核模式模块的代码段;

- 带有分配结构的无文档内部列表。

不支持第三方驱动分配的内存完整性和机密性，并且非法内存修改导致的蓝屏并不适合工业设施。

### 学术研究

保护内核数据可以分为基于内核驱动和基于硬件虚拟化，后者具有更高的权限并且在防御攻击上更有弹性。

基于硬件虚拟化的研究根据中断内核模式的内存访问的技术可以分为两类：

- Page Fault：标记内存页不存在，对页面的访问触发PF，进而由hyper-v控制；
- EPT技术：对read、write和execute分别中断，触发EPT violation，进而由hyper-v处理；
- EPT更快，自Nehalem微体系结构在Intel CPU集成；

|                  | 工作                                                         | 局限                                                         |
| ---------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Srivastava(2009) | 基于PF技术，将内核分为两部分：保护和不受保护，完全信任内核，对其它驱动只有有限的信任； | * 复杂的内存访问策略；* 数据的机密性；* 内核代码的完整性；* 需要内核源码； |
| HACS(2017)       | 基于EPT技术，拦截受保护区域的写请求；基于白名单策略。        | * 无法阻止两个合法模块之间的访问；* Linux                    |
| DADE(2017)       | 基于EPT技术，拦截写请求，比较回溯调用，识别出非法请求；揭示了unlink攻击。 | * 原型为Linux，kvm，需要os源码；*                            |
| LKMG(2018)       | 基于EPT技术，将驱动与内核其它部分隔离；                      | * Linux，Xen；* 策略从源码生成，缺乏灵活性；                 |
| HUKO(2011)       | EPT;                                                         | * 合法的接口可以被利用；                                     |

![image-20211221135154738](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211221135154738.png)

## 3. 系统架构和实验结果

### 如何将EPT应用到动态分配数据的完整性和机密性保护

三种类型的攻击：

- 读写第三方驱动的数据；
- 读写第三方驱动的代码段；
- unlink和修改Windows内部列表的结构体；

保护的特征是避免非法操作，而不会产生蓝屏；

#### 读写第三方驱动的数据

简单来说就是，hook动态分配的函数ExAllocatePoolWithTag，当受保护的驱动调用该函数，对分配的空间设置不可读写；于是任何对该区域的访问都会产生vm-exit；

陷入到hyper-v后，它检查请求的源地址是否符合规则，若符合：

- 设置读写位为true，PFN（代表物理地址）不变；
- MTF设置为true：当执行指令后，产生vm exit，从而恢复读写位和MTF；

若不符合:

- 设置PFN为一个假的，其他的和符合规则的一样；

![image-20211221145634055](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211221145634055.png)

#### 读写第三方驱动的代码段；

(KMCI)保证不被改，不保证机密性；

不能和上面一样，因为会产生巨大开销。

两套EPT，一套用于执行代码，一套用于保护数据；

#### unlink和修改Windows内部列表的结构体

监控进程的创建删除，将EPROCESS的地址加入规则；

## 4. 总结和展望

## 攻击

![image-20220107190210705](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220107190210705.png)

# MemoryRanger-Run drivers in isolated kernel space 2018

## 出发点

- 关键思想是动态分配EPT分页结构，并实时更新EPT页表条目的访问属性。

![image-20220107161609846](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220107161609846.png)

![image-20220107161752672](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220107161752672.png)

# MemoryRanger-Hijacking FILE_OBJECT 2019 CDFSL

> https://igorkorkin.blogspot.com/2019/04/memoryranger-prevents-hijacking.html

## 0. 出发点

- 存在一种新的攻击方法：
  - 针对FILE_OBJECT的劫持，使用驱动对**独占模式**的文件内容进行读写；造成对文件的非法访问；

## 1. 攻击原理

文件系统的接口调用如下图，对象管理器调用SRM进行安全检查。

- SRM决定“一个文件的访问控制列表(ACL)是否允许以线程请求的方式访问该文件。”如果是，对象管理器授予访问权限，并将被授予的访问权限与它返回的文件句柄关联起来”。
- IO管理器在对象管理器的帮助下创建FILE_OBJECT。
- 每个打开的文件在内存中存在两个结构体：
  - FILE_HANDLE 句柄：Ring3
  - FILE_OBJECT 对象：Ring0

问题在于，使用文件句柄handle对文件进行读写和关闭时，SRM不参与（2003）。

![image-20220108104801707](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108104801707.png)

### A. Windows内置的安全共享机制

ZwCreateFile ShareAccess Flag,这个标志决定了当前文件是如何打开的，也决定了允许继续或拒绝访问的类型，它的错误代码是STATUS_SHARING_VIOLATION。

如之前所述，只有ZwCreateFile时SRM进行安全检查，于是下图攻击场景失败。

![image-20220108105212431](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108105212431.png)

### B. FILE_OBJECT

字段SharedRead和SharedWrite对应了ZwCreateFile函数的参数SharedAccess。

此外，以下四个字段也被用于读写操作，并且不涉及SRM和检查共享权限：

* Vpb：
  * 在向文件系统驱动程序发送创建请求或打开请求之前，I/O管理器对Vpb字段进行初始化。
  * Vpb字段指向一个挂载的Vpb (Volume Parameter Block)，它与目标设备对象相关联。
* FsContext: 指向FSRTL_COMMON_FCB_HEADER结构体，该结构体必须由文件系统或网络驱动器分配;
* FsContext2: 与文件对象相关联的上下文控制块(CBB)
* SectionObjectPointer: 是一个section_object_pointer类型的结构体，用于存储文件流的文件映射和缓存相关信息

**攻击的核心原因是攻击者可以在无报错的情况下读取这些字段，并使用它们来访问对应的文件。**

### C. 实施攻击

1. ZwCreateFIle: 创建一个HijackFile.txt；
2. ObReferenceObjectByHandle：创建HijackFile.txt的句柄；
3. 通过**文件名**遍历**对象目录列表**，得到目标文件的文件对象；
4. **复制**目标文件对象的**四个元素**到HijackFile.txt的文件对象变量；
5. 调用ZwRead/Write/CloseFile，使用HijackFile的文件句柄对目标文件内容进行读写和关闭。

**结果：Win 10.1809，10小时后无异常（BSOD），攻击成功。**

![image-20220108110956574](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108110956574.png)

## 2. MemoryRanger的防御

- **Kernel-mode Driver**: 注册回调函数，获取各种os活动，如驱动加载；

- **DdiMon(Device Driver Interface Monitor)**: hook内核模式的api调用
- **MemoryMonRWX**：跟踪捕获内存访问；
- **Memory Access Policy (MAP)**：决定是否阻止或允许访问；

![image-20220108111510949](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108111510949.png)

### 针对FILE_OBJECT的保护

自己的思路：从攻击面做起，

- 访问ODL：禁止
- 复制句柄：禁止
- 文件操作

作者的思路：监控ZwCreateFile和Close，获取每个文件的句柄和对应的driver，进行访问控制。

![image-20220108112230093](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108112230093.png)

# MemoryRanger-Kernel Hijacking 2020 JDFSL

> https://igorkorkin.blogspot.com/2021/05/kernel-hijacking-is-not-option.html

## 0. 出发点

- 三种新的内核数据劫持攻击：

  - 未经授权的访问：Object Manager
  - 未经授权的访问：NTFS driver components
  - 升级进程特权：patch _TOKEN结构体

- 问题的原因在于：

  - 一方面，所有的驱动程序和操作系统内核**共享**相同的内存空间；
  - 另一方面，没有内置的机制来**限制对内核内存的访问**。所有的驱动程序都有访问系统的权限，可以被攻击者使用。
  - 而Windows安全特性提供有限的内核内存保护。

- 防御方法：

  - 运行一个特殊的数据enclave，将敏感的系统内核数据保护隔离：
    - os结构体
    - os内核核心：nt
    - os内核内置的driver

## 1. 攻击

作者介绍了三种Hijacking的攻击方法：

- Handle Table Hijacking
- ~~Hijacking FILE_OBJECT（2019 CDFSL）~~
- Hijacking NTFS structures
- Token Hijacking

![image-20220108144359276](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108144359276.png)

### A. Handle Table Hijacking

内核句柄表（Kernel Handle Table）：存储从句柄到对象结构的映射；

- 如何获取：
  - nt!ObpKernelHandleTable
  - SYSTEM:4 process的EPROCESS.ObjectTable
- 基于句柄的机制操作各种对象，如文件、进程、线程或注册表；

Windows提供了**ExEnumHandleTable**进行句柄枚举。

**攻击原理：复制目标文件的的OBJECT_HEADER的ObjectPointerBits字段。**

![image-20220108145907788](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108145907788.png)

### B. Hijacking NTFS structures

> 基于FILE_OBJECT Hijacking攻击的改进。

场景：安全服务提供对FILE_OBJECT的机密性和完整性保护，其它驱动对其访问被拒绝。

#### 攻击原理

到更底层的层面（**FILE_OBJECT指向的控制数据块**）进行攻击。

FILE_OBJECT结构包括字段FsContext和FsContext2，它们指向控制块结构；

- FsContext -> File Control Block (Ring3), 其存储一个**FSRTL_ADVANCED_FCB_HEADER**结构体，标识了文件系统的文件流。
- FsContext2 -> Context Control Block (Ring0)
- 两个字段的内存连续，可以同时覆盖。
- FSRTL_ADVANCED_FCB_HEADER没有受到patchguard保护；

流程：

- 覆写FSRTL_ADVANCED_FCB_HEADER结构体（怎么获取？？？）
  - 直接覆写存在一个问题：windows会对资源的拥有者thread进行校验，需要对该数据也修改；
- 修改Resource->OwnerEntry.OwnerThread和PagingIoResource-OwnerEntry.OwnerThread为攻击者的线程id；
- Windows在每次访问后都会修改FSRTL_ADVANCED_FCB_HEADER，于是为了多次访问，需要重复以上两个步骤；

![image-20220108150323139](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108150323139.png)

### C.Token Hijacking

#### 攻击原理

本方法是Hoglund and Butler (2006)提出方法的完善版，区别在于本方法完全复制UserAndGroups数据，而前人只提出复制几个字段。

复制_TOKEN结构体的三个字段：

- UserAndGroupCount;
- UserAndGroups array: Attributes and Sid structures;
- SidHash structure;

难点在于，UserAndGroups数组的大小不是固定的。而攻击能够成功的原因是**System:4进程的_TOKEN结构的可变部分小于普通进程的相应结构**。

下图是复制前后攻击者进程的EPROCESS结构体的变化。

![image-20220108152524234](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108152524234.png)

## 2. MemoryRanger的防御

- 对于Handle Hijacking，**控制**相应文件的HANDLE_TABLE_ENTRY的访问；
- 对于NTFS Hijacking，**控制**FILE_OBJECT的FSRTL_ADVANCED_FCB_HEADER字段的访问；
- 对于Token Hijacking，**禁止**访问EPROCESS；

![image-20220108153655038](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20220108153655038.png)

# Protected Process Light is not Protected: MemoryRanger Fills The Gap Again（2021）

## 出发点

- 为了防止非法访问关键进程的内存以及数字版权管理(DRM)的要求，Windows OS采用PPL(Protected Process Light);
- 问题：入侵者可以使用内核驱动来禁用PPL，从而访问受保护的进程内存；并且可以为malware开启PPL；
- 原因：PatchGuard不检查PPL的完整性；
- 解决：本文提出基于hypervisor的解决方案MemoryRanger。
  - 在enclave中运行新加载的驱动程序；
- 本文方法不适用以下情况：
  - Lagrasta[27]展示了如何通过在NtlmShared.dll中hook MsvpPasswordValidate来提取密码散列;
  - Ciholas[28]揭示了如何获得受保护进程的处理，包括反恶意软件和反作弊保护解决方案;
  - Forshaw[29]使用COM技术的一个特性将任意代码注入到PPL中;
  - 另一种方法是通过使用合法的comsvcs.dll库[30]转储LSASS进程的内容来获取凭证;

## 介绍

### PP Model

进程内存的保护对于各个领域都至关重要，包括数字版权管理(DRM)市场、游戏和反病毒行业以及证书保护。

为了满足这些需求，Windows扩展了它的安全模型[1]，并引入了受保护的过程模型(PP)来为高价值内容提供更多的保护。

该模型提供了几个新的安全特性，包括**限制**使用管理权限运行的其他进程对**受保护进程内存的读写访问**。

为了作为PP加载磁盘上的映像文件必须使**用Microsoft证书签名**。

### PPL

PPL特性是通过在EPROCESS结构中添加一个新的PS_PROTECTION字节实现的。这个字节是为PPL进程设置的，并在Windows  API例程中检入。

恶意软件驱动程序可以禁用PPL保护通过清除这个字节，这将停止对该进程的限制访问。这种DKOM攻击对平台安全至关重要。

微软专家考虑通过禁止恶意代码的数字签名来防止此类攻击，并使用内核补丁保护(KPP/PatchGuard)和受保护环境认证和授权导出驱动程序(PEAuth)来识别此类攻击.

## PPL细节

> 介绍PPL的实现原理，以及存在的缺陷。

PPL包含三个元素：受保护的签名者、受保护的类型以及审计模式。并且加载到受保护进程中的**所有dll**也必须使用**相同的证书**进行签名。

PPL被应用于保护关键OS APP的内存，以及各种安全厂商的软件，如Bitdefender [33], Cisco [34], ESET [35], **Kaspesky** [36], SolarWinds [37], McAfee [38].

PPL限制了不受保护的进程对受保护的活动，包括**线程注入、内存写入、调试以及内存转储**。

### 激活和检查PPL

PPL是自动激活的，但在某些情况下，例如，为了激活LSASS进程的本地安全机构(LSA)保护，必须采取以下步骤[40]。

检查PPL可以调用如下API，原理都是读取进程的EPROCESS结构体: 

- ZwQueryInformationProcess with 
  ProcessProtectionInformation flag
- PsGetProcessProtection
- PsIsProtectedProcess
- PsIsProtectedProcessLight

### 实现细节

#### 1) EPROCESS 更新

#### 2) 创建PPL进程

有几个条件，

第一个是二进制文件必须有由Microsoft提供的签名，但目前只对Microsoft二进制文件可用。

在启动过程PspInitPhase和运行时通过调用NtCreateProcess可以创建受保护的进程，如图2所示。

![image-20211208202538346](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211208202538346.png)

所有这些函数都使用相同的进程管理器例程SepSetTrustLevelForProcessToken来更新字段Protection  PS_PROTECTION[46]。

Windows提供了一个带有SERVICE_CONFIG_LAUNCH_PROTECTED标志的ChangeServiceConfig2例程来使用ELAM以PPL方式运行服务，服务保护类型存储在SERVICE_LAUNCH_PROTECTED_INFO结构中[31,478,48]。

#### 3）访问进程内存

访问普通进程的内存必须调用如下API：

- OpenProcess
- ReadProcessMemory\WriteProcessMemory
- CloseHandle

#### 4）使用OpenProcess接口禁用PPL

MSDN描述了OpenProcess函数使用安全描述符对caller的访问权限进行检查。

如果调用者已经启用了**SeDebugPrivilege**特权，那么不管安全描述符的内容如何，请求的访问都会被授予。

在最新的win10中，该部分在nt!PsOpenProcess中实现。

![image-20211208203010091](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211208203010091.png)

开启SeDebugPrivilege后，可以获得进程的句柄，但是对于PPL进程，还有额外的一个检查。

#### 5）使用OpenProcess接口开启PPL

nt!RtlTestProtectedAccess和nt!PspCheckForInvalidAccessByProtection会对PPL进程的PS_PROTECTION字段进行检查。

![image-20211208203612218](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211208203612218.png)

### PPL未受保护

PPL安全特性仅基于在**OpenProcess**调用过程中**检查EPROCESS的保护字段**。同时，可以修改该字段，以禁用操作系统内置的关键进程的PPL，反之亦然，以将一个未受保护的进程提升为受保护的进程。

**攻击者**可以通过**禁用PPL保护功能轻易地杀死AV解决方案**（嘿嘿嘿），并从LSASS内存中窃取用户的证书。此外，他们可以使用PPL保护他们的恶意应用程序（这倒没有想到！）。

## 证明PPL的缺陷-Mimikatz可以关闭PPL

- 说明PPL机制的缺陷：用Mimikatz通过关闭LSASS的PPL，进而提取用户密码；
- 现有防御Mimikatz的机制；

### A. 攻击LSASS

调用Mimikatz命令如下：

1) privilege::debug - SeDebugPrivilege for Mimikatz；
2) lsadump::lsa /inject - 提取密码的hash；

更新后的Mimikatz可以通过patch进程的EPROCESS结构体来关闭PPL：

1) !+ - loads a Mimikatz driver
2) !processprotect /process:lsass.exe /remove  - 关闭PPL
3) privilege::debug - SeDebugPrivilege for Mimikatz；
4) lsadump::lsa /inject - 提取密码的hash；

![image-20211209102625675](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211209102625675.png)

另一种攻击的思路是提升malware的权限，只要比LSASS的PPL高，就可以访问其进程内存。

修改进程的PPL，结果如下图：

![image-20211209102858543](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211209102858543.png)

### B. 现有防御措施

## 本文工作-MemoryRanger

> MR提供可信的受保护进程。

### 简要介绍

MR有两个部分组成：一个内核驱动和一个Type 1 hypervisor：

- Driver：注册多个回调函数接收OS活动，如驱动（加载、卸载）、进程（创建、终止）；
- Hypervisor: MR可以通过重置内存页上相应的访问位来捕获对内存页的读、写、执行访问。

### PPL Safeguarding: MemoryRanger Updates

为了实现MR阻止对EPROCESS结构的保护字段的所有写访问，而不限制读访问，进行了更新。

- Driver:

  - 定位所有进程的EPROCESS，并维护一个Active Protected Processes列表；
  - 监控进程的创建和终止，从而实时更新APL；
  - 定位APL的每个进程的PS_PROTECTION地址，并发送给Hypervisor;

- Hypervisor：

  - 允许或禁止相应enclave的内存区域的访问；
  - 触发内存访问例外，决定是否是对PS结构体的写访问；

  

  ![image-20211208210758645](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211208210758645.png)

  ![image-20211208210814629](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211208210814629.png)

### 测试

开销约50%，可能的原因如下：

- MR被设计为一种概念验证解决方案，用于演示防止内核攻击的能力，其性能并不是优先考虑的问题。可以改进MR的内部调度算法，提高其整体性能。
- 分配给虚拟机操作系统的资源有限，性能下降加剧。使用更强大的测试平台可以提高性能结果。VMware工作站仿真VMX特性，这额外地消耗CPU资源。



#### 与MDCG对比

![image-20211209105050979](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211209105050979.png)

