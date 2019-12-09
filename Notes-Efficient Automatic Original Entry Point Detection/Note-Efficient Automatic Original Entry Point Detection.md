# Efficient Automatic Original Entry Point Detection（高效的自动化OEP检测方法）

> [论文地址](https://pdfs.semanticscholar.org/ddaa/298a521e72d77d74380b71b079ce656b2efd.pdf)



## 1. Related work

### 1.1 Generic Unpacking using Entropy Analysis（通过熵值分析进行通用的脱壳）

packed PE中有个段存放unpacked PE的数据，这个段的熵值明显比其他压缩过的段熵值低。

利用这一特性，在运行程序的时候，遇到**分支指令**的执行（jmp, jcc, call, retn）时，则暂停执行，然后计算该段的熵值，若该段的熵值较低（**4.1-4.6**）而它前一个的熵值较高，那么可以认为该地址为**OEP**。

但相较其他方法该方法的误报率较高。

### 1.2 OEP Detection Method with Candidate-Sorting（候选排序的OEP检测方法）

> 生成页（generating page）: 向另一个页面写入数据，并且这些数据随后会被执行。
>
> 共享页（sharing page）: 向生成页或共享页写入数据。

该方法建立两个数组（W，X）。

初始化，将所有页面标记为R/X，可读或可执行。

首先，将packed PE加载进内存，执行。

当写数据进入R/X页面时，**写时页面异常**抛出，该写入指令的起始和终止地址记录进**数组W**，并将该页面标记为W/NX，即可写不可执行。

当W/NX页面中的指令随后被执行时，**执行页面异常**抛出。对于每个执行异常，相应的地址放进**数组X**中。

一个执行页面异常的产生意味着该地址对应的正在执行的指令，是之前被写入的。接着，该页面被重新标记为R/X。将该地址称为`WrittenAndExecuted`。

该标记的进程继续直到packed PE停止执行。

* Tracking the decoding routine

首先将W数组的元素按**时间**排序。

然后通过与数组X中的地址比较检查数组W中的地址是否之后会被执行，即数组W的元素既有写入操作，也有执行操作；如果是，该元素被当做是生成页，并将它们当做脱壳过程的一部分，标记为`U`。

然后，再次遍历经过时间排序的数组W，如果dst地址被标记为U，那么该页面含有src地址就是共享页面，标记它们为U。

当程序执行完毕后，将数组X的所有地址和数组W中的所有src地址按时间排序，其中，在数组X中的最接近最后一个被标记为U的地址的地址，被选择为最佳OEP候选。

* Sorting the OEP candidates

将上一部分的所有OEP候选排序，这里省略了详细的算法由于篇幅不足。

### 1.3 PinDemonium

动态二进制插桩是一种在运行时插入可执行代码来分析二进制程序的行为的方法。

PinDemonium是基于intel DBI-Pin实现的unpacker。

它使用Scylla在`WrittenAndExecuted`时dump内存，依靠启发式方法（熵值分析，长跳转，跳过段和Yara规则）。



### 1.4 PolyUnpack

提供基于行为的方法来自动化从执行解压缩的恶意程序中提取隐藏代码。

执行解压缩的恶意程序有一个混淆机制使得恶意的代码在编译时看起来像数据，然后再运行时将它们转换成可执行的代码。

该方法由静态分析和动态分析组成，首先它对恶意程序进行静态分析从而提取静态代码流图；然后运行恶意程序进行动态分析，若出现了一个新的指令序列（在静态分析中未出现的），PolyUnpack将它当做隐藏的代码并自动提取相应的代码块以便后续的分析。

该方法不需要了解恶意程序使用的unpacking技术，但有一个缺点是它需要大量资源进行静态分析的代码比较。

## 2. OEP的性质及建议方案

### 2.1 OEP的性质

#### (A) OEP之后的系统启动函数调用

通常，用高级程序语言编写的程序在被编译成二进制代码时，特定的编译器系统启动函数被加入。启动函数初始化资源，设置环境等等，为了准备main函数的执行。

对比加壳和原始程序的这些系统函数，发现这两类程序的函数调用是相同的。并且，所有这些函数在OEP之后被立即调用。因此，我们可以追踪这些函数调用来寻找OEP。

尽管它取决于编译器/操作系统，系统启动函数可以粗略分类为以下几类

> 1.获取系统环境值（process ID, current time, OS version）
>
> 2.内存分配和函数指针表的初始化
>
> 3.设置程序类型，屏幕信息或文件句柄
>
> 4.设置环境变量

Table1记录的主要的编译器的系统启动函数.这些数据可以被用来识别编译器和用来寻找 SE handler installation routine。

![Qw0Wmn.png](https://s2.ax1x.com/2019/12/09/Qw0Wmn.png)

#### (B) main函数使用的命令行参数

因为main函数在OEP执行后被调用，我们可以排除所有在main执行之后的OEP候选。为了实现这个想法，我们追踪这些获取main函数的命令行参数的函数，因为系统启动函数的参数对于加壳和原始程序是一样的。

在微软编译器中有两个代表性的获取main函数命令行参数的函数，分别是`__getmainargs()`和`__wgetmainargs()`。它们调用命令行解析并通过传递指针复制参数至main函数。

#### (C) OEP w.r.t. LongJump/JumpOuterSection

OEP是程序执行流更改的目标地址之一，比如分支。我们识别长跳转和跳转至另一个section来寻找OEP。

长跳转是指当前EIP与前一个EIP相差超过0x200。

如下图，例子b,c,d的目标地址都有可能是OEP，其中d的可能性最高，然而对于a还没发现OEP的存在。

![QwDuUx.png](https://s2.ax1x.com/2019/12/09/QwDuUx.png)

#### (D) WrittenAndExecuted

#### (E) Entropy of memory region containing OEP

### 2.2 Proposed scheme



## 3. 实现方式

## 4. 实验结果

