# 读论文笔记 - The_Study_of_Evasion_of_Packed_PE_from_Static_Detection

> [论文地址](https://www.researchgate.net/publication/259647266_The_Study_of_Evasion_of_Packed_PE_from_Static_Detection)

### packed PE的特征
* Non-standard section name
* At least one section that has read, write and execute permissions.
   因为包含unpack功能的段要unpack压缩过的PE文件，故需要可执行，可读权限；而大部分packers需要更新及解密自身，因此还需要可写权限。



### 检测packed PE的标准

#### 1) Import Address Table（IAT）

IAT存储了所有外部函数（PE文件通过加载DLL导入的windows api）的地址。

packers通过**压缩IAT**导致有意义的import function call数量很少。

基于此（**IAT的有意义的导入函数数量**），可以检测是否是**packed PE**。

#### 2）Section Access Rights（段访问权限）

| Section Name | Access Rights    |
| ------------ | ---------------- |
| .text        | Read and Execute |
| .rdata       | Read-Only        |
| .data        | Read and Write   |
| .bss         | Read and Write   |
| .rsrc        | Read-Only        |
| .reloc       | Read-Onlys       |

正常的PE文件**只有一个**段有`读和执行`权限；

packed PE有**至少一个**段有`读，写和执行`权限。

packed PE可执行 - 段权限包含可写是可执行的基本要素。

#### 3）Entropy Value（熵值）

![QJ37Ks.png](https://s2.ax1x.com/2019/12/06/QJ37Ks.png)

n为256，p(i)为16进制数为i的出现概率。

packed PE熵值在`7.07-7.99`之间。

benign PE熵值在`3.60-6.65`之间。

我自己测试了一个文件，原始文件的熵值为`3.89860507141`，加UPX壳后熵值为`7.10302138528`。

#### 4）Section Characteristics（段特点）

PE文件有一套文件格式的基准，如下。

| section | function                                                     |
| ------- | ------------------------------------------------------------ |
| .bss    | holds uninitialized data                                     |
| .data   | hold initialized data                                        |
| .debug  | holds information for symbolic debugging                     |
| .text   | holds the ‘‘text’’ or executable instructions                |
| .rsrc   | contains all the resources for the module                    |
| .reloc  | holds a table of base relocations                            |
| .idata  | contains information about functions that the module imports from other DLLs (dynamic link libraries) |
| .rdata  | holds the debug directory and the description string         |

依靠packed PE的非标准的section name可以 检测加壳。

#### 5）Address of Original Entry Point (OEP，程序入口点地址) 

正常的PE文件中，EP的地址通常指向.text或.data段，或者在PE header中。
对于packed PE，EP的地址取决于packer的类型，但通常将原始的PE放在.text段。
为了隐藏恶意意图，恶意程序的作者修改EP到非代码段，再让EP指向.text段之外，并标记为code。

#### 6）Header Overlapping（文件头重叠）

PE可能存在PE/COFF header offset与预先存在于文件开始的MS DOS stub重叠的情况。
而**编译器**通常不会产生这种情况，故这种情况的出现很可能表明文件被packed。
检测器有`Mandiant Red Curtain`。

### 绕过上述检测标准的方法

#### 1) Import Address Table（IAT）

**增加导入函数调用的数量**，通过增加无用的函数（对于加壳和脱壳来说），但能够丰富IAT从而逃避检测。

工具为`Stud_PE`，在IAT中增加一个动态链接库（User32.dll）。

#### 2）Section Access Rights（段访问权限）

方法一：将三种权限（read, write, executable）分离，如下图。

段A只有读和写权限，段B只有读和执行权限，段C只有写权限。

执行程序时，段A和段B都运行起来，建立读写和可执行权限给段C，这样段C就可以进行解压操作并运行了。

这啥意思啊。。。

![QJRYMd.png](https://s2.ax1x.com/2019/12/06/QJRYMd.png)

方法二：在table header上设置 **PAGE_NO_ACCESS**，即不可访问权限。这样检测程序无法读取这个table header，从而绕过检测。

#### 3）Entropy Value（熵值）

对packed PE进行再次编码，减小熵值。

* truncated binary algorithm 

* Run-length encoding（游程编码）
* Normalized Shannon entropy（香农归一化）
* Minimum Entropy Deconvolution (MED)

#### 4）Section Characteristics（段特点）

一些packers采用空的section name或者重复的section name在不同的section上。

通过**重命名**section name，工具也是`Stud_PE`。

比如upx壳的`UPX0->.text`等等。

#### 5）Address of Original Entry Point (OEP，程序入口点地址) 

这里有两个关键的点需要知道。

* If Windows API functions are found, which are not usually called by packers (such as CreateWindowA) then searching for the OEP should be stopped and the executable can be marked as benign.
* The entry point should point into the .text or .data sections, and must be within the standards as described by Microsoft.

基于此，我们可以使用一些packers不经常使用的windows api，并确保EP位于`.text`或`.data`段中。

#### 6）Header Overlapping（文件头重叠）

Microsoft避免使用不重叠的内存地址，以确保与PE相关联的进程的高性能。

打包的PE不遵循Microsoft建议的这些规格，因此打包的PE中存在异常。

标头重叠用于隐藏打包的PE中的恶意内容，但可以检测到，例如由Mandiant的Red Curtain和其他工具制作。

故避免header overlapping即可（说了跟没说一样）。

### 总结

检测packed PE的标准是**存在缺陷**的，不能完全依赖这些标准来判断PE文件是否packed。

