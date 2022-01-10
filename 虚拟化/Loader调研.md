# Loader调研

## 思路

- 存在的问题：
  - Windows加载程序的版本之间存在差异，没有一个版本可以加载其他版本可以加载的所有程序。大多数动态恶意软件分析管道只运行一个Windows版本的样本，这通常是过时的，与最终用户选择的[44]不同。
  - 操作系统加载程序、反向工程工具和防病毒软件，在解释输入文件的方式上通常没有什么差异。攻击者可以利用这些差异逃避检测或使逆向工程复杂化，研究人员通常通过手动、反复试验的过程发现这些差异。
  - 文件类型的判断 ppt pdf 
    - 如果av判断是一个ppt但其实是pdf，接着它用ppt的签名进行校验，wrong。
  - pdf：Adobe Reader作为windows系统，
  
- 找不足

  - 添加PE+模型，win8 11
  - 模型的生成：自动化，源代码->约束
    - angr 对ntoskrnl.exe的校验PE函数，生成cfg，
  - 约束解的有效性
  - Verify一个PE文件是否合法：
    - MiCreateImageFileMap API：调用CreateFileMapping API可以静态完成校验；
    - LdrpInitializeProcess API

- 产出：

  - 若干验证pe有效性的模型，对于不同的系统及软件；
    - Windows系统
    - 调试器ollydbg等
    - 杀软
  - 生成绕过软件而对系统有效的pe；
  - 一个自动化的系统，不止生成pe头，修改现有的pe，绕过特定目标。
  - 过滤无效PE文件

- 对比

  |                          | Loader      | 本文         |
  | ------------------------ | ----------- | ------------ |
  | 支持的可执行文件         | PE, ELF     | [+] PE+      |
  | 系统模型                 | Win xp,7,10 | [+] Win 8,11 |
  | 自动化分析PE，修改PE头   | 否          | 是           |
  | 优化求解约束（时间对比） |             |              |
  | 模型欠约束               | yes         | no           |
  |                          |             |              |
  

## Loader Modeling

### 模型语言

语言支持通过解析c语言的头文件导入类型。

### 测试

1. ./generate.py -A models/windows/10/MiCreateImageFileMap.lmod -N models/windows/10/LdrpInitializeProcess.lmod

   ```
   ❯ python3 verify.py models/windows/10/MiCreateImageFileMap.lmod ./testcase -l INFO
   2021-12-28 22:36:56 ubuntu __main__[37996] INFO PASS
   ```

   通过模型测试，但是win10的MiCreateImageFileMap函数返回错误，原因如下

   `line 183: pNt->FileHeader.SizeOfOptionalHeader % 8 == 0【被遗漏】`

   ![image-20211229151612034](http://gavinl1b0223342.oss-cn-beijing.aliyuncs.com/img/image-20211229151612034.png)

   

   添加如下约束后，生成的例子可以通过MiCreateImageFileMap。
   
   ```
   ### New
   V60: Eq (BITAND progHdr.SizeOfOptionalHeader 0x7) 0 term
   ```
   
   

## Windows 10.19041

> windbg lm m nt 查看nt符号表位置
>
> IDA File->Load File加载pdb符号表

CreateProces

KERNEL32!CreateProcessW

KERNELBASE!CreateProcessW

KERNELBASE!CreateProcessInternalW

0000000180008E6C NtCreateUserProcess

ntdll!NtCreateUserProcess

```
u ntdll!NtCreateUserProcess
ntdll!NtCreateUserProcess:
00007ffc`2256e650 4c8bd1          mov     r10,rcx
00007ffc`2256e653 b8c8000000      mov     eax,0C8h
00007ffc`2256e658 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffc`2256e660 7503            jne     ntdll!NtCreateUserProcess+0x15 (00007ffc`2256e665)
00007ffc`2256e662 0f05            syscall
00007ffc`2256e664 c3              ret
00007ffc`2256e665 cd2e            int     2Eh
00007ffc`2256e667 c3              ret
```

syscall 0xC8 ==> nt!NtCreateUserProcess 未导出，根据与ZwCreateProcessEx之间的偏移定位；

IoCreateFileEx

```python
# find ZwCreateSection
from idaapi import *
import idautils
from idc import *

# ZwCS
addr = []
temp = [0x1403F40D0]
flag = 0

while 1:

    addr = temp
    temp = []
    
    for i in range(len(addr)):
        
        xrefs = list(idautils.XrefsTo(addr[i]))
        for xref in xrefs:
            func = idc.GetFunctionAttr(xref.frm, FUNCATTR_START)
            if func == 0x1406149A0:
                flag = 1
                print("find!")
            print(hex(addr[i]), hex(func))
            
            temp.append(func)
    if flag:
        break
```

ZwCreateSection->NtCreateSection->MiCreateSectionCommon

### MiCreateImageFileMap

- line 260: DosHeader.e_magic == 'MZ'
- line 264: DosHeader.e_lfanew(AddressOfNewExeHeader, NtHeaderOffset) < 

#### MiVerifyImageHeader

- line28：Addr(NtHeader) % 4 == 0
- line33：NtHeader[0:2] == 'PE'
- line35：NtHeader[4:6] (Machine) != 0 && NtHeader[20:22] (SizeOfOptionalHeader) != 0
- line40：NtHeader[22] (Characteristics) & 2 != 0 第二个bit为1，即IMAGE_FILE_EXECUTABLE_IAMGE
- line50：NtHeader[24:26] == 0x20b ? x64 : x86 【OptionalHeader.Magic, 0x20B代表PE64，0x10B代表PE32】
  - A：对pOutInfo赋值
    - line68: NtHeader[132:136] 【NumberOfRvaAndSizes，DataDirectory元素的个数】
    - line113：NtHeader[0x58:] NtHeader[0x50:]【CheckSum和SizeOfImage】
    - line116: (pNt->OptionalHeader.Magic - 0x10b) & 0xFEFF != 0
    - line 123: (pNt->OptionalHeader.FileAlignment & 0x1FF == 0) || pNt->OptionalHeader.FileAlignment == pNt->OptionalHeader.SectionAlignment)
    - line128: pNt->OptionalHeader.FileAlignment != 0
    - line134&139: pNt->OptionalHeader.FileAlignment pNt->OptionalHeader.SectionAlignment是2的倍数
    - line144: pNt->OptionalHeader.SectionAlignment >= pNt->OptionalHeader.FileAlignment
    - line150: pNt->OptionalHeader.SizeOfImage <= 0x77000000
    - line 155&158: pNt->OptionalHeader.Magic == 0x10B && (pNt->FileHeader.Machine == 0x14C(I386) || pNt->FileHeader.Machine == 0x1C4(ARMNT))
    - line 164&167: pNt->OptionalHeader.Magic == 0x20B && (pNt->FileHeader.Machine == 0x8664(AMD64) || pNt->FileHeader.Machine == 0xAA64(ARM64))
    - line 173: pNt->OptionalHeader.SizeOfHeader < SizeOfImage
    - line 178: pNt->OptionalHeader.ImageBase&0xffff == 0
    - line 183: pNt->FileHeader.SizeOfOptionalHeader % 8 == 0【被遗漏】
    - line 190: 
      - A: pNt->FileHeader.Machine == 0x8664(AMD64) || pNt->FileHeader.Machine == 0x14C(I386)
      - B: pNt->FileHeader.Machine != 0x8664(AMD64) && pNt->FileHeader.Machine != 0x14C(I386) && pNt->FileHeaer.Characteristics[0] == 0 && pNt->OptionalHeader.DllCharacteristics & 0x140 == 0x140(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040 IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100)
    - line 205: pNt->OptionalHeader.DllCharacteristics & 0x1000 (IMAGE_DLLCHARACTERISTICS_APPCONTAINER) == 0 || pNt->FileHeaer.Characteristics[0] (IMAGE_FILE_RELOCS_STRIPPED) == 0 表示存在重定位信息                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
  - B: 

## Status Code in Ntoskrnl.exe

> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

| Code                                 | Value          | Description                                                  |
| ------------------------------------ | -------------- | ------------------------------------------------------------ |
| STATUS_INVALID_FILE_FOR_SECTION      | 0xC0000020     | {Bad File} The attributes of the specified mapping file for a section of memory cannot be read. |
| STATUS_FILE_LOCK_CONFLICT            | 0xC0000054     | A requested read/write cannot be granted due to a conflicting file lock. |
| **STATUS_INVALID_IMAGE_FORMAT**      | **0xC000007B** | {Bad Image} hs is either not designed to run on Windows or it contains an error. Try installing the program again using the original installation media or contact your system administrator or the software vendor for support. Error status 0x |
| STATUS_INSUFFICIENT_RESOURCES        | 0xC000009A     | Insufficient system resources exist to complete the API.     |
| STATUS_COMMITMENT_LIMIT              | 0xC000012D     | {Out of Virtual Memory} Your system is low on virtual memory. To ensure that Windows runs properly, increase the size of your virtual memory paging file. For more information, see Help. |
| STATUS_INVALID_IMAGE_NOT_MZ          | 0xC000012F     | The specified image file did not have the correct format, it did not have an initial MZ. |
| STATUS_INVALID_IMAGE_PROTECT         | 0xC0000130     | The specified image file did not have the correct format, it did not have a proper e_lfarlc in the MZ header. |
| STATUS_ENCOUNTERED_WRITE_IN_PROGRESS | 0xC0000433     | The attempted write operation encountered a write already in progress for some portion of the range. |



## 杀软

### ClamAV

https://github.com/Cisco-Talos/clamav/

#### 测试

```
clamscan --scan-pe --debug ../createprocessLM.exe
```

#### pdf

cli_scanpdf->cli_pdf

### MoonAV

https://sourceforge.net/projects/moonav/

### ClamWin

https://clamwin.com/content/view/18/46/

## 添加pe节

### 添加头大小



大于0x1000时，修改optionalheader.dataentry每个 ，加0x10000

fileheader.sizeofimage

optionalheader.sizeofheaders

sectionheader.pointretorawdata

importdescriptor每个的chunk，对应的api地址+0x1000

失败，原因是修改导入表地址后，在text节的代码跳转的地址就不对了。。。

## 参考资料

- [原创]64位Windows创建64位进程逆向分析（总目录）：https://bbs.pediy.com/thread-207430.htm
- [原创]64位CreateProcess逆向:(三)PE格式的解析与效验: https://bbs.pediy.com/thread-208101.htm
- Processes, Threads, and Jobs in the Windows Operating System：https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=3

