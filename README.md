# 在Windows环境下的进程注入方法

## 一、关于进程注入  
进程注入简而言之就是将代码注入到正在运行的进程内存空间中，进程注入也是PC端软件开发必须掌握的一个基础知识点。

Windows为每个进程分配了4G内存空间，在这4G空间中的代码可以被这个进程访问执行。 
给软件“打补丁”实际上就是进程注入，想给已经上线的软件添加一个小功能，不需要重新设计软件，只需要将你需要添加功能的代码注入到进程中即可。  
也有很多黑客利用进程注入将恶意代码注入到目标进程中进行攻击。  
  
Windows环境下常用的进程注入方法有：CreateRemoteThread、APCInject、SuspendThread、SetWindowHookEX等。    
此外还学过一种比较奇特的注入方法：反射注入。反射注入主要是通过对PE文件的操作实现注入，注入成功率高，也最有学习价值。  

## 二、几种进程注入方法的原理  

### 1.远程线程注入
* 打开目标进程(` OpneProcess`)。  
* 在目标进程空间为dll得路径内申请空间(`VirtualAllocEX`)。    
* 将dll路劲写入目标进程空间内(`WriteProcessMemory`)。  
* 创建远程线程(`CreateRemoteThread`)。从kenerl32中得到loadlibrary的函数地址(`GetProcAddress`)，将写入目标进程的动态库路径作为参数传入loadlibrary。  
* 等待远程线程结束(`WaitForSingleObejct`)，释放内存，关闭句柄。

### 2.创建进程挂起  
* 创建挂起进程(`CreateProcess`)将第六参数设置为挂起。
* 在进程地址空间中为DLL路径和shellcode申请内存
* 得到主线程的上下背景文，根据线程的eip创建shellcode。
* 将dll路径和shellcode写入目标进程中。唤醒挂起线程。

### 3.APCInject  
* 在目标进程空间内申请内存，将动态库路径写入
* 创建快照，遍历目标进程的线程
* 打开目标进程的线程 使用`QueueUserAPC`函数将`LoadLibrary`函数作为APC对象加入到线程的APC队列中，并将DLL的路径作为参数传入。注意释放句柄和内存。

### 4.反射注入
整体思路是在dll中实现加载动态库的`loadlibrary`函数，将自身加载到目标进程中。  

* 打开dll文件，获取大小。
* 在自身程序中申请内存，将dll的数据写入。提升自身权限。
* 打开目标进程，将动态库载入。   
  
其中`Loadibrary`函数是通过修改PE文件实现的：    
1、在目标进程地址空间申请空间将dll写入。    
2、得到dll中实现的加载自身的函数在文件中的地址，创建远程线程，将该函数地址传入。而在dll中加载自身的函数也实现的很巧妙。

### 5.SetWindowHookEX  
* 首先在动态库中得到导出函数地址，导出函数的作用是弹出messagebox。
* 得到目标进程的一个线程ID
* 使用`setWindowsHookEX`函数进行注入。

### 6.挂起线程注入
  
### 7.注册表注入  

## 三、开发环境

Windows操作系统、VS2015。  
在32位windows系统和64位windows系统中均测试通过，进行测试时请修改源代码中的目标进程以及Dll路径。

## 四、项目目录

```
.
|-- APCInject(Ring0)                 // 驱动层的APC注入
|-- APCInject                        // Ring3层的APC注入
|-- CreateSuspend                    // 挂起线程注入
|-- InjectByRegister                 // 注册表注入（未测试）
|-- ReflectDll                       // 反射注入的Dll
|-- ReflectiveInject                 // 反射注入
|-- RemoteThread                     // 远程线程注入
|-- Src                              // 驱动层的APC注入源码
|-- Dll.dll                          // 32位测试Dll
|-- Dll64.dll                        // 64位测试Dll
|-- Process-Inject.sln               // 项目启动文件
|-- README.md                        // 项目说明文件
.
```

## 五、其他
欢迎Pull Request，欢迎提Issue。

## License
在对本作品进行演绎时，请署名并以相同方式共享。
