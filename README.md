# Inject-Master

进程注入合集:在Windows环境下的进程注入方法：
CreateRemoteThread、APCInject、SuspendThread、SetWindowHookEX...

	一、远程线程注入：
第一步：打开目标进程(OpneProcess)。
第二步：在目标进程空间为dll得路径内申请空间(VirtualAllocEX)。
第三步：将dll路劲写入目标进程空间内(WriteProcessMemory)。
第四步：创建远程线程(CreateRemoteThread)。从kenerl32中得到loadlibrary的函数地址(GetProcAddress)，将写入目标进程的动态库路径作为参数传入loadlibrary。
第五步：等待远程线程结束(WaitForSingleObejct)，释放内存，关闭句柄。

	二、创建进程挂起：
第一步：创建挂起进程(CreateProcess)将第六参数设置为挂起。
第二步：在进程地址空间中为DLL路径和shellcode申请内存
第三步：得到主线程的上下背景文，根据线程的eip创建shellcode。
第四步：将dll路径和shellcode写入目标进程中。唤醒挂起线程。

	三、反射注入：在dll中实现加载动态库的loadlibrary函数，将自身加载到目标进程中。
第一步：打开dll文件，获取大小。
第二步：在自身程序中申请内存，将dll的数据写入。提升自身权限。
第三步：打开目标进程，将动态库载入。

其中Loadibrary函数是自己实现的：
1、在目标进程地址空间申请空间将dll写入
2、得到dll中实现的加载自身的函数在文件中的地址，创建远程线程，将该函数地址传入。
而在dll中加载自身的函数也实现的很巧妙。

	四、SetWindowHookEX
第一步：首先在动态库中得到导出函数地址，导出函数的作用是弹出messagebox。
第二步：得到目标进程的一个线程ID
第三步：使用setWindowsHookEX函数进行注入。

	五、APCInject
第一步：在目标进程空间内申请内存，将动态库路径写入
第二步：创建快照，遍历目标进程的线程
第三步：打开目标进程的线程 使用QueueUserAPC函数将LoadLiibrary函数作为APC对象加入到线程的APC队列中，并将DLL的路径作为参数传入。
注意释放句柄和内存。

	六、挂起线程注入
  
	七、注册表注入
