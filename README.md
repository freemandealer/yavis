# YAVIS #

## 简介 ##
YAVIS是一款虚拟以太网卡，可以为中国科学院计算技术研究所高性能中心设计的FCC融合控制器增加TCP/IP支持。项目处于试验阶段。

## 编译和测试 ##

Step1. 获得最新的chpp-stack，并切换到dev分支。


```
	git clone git@10.18.129.91:/srv/chpp-stack
	cd chpp-stack
	git checkout dev
```

Step2. 修改make.x86相关工作目录为真实chpp目录。修改bcl6/driver/hppnet_main.c中的src_cpu为机器节点号。

Step3. 获得最新的yavis。在chpp-stack目录下执行：

```
	git clone https://github.com/freemandealer/yavis.git
```

Step4. 切换yavis到hrtimer分支。yavis目前有两个分支：

	- hrtimer: 使用高精度定时器
	- master: 使用NAPI[暂未更新]

Step5. 修改yavis的Makefile的`KDIR`值，并修改yavis的Kbuild文件的Include目录：

```
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/bcl6/bcl/include
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/bcl6/include
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/hpp_driver/include
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/bcl6/drivers
```

将上面部分修改为对应的真实目录。


Step6. 为chpp-stack打补丁，补丁文件在yavis的bcl-patch目录中：

```
	git apply 0001-Fix-kernel_test-undefined-problem.patch #可选，用来修复bcl6/kernel_test的编译问题
	git apply 0001-Peek-send-recv-buffer-in-kernel_test.patch　#可选，用来查看bcl6/kernel_test收发的数据
	git apply 0002-Break-the-8-bytes-rule-in-BCL.patch　#要使用yavis必选，使bcl能收发任意数量的数据
	git apply 0001-Fix-bcl6-include-const.h #要使用yavis必选，修复bcl发送大量数据时锁住
```

Step7. 接着重新编译bcl和hpp驱动：

	cd chpp-stack/bcl6
	sudo make clean
	./Bootstrap
	./make.x86
	./go
	cd ../hpp_driver/
	sudo make clean
	make

Step8. 加载hpp driver和bcl:

```
	cd chpp-stack/hpp_driver/
	sudo ./load
	sudo /etc/init.d/bcl start
	sudo cat bcl6/drivers/kbuild/Module.symvers >> yavis/Module.symvers
```

Step9. 编译加载yavis:

```
	cd chpp-stack/yavis/
	make
	sudo insmod yavis.ko hwid=<这里填cpuid> poll_delay_ns=<填延迟时间ns，如100>
```

Step10. 打开yavis设备接口：

```
	sudo ifconfig sn0 <IP地址，最后一个域必须为(cpuid+1)>
```

Step11. 测试：

	在两台机器上执行上述操作，设定合适的hwid和ip，便可以实现互ping

说明：以上为第一次执行的操作清单。以后进行修改测试时：

1）若修改yavis代码，只需在修改完代码后重复最后四步。

2）如果修改了chpp-stack代码，需要重复执行最后五步。

-------------------------------------
作者：张正宇 <zhangzhengyu@ncic.ac.cn>

