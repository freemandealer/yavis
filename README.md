# YAVIS #

## 简介 ##
YAVIS是一款虚拟以太网卡，可以为中国科学院计算技术研究所高性能中心设计的FCC融合控制器增加TCP/IP支持。项目处于试验阶段。

## 编译和测试 ##

1. 获得最新的chpp-stack，并切换到dev分支:

	git clone git@10.18.129.91:/srv/chpp-stack
	cd chpp-stack
	git checkout dev

2. 获得最新的yavis。在chpp-stack目录下执行：

	git clone https://github.com/freemandealer/yavis.git

3. 为chpp-stack打补丁，补丁文件在bcl-patch目录中：

	git apply 0001-Fix-kernel_test-undefined-problem.patch #可选，用来修复bcl6/kernel_test的编译问题
	git apply 0001-Peek-send-recv-buffer-in-kernel_test.patch　#可选，用来查看bcl6/kernel_test收发的数据
	git apply 0002-Break-the-8-bytes-rule-in-BCL.patch　#要使用yavis必选，使bcl能收发任意数量的数据
	git apply 0001-Fix-bcl6-include-const.h #要使用yavis必选，修复bcl发送大量数据时锁住

4. 切换yavis的分支。yavis目前有两个分支：

	- hrtimer: 使用高精度定时器
	- master: 使用NAPI

5. 修改yavis的Makefile的`KDIR`值，并修改yavis的Kbuild文件的Include目录：

	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/bcl6/bcl/include
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/bcl6/include
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/hpp_driver/include
	EXTRA_CFLAGS += -I/home/freeman/project/graduating-thesis/phpc-lab/chpp-stack-git/bcl6/drivers
将上面部分修改为对应的真实目录。

6. 加载hppdriver:

	cd chpp-stack/hpp_driver/
	sudo ./load

7. 加载bcl:
	sudo insmod chpp-stack/bcl6/drivers/kbuild/bcl.ko
	sudo cat bcl6/drivers/kbuild/Module.symvers >> yavis/Module.symvers

8. 编译加载yavis:

	cd chpp-stack/yavis/
	make
	sudo insmod yavis.ko hwid=<这里填cpuid>

9. 打开yavis设备接口：

	sudo ifconfig sn0 <IP地址，最后一个域必须为(cpuid+1)>

10. 测试：

	在两台机器上执行上述操作，设定合适的hwid和ip，便可以实现互ping

-------------------------------------
作者：张正宇 <zhangzhengyu@ncic.ac.cn>

