obj-m += skb_hook.o  
 
#generate the path  
CURRENT_PATH:=$(shell pwd)
 
#the current kernel version number  
LINUX_KERNEL:=$(shell uname -r) 
 
#the absolute path--根据获取的内核版本拼装绝对路径
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)  
 
#complie object  
all:  
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules
#clean  
clean:  
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean  