#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${DIR}
sudo make clean > ./log.txt
sudo make > ./log.txt
sudo rmmod skb_hook > ./log.txt
sudo insmod ./skb_hook.ko
sudo dmesg -c > ./skb_hook.txt
sudo dmesg -C
