sudo insmod yavis.ko
sudo cat /sys/module/yavis/sections/.text
sudo chmod 222 /proc/sysrq-trigger
sudo echo g > /proc/sysrq-trigger
