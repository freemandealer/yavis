cp Makefile chpp-stack/yavis/
cp Kbuild chpp-stack/yavis/
cd chpp-stack/hpp_driver/
sudo ./load
cd ..
sudo insmod bcl6/drivers/kbuild/bcl.ko
cat bcl6/drivers/kbuild/Module.symvers >> yavis/Module.symvers
cd yavis/
make
sudo insmod yavis.ko

