#!/bin/bash

#script adapted from anarkia's build script
#thanks for anarkia

# Add Colors
green='\033[01;32m'
red='\033[01;31m'
blink_red='\033[05;31m'
restore='\033[0m'

clear

export CROSS_COMPILE=~/android/toolchain/arm-cortex_a8-linux-gnueabi-linaro_4.8.2-2013.10/bin/arm-cortex_a8-linux-gnueabi-
export ARCH=arm

DATE_START=$(date +"%s")


# clean up last build
echo "cleaning up your working area"
make clean


echo
echo -e "${green}"
echo "start building"
echo -e "${restore}"
echo

MODULES_DIR=${HOME}/android/kernel/pac4.3.1/ramdisk/lib/modules
RAMDISK_DIR=${HOME}/android/kernel/pac4.3.1/ramdisk
KERNEL_DIR=`pwd`
OUTPUT_DIR=${HOME}/android/kernel/pac4.3.1/build
ZIMAGE_DIR=${HOME}/android/arco-kernel/samsung-kernel-msm7x30/arch/arm/boot
ANYKERNEL_DIR=${HOME}/android/kernel/pac4.3.1

echo "CROSS_COMPILE="$CROSS_COMPILE
echo "ARCH="$ARCH
echo "MODULES_DIR="$MODULES_DIR
echo "KERNEL_DIR="$KERNEL_DIR
echo "OUTPUT_DIR="$OUTPUT_DIR
echo "ZIMAGE_DIR="$ZIMAGE_DIR
echo "ANYKERNEL_DIR="$ANYKERNEL_DIR

echo -e "${green}"
echo "-------------------------"
echo "compiling"
echo "-------------------------"
echo -e "${restore}"

make -j25

echo -e "${green}"
echo "-------------------------"
echo "Create: Kernel and Zip"
echo "-------------------------"
echo -e "${restore}"


echo -e "${green}"
echo "moving your module files"
find $KERNEL_DIR -name '*.ko' -exec cp -v {} $MODULES_DIR \;

echo "making ramdisk"
cd $RAMDISK_DIR
find . | cpio -o -H newc | gzip > ../newramdisk.cpio.gz

cp -vr $ZIMAGE_DIR/zImage $ANYKERNEL_DIR
echo
echo -e "${restore}"


echo "creating boot.img"
cd $ANYKERNEL_DIR
mkbootimg --kernel zImage --ramdisk newramdisk.cpio.gz --base 0x00400000 -o boot.img

cp -vr $ANYKERNEL_DIR/boot.img $OUTPUT_DIR

cd $KERNEL_DIR
echo

echo -e "${green}"
echo "-------------------------"
echo "Build Completed in:"
echo "your boot.img is in $ANYKERNEL_DIR"
echo "-------------------------"
echo -e "${restore}"

DATE_END=$(date +"%s")
DIFF=$(($DATE_END - $DATE_START))
echo "Time: $(($DIFF / 60)) minute(s) and $(($DIFF % 60)) seconds."
echo
