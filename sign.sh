mkdir work
busybox unzip -oq original.zip -d work
mkdir -p boot/zzz
mkdir -p vbmeta/keys
mkdir output
tar xzvf avbtool.tgz -C vbmeta/
mv work/boot* boot/boot.img
mv work/vbmeta* vbmeta/keys/vbmeta.img
busybox unzip -oq magisk.apk -d boot/zzz
mv main/boot_patch_9.sh boot/
mv main/boot_patch_10.sh boot/
mv main/sign_avb.sh vbmeta/
git clone https://github.com/TomKing062/vendor_sprd_proprietories-source_packimage.git
cp -a vendor_sprd_proprietories-source_packimage/sign_image/v2/prebuilt/* work/
cp -a vendor_sprd_proprietories-source_packimage/sign_image/config-unisoc work/
cp vendor_sprd_proprietories-source_packimage/sign_image/v2/sign_image_v2.sh work/
gcc -o work/get-raw-image vendor_sprd_proprietories-source_packimage/sign_image/get-raw-image.c
chmod +x work/*
cd vendor_sprd_proprietories-source_packimage/sign_vbmeta
make
chmod +x generate_sign_script_for_vbmeta
cp generate_sign_script_for_vbmeta ../../vbmeta/keys/
cd ../../vbmeta/keys/
./generate_sign_script_for_vbmeta vbmeta.img
mv sign_vbmeta.sh ../
mv padding.py ../
cd ../..
cp work/config-unisoc/rsa4096_boot.pem vbmeta/
cp -f work/config-unisoc/rsa4096_boot_pub.bin vbmeta/keys/
cp work/config-unisoc/rsa4096_vbmeta.pem vbmeta/
chmod +x vbmeta/*
sudo rm -rf /usr/bin/python
sudo ln -s /usr/bin/python2 /usr/bin/python
cd work

if [ -f "splloader.bin" ]; then
    ./get-raw-image "splloader.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv splloader.bin u-boot-spl-16k.bin
    else
        exit 1
    fi
fi

if [ -f "uboot.bin" ]; then
    ./get-raw-image "uboot.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv uboot.bin u-boot.bin
    else
        exit 1
    fi
fi

if [ -f "sml.bin" ]; then
    ./get-raw-image "sml.bin"
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
        exit 1
    fi
fi

if [ -f "tos.bin" ]; then
    ./get-raw-image "tos.bin"
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
        exit 1
    fi
elif [ -f "trustos.bin" ]; then
    ./get-raw-image "trustos.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv "trustos.bin" "tos.bin"
    else
        exit 1
    fi
fi

if [ ! -f "teecfg.bin" ]; then
    cd ../boot
    ./boot_patch_9.sh
else
    ./get-raw-image "teecfg.bin"
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
        rm teecfg.bin
        cd ../boot
        ./boot_patch_9.sh
    else
        cd ../boot
        ./boot_patch_10.sh
    fi
fi

cd ../vbmeta
./sign_avb.sh boot ../boot/boot.img ../boot/patched.img
cp ../boot/patched.img ../output/boot.img
cd ..

mkdir recovery
mv work/recovery* recovery/recovery.img
RETVAL=$?
if [ $RETVAL -eq 0 ]; then
    cp work/config-unisoc/rsa4096_recovery.pem vbmeta/
    cp -f work/config-unisoc/rsa4096_recovery_pub.bin vbmeta/keys/
    cd vbmeta
    ./sign_avb.sh recovery ../recovery/recovery.img ../recovery/recovery.img
    cp ../recovery/recovery.img ../output/recovery.img
    cd ..
fi

cd vbmeta
./sign_vbmeta.sh
python padding.py
cp vbmeta-sign-custom.img ../output/vbmeta.img

cd ../work
./sign_image_v2.sh
cp *-sign.bin ../output/
cd ..
zip -r -v resigned.zip output
