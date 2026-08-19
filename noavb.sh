mkdir work
# static 7zz replaces busybox unzip; 7zz exit code 1 = warnings only (archive still fully extracted), tolerate it like unzip did
7zz x -y -bd -owork/ original.zip || [ "$?" -eq 1 ]
mkdir -p boot/zzz
mkdir -p vbmeta/keys
mkdir output
cp main/avbctl/avbctl vbmeta/
chmod +x vbmeta/avbctl
mv work/vbmeta* vbmeta/keys/vbmeta.img
7zz x -y -bd -oboot/zzz/ magisk.apk || [ "$?" -eq 1 ]
mv main/boot_patch.sh boot/
git clone https://github.com/TomKing062/vendor_sprd_proprietories-source_packimage.git
cp -a vendor_sprd_proprietories-source_packimage/sign_image/v2/prebuilt/* work/
cp -a main/config work/config-unisoc
if [ -d extra_key ]; then cp -f extra_key/* work/config-unisoc/; fi
cp vendor_sprd_proprietories-source_packimage/sign_image/v2/sign_image_v2.sh work/
gcc -o work/get-raw-image vendor_sprd_proprietories-source_packimage/sign_image/get-raw-image.c
git clone https://github.com/TomKing062/action_spd_dump_it.git
gcc -o work/gen_tos-noavb action_spd_dump_it/gen_tos-noavb.c
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
# rewrite the generated script to use avbctl instead of "python avbtool"
sed -i "s|^python avbtool |./avbctl |" vbmeta/sign_vbmeta.sh
cp work/config-unisoc/rsa4096_vbmeta.pem vbmeta/
chmod +x vbmeta/*
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

if [ -f "u-boot-spl-16k-sign.bin" ]; then
    ./get-raw-image "u-boot-spl-16k-sign.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv u-boot-spl-16k-sign.bin u-boot-spl-16k.bin
    else
        exit 1
    fi
fi

if [ -f "u-boot-spl-16k-emmc-sign.bin" ]; then
    ./get-raw-image "u-boot-spl-16k-emmc-sign.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv u-boot-spl-16k-emmc-sign.bin u-boot-spl-16k-emmc.bin
    else
        exit 1
    fi
fi

if [ -f "u-boot-spl-16k-ufs-sign.bin" ]; then
    ./get-raw-image "u-boot-spl-16k-ufs-sign.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv u-boot-spl-16k-ufs-sign.bin u-boot-spl-16k-ufs.bin
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
    ./gen_tos-noavb "tos.bin"
    if [ -f "tos-noavb.bin" ]; then
        cp -f "tos-noavb.bin" "tos.bin"
    fi
    ./get-raw-image "tos.bin"
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
        exit 1
    fi
elif [ -f "trustos.bin" ]; then
    ./gen_tos-noavb "trustos.bin"
    if [ -f "tos-noavb.bin" ]; then
        cp -f "tos-noavb.bin" "trustos.bin"
    fi
    ./get-raw-image "trustos.bin"
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        mv "trustos.bin" "tos.bin"
    else
        exit 1
    fi
fi

./get-raw-image "teecfg.bin"
RETVAL=$?
if [ $RETVAL -ne 0 ]; then
    rm teecfg.bin
fi

cd ..

mv work/init_boot* boot/boot.img
RETVAL=$?
if [ $RETVAL -eq 0 ]; then
    cd boot
    ./boot_patch.sh
    cp patched.img ../output/init_boot.img
    cd ..
fi

mv work/boot* boot/boot_real.img
RETVAL=$?
if [ $RETVAL -eq 0 ]; then
    cd boot
    if [ -f output/init_boot.img ]; then
        cp boot_real.img ../output/boot.img
    else
	cp -f boot_real.img boot.img
        ./boot_patch.sh
        cp patched.img ../output/boot.img
    fi
    cd ..
fi


cd vbmeta
./sign_vbmeta.sh
python3 padding.py
cp vbmeta-sign-custom.img ../output/vbmeta.img

cd ../work
./sign_image_v2.sh
cp *-sign.bin ../output/
cd ..
zip -r -v resigned.zip output
