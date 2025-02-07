# Flags
export KEEPVERITY=false
export KEEPFORCEENCRYPT=false
export RECOVERYMODE=true
export PREINITDEVICE=cache

#########
# Unpack
#########

chmod -R 755 .

CHROMEOS=false

echo "Unpacking boot image"
../magiskboot unpack boot.img

case $? in
  0 ) ;;
  1 )
    echo "Unsupported/Unknown image format"
    ;;
  2 )
    echo "ChromeOS boot image detected"
    ;;
  * )
    echo "Unable to unpack boot image"
    ;;
esac

###################
# Ramdisk Restores
###################

# Test patch status and do restore
echo "Checking ramdisk status"
if [ -e ramdisk.cpio ]; then
  ../magiskboot cpio ramdisk.cpio test
  STATUS=$?
else
  # Stock A only legacy SAR, or some Android 13 GKIs
  STATUS=0
fi
case $((STATUS & 3)) in
  0 )  # Stock boot
    echo "Stock boot image detected"
    SHA1=$(../magiskboot sha1 boot.img)
    cp -af ramdisk.cpio ramdisk.cpio.orig 2>/dev/null
    ;;
  1 )  # Magisk patched
    echo "Magisk patched boot image detected"
    # Find SHA1 of stock boot image
    [ -z $SHA1 ] && SHA1=$(../magiskboot cpio ramdisk.cpio sha1)
    ../magiskboot cpio ramdisk.cpio restore
    cp -af ramdisk.cpio ramdisk.cpio.orig 2>/dev/null
    ;;
  2 )  # Unsupported
    echo "Boot image patched by unsupported programs"
    echo "Please restore back to stock boot image"
    ;;
esac

# Work around custom legacy Sony /init -> /(s)bin/init_sony : /init.real setup
INIT=init
if [ $((STATUS & 4)) -ne 0 ]; then
  INIT=init.real
fi

##################
# Ramdisk Patches
##################

echo "- Patching ramdisk"
mkdir cpiotmp
cd cpiotmp
sudo cpio -idv < ../ramdisk.cpio
cd ..
export cpu_abi=$(grep -o 'ro.product.cpu.abi=[^ ]*' cpiotmp/prop.default | cut -d '=' -f 2)
if [ "$cpu_abi" != "arm64-v8a" ]; then
    cpu_abi=armeabi-v7a
fi

echo -n "RANDOMSEED=" > config
tr -dc A-Za-z0-9 </dev/urandom | head -c 8 >> config
echo -ne "\n" >> config
echo "KEEPVERITY=$KEEPVERITY" >> config
echo "KEEPFORCEENCRYPT=$KEEPFORCEENCRYPT" >> config
echo "RECOVERYMODE=$RECOVERYMODE" >> config
echo "PREINITDEVICE=$PREINITDEVICE" >> config
[ ! -z $SHA1 ] && echo "SHA1=$SHA1" >> config

# Compress to save precious ramdisk space
../magiskboot compress=xz zzz/lib/$cpu_abi/libmagisk.so magisk.xz
../magiskboot compress=xz zzz/assets/stub.apk stub.xz
../magiskboot compress=xz zzz/lib/$cpu_abi/libinit-ld.so init-ld.xz

../magiskboot cpio ramdisk.cpio \
"add 0750 $INIT zzz/lib/$cpu_abi/libmagiskinit.so" \
"mkdir 0750 overlay.d" \
"mkdir 0750 overlay.d/sbin" \
"add 0644 overlay.d/sbin/magisk.xz magisk.xz" \
"add 0644 overlay.d/sbin/stub.xz stub.xz" \
"add 0644 overlay.d/sbin/init-ld.xz init-ld.xz" \
"patch" \
"backup ramdisk.cpio.orig" \
"mkdir 000 .backup" \
"add 000 .backup/.magisk config"

#################
# Binary Patches
#################

for dt in dtb kernel_dtb extra; do
  if [ -f $dt ]; then
    if ! ../magiskboot dtb $dt test; then
      echo "! Boot image $dt was patched by old (unsupported) Magisk"
      echo "! Please try again with *unpatched* boot image"
    fi
    if ../magiskboot dtb $dt patch; then
      echo "- Patch fstab in boot image $dt"
    fi
  fi
done

if [ -f kernel ]; then
  PATCHEDKERNEL=false
  # Remove Samsung RKP
  ../magiskboot hexpatch kernel \
  49010054011440B93FA00F71E9000054010840B93FA00F7189000054001840B91FA00F7188010054 \
  A1020054011440B93FA00F7140020054010840B93FA00F71E0010054001840B91FA00F7181010054 \
  && PATCHEDKERNEL=true

  # Remove Samsung defex
  # Before: [mov w2, #-221]   (-__NR_execve)
  # After:  [mov w2, #-32768]
  ../magiskboot hexpatch kernel 821B8012 E2FF8F12 && PATCHEDKERNEL=true

  # Disable Samsung PROCA
  # proca_config -> proca_magisk
  ../magiskboot hexpatch kernel \
  70726F63615F636F6E66696700 \
  70726F63615F6D616769736B00 \
  && PATCHEDKERNEL=true

  # Force kernel to load rootfs for legacy SAR devices
  # skip_initramfs -> want_initramfs
  ../magiskboot hexpatch kernel \
  736B69705F696E697472616D667300 \
  77616E745F696E697472616D667300 \
  && PATCHEDKERNEL=true

  # If the kernel doesn't need to be patched at all,
  # keep raw kernel to avoid bootloops on some weird devices
  $PATCHEDKERNEL || rm -f kernel
fi

#################
# Repack & Flash
#################

echo "- Repacking boot image"
../magiskboot repack boot.img patched.img || echo "! Unable to repack boot image"

