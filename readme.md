## resign

This method works with both unlocked and locked BL, but wiping userdata might be still needed. (vmbeta change will affect data encryption)

|                                               | android 9                                                    | android 10(+)                                                |
| --------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| ums312/ums512/ud710 (not-fused or public key) | splloader+uboot+sml+trustos+vbmeta+boot+(recovery)           | splloader+uboot+sml+trustos+teecfg+vbmeta+boot+(recovery)    |
| ums312/ums512/ud710 (fused)                   | uboot+sml+trustos+vbmeta+boot+(recovery)<br />see note for splloader information | uboot+sml+trustos+teecfg+vbmeta+boot+(recovery)<br />see note for splloader information |
| other cpu (not-fused or public key)           | splloader+uboot+sml+trustos+vbmeta+boot+(recovery)           | splloader+uboot+sml+trustos+teecfg+vbmeta+boot+(recovery)    |
| other cpu (fused)                             | UNSUPPORTED                                                  | UNSUPPORTED                                                  |

Note for ums312/ums512/ud710 (fused)：

​	on android 9/10, you need IDA to get patched splloader ([guide](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/wiki/patch_do_cboot%E2%80%90SPL#old-type)), then process with [CVE-2022-38691](https://github.com/TomKing062/CVE-2022-38691_38692)

​	on android 11(+), you can use gen_spl-unlock ([source_code](https://raw.githubusercontent.com/TomKing062/CVE-2022-38694_unlock_bootloader/info/gen_spl-unlock.c)|[windows_prebuilt](https://github.com/TomKing062/spreadtrum_flash/releases/latest)) to get patched splloader, then process with [CVE-2022-38691](https://github.com/TomKing062/CVE-2022-38691_38692)
