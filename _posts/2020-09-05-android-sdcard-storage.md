---
layout: post
title: "android sdcard 存储"
categories: [android,sdcard]
---

# 概述

从android 10及android 11，android强化的对外部存储访问的限制，修补了系统相比ios一直存在的隐私泄漏的隐患。
ios一步到位，系统存储一开始完全采用了沙盒机制，android兜兜转转终于也走回了存储完全沙盒化的路上，兼容成本巨大。

在ios和android刚问世的时代，存储芯片价格极其昂贵，iPhone初代采用了[4G和8G](https://zh.wikipedia.org/wiki/IPhone)存储，
HTC G1的内置存储只有[265MB](https://en.wikipedia.org/wiki/HTC_Dream)
注意这些大小在刨除操作系统本身占用外，留给用户使用的空间及其有限。在当时功能手机和相机市场培育了外置存储卡的市场，android据说最早
是为[相机设计的系统](https://www.pcworld.com/article/2034723/android-founder-we-aimed-to-make-a-camera-os.html)，
更是照搬了相机对存储卡的使用，将拍照照片存储在了外置sdcard上，将存储卡拔下来插到电脑上可以直接读取的模式。这种模式在后续看来是巨大的隐患。

外部存储，一开始用来指代可移除的外部sdcard卡，随着存储芯片价格的降低和性能考虑，android开始用内部的存储芯片完成之前的外部存储的功能，
开始使用primary存储代表内部模拟的sdcard存储，secondary表示外部可移除的sdcard卡。这里主要讨论内部模拟的sdcard的机制，默认用sdcard指代。


# sdcard上存储那些内容

sdcard最初采用了可以普遍被windows读取的FAT32格式，这种格式是大小写不敏感，同时没有权限控制。后续的实现都兼容了[该特点](https://source.android.com/devices/storage/config#android_5_x_and_earlier)。

```
generic_x86_64:/ # ls -l /sdcard/                                                                      
total 88
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Alarms
drwxrwx--x 5 root sdcard_rw 4096 2020-09-01 17:26 Android
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 DCIM
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Download
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Movies
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Music
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Notifications
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Pictures
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Podcasts
drwxrwx--x 2 root sdcard_rw 4096 2020-09-01 11:16 Ringtones
```
相应目录的名字定义在[Environment](https://developer.android.com/reference/android/os/Environment)中。

常用的

* Android 存储应用的数据（后面详细介绍）
* DCIM 相机拍照的照片
* Download 浏览器下载文件的存储位置

综合看来存储有两类，一类是app自己使用的数据，不用来分享位于Android目录，一类是多媒体类，照片、视频，等在所有应用之间共享。


android存储的发展历程[^history-ref].

android 1.0开始读写sdcard不需要任何权限，sdcard使用mountd进行mount.

[init.rc](https://android.googlesource.com/platform/system/core/+/4f6e8d7a00cbeda1e70cc15be9c4af1018bdad53/rootdir/init.rc)

```
    export PATH /sbin:/system/sbin:/system/bin:/system/xbin
    export LD_LIBRARY_PATH /system/lib
    export ANDROID_BOOTLOGO 1
    export ANDROID_ROOT /system
    export ANDROID_ASSETS /system/app
    export ANDROID_DATA /data
    export EXTERNAL_STORAGE /sdcard
```

[rootdir/etc/mountd.conf](https://android.googlesource.com/platform/system/core/+/4f6e8d7a00cbeda1e70cc15be9c4af1018bdad53/rootdir/etc/mountd.conf)

```
mount {
    ## root block device with partition map or raw FAT file system
    block_device    /dev/block/mmcblk0
        
    ## mount point for block device
    mount_point     /sdcard
    
    ## true if this mount point can be shared via USB mass storage
    enable_ums      true
}
```
[mountd/AutoMount.c](https://android.googlesource.com/platform/system/core/+/4f6e8d7a00cbeda1e70cc15be9c4af1018bdad53/mountd/AutoMount.c#DoMountDevice)
```cpp
static int DoMountDevice(const char* device, const char* mountPoint)
    ...
    // Extra safety measures:
    flags |= MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;
    // Also, set fmask = 711 so that files cannot be marked executable,
    // and cannot by opened by uid 1000 (system). Similar, dmask = 700
    // so that directories cannot be accessed by uid 1000.
    result = mount(device, mountPoint, "vfat", flags, 
                       "utf8,uid=1000,gid=1000,fmask=711,dmask=700");
```
可见sdcard所有文件使用system uid对外暴露，,sdcard对应的设备会直接mount到`/sdcard`目录。所有文件的权限都是066，即除了system uid所有用户都可以读写。至于system uid设计为不可以读写sdcard是[因为](https://stackoverflow.com/questions/5617797/android-shared-user-id-and-reading-writing-a-file)
sdcard卡是可以移除的，移除后所有读写sd的进程需要重启.

android 1.5开始写sdcard需要[WRITE_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission.html#WRITE_EXTERNAL_STORAGE), 增加了[AID_SDCARD_RW ](https://android.googlesource.com/platform/system/core/+/6e1f21584f43311f35ae7f6a4737c6a7e846083a)权限，sdcard的挂载从mountd改为使用vold，挂载时对应的[修改](https://android.googlesource.com/platform/system/core/+/b76a63b7bbdf8f51c4e689e241fca6d3a0bc1b1c%5E%21/#F0)。

```cpp
+    /*
+     * The mount masks restrict access so that:
+     * 1. The 'system' user cannot access the SD card at all - 
+     *    (protects system_server from grabbing file references)
+     * 2. Group users can RWX
+     * 3. Others can only RX
+     */
     rc = mount(devpath, vol->mount_point, "vfat", flags,
-               "utf8,uid=1000,gid=1000,fmask=711,dmask=700,shortname=mixed");
+               "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
 
     if (rc && errno == EROFS) {
         LOGE("vfat_mount(%d:%d, %s): Read only filesystem - retrying mount RO",
              dev->major, dev->minor, vol->mount_point);
         flags |= MS_RDONLY;
         rc = mount(devpath, vol->mount_point, "vfat", flags,
-                   "utf8,uid=1000,gid=1000,fmask=711,dmask=700,shortname=mixed");
+                   "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
     }
```
首先gid从AID_SYSTEM 1000改为了AID_SDCARD_RW 1015，文件的权限为075，组用户拥有读写执行权限，其他用户只有读和执行权限没有写权限。
对应的配置文件从mountd.conf修改为了[vold.fstab](https://android.googlesource.com/platform/system/core/+/refs/tags/android-4.0.4_r1.1/rootdir/etc/vold.fstab)。

```
#######################
## Regular device mount
##
## Format: dev_mount <label> <mount_point> <part> <sysfs_path1...> 
## label        - Label for the volume
## mount_point  - Where the volume will be mounted
## part         - Partition # (1 based), or 'auto' for first usable partition.
## <sysfs_path> - List of sysfs paths to source devices
######################
## Example of a standard sdcard mount for the emulator / Dream
# Mounts the first usable partition of the specified device
dev_mount sdcard /mnt/sdcard auto /devices/platform/goldfish_mmc.0 /devices/platform/msm_sdcc.2/mmc_host/mmc1
## Example of a dual card setup
# dev_mount left_sdcard  /sdcard1  auto /devices/platform/goldfish_mmc.0 /devices/platform/msm_sdcc.2/mmc_host/mmc1
# dev_mount right_sdcard /sdcard2  auto /devices/platform/goldfish_mmc.1 /devices/platform/msm_sdcc.3/mmc_host/mmc1
## Example of specifying a specific partition for mounts
# dev_mount sdcard /sdcard 2 /devices/platform/goldfish_mmc.0 /devices/platform/msm_sdcc.2/mmc_host/mmc1
```
//todo 获取权限加入用户组1015的过程

android 2.3开始代码里[引入](https://android.googlesource.com/platform/system/core/+/03ee9479a4ed67689b9bbccda20c60800a38b178)了FUSE，
初期的代码只实现了通过FUSE暴露的文件的拥有者为AID_SDCARD_RW，并没有实现对大小写文件名的处理。在[修改](https://android.googlesource.com/platform/system/core/+/51b3a2d77a3361f6088172a4a68a0111058d3aab)里把所有对文件的访问使用小写字母文件名访问。

android 3.1开始把电脑访问sdcard的方式从UMS(usb大容量存储)访问方式修改为MTP(Media Transfer Protocol)，这样在连接电脑读取文件时不影响手机运行。

android 3.2增加了AID_MEDIA_RW 1023 权限，限制只有该权限才可以读写外置的存储卡，该权限只有系统应用可以申请。

android 4.0开始可以通过FUSE将/data/media目录模拟为primary external storage，这种方式在使用MTP方式之前无法实现，因为需要先umount才可以。手机厂商可以使用外置sdcard做主存储，也可以使用内部FUSE模拟的sdcard，对应的配置从init.rc转移到厂商的init.hardware.rc，作为android 4.0首款三星Galaxy Nexus使用的是外部sdcard卡槽做为主存储[配置](https://android.googlesource.com/platform/system/core/+/refs/tags/android-4.0.4_r1.1/rootdir/init.rc)如下：

```
on early-init
    export EXTERNAL_STORAGE /mnt/sdcard
    mkdir /mnt/sdcard 0000 system system
    # for backwards compatibility
    symlink /mnt/sdcard /sdcard
```

android 4.1增加了sdcard读取的[权限](https://developer.android.com/reference/android/Manifest.permission.html#READ_EXTERNAL_STORAGE), AID_SDCARD_R 1028


![fuse结构图](https://en.wikipedia.org/wiki/Filesystem_in_Userspace#/media/File:FUSE_structure.svg)







<iframe frameborder="0" style="width:100%;height:423px;" src="https://viewer.diagrams.net/?highlight=0000ff&edit=https%3A%2F%2Fapp.diagrams.net%2F%23Hf23505106%252Fdrawio%252Fmaster%252Fandroid-storage&layers=1&nav=1&title=android-storage#R5ZZRb5tADMc%2FDY%2BTgEto87im6TptkyYxbdrjDRy46cDsYkKyTz8TTAChZqvUrg99yvlv39n388nEU%2Bvi8M7pKv%2BEKVgv9NODp269MAyXYcQ%2FrXLslCBYrDolcyYVbRBi8xtE9EWtTQq7SSAhWjLVVEywLCGhiaadw2YatkU7zVrpDGZCnGg7V7%2BZlPJOvV76g34PJsv7zIEvnkL3wSLscp1iM5LUxlNrh0jdqjiswbb0ei7dvrsHvOfCHJT0Lxu%2Bblcquo9%2FLb7A5w%2Fl9%2Bp9jrdv5JQdHfsLQ8r3FxMd5Zhhqe1mUG8c1mUK7ak%2BW0PMR8SKxYDFn0B0lGbqmpClnAor3i2WJM5gxXZXQ5v4wav1dWLtErhwHyVPRLsM6ELc4twAfrqABZA78j4HVpPZT%2BvQ8oSyc9xAmRcC%2BhHQw1cKffmS0KXIvba1ZPLCyHK5N7tKl7zO2nVM6NqJIC7ONPbO%2BjZ0pUXc5IYgrvQJVsMD8XIHtDVZyUbCwMGdj9%2BDIzhcbsocomxQSqaNzNvwSuxmGF5BP5Hy0eCK%2FGfivphxJ6dTQ6Z9vSeaQvzRaP%2FKc8T%2BCdAG11O0KnpptMsZWv7CVKR%2FMMN16L31nxfvEzBdXP0%2FpmwOH9uTb%2FSfRW3%2BAA%3D%3D"></iframe>


[^history-ref]: [ANDROID'S STORAGE JOURNEY](https://android.stackexchange.com/questions/214288/how-to-stop-apps-writing-to-android-folder-on-the-sd-card/218469#218469)