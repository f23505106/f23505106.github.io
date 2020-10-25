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
对应的配置文件从mountd.conf修改为了[vold.fstab](https://android.googlesource.com/device/htc/dream-sapphire/+/refs/tags/android-2.2_r1/vold.fstab)。

```
## Vold 2.0 fstab for HTC Dream or Sapphire
#
## - San Mehat (san@android.com)
## 
#######################
## Regular device mount
##
## Format: dev_mount <label> <mount_point> <part> <sysfs_path1...> 
## label        - Label for the volume
## mount_point  - Where the volume will be mounted
## part         - Partition # (1 based), or 'auto' for first usable partition.
## <sysfs_path> - List of sysfs paths to source devices
######################
# Mounts the first usable partition of the specified device
dev_mount sdcard /mnt/sdcard auto /devices/platform/goldfish_mmc.0 /devices/platform/msm_sdcc.2/mmc_host/mmc1
```

android [2.2](https://android.googlesource.com/platform/system/core/+log/refs/tags/android-2.2_r1/rootdir/init.rc)开始, sdcard的挂载目录改为`/mnt/sdcard`，EXTERNAL_STORAGE的值也为`/mnt/sdcard`，之前的`/sdcard`最为一个链接指向`/mnt/sdcard`。

```
--- a/rootdir/init.rc
+++ b/rootdir/init.rc
@@ -12,7 +12,7 @@
     export ANDROID_ROOT /system
     export ANDROID_ASSETS /system/app
     export ANDROID_DATA /data
-    export EXTERNAL_STORAGE /sdcard
+    export EXTERNAL_STORAGE /mnt/sdcard
     export BOOTCLASSPATH /system/framework/core.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/android.policy.jar:/system/framework/services.jar
 
 # Backward compatibility
@@ -20,15 +20,30 @@
     symlink /sys/kernel/debug /d
 
 # create mountpoints
-    mkdir /sdcard 0000 system system
+    mkdir /mnt 0775 root system
+    mkdir /mnt/sdcard 0000 system system
+
+# Backwards Compat - XXX: Going away in G*
+    symlink /mnt/sdcard /sdcard
+
```
//todo 获取权限加入用户组1015的过程 https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-4.1.1_r1/data/etc/platform.xml


android 2.3开始代码里[引入](https://android.googlesource.com/platform/system/core/+/03ee9479a4ed67689b9bbccda20c60800a38b178)了FUSE，
初期的代码只实现了通过FUSE暴露的文件的拥有者为AID_SDCARD_RW，并没有实现对大小写文件名的处理。在[修改](https://android.googlesource.com/platform/system/core/+/51b3a2d77a3361f6088172a4a68a0111058d3aab)里把所有对文件的访问使用小写字母文件名访问，后续连续出现了一下修改，将所有文件名为小写，修改为文件名可以大小写保持，但不区分大小写，主要通过`strcasecmp`[实现](https://android.googlesource.com/platform/system/core/+/6249b9009f44f2127670eda4d5aa6d5fd3e26e02%5E%21/#F1)。

android 3.1开始把电脑访问sdcard的方式从UMS(usb大容量存储)访问方式修改为MTP(Media Transfer Protocol)，这样在连接电脑读取文件时不影响手机运行。

android 3.2增加了AID_MEDIA_RW 1023 权限，限制只有该权限才可以读写外置的存储卡，该权限只有系统应用可以申请。

android 4.0开始可以通过FUSE将/data/media目录模拟为primary external storage，这种方式在使用MTP方式之前无法实现，因为需要先umount才可以。手机厂商可以使用外置sdcard做主存储，也可以使用内部FUSE模拟的sdcard. Nexus S没有外部sdcard插槽，为兼容之前版本，继续采用在内部存储上划分出一个单独的分区做sdcard分区，首先在[init.herring.rc](https://android.googlesource.com/device/samsung/crespo/+/refs/tags/android-4.0.3_r1/init.herring.rc)里配置sdcard的挂载点

```
on fs
    mount ext4 /dev/block/platform/s3c-sdhci.0/by-name/system /system wait ro
    mount ext4 /dev/block/platform/s3c-sdhci.0/by-name/userdata /data wait noatime nosuid nodev nomblk_io_submit
    export EXTERNAL_STORAGE /mnt/sdcard
    mkdir /mnt/sdcard 0000 system system
    symlink /mnt/sdcard /sdcard
```
然后在[vold.fstab](https://android.googlesource.com/device/samsung/crespo/+/refs/tags/android-4.0.3_r1/vold.fstab)里配置具体的挂载配置。

```
#######################
## Regular device mount
##
## Format: dev_mount <label> <mount_point> <part> <sysfs_path1...> 
## label        - Label for the volume
## mount_point  - Where the volume will be mounted
## part         - Partition # (1 based), or 'auto' for first usable partition.
## <sysfs_path> - List of sysfs paths to source devices, must start with '/' character
## flags        - (optional) Comma separated list of flags, must not contain '/' character
######################
dev_mount sdcard /mnt/sdcard 3 /devices/platform/s3c-sdhci.0/mmc_host/mmc0/mmc0:0001/block/mmcblk0 nonremovable,encryptable
```

使用FUSE的配置，参考Galaxy Nexus手机的配置[init.tuna.rc](https://android.googlesource.com/device/samsung/tuna/+/refs/tags/android-4.0.1_r1/init.tuna.rc)

```
on early-init
	export EXTERNAL_STORAGE /mnt/sdcard
	mkdir /mnt/sdcard 0000 system system
	# for backwards compatibility
	symlink /mnt/sdcard /sdcard

service sdcard /system/bin/sdcard /data/media 1023 1023
	class late_start
```
`/system/bin/sdcard`即为在用户态实现的文件系统，参考下图中的hello程序。
![fuse结构图](https://upload.wikimedia.org/wikipedia/commons/0/08/FUSE_structure.svg)

以查找文件的操作FUSE_LOOKUP为例 [sdcard.c](https://android.googlesource.com/platform/system/core/+/refs/tags/android-4.0.1_r1.2/sdcard/sdcard.c)

```c
#define MOUNT_POINT "/mnt/sdcard"
void handle_fuse_request(struct fuse *fuse, struct fuse_in_header *hdr, void *data, unsigned len)
{
    struct node *node;
    switch (hdr->opcode) {
        case FUSE_LOOKUP: { /* bytez[] -> entry_out */
            TRACE("LOOKUP %llx %s\n", hdr->nodeid, (char*) data);
            lookup_entry(fuse, node, (char*) data, hdr->unique);
            return;
        }
    ...
    }
}
void lookup_entry(struct fuse *fuse, struct node *node,
                  const char *name, __u64 unique)
{
    struct fuse_entry_out out;
    memset(&out, 0, sizeof(out));
    node = node_lookup(fuse, node, name, &out.attr);
    if (!node) {
        fuse_status(fuse, unique, -ENOENT);
        return;
    }
    fuse_reply(fuse, unique, &out, sizeof(out));
}

struct node *node_lookup(struct fuse *fuse, struct node *parent, const char *name,
                         struct fuse_attr *attr)
{
    int res;
    struct stat s;
    char *path, buffer[PATH_BUFFER_SIZE];
    struct node *node;
    path = node_get_path(parent, buffer, name);
}
char *node_get_path(struct node *node, char *buf, const char *name)
{
    /* We look for case insensitive matches by default */
    return do_node_get_path(node, buf, name, CASE_SENSITIVE_MATCH);
}
char *do_node_get_path(struct node *node, char *buf, const char *name, int match_case_insensitive)
{
    if (in_name && match_case_insensitive && access(out, F_OK) != 0) {
        while ((entry = readdir(dir))) {
            if (!strcasecmp(entry->d_name, in_name)) {//这里使用忽略大小写的查找方式找到对应文件
                /* we have a match - replace the name */
                len = strlen(in_name);
                memcpy(buf + PATH_BUFFER_SIZE - len - 1, entry->d_name, len);
                break;
            }
        }
        closedir(dir);
    }
   return out;
}
```
在FUSE的中介作用下，通过sdcard目录进行读写需要sdcard_rw权限，在真正写到/data/media目录时使用的是media_rw权限。

```
generic_x86_64:/ # ls -l /data/media/0                                                                          
total 88
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Alarms
drwxrwxr-x 5 media_rw media_rw 4096 2020-09-01 17:26 Android
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 DCIM
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Download
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Movies
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Music
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Notifications
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Pictures
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Podcasts
drwxrwxr-x 2 media_rw media_rw 4096 2020-09-01 11:16 Ringtones
-rw-rw-r-- 1 media_rw media_rw    3 2020-09-02 10:44 test.txt
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
-rw-rw---- 1 root sdcard_rw    3 2020-09-02 10:44 test.txt
```

android 4.1增加了sdcard读取的[权限](https://developer.android.com/reference/android/Manifest.permission.html#READ_EXTERNAL_STORAGE), AID_SDCARD_R 1028
增加/storage目录，使用AID_SDCARD_R控制目录的可执行权限，来实现对sdcard上文件读取的控制。[init.tuna.rc](https://android.googlesource.com/device/samsung/tuna/+/6ad18b6e264c8e97914a15f498aaa8dfdb702f07%5E%21/init.tuna.rc),采用这种方式，[获取写sdcard的写权限时必然也获得了读权限](https://android.googlesource.com/platform/frameworks/base/+/7924512aa12c6af37d90e8ccfcdf04eb78a294a3%5E%21/#F1)。

```
+    /**
+     * List of permissions that have been split into more granular or dependent
+     * permissions.
+     * @hide
+     */
+    public static final PackageParser.SplitPermissionInfo SPLIT_PERMISSIONS[] =
+        new PackageParser.SplitPermissionInfo[] {
+            new PackageParser.SplitPermissionInfo(android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
+                    new String[] { android.Manifest.permission.READ_EXTERNAL_STORAGE })
+    };
+
```

android 4.2开始支持多用户，修改了sdcard读取权限的实现方式，读取sdcard的实现由[zygot通过bind mount实现](https://android.googlesource.com/device/samsung/tuna/+/a3471cd8e45f43704c882ddff985df7818971e3a%5E%21/#F0)

[init.tuna.rc](https://android.googlesource.com/device/samsung/tuna/+/refs/tags/android-4.2_r1/init.tuna.rc)

```
on init
    # See storage config details at http://source.android.com/tech/storage/
    mkdir /mnt/shell/emulated 0700 shell shell
    mkdir /storage/emulated 0555 root root
    export EXTERNAL_STORAGE /storage/emulated/legacy
    export EMULATED_STORAGE_SOURCE /mnt/shell/emulated
    export EMULATED_STORAGE_TARGET /storage/emulated
    # Support legacy paths
    symlink /storage/emulated/legacy /sdcard
    symlink /storage/emulated/legacy /mnt/sdcard
    symlink /storage/emulated/legacy /storage/sdcard0
    symlink /mnt/shell/emulated/0 /storage/emulated/legacy

    # virtual sdcard daemon running as media_rw (1023)
service sdcard /system/bin/sdcard /data/media /mnt/shell/emulated 1023 1023
    class late_start
```

[init.rc](https://android.googlesource.com/platform/system/core/+/refs/tags/android-4.2_r1/rootdir/init.rc)

```
# setup the global environment
    export ANDROID_STORAGE /storage
    # See storage config details at http://source.android.com/tech/storage/
    mkdir /mnt/shell 0700 shell shell
    mkdir /storage 0050 root sdcard_r
```
下面的分析需要使用linux的namespace原理和bind mount的机制，可以参考[DOCKER基础技术：LINUX NAMESPACE](https://coolshell.cn/articles/17010.html)

[vm/Init.cpp](https://android.googlesource.com/platform/dalvik.git/+/refs/tags/android-4.2_r1/vm/Init.cpp)

```cpp
//这里是zygot进程，这里设置影响所有从zygot孵化出的应用进程
static bool initZygote()
{
    // 通过unshare表明新的进程使用的独立的Mount namespaces
    if (unshare(CLONE_NEWNS) == -1) {
        SLOGE("Failed to unshare(): %s", strerror(errno));
        return -1;
    }
    // 使用MS_SLAVE默认namespace的挂载事件会传播到子进程
    // 使用MS_REC递归设置子目录
    if (mount("rootfs", "/", NULL, (MS_SLAVE | MS_REC), NULL) == -1) {
        SLOGE("Failed to mount() rootfs as MS_SLAVE: %s", strerror(errno));
        return -1;
    }
    // Create a staging tmpfs that is shared by our children; they will
    // bind mount storage into their respective private namespaces, which
    // are isolated from each other.
    const char* target_base = getenv("EMULATED_STORAGE_TARGET");//init.rc 定义 /storage/emulated
    if (target_base != NULL) {
        if (mount("tmpfs", target_base, "tmpfs", MS_NOSUID | MS_NODEV,
                "uid=0,gid=1028,mode=0050") == -1) {
            SLOGE("Failed to mount tmpfs to %s: %s", target_base, strerror(errno));
            return -1;
        }
    }
    return true;
}
```
[dalvik_system_Zygote.cpp](https://android.googlesource.com/platform/dalvik.git/+/refs/tags/android-4.2_r1/vm/native/dalvik_system_Zygote.cpp)

```cpp
//这里是fork后的应用进程
static int mountEmulatedStorage(uid_t uid, u4 mountMode) {
    // See storage config details at http://source.android.com/tech/storage/
    userid_t userid = multiuser_get_user_id(uid);
    // Create a second private mount namespace for our process
    if (unshare(CLONE_NEWNS) == -1) {
        SLOGE("Failed to unshare(): %s", strerror(errno));
        return -1;
    }
    // Create bind mounts to expose external storage
    if (mountMode == MOUNT_EXTERNAL_MULTIUSER
            || mountMode == MOUNT_EXTERNAL_MULTIUSER_ALL) {
        // These paths must already be created by init.rc
        const char* source = getenv("EMULATED_STORAGE_SOURCE");// /mnt/shell/emulated
        const char* target = getenv("EMULATED_STORAGE_TARGET");// /storage/emulated
        const char* legacy = getenv("EXTERNAL_STORAGE");// /storage/emulated/legacy
        if (source == NULL || target == NULL || legacy == NULL) {
            SLOGE("Storage environment undefined; unable to provide external storage");
            return -1;
        }
        // Prepare source paths
        char source_user[PATH_MAX];
        char source_obb[PATH_MAX];
        char target_user[PATH_MAX];
        // /mnt/shell/emulated/0
        snprintf(source_user, PATH_MAX, "%s/%d", source, userid);
        // /mnt/shell/emulated/obb
        snprintf(source_obb, PATH_MAX, "%s/obb", source);
        // /storage/emulated/0
        snprintf(target_user, PATH_MAX, "%s/%d", target, userid);
        if (fs_prepare_dir(source_user, 0000, 0, 0) == -1
                || fs_prepare_dir(source_obb, 0000, 0, 0) == -1
                || fs_prepare_dir(target_user, 0000, 0, 0) == -1) {
            return -1;
        }
        if (mountMode == MOUNT_EXTERNAL_MULTIUSER_ALL) {
            // Mount entire external storage tree for all users
            if (mount(source, target, NULL, MS_BIND, NULL) == -1) {
                SLOGE("Failed to mount %s to %s: %s", source, target, strerror(errno));
                return -1;
            }
        } else {
            // Only mount user-specific external storage
            if (mount(source_user, target_user, NULL, MS_BIND, NULL) == -1) {
                SLOGE("Failed to mount %s to %s: %s", source_user, target_user, strerror(errno));
                return -1;
            }
        }
        // Now that user is mounted, prepare and mount OBB storage
        // into place for current user
        char target_android[PATH_MAX];
        char target_obb[PATH_MAX];
        // /storage/emulated/0/Android
        snprintf(target_android, PATH_MAX, "%s/%d/Android", target, userid);
        // /storage/emulated/0/Android/obb
        snprintf(target_obb, PATH_MAX, "%s/%d/Android/obb", target, userid);
        if (fs_prepare_dir(target_android, 0000, 0, 0) == -1
                || fs_prepare_dir(target_obb, 0000, 0, 0) == -1
                || fs_prepare_dir(legacy, 0000, 0, 0) == -1) {
            return -1;
        }
        if (mount(source_obb, target_obb, NULL, MS_BIND, NULL) == -1) {
            SLOGE("Failed to mount %s to %s: %s", source_obb, target_obb, strerror(errno));
            return -1;
        }
        // Finally, mount user-specific path into place for legacy users
        if (mount(target_user, legacy, NULL, MS_BIND | MS_REC, NULL) == -1) {
            SLOGE("Failed to mount %s to %s: %s", target_user, legacy, strerror(errno));
            return -1;
        }
    } else {
        SLOGE("Mount mode %d unsupported", mountMode);
        return -1;
    }
    return 0;
}
```
<iframe frameborder="0" style="width:100%;height:317px;" src="https://viewer.diagrams.net/?highlight=0000ff&edit=https%3A%2F%2Fapp.diagrams.net%2F%23Hf23505106%252Fdrawio%252Fmaster%252Fandroid_sdcard&layers=1&nav=1&title=android_sdcard#R7V3rc9q4Fv9rmLn7IYz8Jh8DSdqdbXd3kt657f3SEViAt7ZFjQmhf%2F1KluSXZCDEDxKc6RRLlmyhc87vPG0GxiR4%2FhDB1fIzdpE%2F0IH7PDBuB7ruWA75n3bsWIdpmKxjEXku69KyjkfvF%2BKdgPduPBetCwNjjP3YWxU7ZzgM0Swu9MEowtvisDn2i3ddwQWSOh5n0Jd7%2F%2Be58ZL1jiyQ9X9E3mIp7qwBfiaAYjDvWC%2Bhi7e5LuNuYEwijGN2FDxPkE%2F3TuwLm3dfcTZdWITC%2BJgJPx82H6JJNP756Ze3%2FOOjb3%2F8y7nS2VWeoL%2FhX3jtzmDk8iXHO7EP26UXo8cVnNH2lpB6YIyXceCTlkYOyZdb0TNkObEH%2FQdCChgu6ORxjMnYW0COfDSP%2BeEUxzEO%2BOSI7x89scJeGCc0s8bkH%2FlKE21gkRVMSEsTLfLPGM89359gH0dkdIhDei%2Foe4uQNGdkTxDpHz8hsh5CzRt%2BQtx3HOFN7IWLSTLwG7350KLfI4SrL%2FhvugixODTbRGvvCT2gNeNOuky4iTFv0kFxhNA9YS1yxVzPZ%2FyUdYRoe%2BcS1hJb6owHuv1zQ6k%2FRumJtGtg3OTOh7EX7x6QD2MPh3eK0WR70sY6JkS4obxfcblks9RzUeieOHONFgHlxPxEKsS5IWQjn5BbHDFwbpMrJVxIiIWeK9lbS4WGgA3CAYqjHRkiJjjG0LHYLI41upDFbSa5Du9a5oRWSCjkWLFIL56JEzngEvUC6TIk6ZLkCuV4oorMBZKmvJ6SKu0RJCAMB7LtZuzHbkzvVsRSGC1QfBggjqBDlKz7qXh91ZbyqUzIMvoZoEi8UYkqa7yJZojPKhEmXcbptDIlWgX8Rj0M9jDYMQzOsO%2FD1RpV6%2F5D4FgSLltGRttqERmtt4%2BM5qUgoy3biHGEqd3co2OPjmeAji%2FAwZE21ItGomZ2bCQ6bx8K7UuBwpGCVrafcPYKhlRR%2B3DNliL41%2Ffy7J4nq%2Bic4ucrAhMJChAxAlMcuSi6It1sRkC23wvZObDinSvouumMtHfGkI72RYvpf5hkAQ3o6cFvbOAch%2FHVHAaev2PDyXJgQPFaSGqykcklXfqxinB5CLtmgEO8ZpCfXpiB3k1yR7G0KZz9WBBADd2r0ip1y2KXyh%2BwdWb7Zi%2FoJ3Coi8d2nBCQbTo7dZAQKz9sjxBvdH%2FpDBqQIruzW8coqNzrEkARRI5Lup6YCD9QSfOeoowDz3UTeFMZF8n3TeCLYhndGx5BTLCtDoVh6ENLDTk5faEZzrBN6%2Fm6h6FuYQjQ%2BG8PQy3AUBKN%2Fh71QGSOyuFNTeHEa3qbpqumya7hMpnXO4a9Y9iaY5gXN70ecTPAEQGzVkVNztR15iaW4Q09e%2FHXRAjsEW9SmbgCQ2Dx9u0zZ%2F2kscs1%2FkaRR7aIyttthpUv90G1KhqTLWJK7oBbV7uzqhsVlmNLzqompzSEGqUUpFoczoqmh9IcKKp%2FhU9GZQVw4Befqbpmt7o0da3bUqDpHBwHTY67o2BDuJwCa6%2Bze53dmc6mbUHaAVW%2F9K8eWTT1w7p81KoulzMqZ6PLq%2BiQ0%2FG2k1PyqU5vXsFbpyt4pgpr1%2FCG1bGGV%2BUOeg3fioY3rs9Tw8spir6ir9fv71m%2F69cl%2FW7IYthqRldTxefPQL8fpsMJWnl0ulZuRinrpjUEQLeA%2BCuBtD1qVUcLLssxgwtj2MNxD8fvE44VhdiGeOijq%2BipLicqzh6RU4%2FraG%2FrVAwX234%2BoVM57Z4mu9qCbTneHiDX63G7x%2B13itv69VG43aolrZ%2FREzRNW9LiqzVfRUnoKlHaMtuF1%2BrcFLk0pPGpJYzWfMOEXGziOVU4e6tnqipT5BqTvmLqqIoedoJ9eXomxFEA%2Fdy5LUcCetLkIgB8FBP9cUVvkH7b%2FEwaF7zyQjdh9cJWJGfiCIbrORkvZoZ8mVuyx8Wr1l5hqr2J0i41x4iPnlta4ZZBVij7Lipmm3QLLaDWOPlgudZusFzv0%2BG9nX95dr59zDNQrWbE9TedEXdElVuDIZpXJL%2Bvm3EiLJmNWk5%2F63L6G1hUZ4vqcfZx6ZpXJfBdl8AYzl75xlG8xAscQj8v28UdzMZ8womGpaT8hxiSO76vVEUVCX2SyJJdjnZf841MWybNbFrS2p1EYQkSTpF0fXQknBh6HZhAQBXucgO46VIJGSZQm4D3p40nB2wF9YKKXEBBfEJa%2F5LEf79H28LhxYOLLT2XorTsjVbRxe4WXU4BFw5JKb7UhC55TiP9NoDXmiOxJTmj3zp23Xhk6EfiEStkaxuPrHJh6AgMGscXsSc5fLn%2F7%2BOdiBtMoyxkcC9CCvdTL6RNXshVHlmJRhlLaxW4kWNfBSa1iCOmXcJ6XQEiqofbynnB%2Bl5RA6T9PHcQ0fIIojWDIPTZVzRXIQgA2u14UjOCmEciiNkJgtjl0jNg77VoyuOFHd4o4jhap4ycZ2Pqh5wNJyNLYwFoiZPHev22%2BdGcbNeS9HuxLiy%2FIcwy9nKyNJ6X5zerO%2BWs4f93CxyjNGcRTterQZaqyXTkHEc%2FbkL3cYVmHjG1fxFyBwEOFcqUMH5cdT2e%2BqnIOioTLYMki74%2F0yLGJPNKxfg8Q1JOuBhDg%2FytntMBB%2FIZIJfSALmshpTS%2BPz4ffz7n7fyxrBgimylHJfveEOmiC2etRWsLeJMeVPEUuQpNFFqWrstIt7N1w2Ei%2BNvueNuYiWd2iKmdSSCG7UUNr8Ywcu2SBvejCln0GSzuU%2Bd9amzdlJnDWsGq%2Fz6OUUY3cjiYa3Eusw3mDqrAOXDTl5VFqz27JZVfv9Hy6ktp9PgwykKn7t2Dccv2%2FXZTOesNb45KkUTnNIvQJSjD5a2b3xDFoIiSdtbCL2F8D4tBNMsiaSissZURLGbMw9Ur6w9c%2FNApYaaKasR4HRSsr2WiLP8TgmnulqjJeNDqIkcz9yEboTJJB2YQ5mBLi7rrSCSIwu6bbTrClhyanHQyOtAaEah%2FIbO7eDS3whilgMw1zJLtP06EEv1AFXPEq2xhK620DtlCTlkd%2Ff1y93Dnzefvj9%2B%2Bevh5oOiGMFHCzjbvRHCNZkbkAhqdWvfOcZec%2B78AgUvyuy6cL2sK7p0io1nv%2Bhn0rr2%2F0u%2FANlQNYEMH%2BtdMMV0ou%2BFP5Ts%2BAlOkV9koeMBIKKuMZz6wjsuOvG1OHj810P5TQapuOZ5Zo%2F4VcLFFRhqdvm13ax1qpsghuD5nD4e20Ts0ewh5QwgRavl1RqvxhSrDUxR%2FMTYBWNKRTCZXx4MDccoBnL1s4cU%2BY1ohwn8TgDnWEYqAFMXgON0UkIpAY5RKCSTM3P268ZrbRhJthxBq%2FCg%2BsxHn%2Fl4H5mPsmd8LXvGrb7zzVZFQ%2FvMRwmhzijzYer0xZ3ZXylZbYPCWWAUr9%2F0j%2BB2%2B8Bqnh%2BGR9bQ58oum3yiDAIwV9ZgGg4Ak0mDls3RJfVdFWTqRUulWJB5%2BGGSl44HTguu2n4QbfypKP31D27rdVUjF0MJb%2BLhkm4koVx4VHq4pCFOlQuPWGKqLz%2FqjfBLMcKBnG9s98fN30n50f7A0KlGuPOa8iOrESPcKD3XlxawvdrOJs2kPiA3nCDt8jN2aRj37l8%3D"></iframe>

[文档说明](https://source.android.com/devices/storage/traditional#multi-user-external-storage)

> The default platform implementation of this feature leverages Linux kernel namespaces to create isolated mount tables for each Zygote-forked process, and then uses bind mounts to offer the correct user-specific primary external storage into that private namespace.
> 
> At boot, the system mounts a single emulated external storage FUSE daemon at EMULATED_STORAGE_SOURCE, which is hidden from apps. After the Zygote forks, it bind mounts the appropriate user-specific subdirectory from under the FUSE daemon to EMULATED_STORAGE_TARGET so that external storage paths resolve correctly for the app. Because an app lacks accessible mount points for other users' storage, they can only access storage for the user it was started as.









<iframe frameborder="0" style="width:100%;height:423px;" src="https://viewer.diagrams.net/?highlight=0000ff&edit=https%3A%2F%2Fapp.diagrams.net%2F%23Hf23505106%252Fdrawio%252Fmaster%252Fandroid-storage&layers=1&nav=1&title=android-storage#R5ZZRb5tADMc%2FDY%2BTgEto87im6TptkyYxbdrjDRy46cDsYkKyTz8TTAChZqvUrg99yvlv39n388nEU%2Bvi8M7pKv%2BEKVgv9NODp269MAyXYcQ%2FrXLslCBYrDolcyYVbRBi8xtE9EWtTQq7SSAhWjLVVEywLCGhiaadw2YatkU7zVrpDGZCnGg7V7%2BZlPJOvV76g34PJsv7zIEvnkL3wSLscp1iM5LUxlNrh0jdqjiswbb0ei7dvrsHvOfCHJT0Lxu%2Bblcquo9%2FLb7A5w%2Fl9%2Bp9jrdv5JQdHfsLQ8r3FxMd5Zhhqe1mUG8c1mUK7ak%2BW0PMR8SKxYDFn0B0lGbqmpClnAor3i2WJM5gxXZXQ5v4wav1dWLtErhwHyVPRLsM6ELc4twAfrqABZA78j4HVpPZT%2BvQ8oSyc9xAmRcC%2BhHQw1cKffmS0KXIvba1ZPLCyHK5N7tKl7zO2nVM6NqJIC7ONPbO%2BjZ0pUXc5IYgrvQJVsMD8XIHtDVZyUbCwMGdj9%2BDIzhcbsocomxQSqaNzNvwSuxmGF5BP5Hy0eCK%2FGfivphxJ6dTQ6Z9vSeaQvzRaP%2FKc8T%2BCdAG11O0KnpptMsZWv7CVKR%2FMMN16L31nxfvEzBdXP0%2FpmwOH9uTb%2FSfRW3%2BAA%3D%3D"></iframe>


[^history-ref]: [ANDROID'S STORAGE JOURNEY](https://android.stackexchange.com/questions/214288/how-to-stop-apps-writing-to-android-folder-on-the-sd-card/218469#218469)