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


android存储的发展历程参考1[^history-ref]参考2[^wetest-ref].

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

android 4.2开始支持多用户。

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

[文档说明](https://source.android.com/devices/storage/traditional#multi-user-external-storage)

> The default platform implementation of this feature leverages Linux kernel namespaces to create isolated mount tables for each Zygote-forked process, and then uses bind mounts to offer the correct user-specific primary external storage into that private namespace.
> 
> At boot, the system mounts a single emulated external storage FUSE daemon at EMULATED_STORAGE_SOURCE, which is hidden from apps. After the Zygote forks, it bind mounts the appropriate user-specific subdirectory from under the FUSE daemon to EMULATED_STORAGE_TARGET so that external storage paths resolve correctly for the app. Because an app lacks accessible mount points for other users' storage, they can only access storage for the user it was started as.


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
![android 4.2 sdcard](https://raw.githubusercontent.com/f23505106/drawio/master/android_sdcard.svg)

应用获取sdcard路径的逻辑[Environment.java](https://android.googlesource.com/platform/frameworks/base/+/android-4.2_r1/core/java/android/os/Environment.java)
```java
//按顺序尝试下列目录
// /storage/emulated/<user-id>
// /storage/emulated/legacy
// /storage/sdcard0
public class Environment {
    private static final String ENV_EXTERNAL_STORAGE = "EXTERNAL_STORAGE";
    private static final String ENV_EMULATED_STORAGE_TARGET = "EMULATED_STORAGE_TARGET";
    private static UserEnvironment sCurrentUser;
    public static File getExternalStorageDirectory() {
        throwIfSystem();
        return sCurrentUser.getExternalStorageDirectory();
    }
    public static class UserEnvironment {
        public UserEnvironment(int userId) {
            String rawExternalStorage = System.getenv(ENV_EXTERNAL_STORAGE);// /storage/emulated/legacy
            String rawEmulatedStorageTarget = System.getenv(ENV_EMULATED_STORAGE_TARGET);// /storage/emulated

            if (!TextUtils.isEmpty(rawEmulatedStorageTarget)) {
                // /storage/emulated/0
                mExternalStorage = buildPath(emulatedBase, rawUserId);
            } else {
                // Device has physical external storage; use plain paths.
                if (TextUtils.isEmpty(rawExternalStorage)) {
                    rawExternalStorage = "/storage/sdcard0";
                }
                mExternalStorage = new File(rawExternalStorage);
            }
        }
        public File getExternalStorageDirectory() {
            return mExternalStorage;
        }
    }
}
```
```
shell@klte:/ $ ls -l /storage/emulated/                                        
lrwxrwxrwx root     root              2014-03-08 07:34 legacy -> /mnt/shell/emulated/0
```


android 4.4开始应用读写在外部存储的应用目录（/sdcard/Android/<pkg>/）不需要声明权限，增加了Context.getExternalFilesDirs() 接口，可以获取应用在主外部存储和其他二级外部存储下的files路径，引入存储访问框架（SAF，Storage Access Framework。

除了之前的目录结构外引入了一套新的目录结构，DERIVE_NONE,DERIVE_LEGACY,DERIVE_UNIFIED。

* DERIVE_NONE 相当于Android 1.5-4.1引入AID_SDCARD_R之前的模式，整个sdcard通过AID_SDCARD_RW控制是否可以写，任何程序都可以读
* DERIVE_LEGACY 相当于4.2之后的目录结构，sdcard根目录下是用户的目录0，1等，0下面是用户看到的sdcard的目录结构，obb和0，1目录是同级的，所有用户共享。
* DERIVE_UNIFIED 新引入，sdcard根目录下是用户看到的sdcard的目录结构，多用户的数据位于Android/user目录下

具体使用那种模式在init里启动sdcard的服务时候通过参数传入，-l表示使用DERIVE_LEGACY，只见过使用这种模式的。

[init.rc](https://android.googlesource.com/platform/system/core/+/refs/tags/android-4.4_r1/rootdir/init.rc)

```
    # See storage config details at http://source.android.com/tech/storage/
    mkdir /mnt/shell 0700 shell shell
    mkdir /mnt/media_rw 0700 media_rw media_rw
    mkdir /storage 0751 root sdcard_r
```

[init.hammerhead.rc](https://android.googlesource.com/device/lge/hammerhead/+/refs/tags/android-4.4_r1/init.hammerhead.rc)

```
# virtual sdcard daemon running as media_rw (1023)
service sdcard /system/bin/sdcard -u 1023 -g 1023 -l /data/media /mnt/shell/emulated
    class late_start
```
为了达到任何应用访问应用对应的目录（/sdcard/Android/<pkg>/）不需要权限，原来的AID_SDCARD_R控制模式必须改变，需要使用新的sdcard读写权限的实现模式。

* 首先是放开了storage目录other的执行权限，意味着不用申请读取sdcard权限，只要对应文件的读取权限就可以读取文件。
* 通过读取"/data/system/packages.list"将读写进程的uid和对应的/sdcard/Android/<pkg>/目录联系起来。
* 文件的写权限不再由文件对应的标志位控制，而是在写文件时动态判断是不是可以写入。

对应的目录权限如下
![android 4.4 fuse](https://raw.githubusercontent.com/f23505106/drawio/master/android-4.4-fuse.svg)

```
shell@klte:/ $ ls -l
drwxrwxr-x root     system            2014-03-09 15:05 mnt
    lrwxrwxrwx root     root              2014-03-09 15:05 sdcard -> /storage/emulated/legacy
    drwxr-x--- shell    shell             2014-03-09 15:05 shell
        drwxrwx--x root     sdcard_r          2014-01-01 08:00 emulated
            drwxrwx--x root     sdcard_r          2020-10-14 19:23 0
                drwxrwx--x root     sdcard_r          2020-10-27 17:08 data
                    drwxrwx--- u0_a39   sdcard_r          2020-01-17 17:48 com.android.providers.downloads
                    drwxrwx--- root     sdcard_r          2020-01-17 17:48 com.android.vending
                    drwxrwx--- u0_a179  sdcard_r          2020-08-27 10:34 com.devopsapp
                    drwxrwx--- u0_a619  sdcard_r          2020-01-17 17:48 com.excean.gspace
                drwxrwx--x root     sdcard_r          2020-07-06 11:34 obb
            drwxrwx--x root     sdcard_r          2020-07-06 11:34 obb
lrwxrwxrwx root     root              2014-03-09 15:05 sdcard -> /storage/emulated/legacy
drwxr-x--x root     sdcard_r          2014-03-09 15:05 storage
    lrwxrwxrwx root     root              2014-03-09 15:05 sdcard0 -> /storage/emulated/legacy
    dr-xr-xr-x root     root              2014-03-09 15:05 emulated
        lrwxrwxrwx root     root              2014-03-09 15:05 legacy -> /mnt/shell/emulated/0
```
仅从权限看，只要有sdcard_r权限就可以读写所有sdcard上的文件，实际并不能写，具体是在FUSE里在写文件时进行了二次判断，以mkdir为例。

[sdcard.c](https://android.googlesource.com/platform/system/core/+/refs/tags/android-4.4_r1/sdcard/sdcard.c)

```c
static int handle_mkdir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_mkdir_in* req, const char* name)
{
    bool has_rw;
    has_rw = get_caller_has_rw_locked(fuse, hdr);//这里是通过初始化的时候从系统获取的应用是不是有sdcard_rw权限
    if (!check_caller_access_to_name(fuse, hdr, parent_node, name, W_OK, has_rw)) {//一般取决于has_rw
        return -EACCES;
    }
    __u32 mode = (req->mode & (~0777)) | 0775;
    if (mkdir(child_path, mode) < 0) {
        return -errno;
    }
}
/* Return if the calling UID holds sdcard_rw. */
static bool get_caller_has_rw_locked(struct fuse* fuse, const struct fuse_in_header *hdr) {
    appid_t appid = multiuser_get_app_id(hdr->uid);
    return hashmapContainsKey(fuse->appid_with_rw, (void*) appid);
}
/* Kernel has already enforced everything we returned through
 * derive_permissions_locked(), so this is used to lock down access
 * even further, such as enforcing that apps hold sdcard_rw. */
static bool check_caller_access_to_name(struct fuse* fuse,
        const struct fuse_in_header *hdr, const struct node* parent_node,
        const char* name, int mode, bool has_rw) {
    if (mode & W_OK) {
        return has_rw;
    }
    /* No extra permissions to enforce */
    return true;
}
```
可见当应用没有sdcard_rw权限进行写操作的时候会返回-EACCES错误。


android 6.0 外部存储支持动态权限管理，即用户可以随时赋予应用读写sdcard的权限，也可以随时移除对应权限。

[init.rc](https://android.googlesource.com/platform/system/core/+/refs/tags/android-6.0.0_r1/rootdir/init.rc)

```
    mkdir /mnt 0755 root system
    mount tmpfs tmpfs /mnt mode=0755,uid=0,gid=1000

    mkdir /mnt/user 0755 root root
    mkdir /mnt/user/0 0755 root root
    mkdir /mnt/expand 0771 system system
    # Storage views to support runtime permissions
    mkdir /storage 0755 root root
    mkdir /mnt/runtime 0700 root root
    mkdir /mnt/runtime/default 0755 root root
    mkdir /mnt/runtime/default/self 0755 root root
    mkdir /mnt/runtime/read 0755 root root
    mkdir /mnt/runtime/read/self 0755 root root
    mkdir /mnt/runtime/write 0755 root root
    mkdir /mnt/runtime/write/self 0755 root root
    # Symlink to keep legacy apps working in multi-user world
    symlink /storage/self/primary /sdcard
    symlink /mnt/user/0/primary /mnt/runtime/default/self/primary
```
![android 6.0 storage](https://raw.githubusercontent.com/f23505106/drawio/master/android-6.0-storage.svg)

[EmulatedVolume.cpp](https://android.googlesource.com/platform/system/vold/+/refs/tags/android-6.0.1_r1/EmulatedVolume.cpp)

```cpp
static const char* kFusePath = "/system/bin/sdcard";
status_t EmulatedVolume::doMount() {
    std::string label = mLabel;//"emulated"

    mFuseDefault = StringPrintf("/mnt/runtime/default/%s", label.c_str());
    mFuseRead = StringPrintf("/mnt/runtime/read/%s", label.c_str());
    mFuseWrite = StringPrintf("/mnt/runtime/write/%s", label.c_str());

    if (fs_prepare_dir(mFuseDefault.c_str(), 0700, AID_ROOT, AID_ROOT) ||
            fs_prepare_dir(mFuseRead.c_str(), 0700, AID_ROOT, AID_ROOT) ||
            fs_prepare_dir(mFuseWrite.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount points";
        return -errno;
    }

    if (!(mFusePid = fork())) {
        if (execl(kFusePath, kFusePath,
                "-u", "1023", // AID_MEDIA_RW
                "-g", "1023", // AID_MEDIA_RW
                "-m",
                "-w",
                mRawPath.c_str(),//"/data/media"
                label.c_str(),
                NULL)) {
        }
    }

    return OK;
}
```
[VolumeManager.cpp](https://android.googlesource.com/platform/system/vold/+/refs/tags/android-6.0.1_r1/VolumeManager.cpp)

```cpp
//把storage/emulated/0/ 创建软链接到mnt/user/0/primary
int VolumeManager::linkPrimary(userid_t userId) {
    std::string source(mPrimary->getPath());
    if (mPrimary->getType() == android::vold::VolumeBase::Type::kEmulated) {
        source = StringPrintf("%s/%d", source.c_str(), userId);
        fs_prepare_dir(source.c_str(), 0755, AID_ROOT, AID_ROOT);
    }
    std::string target(StringPrintf("/mnt/user/%d/primary", userId));
    if (TEMP_FAILURE_RETRY(unlink(target.c_str()))) {
        if (errno != ENOENT) {
            SLOGW("Failed to unlink %s: %s", target.c_str(), strerror(errno));
        }
    }
    LOG(DEBUG) << "Linking " << source << " to " << target;
    if (TEMP_FAILURE_RETRY(symlink(source.c_str(), target.c_str()))) {
        SLOGW("Failed to link %s to %s: %s", source.c_str(), target.c_str(),
                strerror(errno));
        return -errno;
    }
    return 0;
}
```
[sdcard.c](https://android.googlesource.com/platform/system/core/+/refs/tags/android-6.0.0_r1/sdcard/sdcard.c)

```cpp
static void run(const char* source_path, const char* label, uid_t uid,
        gid_t gid, userid_t userid, bool multi_user, bool full_write) {

    snprintf(fuse_default.dest_path, PATH_MAX, "/mnt/runtime/default/%s", label);
    snprintf(fuse_read.dest_path, PATH_MAX, "/mnt/runtime/read/%s", label);
    snprintf(fuse_write.dest_path, PATH_MAX, "/mnt/runtime/write/%s", label);
    handler_default.fuse = &fuse_default;
    handler_read.fuse = &fuse_read;
    handler_write.fuse = &fuse_write;
    handler_default.token = 0;
    handler_read.token = 1;
    handler_write.token = 2;

    if (multi_user) {
        /* Multi-user storage is fully isolated per user, so "other"
         * permissions are completely masked off. */
        if (fuse_setup(&fuse_default, AID_SDCARD_RW, 0006)
                || fuse_setup(&fuse_read, AID_EVERYBODY, 0027)
                || fuse_setup(&fuse_write, AID_EVERYBODY, full_write ? 0007 : 0027)) {
            ERROR("failed to fuse_setup\n");
            exit(1);
        }
    } 
}
static int fuse_setup(struct fuse* fuse, gid_t gid, mode_t mask) {
    char opts[256];
    fuse->fd = open("/dev/fuse", O_RDWR);
    if (fuse->fd == -1) {
        ERROR("failed to open fuse device: %s\n", strerror(errno));
        return -1;
    }
    umount2(fuse->dest_path, MNT_DETACH);
    snprintf(opts, sizeof(opts),
            "fd=%i,rootmode=40000,default_permissions,allow_other,user_id=%d,group_id=%d",
            fuse->fd, fuse->global->uid, fuse->global->gid);
    if (mount("/dev/fuse", fuse->dest_path, "fuse", MS_NOSUID | MS_NODEV | MS_NOEXEC |
            MS_NOATIME, opts) != 0) {
        ERROR("failed to mount fuse filesystem: %s\n", strerror(errno));
        return -1;
    }
    fuse->gid = gid;
    fuse->mask = mask;
    return 0;
}
```

[com_android_internal_os_Zygote.cpp](https://android.googlesource.com/platform/frameworks/base.git/+/refs/tags/android-6.0.1_r1/core/jni/com_android_internal_os_Zygote.cpp)

```cpp
// Create a private mount namespace and bind mount appropriate emulated
// storage for the given user.
static bool MountEmulatedStorage(uid_t uid, jint mount_mode,
        bool force_mount_namespace) {
    // See storage config details at http://source.android.com/tech/storage/
    // Create a second private mount namespace for our process
    if (unshare(CLONE_NEWNS) == -1) {
        ALOGW("Failed to unshare(): %s", strerror(errno));
        return false;
    }
    // Unmount storage provided by root namespace and mount requested view
    UnmountTree("/storage");
    String8 storageSource;
    if (mount_mode == MOUNT_EXTERNAL_DEFAULT) {
        storageSource = "/mnt/runtime/default";
    } else if (mount_mode == MOUNT_EXTERNAL_READ) {
        storageSource = "/mnt/runtime/read";
    } else if (mount_mode == MOUNT_EXTERNAL_WRITE) {
        storageSource = "/mnt/runtime/write";
    } else {
        // Sane default of no storage visible
        return true;
    }
    if (TEMP_FAILURE_RETRY(mount(storageSource.string(), "/storage",
            NULL, MS_BIND | MS_REC | MS_SLAVE, NULL)) == -1) {
        ALOGW("Failed to mount %s to /storage: %s", storageSource.string(), strerror(errno));
        return false;
    }
    // Mount user-specific symlink helper into place
    userid_t user_id = multiuser_get_user_id(uid);
    const String8 userSource(String8::format("/mnt/user/%d", user_id));
    if (fs_prepare_dir(userSource.string(), 0751, 0, 0) == -1) {
        return false;
    }
    if (TEMP_FAILURE_RETRY(mount(userSource.string(), "/storage/self",
            NULL, MS_BIND, NULL)) == -1) {
        ALOGW("Failed to mount %s to /storage/self: %s", userSource.string(), strerror(errno));
        return false;
    }
    return true;
}
```

![android sdcard 6.0](https://raw.githubusercontent.com/f23505106/drawio/master/android-sdcard-6.0.svg)

> # for services/daemons/processes in root/global namespace (VIEW = default)
/sdcard >S> /storage/self/primary
/storage >B> /mnt/runtime/default
/mnt/runtime/default/self/primary >S> /mnt/user/USER-ID/primary
/mnt/user/USER-ID/primary >S> /storage/emulated/USER-ID
/storage/emulated >B> /mnt/runtime/default/emulated
/mnt/runtime/default/emulated >E> /data/media

<iframe frameborder="0" style="width:100%;height:423px;" src="https://viewer.diagrams.net/?highlight=0000ff&edit=https%3A%2F%2Fapp.diagrams.net%2F%23Hf23505106%252Fdrawio%252Fmaster%252Fandroid-storage&layers=1&nav=1&title=android-storage#R5ZZRb5tADMc%2FDY%2BTgEto87im6TptkyYxbdrjDRy46cDsYkKyTz8TTAChZqvUrg99yvlv39n388nEU%2Bvi8M7pKv%2BEKVgv9NODp269MAyXYcQ%2FrXLslCBYrDolcyYVbRBi8xtE9EWtTQq7SSAhWjLVVEywLCGhiaadw2YatkU7zVrpDGZCnGg7V7%2BZlPJOvV76g34PJsv7zIEvnkL3wSLscp1iM5LUxlNrh0jdqjiswbb0ei7dvrsHvOfCHJT0Lxu%2Bblcquo9%2FLb7A5w%2Fl9%2Bp9jrdv5JQdHfsLQ8r3FxMd5Zhhqe1mUG8c1mUK7ak%2BW0PMR8SKxYDFn0B0lGbqmpClnAor3i2WJM5gxXZXQ5v4wav1dWLtErhwHyVPRLsM6ELc4twAfrqABZA78j4HVpPZT%2BvQ8oSyc9xAmRcC%2BhHQw1cKffmS0KXIvba1ZPLCyHK5N7tKl7zO2nVM6NqJIC7ONPbO%2BjZ0pUXc5IYgrvQJVsMD8XIHtDVZyUbCwMGdj9%2BDIzhcbsocomxQSqaNzNvwSuxmGF5BP5Hy0eCK%2FGfivphxJ6dTQ6Z9vSeaQvzRaP%2FKc8T%2BCdAG11O0KnpptMsZWv7CVKR%2FMMN16L31nxfvEzBdXP0%2FpmwOH9uTb%2FSfRW3%2BAA%3D%3D"></iframe>


[^history-ref]: [ANDROID'S STORAGE JOURNEY](https://android.stackexchange.com/questions/214288/how-to-stop-apps-writing-to-android-folder-on-the-sd-card/218469#218469)
[^wetest-ref]: [Android外部存储](https://wetest.qq.com/lab/view/368.html?from=coop_gad)
[^SDCardFS-FUSE][Diving into SDCardFS: How Google’s FUSE Replacement Will Reduce I/O Overhead](https://www.xda-developers.com/diving-into-sdcardfs-how-googles-fuse-replacement-will-reduce-io-overhead/)
[Android M 外部存储剖析](http://kernel.meizu.com/android-m-external-storage.html)
[What is /storage/emulated/0/?](https://android.stackexchange.com/questions/205430/what-is-storage-emulated-0/205494#205494)
[External Blues: Google Has Brought Big Changes To SD Cards In KitKat, And Even Samsung Is Implementing Them](https://www.androidpolice.com/2014/02/17/external-blues-google-has-brought-big-changes-to-sd-cards-in-kitkat-and-even-samsung-may-be-implementing-them/)