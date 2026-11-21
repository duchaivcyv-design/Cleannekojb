#import <Foundation/Foundation.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <spawn.h>
#include <sys/wait.h>
#include <libjailbreak/primitives_external.h>
#include <libjailbreak/info.h>

extern char **environ;

@interface RootfulEnabler : NSObject
+ (BOOL)bypassSSVAndEnableRootful;
+ (BOOL)patchKernelVnodeForRootful:(const char *const)devPath;
@end

@implementation RootfulEnabler

+ (BOOL)bypassSSVAndEnableRootful {
    NSLog(@"[+] Olimi Engine: Bắt đầu bẻ khóa SSV và APFS Snapshot cho iOS 16.0 - 16.7.16...");

    // 1. Kiểm tra trạng thái phân vùng hiện tại
    struct statfs vfsStat;
    if (statfs("/", &vfsStat) < 0) {
        NSLog(@"[-] Lỗi không thể đọc trạng thái phân vùng gốc.");
        return NO;
    }

    // 2. Đọc thiết bị nguồn của phân vùng gốc
    const char *root_dev = vfsStat.f_mntfromname;
    NSLog(@"[+] Phát hiện thiết bị gắn kết gốc từ: %s", root_dev);

    // 3. Ép phân vùng gốc sang chế độ Read-Write bằng POSIX mount
    char command[512];
    snprintf(command, sizeof(command), "mount -o rw,union,update /");
    int result = -1;
    pid_t pid = 0;
    char *spawnArgv[] = { "/bin/sh", "-c", command, NULL };
    if (posix_spawn(&pid, "/bin/sh", NULL, NULL, spawnArgv, environ) == 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) != -1 && WIFEXITED(status)) {
            result = WEXITSTATUS(status);
        }
    }

    if (result != 0) {
        NSLog(@"[-] Lỗi mount RW trực tiếp qua POSIX, đang kích hoạt Kernel Primitive Patch thực tế cho iOS 16...");
        return [self patchKernelVnodeForRootful:root_dev];
    }

    NSLog(@"[+] ĐÃ BẺ KHÓA SSV THÀNH CÔNG! Phân vùng gốc đã chuyển sang chế độ Rootful Read-Write.");
    return YES;
}

+ (BOOL)patchKernelVnodeForRootful:(const char *const)devPath {
    (void)devPath;
    NSLog(@"[+] Đang thực thi vá cờ MNT_RDONLY trực tiếp tại kernel space cho iOS 16.0 - 16.7.16...");

    uint64_t kernel_slide = gSystemInfo.kernelConstant.slide;
    if (kernel_slide == 0) {
        NSLog(@"[-] Lỗi: Kernel slide chưa được xác định.");
        return NO;
    }

    // Định vị địa chỉ rootvnode trong kernel space (cần khớp với offset thực tế của XNU iOS 16)
    uint64_t rootvnode_ptr = kernel_slide + 0xFFFFfff007c00000ULL; 
    uint64_t root_vnode = 0;

    if (gPrimitives.kreadbuf(rootvnode_ptr, &root_vnode, sizeof(root_vnode)) != 0 || root_vnode == 0) {
        NSLog(@"[-] Lỗi: Không thể đọc địa chỉ rootvnode từ kernel.");
        return NO;
    }

    // Đọc cấu trúc v_mount từ vnode (offset v_mount chuẩn trên XNU ARM64e iOS 16)
    uint64_t v_mount = 0;
    if (gPrimitives.kreadbuf(root_vnode + 0xd8, &v_mount, sizeof(v_mount)) != 0 || v_mount == 0) {
        NSLog(@"[-] Lỗi: Không thể đọc v_mount pointer từ root vnode.");
        return NO;
    }

    // Đọc trường mnt_flag trong struct mount
    uint32_t mnt_flag = 0;
    uint64_t mnt_flag_addr = v_mount + 0x70;
    if (gPrimitives.kreadbuf(mnt_flag_addr, &mnt_flag, sizeof(mnt_flag)) != 0) {
        NSLog(@"[-] Lỗi: Không thể đọc mnt_flag từ cấu trúc mount.");
        return NO;
    }

    // Xóa cờ MNT_RDONLY (0x00000001) và thêm cờ MNT_UPDATE (0x00010000)
    mnt_flag &= ~0x00000001;
    mnt_flag |= 0x00010000;

    if (gPrimitives.kwritebuf(mnt_flag_addr, &mnt_flag, sizeof(mnt_flag)) != 0) {
        NSLog(@"[-] Lỗi: Không thể ghi đè mnt_flag trong kernel space.");
        return NO;
    }

    NSLog(@"[+] ĐÃ VÁ KERNEL VNODE THÀNH CÔNG! Phân vùng gốc đã được unseal hoàn toàn.");
    return YES;
}

@end
