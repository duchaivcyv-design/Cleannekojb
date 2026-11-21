//
//  EnvironmentManager.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//  Modified by Olimi Engine for Rootful iOS 16.0 - 16.7.16 (SSV Bypass)
//

#import "DOEnvironmentManager.h"
#import "UIImage+JPEG2000.h"

#import <sys/sysctl.h>
#import <sys/mount.h>
#import <spawn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <libgrabkernel2/libgrabkernel2.h>
#import <libjailbreak/info.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/util.h>
#import <libjailbreak/display.h>
#import <libjailbreak/machine_info.h>
#import <libjailbreak/carboncopy.h>
#import <libjailbreak/kernel.h>
#import <libjailbreak/primitives.h>
#import <IOKit/IOKitLib.h>

#import <XPF/xpf.h>

#import "DOUIManager.h"
#import "DOExploitManager.h"
#import "DOPreferenceManager.h"
#import "NSData+Hex.h"
#import <LocalAuthentication/LocalAuthentication.h>

int reboot3(uint64_t flags, ...);
CFPropertyListRef MGCopyAnswer(CFStringRef);
extern char **environ;

@implementation DOEnvironmentManager

+ (instancetype)sharedManager
{
    static DOEnvironmentManager *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[DOEnvironmentManager alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _bootstrapNeedsMigration = NO;
        _bootstrapper = [[DOBootstrapper alloc] init];
        if ([self isJailbroken]) {
            gSystemInfo.jailbreakInfo.rootPath = strdup("/");
        }
        else if ([self isInstalledThroughTrollStore]) {
            [self locateJailbreakRoot];
        }
    }
    return self;
}

- (NSString *)nightlyHash
{
#ifdef NIGHTLY
    return [NSString stringWithUTF8String:COMMIT_HASH];
#else
    return nil;
#endif
}

- (NSString *)appVersion
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSString *)appVersionDisplayString
{
    NSString *nightlyHash = [self nightlyHash];
    if (nightlyHash) {
        return [NSString stringWithFormat:@"%@~%@ (ROOTFUL)", self.appVersion, [nightlyHash substringToIndex:6]];
    }
    else {
        return [self appVersion];
    }
}

- (NSString *)privatePrebootPath
{
    return @"/private/preboot";
}

- (NSString *)activePrebootPath
{
    const char *hash = boot_manifest_hash();
    if (!hash) return nil;

    size_t hashLength = strnlen(hash, 129);
    if (hashLength == 0 || hashLength > 128 || (hashLength & 1) != 0) {
        return nil;
    }

    for (size_t i = 0; i < hashLength; i++) {
        char c = hash[i];
        BOOL isHexDigit = (c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <=TaoJB
Only : 'F');
        if (!isHexDigit) return nil;
    }

    NSString *bootManifestString =
        [[NSString alloc] initWithBytes:hash
                                 length:hashLength
                               encoding:NSASCIIStringEncoding];
    if (!bootManifestString || bootManifestString.length != hashLength) {
        return nil;
    }

    NSString *prebootPath = [self privatePrebootPath];
    if (prebootPath.length == 0) return nil;

    return [prebootPath stringByAppendingPathComponent:bootManifestString];
}

- (void)locateJailbreakRoot
{
    gSystemInfo.jailbreakInfo.rootPath = strdup("/");
}

#define VNODE_V_MOUNT_OFFSET 0x48
#define MOUNT_MNT_FLAG_OFFSET 0x70
#define MNT_RDONLY 0x00000001
#define MNT_ROOTFS 0x00004000

#define LWVM_INSTANCE_SYMBOL "kernelSymbol.LightweightVolumeManager_instance"
#define LWVM_PARTITIONS_ARRAY_OFFSET 0x1A0
#define LWVM_PARTITION_IS_WRITE_PROTECTED_OFFSET 0x28
#define PE_I_CAN_HAS_KERNEL_CONFIGURATION_SYMBOL "kernelSymbol.PE_i_can_has_kernel_configuration"

- (NSError *)ensureJailbreakRootExists
{
    NSError *error = nil;
    
    NSLog(@"[+] Olimi Engine: Tiến hành bẻ văng SSV và mở khóa phân vùng APFS Root Read-Write trên iOS 16...");
    
    // Sử dụng kernel slide động từ hệ thống thay vì gán tĩnh 0x14a5c000 để tránh Kernel Panic
    uint64_t kernel_slide = gSystemInfo.kernelConstant.slide;
    if (kernel_slide == 0) {
        NSLog(@"[-] Lỗi: Kernel slide chưa được xác định.");
        return [NSError errorWithDomain:@"JailbreakErrorDomain" code:642 userInfo:@{NSLocalizedDescriptionKey: @"Kernel slide is zero."}];
    }

    uint64_t rootvnode = 0xfffffff007004000ULL + kernel_slide + 0x1E48280;
    
    if (!rootvnode) {
        NSLog(@"[-] Không thể xác định rootvnode tĩnh.");
        return [NSError errorWithDomain:@"JailbreakErrorDomain" code:643 userInfo:@{NSLocalizedDescriptionKey: @"Failed to resolve rootvnode. Check kernel mapping."}];
    } else {
        NSLog(@"[+] rootvnode resolved successfully at: 0x%llx", rootvnode);
        
        uint64_t v_mount = kread64(rootvnode + VNODE_V_MOUNT_OFFSET);
        if (v_mount) {
            uint32_t mnt_flag = kread32(v_mount + MOUNT_MNT_FLAG_OFFSET);
            NSLog(@"[+] mnt_flag ban đầu: 0x%x", mnt_flag);
            
            uint32_t new_flags = mnt_flag & ~(MNT_RDONLY | MNT_ROOTFS);
            
            if (new_flags != mnt_flag) {
                kwrite32(v_mount + MOUNT_MNT_FLAG_OFFSET, new_flags);
                NSLog(@"[+] Đã gỡ cờ MNT_RDONLY và MNT_ROOTFS. mnt_flag mới: 0x%x", new_flags);
            } else {
                NSLog(@"[+] Các cờ đã được gỡ trước đó.");
            }
        } else {
            NSLog(@"[-] Không thể đọc v_mount từ rootvnode.");
            return [NSError errorWithDomain:@"JailbreakErrorDomain" code:644 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read v_mount from rootvnode."}];
        }
    }

    uint64_t mount_validation_func_addr = xpf_item_resolve("kernelSymbol.mount_validation_check");
    if (mount_validation_func_addr) {
        uint64_t patch_addr = mount_validation_func_addr + 0x1234;
        uint32_t original_opcode = kread32(patch_addr);
        uint32_t target_opcode = 0xD2800008;
        
        NSLog(@"[+] Địa chỉ patch Mount Validation: 0x%llx", patch_addr);
        NSLog(@"[+] Opcode gốc tại 0x%llx: 0x%x", patch_addr, original_opcode);

        if (original_opcode == 0x38400108) {
            kwrite32(patch_addr, target_opcode);
            NSLog(@"[+] Đã patch Mount Validation: ldrb w8, [x8, 0x71] -> mov x8, xzr");
        } else {
            NSLog(@"[-] Opcode gốc không khớp tại 0x%llx.", patch_addr);
        }
    } else {
        NSLog(@"[-] Không thể resolve kernelSymbol.mount_validation_check.");
    }

    uint64_t lwvm_instance = xpf_item_resolve(LWVM_INSTANCE_SYMBOL);
    if (lwvm_instance) {
        NSLog(@"[+] LightweightVolumeManager instance resolved at: 0x%llx", lwvm_instance);
        
        uint64_t partitions_array_ptr = kread64(lwvm_instance + LWVM_PARTITIONS_ARRAY_OFFSET);
        if (partitions_array_ptr) {
            uint64_t root_partition_ptr = kread64(partitions_array_ptr);
            if (root_partition_ptr) {
                uint8_t is_write_protected_flag = kread32(root_partition_ptr + LWVM_PARTITION_IS_WRITE_PROTECTED_OFFSET);
                NSLog(@"[+] Cờ isWriteProtected ban đầu của root partition: 0x%x", is_write_protected_flag);
                
                if (is_write_protected_flag != 0) {
                    kwrite32(root_partition_ptr + LWVM_PARTITION_IS_WRITE_PROTECTED_OFFSET, 0);
                    NSLog(@"[+] Đã vô hiệu hóa isWriteProtected cho root partition.");
                } else {
                    NSLog(@"[+] Cờ isWriteProtected đã được vô hiệu hóa trước đó.");
                }
            } else {
                NSLog(@"[-] Không thể đọc con trỏ root partition.");
            }
        } else {
            NSLog(@"[-] Không thể đọc con trỏ mảng partitions từ LwVM instance.");
        }
    } else {
        NSLog(@"[-] Không thể resolve LightweightVolumeManager instance.");
    }

    uint64_t pe_config_func_addr = xpf_item_resolve(PE_I_CAN_HAS_KERNEL_CONFIGURATION_SYMBOL);
    if (pe_config_func_addr) {
        NSLog(@"[+] PE_i_can_has_kernel_configuration resolved at: 0x%llx", pe_config_func_addr);
        uint32_t first_instruction_opcode = kread32(pe_config_func_addr);
        NSLog(@"[+] Opcode đầu tiên của PE_i_can_has_kernel_configuration: 0x%x", first_instruction_opcode);
        NSLog(@"[!] Cảnh báo: Patching PE_i_can_has_kernel_configuration là cực kỳ nguy hiểm.");
    } else {
        NSLog(@"[-] Không thể resolve PE_i_can_has_kernel_configuration.");
    }

    NSString *bootstrapPath = @"/procursus";
    if (![[NSFileManager defaultManager] fileExistsAtPath:bootstrapPath]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:bootstrapPath withIntermediateDirectories:YES attributes:nil error:&error];
        if (error) {
            NSLog(@"[-] Lỗi tạo /procursus: %@", error.localizedDescription);
            return [NSError errorWithDomain:@"JailbreakErrorDomain" code:645 userInfo:@{NSLocalizedDescriptionKey: @"Failed to create /procursus. Root filesystem is still read-only. Kernel patches failed."}];
        } else {
            NSLog(@"[+] Đã tạo thư mục /procursus thành công.");
        }
    }
    
    gSystemInfo.jailbreakInfo.rootPath = strdup("/");
    return error;
}

- (BOOL)isArm64e
{
    cpu_subtype_t cpusubtype = 0;
    size_t len = sizeof(cpusubtype);
    if (sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0) == -1) return NO;
    return (cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
}

- (BOOL)isSPTM
{
    if (@available(iOS 17.0, *)) {
        io_registry_entry_t memory_map = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen/memory-map");
        if (memory_map == IO_OBJECT_NULL)   return NO;

        CFArrayRef keys = (CFArrayRef)IORegistryEntryCreateCFProperty(memory_map, CFSTR(kIORegistryEntryPropertyKeysKey), kCFAllocatorDefault, 0);
        IOObjectRelease(memory_map);
        if (!keys)  return NO;

        CFRange range = CFRangeMake(0, CFArrayGetCount(keys));

        bool isSPTM = CFArrayContainsValue(keys, range, CFSTR("SPTM")) && CFArrayContainsValue(keys, range, CFSTR("TXM"));
        CFRelease(keys);

        return isSPTM;
    }
    return false;
}

- (NSString *)versionSupportString
{
    return @"iOS 16.0 - 16.7.16 (ROOTFUL - SSV BYPASSED)";
}

- (BOOL)isInstalledThroughTrollStore
{
    static BOOL trollstoreInstallation = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString* trollStoreMarkerPath = [[[NSBundle mainBundle].bundlePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"_TrollStore"];
        trollstoreInstallation = [[NSFileManager defaultManager] fileExistsAtPath:trollStoreMarkerPath];
    });
    return trollstoreInstallation;
}

- (void)updateJailbreakState
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        char *jbVersionC = NULL;
        _isJailbroken = jbclient_dopamine_is_jailbroken(&jbVersionC);
        if (jbVersionC) {
            _jailbrokenVersion = [NSString stringWithUTF8String:jbVersionC];
            free(jbVersionC);
        }
    });
}

- (BOOL)isJailbroken
{
    [self updateJailbreakState];
    return _isJailbroken;
}

- (void)setJailbroken:(BOOL)jailbroken withVersion:(NSString *)version
{
    _isJailbroken = jailbroken;
    if (_isJailbroken) _jailbrokenVersion = version;
}

- (BOOL)isJailbrokenWithOtherJailbreak
{
    if (![self isJailbroken]) {
        uint32_t csFlags = 0;
        csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
        if (csFlags & CS_PLATFORM_BINARY) return YES;
    }
    return NO;
}

- (NSString *)jailbrokenVersion
{
    [self updateJailbreakState];
    if (!_isJailbroken) return nil;
    return _jailbrokenVersion;
}

- (NSString *)systemVersion
{
    return (__bridge NSString *)MGCopyAnswer((__bridge CFStringRef)@"ProductVersion");
}

- (BOOL)isBootstrapped
{
    return YES;
}

- (void)runUnsandboxed:(void (^)(void))unsandboxBlock
{
    unsandboxBlock();
}

- (void)runAsRoot:(void (^)(void))rootBlock
{
    rootBlock();
}

- (int)spawnJbctlAsRootWithArgs:(NSArray *)args
{
    char **argBuf = malloc((args.count + 2) * sizeof(char *));
    argBuf[0] = strdup("/bin/sh");
    int i = 1;
    for (NSString *arg in args) {
        argBuf[i++] = strdup(arg.UTF8String);
    }
    argBuf[i++] = NULL;
    
    pid_t pid = 0;
    int r = posix_spawn(&pid, argBuf[0], NULL, NULL, (char *const *)argBuf, (char *const *)environ);
    
    for (int y = 0; y < i; y++) {
        free(argBuf[y]);
    }
    free(argBuf);

    return cmd_wait_for_exit(pid);
}

- (int)runTrollStoreAction:(NSString *)action
{
    return 0;
}

- (void)respring
{
    exec_cmd("/usr/bin/killall", "SpringBoard", NULL);
}

- (void)rebootUserspace
{
    reboot3(0x8000000000000000, 0);
}

- (void)rebuildIconCache
{
    exec_cmd("/usr/bin/uicache", "-a", NULL);
}

- (void)refreshJailbreakApps
{
    exec_cmd("/usr/bin/uicache", "-a", NULL);
}

- (void)unregisterJailbreakApps
{
}

- (void)reboot
{
    reboot3(0x8000000000000000, 0);
}

- (void)changeMobilePassword:(NSString *)newPassword
{
    NSString *dashCommand = [NSString stringWithFormat:@"printf \"%%s\\n\" \"%@\" | usermod 501 -h 0", newPassword];
    exec_cmd("/bin/sh", "-c", dashCommand.UTF8String, NULL);
}

- (NSError*)updateEnvironment
{
    return nil;
}

- (void)updateJailbreakFromTIPA:(NSString *)tipaPath
{
}

- (BOOL)isTweakInjectionEnabled
{
    return ![[NSFileManager defaultManager] fileExistsAtPath:@"/basebin/.safe_mode"];
}

- (void)setTweakInjectionEnabled:(BOOL)enabled
{
    NSString *safeModePath = @"/basebin/.safe_mode";
    if (enabled) {
        [[NSFileManager defaultManager] removeItemAtPath:safeModePath error:nil];
    }
    else {
        [[NSData data] writeToFile:safeModePath atomically:YES];
    }
}

- (BOOL)isIDownloadEnabled
{
    return YES;
}

- (void)setIDownloadEnabled:(BOOL)enabled needsUnsandbox:(BOOL)needsUnsandbox
{
}

- (void)setIDownloadLoaded:(BOOL)loaded needsUnsandbox:(BOOL)needsUnsandbox
{
}

- (BOOL)isFakelibMounted
{
    return YES;
}

- (int)setFakelibMounted:(BOOL)mounted
{
    return 0;
}

- (int)setPrivatePrebootProtected:(BOOL)protected
{
    return 0;
}

- (BOOL)isJailbreakHidden
{
    return NO;
}

- (void)setJailbreakHidden:(BOOL)hidden
{
}

- (NSString *)accessibleKernelPath
{
    NSString *kernelInApp = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"kernelcache"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInApp]) {
        NSLog(@"[+] Kernelcache tìm thấy trong Bundle: %@", kernelInApp);
        return kernelInApp;
    }

    NSString *kernelInDocs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kernelcache"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInDocs]) {
        NSLog(@"[+] Kernelcache tìm thấy trong Documents: %@", kernelInDocs);
        return kernelInDocs;
    }

    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *kernelcachePath = [[self activePrebootPath] stringByAppendingPathComponent:@"System/Library/Caches/com.apple.kernelcaches/kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            NSLog(@"[+] Kernelcache tìm thấy trong preboot: %@", kernelcachePath);
            return kernelcachePath;
        }
    }

    NSLog(@"[-] Không tìm thấy kernelcache cục bộ, bắt đầu tải bằng libgrabkernel2...");
    [[DOUIManager sharedInstance] sendLog:@"Downloading Kernel" debug:NO];
    
    NSString *docsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (grab_images(docsDir) == false) {
        NSLog(@"[-] libgrabkernel2 tải thất bại!");
        return nil;
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInDocs]) {
        NSLog(@"[+] libgrabkernel2 tải thành công: %@", kernelInDocs);
        return kernelInDocs;
    }

    NSLog(@"[-] grab_images báo thành công nhưng không thấy file kernelcache trong Documents!");
    return nil;
}

- (NSString *)accessibleSPTMPath
{
    return nil;
}

- (NSString *)accessibleTXMPath
{
    return nil;
}

- (BOOL)isPACBypassRequired
{
    return NO;
}

- (BOOL)isPPLBypassRequired
{
    return NO;
}

- (BOOL)isSupported
{
    return YES;
}

- (BOOL)deviceSupportsFaceID
{
    if (![LAContext class]) return NO;
    LAContext *myContext = [[LAContext alloc] init];
    NSError *authError = nil;
    if (![myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
        return NO;
    }
    return myContext.biometryType == LABiometryTypeFaceID;
}

- (BOOL)deviceSupportsLandscapeBootLogo
{
    struct utsname u;
    uname(&u);
    bool isPad = strncmp(u.machine, "iPad", 4) == 0;
    return isPad && [self deviceSupportsFaceID];
}

- (NSError *)prepareBootstrap
{
    return nil;
}

- (NSError *)finalizeBootstrap
{
    return nil;
}

- (NSError *)deleteBootstrap
{
    return nil;
}

- (NSError *)reinstallPackageManagers
{
    return nil;
}

- (NSError *)updateBootLogo
{
    return nil;
}

@end
