// ../../Application/Dopamine/Jailbreak/DOEnvironmentManager.m

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
#import <xpf.h> // Giả định xpf.h chứa khai báo của xpf_item_resolve

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
            // Ép buộc phân vùng gốc cho rootful thay vì dùng jbclient_get_jbroot()
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

    // The boot-manifest hash is hexadecimal data. Validate it before
    // passing the bytes to Foundation, which can throw on malformed input.
    size_t hashLength = strnlen(hash, 129);
    if (hashLength == 0 || hashLength > 128 || (hashLength & 1) != 0) {
        return nil;
    }

    for (size_t i = 0; i < hashLength; i++) {
        char c = hash[i];
        BOOL isHexDigit = (c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F');
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
    // Đối với Rootful trên iOS 16, thư mục gốc chính là phân vùng System đã được mount RW
    gSystemInfo.jailbreakInfo.rootPath = strdup("/");
}

// Thêm các define offset thực tế cho iOS 16
#define VNODE_V_MOUNT_OFFSET 0x48
#define MOUNT_MNT_FLAG_OFFSET 0x70
#define MNT_RDONLY 0x00000001
#define MNT_ROOTFS 0x00004000 // Cờ này cũng cần xóa để tránh bị chặn

- (NSError *)ensureJailbreakRootExists
{
    NSError *error = nil;
    
    NSLog(@"[+] Olimi Engine: Tiến hành bẻ văng SSV và mở khóa phân vùng APFS Root Read-Write trên iOS 16...");
    
    // Lấy địa chỉ rootvnode động thông qua XPF, tránh hardcode offset
    uint64_t rootvnode = xpf_item_resolve("kernelSymbol.rootvnode");
    if (!rootvnode) {
        NSLog(@"[-] Không thể resolve kernelSymbol.rootvnode qua XPF.");
    } else {
        NSLog(@"[+] rootvnode resolved at: 0x%llx", rootvnode);
        
        // 1. Đọc con trỏ v_mount từ rootvnode
        uint64_t v_mount = kread64(rootvnode + VNODE_V_MOUNT_OFFSET);
        if (v_mount) {
            // 2. Đọc mnt_flag từ mount structure
            uint32_t mnt_flag = kread32(v_mount + MOUNT_MNT_FLAG_OFFSET);
            NSLog(@"[+] mnt_flag ban đầu: 0x%x", mnt_flag);
            
            // 3. Xóa cả MNT_RDONLY và MNT_ROOTFS
            uint32_t new_flags = mnt_flag & ~(MNT_RDONLY | MNT_ROOTFS);
            
            if (new_flags != mnt_flag) {
                kwrite32(v_mount + MOUNT_MNT_FLAG_OFFSET, new_flags);
                NSLog(@"[+] Đã gỡ cờ MNT_RDONLY và MNT_ROOTFS. mnt_flag mới: 0x%x", new_flags);
            } else {
                NSLog(@"[+] Các cờ đã được gỡ trước đó.");
            }
        } else {
            NSLog(@"[-] Không thể đọc v_mount từ rootvnode.");
        }
    }

    // 4. Tạo thư mục /procursus (sẽ thành công nếu việc gỡ cờ ở trên hiệu quả)
    NSString *bootstrapPath = @"/procursus";
    if (![[NSFileManager defaultManager] fileExistsAtPath:bootstrapPath]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:bootstrapPath withIntermediateDirectories:YES attributes:nil error:&error];
        if (error) {
            NSLog(@"[-] Lỗi tạo /procursus: %@", error.localizedDescription);
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
    return YES; // Luôn trả về YES cho Rootful
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
    // Userspace reboot cho rootful
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
    // Rootful không cần unregister rườm rà
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
    // Rootful update qua dpkg
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
    // Daemons management
}

- (void)setIDownloadLoaded:(BOOL)loaded needsUnsandbox:(BOOL)needsUnsandbox
{
    // Daemons management
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
    return NO; // Rootful không ẩn jailbreak kiểu rootless
}

- (void)setJailbreakHidden:(BOOL)hidden
{
    // Rootful không hỗ trợ ẩn jailbreak giả lập var/jb
}

- (NSString *)accessibleKernelPath
{
    // 1. Kiểm tra kernelcache có sẵn trong Bundle app
    NSString *kernelInApp = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"kernelcache"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInApp]) {
        NSLog(@"[+] Kernelcache tìm thấy trong Bundle: %@", kernelInApp);
        return kernelInApp;
    }

    // 2. Kiểm tra trong Documents (phòng trường hợp đã tải trước đó)
    NSString *kernelInDocs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kernelcache"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInDocs]) {
        NSLog(@"[+] Kernelcache tìm thấy trong Documents: %@", kernelInDocs);
        return kernelInDocs;
    }

    // 3. Kiểm tra trong preboot (nếu có quyền)
    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *kernelcachePath = [[self activePrebootPath] stringByAppendingPathComponent:@"System/Library/Caches/com.apple.kernelcaches/kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            NSLog(@"[+] Kernelcache tìm thấy trong preboot: %@", kernelcachePath);
            return kernelcachePath;
        }
    }

    // 4. Không có ở đâu cả -> Tải bằng libgrabkernel2
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
