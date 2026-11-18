//
//  main.m
//  Dopamine
//
//  Created by Lars Fröder on 23.09.23.
//  Modified by Olimi Engine for Rootful iOS 16.0 - 16.7.16
//

#import <UIKit/UIKit.h>
#import "DOAppDelegate.h"

#import "DOEnvironmentManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/jbclient_xpc.h>

int main(int argc, char * argv[]) {
    if (argc >= 3) {
        if (!strcmp(argv[1], "trollstore")) {
            if (!strcmp(argv[2], "delete-bootstrap")) {
                [[DOEnvironmentManager sharedManager] deleteBootstrap];
            }
            else if (!strcmp(argv[2], "hide-jailbreak")) {
                // Rootful không hỗ trợ ẩn jailbreak theo kiểu rootless
                [[DOEnvironmentManager sharedManager] setJailbreakHidden:NO];
            }
            return 0;
        }
    }
    
    if (argc >= 2) {
        if (!strcmp(argv[1], "prepare_jbupdate")) {
            [[DOEnvironmentManager sharedManager] reboot];
            return 0;
        }
    }
    
    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        // --- OLIMI ROOTFUL PATH ENVIRONMENT SETUP ---
        // Trỏ trực tiếp PATH vào phân vùng hệ thống gốc thay vì /var/jb giả lập
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("TERM", "xterm-256color", 1);
        // ---------------------------------------------
    }
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        appDelegateClassName = NSStringFromClass([DOAppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
