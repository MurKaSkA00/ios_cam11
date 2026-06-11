// AntifraudHooks.x - MediaPlaybackUtils v1.4.5
// ФИКС: добавлен Security framework, sysctl защищён от краша,
//       все хуки обёрнуты в проверки на nil

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <QuartzCore/QuartzCore.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <substrate.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <dlfcn.h>

// ─── Helper: строки которые выдают джейл ─────────────────────────────────────

static BOOL _af_is_jb_string(NSString *s) {
    if (!s || s.length == 0) return NO;
    static NSArray *jbStrings = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        jbStrings = @[
            @"MobileSubstrate", @"libsubstrate", @"libhooker", @"libellekit",
            @"Substitute",      @"TweakInject",
            @"MediaPlaybackUtils", @"proximacore",
            @"Cydia",           @"Sileo",
            @"palera1n",        @"unc0ver", @"checkra1n",
            @"electra",         @"taurine",
        ];
    });
    for (NSString *k in jbStrings) {
        if ([s containsString:k]) return YES;
    }
    return NO;
}

// ─── 1. NSStringFromClass — скрываем _MPU суффикс ────────────────────────────

static NSString *(*orig_NSStringFromClass)(Class) = NULL;
static NSString *hook_NSStringFromClass(Class cls) {
    NSString *r = orig_NSStringFromClass ? orig_NSStringFromClass(cls) : NSStringFromClass(cls);
    if (r && [r hasSuffix:@"_MPU"])
        return [r substringToIndex:r.length - 4];
    return r;
}

// ─── 2. objc_getAssociatedObject — скрываем overlay ──────────────────────────

static id (*orig_objc_getAssociatedObject)(id, const void *) = NULL;
static id hook_objc_getAssociatedObject(id object, const void *key) {
    if (key && strcmp((const char *)key, "_v_overlay") == 0) return nil;
    return orig_objc_getAssociatedObject
        ? orig_objc_getAssociatedObject(object, key)
        : objc_getAssociatedObject(object, key);
}

// ─── 3. SecItemCopyMatching — скрываем jb-артефакты из keychain ──────────────
// ФИКС: проверка что orig_SecItemCopyMatching не NULL перед вызовом

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (!orig_SecItemCopyMatching) return errSecItemNotFound;
    @try {
        if (query) {
            CFStringRef svc = CFDictionaryGetValue(query, kSecAttrService);
            CFStringRef acc = CFDictionaryGetValue(query, kSecAttrAccount);
            NSString *s = svc ? (__bridge NSString *)svc : nil;
            NSString *a = acc ? (__bridge NSString *)acc : nil;
            if (_af_is_jb_string(s) || _af_is_jb_string(a))
                return errSecItemNotFound;
        }
        return orig_SecItemCopyMatching(query, result);
    } @catch (...) {
        return orig_SecItemCopyMatching(query, result);
    }
}

// ─── 4. sysctl — скрываем P_TRACED ───────────────────────────────────────────
// ФИКС: весь хук в @try/@catch — раньше мог крашить любое приложение

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                       void *newp, size_t newlen) {
    if (!orig_sysctl) return EINVAL;
    int r = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    @try {
        if (r == 0 && namelen >= 4 && name &&
            name[0] == CTL_KERN && name[1] == KERN_PROC &&
            name[2] == KERN_PROC_PID && oldp && oldlenp &&
            *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    } @catch (...) {
        // тихо — не крашим приложение
    }
    return r;
}

// ─── 5. NSProcessInfo — скрываем DYLD_INSERT_LIBRARIES ───────────────────────

%hook NSProcessInfo

- (NSDictionary<NSString *, NSString *> *)environment {
    NSDictionary *orig = %orig;
    if (!orig) return orig;
    NSMutableDictionary *clean = [orig mutableCopy];
    [clean removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [clean removeObjectForKey:@"_MSSafeMode"];
    [clean removeObjectForKey:@"_SafeMode"];
    return clean;
}

%end

// ─── 6. NSBundle — скрываем твик ─────────────────────────────────────────────

%hook NSBundle

+ (NSBundle *)bundleWithIdentifier:(NSString *)identifier {
    if (_af_is_jb_string(identifier)) return nil;
    return %orig;
}

%end

// ─── 7. AVCaptureVideoPreviewLayer — скрываем overlay из sublayers ────────────

%hook AVCaptureVideoPreviewLayer

- (NSArray<CALayer *> *)sublayers {
    NSArray<CALayer *> *orig = %orig;
    if (!orig || !orig_objc_getAssociatedObject) return orig;
    CALayer *overlay = (CALayer *)orig_objc_getAssociatedObject(self, "_v_overlay");
    if (!overlay) return orig;
    NSMutableArray *clean = [orig mutableCopy];
    [clean removeObject:overlay];
    return clean;
}

%end

// ─── 8. UIApplication — скрываем jb URL схемы ────────────────────────────────

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    NSString *scheme = url.scheme.lowercaseString;
    if (!scheme) return %orig;
    if ([scheme isEqualToString:@"cydia"])     return NO;
    if ([scheme isEqualToString:@"sileo"])     return NO;
    if ([scheme isEqualToString:@"zbra"])      return NO;
    if ([scheme isEqualToString:@"undecimus"]) return NO;
    if ([scheme isEqualToString:@"activator"]) return NO;
    if ([scheme isEqualToString:@"apt-repo"])  return NO;
    return %orig;
}

%end

// ─── ИНИЦИАЛИЗАЦИЯ ────────────────────────────────────────────────────────────

%ctor {
    @autoreleasepool {
        NSString *bid  = [[NSBundle mainBundle] bundleIdentifier];
        NSString *path = [[NSBundle mainBundle] bundlePath];
        if (!bid) return;

        // Системные процессы
        if ([bid hasPrefix:@"com.apple."]) return;
        if ([path hasPrefix:@"/usr/"])     return;
        if ([path hasPrefix:@"/System/"])  return;

        // jb-инструменты — не трогаем
        if ([bid isEqualToString:@"org.coolstar.SileoStore"]) return;
        if ([bid isEqualToString:@"com.tigisoftware.Filza"])   return;
        if ([bid isEqualToString:@"xyz.willy.Zebra"])          return;
        if ([bid hasPrefix:@"com.opa334.TrollStore"])          return;
        if ([bid hasPrefix:@"com.palera1n"])                   return;
        if ([bid hasPrefix:@"org.coolstar."])                  return;
        if ([bid hasPrefix:@"org.theos."])                     return;
        if ([bid hasPrefix:@"science.xnu."])                   return;

        // ФИКС: проверяем что функции реально доступны перед хуком
        void *secLib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);

        if (orig_NSStringFromClass == NULL)
            MSHookFunction((void *)NSStringFromClass,
                           (void *)hook_NSStringFromClass,
                           (void **)&orig_NSStringFromClass);

        if (orig_objc_getAssociatedObject == NULL)
            MSHookFunction((void *)objc_getAssociatedObject,
                           (void *)hook_objc_getAssociatedObject,
                           (void **)&orig_objc_getAssociatedObject);

        // SecItemCopyMatching — только если Security фреймворк загрузился
        if (secLib) {
            void *secFn = dlsym(secLib, "SecItemCopyMatching");
            if (secFn && orig_SecItemCopyMatching == NULL)
                MSHookFunction(secFn,
                               (void *)hook_SecItemCopyMatching,
                               (void **)&orig_SecItemCopyMatching);
        }

        // sysctl — аккуратно
        if (orig_sysctl == NULL)
            MSHookFunction((void *)sysctl,
                           (void *)hook_sysctl,
                           (void **)&orig_sysctl);

        %init;
        NSLog(@"[MPU/Antifrod] Installed for %@", bid);
    }
}
