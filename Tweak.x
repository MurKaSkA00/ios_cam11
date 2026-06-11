// Tweak.x - MediaPlaybackUtils v1.4.4
// - Работает во ВСЕХ приложениях с камерой (Telegram, PayPal, Instagram и т.д.)
// - Не крашит приложения без камеры
// - Фикс застывшего кадра при переключении камеры
// - Фикс фото — сохраняется со стрима, а не с реальной камеры

#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import "_MPUMediaBufferAdapter.h"

#define MPU_PREFS_ID CFSTR("com.proximacore.mediaplaybackutils")

static BOOL              _enabled         = YES;
static NSString         *_url             = @"http://192.168.1.44:8888/live/stream/index.m3u8";
static _MPUMediaBufferAdapter *_reader    = nil;
static CVPixelBufferRef  _lastBuffer      = NULL;
static CFTimeInterval    _lastBufferTime  = 0;  // время последнего кадра
static id                _v_lock          = nil;
static CIContext        *_v_ciContext     = nil;
static NSString         *_currentStreamURL = nil;

static void _v_loadPrefs(void) {
    CFPreferencesAppSynchronize(MPU_PREFS_ID);

    CFPropertyListRef en = CFPreferencesCopyAppValue(CFSTR("enabled"), MPU_PREFS_ID);
    if (en) {
        if (CFGetTypeID(en) == CFBooleanGetTypeID())
            _enabled = CFBooleanGetValue((CFBooleanRef)en);
        CFRelease(en);
    }

    CFPropertyListRef u = CFPreferencesCopyAppValue(CFSTR("rtspURL"), MPU_PREFS_ID);
    if (u) {
        if (CFGetTypeID(u) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)u;
            if (s.length > 0) _url = [s copy];
        }
        CFRelease(u);
    }
}

static void _v_restartStreamIfNeeded(void) {
    @synchronized(_v_lock) {
        if (_reader && ![_currentStreamURL isEqualToString:_url]) {
            NSLog(@"[MPU] URL changed, restarting stream");
            [_reader stopStreaming];
            _reader = nil;
            if (_lastBuffer) { CVPixelBufferRelease(_lastBuffer); _lastBuffer = NULL; }
            _lastBufferTime = 0;
            _currentStreamURL = nil;
        }
        if (!_reader && _enabled) {
            NSURL *u = [NSURL URLWithString:_url];
            if (!u) return;
            _currentStreamURL = [_url copy];
            _reader = [[_MPUMediaBufferAdapter alloc] initWithURL:u];
            _reader.pixelBufferCallback = ^(CVPixelBufferRef buffer) {
                if (!buffer) return;
                @synchronized(_v_lock) {
                    if (_lastBuffer) CVPixelBufferRelease(_lastBuffer);
                    _lastBuffer = CVPixelBufferRetain(buffer);
                    _lastBufferTime = CACurrentMediaTime(); // фиксируем время кадра
                }
            };
            [_reader startStreaming];
            NSLog(@"[MPU] Stream started: %@", _url);
        }
    }
}

static void _v_init(void) {
    _v_restartStreamIfNeeded();
}

static void _v_prefsChanged(CFNotificationCenterRef c, void *o, CFStringRef n,
                             const void *obj, CFDictionaryRef i) {
    _v_loadPrefs();
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        _v_restartStreamIfNeeded();
    });
}

static CMSampleBufferRef _v_makeReplacementSampleBuffer(CMSampleBufferRef original) {
    CVPixelBufferRef src = NULL;
    @synchronized(_v_lock) {
        if (_lastBuffer) src = CVPixelBufferRetain(_lastBuffer);
    }
    if (!src) return NULL;

    CMVideoFormatDescriptionRef fmt = NULL;
    if (CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault, src, &fmt) != noErr || !fmt) {
        CVPixelBufferRelease(src);
        return NULL;
    }

    CMSampleTimingInfo timing;
    if (!original || CMSampleBufferGetSampleTimingInfo(original, 0, &timing) != noErr) {
        timing.duration = CMTimeMake(1, 30);
        timing.presentationTimeStamp = CMTimeMakeWithSeconds(CACurrentMediaTime(), 1000000);
        timing.decodeTimeStamp = kCMTimeInvalid;
    }

    CMSampleBufferRef out = NULL;
    OSStatus s = CMSampleBufferCreateReadyWithImageBuffer(kCFAllocatorDefault, src, fmt, &timing, &out);
    CFRelease(fmt);
    CVPixelBufferRelease(src);
    return (s == noErr) ? out : NULL;
}

// ========================================
// 1. ПЕРЕХВАТ ДЕЛЕГАТА ВИДЕО-ВЫВОДА
// Безопасный свиззлинг — не крашит Telegram, PayPal, React Native приложения
// ========================================

%hook AVCaptureVideoDataOutput

- (void)setSampleBufferDelegate:(id<AVCaptureVideoDataOutputSampleBufferDelegate>)delegate
                          queue:(dispatch_queue_t)queue {
    if (!_enabled || !delegate) { %orig; return; }

    _v_init();

    static NSMutableSet *swizzledClasses = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ swizzledClasses = [NSMutableSet new]; });

    Class cls = object_getClass(delegate);
    if (!cls) { %orig; return; }

    NSString *clsName = NSStringFromClass(cls);

    // Пропускаем классы которые гарантированно сломаются при свиззлинге
    if (!clsName ||
        [clsName hasPrefix:@"RCT"]        ||  // React Native (Telegram, Instagram)
        [clsName hasPrefix:@"WK"]         ||  // WebKit
        [clsName hasPrefix:@"WebKit"]     ||  // WebKit internal
        [clsName hasPrefix:@"_NS"]        ||  // приватные NSFoundation
        [clsName hasPrefix:@"__NS"]       ||  // приватные NSFoundation
        [clsName hasPrefix:@"_UI"]        ||  // приватные UIKit
        [clsName containsString:@"Internal"] ||
        [clsName hasPrefix:@"_"]) {
        %orig;
        return;
    }

    SEL sel = @selector(captureOutput:didOutputSampleBuffer:fromConnection:);

    @synchronized(swizzledClasses) {
        if (![swizzledClasses containsObject:clsName]) {
            Method m = class_getInstanceMethod(cls, sel);
            if (m) {
                const char *types = method_getTypeEncoding(m);
                IMP origIMP = method_getImplementation(m);
                __block IMP capturedIMP = origIMP;

                IMP newIMP = imp_implementationWithBlock(^(id self_,
                                                           AVCaptureOutput *output,
                                                           CMSampleBufferRef sb,
                                                           AVCaptureConnection *conn) {
                    // @try/@catch — если что-то пошло не так, приложение не крашится
                    @try {
                        CMSampleBufferRef replacement = (_enabled && sb)
                            ? _v_makeReplacementSampleBuffer(sb) : NULL;

                        CMSampleBufferRef toUse = replacement ? replacement : sb;
                        if (toUse) {
                            ((void(*)(id,SEL,AVCaptureOutput*,CMSampleBufferRef,AVCaptureConnection*))
                                capturedIMP)(self_, sel, output, toUse, conn);
                        }
                        if (replacement) CFRelease(replacement);
                    } @catch (NSException *ex) {
                        // Тихо логируем и вызываем оригинал — приложение продолжает работать
                        NSLog(@"[MPU] Hook exception in %@: %@", clsName, ex.reason);
                        @try {
                            if (sb)
                                ((void(*)(id,SEL,AVCaptureOutput*,CMSampleBufferRef,AVCaptureConnection*))
                                    capturedIMP)(self_, sel, output, sb, conn);
                        } @catch (...) {}
                    }
                });

                BOOL added = class_addMethod(cls, sel, newIMP, types);
                if (!added) {
                    IMP prev = class_replaceMethod(cls, sel, newIMP, types);
                    if (prev) capturedIMP = prev;
                }
                [swizzledClasses addObject:clsName];
                NSLog(@"[MPU] Hooked delegate: %@", clsName);
            }
        }
    }

    %orig;
}

%end

// ========================================
// 2. ПЕРЕХВАТ ФОТО
// Фото сохраняется со стрима, не с реальной камеры
// ========================================

%hook AVCapturePhoto

- (CVPixelBufferRef)pixelBuffer {
    @synchronized(_v_lock) {
        if (_enabled && _lastBuffer)
            return (CVPixelBufferRef)CFAutorelease(CFRetain(_lastBuffer));
    }
    return %orig;
}

- (NSData *)fileDataRepresentation {
    @synchronized(_v_lock) {
        if (!_enabled || !_lastBuffer) return %orig;

        if (!_v_ciContext) {
            _v_ciContext = [CIContext contextWithOptions:@{kCIContextUseSoftwareRenderer: @NO}];
        }

        CIImage *ci = [CIImage imageWithCVPixelBuffer:_lastBuffer];
        if (!ci) { NSLog(@"[MPU] Photo: CIImage nil, fallback"); return %orig; }

        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGImageRef cg = [_v_ciContext createCGImage:ci
                                           fromRect:ci.extent
                                             format:kCIFormatBGRA8
                                         colorSpace:cs];
        CGColorSpaceRelease(cs);

        if (!cg) { NSLog(@"[MPU] Photo: CGImage nil, fallback"); return %orig; }

        NSData *d = UIImageJPEGRepresentation([UIImage imageWithCGImage:cg], 0.92);
        CGImageRelease(cg);

        if (!d) { NSLog(@"[MPU] Photo: JPEG nil, fallback"); return %orig; }

        NSLog(@"[MPU] Photo saved from stream (%lu bytes)", (unsigned long)d.length);
        return d;
    }
}

%end

// ========================================
// 3. ПРЕДПРОСМОТР КАМЕРЫ
// Фикс: сброс overlay при переключении камеры + проверка актуальности кадра
// ========================================

%hook AVCaptureVideoPreviewLayer

- (void)layoutSublayers {
    %orig;
    if (!_enabled) return;
    _v_init();

    CALayer *overlay = objc_getAssociatedObject(self, "_v_overlay");
    if (!overlay) {
        overlay = [CALayer layer];
        overlay.contentsGravity = kCAGravityResizeAspectFill;
        overlay.zPosition = 999999;
        overlay.backgroundColor = [UIColor blackColor].CGColor;
        overlay.opaque = YES;
        [self addSublayer:overlay];
        objc_setAssociatedObject(self, "_v_overlay", overlay, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

        CADisplayLink *dl = [CADisplayLink displayLinkWithTarget:self
                                                        selector:@selector(_mpu_updateOverlay:)];
        dl.preferredFramesPerSecond = 30;
        [dl addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
        objc_setAssociatedObject(self, "_v_displayLink", dl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }

    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    overlay.frame = self.bounds;
    overlay.hidden = NO;
    overlay.opacity = 1.0;
    overlay.contents = nil; // сбрасываем при переключении камеры
    [CATransaction commit];
}

%new
- (void)_mpu_updateOverlay:(CADisplayLink *)sender {
    if (!_enabled) return;
    CALayer *overlay = objc_getAssociatedObject(self, "_v_overlay");
    if (!overlay) return;

    @synchronized(_v_lock) {
        // Буфер старше 500ms — кадр устарел (переключение камеры / потеря стрима)
        CFTimeInterval age = CACurrentMediaTime() - _lastBufferTime;
        if (!_lastBuffer || age > 0.5) {
            [CATransaction begin];
            [CATransaction setDisableActions:YES];
            overlay.contents = nil;
            [CATransaction commit];
            return;
        }

        IOSurfaceRef surf = CVPixelBufferGetIOSurface(_lastBuffer);
        if (surf) {
            [CATransaction begin];
            [CATransaction setDisableActions:YES];
            overlay.contents = (__bridge id)surf;
            overlay.frame = self.bounds;
            [CATransaction commit];
        }
    }
}

%end

// ========================================
// 4. ИНИЦИАЛИЗАЦИЯ УСТРОЙСТВА
// ========================================

%hook AVCaptureDevice

+ (AVCaptureDevice *)defaultDeviceWithMediaType:(AVMediaType)mediaType {
    if (_enabled && [mediaType isEqualToString:AVMediaTypeVideo]) _v_init();
    return %orig;
}

+ (AVCaptureDevice *)defaultDeviceWithDeviceType:(AVCaptureDeviceType)deviceType
                                       mediaType:(AVMediaType)mediaType
                                        position:(AVCaptureDevicePosition)position {
    if (_enabled && [mediaType isEqualToString:AVMediaTypeVideo]) _v_init();
    return %orig;
}

%end

// ========================================
// ИНИЦИАЛИЗАЦИЯ ТВИКА
// ========================================

%ctor {
    @autoreleasepool {
        NSString *bid  = [[NSBundle mainBundle] bundleIdentifier];
        NSString *path = [[NSBundle mainBundle] bundlePath];

        if (!bid) return;

        // Системные процессы — не трогаем
        if ([bid hasPrefix:@"com.apple.springboard"])      return;
        if ([bid hasPrefix:@"com.apple.WebKit"])            return;
        if ([bid hasPrefix:@"com.apple.mediaserverd"])      return;
        if ([bid hasPrefix:@"com.apple.assetsd"])           return;
        if ([bid hasPrefix:@"com.apple.coremedia"])         return;
        if ([bid hasPrefix:@"com.apple.avconferenced"])     return;
        if ([bid hasPrefix:@"com.apple.cameracaptured"])    return;
        if ([path hasPrefix:@"/usr/"])                      return;
        if ([path hasPrefix:@"/System/Library/"])           return;

        _v_lock      = [NSObject new];
        _v_ciContext = [CIContext contextWithOptions:@{kCIContextUseSoftwareRenderer: @NO}];

        _v_loadPrefs();

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(), NULL, _v_prefsChanged,
            CFSTR("com.proximacore.mediaplaybackutils/prefsChanged"),
            NULL, CFNotificationSuspensionBehaviorDeliverImmediately);

        if (_enabled) {
            NSLog(@"[MPU] Loaded in: %@  url=%@", bid, _url);
            %init;
        } else {
            NSLog(@"[MPU] Disabled for: %@", bid);
        }
    }
}
