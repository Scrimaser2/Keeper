#import <AppKit/AppKit.h>
#import <AVKit/AVKit.h>
#import <PDFKit/PDFKit.h>
#import <QuickLookUI/QuickLookUI.h>
#import <ImageIO/ImageIO.h>
#import <CoreServices/CoreServices.h>
#import <math.h>
#import <stdio.h>
#import <stdlib.h>

@interface LibraryMediaDelegate : NSObject <NSApplicationDelegate, QLPreviewPanelDataSource, QLPreviewPanelDelegate>
@property(nonatomic, copy) NSString *temporaryDirectory;
@property(nonatomic, strong) NSURL *previewURL;
@end

@implementation LibraryMediaDelegate
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    if (self.temporaryDirectory.length > 0) {
        [[NSFileManager defaultManager] removeItemAtPath:self.temporaryDirectory error:nil];
    }
}

- (NSInteger)numberOfPreviewItemsInPreviewPanel:(QLPreviewPanel *)panel {
    return self.previewURL == nil ? 0 : 1;
}

- (id<QLPreviewItem>)previewPanel:(QLPreviewPanel *)panel previewItemAtIndex:(NSInteger)index {
    return self.previewURL;
}
@end

static NSWindow *LibraryNewWindow(NSRect frame, NSString *title) {
    NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                 NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    window.title = title;
    window.minSize = NSMakeSize(640, 420);
    [window setReleasedWhenClosed:NO];
    return window;
}

static int LibraryDecodeThumbnail(NSString *filePath, int64_t maxPixels, int maxDimension) {
    NSURL *url = [NSURL fileURLWithPath:filePath];
    CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
    if (source == NULL) return 5;

    NSDictionary *properties = CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source, 0, NULL));
    CGFloat width = [properties[(__bridge NSString *)kCGImagePropertyPixelWidth] doubleValue];
    CGFloat height = [properties[(__bridge NSString *)kCGImagePropertyPixelHeight] doubleValue];
    if (width <= 0 || height <= 0) {
        CFRelease(source);
        return 6;
    }

    CGFloat scale = 1.0;
    CGFloat pixels = width * height;
    if (maxPixels > 0 && pixels > maxPixels) scale = sqrt((CGFloat)maxPixels / pixels);
    CGFloat longest = MAX(width, height) * scale;
    if (maxDimension > 0 && longest > maxDimension) longest = maxDimension;
    NSUInteger target = MAX(1, (NSUInteger)floor(longest));
    NSDictionary *options = @{
        (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
        (__bridge NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
        (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @(target)
    };
    CGImageRef image = CGImageSourceCreateThumbnailAtIndex(source, 0, (__bridge CFDictionaryRef)options);
    CFRelease(source);
    if (image == NULL) return 7;

    CFMutableDataRef pngData = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(pngData, CFSTR("public.png"), 1, NULL);
    if (destination == NULL) {
        CGImageRelease(image);
        CFRelease(pngData);
        return 8;
    }
    CGImageDestinationAddImage(destination, image, NULL);
    BOOL finalized = CGImageDestinationFinalize(destination);
    CFRelease(destination);
    CGImageRelease(image);
    if (!finalized) {
        CFRelease(pngData);
        return 9;
    }
    size_t length = (size_t)CFDataGetLength(pngData);
    size_t written = fwrite(CFDataGetBytePtr(pngData), 1, length, stdout);
    fflush(stdout);
    CFRelease(pngData);
    return written == length ? 0 : 10;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 4) return 2;
        NSString *kind = [NSString stringWithUTF8String:argv[1]];
        NSString *filePath = [NSString stringWithUTF8String:argv[2]];
        NSString *temporaryDirectory = [NSString stringWithUTF8String:argv[3]];
        NSURL *fileURL = [NSURL fileURLWithPath:filePath];

        if ([kind isEqualToString:@"thumbnail"]) {
            if (argc < 6) return 2;
            return LibraryDecodeThumbnail(filePath, atoll(argv[4]), atoi(argv[5]));
        }

        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        LibraryMediaDelegate *delegate = [LibraryMediaDelegate new];
        delegate.temporaryDirectory = temporaryDirectory;
        NSApp.delegate = delegate;

        NSRect frame = NSMakeRect(0, 0, 1100, 760);
        NSWindow *window = nil;

        if ([kind isEqualToString:@"video"]) {
            window = LibraryNewWindow(frame, fileURL.lastPathComponent);
            AVPlayerView *view = [[AVPlayerView alloc] initWithFrame:frame];
            view.controlsStyle = AVPlayerViewControlsStyleDefault;
            view.player = [AVPlayer playerWithURL:fileURL];
            window.contentView = view;
            [view.player play];
        } else if ([kind isEqualToString:@"pdf"]) {
            window = LibraryNewWindow(frame, fileURL.lastPathComponent);
            PDFView *view = [[PDFView alloc] initWithFrame:frame];
            view.autoScales = YES;
            view.displayMode = kPDFDisplaySinglePageContinuous;
            view.document = [[PDFDocument alloc] initWithURL:fileURL];
            if (view.document == nil) return 3;
            window.contentView = view;
        } else if ([kind isEqualToString:@"quicklook"]) {
            delegate.previewURL = fileURL;
            QLPreviewPanel *panel = [QLPreviewPanel sharedPreviewPanel];
            panel.dataSource = delegate;
            panel.delegate = delegate;
            [panel setTitle:fileURL.lastPathComponent];
            [panel makeKeyAndOrderFront:nil];
        } else if ([kind isEqualToString:@"richtext"]) {
            window = LibraryNewWindow(frame, fileURL.lastPathComponent);
            NSString *extension = fileURL.pathExtension.lowercaseString;
            NSString *documentType = [extension isEqualToString:@"doc"]
                ? NSDocFormatTextDocumentType : NSRTFTextDocumentType;
            NSError *error = nil;
            NSAttributedString *text = [[NSAttributedString alloc] initWithURL:fileURL
                options:@{NSDocumentTypeDocumentAttribute: documentType}
                documentAttributes:nil error:&error];
            if (text == nil) return 4;
            NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:frame];
            scroll.hasVerticalScroller = YES;
            scroll.hasHorizontalScroller = YES;
            NSTextView *view = [[NSTextView alloc] initWithFrame:frame];
            view.editable = NO;
            view.selectable = YES;
            [view.textStorage setAttributedString:text];
            scroll.documentView = view;
            window.contentView = scroll;
        } else {
            return 2;
        }

        if (window != nil) {
            [window center];
            [window makeKeyAndOrderFront:nil];
        }
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];
    }
    return 0;
}
