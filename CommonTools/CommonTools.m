//
//  CommonTools.m
//  CommonTools
//
//  Created by WeiJun on 8/14/15.
//  Copyright (c) 2015 Daniel. All rights reserved.
//

#import "CommonTools.h"
#import <SystemConfiguration/CaptiveNetwork.h>

#include <arpa/inet.h>
#include <ifaddrs.h>

@import NetworkExtension;

@implementation WifiInfoClass

@synthesize bssid;
@synthesize ssid;

@end

@implementation LocalIPInfoClass

@synthesize currentInterfaceIP;
@synthesize wifiIP;
@synthesize cellularIP;

@end

NSString *const GOOD_IRI_CHAR = @"a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF";
NSString *const TOP_LEVEL_DOMAIN_STR_FOR_WEB_URL = @"(?:(?:aero|arpa|asia|a[cdefgilmnoqrstuwxz])|(?:biz|b[abdefghijmnorstvwyz])|(?:cat|com|coop|c[acdfghiklmnoruvxyz])|d[ejkmoz]|(?:edu|e[cegrstu])|f[ijkmor]|(?:gov|g[abdefghilmnpqrstuwy])|h[kmnrtu]|(?:info|int|i[delmnoqrst])|(?:jobs|j[emop])|k[eghimnprwyz]|l[abcikrstuvy]|(?:mil|mobi|museum|m[acdeghklmnopqrstuvwxyz])|(?:name|net|n[acefgilopruz])|(?:org|om)|(?:pro|p[aefghklmnrstwy])|qa|r[eosuw]|s[abcdeghijklmnortuvyz]|(?:tel|travel|t[cdfghjklmnoprtvwz])|u[agksyz]|v[aceginu]|w[fs]|(?:xn\\-\\-0zwm56d|xn\\-\\-11b5bs3a9aj6g|xn\\-\\-80akhbyknj4f|xn\\-\\-9t4b11yi5a|xn\\-\\-deba0ad|xn\\-\\-g6w251d|xn\\-\\-hgbk6aj7f53bba|xn\\-\\-hlcj6aya9esc7a|xn\\-\\-jxalpdlp|xn\\-\\-kgbechtv|xn\\-\\-zckzah)|y[etu]|z[amw]))";

@implementation CommonTools

#pragma mark - Library Info

+ (NSString*)getLibraryVersion{
    return @"1.0.20010160";
}

#pragma mark - About System

+ (NSInteger)getIosVersionNumber{
    NSArray *vComp = [[UIDevice currentDevice].systemVersion componentsSeparatedByString:@"."];
    return [[vComp objectAtIndex:0] intValue];
}

+ (NSString*)getIosVersionString{
    UIDevice * device = [UIDevice currentDevice];
    return [device systemVersion];
}

+ (NSString*)getAppVersionName{
    NSString *path = [[NSBundle mainBundle] bundlePath];
    NSString *finalPath = [path stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *plistData = [NSDictionary dictionaryWithContentsOfFile:finalPath];
    NSString *version = [plistData objectForKey:@"CFBundleVersion"];
    return version;
}

+ (CGSize)getScreenSize{
    CGSize rtnSize;
    
    CGRect screenRect = [[UIScreen mainScreen] bounds];
    CGFloat screenHeight = screenRect.size.height;
    CGFloat screenWidth = screenRect.size.width;
    CGFloat setHeight = screenHeight;
    CGFloat setWidth = screenWidth;
    
    if([[UIApplication sharedApplication] statusBarOrientation] == UIInterfaceOrientationLandscapeLeft
       || [[UIApplication sharedApplication] statusBarOrientation] == UIInterfaceOrientationLandscapeRight)
    {//if landscape mode , switch width and height
        setHeight = screenWidth;
        setWidth = screenHeight;
    }
    
    rtnSize = CGSizeMake(setWidth, setHeight);
    return rtnSize;
}

#pragma mark - About Network
+ (Reachability*)startReachability {
    Reachability *reachability = [Reachability reachabilityForInternetConnection];
    
    return reachability;
}

+ (NetworkStatus)detectNetworkInterface{
    Reachability *reachability = [Reachability reachabilityForInternetConnection];
    [reachability startNotifier];
    
    return [reachability currentReachabilityStatus];
}

+ (void)fetchWifiInfoWithCompletionHandler:(void (^)(WifiInfoClass *))completionHandler {
    
    if (@available(iOS 14.0, *)) {
        [NEHotspotNetwork fetchCurrentWithCompletionHandler:^(NEHotspotNetwork * _Nullable currentNetwork) {
            if (currentNetwork) {
                WifiInfoClass* wifiInfo = [WifiInfoClass new];
                wifiInfo.ssid = currentNetwork.SSID;
                wifiInfo.bssid = currentNetwork.BSSID;
                completionHandler(wifiInfo);
                return;
            }
            completionHandler(nil);
        }];
        return;
    }
    
    NSArray *interfaces = CFBridgingRelease(CNCopySupportedInterfaces());
    
    for (NSString *interfaceName in interfaces) {
        NSDictionary *SSIDInfo = CFBridgingRelease(
                                                   CNCopyCurrentNetworkInfo((__bridge CFStringRef)interfaceName));
        
        if (SSIDInfo) {
            WifiInfoClass* wifiInfo = [WifiInfoClass new];
            wifiInfo.bssid = [CommonTools standardFormateMAC:[SSIDInfo objectForKey:@"BSSID"]];
            wifiInfo.ssid = [SSIDInfo objectForKey:@"SSID"];
            completionHandler(wifiInfo);
            return;
        }
        
    }
    
    completionHandler(nil);
    
}

+ (NSString *)standardFormateMAC:(NSString *)MAC
{
    NSArray* subStr = [MAC componentsSeparatedByString:@":"];
    NSMutableArray* subStr_M = [NSMutableArray array];
    for (NSString* str in subStr) {
        if (1 == str.length) {
            NSString* tmpStr = [NSString stringWithFormat:@"0%@",str];
            [subStr_M addObject:tmpStr];
        }else{
            [subStr_M addObject:str];
        }
    }
    NSString* formateMAC = [subStr_M componentsJoinedByString:@":"];
    return [formateMAC uppercaseString];
}

+ (LocalIPInfoClass*)getLocalIPInfo{
    NSString* wifiAddress = nil;
    NSString* wifiNetMask = nil;
    NSString* cellAddress = nil;
    NSString* cellNetMask = nil;
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                // Check if interface is en0 which is the wifi connection on the iPhone
                if([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    // Get NSString from C String
                    wifiAddress = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                    wifiNetMask = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_netmask)->sin_addr)];
                }
                if ([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"pdp_ip0"]) {
                    cellAddress = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                    cellNetMask = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_netmask)->sin_addr)];
                }
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    // Free memory
    freeifaddrs(interfaces);
    
    LocalIPInfoClass* localIPInfo = [LocalIPInfoClass new];
    localIPInfo.wifiIP = wifiAddress;
    localIPInfo.wifiMask = wifiNetMask;
    localIPInfo.cellularIP = cellAddress;
    localIPInfo.cellularMask = cellNetMask;
    if (wifiAddress) {
        localIPInfo.currentInterfaceIP = wifiAddress;
        localIPInfo.currentInterfaceMask = wifiNetMask;
        return localIPInfo;
    }
    
    localIPInfo.currentInterfaceIP = cellAddress;
    localIPInfo.currentInterfaceMask = cellNetMask;
    return localIPInfo;
}

+(NSString*)getIPNetworkSegment:(NSString *)ip WithSubnetMask:(NSString *)subnetMask{
    if ([ip rangeOfString:@"."].location == NSNotFound || [subnetMask rangeOfString:@"."].location == NSNotFound) {
        return nil;
    }
    
    NSArray* ipArray = [[CommonTools fixIPFormate:ip] componentsSeparatedByString:@"."];
    NSArray* maskArray = [[CommonTools fixIPFormate:subnetMask] componentsSeparatedByString:@"."];
    
    if ([ipArray count] !=4 || [maskArray count] != 4) {
        return  nil;
    }
    
    NSMutableArray* segmentArray = [NSMutableArray array];
    
    for (int i = 0; i < [ipArray count]; i++) {
        int ipOctet = [ipArray[i] intValue];
        int maskOctet = [maskArray[i] intValue];
        int segmentOctet = (ipOctet & maskOctet);
        [segmentArray addObject:[NSString stringWithFormat:@"%d",segmentOctet]];
    }
    
    return [NSString stringWithFormat:@"%@.%@.%@.%@",segmentArray[0],segmentArray[1],segmentArray[2],segmentArray[3]];
}

+(NSString*)getIPBroadcast:(NSString *)ip WithSubnetMask:(NSString *)subnetMask{
    if ([ip rangeOfString:@"."].location == NSNotFound || [subnetMask rangeOfString:@"."].location == NSNotFound) {
        return nil;
    }
    
    NSArray* ipArray = [[CommonTools fixIPFormate:ip] componentsSeparatedByString:@"."];
    NSArray* maskArray = [[CommonTools fixIPFormate:subnetMask] componentsSeparatedByString:@"."];
    
    if ([ipArray count] !=4 || [maskArray count] != 4) {
        return  nil;
    }
    
    NSMutableArray* broadcastArray = [NSMutableArray array];
    
    for (int i = 0; i < [ipArray count]; i++) {
        int ipOctet = [ipArray[i] intValue];
        int maskOctet = [maskArray[i] intValue];
        int broadcastOctet = (ipOctet | (255 - maskOctet));
        [broadcastArray addObject:[NSString stringWithFormat:@"%d",broadcastOctet]];
    }
    
    return [NSString stringWithFormat:@"%@.%@.%@.%@",broadcastArray[0],broadcastArray[1],broadcastArray[2],broadcastArray[3]];
}

+ (unsigned int)getDecFromHex:(NSString*)hex
{
    unsigned int result = 0;
    NSScanner *scanner = [NSScanner scannerWithString:hex];
    [scanner scanHexInt:&result];
    return result;
}

+ (NSString *)getIPV6FromMac:(NSString *)mac ForTest:(BOOL)forTest
{
    if (!mac || mac.length == 0) {
        return @"";
    }
    
    NSMutableArray* macArray = [NSMutableArray array];
    NSMutableArray* macValueArray = [NSMutableArray array];
    
    for (int i = 0; i < [mac length]; i++) {
        NSString *ch = [mac substringWithRange:NSMakeRange(i, 1)];
        if (![ch isEqualToString:@":"]) {
            [macArray addObject:ch];
        }
    }
    
    if (macArray.count != 12) {
        return @"";
    }
    
    NSInteger x = 0;
    while (x < macArray.count) {
        unsigned int macValue = [CommonTools getDecFromHex:macArray[x]] * 16;
        x++;
        macValue = macValue + [CommonTools getDecFromHex:macArray[x]];
        x++;
        [macValueArray addObject:@(macValue)];
    }
    
    NSMutableString* ipv6String = nil;
    if (forTest) {
        ipv6String = [[NSMutableString alloc] initWithString:@"fc00::"];
    } else {
        ipv6String = [[NSMutableString alloc] initWithString:@"fe80::"];
    }
    
    if (0 == ([macValueArray[0] unsignedIntValue] ^ 0x02)) {
        if (0 != [macValueArray[1] unsignedIntValue]) {
            [ipv6String appendFormat:@"%x:",[macValueArray[1] unsignedIntValue]];
        }
    }else{
        [ipv6String appendFormat:@"%x%02x:",[macValueArray[0] unsignedIntValue] ^ 0x02,[macValueArray[1] unsignedIntValue]];
    }
    
    if (0 == [macValueArray[2] unsignedIntValue]) {
        [ipv6String appendFormat:@"ff:fe%02x:",[macValueArray[3] unsignedIntValue]];
    }else{
        [ipv6String appendFormat:@"%xff:fe%02x:",[macValueArray[2] unsignedIntValue],[macValueArray[3] unsignedIntValue]];
    }
    
    if (0 == [macValueArray[4] unsignedIntValue]) {
        if (0 == [macValueArray[5] unsignedIntValue]) {
            [ipv6String appendFormat:@"0"];
        }else{
            [ipv6String appendFormat:@"%x",[macValueArray[5] unsignedIntValue]];
        }
    }else
    {
        [ipv6String appendFormat:@"%x%02x",[macValueArray[4] unsignedIntValue],[macValueArray[5] unsignedIntValue]];
    }
    
    return ipv6String;
}

#pragma mark - About Image
+ (UIImage*)imageWithImage:(UIImage *)image scaledToSize:(CGSize)newSize {
    UIGraphicsBeginImageContextWithOptions(newSize, NO, 0.0);
    [image drawInRect:CGRectMake(0, 0, newSize.width, newSize.height)];
    UIImage *newImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return newImage;
}

+ (UIImage *)imageWithImage:(UIImage *)image scaledWithPercent:(CGFloat)percent {
    CGSize newSize = CGSizeMake(image.size.width * percent, image.size.height * percent);
    return [CommonTools imageWithImage:image scaledToSize:newSize];
}

+ (UIImage*)circleImage:(UIImage *)image withParm:(CGFloat)inset{
    UIGraphicsBeginImageContext(image.size);
    CGContextRef context=UIGraphicsGetCurrentContext();
    CGContextSetLineWidth(context, 2);
    CGContextSetStrokeColorWithColor(context, [UIColor clearColor].CGColor);
    CGRect rect=CGRectMake(inset, inset, image.size.width-inset*2.0f, image.size.height-inset*2.0f);
    CGContextAddEllipseInRect(context, rect);
    CGContextClip(context);
    
    [image drawInRect:rect];
    CGContextAddEllipseInRect(context, rect);
    CGContextStrokePath(context);
    UIImage *newimg=UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return newimg;
}

+ (UIImage*)imageByCropping:(UIImage *)imageToCrop toRect:(CGRect)rect
{
    CGImageRef tmp = CGImageCreateWithImageInRect(imageToCrop.CGImage, rect);
    UIImage *timage = [UIImage imageWithCGImage:tmp];
    CGImageRelease(tmp);
    return timage;
}

+ (UIImage*)imageWithColor:(UIColor *)color Size:(CGSize)size{
    CGRect rect = CGRectMake(0.f, 0.f, size.width, size.height);
    UIGraphicsBeginImageContext(size);
    CGContextRef context = UIGraphicsGetCurrentContext();
    
    CGContextSetFillColorWithColor(context, [color CGColor]);
    CGContextFillRect(context, rect);
    
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    
    return image;
}

+(UIImage *)circleImageWIthColor:(UIColor *)color Size:(CGSize)size{
    UIImage* colorImage = [CommonTools imageWithColor:color Size:size];
    return [CommonTools circleImage:colorImage withParm:0];
}

+(UIImage *)snapshot:(UIView *)view{
    UIGraphicsBeginImageContextWithOptions(view.bounds.size, YES, [UIScreen mainScreen].scale);
    [view drawViewHierarchyInRect:view.bounds afterScreenUpdates:YES];
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    
    return image;
}

#pragma mark - About String
+ (NSString *)truncateBackItemTitle:(NSString *)barItemTitle withMainTitle:(NSString *)mainTitle
{
    CGFloat width = [CommonTools getScreenSize].width;
    NSInteger maxLength = (NSInteger)roundf(width*0.048);
    NSInteger leftLength = maxLength - roundf((float)mainTitle.length/2.0);
    if (barItemTitle.length > leftLength) {
        NSString* shortString = [barItemTitle substringToIndex:leftLength-3];
        return [NSString stringWithFormat:@"%@...",shortString];
    }
    return barItemTitle;
}

#pragma mark - About Convert
+(NSString *)decToBinary:(NSInteger)decInt
{
    NSString *string = @"" ;
    NSInteger x = decInt ;
    do {
        string = [[NSString stringWithFormat: @"%ld", (long)(x&1)] stringByAppendingString:string];
    } while (x >>= 1);
    return string;
}

+ (NSString *)getJSONStringFromJSONObject:(id)jsonObject
{
    if (![NSJSONSerialization isValidJSONObject:jsonObject]) {
        return nil;
    }
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:jsonObject
                                                       options:0
                                                         error:nil];
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

#pragma mark - About Format Check
+(BOOL)checkIsAllDigits:(NSString*)str{
    NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
    return r.location == NSNotFound;
}

+ (BOOL)checkUIDFormateValid:(NSString *)uid{
    if (!uid)
        return NO;
    
    if (uid.length != 7)
        return NO;
    
    if ([[uid stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] length] != 7)
        return NO;
    
    if ([uid rangeOfString:@" "].location != NSNotFound)
        return NO;
    
    if (![NSURL URLWithString:[NSString stringWithFormat:@"%@.domain.com",uid]])
        return NO;
    
    if (![CommonTools regularCheck:@"^[\\x00-\\x7F]+$" checkStr:uid])
        return NO;
    
    if ([uid isEqualToString:@"0000000"]) {
        return NO;
    }
    
    return YES;
}

+ (BOOL)checkEmailFormateValid:(NSString *)mail{
    BOOL stricterFilter=YES;
    NSString *stricterFilterString = @"[A-Z0-9a-z\\._%+-]+@([A-Za-z0-9-]+\\.)+[A-Za-z]{2,4}";
    NSString *laxString = @".+@([A-Za-z0-9]+\\.)+[A-Za-z]{2}[A-Za-z]*";
    NSString *emailRegex = stricterFilter ? stricterFilterString : laxString;
    NSPredicate *emailTest = [NSPredicate predicateWithFormat:@"SELF MATCHES %@", emailRegex];
    return [emailTest evaluateWithObject:mail];
}

+ (BOOL)checkSSIDValid:(NSString *)ssid{
    NSString* tmpString = [ssid stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    
    if (tmpString.length == 0) {
        return NO;
    }
    
    if (tmpString.length > 32) {
        return NO;
    }
    
    NSData* tmpData = [tmpString dataUsingEncoding:NSUTF8StringEncoding];
    if (tmpData.length == 0) {
        return NO;
    }
    
    if (tmpData.length > 32) {
        return NO;
    }
    
    if(![CommonTools regularCheck:@"^[\\x00-\\x7F]+$" checkStr:tmpString]){
        return NO;
    }
    
    return YES;
}

+(WPAInvalidType)checkWPAKeyValid:(NSString *)key{
    if (key) {
        if (key.length < 8) {
            return InvalidWPALengthType;
        }
        
        if (key.length > 64) {
            return InvalidWPALengthType;
        }
        
        if (key.length == 64) {
            if (![CommonTools regularCheck:@"^([a-f]|[A-F]|[0-9]){64}$" checkStr:key]) {
                return  InvalidWPAHEXType;
            }
        }else{
            if (![CommonTools regularCheck:@"^[\\x00-\\x7F]+$" checkStr:key]) {
                return InvalidWPAASCIIType;
            }
        }
        
        return ValidWPAType;
    }
    return InvalidWPALengthType;
}

+(WEPInvalidType)checkWEPKeyValid:(NSString *)key{
    WEPInvalidType type = ValidWEPType;
    
    if (key.length == 5 || key.length == 13 || key.length == 16) {
        if (![CommonTools regularCheck:[NSString stringWithFormat:@"^(\\d|\\D){%zd}$",key.length] checkStr:key]) {
            type = InvalidWEPASCIIType;
        }
    }else if (key.length == 10 || key.length == 26 || key.length == 32){
        if (![CommonTools regularCheck:[NSString stringWithFormat:@"[a-fA-F0-9]{%zd}",key.length] checkStr:key]) {
            type = InvalidWEPHEXType;
        }
    }else{
        type = InvalidWEPLengthType;
    }
    
    return type;
}

+(BOOL)checkSubnetMaskBinary:(NSArray*)subnetMaskArray
{
    if ([subnetMaskArray count] != 4) {
        return NO;
    }
    
    NSMutableString* binString = [[NSMutableString alloc] initWithString:@""];
    
    for (int i=0; i<4; i++) {
        if (![CommonTools checkIsAllDigits:subnetMaskArray[i]]) {
            return NO;
        }
        
        int num = [subnetMaskArray[i] intValue];
        
        if (num < 0 || num > 255) {
            return NO;
        }
        
        NSMutableString* zeroString = [[NSMutableString alloc] initWithString:@""];
        NSString* numBinString = [CommonTools decToBinary:num];
        if (numBinString.length < 8) {
            for (int j=0; j < (8-numBinString.length); j++) {
                [zeroString appendFormat:@"0"];
            }
        }
        [binString appendFormat:@"%@",zeroString];
        [binString appendFormat:@"%@",numBinString];
    }
    
    if (binString.length == 0) {
        return NO;
    }
    
    return [CommonTools regularCheck:@"^1*0*$" checkStr:binString];
}

+(BOOL)checkSubnetMaskValid:(NSString *)subnetMask{
    if ([CommonTools checkHasFullWidthWord:subnetMask]) {
        return NO;
    }
    
    NSArray* strArray = [[CommonTools fixIPFormate:subnetMask] componentsSeparatedByString:@"."];
    if (![CommonTools checkSubnetMaskBinary:strArray]) {
        return NO;
    }
    return [CommonTools regularCheck:@"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}0" checkStr:[CommonTools fixIPFormate:subnetMask]];
}

+(BOOL)checkServerGatewayValid:(NSString *)serverGateway
{
    if (serverGateway == nil) {
        return NO;
    }
    
    if (serverGateway.length == 0) {
        return NO;
    }
    
    if ([serverGateway isEqualToString:@"0.0.0.0"]) {
        return NO;
    }
    
    if ([serverGateway isEqualToString:@"127.0.0.1"]) {
        return NO;
    }
    
    if ([NSURL URLWithString:serverGateway] == nil) {
        return NO;
    }
    
    if (!([CommonTools checkStaticIPInfo:serverGateway Type:StaticIPInfoGatewayType] || [CommonTools checkHostnameValid:serverGateway])) {
        return NO;
    }
    
    return YES;
}


+(BOOL)checkPortValid:(NSInteger)port MinValue:(NSInteger)minValue MaxValue:(NSInteger)maxValue{
    if (port > maxValue || port < minValue) {
        return NO;
    }
    return YES;
}

+(BOOL)checkIPV4AddressValid:(NSString *)ipaddr{
    if ([CommonTools checkHasFullWidthWord:ipaddr]) {
        return NO;
    }
    return [CommonTools regularCheck:@"^(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5]).(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5]).(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5]).(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])$" checkStr:[CommonTools fixIPFormate:ipaddr]];
}

+ (BOOL)checkDomainValid:(NSString *)domain
{
    NSMutableString* pattern = [[NSMutableString alloc] initWithString:@"((?:(http|https|Http|Https|rtsp|Rtsp):\\/\\/(?:(?:[a-zA-Z0-9\\$\\-\\_\\.\\+\\!\\*\\'\\(\\)"];
    [pattern appendString:@"\\,\\;\\?\\&\\=]|(?:\\%[a-fA-F0-9]{2})){1,64}(?:\\:(?:[a-zA-Z0-9\\$\\-\\_"];
    [pattern appendString:@"\\.\\+\\!\\*\\'\\(\\)\\,\\;\\?\\&\\=]|(?:\\%[a-fA-F0-9]{2})){1,25})?\\@)?)?"];
    [pattern appendFormat:@"((?:(?:[%@][%@\\-]{0,64}\\.)+",GOOD_IRI_CHAR,GOOD_IRI_CHAR]; // named host
    [pattern appendFormat:@"%@",TOP_LEVEL_DOMAIN_STR_FOR_WEB_URL];
    [pattern appendString:@"|(?:(?:25[0-5]|2[0-4]"]; // or ip address
    [pattern appendString:@"[0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\\.(?:25[0-5]|2[0-4][0-9]"];
    [pattern appendString:@"|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(?:25[0-5]|2[0-4][0-9]|[0-1]"];
    [pattern appendString:@"[0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}"];
    [pattern appendString:@"|[1-9][0-9]|[0-9])))"];
    [pattern appendString:@"(?:\\:\\d{1,5})?)"]; // plus option port number
    [pattern appendString:@"(\\/(?:(?:[a-zA-Z0-9\\;\\/\\?\\:\\@\\&\\=\\#\\~"]; // plus option query params
    [pattern appendString:@"\\-\\.\\+\\!\\*\\'\\(\\)\\,\\_])|(?:\\%[a-fA-F0-9]{2}))*)?"];
    [pattern appendString:@"(?:\\b|$)"];// and finally, a word boundary or end of input.  This is to stop foo.sure from matching as foo.su
    return [CommonTools regularCheck:pattern checkStr:domain];
}

+(BOOL)checkStaticIPInfo:(NSString *)ip Type:(StaticIPInfoType)type{
    
    if (!ip) {
        return NO;
    }
    
    if ([CommonTools checkHasFullWidthWord:ip]) {
        return NO;
    }
    
    if ([[CommonTools fixIPFormate:ip] isEqualToString:@"0.0.0.0"]) {
        switch (type) {
            case StaticIPInfoIPType:
            {
                return NO;
            }
                break;
            case StaticIPInfoGatewayType:
            {
                return YES;
            }
                break;
        }
    }
    
    NSArray* numArray = [[CommonTools fixIPFormate:ip] componentsSeparatedByString:@"."];
    if (numArray.count != 4) {
        return NO;
    }
    
    for (int i=0; i<4; i++) {
        if (![CommonTools checkIsAllDigits:numArray[i]]) {
            return NO;
        }
        
        int digit = [numArray[i] intValue];
        if (digit < 0) {
            return NO;
        }
        if (digit > 255) {
            return NO;
        }
        
        if (i == 0) {
            if (digit < 1 || digit > 223) {
                return NO;
            }
        }
        
        if (i == 3) {
            if (digit < 1 || digit > 254) {
                return NO;
            }
        }
    }
    
    if (![CommonTools checkIPV4AddressValid:ip]) {
        return NO;
    }
    
    if ([[CommonTools getIPNetworkSegment:@"127.0.0.1" WithSubnetMask:@"255.0.0.0"] isEqualToString:[CommonTools getIPNetworkSegment:ip WithSubnetMask:@"255.0.0.0"]]) {
        return NO;
    }
    
    if ([[CommonTools getIPNetworkSegment:@"169.254.0.1" WithSubnetMask:@"255.255.0.0"] isEqualToString:[CommonTools getIPNetworkSegment:ip WithSubnetMask:@"255.255.0.0"]]) {
        return NO;
    }
    
    if ([CommonTools regularCheck:@"^(22[4-9]|2[3-4][0-9]|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])$" checkStr:ip]) {
        return NO;
    }
    
    return YES;
}

+(BOOL)checkHostnameValid:(NSString *)hostname{
    return [CommonTools regularCheck:@"^[a-zA-Z0-9]\\w{0,30}$" checkStr:hostname];
}

+(BOOL)checkHasFullWidthWord:(NSString*)string{
    return [CommonTools regularCheck:@"[^\\x00-\\xff]" checkStr:string];
}

+(BOOL)regularCheck:(NSString*)pattern checkStr:(NSString*)checkStr{
    if (!checkStr || checkStr.length == 0) {
        return NO;
    }
    
    NSString* trimCheckStr = [checkStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    
    if (!trimCheckStr || trimCheckStr.length == 0) {
        return NO;
    }
    
    NSPredicate *pred = [NSPredicate predicateWithFormat:@"SELF MATCHES %@", pattern];
    if ([pred evaluateWithObject: checkStr]){
        return YES;
    }else{
        return NO;
    }
}

+ (BOOL)checkIsHexadecima:(NSString *)string {
    NSCharacterSet *chars = [[NSCharacterSet
                              characterSetWithCharactersInString:@"0123456789ABCDEF"] invertedSet];
    return NSNotFound == [string rangeOfCharacterFromSet:chars].location;
}

+(NSString*)fixIPFormate:(NSString*)ip{
    //    example: 10.0.053.122 -- replace to -- > 10.0.53.122
    NSArray* tokArray = [ip componentsSeparatedByString:@"."];
    NSMutableString* retString = [[NSMutableString alloc] initWithString:@""];
    
    for (int i = 0; i<tokArray.count; i++) {
        NSString* lastOneString=(i==tokArray.count-1)?@"":@".";
        NSString* tok = tokArray[i];
        if (tok.length >= 2) {
            if ([CommonTools checkIsAllDigits:tok] &&
                [[tok substringToIndex:1] isEqualToString:@"0"])
                tok = [NSString stringWithFormat:@"%d",tok.intValue];
        }
        [retString appendString:tok];
        [retString appendString:lastOneString];
    }
    
    return retString;
}

#pragma mark - About Web View
+ (void)loadDocument:(NSString *)documentName inWKView:(WKWebView *)documentWebView
{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *path = [[NSBundle mainBundle] pathForResource:documentName ofType:nil];
        NSString *html = [NSString stringWithContentsOfFile:path
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
        NSURL *url = [NSURL fileURLWithPath:path];
        NSString *headerString = @"<header><meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no'></header>";
        [documentWebView loadHTMLString:[headerString stringByAppendingString:html] baseURL:url];
    });
}

+ (void)loadDocument:(NSString *)documentName withType:(NSString *)type inWKView:(WKWebView *)documentWebView{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *path = [[NSBundle mainBundle] pathForResource:documentName ofType:type];
        NSString *html = [NSString stringWithContentsOfFile:path
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
        NSURL *url = [NSURL fileURLWithPath:path];
        NSString *headerString = @"<header><meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no'></header>";
        [documentWebView loadHTMLString:[headerString stringByAppendingString:html] baseURL:url];
    });
}

+ (void)loadDocumentPath:(NSString *)path inWKView:(WKWebView *)documentWebView{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *html = [NSString stringWithContentsOfFile:path
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
        NSURL *url = [NSURL fileURLWithPath:path];
        NSString *headerString = @"<header><meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no'></header>";
        [documentWebView loadHTMLString:[headerString stringByAppendingString:html] baseURL:url];
    });
}

#pragma mark - About Version Number
+ (BOOL)checkVersionNumber:(NSString *)version isNewerThan:(NSString *)standardVersion{
    if ([standardVersion compare:version options:NSNumericSearch] == NSOrderedAscending) {
        return YES;
    }
    return NO;
}

+ (BOOL)checkVersionNumber:(NSString *)version isLowerThan:(NSString *)standardVersion{
    if ([standardVersion compare:version options:NSNumericSearch] == NSOrderedDescending) {
        return YES;
    }
    return NO;
}

+ (BOOL)checkVersionNumber:(NSString *)version isSameWith:(NSString *)standardVersion{
    if ([standardVersion compare:version options:NSNumericSearch] == NSOrderedSame) {
        return YES;
    }
    return NO;
}

@end
