// iOS14-style SEA reference key as UIK; the native N56 SEP has no system UIK.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

extern const CFStringRef kSecAttrTokenIDAppleKeyStore;
extern const CFStringRef kSecAttrTokenOID;
extern const CFStringRef kSecAttrKeyTypeSecureEnclaveAttestation;
extern const CFStringRef kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate;
extern SecKeyRef SecKeyCopySystemKey(uint32_t, CFErrorRef *);
extern char *container_system_group_path_for_identifier(void *, const char *, int *);

static const uint32_t copy_uik_flag = 0x40000000;
static const uint32_t uik_action = UINT32_MAX - 1;
static pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor))
static void adapter_loaded(void) {
    NSLog(@"N56UIK: legacy adapter loaded");
}

static NSError *key_error(CFErrorRef error) {
    return error ? CFBridgingRelease(error) :
        [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecInternalComponent userInfo:nil];
}

static NSURL *key_directory(NSError **error) {
    int code = 0;
    char *path = container_system_group_path_for_identifier(
        NULL, "systemgroup.com.apple.mobileactivationd", &code);
    if (!path) {
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil];
        return nil;
    }
    NSURL *directory = [[NSURL fileURLWithPath:@(path) isDirectory:YES]
        URLByAppendingPathComponent:@"Library/uik" isDirectory:YES];
    free(path);
    if (![[NSFileManager defaultManager] createDirectoryAtURL:directory
            withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone} error:error]) return nil;
    return directory;
}

static NSMutableDictionary *key_parameters(CFErrorRef *error) {
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        NULL, kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate, kSecAccessControlPrivateKeyUsage, error);
    if (!access) return nil;
    return [@{
        (__bridge id)kSecAttrIsPermanent: @NO,
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDAppleKeyStore,
        (__bridge id)kSecAttrAccessControl: CFBridgingRelease(access)
    } mutableCopy];
}

static SecKeyRef read_key(NSURL *file, NSError **error) {
    NSData *reference = [NSData dataWithContentsOfURL:file options:0 error:error];
    if (!reference) return NULL;
    CFErrorRef failure = NULL;
    NSMutableDictionary *parameters = key_parameters(&failure);
    if (!parameters) {
        if (error) *error = key_error(failure);
        else if (failure) CFRelease(failure);
        return NULL;
    }
    parameters[(__bridge id)kSecAttrTokenOID] = reference;
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)[NSData data],
        (__bridge CFDictionaryRef)parameters, &failure);
    if (!key) {
        if (error) *error = key_error(failure);
        else if (failure) CFRelease(failure);
    }
    return key;
}

static SecKeyRef generate_key(NSURL *file, NSError **error) {
    CFErrorRef failure = NULL;
    NSMutableDictionary *parameters = key_parameters(&failure);
    if (!parameters) {
        if (error) *error = key_error(failure);
        else if (failure) CFRelease(failure);
        return NULL;
    }
    parameters[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeSecureEnclaveAttestation;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)parameters, &failure);
    if (!key) {
        if (error) *error = key_error(failure);
        else if (failure) CFRelease(failure);
        return NULL;
    }
    NSDictionary *attributes = CFBridgingRelease(SecKeyCopyAttributes(key));
    NSData *reference = attributes[(__bridge id)kSecAttrTokenOID];
    if (![reference isKindOfClass:[NSData class]] ||
        ![reference writeToURL:file options:NSDataWritingAtomic | NSDataWritingFileProtectionNone error:error]) {
        if (!reference && error) *error = key_error(NULL);
        CFRelease(key);
        return NULL;
    }
    NSLog(@"N56UIK: generated legacy SEA reference");
    return key;
}

static SecKeyRef copy_key(BOOL committed, NSError **error) {
    NSURL *directory = key_directory(error);
    if (!directory) return NULL;
    NSURL *pending = [directory URLByAppendingPathComponent:@"n56-pending.key"];
    NSURL *current = [directory URLByAppendingPathComponent:@"n56-committed.key"];
    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *wanted = committed ? current : pending;
    if ([files fileExistsAtPath:wanted.path]) return read_key(wanted, error);
    NSURL *other = committed ? pending : current;
    if ([files fileExistsAtPath:other.path]) return read_key(other, error);
    return generate_key(pending, error);
}

static int perform_action(unsigned action) {
    NSError *error = nil;
    NSURL *directory = key_directory(&error);
    BOOL success = NO;
    if (directory) {
        NSURL *pending = [directory URLByAppendingPathComponent:@"n56-pending.key"];
        NSURL *current = [directory URLByAppendingPathComponent:@"n56-committed.key"];
        if (action == 1) {
            SecKeyRef key = generate_key(pending, &error);
            success = key != NULL;
            if (key) CFRelease(key);
        } else if (action == 2) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:pending.path]) {
                success = rename(pending.fileSystemRepresentation, current.fileSystemRepresentation) == 0;
                if (!success) error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
            } else {
                success = [[NSFileManager defaultManager] fileExistsAtPath:current.path];
            }
            if (success) NSLog(@"N56UIK: committed legacy SEA reference");
        }
    }
    if (!success) NSLog(@"N56UIK: action %u failed %@ (%ld)", action, error.domain, (long)error.code);
    return success ? 0 : (int)0xe00002c2;
}

// The daemon's existing Security import is also the entry for two small
// adapters: copy_uik(flag, legacy*, error**) and begin/commit(action).
static SecKeyRef n56_copy_system_key(uint32_t type, CFErrorRef *error, NSError **legacy_error) {
    if (!(type & copy_uik_flag) && type != uik_action && type != 2 && type != 3)
        return SecKeyCopySystemKey(type, error);
    SecKeyRef result;
    NSError *saved_error = nil;
    BOOL adapted_copy = type != uik_action && (type & copy_uik_flag) != 0;
    @autoreleasepool {
        pthread_mutex_lock(&key_lock);
        if (type == uik_action) {
            result = (SecKeyRef)(uintptr_t)(uint32_t)perform_action((unsigned)(uintptr_t)error);
        } else {
            NSError *failure = nil;
            BOOL committed = adapted_copy ? (type & 1) != 0 : type == 2;
            result = copy_key(committed, &failure);
            if (adapted_copy) {
                if (error) *(BOOL *)error = YES;
                if (!result) saved_error = failure;
            } else if (!result && error) {
                *error = (__bridge_retained CFErrorRef)failure;
            }
            if (!result) NSLog(@"N56UIK: read failed %@ (%ld)", failure.domain, (long)failure.code);
        }
        pthread_mutex_unlock(&key_lock);
    }
    // copy_uik and SecKeyCopySystemKey both hand the caller a +1 key.
    if (adapted_copy && !result && legacy_error) *legacy_error = saved_error;
    return result;
}

__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interpose = {
    (const void *)n56_copy_system_key, (const void *)SecKeyCopySystemKey
};
