//
//  KIMUtilities.h
//  Kerberos5
//
//  Created by Justin Anderson on 9/28/08.
//  Copyright 2008 MIT. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Kerberos/kim.h>

#define log_kim_error_to_console(err)\
{\
NSLog(@"%s got error %@", _cmd, [KIMUtilities stringForLastKIMError:err]);\
} while (0);

@interface KIMUtilities : NSObject

+ (NSString *) stringForLastKIMError: (kim_error) in_err;

+ (BOOL) validatePrincipalWithName: (NSString *) name
                             realm: (NSString *) realm;

@end