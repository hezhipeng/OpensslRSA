//
//  RSA.h
//  RSA_Openssl
//
//  Created by Frank.he on 16/3/29.
//  Copyright © 2016年 新智泛能网络科技有限公司. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OpensslRSA : NSObject

/* RSA编码 */
+ (NSString *)RSAEncrypt:(NSString *)encryptContent;

/* RSA解码 */
+ (NSString *)RSADecrypt:(NSString *)decryptContent;

@end
