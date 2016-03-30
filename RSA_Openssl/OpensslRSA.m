//
//  RSA.m
//  RSA_Openssl
//
//  Created by Frank.he on 16/3/29.
//  Copyright © 2016年 新智泛能网络科技有限公司. All rights reserved.
//

#import "OpensslRSA.h"
#import "NSData+Base64.h"
#import "NSString+Base64.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

typedef NS_ENUM(NSUInteger,RSA_PADDING_TYPE) {
    RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
};

@implementation OpensslRSA

+ (int)getBlockSizeWithRSA_PADDING_TYPE:(RSA_PADDING_TYPE)padding_type RSA:(RSA *)_rsa
{
    int len = RSA_size(_rsa);
    if (padding_type == RSA_PADDING_TYPE_PKCS1 || padding_type == RSA_PADDING_TYPE_SSLV23) {
        len -= 11;
    }
    return len;
}


/* RSA编码 */
+ (NSString *)RSAEncrypt:(NSString *)encryptContent{
    
    NSString *path = [[NSBundle mainBundle] pathForResource:@"rsa_public_key1024" ofType:@"pem"];
    FILE *pubkey = fopen([path cStringUsingEncoding:1], "r");
    if (pubkey == NULL) {
        NSLog(@"duh: %@", [path stringByAppendingString:@" not found"]);
        return NULL;
    }
    
    RSA *rsa = PEM_read_RSA_PUBKEY(pubkey, NULL, NULL, NULL);
    if (rsa == NULL) {
        NSLog(@"Error reading RSA public key.");
        return NULL;
    }
    
    const char *msgInChar = [encryptContent UTF8String];
    unsigned char *encrypted = (unsigned char *) malloc(128); //rsa编码位数，比如1024位编码就是1024*8  比如2048位编码就是2048*8
    int status = RSA_public_encrypt((int)strlen(msgInChar), (unsigned char *)msgInChar, encrypted, rsa, RSA_PKCS1_PADDING);
    if (status == -1) {
        NSLog(@"Encryption failed");
        return NULL;
    }
    
    NSData *data = [NSData dataWithBytes:(const void *)encrypted length:128];
    NSString *result = [data base64EncodedString];
    
    free(rsa);
    fclose(pubkey);
    free(encrypted);
    
    return result;
}


/* RSA解码 */
+ (NSString *)RSADecrypt:(NSString *)decryptContent{
    
    NSData *decryptData = [decryptContent base64DecodedData];
    if (decryptData && [decryptData length]) {
        
        NSString *path = [[NSBundle mainBundle] pathForResource:@"rsa_private_key1024" ofType:@"pem"];
        FILE *prikey = fopen([path cStringUsingEncoding:1], "r");
        if (prikey == NULL) {
            NSLog(@"duh: %@", [path stringByAppendingString:@" not found"]);
            return NULL;
        }
        
        RSA *rsa = PEM_read_RSAPrivateKey(prikey, NULL, NULL, NULL);
        if (rsa == NULL) {
            NSLog(@"Error reading RSA private key.");
            return NULL;
        }
        
        int status = RSA_check_key(rsa);
        if (!status) {
            return NULL;
        }

        NSUInteger length = [decryptData length];
        NSInteger flen = [self getBlockSizeWithRSA_PADDING_TYPE:RSA_PADDING_TYPE_PKCS1 RSA:rsa];
        char *decrypted = (char*)malloc(flen);
        bzero(decrypted, flen);
        
        status = RSA_private_decrypt((int)length, (unsigned char*)[decryptData bytes], (unsigned char*)decrypted, rsa, RSA_PADDING_TYPE_PKCS1);
        if (status == -1) {
            NSLog(@"Decryption failed");
            return NULL;
        }
        
        NSData *decData = [NSData dataWithBytes:decrypted length:sizeof(decrypted)];
        
        free(rsa);
        fclose(prikey);
        free(decrypted);
        
        return [[NSString alloc] initWithData:decData encoding:NSUTF8StringEncoding];

    }
    return NULL;
}



@end

