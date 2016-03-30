//
//  ViewController.m
//  RSA_Openssl
//
//  Created by Frank.he on 16/3/29.
//  Copyright © 2016年 新智泛能网络科技有限公司. All rights reserved.
//

#import "ViewController.h"

#import "OpensslRSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSString *encrypt = [OpensslRSA RSAEncrypt:@"frank.he"];
    NSLog(@"%@\n\n----------",encrypt);

    NSString *decrypt = [OpensslRSA RSADecrypt:encrypt];
    NSLog(@"%@\n\n----------",decrypt);

}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
