//
//  main.c
//  socks5
//
//  Created by name327 on 2020/6/13.
//  Copyright © 2020 name327. All rights reserved.
//

#include <stdio.h>
#include <signal.h>
#include "socks5.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    printf("Hello, World!\n");
    struct socks5_svr svr;
    svr.port=4567;
    //忽略SIGPIPE信号，防止socket写入出错，产生SIGPIPE信号，导致进程退出
    signal(SIGPIPE, SIG_IGN);
    socks5_start(&svr);
    return 0;
}
