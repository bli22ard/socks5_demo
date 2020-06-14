//
//  socks5.h
//  socks5
//
//  Created by name327 on 2020/6/13.
//  Copyright © 2020 name327. All rights reserved.
//

#ifndef socks5_h
#define socks5_h

#include <stdio.h>
#include <sys/socket.h>
#include <pthread.h>
struct socks5_svr{
    u_int16_t port;
};
struct socks5_client{
    struct sockaddr client_addr;
    socklen_t addr_len;
    int client_fd;
    int remote_fd;
    pthread_t client_thread;
};
struct copy_param{
    int src_fd;
    int dest_fd;
};
int socks5_start(struct socks5_svr *svr);
#endif /* socks5_h */
