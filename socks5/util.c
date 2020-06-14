//
//  uitl.c
//  socks5
//
//  Created by name327 on 2020/6/14.
//  Copyright © 2020 name327. All rights reserved.
//

#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "util.h"

void LOG_INFO(const char *fmt,...){
    char msg[1024],ts[32],thread_info[64];
    struct iovec iov[4];
    time_t now;
    time (&now);
    struct tm *ti;
    
    ti = localtime (&now);
    int time_len=snprintf (ts, 32, "[%04u-%02u-%02u %02u:%02u:%02u] ",
    ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday,
    ti->tm_hour, ti->tm_min, ti->tm_sec);
    iov[0].iov_base = ts;
    iov[0].iov_len=time_len;
    pthread_t curr_t;
    curr_t=pthread_self();
    
    iov[1].iov_base=thread_info;
    int thread_len=snprintf(thread_info, 64, " tid:[%ld] ",(long)curr_t);
    iov[1].iov_len=thread_len;
    
    
    va_list ap;
    va_start(ap, fmt);
    
    int msg_len=vsnprintf(msg, 1024, fmt, ap);
    iov[2].iov_base=msg;
    iov[2].iov_len=msg_len;
    va_end(ap);
    
    iov[3].iov_base="\n";
    iov[3].iov_len=1;
    
    writev(1,iov,4);
    
}
