//
//  socks5.c
//  socks5
//
//  Created by name327 on 2020/6/13.
//  Copyright © 2020 name327. All rights reserved.
//
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include "util.h"
#include "socks5.h"
#define BIND_IP "0.0.0.0"
#define COPY_BUFF 2*1024
static void* handler(void *arg);
static void free_socks5_client(struct socks5_client *sc);
ssize_t send_all(int socket, void *buffer, size_t length);
void *copy(void *arg);

int socks5_start(struct socks5_svr *svr){
    
    int server_fd=socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if(server_fd==-1){
        LOG_INFO("server socket error,cause:%s",strerror(errno));
        return -1;
    }
    int reuse=1;
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse))<0){
        LOG_INFO("setsockopt() reuse fail,cause:%s",strerror(errno));
        return -1;
    }
    
    struct sockaddr_in in;
    bzero(&in, sizeof(in));
    in.sin_family=AF_INET;
    in.sin_port=htons(svr->port);
    if(inet_pton(AF_INET,BIND_IP,&in.sin_addr.s_addr)<0){
        LOG_INFO("bind_ip error,cause:%s",strerror(errno));
        return -1;
    }
    socklen_t in_len=sizeof(in);
    int bind_r=bind(server_fd, (struct sockaddr*)&in, in_len);
    if(bind_r==-1){
        LOG_INFO("server socket bind error,cause:%s",strerror(errno));
        return -1;
    }
    
    if(listen(server_fd, 0)==-1){
        LOG_INFO("listen fail,cause:%s",strerror(errno));
        return -1;
    }
    
    LOG_INFO("listen in " BIND_IP " :%u",svr->port);
    while(1){
        size_t sc_client_len=sizeof(struct socks5_client);
        struct socks5_client *sc=malloc(sc_client_len);
        bzero(sc, sc_client_len);
        int client_fd=accept(server_fd, &sc->client_addr,&sc->addr_len);
        if(client_fd==-1){
            free_socks5_client(sc);
            LOG_INFO("accept error,cause:%s",strerror(errno));
            continue;
        }
        LOG_INFO("client connected");
        sc->client_fd=client_fd;
        pthread_create(&sc->client_thread, NULL, handler, sc);
    }
    
    
    
    return 0;
}
static void* handler(void *arg){
    struct socks5_client *sc=(struct socks5_client *)arg;
    int client_fd=sc->client_fd;
    u_char ver_methods[2];
    if(recv(client_fd, ver_methods, 2, MSG_WAITALL)<0){
        LOG_INFO("recv ver methods error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    if(ver_methods[0]!=0x05){
        LOG_INFO("not support socks version %u\n",ver_methods[0]);
        free_socks5_client(sc);
        return NULL;
    }
    u_int8_t method_count=ver_methods[1];
    u_int8_t methods[method_count];
    if(recv(client_fd, methods, sizeof(methods), MSG_WAITALL)<0){
        LOG_INFO("recv method count error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    u_char auth_resp[]={0x05,0x00};
    if(send_all(client_fd, auth_resp, sizeof(auth_resp))<0){
        LOG_INFO("write auth resp error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    //读取目的地址
    u_int8_t dest_info[4];
    if(recv(client_fd, dest_info, 4, MSG_WAITALL)<0){
        LOG_INFO("read dest info error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    
    
    u_int8_t cmd=dest_info[1];
    if(cmd!=0x01){
        LOG_INFO("not support cmd %u",cmd);
        free_socks5_client(sc);
        return NULL;
    }
    
    u_int8_t addr_type=dest_info[3];
    struct sockaddr_in dest_in;
    bzero(&dest_in, sizeof(dest_in));
    dest_in.sin_family=AF_INET;
    if(addr_type==0x01){
        uint32_t addr_u32;
        if(recv(client_fd, &addr_u32, 4, MSG_WAITALL)<0){
            perror("read dest ip error");
            free_socks5_client(sc);
            return NULL;
        }
        dest_in.sin_addr.s_addr=addr_u32;
    }else if(addr_type==0x03){
        //域名
        u_int8_t domain_len;
        if(recv(client_fd, &domain_len, 1, MSG_WAITALL)<0){
            perror("read domain len error");
            free_socks5_client(sc);
            return NULL;
        }
        u_char domain[domain_len];
        if(recv(client_fd, domain, domain_len, MSG_WAITALL)<0){
            perror("read domain error");
            free_socks5_client(sc);
            return NULL;
        }
        struct addrinfo *ai;
        int getaddrinfo_ret;
        char domain_str[256];
        bzero(domain_str, 256);
        memcpy(domain_str, domain, domain_len);
        LOG_INFO("domian_str:[%s]",domain_str);
        if((getaddrinfo_ret=getaddrinfo(domain_str,NULL, NULL, &ai))!=0){
            const char *err_msg=gai_strerror(getaddrinfo_ret);
            LOG_INFO("dns error,cause:%s",err_msg);
            free_socks5_client(sc);
            return NULL;
        }
        struct sockaddr_in *tmp=(struct sockaddr_in *)ai->ai_addr;
        dest_in.sin_addr.s_addr=tmp->sin_addr.s_addr;
        freeaddrinfo(ai);
    }else{
        printf("not support addr_type %u\n",addr_type);
        free_socks5_client(sc);
        return NULL;
    }
    
    u_int16_t port_u16;
    if(recv(client_fd, &port_u16, 2, MSG_WAITALL)<0){
        perror("read dest port error");
        free_socks5_client(sc);
        return NULL;
    }
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_in.sin_addr.s_addr, ip_str, INET_ADDRSTRLEN);
    
    dest_in.sin_port=port_u16;
    int remote_fd=socket(AF_INET, SOCK_STREAM, 0);
    if(remote_fd<0){
        LOG_INFO("remote socket error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    sc->remote_fd=remote_fd;
    LOG_INFO("start connect dest_ip:%s,port:%u",ip_str,ntohs(port_u16));
    if(connect(remote_fd, (struct sockaddr *)&dest_in, sizeof(dest_in))<0){
        LOG_INFO("connect remote error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    LOG_INFO("connect success");
    uint8_t success_handshake_resp[]={
        0x05, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x88
    };
    if(send_all(client_fd, success_handshake_resp, sizeof(success_handshake_resp))<0){
        LOG_INFO("write handshake resp error,cause:%s",strerror(errno));
        free_socks5_client(sc);
        return NULL;
    }
    struct copy_param client_to_remote;
    client_to_remote.src_fd=client_fd;
    client_to_remote.dest_fd=remote_fd;
    pthread_t thread;
    pthread_create(&thread, NULL, copy, &client_to_remote);
    
    struct copy_param remote_to_client;
    remote_to_client.src_fd=remote_fd;
    remote_to_client.dest_fd=client_fd;
    copy(&remote_to_client);
    pthread_join(thread, NULL);
    free_socks5_client(sc);
    return NULL;
}


void *copy(void *arg){
    struct copy_param *cp=(struct copy_param *)arg;
    char buff[COPY_BUFF];
    while (1) {
        //printf("src_fd:%d,dest_fd:%d start copy\n",cp->src_fd,cp->dest_fd);
        LOG_INFO("start copy");
        ssize_t read_len=read(cp->src_fd, buff, COPY_BUFF);
        
        if(read_len==0){
            LOG_INFO("copy EOF fd:%d",cp->src_fd);
            shutdown(cp->src_fd, SHUT_RDWR);
            shutdown(cp->dest_fd,SHUT_RDWR);

            //shutdown(cp->src_fd, SHUT_RD);
            return NULL;
        }
        if(read_len<0){
            shutdown(cp->src_fd, SHUT_RDWR);
            shutdown(cp->dest_fd,SHUT_RDWR);
            LOG_INFO("copy error fd:%d ,cause:%s",cp->src_fd,strerror(errno));
            return NULL;
        }
        LOG_INFO("read len:%d",read_len);
        if(send_all(cp->dest_fd, buff, read_len)<0){
            shutdown(cp->src_fd, SHUT_RDWR);
            shutdown(cp->dest_fd,SHUT_RDWR);
            LOG_INFO("copy write dest error,cause:%s",strerror(errno));
            return NULL;
        }
        LOG_INFO("send over");
        //printf("src_fd:%d,dest_fd:%d end copy\n",cp->src_fd,cp->dest_fd);
    }
    return NULL;
}

ssize_t send_all(int socket, void *buffer, size_t length){
    char *ptr = (char*) buffer;
    while (length > 0)
    {
        ssize_t i = send(socket, ptr, length,0);
        if (i < 1) {
            return i;
        }
        ptr += i;
        length -= i;
    }
    return 0;
}
static void free_socks5_client(struct socks5_client *sc){
    close(sc->client_fd);
    if(sc->remote_fd>0){
        close(sc->remote_fd);
    }
    free(sc);
    LOG_INFO("free connect\n");
}


