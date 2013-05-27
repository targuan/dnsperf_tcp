/* 
 * File:   main.c
 * Author: targuan
 *
 * Created on 23 mai 2013, 19:56
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <string.h>

#include <pthread.h>

#include "tcp.h"
#include "listener.h"
#include "initiator.h"
#include "options.h"


/*
 * 
 */
int main(int argc, char** argv) {
    int s,c;
    int optval, optlen;
    struct options opt;

    struct parameters params;
    pthread_t thread_listener, thread_initiator;
    
    setopt(argc,argv,&opt);

    


    s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) {
        perror("socket() error");
        exit(EXIT_FAILURE);
    }

    optval = 1;
    optlen = sizeof (optval);
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &optval, optlen) != 0) {
        perror("setsockopt() error");
        exit(EXIT_FAILURE);
    }
    
    params.sin_dst = opt.sin_dst;
    params.sin_src_mask = opt.sin_src_mask;
    params.sin_src = opt.sin_src;
    params.socket = s;
    
    if(pthread_create(&thread_listener, NULL, listner, &params) != 0) {
        perror("pthread_create() error");
        exit(EXIT_FAILURE);
    }
    
    sleep(1);
    
    if(pthread_create(&thread_initiator, NULL, initiator, &params) != 0) {
        perror("pthread_create() error");
        exit(EXIT_FAILURE);
    }
    
    do {
        c=getc(stdin);
        switch(c) {
            case 's':
                print_stat();
                break;
            case 'p':
                pause_(1);
                break;  
        }
        
    } while(c != 'q');

    pthread_cancel(thread_initiator);
    sleep(10);
    pthread_cancel(thread_listener);

    return (EXIT_SUCCESS);
}

