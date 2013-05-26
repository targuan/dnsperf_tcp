/* 
 * File:   main.c
 * Author: targuan
 *
 * Created on 23 mai 2013, 19:56
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * 
 */
int b(int argc, char** argv) {
    struct addrinfo * res;
    struct addrinfo * info;
    struct addrinfo hints = {0};
    int error;
    
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    
    hints.ai_socktype = SOCK_RAW;

    error = getaddrinfo("google.fr",NULL,&hints,&res);
    if (error != 0)
    {   
        if (error == EAI_SYSTEM)
        {
            perror("getaddrinfo");
        }
        else
        {
            fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
        }   
        exit(EXIT_FAILURE);
    }
    else {
        for(info = res;info != NULL; info = info->ai_next) {
            error = getnameinfo(info->ai_addr,
                        info->ai_addrlen, host, NI_MAXHOST,
                        service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST );
            if(error != 0) {
                fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
            } else {
                printf("%s:%s\n",host,service);
            }
        }
        
        freeaddrinfo(res);
    }
    
    
    
    return (EXIT_SUCCESS);
}


