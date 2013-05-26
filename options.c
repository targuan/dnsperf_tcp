#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include "options.h"

int setaddr(char * name, struct sockaddr_in * sin) {
    struct addrinfo * res;
    struct addrinfo * info;
    struct addrinfo hints = {0};
    int error;
    
    
    hints.ai_socktype = SOCK_RAW;
    
    error = getaddrinfo(name,NULL,&hints,&res);
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
            if(info->ai_addr->sa_family == AF_INET) {
                memcpy(sin,info->ai_addr,info->ai_addrlen);
                
                break;
                
            }
        }
        
        freeaddrinfo(res);
    }
}

int setopt(int argc, char** argv, struct options * opt) {
    int c;
    short ver = 4;
    
    opt->sin_src_mask.sin_addr.s_addr = htonl(0xff000000);

    while ((c = getopt(argc, argv, "v:s:d:m:")) != -1)
        switch (c) {
            case 's' :
                setaddr(optarg,&(opt->sin_src));
                break;
            case 'm' :
                setaddr(optarg,&(opt->sin_src_mask));
                break;
            case 'd' :
                setaddr(optarg,&(opt->sin_dst));
                break;
            case 'v' :
                ver = atoi(optarg);
                break;
        }
}

int syn_s = 0;
int syn_r = 0;
int psh_s = 0;
int psh_r = 0;
int fin_s = 0;
int fin_r = 0;

void syn_sent(){
    syn_s++;
}
void syn_received(){
    syn_r++;
}
void psh_sent(){
    psh_s++;
}
void psh_received(){
    psh_r++;
}
void fin_sent(){
    fin_s++;
}
void fin_received(){
    fin_r++;
}
void print_stat(){
    int _syn_s = syn_s;
    int _syn_r = syn_r;
    int _psh_s = psh_s;
    int _psh_r = psh_r;
    int _fin_s = fin_s;
    int _fin_r = fin_r;
    
    printf("lost syn %d\n",_syn_s-_syn_r);
    printf("lost psh %d\n",_psh_s-_psh_r);
    printf("packet sent %d\n",_psh_s);
    printf("packet received %d\n",_psh_r);
}
int toogle;
int pause_(int t) {
    toogle = toogle ^ t;
    
    return toogle;
}