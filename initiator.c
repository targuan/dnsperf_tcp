#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <unistd.h>
#include "initiator.h"
#include "options.h"

void * initiator(void * p_data) {
    struct options * params = (struct options *) p_data;
    u_char *buffer;

    struct iphdr *ip;
    struct tcphdr *tcp;
    
    uint16_t port = 11111;
    uint32_t ips = ntohl(params->sin_src.sin_addr.s_addr);
    
    int usleep_v;
    int dosleep = 0;

    buffer = calloc(sizeof (struct iphdr) + sizeof (struct tcphdr), 1);

    ip = (struct iphdr *) buffer;
    ip->ihl = 5;
    ip->version = 4;
    ip->ttl = 100;
    ip->frag_off = 0;
    //ip->protocol = 17;
    ip->protocol = 6;
    ip->check = 0;
    ip->daddr = params->sin_dst.sin_addr.s_addr;
    //ip->saddr = params->sin_src.sin_addr.s_addr;

    tcp = (struct tcphdr *) (buffer + (ip->ihl * 4));
    tcp->doff = 5;
    //tcp->source = htons(port++);
    tcp->dest = htons(53);
    tcp->syn = 1;
    tcp->window = htons(14600);
    

    ip->tot_len = sizeof (struct tcphdr) + (ip->ihl * 4);

    srand( time( NULL ) );
    
    usleep_v = 1000000.0/params->pps;
    printf("usleep %d",usleep_v);
    
    while (1) {
        dosleep = !dosleep;
        if(!pause_(0)){
            tcp->seq = rand();
            tcp->source = rand();
            ip->saddr = (htonl(rand()) &  (~params->sin_src_mask.sin_addr.s_addr) | params->sin_src.sin_addr.s_addr);
            tcp->check = 0;
            tcp->check = tcp_cksum(tcp, sizeof (struct tcphdr), ip->daddr, ip->saddr);
            if (sendto(params->socket, buffer, ip->tot_len, 0, (struct sockaddr *) &(params->sin_dst), sizeof (params->sin_dst)) < 0) {
                perror("sendto() error");
                return;
            }
            syn_sent();
        }
        if(dosleep) {
            usleep(usleep_v);
        }
        
        
    }
}
