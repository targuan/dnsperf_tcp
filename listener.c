#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <resolv.h>

#include "listener.h"
#include "options.h"


FILE* fp_domain;
void init_domain_file(struct options *params) {
    fp_domain = fopen(params->file,"r");
    
    if(fp_domain == NULL) {
        perror("fopen() domain file");
        exit(1);
    } else {
        printf("fopen() OK\n");
    }
}
void nextdomain(char **domain) {
    char line[1024];
    
    if(feof(fp_domain)) {
        rewind(fp_domain);
    }
    fgets(line,1024,fp_domain);
    *domain=strtok(line,"\n\r \t");
}

void fill_ipv4(struct iphdr *ip, u_int32_t daddr, u_int32_t saddr,u_int8_t protocol) {
    ip->ihl = 5;
    ip->version = 4;
    ip->ttl = IPDEFTTL;
    ip->frag_off = 0;
    ip->protocol = protocol;
    
    ip->check = 0;
    
    ip->saddr = daddr;
    ip->daddr = saddr;
}

u_char *buffer_ack = NULL;
void send_ack(int socket, struct iphdr *ip_syn,struct tcphdr *tcp_syn){
    u_char *buffer;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in daddr = {0};
    int payloadsize;
    
    payloadsize = ntohs(ip_syn->tot_len) - (ip_syn->ihl*4) - (tcp_syn->doff*4);
    payloadsize = payloadsize==0?1:payloadsize;
    
    if(buffer_ack == NULL){
        buffer_ack = calloc(sizeof(u_char)*(PACKETSZ) + sizeof(struct iphdr) + sizeof(struct tcphdr),1);
    }
    buffer = buffer_ack;
    ip = (struct iphdr *)buffer;
    fill_ipv4(ip, ip_syn->daddr, ip_syn->saddr, IPPROTO_TCP);
    
    daddr.sin_addr.s_addr = ip_syn->saddr;
    daddr.sin_family = AF_INET;
    
    tcp = (struct tcphdr *)(buffer + (ip->ihl * 4));
    tcp->doff = 5;
    tcp->source = tcp_syn->dest;
    tcp->dest = tcp_syn->source;
    tcp->seq = tcp_syn->ack_seq;
    tcp->ack_seq = htonl(ntohl(tcp_syn->seq) + payloadsize);
    tcp->window = htons(14600);
    tcp->ack = 1;
    
    ip->tot_len = sizeof(struct tcphdr) + (ip->ihl * 4);
    
    tcp->check = 0;
    tcp->check = tcp_cksum(tcp, sizeof(struct tcphdr), ip->daddr,  ip->saddr);
    
    if (sendto(socket, buffer, ip->tot_len, 0, (struct sockaddr *) &(daddr), sizeof(daddr)) < 0) {
        perror("sendto() ack error");
        return;
    }
}
u_char * buffer_psh = NULL;
void send_psh(int socket, struct iphdr *ip_syn,struct tcphdr *tcp_syn){
    u_char *buffer;
    struct iphdr *ip;
    struct tcphdr *tcp;
    u_char *dns;
    int sendsize;
    short *len;
    struct sockaddr_in daddr = {0};
    char *domain;
    
    if(buffer_psh == NULL){
        buffer_psh = calloc(sizeof(u_char)*(PACKETSZ) + sizeof(struct iphdr) + sizeof(struct tcphdr),1);
    }
    buffer = buffer_psh;
    
    ip = (struct iphdr *)buffer;
    fill_ipv4(ip, ip_syn->daddr, ip_syn->saddr, IPPROTO_TCP);
    
    daddr.sin_addr.s_addr = ip_syn->saddr;
    daddr.sin_family = AF_INET;
    
    tcp = (struct tcphdr *)(buffer + (ip->ihl * 4));
    tcp->doff = 5;
    tcp->source = tcp_syn->dest;
    tcp->dest = tcp_syn->source;
    tcp->seq = tcp_syn->ack_seq;
    tcp->ack_seq = htonl(ntohl(tcp_syn->seq) + 1);
    tcp->window = htons(14600);
    tcp->ack = 1;
    tcp->psh = 1;
    
    nextdomain(&domain);
    
    dns = buffer + (ip->ihl * 4) + sizeof(struct tcphdr) + 2;
    sendsize = res_mkquery(QUERY, domain, C_IN, T_A, NULL,
            0, NULL, dns, PACKETSZ);
    
    
    len = (short *)(buffer + (ip->ihl * 4) + sizeof(struct tcphdr));
    *len = htons(sendsize);
    ip->tot_len = sendsize + 2 + sizeof(struct tcphdr) + (ip->ihl * 4);
    
    tcp->check = 0;
    tcp->check = tcp_cksum(tcp, sizeof(struct tcphdr) + 2 +  sendsize, ip->daddr,  ip->saddr);
    
    if (sendto(socket, buffer, ip->tot_len, 0, (struct sockaddr *) &(daddr), sizeof(daddr)) < 0) {
        perror("sendto() ack error");
        return;
    }
}
u_char * buffer_fin = NULL;
void send_fin(int socket, struct iphdr *ip_syn,struct tcphdr *tcp_syn){
    u_char *buffer;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in daddr = {0};
    int payloadsize;
    
    payloadsize = ntohs(ip_syn->tot_len) - (ip_syn->ihl*4) - (tcp_syn->doff*4);
    payloadsize = payloadsize==0?1:payloadsize;
    
    if(buffer_fin == NULL){
        buffer_fin = calloc(sizeof(u_char)*(PACKETSZ) + sizeof(struct iphdr) + sizeof(struct tcphdr),1);
    }
    buffer = buffer_fin;
    
    ip = (struct iphdr *)buffer;
    fill_ipv4(ip, ip_syn->daddr, ip_syn->saddr, IPPROTO_TCP);
    
    daddr.sin_addr.s_addr = ip_syn->saddr;
    daddr.sin_family = AF_INET;
    
    tcp = (struct tcphdr *)(buffer + (ip->ihl * 4));
    tcp->doff = 5;
    tcp->source = tcp_syn->dest;
    tcp->dest = tcp_syn->source;
    tcp->seq = tcp_syn->ack_seq;
    tcp->ack_seq = htonl(ntohl(tcp_syn->seq) + payloadsize);
    tcp->window = htons(14600);
    tcp->ack = 1;
    tcp->fin = 1;
    
    ip->tot_len = sizeof(struct tcphdr) + (ip->ihl * 4);
    
    tcp->check = 0;
    tcp->check = tcp_cksum(tcp, sizeof(struct tcphdr), ip->daddr,  ip->saddr);
    
    if (sendto(socket, buffer, ip->tot_len, 0, (struct sockaddr *) &(daddr), sizeof(daddr)) < 0) {
        perror("sendto() ack error");
        return;
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int offset = 0;
    struct ether_header *ether;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct options * params = (struct options *)args;
    
    ether = (struct ether_header *)(packet+offset);
    
    //eth hdr truncated
    if((offset+ETHER_HDR_LEN) >= header->caplen) {
        printf("caplen too short for eth hdr\n");
        return;
    }
    if(ntohs(ether->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    
    offset += ETHER_HDR_LEN;
    ip = (struct iphdr *)(packet + offset);
    
    //ip hdr truncated
    if((offset + sizeof(struct iphdr)) >= header->caplen) {
        printf("caplen too short for ip hdr\n");
        return;
    }
    //ip hdr truncated
    if((offset + ip->ihl*4) >= header->caplen) {
        printf("caplen too short for ip hdr with options\n");
        return;
    }
    if(ip->protocol != IPPROTO_TCP) {
        printf("not a tcp fragment\n");
        return;
    }
    
    
    offset += ip->ihl*4;
    tcp = (struct tcphdr *)(packet + offset);
    if((offset + sizeof(struct tcphdr)) >= header->caplen) {
        printf("caplen too short for tcp hdr\n");
        return;
    }
    if((offset + tcp->doff*4) >= header->caplen) {
        printf("caplen too short for tcp hdr with options\n");
        return;
    }
    

    
    if(tcp->syn && tcp->ack) {
        syn_received();
        send_ack(params->socket,ip,tcp);
        send_psh(params->socket,ip,tcp);
        psh_sent();
    } else if(tcp->psh) {
        psh_received();
        send_ack(params->socket,ip,tcp);
        send_fin(params->socket,ip,tcp);
        fin_sent();
    } else if(tcp->fin) {
        fin_received();
        send_ack(params->socket,ip,tcp);
    }
}

void * listner(void * p_data) {
    printf("listener created");

    struct options *params = p_data;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "dst net 1.0.0.0/8 and src port 53";
    
    init_domain_file(params);

    handle = pcap_open_live("bond1", BUFSIZ, 1, 200, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth2", errbuf);
        return;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }

    pcap_loop(handle, -1, got_packet, p_data);

    pcap_close(handle);
}
