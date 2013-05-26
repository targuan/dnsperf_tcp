/**
 * in_cksum from : 
 * http://stackoverflow.com/questions/14410128/how-to-verify-tcp-checksum
 * 
 **/
#include <sys/types.h>
#include "tcp.h"

unsigned short int inet_cksum(unsigned short int *addr, size_t len, uint16_t init) {
    register int nleft = (int) len;
    register unsigned short int *w = addr;
    unsigned short int answer = 0;
    register int sum = init;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return (answer);
}

uint16_t tcp_cksum(const void * addr, unsigned len, struct in_addr dest_ip, struct in_addr src_ip) {
    struct tcp_pseudo tcp_pseudo_hdr = {0};
    uint16_t csum;


    tcp_pseudo_hdr.dest_ip = dest_ip;
    tcp_pseudo_hdr.src_ip = src_ip;
    tcp_pseudo_hdr.protocol = IPPROTO_TCP;
    tcp_pseudo_hdr.len = htons(len);

    csum = inet_cksum(&tcp_pseudo_hdr, (unsigned) sizeof (tcp_pseudo_hdr), 0);
    csum = inet_cksum(addr, len, (uint16_t) ~csum);

    return csum;
}