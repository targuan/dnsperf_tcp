/* 
 * File:   tcp.h
 * Author: targuan
 *
 * Created on 25 mai 2013, 19:33
 */

#ifndef TCP_H
#define	TCP_H

#ifdef	__cplusplus
extern "C" {
#endif
    
    
    #include <sys/types.h>
    #include <netinet/in.h>

    
    struct tcp_pseudo {
        struct in_addr src_ip; /* source ip */
        struct in_addr dest_ip; /* destination ip */
        uint8_t zeroes; /* = 0 */
        uint8_t protocol; /* = 6 */
        uint16_t len; /* length of TCPHeader */
    } __attribute__((packed));

    uint16_t in_cksum (const void * addr, unsigned len, uint16_t init);
    
    
    uint16_t tcp_cksum (const void * addr, unsigned len, struct in_addr src_ip, struct in_addr dest_ip);
    
    
#ifdef	__cplusplus
}
#endif

#endif	/* TCP_H */

