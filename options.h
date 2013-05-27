/* 
 * File:   options.h
 * Author: targuan
 *
 * Created on 25 mai 2013, 19:56
 */

#ifndef OPTIONS_H
#define	OPTIONS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>

struct options {
    struct sockaddr_in sin_src;
    struct sockaddr_in sin_src_mask;
    struct sockaddr_in sin_dst;
    char *file;
    int socket;
    int wait; // wait _wait_ seconds before cancelling listener
    int pps;
};

int setopt(int argc, char** argv, struct options * opt);
int syn_lost();
void syn_sent();
void syn_received();
void psh_sent();
void psh_received();
void fin_sent();
void fin_received();

int pause_(int);

void print_stat();

#ifdef	__cplusplus
}
#endif

#endif	/* OPTIONS_H */

