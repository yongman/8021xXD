#ifndef _8021X_H_
#define _8021X_H_

#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <syslog.h>

#define USER_MAX 20
#define PASS_MAX 20
#define FCE_MAX 10
#define MAC_LEN 13

struct userinfo 
{
        pcap_t *phandle;
        char username[USER_MAX];
        char password[PASS_MAX];
        char interface[FCE_MAX];
        char mac[MAC_LEN];
        
};

extern void StartAuth(struct userinfo *);
extern void Cleanup(int);

#endif
