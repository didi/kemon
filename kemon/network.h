/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    network.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __NETWORK_DRIVER_H__
#define __NETWORK_DRIVER_H__


#include <netinet/in.h>


//
// sflt_filter.sflt_handle
//

#define SFLT_HANDLE 0xFFF80386

#define SFLT_RAW_HANDLE (SFLT_HANDLE - (AF_INET + IPPROTO_RAW))
#define SFLT_TCP_IPV4_HANDLE (SFLT_HANDLE - (AF_INET + IPPROTO_TCP))
#define SFLT_TCP_IPV6_HANDLE (SFLT_HANDLE - (AF_INET6 + IPPROTO_TCP))
#define SFLT_UDP_IPV4_HANDLE (SFLT_HANDLE - (AF_INET + IPPROTO_UDP))
#define SFLT_UDP_IPV6_HANDLE (SFLT_HANDLE - (AF_INET6 + IPPROTO_UDP))
#define SFLT_ICMP_IPV4_HANDLE (SFLT_HANDLE - (AF_INET + IPPROTO_ICMP))
#define SFLT_ICMP_IPV6_HANDLE (SFLT_HANDLE - (AF_INET6 + IPPROTO_ICMPV6))

//
// sflt_filter.sflt_name
//

#define SFLT_BUNDLE_ID "com.assuresec.kemon.sflt"

//
// DNS protocol
//

#define DNS_PORT 53

struct dnshdr {
    unsigned short id;      // 16 bit message ID

    unsigned char rd:1;     // Recursion desired
    unsigned char tc:1;     // Truncated message
    unsigned char aa:1;     // Authoritative answer
    unsigned char opcode:4; // Identifies the request/operation type
    unsigned char qr:1;     // Query/response bit

    unsigned char rcode:4;  // Identifies the response type to the query
    unsigned char z:3;      // Reserved for future use
    unsigned char ra:1;     // Recursion available

    unsigned short qdcount; // Number of question entries
    unsigned short ancount; // Number of answer entries
    unsigned short nscount; // Number of authority entries
    unsigned short arcount; // Number of resource entries
};

//
// Connection status
//

#define STATE_CONNECT_IN  0x01
#define STATE_CONNECT_OUT 0x02
#define STATE_LISTENING   0x04

//
// Packet information
//

struct log_info {
    pid_t pid;
    pid_t uid;
    size_t length;
    UInt32 status;
    struct timeval start;
    struct timeval stop;

    union {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } source;
    union {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } destination;
    SInt32 ether_header;
    u_char ether_shost[ETHER_ADDR_LEN];
    u_char ether_dhost[ETHER_ADDR_LEN];

    SInt32 in_bytes;
    SInt32 in_packets;
    UInt32 first_in_bytes;
    void *first_in_packet;

    SInt32 out_bytes;
    SInt32 out_packets;
    UInt32 first_out_bytes;
    void *first_out_packet;
};

//
// Per socket extension control block for the log function
//

struct sflt_log_entry {
    TAILQ_ENTRY(sflt_log_entry) list;
    int protocol;
    socket_t socket;
    boolean_t tcp_ipv4_attached;
    boolean_t udp_ipv4_attached;
    boolean_t detached;
    struct log_info info;
};

//
// Event queues
//

TAILQ_HEAD(sflt_entry, sflt_log_entry);

static struct sflt_entry sflt_active_list;
static struct sflt_entry sflt_inactive_list;

struct filter_stats {
    //
    // TCP IPv4 socket
    //

    SInt32 tcp_ipv4_total;
    SInt32 tcp_ipv4_in_use;
    UInt32 tcp_ipv4_registered;

    //
    // UDP IPv4 socket
    //

    SInt32 udp_ipv4_total;
    SInt32 udp_ipv4_in_use;
    UInt32 udp_ipv4_registered;

    boolean_t filter_enabled;
};

static struct filter_stats filter_stats;

//
// Declaration
//

extern lck_grp_t *glock_group;

extern OSMallocTag gmalloc_tag;

extern
kern_return_t
sflt_initialization(
    boolean_t flag
    );

#endif