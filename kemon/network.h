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
#include <net/ethernet.h>


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
// Connection status
//

#define STATE_CONNECT_IN  0x01
#define STATE_CONNECT_OUT 0x02
#define STATE_LISTENING   0x04

//
// DNS protocol
//

#define DNS_PORT 53

struct dnshdr
{
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
// Packet log information
//

struct log_info
{
    pid_t pid;
    pid_t uid;
    size_t length;
    uint32_t status;
    struct timeval start;
    struct timeval stop;

    union
    {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } source;
    union
    {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } destination;
    SInt32 ether_header;
    u_char ether_shost[ETHER_ADDR_LEN];
    u_char ether_dhost[ETHER_ADDR_LEN];

    SInt32 in_bytes;
    SInt32 in_packets;
    SInt32 first_in_packet;
    uint32_t first_in_packet_size;
    void *first_in_packet_data;

    SInt32 out_bytes;
    SInt32 out_packets;
    SInt32 first_out_packet;
    uint32_t first_out_packet_size;
    void *first_out_packet_data;
};

//
// Per socket extension control block for the log function
//

struct log_entry
{
    TAILQ_ENTRY(log_entry) next;
    int protocol;
    socket_t socket;
    boolean_t tcp_ipv4_attached;
    boolean_t udp_ipv4_attached;
    boolean_t detach;
    struct log_info info;
};

TAILQ_HEAD(ListEntry, log_entry);

struct filter_stats
{
    //
    // TCP IPv4 socket
    //

    SInt32 tcp_ipv4_total;
    SInt32 tcp_ipv4_in_use;
    UInt32 tcp_ipv4_registered;

    //
    // UDP IPv4 socket
    //

    UInt32 udp_ipv4_total;
    UInt32 udp_ipv4_in_use;
    UInt32 udp_ipv4_registered;

    boolean_t filter_enabled;
};

static struct filter_stats gfilter_stats;

static struct ListEntry glist_active;
static struct ListEntry glist_inactive;

//
// Declaration
//

extern OSMallocTag gmalloc_tag;

extern lck_mtx_t *gnetwork_filter_lock;

extern
kern_return_t
sflt_initialization(
    boolean_t flag
    );

#endif