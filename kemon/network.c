/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    network.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <kern/assert.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <sys/kpi_socketfilter.h>
#include <sys/kpi_mbuf.h>
#include <sys/systm.h>
#include <sys/kauth.h>
#include "include.h"
#include "nke.h"
#include "trace.h"
#include "network.h"


//
// Socket filter mutex lock
//

lck_mtx_t *gnetwork_filter_lock = NULL;

#ifdef NDEBUG
#   define get_entry_from_cookie(cookie) ((struct log_entry *) cookie)
#else
    static struct log_entry *get_entry_from_cookie(void *cookie)
    {
        struct log_entry *result = (struct log_entry *) cookie;

        assert (result);

        return result;
    }
#endif

//
// sflt_filter.sflt_unregistered_func is called to notify the filter it has been unregistered.
//

static
void
sflt_unregistered(
    sflt_handle handle
    )
{
    if (SFLT_TCP_IPV4_HANDLE == handle)
    {
        OSCompareAndSwap(1, 0, &gfilter_stats.tcp_ipv4_registered);

    #if SFLT_TROUBLESHOOTING
        printf("[%s.kext] : Socket filter for TCP IPv4 was unregistered (tcp_ipv4_in_use=%d, tcp_ipv4_total=%d).\n",
               DRIVER_NAME, gfilter_stats.tcp_ipv4_in_use, gfilter_stats.tcp_ipv4_total);
    #endif
    }
    else if (SFLT_UDP_IPV4_HANDLE == handle)
    {
        OSCompareAndSwap(1, 0, &gfilter_stats.udp_ipv4_registered);

    #if SFLT_TROUBLESHOOTING
        printf("[%s.kext] : Socket filter for UDP IPv4 was unregistered (udp_ipv4_in_use=%d, udp_ipv4_total=%d).\n",
               DRIVER_NAME, gfilter_stats.udp_ipv4_in_use, gfilter_stats.udp_ipv4_total);
    #endif
    }
}

//
// sflt_attach_func_locked is called by sflt_attach_func to initialize internal memory structures.
// Assumption that the fine grain lock associated with the glist_active queue is held
// so that the queue entry can be inserted atomically.
//

static
void
sflt_attach_locked(
    struct log_entry *entry,
    socket_t socket
    )
{
    memset(entry, 0, sizeof(struct log_entry));

    //
    // Record start time
    //

    microtime(&(entry->info.start));

    //
    // Attach time is a good time to identify the calling process ID and user ID
    //

    entry->info.pid = proc_selfpid();
    entry->info.uid = kauth_getuid();
    entry->info.length = sizeof(struct log_entry);

    entry->socket = socket;

    TAILQ_INSERT_TAIL(&glist_active, entry, next);
}

//
// sflt_filter.sflt_attach_func is called to notify the filter it has been attached to a new TCP socket.
// This filter is called in one of two cases:
//   (1) You've installed a global filter and a new socket was created.
//   (2) Your non-global socket filter is being attached using the SO_NKE socket option.
// If the filter allocated any memory for this attachment, it should be freed.
//

static
errno_t
sflt_attach_tcp_ipv4(
    void **cookie,
    socket_t socket
    )
{
    errno_t result = 0;
    struct log_entry *entry = NULL;

    if (gfilter_stats.filter_enabled)
    {
        entry = (struct log_entry *) OSMalloc(sizeof(struct log_entry), gmalloc_tag);

        //
        // Save the log entry as the cookie associated with this socket
        //

        *(struct log_entry **) cookie = entry;

        if (!entry) return ENOBUFS;

        lck_mtx_lock(gnetwork_filter_lock);

        sflt_attach_locked(entry, socket);

        //
        // Indicate that this is an IPv4 connection
        //

        entry->protocol = AF_INET;

        //
        // TCP IPv4 socket attached
        //

        entry->tcp_ipv4_attached = TRUE;

        OSIncrementAtomic(&(gfilter_stats.tcp_ipv4_total));
        OSIncrementAtomic(&(gfilter_stats.tcp_ipv4_in_use));

        lck_mtx_unlock(gnetwork_filter_lock);
    }
    else
    {
        *cookie = NULL;

        //
        // Return an error so that the socket filter is disassociated with this socket
        //

        result = ENXIO;
    }

    return result;
}

//
// sflt_filter.sflt_attach_func is called to notify the filter it has been attached to a new UDP socket.
// This filter is called in one of two cases:
//   (1) You've installed a global filter and a new socket was created.
//   (2) Your non-global socket filter is being attached using the SO_NKE socket option.
// If the filter allocated any memory for this attachment, it should be freed.
//

static
errno_t
sflt_attach_udp_ipv4(
    void **cookie,
    socket_t socket
    )
{
    errno_t result = 0;
    struct log_entry *entry = NULL;

    if (gfilter_stats.filter_enabled)
    {
        entry = (struct log_entry *) OSMalloc(sizeof(struct log_entry), gmalloc_tag);

        //
        // Save the log entry as the cookie associated with this socket
        //

        *(struct log_entry **) cookie = entry;

        if (!entry) return ENOBUFS;

        lck_mtx_lock(gnetwork_filter_lock);

        sflt_attach_locked(entry, socket);

        //
        // Indicate that this is an IPv4 connection
        //

        entry->protocol = AF_INET;

        //
        // UDP IPv4 socket attached
        //

        entry->udp_ipv4_attached = TRUE;

        OSIncrementAtomic(&(gfilter_stats.udp_ipv4_total));
        OSIncrementAtomic(&(gfilter_stats.udp_ipv4_in_use));

        lck_mtx_unlock(gnetwork_filter_lock);
    }
    else
    {
        *cookie = NULL;

        //
        // Return an error so that the socket filter is disassociated with this socket
        //

        result = ENXIO;
    }

    return result;
}

//
// Removes the target item from the glist_inactive list.
//

static
void
sflt_remove(
    struct log_entry *entry
    )
{
    TAILQ_REMOVE(&glist_inactive, entry, next);

    if (entry->info.first_in_packet_data)
    {
        OSFree(entry->info.first_in_packet_data, entry->info.first_in_packet_size, gmalloc_tag);

        entry->info.first_in_packet_data = NULL;
    }

    if (entry->info.first_out_packet_data)
    {
        OSFree(entry->info.first_out_packet_data, entry->info.first_out_packet_size, gmalloc_tag);

        entry->info.first_out_packet_data = NULL;
    }

    if (entry->tcp_ipv4_attached)
        OSDecrementAtomic(&(gfilter_stats.tcp_ipv4_in_use));
    else if (entry->udp_ipv4_attached)
        OSDecrementAtomic(&(gfilter_stats.udp_ipv4_in_use));

    OSFree(entry, sizeof(struct log_entry), gmalloc_tag);
}

//
// Clears log_entries from the glist_inactive list.
// Set 'all' to true when you want to flush the glist_active entries as well as the memory entries in the glist_inactive queue.
//

static
void
sflt_remove_all(
    boolean_t all
    )
{
    struct log_entry *entry = NULL, *next = NULL;

    lck_mtx_lock(gnetwork_filter_lock);

    if (all)
    {
        //
        // Move all entries into the glist_inactive queue
        //

        for (entry = TAILQ_FIRST(&glist_active); entry; entry = next)
        {
            next = TAILQ_NEXT(entry, next);

            TAILQ_REMOVE(&glist_active, entry, next);

            TAILQ_INSERT_TAIL(&glist_inactive, entry, next);

            entry->detach = TRUE;
        }
    }

    for (entry = TAILQ_FIRST(&glist_inactive); entry; entry = next)
    {
        next = TAILQ_NEXT(entry, next);

        sflt_remove(entry);
    }

    lck_mtx_unlock(gnetwork_filter_lock);
}

//
// Used to send information to the registered client iterates through all log_entries in the glist_inactive queue.
//

static
void
sflt_cleanup(
    )
{
    struct log_entry *entry = NULL, *next = NULL;

    lck_mtx_lock(gnetwork_filter_lock);

    for (entry = TAILQ_FIRST(&glist_inactive); entry; entry = next)
    {
        next = TAILQ_NEXT(entry, next);

        sflt_remove(entry);
    }

    lck_mtx_unlock(gnetwork_filter_lock);
}

//
// sflt_detach_func_locked is called by sflt_detach_func.
//

static
void
sflt_detach_locked(
    struct log_entry *entry
    )
{
    TAILQ_REMOVE(&glist_active, entry, next);

    TAILQ_INSERT_TAIL(&glist_inactive, entry, next);
}

//
// sflt_filter.sflt_detach_func is called to notify the filter it has been detached from a socket.
//

static
void
sflt_detach_ipv4(
    void *cookie,
    socket_t socket
    )
{
    void *src_address = NULL, *dst_address = NULL;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return;

    entry->detach = TRUE;

    //
    // Record stop time
    //

    microtime(&(entry->info.stop));

    boolean_t tcp_attached = entry->tcp_ipv4_attached, udp_attached = entry->udp_ipv4_attached;

    //
    // Notify user mode client
    //

    if (AF_INET == entry->protocol && tcp_attached)
    {
        struct network_tcp_monitoring *message = NULL;
        uint32_t first_in_size = 0, first_out_size = 0, total_size = 0;

        first_in_size = entry->info.first_in_packet_size;
        first_out_size = entry->info.first_out_packet_size;
        total_size = sizeof(struct network_tcp_monitoring) + first_in_size + first_out_size;

        message = (struct network_tcp_monitoring *) OSMalloc(total_size, gmalloc_tag);

        if (message)
        {
            memset(message, 0, total_size);

            //
            // Message header
            //

            message->header.event_time = entry->info.stop;
            message->header.type = NETWORK_TCP_IPV4_DETACH;

            message->header.pid = entry->info.pid;
            proc_name(message->header.pid, message->header.proc_name_pid, MAXPATHLEN);

            message->header.ppid = proc_selfppid();
            proc_name(message->header.ppid, message->header.proc_name_ppid, MAXPATHLEN);

            message->header.uid = entry->info.uid;
            message->header.gid = kauth_getgid();

            //
            // Message body
            //

            message->start_time = entry->info.start;
            message->stop_time = entry->info.stop;

            src_address = &(entry->info.source.addr4.sin_addr);
            inet_ntop(entry->protocol, src_address, (char *) message->source_address_string, sizeof(message->source_address_string));

            dst_address = &(entry->info.destination.addr4.sin_addr);
            inet_ntop(entry->protocol, dst_address, (char *) message->destination_address_string, sizeof(message->destination_address_string));

            //
            // If we have received the notification from sock_evt_connecting and sock_evt_connected
            //

            message->source_address_ether[0] = entry->info.ether_shost[0]; message->source_address_ether[1] = entry->info.ether_shost[1];
            message->source_address_ether[2] = entry->info.ether_shost[2]; message->source_address_ether[3] = entry->info.ether_shost[3];
            message->source_address_ether[4] = entry->info.ether_shost[4]; message->source_address_ether[5] = entry->info.ether_shost[5];

            message->destination_address_ether[0] = entry->info.ether_dhost[0]; message->destination_address_ether[1] = entry->info.ether_dhost[1];
            message->destination_address_ether[2] = entry->info.ether_dhost[2]; message->destination_address_ether[3] = entry->info.ether_dhost[3];
            message->destination_address_ether[4] = entry->info.ether_dhost[4]; message->destination_address_ether[5] = entry->info.ether_dhost[5];

            message->source_port = entry->info.source.addr4.sin_port;
            message->destination_port = entry->info.destination.addr4.sin_port;

            message->in_bytes = entry->info.in_bytes;
            message->in_packets = entry->info.in_packets;
            message->out_bytes = entry->info.out_bytes;
            message->out_packets = entry->info.out_packets;
            message->first_in_packet_size = first_in_size;
            message->first_out_packet_size = first_out_size;

            //
            // The remaining part
            //

            char *first_in_offset = (char *) message + sizeof(struct network_tcp_monitoring);
            char *first_out_offset = (char *) message + sizeof(struct network_tcp_monitoring) + first_in_size;

            if (first_in_size && entry->info.first_in_packet_data)
                memcpy(first_in_offset, entry->info.first_in_packet_data, first_in_size);

            if (first_out_size && entry->info.first_out_packet_data)
                memcpy(first_out_offset, entry->info.first_out_packet_data, first_out_size);

            send_message((struct message_header *) message);

            OSFree(message, total_size, gmalloc_tag);
        }
    }
    else if (AF_INET == entry->protocol && udp_attached)
    {
        //
        // We don't care about udp detach traffic in this version
        //
    }

    lck_mtx_lock(gnetwork_filter_lock);

    sflt_detach_locked(entry);

    lck_mtx_unlock(gnetwork_filter_lock);

    sflt_cleanup();

#if SFLT_TRAFFIC_TROUBLESHOOTING
    if (tcp_attached)
        printf("[%s.kext] : sflt_detach_ipv4(%s - socket=0x%X), %d/%d.\n",
               DRIVER_NAME, "tcp_ipv4", (unsigned int) socket, gfilter_stats.tcp_ipv4_in_use, gfilter_stats.tcp_ipv4_total);
    else if (udp_attached)
        printf("[%s.kext] : sflt_detach_ipv4(%s - socket=0x%X), %d/%d.\n",
               DRIVER_NAME, "udp_ipv4", (unsigned int) socket, gfilter_stats.udp_ipv4_in_use, gfilter_stats.udp_ipv4_total);
#endif
}

//
// sflt_filter.sflt_notify_func is called to notify the filter of various state changes and other events occuring on the socket.
//

static
void
sflt_notify(
    void *cookie,
    socket_t socket,
    sflt_event_t event,
    void *param
    )
{
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return;

    assert (entry->info.status);

    switch (event)
    {
    case sock_evt_connecting:
        {
            char src_string[256];
            in_port_t src_port = 0;
            void *src_address = NULL;

            if (AF_INET == entry->protocol)
            {
                //
                // Check to see if we have obtained the source socket information
                //

                if (!entry->info.source.addr4.sin_len)
                {
                    sock_getsockname(socket, (struct sockaddr*) &(entry->info.source.addr4), sizeof(entry->info.source.addr4));
                    entry->info.source.addr4.sin_port = ntohs(entry->info.source.addr4.sin_port);
                }

                src_port = entry->info.source.addr4.sin_port;
                src_address = &(entry->info.source.addr4.sin_addr);
            }
            else if (AF_INET6 == entry->protocol)
            {
                //
                // It's an AF_INET6 connection
                //

                if (!entry->info.source.addr6.sin6_len)
                {
                    sock_getsockname(socket, (struct sockaddr*) &(entry->info.source.addr6), sizeof(entry->info.source.addr6));
                    entry->info.source.addr6.sin6_port = ntohs(entry->info.source.addr6.sin6_port);
                }

                src_port = entry->info.source.addr6.sin6_port;
                src_address = &(entry->info.source.addr6.sin6_addr);
            }

            inet_ntop(entry->protocol, src_address, src_string, sizeof(src_string));

        #if SFLT_TRAFFIC_TROUBLESHOOTING
            if (entry->tcp_ipv4_attached)
                printf("[%s.kext] : sock_evt_connecting(%s - socket=0x%X), source address=%s:%d.\n",
                       DRIVER_NAME, "tcp_ipv4", (unsigned int) socket, src_string, src_port);
            else if (entry->udp_ipv4_attached)
                printf("[%s.kext] : sock_evt_connecting(%s - socket=0x%X), source address=%s:%d.\n",
                       DRIVER_NAME, "udp_ipv4", (unsigned int) socket, src_string, src_port);
        #endif
        }
        break;

    case sock_evt_connected:
        {
            char dst_string[256];
            in_port_t dst_port = 0;
            void *dst_address = NULL;

            if (AF_INET == entry->protocol)
            {
                //
                // Check to see if we have obtained the destination socket information
                //

                if (!entry->info.destination.addr4.sin_len)
                {
                    sock_getpeername(socket, (struct sockaddr*) &(entry->info.destination.addr4), sizeof(entry->info.destination.addr4));
                    entry->info.destination.addr4.sin_port = ntohs(entry->info.destination.addr4.sin_port);
                }

                dst_port = entry->info.destination.addr4.sin_port;
                dst_address = &(entry->info.destination.addr4.sin_addr);
            }
            else if (AF_INET6 == entry->protocol)
            {
                //
                // It's an AF_INET6 connection
                //

                if (!entry->info.destination.addr6.sin6_len)
                {
                    sock_getpeername(socket, (struct sockaddr*) &(entry->info.destination.addr6), sizeof(entry->info.destination.addr6));
                    entry->info.destination.addr6.sin6_port = ntohs(entry->info.destination.addr6.sin6_port);
                }

                dst_port = entry->info.destination.addr6.sin6_port;
                dst_address = &(entry->info.destination.addr6.sin6_addr);
            }

            inet_ntop(entry->protocol, dst_address, dst_string, sizeof(dst_string));

        #if SFLT_TRAFFIC_TROUBLESHOOTING
            if (entry->tcp_ipv4_attached)
                printf("[%s.kext] : sock_evt_connected(%s - socket=0x%X), destination address=%s:%d.\n",
                       DRIVER_NAME, "tcp_ipv4", (unsigned int) socket, dst_string, dst_port);
            else if (entry->udp_ipv4_attached)
                printf("[%s.kext] : sock_evt_connected(%s - socket=0x%X), destination address=%s:%d.\n",
                       DRIVER_NAME, "udp_ipv4", (unsigned int) socket, dst_string, dst_port);
        #endif
        }
        break;

#if SFLT_TRAFFIC_TROUBLESHOOTING
    case sock_evt_disconnecting:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_disconnecting(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_disconnecting(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_disconnected:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_disconnected(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_disconnected(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_flush_read:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_flush_read(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_flush_read(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_shutdown:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_shutdown(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_shutdown(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_cantrecvmore:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_cantrecvmore(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_cantrecvmore(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_cantsendmore:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_cantsendmore(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_cantsendmore(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_closing:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_closing(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_closing(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    case sock_evt_bound:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sock_evt_bound(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sock_evt_bound(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
        break;

    default:
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : Unknown event!(%s - socket=0x%X), event=0x%X.\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket, event);
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : Unknown event!(%s - socket=0x%X), event=0x%X.\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket, event);
        break;
#endif
    }
}

//
// sflt_filter.sflt_data_in_func is called to filter incoming data.
//

static
errno_t
sflt_data_in(
    void *cookie,
    socket_t socket,
    const struct sockaddr *from,
    mbuf_t *data,
    mbuf_t *control,
    sflt_data_flag_t flags
    )
{
    errno_t result = 0;
    in_port_t src_port = 0, dst_port = 0;
    char src_string[256], dst_string[256];
    void *src_address = NULL, *dst_address = NULL;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return result;

    //
    // First, let's get some statistics from the packet
    //

    mbuf_t packet = *data;
    size_t bytes = mbuf_pkthdr_len(*data);
    OSIncrementAtomic(&(entry->info.in_packets));
    OSAddAtomic((SInt32) bytes, &(entry->info.in_bytes)); // Integer overflow?

    //
    // Parse the first inbound packet
    //

    if ((AF_INET == entry->protocol) && OSCompareAndSwap(0, 1, &(entry->info.first_in_packet)))
    {
        src_port = entry->info.source.addr4.sin_port;
        dst_port = entry->info.destination.addr4.sin_port;

        memset(src_string, 0, sizeof(src_string));
        memset(dst_string, 0, sizeof(dst_string));

        src_address = &(entry->info.source.addr4.sin_addr);
        inet_ntop(entry->protocol, src_address, src_string, sizeof(src_string));

        dst_address = &(entry->info.destination.addr4.sin_addr);
        inet_ntop(entry->protocol, dst_address, dst_string, sizeof(dst_string));

        if (src_address && src_port && dst_address && dst_port)
        {
            while (packet && MBUF_TYPE_DATA != mbuf_type(packet))
            {
                packet = mbuf_next(packet);
            }

            if (packet && MBUF_TYPE_DATA == mbuf_type(packet))
            {
                struct ether_header *etherheader = (struct ether_header *) mbuf_pkthdr_header(*data);

                if (etherheader)
                {
                    //
                    // TCP IPv4 socket
                    //

                    if (entry->tcp_ipv4_attached)
                    {
                        struct ip *ipheader = (struct ip *) ((unsigned char *) etherheader + sizeof(struct ether_header));
                        unsigned int ipsize = ipheader->ip_hl * sizeof(unsigned int);
                        struct tcphdr *tcpheader = (struct tcphdr *) ((unsigned char *) ipheader + ipsize);
                        unsigned int tcpsize = tcpheader->th_off * sizeof(unsigned int);
                        unsigned int headersize = sizeof(struct ether_header) + ipsize + tcpsize;

                        if (OSCompareAndSwap(0, 1, &(entry->info.ether_header)))
                        {
                            entry->info.ether_shost[0] = etherheader->ether_shost[0]; entry->info.ether_shost[1] = etherheader->ether_shost[1];
                            entry->info.ether_shost[2] = etherheader->ether_shost[2]; entry->info.ether_shost[3] = etherheader->ether_shost[3];
                            entry->info.ether_shost[4] = etherheader->ether_shost[4]; entry->info.ether_shost[5] = etherheader->ether_shost[5];

                            entry->info.ether_dhost[0] = etherheader->ether_dhost[0]; entry->info.ether_dhost[1] = etherheader->ether_dhost[1];
                            entry->info.ether_dhost[2] = etherheader->ether_dhost[2]; entry->info.ether_dhost[3] = etherheader->ether_dhost[3];
                            entry->info.ether_dhost[4] = etherheader->ether_dhost[4]; entry->info.ether_dhost[5] = etherheader->ether_dhost[5];
                        }

                    #if SFLT_TRAFFIC_TROUBLESHOOTING
                        printf("[%s.kext] : <TCP> %s:%d(%02x:%02x:%02x:%02x:%02x:%02x)<-%s:%d(%02x:%02x:%02x:%02x:%02x:%02x).\n",
                               DRIVER_NAME, src_string, src_port,
                               etherheader->ether_dhost[0], etherheader->ether_dhost[1], etherheader->ether_dhost[2],
                               etherheader->ether_dhost[3], etherheader->ether_dhost[4], etherheader->ether_dhost[5],
                               dst_string, dst_port,
                               etherheader->ether_shost[0], etherheader->ether_shost[1], etherheader->ether_shost[2],
                               etherheader->ether_shost[3], etherheader->ether_shost[4], etherheader->ether_shost[5]);
                    #endif

                        //
                        // Save the first inbound packet data
                        //

                        if (!entry->info.first_in_packet_data)
                        {
                            if ((void *) ((unsigned char *) etherheader + headersize) == mbuf_data(packet))
                            {
                                entry->info.first_in_packet_data = OSMalloc((uint32_t) (bytes + headersize), gmalloc_tag);

                                if (entry->info.first_in_packet_data)
                                {
                                    memset(entry->info.first_in_packet_data, 0, bytes + headersize);

                                    entry->info.first_in_packet_size = (uint32_t) (bytes + headersize);

                                    memcpy(entry->info.first_in_packet_data, mbuf_pkthdr_header(*data), bytes + headersize);

                                #if SFLT_TRAFFIC_TROUBLESHOOTING
                                    hex_printf(entry->info.first_in_packet_data, bytes + headersize, HEX_PRINTF_B);
                                #endif
                                }
                            }
                            else
                            {
                                entry->info.first_in_packet_data = OSMalloc((uint32_t) mbuf_len(packet), gmalloc_tag);

                                if (entry->info.first_in_packet_data)
                                {
                                    memset(entry->info.first_in_packet_data, 0, mbuf_len(packet));

                                    entry->info.first_in_packet_size = (uint32_t) mbuf_len(packet);

                                    memcpy(entry->info.first_in_packet_data, mbuf_data(packet), mbuf_len(packet));

                                #if SFLT_TRAFFIC_TROUBLESHOOTING
                                    hex_printf(entry->info.first_in_packet_data, mbuf_len(packet), HEX_PRINTF_B);
                                #endif
                                }
                            }
                        }
                    }

                    //
                    // UDP IPv4 socket
                    //

                    else if (entry->udp_ipv4_attached)
                    {
                        char ip_dst_string[256];
                        struct ip *ipheader = (struct ip *) ((unsigned char *) etherheader + sizeof(struct ether_header));
                        unsigned int ipsize = ipheader->ip_hl * sizeof(unsigned int);
                        unsigned int headersize = sizeof(struct ether_header) + ipsize + sizeof(struct udphdr);
                        void *ip_dst_address = &ipheader->ip_dst;

                        if (OSCompareAndSwap(0, 1, &(entry->info.ether_header)))
                        {
                            entry->info.ether_shost[0] = etherheader->ether_shost[0]; entry->info.ether_shost[1] = etherheader->ether_shost[1];
                            entry->info.ether_shost[2] = etherheader->ether_shost[2]; entry->info.ether_shost[3] = etherheader->ether_shost[3];
                            entry->info.ether_shost[4] = etherheader->ether_shost[4]; entry->info.ether_shost[5] = etherheader->ether_shost[5];

                            entry->info.ether_dhost[0] = etherheader->ether_dhost[0]; entry->info.ether_dhost[1] = etherheader->ether_dhost[1];
                            entry->info.ether_dhost[2] = etherheader->ether_dhost[2]; entry->info.ether_dhost[3] = etherheader->ether_dhost[3];
                            entry->info.ether_dhost[4] = etherheader->ether_dhost[4]; entry->info.ether_dhost[5] = etherheader->ether_dhost[5];
                        }

                        if (!entry->info.source.addr4.sin_addr.s_addr)
                        {
                            inet_ntop(entry->protocol, ip_dst_address, ip_dst_string, sizeof(ip_dst_string));
                        }

                    #if SFLT_TRAFFIC_TROUBLESHOOTING
                        printf("[%s.kext] : <UDP> %s:%d(%02x:%02x:%02x:%02x:%02x:%02x)<-%s:%d(%02x:%02x:%02x:%02x:%02x:%02x).\n",
                               DRIVER_NAME, entry->info.source.addr4.sin_addr.s_addr ? src_string : ip_dst_string, src_port,
                               etherheader->ether_dhost[0], etherheader->ether_dhost[1], etherheader->ether_dhost[2],
                               etherheader->ether_dhost[3], etherheader->ether_dhost[4], etherheader->ether_dhost[5],
                               dst_string, dst_port,
                               etherheader->ether_shost[0], etherheader->ether_shost[1], etherheader->ether_shost[2],
                               etherheader->ether_shost[3], etherheader->ether_shost[4], etherheader->ether_shost[5]);
                    #endif

                        //
                        // Save the first inbound packet data
                        //

                        if (!entry->info.first_in_packet_data)
                        {
                            if ((void *) ((unsigned char *) etherheader + headersize) == mbuf_data(packet))
                            {
                                entry->info.first_in_packet_data = OSMalloc((uint32_t) (bytes + headersize), gmalloc_tag);

                                if (entry->info.first_in_packet_data)
                                {
                                    memset(entry->info.first_in_packet_data, 0, bytes + headersize);

                                    entry->info.first_in_packet_size = (uint32_t) (bytes + headersize);

                                    memcpy(entry->info.first_in_packet_data, mbuf_pkthdr_header(*data), bytes + headersize);

                                #if SFLT_TRAFFIC_TROUBLESHOOTING
                                    hex_printf(entry->info.first_in_packet_data, bytes + headersize, HEX_PRINTF_B);
                                #endif
                                }
                            }
                            else
                            {
                                entry->info.first_in_packet_data = OSMalloc((uint32_t) mbuf_len(packet), gmalloc_tag);

                                if (entry->info.first_in_packet_data)
                                {
                                    memset(entry->info.first_in_packet_data, 0, mbuf_len(packet));

                                    entry->info.first_in_packet_size = (uint32_t) mbuf_len(packet);

                                    memcpy(entry->info.first_in_packet_data, mbuf_data(packet), mbuf_len(packet));

                                #if SFLT_TRAFFIC_TROUBLESHOOTING
                                    hex_printf(entry->info.first_in_packet_data, mbuf_len(packet), HEX_PRINTF_B);
                                #endif
                                }
                            }
                        }
                    }
                }
                else
                {
                    //
                    // Impossible
                    //

                #if SFLT_TRAFFIC_TROUBLESHOOTING
                    printf("[%s.kext] : %s:%d<-%s:%d.\n", DRIVER_NAME, src_string, src_port, dst_string, dst_port);
                #endif

                    if (!entry->info.first_in_packet_data)
                    {
                        entry->info.first_in_packet_data = OSMalloc((uint32_t) mbuf_len(packet), gmalloc_tag);

                        if (entry->info.first_in_packet_data)
                        {
                            memset(entry->info.first_in_packet_data, 0, mbuf_len(packet));

                            entry->info.first_in_packet_size = (uint32_t) mbuf_len(packet);

                            memcpy(entry->info.first_in_packet_data, mbuf_data(packet), mbuf_len(packet));

                        #if SFLT_TRAFFIC_TROUBLESHOOTING
                            hex_printf(entry->info.first_in_packet_data, mbuf_len(packet), HEX_PRINTF_B);
                        #endif
                        }
                    }
                }
            }
        }
    }
    else if ((AF_INET6 == entry->protocol) && OSCompareAndSwap(0, 1, &(entry->info.first_in_packet)))
    {
        src_port = entry->info.source.addr6.sin6_port;
        dst_port = entry->info.destination.addr6.sin6_port;

        memset(src_string, 0, sizeof(src_string));
        memset(dst_string, 0, sizeof(dst_string));

        src_address = &(entry->info.source.addr6.sin6_addr);
        inet_ntop(entry->protocol, src_address, src_string, sizeof(src_string));

        dst_address = &(entry->info.destination.addr6.sin6_addr);
        inet_ntop(entry->protocol, dst_address, dst_string, sizeof(dst_string));

        if (src_address && src_port && dst_address && dst_port)
        {
            while (packet && MBUF_TYPE_DATA != mbuf_type(packet))
            {
                packet = mbuf_next(packet);
            }

            if (packet && MBUF_TYPE_DATA == mbuf_type(packet))
            {
            #if SFLT_TRAFFIC_TROUBLESHOOTING
                printf("[%s.kext] : %s:%d<-%s:%d.\n", DRIVER_NAME, src_string, src_port, dst_string, dst_port);

                hex_printf(mbuf_data(packet), mbuf_len(packet), HEX_PRINTF_B);
            #endif
            }
        }
    }

    return result;
}

//
// sflt_filter.sflt_data_out_func is called to filter outbound data.
//

static
errno_t
sflt_data_out(
    void *cookie,
    socket_t socket,
    const struct sockaddr *to,
    mbuf_t *data,
    mbuf_t *control,
    sflt_data_flag_t flags
    )
{
    errno_t result = 0;
    in_port_t src_port = 0, dst_port = 0;
    char src_string[256], dst_string[256];
    void *src_address = NULL, *dst_address = NULL;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return result;

    //
    // First, let's get some statistics from the packet
    //

    mbuf_t packet = *data;
    size_t bytes = mbuf_pkthdr_len(*data);
    OSIncrementAtomic(&(entry->info.out_packets));
    OSAddAtomic((SInt32) bytes, &(entry->info.out_bytes)); // Integer overflow?

    //
    // Parse the first outbound packet
    //

    if ((AF_INET == entry->protocol) && OSCompareAndSwap(0, 1, &(entry->info.first_out_packet)))
    {
        src_port = entry->info.source.addr4.sin_port;
        dst_port = entry->info.destination.addr4.sin_port;

        memset(src_string, 0, sizeof(src_string));
        memset(dst_string, 0, sizeof(dst_string));

        src_address = &(entry->info.source.addr4.sin_addr);
        inet_ntop(entry->protocol, src_address, src_string, sizeof(src_string));

        dst_address = &(entry->info.destination.addr4.sin_addr);
        inet_ntop(entry->protocol, dst_address, dst_string, sizeof(dst_string));

        if (src_address && src_port && dst_address && dst_port)
        {
            while (packet && MBUF_TYPE_DATA != mbuf_type(packet))
            {
                packet = mbuf_next(packet);
            }

            if (packet && MBUF_TYPE_DATA == mbuf_type(packet))
            {
                struct ether_header *etherheader = (struct ether_header *) mbuf_pkthdr_header(*data);

                if (!etherheader)
                {
                    //
                    // TCP IPv4 socket
                    //

                    if (entry->tcp_ipv4_attached)
                    {
                    #if SFLT_TRAFFIC_TROUBLESHOOTING
                        printf("[%s.kext] : <TCP> %s:%d->%s:%d.\n", DRIVER_NAME, src_string, src_port, dst_string, dst_port);
                    #endif

                        if (!entry->info.first_out_packet_data)
                        {
                            entry->info.first_out_packet_data = OSMalloc((uint32_t) mbuf_len(packet), gmalloc_tag);

                            if (entry->info.first_out_packet_data)
                            {
                                memset(entry->info.first_out_packet_data, 0, mbuf_len(packet));

                                entry->info.first_out_packet_size = (uint32_t) mbuf_len(packet);

                                memcpy(entry->info.first_out_packet_data, mbuf_data(packet), mbuf_len(packet));

                            #if SFLT_TRAFFIC_TROUBLESHOOTING
                                hex_printf(entry->info.first_out_packet_data, mbuf_len(packet), HEX_PRINTF_B);
                            #endif
                            }
                        }
                    }

                    //
                    // UDP IPv4 socket
                    //

                    else if (entry->udp_ipv4_attached)
                    {
                        //
                        // No IP header
                        //

                    #if SFLT_TRAFFIC_TROUBLESHOOTING
                        printf("[%s.kext] : <UDP> %s:%d->%s:%d.\n",
                               DRIVER_NAME, entry->info.source.addr4.sin_addr.s_addr ? src_string : "localhost",
                               src_port, dst_string, dst_port);
                    #endif

                        if (!entry->info.first_out_packet_data)
                        {
                            entry->info.first_out_packet_data = OSMalloc((uint32_t) mbuf_len(packet), gmalloc_tag);

                            if (entry->info.first_out_packet_data)
                            {
                                memset(entry->info.first_out_packet_data, 0, mbuf_len(packet));

                                entry->info.first_out_packet_size = (uint32_t) mbuf_len(packet);

                                memcpy(entry->info.first_out_packet_data, mbuf_data(packet), mbuf_len(packet));

                            #if SFLT_TRAFFIC_TROUBLESHOOTING
                                hex_printf(entry->info.first_out_packet_data, mbuf_len(packet), HEX_PRINTF_B);
                            #endif
                            }
                        }

                        //
                        // DNS query monitoring
                        //
                        // TODO: mDNSResponder monitoring
                        //

                        if (DNS_PORT == dst_port)
                        {
                            void *dnspacket = OSMalloc((uint32_t) mbuf_len(packet), gmalloc_tag);

                            if (dnspacket)
                            {
                                struct dnshdr *dnsheader = (struct dnshdr *) dnspacket;
                                unsigned char *dnsquestion = (unsigned char *) dnsheader + sizeof(struct dnshdr);
                                unsigned long length = 0, total_length = 0, index = 0, total = 0, limit = 0;

                                memset(dnspacket, 0, mbuf_len(packet));
                                memcpy(dnspacket, mbuf_data(packet), mbuf_len(packet));
                                limit = strlen((const char *) dnsquestion);

                                for (index = 0; index < limit; index++)
                                {
                                    length = dnsquestion[index];

                                    total_length += length;

                                    if (total_length > limit) goto DNS_QUERY_OVERFLOW;

                                    for (total = 0; total < length; total++)
                                    {
                                        dnsquestion[index] = dnsquestion[index + 1];

                                        index += 1;
                                    }

                                    dnsquestion[index] = '.';
                                }

                                dnsquestion[index - 1] = '\0';

                                char proc_name_pid[MAXPATHLEN] = {0};
                                memset(proc_name_pid, 0, MAXPATHLEN);
                                proc_name(entry->info.pid, proc_name_pid, MAXPATHLEN);

                                int ppid = proc_selfppid();
                                char proc_name_ppid[MAXPATHLEN] = {0};
                                memset(proc_name_ppid, 0, MAXPATHLEN);
                                proc_name(ppid, proc_name_ppid, MAXPATHLEN);

                            #if SFLT_TRAFFIC_TROUBLESHOOTING
                                printf("[%s.kext] : <DNS Query> %s:%d->%s:%d, uid=%d, process(pid %d)=%s, parent(ppid %d)=%s, query=%s.\n",
                                       DRIVER_NAME, entry->info.source.addr4.sin_addr.s_addr ? src_string : "localhost", src_port,
                                       dst_string, dst_port, entry->info.uid, entry->info.pid, proc_name_pid, ppid, proc_name_ppid, dnsquestion);
                            #endif

                                //
                                // Notify user mode client
                                //

                                struct network_dns_monitoring *message = NULL;
                                uint32_t total_size = sizeof(struct network_dns_monitoring) + (uint32_t) strlen((const char *) dnsquestion) + 1;

                                message = (struct network_dns_monitoring *) OSMalloc(total_size, gmalloc_tag);

                                if (message)
                                {
                                    size_t data_length = 0;

                                    memset(message, 0, total_size);

                                    //
                                    // Message header
                                    //

                                    microtime(&(message->header.event_time));
                                    message->header.type = NETWORK_UDP_DNS_QUERY;

                                    message->header.pid = entry->info.pid;
                                    proc_name(message->header.pid, message->header.proc_name_pid, MAXPATHLEN);

                                    message->header.ppid = ppid;
                                    proc_name(message->header.ppid, message->header.proc_name_ppid, MAXPATHLEN);

                                    message->header.uid = entry->info.uid;
                                    message->header.gid = kauth_getgid();

                                    //
                                    // Message body
                                    //

                                    if (entry->info.source.addr4.sin_addr.s_addr)
                                    {
                                        data_length = strlen((const char *) src_string);
                                        memcpy(message->source_address_string, src_string,
                                               (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
                                    }
                                    else
                                    {
                                        data_length = strlen((const char *) "localhost");
                                        memcpy(message->source_address_string, "localhost",
                                               (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
                                    }
                                    data_length = strlen((const char *) dst_string);
                                    memcpy(message->destination_address_string, dst_string,
                                           (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

                                    message->source_port = src_port;
                                    message->destination_port = dst_port;

                                    message->dns_question_length = strlen((const char *) dnsquestion);

                                    char *dns_question_offset = (char *) message + sizeof(struct network_dns_monitoring);
                                    memcpy(dns_question_offset, dnsquestion, strlen((const char *) dnsquestion));

                                    send_message((struct message_header *) message);

                                    OSFree(message, total_size, gmalloc_tag);
                                }

                            DNS_QUERY_OVERFLOW:

                                OSFree(dnspacket, (uint32_t) mbuf_len(packet), gmalloc_tag);
                            }
                        }
                    }
                }
                else
                {
                    //
                    // Impossible
                    //
                }
            }
        }
    }
    else if ((AF_INET6 == entry->protocol) && OSCompareAndSwap(0, 1, &(entry->info.first_out_packet)))
    {
        src_port = entry->info.source.addr6.sin6_port;
        dst_port = entry->info.destination.addr6.sin6_port;

        memset(src_string, 0, sizeof(src_string));
        memset(dst_string, 0, sizeof(dst_string));

        src_address = &(entry->info.source.addr6.sin6_addr);
        inet_ntop(entry->protocol, src_address, src_string, sizeof(src_string));

        dst_address = &(entry->info.destination.addr6.sin6_addr);
        inet_ntop(entry->protocol, dst_address, dst_string, sizeof(dst_string));

        if (src_address && src_port && dst_address && dst_port)
        {
            while (packet && MBUF_TYPE_DATA != mbuf_type(packet))
            {
                packet = mbuf_next(packet);
            }

            if (packet && MBUF_TYPE_DATA == mbuf_type(packet))
            {
            #if SFLT_TRAFFIC_TROUBLESHOOTING
                printf("[%s.kext] : %s:%d->%s:%d.\n", DRIVER_NAME, src_string, src_port, dst_string, dst_port);

                hex_printf(mbuf_data(packet), mbuf_len(packet), HEX_PRINTF_B);
            #endif
            }
        }
    }

    return result;
}

//
// sflt_filter.sflt_connect_in_func is called to filter inbound connections.
//

static
errno_t
sflt_connect_in(
    void *cookie,
    socket_t socket,
    const struct sockaddr *from
    )
{
    errno_t result = 0;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    //
    // Verify that the address is AF_INET or AF_INET6
    //

    assert ((AF_INET == from->sa_family) || (AF_INET6 == from->sa_family));

    if (!entry) return result;

    OSBitOrAtomic(STATE_CONNECT_IN, &(entry->info.status));

    if (AF_INET == entry->protocol)
    {
        //
        // Save the destination address in the info.destination field
        //

        if (sizeof(entry->info.destination.addr4) >= from->sa_len)
        {
            bcopy(from, &(entry->info.destination.addr4), from->sa_len);

            //
            // Ensure port is in host format
            //

            entry->info.destination.addr4.sin_port = ntohs(entry->info.destination.addr4.sin_port);
        }
    }
    else if (AF_INET6 == entry->protocol)
    {
        //
        // Save the destination address in the info.destination field
        //

        if (sizeof(entry->info.destination.addr6) >= from->sa_len)
        {
            bcopy(from, &(entry->info.destination.addr6), from->sa_len);

            //
            // Ensure port is in host format
            //

            entry->info.destination.addr6.sin6_port = ntohs(entry->info.destination.addr6.sin6_port);
        }
    }

    return result;
}

//
// sflt_filter.sflt_connect_out_func is called to filter outbound connections.
//

static
errno_t
sflt_connect_out(
    void *cookie,
    socket_t socket,
    const struct sockaddr *to
    )
{
    errno_t result = 0;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    //
    // Verify that the address is AF_INET or AF_INET6
    //

    assert ((AF_INET == to->sa_family) || (AF_INET6 == to->sa_family));

    if (!entry) return result;

    OSBitOrAtomic(STATE_CONNECT_OUT, &(entry->info.status));

    if (AF_INET == entry->protocol)
    {
        //
        // Save the destination address in the info.destination field
        //

        if (sizeof(entry->info.destination.addr4) >= to->sa_len)
        {
            bcopy(to, &(entry->info.destination.addr4), to->sa_len);

            //
            // Ensure port is in host format
            //

            entry->info.destination.addr4.sin_port = ntohs(entry->info.destination.addr4.sin_port);
        }
    }
    else if (AF_INET6 == entry->protocol)
    {
        //
        // Save the destination address in the info.destination field
        //

        if (sizeof(entry->info.destination.addr6) >= to->sa_len)
        {
            bcopy(to, &(entry->info.destination.addr6), to->sa_len);

            //
            // Ensure port is in host format
            //

            entry->info.destination.addr6.sin6_port = ntohs(entry->info.destination.addr6.sin6_port);
        }
    }

    return result;
}

//
// sflt_filter.sflt_bind_func is called before performing a bind operation on a socket.
//

static
errno_t
sflt_bind(
    void *cookie,
    socket_t socket,
    const struct sockaddr *to
    )
{
    errno_t result = 0;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    //
    // Verify that the address is AF_INET or AF_INET6
    //

    assert ((AF_INET == to->sa_family) || (AF_INET6 == to->sa_family));

    if (!entry) return result;

    if (AF_INET == entry->protocol)
    {
        //
        // Save the source address in the info.source field
        //

        if (sizeof(entry->info.source.addr4) >= to->sa_len)
        {
            bcopy(to, &(entry->info.source.addr4), to->sa_len);

            //
            // Ensure port is in host format
            //

            entry->info.source.addr4.sin_port = ntohs(entry->info.source.addr4.sin_port);
        }
    }
    else if (AF_INET6 == entry->protocol)
    {
        //
        // Save the source address in the info.source field
        //

        if (sizeof(entry->info.source.addr6) >= to->sa_len)
        {
            bcopy(to, &(entry->info.source.addr6), to->sa_len);

            //
            // Ensure port is in host format
            //

            entry->info.source.addr6.sin6_port = ntohs(entry->info.source.addr6.sin6_port);
        }
    }

    return result;
}

#if SFLT_TRAFFIC_TROUBLESHOOTING
static
const char *
get_socket_option_name(
    int option
    )
{
    char *name = NULL;

    switch (option)
    {
    case SO_ACCEPTCONN:
        name = "SO_ACCEPTCONN";  // socket has had listen()
        break;

    case SO_REUSEADDR:
        name = "SO_REUSEADDR";   // allow local address reuse
        break;

    case SO_KEEPALIVE:
        name = "SO_KEEPALIVE";   // keep connections alive
        break;

    case SO_DONTROUTE:
        name = "SO_DONTROUTE";   // just use interface addresses
        break;

    case SO_BROADCAST:
        name = "SO_BROADCAST";   // permit sending of broadcast messages
        break;

    case SO_USELOOPBACK:
        name = "SO_USELOOPBACK"; // bypass hardware when possible
        break;

    case SO_LINGER:
        name = "SO_LINGER";      // linger on close if data present (in seconds)
        break;

    case SO_OOBINLINE:
        name = "SO_OOBINLINE";   // leave received OOB data in line
        break;

    case SO_REUSEPORT:
        name = "SO_REUSEPORT";   // allow local address & port reuse
        break;

    case SO_TIMESTAMP:
        name = "SO_TIMESTAMP";   // timestamp received dgram traffic
        break;

    case SO_DONTTRUNC:
        name = "SO_DONTTRUNC";   // retain unread data
        break;

    case SO_SNDBUF:
        name = "SO_SNDBUF";      // send buffer size
        break;

    case SO_RCVBUF:
        name = "SO_RCVBUF";      // receive buffer size
        break;

    case SO_SNDLOWAT:
        name = "SO_SNDLOWAT";    // send low-water mark
        break;

    case SO_RCVLOWAT:
        name = "SO_RCVLOWAT";    // receive low-water mark
        break;

    case SO_SNDTIMEO:
        name = "SO_SNDTIMEO";    // send timeout
        break;

    case SO_RCVTIMEO:
        name = "SO_RCVTIMEO";    // receive timeout
        break;

    case SO_ERROR:
        name = "SO_ERROR";       // get error status and clear
        break;

    case SO_TYPE:
        name = "SO_TYPE";        // get socket type
        break;

    case SO_NOSIGPIPE:
        name = "SO_NOSIGPIPE";   // APPLE: No SIGPIPE on EPIPE
        break;

    default:
        name = "UNKNOWN OPTION";
        break;
    }

    return name;
}
#endif

//
// sflt_filter.sflt_setoption_func is called before performing setsockopt on a socket.
//

static
errno_t
sflt_set_option(
    void *cookie,
    socket_t socket,
    sockopt_t option
    )
{
    errno_t result = 0;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return result;

#if SFLT_TRAFFIC_TROUBLESHOOTING
    if (SOL_SOCKET == sockopt_level(option))
    {
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sflt_set_option(%s - socket=0x%X), option=%s.\n",
                   DRIVER_NAME, "tcp_ipv4", (unsigned int) socket, get_socket_option_name(sockopt_name(option)));
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sflt_set_option(%s - socket=0x%X), option=%s.\n",
                   DRIVER_NAME, "udp_ipv4", (unsigned int) socket, get_socket_option_name(sockopt_name(option)));
    }
#endif

    return result;
}

//
// sflt_filter.sflt_getoption_func is called before performing getsockopt on a socket.
//

static
errno_t
sflt_get_option(
    void *cookie,
    socket_t socket,
    sockopt_t option
    )
{
    errno_t result = 0;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return result;

#if SFLT_TRAFFIC_TROUBLESHOOTING
    if (SOL_SOCKET == sockopt_level(option))
    {
        if (entry->tcp_ipv4_attached)
            printf("[%s.kext] : sflt_get_option(%s - socket=0x%X), option=%s.\n",
                   DRIVER_NAME, "tcp_ipv4", (unsigned int) socket, get_socket_option_name(sockopt_name(option)));
        else if (entry->udp_ipv4_attached)
            printf("[%s.kext] : sflt_get_option(%s - socket=0x%X), option=%s.\n",
                   DRIVER_NAME, "udp_ipv4", (unsigned int) socket, get_socket_option_name(sockopt_name(option)));
    }
#endif

    return result;
}

//
// sflt_filter.sflt_listen_func is called before performing listen on a socket.
//

static
errno_t
sflt_listen(
    void *cookie,
    socket_t socket
    )
{
    errno_t result = 0;
    struct log_entry *entry = get_entry_from_cookie(cookie);

    if (!entry) return result;

#if SFLT_TRAFFIC_TROUBLESHOOTING
    if (entry->tcp_ipv4_attached)
        printf("[%s.kext] : sflt_listen(%s - socket=0x%X).\n", DRIVER_NAME, "tcp_ipv4", (unsigned int) socket);
    else if (entry->udp_ipv4_attached)
        printf("[%s.kext] : sflt_listen(%s - socket=0x%X).\n", DRIVER_NAME, "udp_ipv4", (unsigned int) socket);
#endif

    return result;
}

//
// Dispatch vector for TCP IPv4 socket functions
//

static struct sflt_filter sflt_tcp_ipv4 =
{
    SFLT_TCP_IPV4_HANDLE, // sflt_handle
    SFLT_GLOBAL,          // sflt_flags
    SFLT_BUNDLE_ID,       // sflt_name
    sflt_unregistered,    // sflt_unregistered_func
    sflt_attach_tcp_ipv4, // sflt_attach_func
    sflt_detach_ipv4,     // sflt_detach_func
    sflt_notify,          // sflt_notify_func
    NULL,                 // sflt_getpeername_func
    NULL,                 // sflt_getsockname_func
    sflt_data_in,         // sflt_data_in_func
    sflt_data_out,        // sflt_data_out_func
    sflt_connect_in,      // sflt_connect_in_func
    sflt_connect_out,     // sflt_connect_out_func
    sflt_bind,            // sflt_bind_func
    sflt_set_option,      // sflt_setoption_func
    sflt_get_option,      // sflt_getoption_func
    sflt_listen,          // sflt_listen_func
    NULL,                 // sflt_ioctl_func
                          // sflt_filter_ext
};

//
// Dispatch vector for UDP IPv4 socket functions
//

static struct sflt_filter sflt_udp_ipv4 =
{
    SFLT_UDP_IPV4_HANDLE, // sflt_handle
    SFLT_GLOBAL,          // sflt_flags
    SFLT_BUNDLE_ID,       // sflt_name
    sflt_unregistered,    // sflt_unregistered_func
    sflt_attach_udp_ipv4, // sflt_attach_func
    sflt_detach_ipv4,     // sflt_detach_func
    sflt_notify,          // sflt_notify_func
    NULL,                 // sflt_getpeername_func
    NULL,                 // sflt_getsockname_func
    sflt_data_in,         // sflt_data_in_func
    sflt_data_out,        // sflt_data_out_func
    sflt_connect_in,      // sflt_connect_in_func
    sflt_connect_out,     // sflt_connect_out_func
    sflt_bind,            // sflt_bind_func
    sflt_set_option,      // sflt_setoption_func
    sflt_get_option,      // sflt_getoption_func
    sflt_listen,          // sflt_listen_func
    NULL,                 // sflt_ioctl_func
                          // sflt_filter_ext
};

extern
kern_return_t
sflt_initialization(
    boolean_t flag
    )
{
    kern_return_t status = KERN_SUCCESS;

    if (flag)
    {
        //
        // Initialize the queues which we are going to use
        //

        TAILQ_INIT(&glist_active);
        TAILQ_INIT(&glist_inactive);

        //
        // Register the filter with AF_INET domain, SOCK_STREAM type and TCP protocol
        //

        status = sflt_register(&sflt_tcp_ipv4, AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (!status)
        {
            OSCompareAndSwap(0, 1, &gfilter_stats.tcp_ipv4_registered);
        }
        else
        {
        #if SFLT_TROUBLESHOOTING
            printf("[%s.kext] : Error! sflt_register(%s - %s) failed, status=%d.\n",
                   DRIVER_NAME, "tcp_ipv4", flag ? "true" : "false", status);
        #endif

            return status;
        }

        //
        // Register the filter with AF_INET domain, SOCK_DGRAM type and UDP protocol
        //

        status = sflt_register(&sflt_udp_ipv4, AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (!status)
        {
            OSCompareAndSwap(0, 1, &gfilter_stats.udp_ipv4_registered);

            //
            // Socket filter enabled
            //

            lck_mtx_lock(gnetwork_filter_lock);

            gfilter_stats.filter_enabled = TRUE;

            lck_mtx_unlock(gnetwork_filter_lock);
        }
        else
        {
        #if SFLT_TROUBLESHOOTING
            printf("[%s.kext] : Error! sflt_register(%s - %s) failed, status=%d.\n",
                   DRIVER_NAME, "udp_ipv4", flag ? "true" : "false", status);
        #endif

            return status;
        }
    }
    else
    {
        if (!gfilter_stats.tcp_ipv4_registered &&
            !gfilter_stats.udp_ipv4_registered) return status;

        //
        // Shut down the filter
        //

        if (gnetwork_filter_lock) lck_mtx_lock(gnetwork_filter_lock);

        gfilter_stats.filter_enabled = FALSE;

        if (gnetwork_filter_lock) lck_mtx_unlock(gnetwork_filter_lock);

        status = sflt_unregister(SFLT_TCP_IPV4_HANDLE);

        if (!status)
        {
            status = sflt_unregister(SFLT_UDP_IPV4_HANDLE);
        }

        struct timespec second = {0};

        do
        {
            second.tv_sec = 0;
            second.tv_nsec = 100;

            msleep(&gfilter_stats.tcp_ipv4_in_use, NULL, PUSER, "remove_filter", &second);
        } while (gfilter_stats.tcp_ipv4_in_use);

        do
        {
            second.tv_sec = 0;
            second.tv_nsec = 100;

            msleep(&gfilter_stats.udp_ipv4_in_use, NULL, PUSER, "remove_filter", &second);
        } while (gfilter_stats.udp_ipv4_in_use);

        //
        // We don't have to do this
        //

        sflt_remove_all(TRUE);

    #if SFLT_TROUBLESHOOTING
        printf("[%s.kext] : Stop socket monitoring (tcp_ipv4_in_use=%d, tcp_ipv4_total=%d, udp_ipv4_in_use=%d, udp_ipv4_total=%d).\n",
               DRIVER_NAME, gfilter_stats.tcp_ipv4_in_use, gfilter_stats.tcp_ipv4_total,
               gfilter_stats.udp_ipv4_in_use, gfilter_stats.udp_ipv4_total);
    #endif
    }

    return status;
}