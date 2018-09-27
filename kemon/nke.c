/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    nke.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#include <IOKit/IOLib.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSMalloc.h>
#include <sys/kern_control.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>
#include "include.h"
#include "trace.h"
#include "nke.h"


//
// Mutex lock
//

lck_mtx_t *gnke_event_log_lock = NULL;

//
// NKE log entry
//

struct nke_log_entry
{
    TAILQ_ENTRY(nke_log_entry) next;
    uint32_t entry_size;
    uint32_t retry;
};

TAILQ_HEAD(ListEntry, nke_log_entry);

static struct ListEntry gnke_event_list;

//
// Connection status
//

static UInt32 gctl_registered = 0;

static UInt32 gctl_connected = 0;

static boolean_t gnke_disconnecting = FALSE;

//
// User client connection
//

static kern_ctl_ref gctl_ref = NULL;

static kern_ctl_ref gctl_connection_ref = NULL;

static u_int32_t gctl_connection_unit = 0;

//
// Statistics
//

static SInt32 genqueued_event = 0;

static SInt32 gevent_lost = 0;

//
// The ctl_setopt_func is used to handle set socket option calls for the SYSPROTO_CONTROL option level
//

static
int
ctl_setopt(
    kern_ctl_ref ctl_ref,
    u_int32_t unit,
    void *unitinfo,
    int opt,
    void *data,
    size_t len
    )
{
    int error = 0;

    return error;
}

//
// The ctl_getopt_func is used to handle client get socket option requests for the SYSPROTO_CONTROL option level
//

static
int
ctl_getopt(
    kern_ctl_ref ctl_ref,
    u_int32_t unit,
    void *unitinfo,
    int opt,
    void *data,
    size_t *len
    )
{
    int error = 0;

    return error;
}

//
// The ctl_connect_func is used to receive notification of a client connecting to the kernel control
//

static
int
ctl_connect(
    kern_ctl_ref ctl_ref,
    struct sockaddr_ctl *sac,
    void **unitinfo
    )
{
    int status = -1;

    if (OSCompareAndSwap(0, 1, &gctl_connected))
    {
        if (!gctl_connection_ref)
        {
            gctl_connection_ref = ctl_ref;
            gctl_connection_unit = sac->sc_unit;

            int pid = proc_selfpid();
            char proc_name_pid[MAXPATHLEN] = {0};
            memset(proc_name_pid, 0, MAXPATHLEN);
            proc_name(pid, proc_name_pid, MAXPATHLEN);

            int ppid = proc_selfppid();
            char proc_name_ppid[MAXPATHLEN] = {0};
            memset(proc_name_ppid, 0, MAXPATHLEN);
            proc_name(ppid, proc_name_ppid, MAXPATHLEN);

        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : connection=%p, unit=%x, process(pid %d)=%s, parent(ppid %d)=%s.\n",
                   DRIVER_NAME, gctl_connection_ref, gctl_connection_unit, pid, proc_name_pid, ppid, proc_name_ppid);
        #endif

            status = 0;
        }
    }

    return status;
}

//
// The ctl_disconnect_func is used to receive notification that a client has disconnected from the kernel control
//

static
int
ctl_disconnect(
    kern_ctl_ref ctl_ref,
    u_int32_t unit,
    void *unitinfo
    )
{
    if (!gctl_connection_ref || (gctl_connection_unit != unit))
    {
        return -1;
    }
    else
    {
        gctl_connection_ref = NULL;
        gctl_connection_unit = 0;

        OSCompareAndSwap(1, 0, &gctl_connected);
    }

    return 0;
}

#if FRAMEWORK_TROUBLESHOOTING
static
const char *
get_message_type(
    int type
    )
{
    char *result = NULL;

    switch (type)
    {
    case FILEOP_OPEN:
        result = "FILEOP_OPEN";
        break;

    case FILEOP_CREATE:
        result = "FILEOP_CREATE";
        break;

    case FILEOP_CLOSE:
        result = "FILEOP_CLOSE";
        break;

    case FILEOP_RENAME:
        result = "FILEOP_RENAME";
        break;

    case FILEOP_EXCHANGE:
        result = "FILEOP_EXCHANGE";
        break;

    case FILEOP_LINK:
        result = "FILEOP_LINK";
        break;

    case FILEOP_EXEC:
        result = "FILEOP_EXECUTE";
        break;

    case FILEOP_DELETE:
        result = "FILEOP_DELETE";
        break;

    case FILEOP_WILL_RENAME:
        result = "FILEOP_WILL_RENAME";
        break;

    case FILEOP_WRITE_OR_APPEND:
        result = "FILEOP_WRITE_OR_APPEND";
        break;

    case DEVICE_OPEN:
        result = "DEVICE_OPEN";
        break;

    case MONITORING_DYNAMIC_LIBRARY:
        result = "MONITORING_DYNAMIC_LIBRARY";
        break;

    case MONITORING_KEXT_PRE_CALLBACK:
        result = "MONITORING_KEXT_PRE_CALLBACK";
        break;

    case MONITORING_KEXT_POST_CALLBACK:
        result = "MONITORING_KEXT_POST_CALLBACK";
        break;

    case NETWORK_TCP_IPV4_DETACH:
        result = "NETWORK_TCP_IPV4_DETACH";
        break;

    case NETWORK_UDP_DNS_QUERY:
        result = "NETWORK_UDP_DNS_QUERY";
        break;

    default:
        result = "UNKNOWN MESSAGE TYPE";
        break;
    }

    return result;
}

static
void
dump_message(
    struct message_header *message
    )
{
    if (!message) return;

    switch (message->type)
    {
    case FILEOP_OPEN:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_OPEN, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid, fileop_message->body.fileop_open.path);
        }
        break;

    case FILEOP_CREATE:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_CREATE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid, fileop_message->body.fileop_create.path);
        }
        break;

    case FILEOP_CLOSE:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_CLOSE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s, modified=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_close.path, fileop_message->body.fileop_close.modified ? "true" : "false");
        }
        break;

    case FILEOP_RENAME:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_RENAME, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, from=%s, to=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_rename.from, fileop_message->body.fileop_rename.to);
        }
        break;

    case FILEOP_EXCHANGE:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_EXCHANGE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, file1=%s, file2=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_exchange.file1, fileop_message->body.fileop_exchange.file2);
        }
        break;

    case FILEOP_LINK:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_LINK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, original=%s, new=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_link.original, fileop_message->body.fileop_link.new_link);
        }
        break;

    case FILEOP_EXEC:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            char *command_line = (char *) fileop_message + sizeof(struct file_operation_monitoring);

            printf("[%s.kext] : action=KAUTH_FILEOP_EXEC, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s, command line=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_exec.path, command_line);
        }
        break;

    case FILEOP_DELETE:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_DELETE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid, fileop_message->body.fileop_delete.path);
        }
        break;

    case FILEOP_WILL_RENAME:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_WILL_RENAME, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, from=%s, to=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_will_rename.from, fileop_message->body.fileop_will_rename.to);
        }
        break;

    case FILEOP_WRITE_OR_APPEND:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_WRITE_OR_APPEND, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid, fileop_message->body.fileop_write_or_append.path);
        }
        break;

    case DEVICE_OPEN:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_DEVICE_OPEN, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid, fileop_message->header.pid, fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid, fileop_message->header.proc_name_ppid, fileop_message->body.device_open.path);
        }
        break;

    case MONITORING_DYNAMIC_LIBRARY:
        {
            struct dynamic_library_monitoring *library_message = (struct dynamic_library_monitoring *) message;

            printf("[%s.kext] : action=MONITORING_DYNAMIC_LIBRARY, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, dynamic library path=%s.\n",
                   DRIVER_NAME, library_message->header.uid, library_message->header.pid, library_message->header.proc_name_pid,
                   library_message->header.ppid, library_message->header.proc_name_ppid, library_message->library_path);
        }
        break;

    case MONITORING_KEXT_PRE_CALLBACK:
        {
            struct kernel_module_monitoring *kext_message = (struct kernel_module_monitoring *) message;

            printf("[%s.kext] : action=MONITORING_KEXT_PRE_CALLBACK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, name=%s, path=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
                   DRIVER_NAME, kext_message->header.uid, kext_message->header.pid, kext_message->header.proc_name_pid,
                   kext_message->header.ppid, kext_message->header.proc_name_ppid, kext_message->module_name, kext_message->module_path,
                   kext_message->module_version, kext_message->module_base, kext_message->module_size);
        }
        break;

    case MONITORING_KEXT_POST_CALLBACK:
        {
            struct kernel_module_monitoring *kext_message = (struct kernel_module_monitoring *) message;

            printf("[%s.kext] : action=MONITORING_KEXT_POST_CALLBACK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, status=%d, name=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
                   DRIVER_NAME, kext_message->header.uid, kext_message->header.pid, kext_message->header.proc_name_pid,
                   kext_message->header.ppid, kext_message->header.proc_name_ppid, kext_message->return_value, kext_message->module_name,
                   kext_message->module_version, kext_message->module_base, kext_message->module_size);
        }
        break;

    case NETWORK_TCP_IPV4_DETACH:
        {
            struct timeval diff = {0};
            struct network_tcp_monitoring *tcp_monitoring = (struct network_tcp_monitoring *) message;
            char *first_in_offset = (char *) tcp_monitoring + sizeof(struct network_tcp_monitoring);
            char *first_out_offset = (char *) tcp_monitoring + sizeof(struct network_tcp_monitoring) + tcp_monitoring->first_in_packet_size;

            timersub(&tcp_monitoring->stop_time, &tcp_monitoring->start_time, &diff);

            if (tcp_monitoring->in_packets)
            {
                printf("[%s.kext] : action=TCP_IPV4_DETACH, duration=%ld.%6d seconds, %s:%d(%02x:%02x:%02x:%02x:%02x:%02x)<->%s:%d(%02x:%02x:%02x:%02x:%02x:%02x), uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, in=%d packets, %d bytes, out=%d packets, %d bytes.\n",
                       DRIVER_NAME, diff.tv_sec, diff.tv_usec,
                       tcp_monitoring->source_address_string, tcp_monitoring->source_port,
                       tcp_monitoring->source_address_ether[0], tcp_monitoring->source_address_ether[1], tcp_monitoring->source_address_ether[2],
                       tcp_monitoring->source_address_ether[3], tcp_monitoring->source_address_ether[4], tcp_monitoring->source_address_ether[5],
                       tcp_monitoring->destination_address_string, tcp_monitoring->destination_port,
                       tcp_monitoring->destination_address_ether[0], tcp_monitoring->destination_address_ether[1], tcp_monitoring->destination_address_ether[2],
                       tcp_monitoring->destination_address_ether[3], tcp_monitoring->destination_address_ether[4], tcp_monitoring->destination_address_ether[5],
                       tcp_monitoring->header.uid, tcp_monitoring->header.pid, tcp_monitoring->header.proc_name_pid,
                       tcp_monitoring->header.ppid, tcp_monitoring->header.proc_name_ppid,
                       tcp_monitoring->in_packets, tcp_monitoring->in_bytes, tcp_monitoring->out_packets, tcp_monitoring->out_bytes);
            }
            else
            {
                printf("[%s.kext] : action=TCP_IPV4_DETACH, duration=%ld.%6d seconds, %s:%d%s%s:%d, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, in=%d packets, %d bytes, out=%d packets, %d bytes.\n",
                       DRIVER_NAME, diff.tv_sec, diff.tv_usec,
                       tcp_monitoring->source_address_string, tcp_monitoring->source_port,
                       tcp_monitoring->out_packets ? "-->" : "---",
                       tcp_monitoring->destination_address_string, tcp_monitoring->destination_port,
                       tcp_monitoring->header.uid, tcp_monitoring->header.pid, tcp_monitoring->header.proc_name_pid,
                       tcp_monitoring->header.ppid, tcp_monitoring->header.proc_name_ppid,
                       tcp_monitoring->in_packets, tcp_monitoring->in_bytes, tcp_monitoring->out_packets, tcp_monitoring->out_bytes);
            }

            if (tcp_monitoring->first_in_packet_size)
            {
                printf("[%s.kext] : Dump first IN packet.\n", DRIVER_NAME);

                hex_printf(first_in_offset, tcp_monitoring->first_in_packet_size, HEX_PRINTF_B);
            }

            if (tcp_monitoring->first_out_packet_size)
            {
                printf("[%s.kext] : Dump first OUT packet.\n", DRIVER_NAME);

                hex_printf(first_out_offset, tcp_monitoring->first_out_packet_size, HEX_PRINTF_B);
            }
        }
        break;

    case NETWORK_UDP_DNS_QUERY:
        {
            struct network_dns_monitoring *dns_monitoring = (struct network_dns_monitoring *) message;

            char *dns_question = (char *) dns_monitoring + sizeof(struct network_dns_monitoring);

            printf("[%s.kext] : action=UDP_DNS_QUERY, %s:%d-->%s:%d, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, query=%s.\n",
                   DRIVER_NAME, dns_monitoring->source_address_string, dns_monitoring->source_port,
                   dns_monitoring->destination_address_string, dns_monitoring->destination_port,
                   dns_monitoring->header.uid, dns_monitoring->header.pid, dns_monitoring->header.proc_name_pid,
                   dns_monitoring->header.ppid, dns_monitoring->header.proc_name_ppid, dns_question);
        }
        break;

    default:

        break;
    }
}
#endif

static
errno_t
send_message_internal(
    struct message_header *message
    )
{
    errno_t status = 0;

    if (!gctl_connection_ref || !gctl_connection_unit ||
        !gctl_registered || gnke_disconnecting) return EPERM;

    switch (message->type)
    {
    case FILEOP_OPEN:
    case FILEOP_CREATE:
    case FILEOP_CLOSE:
    case FILEOP_RENAME:
    case FILEOP_EXCHANGE:
    case FILEOP_LINK:
    case FILEOP_DELETE:
    case FILEOP_WILL_RENAME:
    case FILEOP_WRITE_OR_APPEND:
    case DEVICE_OPEN:
        {
            status = ctl_enqueuedata(gctl_connection_ref, gctl_connection_unit, message,
                                     sizeof(struct file_operation_monitoring), CTL_DATA_EOR);
        }
        break;

    case FILEOP_EXEC:
        {
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;

            status = ctl_enqueuedata(gctl_connection_ref, gctl_connection_unit, message,
                                     sizeof(struct file_operation_monitoring) +
                                     fileop_message->body.fileop_exec.command_line_length, CTL_DATA_EOR);
        }
        break;

    case MONITORING_DYNAMIC_LIBRARY:
        {
            status = ctl_enqueuedata(gctl_connection_ref, gctl_connection_unit, message,
                                     sizeof(struct dynamic_library_monitoring), CTL_DATA_EOR);
        }
        break;

    case MONITORING_KEXT_PRE_CALLBACK:
    case MONITORING_KEXT_POST_CALLBACK:
        {
            status = ctl_enqueuedata(gctl_connection_ref, gctl_connection_unit, message,
                                     sizeof(struct kernel_module_monitoring), CTL_DATA_EOR);
        }
        break;

    case NETWORK_TCP_IPV4_DETACH:
        {
            struct network_tcp_monitoring *tcp_monitoring = (struct network_tcp_monitoring *) message;

            status = ctl_enqueuedata(gctl_connection_ref, gctl_connection_unit, message,
                                     sizeof(struct network_tcp_monitoring) + tcp_monitoring->first_in_packet_size +
                                     tcp_monitoring->first_out_packet_size, CTL_DATA_EOR);
        }
        break;

    case NETWORK_UDP_DNS_QUERY:
        {
            struct network_dns_monitoring *dns_monitoring = (struct network_dns_monitoring *) message;

            status = ctl_enqueuedata(gctl_connection_ref, gctl_connection_unit, message,
                                     sizeof(struct network_dns_monitoring) + dns_monitoring->dns_question_length, CTL_DATA_EOR);
        }
        break;

    default:

        break;
    }

    return status;
}

static
void
insert_message(
    struct nke_log_entry *entry
    )
{
    if (genqueued_event < ENQUEUED_EVENT_LIMIT)
    {
        lck_mtx_lock(gnke_event_log_lock);

        TAILQ_INSERT_TAIL(&gnke_event_list, entry, next);

        lck_mtx_unlock(gnke_event_log_lock);

        OSIncrementAtomic(&genqueued_event);
    }
    else
    {
        OSFree(entry, entry->entry_size, gmalloc_tag);

        OSIncrementAtomic(&gevent_lost);
    }
}

extern
void
send_message(
    struct message_header *message
    )
{
    if (!message) return;

#if FRAMEWORK_TROUBLESHOOTING
    dump_message(message);
#endif

    if (!gctl_connection_ref || !gctl_connection_unit ||
        !gctl_registered || gnke_disconnecting) return;

    switch (message->type)
    {
    //
    // We don't care about the FILEOP_OPEN, FILEOP_CLOSE, DEVICE_OPEN and FILEOP_WILL_RENAME in this version
    //

//  case FILEOP_OPEN:
    case FILEOP_CREATE:
//  case FILEOP_CLOSE:
    case FILEOP_RENAME:
    case FILEOP_EXCHANGE:
    case FILEOP_LINK:
    case FILEOP_DELETE:
//  case FILEOP_WILL_RENAME:
    case FILEOP_WRITE_OR_APPEND:
//  case DEVICE_OPEN:
        {
            char *entry_offset = NULL;
            uint32_t entry_size = (uint32_t) (sizeof(struct nke_log_entry) +
                                              sizeof(struct file_operation_monitoring));

            struct nke_log_entry *entry = (struct nke_log_entry *) OSMalloc(entry_size, gmalloc_tag);

            if (entry)
            {
                memset(entry, 0, entry_size);

                entry->entry_size = entry_size;

                entry_offset = (char *) entry + sizeof(struct nke_log_entry);
                memcpy(entry_offset, message, sizeof(struct file_operation_monitoring));

                insert_message(entry);
            }
            else
            {
                OSIncrementAtomic(&gevent_lost);
            }
        }
        break;

    case FILEOP_EXEC:
        {
            char *entry_offset = NULL;
            struct file_operation_monitoring *fileop_message = (struct file_operation_monitoring *) message;
            uint32_t entry_size = (uint32_t) (sizeof(struct nke_log_entry) +
                                              sizeof(struct file_operation_monitoring) +
                                              fileop_message->body.fileop_exec.command_line_length);

            struct nke_log_entry *entry = (struct nke_log_entry *) OSMalloc(entry_size, gmalloc_tag);

            if (entry)
            {
                memset(entry, 0, entry_size);

                entry->entry_size = entry_size;

                entry_offset = (char *) entry + sizeof(struct nke_log_entry);
                memcpy(entry_offset, message, sizeof(struct file_operation_monitoring) +
                       fileop_message->body.fileop_exec.command_line_length);

                insert_message(entry);
            }
            else
            {
                OSIncrementAtomic(&gevent_lost);
            }
        }
        break;

    case MONITORING_DYNAMIC_LIBRARY:
        {
            char *entry_offset = NULL;
            uint32_t entry_size = (uint32_t) (sizeof(struct nke_log_entry) +
                                              sizeof(struct dynamic_library_monitoring));

            struct nke_log_entry *entry = (struct nke_log_entry *) OSMalloc(entry_size, gmalloc_tag);

            if (entry)
            {
                memset(entry, 0, entry_size);

                entry->entry_size = entry_size;

                entry_offset = (char *) entry + sizeof(struct nke_log_entry);
                memcpy(entry_offset, message, sizeof(struct dynamic_library_monitoring));

                insert_message(entry);
            }
            else
            {
                OSIncrementAtomic(&gevent_lost);
            }
        }
        break;

    case MONITORING_KEXT_PRE_CALLBACK:
    case MONITORING_KEXT_POST_CALLBACK:
        {
            char *entry_offset = NULL;
            uint32_t entry_size = (uint32_t) (sizeof(struct nke_log_entry) +
                                              sizeof(struct kernel_module_monitoring));

            struct nke_log_entry *entry = (struct nke_log_entry *) OSMalloc(entry_size, gmalloc_tag);

            if (entry)
            {
                memset(entry, 0, entry_size);

                entry->entry_size = entry_size;

                entry_offset = (char *) entry + sizeof(struct nke_log_entry);
                memcpy(entry_offset, message, sizeof(struct kernel_module_monitoring));

                insert_message(entry);
            }
            else
            {
                OSIncrementAtomic(&gevent_lost);
            }
        }
        break;

    case NETWORK_TCP_IPV4_DETACH:
        {
            char *entry_offset = NULL;
            struct network_tcp_monitoring *tcp_monitoring = (struct network_tcp_monitoring *) message;
            uint32_t entry_size = (uint32_t) (sizeof(struct nke_log_entry) +
                                              sizeof(struct network_tcp_monitoring) +
                                              tcp_monitoring->first_in_packet_size + tcp_monitoring->first_out_packet_size);

            struct nke_log_entry *entry = (struct nke_log_entry *) OSMalloc(entry_size, gmalloc_tag);

            if (entry)
            {
                memset(entry, 0, entry_size);

                entry->entry_size = entry_size;

                entry_offset = (char *) entry + sizeof(struct nke_log_entry);
                memcpy(entry_offset, message, sizeof(struct network_tcp_monitoring) +
                       tcp_monitoring->first_in_packet_size + tcp_monitoring->first_out_packet_size);

                insert_message(entry);
            }
            else
            {
                OSIncrementAtomic(&gevent_lost);
            }
        }
        break;

    case NETWORK_UDP_DNS_QUERY:
        {
            char *entry_offset = NULL;
            struct network_dns_monitoring *dns_monitoring = (struct network_dns_monitoring *) message;
            uint32_t entry_size = (uint32_t) (sizeof(struct nke_log_entry) +
                                              sizeof(struct network_dns_monitoring) + dns_monitoring->dns_question_length);

            struct nke_log_entry *entry = (struct nke_log_entry *) OSMalloc(entry_size, gmalloc_tag);

            if (entry)
            {
                memset(entry, 0, entry_size);

                entry->entry_size = entry_size;

                entry_offset = (char *) entry + sizeof(struct nke_log_entry);
                memcpy(entry_offset, message, sizeof(struct network_dns_monitoring) + dns_monitoring->dns_question_length);

                insert_message(entry);
            }
            else
            {
                OSIncrementAtomic(&gevent_lost);
            }
        }
        break;

    default:

        break;
    }
}

static
void
nke_kernel_thread(
    void *parameter,
    wait_result_t wait_result
    )
{
#pragma unused(parameter)
#pragma unused(wait_result)

    int msleep_chan = 0;
    struct timespec second = {0};
    struct nke_log_entry *entry = NULL;

    second.tv_sec = 0; second.tv_nsec = 400;

    do
    {
        if (gctl_registered && gctl_connection_ref && gctl_connection_unit)
        {
            lck_mtx_lock(gnke_event_log_lock);

            entry = TAILQ_FIRST(&gnke_event_list);

            if (entry) TAILQ_REMOVE(&gnke_event_list, entry, next);

            lck_mtx_unlock(gnke_event_log_lock);

            //
            // Send the event to user application
            //

            if (entry)
            {
                struct message_header *message = (struct message_header *) ((char *) entry + sizeof(struct nke_log_entry));

                if (send_message_internal(message))
                {
                    //
                    // ctl_enqueuedata failed!
                    //

                    lck_mtx_lock(gnke_event_log_lock);

                    entry->retry += 1;

                    TAILQ_INSERT_HEAD(&gnke_event_list, entry, next);

                    lck_mtx_unlock(gnke_event_log_lock);

                    //
                    // Sleep for a while
                    //

                    msleep(&msleep_chan, NULL, PUSER, "kernel_thread", &second);
                }
                else
                {
                    //
                    // Finally
                    //

                #if FRAMEWORK_TROUBLESHOOTING
                    if (entry->retry)
                        printf("[%s.kext] : message type=%s, retried=%d.\n", DRIVER_NAME, get_message_type(message->type), entry->retry);
                    else
                        printf("[%s.kext] : message type=%s.\n", DRIVER_NAME, get_message_type(message->type));
                #endif

                    OSFree(entry, entry->entry_size, gmalloc_tag);

                    OSDecrementAtomic(&genqueued_event);
                }
            }
            else
            {
                msleep(&msleep_chan, NULL, PUSER, "kernel_thread", &second);
            }
        }
        else
        {
            msleep(&msleep_chan, NULL, PUSER, "kernel_thread", &second);
        }
    } while (FALSE == gnke_disconnecting);
}

//
// This is not a const structure since the ctl_id field will be set when the ctl_register call succeeds
//

static struct kern_ctl_reg gctl_reg =
{
    NKE_BUNDLE_ID,       // A Bundle ID string of up to MAX_KCTL_NAME bytes
    0,                   // The control ID may be dynamically assigned
    0,                   // This field is ignored for a dynamically assigned control ID
    CTL_FLAG_PRIVILEGED, // CTL_FLAG_PRIVILEGED and/or CTL_FLAG_REG_ID_UNIT
    0,                   // If set to zero, the default send size will be used
    0,                   // If set to zero, the default receive size will be used
    ctl_connect,         // Specify the function to be called whenever a client connects to the kernel control
    ctl_disconnect,      // Specify the function to be called whenever a client disconnects from the kernel control
    NULL,                // Handles data sent from the client to kernel control
    ctl_setopt,          // Called when the user process makes the setsockopt call
    ctl_getopt           // Called when the user process makes the getsockopt call
};

extern
kern_return_t
nke_initialization(
    boolean_t flag
    )
{
    errno_t status = 0;
    struct timespec second = {0};
    kern_return_t kern_return = KERN_SUCCESS;

    second.tv_sec = 0; second.tv_nsec = 200;

    if (flag)
    {
        //
        // Initialize the queues which we are going to use
        //

        TAILQ_INIT(&gnke_event_list);

        //
        // The value returned by IOCreateThread (deprecated function) is not 100% reliable:
        // https://developer.apple.com/documentation/kernel/1575312-iocreatethread
        //

        kern_return = kernel_thread_start(nke_kernel_thread, NULL, &gnew_kernel_thread);

        if (KERN_SUCCESS == kern_return)
        {
            //
            // Register our control structure so that we can be found by a user mode process
            //

            status = ctl_register(&gctl_reg, &gctl_ref);

            if (!status)
            {
                OSCompareAndSwap(0, 1, &gctl_registered);
            }
            else
            {
                gnke_disconnecting = TRUE;

                if (THREAD_NULL != gnew_kernel_thread)
                {
                    thread_deallocate(gnew_kernel_thread);

                    gnew_kernel_thread = THREAD_NULL;
                }

            #if FRAMEWORK_TROUBLESHOOTING
                printf("[%s.kext] : Error! ctl_register(true) failed, status=%d.\n", DRIVER_NAME, status);
            #endif

                kern_return = KERN_FAILURE;
            }
        }
    }
    else
    {
        gnke_disconnecting = TRUE;

        if (gctl_registered)
        {
            struct nke_log_entry *entry = NULL;

            lck_mtx_lock(gnke_event_log_lock);

            while (!TAILQ_EMPTY(&gnke_event_list))
            {
                entry = TAILQ_FIRST(&gnke_event_list);

                if (entry)
                {
                    TAILQ_REMOVE(&gnke_event_list, entry, next);

                    OSFree(entry, entry->entry_size, gmalloc_tag);

                    OSDecrementAtomic(&genqueued_event);
                }
            }

            lck_mtx_unlock(gnke_event_log_lock);

            if (THREAD_NULL != gnew_kernel_thread)
            {
                thread_deallocate(gnew_kernel_thread);

                gnew_kernel_thread = THREAD_NULL;
            }

            //
            // For EBUSY error
            //

            int retry = 3;

            do
            {
                msleep(&retry, NULL, PUSER, "ctl_deregister", &second);

                status = ctl_deregister(gctl_ref);

                if (!status)
                {
                    OSCompareAndSwap(1, 0, &gctl_registered);

                    kern_return = KERN_SUCCESS; break;
                }
                else
                {
                    kern_return = KERN_FAILURE;

                #if FRAMEWORK_TROUBLESHOOTING
                    printf("[%s.kext] : Error! ctl_register(false) failed, status=%d, retry=%d (events=%d, lost events=%d).\n",
                           DRIVER_NAME, status, retry, genqueued_event, gevent_lost);
                #endif

                    retry--;
                }
            } while (0 < retry);
        }
        else
        {
            kern_return = KERN_SUCCESS;
        }
    }

    return kern_return;
}