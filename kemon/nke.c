/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    nke.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSMalloc.h>
#include <sys/kern_control.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include "include.h"
#include "trace.h"
#include "nke.h"


//
// NKE mutex lock
//

static lck_mtx_t *nke_lock;

//
// User client connection
//

static UInt32 ctl_connected;

static kern_ctl_ref ctl_connection_reference;
static u_int32_t ctl_connection_unit;

//
// ctl_register status
//

static kern_ctl_ref ctl_reference;

static thread_t nke_thread_reference = THREAD_NULL;

static boolean_t nke_disconnecting;

//
// Statistic
//

static SInt32 enqueued_event;
static SInt32 lost_event;

//
// The ctl_setopt_func is used to handle set socket option
// calls for the SYSPROTO_CONTROL option level
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
// The ctl_getopt_func is used to handle client get socket option
// requests for the SYSPROTO_CONTROL option level
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
// The ctl_connect_func is used to receive notification
// of a client connecting to the kernel control
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

    if (OSCompareAndSwap(0, 1, &ctl_connected)) {
        if (!ctl_connection_reference) {
            ctl_connection_reference = ctl_ref;
            ctl_connection_unit = sac->sc_unit;

            int pid = proc_selfpid();
            char proc_name_pid[MAXPATHLEN];
            memset(proc_name_pid, 0, MAXPATHLEN);
            proc_name(pid, proc_name_pid, MAXPATHLEN);

            int ppid = proc_selfppid();
            char proc_name_ppid[MAXPATHLEN];
            memset(proc_name_ppid, 0, MAXPATHLEN);
            proc_name(ppid, proc_name_ppid, MAXPATHLEN);

        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : connection reference=%p, unit=%x, process(pid %d)=%s, parent(ppid %d)=%s.\n",
                   DRIVER_NAME,
                   ctl_connection_reference,
                   ctl_connection_unit,
                   pid, proc_name_pid,
                   ppid, proc_name_ppid);
        #endif

            status = 0;
        }
    }

    return status;
}

//
// The ctl_disconnect_func is used to receive notification
// that a client has disconnected from the kernel control
//

static
int
ctl_disconnect(
    kern_ctl_ref ctl_ref,
    u_int32_t unit,
    void *unitinfo
    )
{
    if (!ctl_connection_reference ||
        ctl_connection_unit != unit) {
        return -1;
    } else {
        ctl_connection_reference = NULL;
        ctl_connection_unit = 0;

        OSCompareAndSwap(1, 0, &ctl_connected);
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
    char *result;

    switch (type) {
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

    case NETWORK_TCP_IPV4_DETACH:
        result = "NETWORK_TCP_IPV4_DETACH";
        break;

    case NETWORK_UDP_DNS_QUERY:
        result = "NETWORK_UDP_DNS_QUERY";
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
    char kext_buffer[0x200];
    unsigned long kext_length;

    if (!message)
        return;

    kext_length = sizeof(kext_buffer);
    memset(kext_buffer, 0, kext_length);

    switch (message->type) {
    case FILEOP_OPEN: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_OPEN, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_open.path);
        }
        break;

    case FILEOP_CREATE: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_CREATE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_create.path);
        }
        break;

    case FILEOP_CLOSE: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_CLOSE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s, modified=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_close.path,
                   fileop_message->body.fileop_close.modified ? "true" : "false");
        }
        break;

    case FILEOP_RENAME: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_RENAME, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, from=%s, to=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_rename.from,
                   fileop_message->body.fileop_rename.to);
        }
        break;

    case FILEOP_EXCHANGE: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_EXCHANGE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, file1=%s, file2=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_exchange.file1,
                   fileop_message->body.fileop_exchange.file2);
        }
        break;

    case FILEOP_LINK: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_LINK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, original=%s, new=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_link.original,
                   fileop_message->body.fileop_link.new_link);
        }
        break;

    case FILEOP_EXEC: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;
            char *command_line = (char *) (fileop_message + 1);

            printf("[%s.kext] : action=KAUTH_FILEOP_EXEC, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s, command line=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_exec.path, command_line);
        }
        break;

    case FILEOP_DELETE: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_DELETE, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_delete.path);
        }
        break;

    case FILEOP_WILL_RENAME: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_WILL_RENAME, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, from=%s, to=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_will_rename.from,
                   fileop_message->body.fileop_will_rename.to);
        }
        break;

    case FILEOP_WRITE_OR_APPEND: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_FILEOP_WRITE_OR_APPEND, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.fileop_write_or_append.path);
        }
        break;

    case DEVICE_OPEN: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            printf("[%s.kext] : action=KAUTH_DEVICE_OPEN, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s.\n",
                   DRIVER_NAME, fileop_message->header.uid,
                   fileop_message->header.pid,
                   fileop_message->header.proc_name_pid,
                   fileop_message->header.ppid,
                   fileop_message->header.proc_name_ppid,
                   fileop_message->body.device_open.path);
        }
        break;

    case NETWORK_TCP_IPV4_DETACH: {
            struct network_tcp_monitoring *tcp_monitoring =
                (struct network_tcp_monitoring *) message;
            char *first_in_offset = (char *) (tcp_monitoring + 1);
            char *first_out_offset = (char *) (tcp_monitoring + 1) +
                tcp_monitoring->first_in_bytes;

            struct timeval diff;
            timersub(&tcp_monitoring->stop_time,
                     &tcp_monitoring->start_time,
                     &diff);

            if (tcp_monitoring->in_packets) {
                printf("[%s.kext] : action=TCP_IPV4_DETACH, duration=%ld.%d seconds, %s:%d(%02x:%02x:%02x:%02x:%02x:%02x)<->%s:%d(%02x:%02x:%02x:%02x:%02x:%02x), uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, in=%d packets, %d bytes, out=%d packets, %d bytes.\n",
                       DRIVER_NAME, diff.tv_sec, diff.tv_usec,
                       tcp_monitoring->source_address_string,
                       tcp_monitoring->source_port,
                       tcp_monitoring->source_address_ether[0],
                       tcp_monitoring->source_address_ether[1],
                       tcp_monitoring->source_address_ether[2],
                       tcp_monitoring->source_address_ether[3],
                       tcp_monitoring->source_address_ether[4],
                       tcp_monitoring->source_address_ether[5],
                       tcp_monitoring->destination_address_string,
                       tcp_monitoring->destination_port,
                       tcp_monitoring->destination_address_ether[0],
                       tcp_monitoring->destination_address_ether[1],
                       tcp_monitoring->destination_address_ether[2],
                       tcp_monitoring->destination_address_ether[3],
                       tcp_monitoring->destination_address_ether[4],
                       tcp_monitoring->destination_address_ether[5],
                       tcp_monitoring->header.uid,
                       tcp_monitoring->header.pid,
                       tcp_monitoring->header.proc_name_pid,
                       tcp_monitoring->header.ppid,
                       tcp_monitoring->header.proc_name_ppid,
                       tcp_monitoring->in_packets, tcp_monitoring->in_bytes,
                       tcp_monitoring->out_packets, tcp_monitoring->out_bytes);
            } else {
                printf("[%s.kext] : action=TCP_IPV4_DETACH, duration=%ld.%d seconds, %s:%d%s%s:%d, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, in=%d packets, %d bytes, out=%d packets, %d bytes.\n",
                       DRIVER_NAME, diff.tv_sec, diff.tv_usec,
                       tcp_monitoring->source_address_string,
                       tcp_monitoring->source_port,
                       tcp_monitoring->out_packets ? "-->" : "---",
                       tcp_monitoring->destination_address_string,
                       tcp_monitoring->destination_port,
                       tcp_monitoring->header.uid,
                       tcp_monitoring->header.pid,
                       tcp_monitoring->header.proc_name_pid,
                       tcp_monitoring->header.ppid,
                       tcp_monitoring->header.proc_name_ppid,
                       tcp_monitoring->in_packets, tcp_monitoring->in_bytes,
                       tcp_monitoring->out_packets, tcp_monitoring->out_bytes);
            }

            if (tcp_monitoring->first_in_bytes) {
                printf("[%s.kext] : Dump first IN packet.\n",
                       DRIVER_NAME);

                hex_printf(first_in_offset,
                           tcp_monitoring->first_in_bytes,
                           HEX_PRINTF_B);
            }

            if (tcp_monitoring->first_out_bytes) {
                printf("[%s.kext] : Dump first OUT packet.\n",
                       DRIVER_NAME);

                hex_printf(first_out_offset,
                           tcp_monitoring->first_out_bytes,
                           HEX_PRINTF_B);
            }
        }
        break;

    case NETWORK_UDP_DNS_QUERY: {
            struct network_dns_monitoring *dns_monitoring =
                (struct network_dns_monitoring *) message;
            char *dns_question = (char *) (dns_monitoring + 1);

            printf("[%s.kext] : action=UDP_DNS_QUERY, %s:%d-->%s:%d, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, query=%s.\n",
                   DRIVER_NAME,
                   dns_monitoring->source_address_string,
                   dns_monitoring->source_port,
                   dns_monitoring->destination_address_string,
                   dns_monitoring->destination_port,
                   dns_monitoring->header.uid,
                   dns_monitoring->header.pid,
                   dns_monitoring->header.proc_name_pid,
                   dns_monitoring->header.ppid,
                   dns_monitoring->header.proc_name_ppid, dns_question);
        }
        break;

    case MONITORING_DYNAMIC_LIBRARY: {
            struct dynamic_library_monitoring *library_message =
                (struct dynamic_library_monitoring *) message;

            printf("[%s.kext] : action=MONITORING_DYNAMIC_LIBRARY, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, dynamic library path=%s.\n",
                   DRIVER_NAME, library_message->header.uid,
                   library_message->header.pid,
                   library_message->header.proc_name_pid,
                   library_message->header.ppid,
                   library_message->header.proc_name_ppid,
                   library_message->library_path);
        }
        break;

    case MONITORING_KEXT_PRE_CALLBACK: {
            struct kernel_module_monitoring *kext_message =
                (struct kernel_module_monitoring *) message;

            int length = snprintf(kext_buffer, kext_length,
                                  "[%s.kext] : action=MONITORING_KEXT_PRE_CALLBACK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, name=%s, path=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
                                  DRIVER_NAME, kext_message->header.uid,
                                  kext_message->header.pid,
                                  kext_message->header.proc_name_pid,
                                  kext_message->header.ppid,
                                  kext_message->header.proc_name_ppid,
                                  kext_message->module_name,
                                  kext_message->module_path,
                                  kext_message->module_version,
                                  kext_message->module_base,
                                  kext_message->module_size);
            if (length < SNPRINTF_LENGTH_LIMIT) {
                printf("%s", kext_buffer);
            } else {
                //
                // For macOS 10.14 Mojave
                //

                memset(kext_buffer, 0, kext_length);

                snprintf(kext_buffer, kext_length,
                         "[%s.kext] : action=MONITORING_KEXT_PRE_CALLBACK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, path=%s, module base=0x%lx.\n",
                         DRIVER_NAME, kext_message->header.uid,
                         kext_message->header.pid,
                         kext_message->header.proc_name_pid,
                         kext_message->header.ppid,
                         kext_message->header.proc_name_ppid,
                         kext_message->module_path,
                         kext_message->module_base);
                printf("%s", kext_buffer);
            }
        }
        break;

    case MONITORING_KEXT_POST_CALLBACK: {
            struct kernel_module_monitoring *kext_message =
                (struct kernel_module_monitoring *) message;

            int length = snprintf(kext_buffer, kext_length,
                                  "[%s.kext] : action=MONITORING_KEXT_POST_CALLBACK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, status=%d, name=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
                                  DRIVER_NAME, kext_message->header.uid,
                                  kext_message->header.pid,
                                  kext_message->header.proc_name_pid,
                                  kext_message->header.ppid,
                                  kext_message->header.proc_name_ppid,
                                  kext_message->return_value,
                                  kext_message->module_name,
                                  kext_message->module_version,
                                  kext_message->module_base,
                                  kext_message->module_size);
            if (length < SNPRINTF_LENGTH_LIMIT) {
                printf("%s", kext_buffer);
            } else {
                //
                // For macOS 10.14 Mojave
                //

                memset(kext_buffer, 0, kext_length);

                snprintf(kext_buffer, kext_length,
                         "[%s.kext] : action=MONITORING_KEXT_POST_CALLBACK, uid=%u, process(pid %d)=%s, parent(ppid %d)=%s, status=%d, module base=0x%lx, module size=0x%lx.\n",
                         DRIVER_NAME, kext_message->header.uid,
                         kext_message->header.pid,
                         kext_message->header.proc_name_pid,
                         kext_message->header.ppid,
                         kext_message->header.proc_name_ppid,
                         kext_message->return_value,
                         kext_message->module_base,
                         kext_message->module_size);
                printf("%s", kext_buffer);
            }
        }
        break;

    default: {
        }
        break;
    }
}
#endif // FRAMEWORK_TROUBLESHOOTING

static
errno_t
send_message_internal(
    struct message_header *message
    )
{
    errno_t result;

    if (!ctl_connection_reference ||
        !ctl_connection_unit ||
        nke_disconnecting)
        return EPERM;

    switch (message->type) {
    case FILEOP_OPEN:
    case FILEOP_CREATE:
    case FILEOP_CLOSE:
    case FILEOP_RENAME:
    case FILEOP_EXCHANGE:
    case FILEOP_LINK:
    case FILEOP_DELETE:
    case FILEOP_WILL_RENAME:
    case FILEOP_WRITE_OR_APPEND:
    case DEVICE_OPEN: {
            result = ctl_enqueuedata(ctl_connection_reference,
                                     ctl_connection_unit,
                                     message,
                                     sizeof(struct file_operation_monitoring),
                                     CTL_DATA_EOR);
        }
        break;

    case FILEOP_EXEC: {
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;

            result = ctl_enqueuedata(ctl_connection_reference,
                                     ctl_connection_unit,
                                     message,
                                     sizeof(struct file_operation_monitoring) +
                                     fileop_message->body.fileop_exec.command_line_length,
                                     CTL_DATA_EOR);
        }
        break;

    case MONITORING_DYNAMIC_LIBRARY: {
            result = ctl_enqueuedata(ctl_connection_reference,
                                     ctl_connection_unit,
                                     message,
                                     sizeof(struct dynamic_library_monitoring),
                                     CTL_DATA_EOR);
        }
        break;

    case MONITORING_KEXT_PRE_CALLBACK:
    case MONITORING_KEXT_POST_CALLBACK: {
            result = ctl_enqueuedata(ctl_connection_reference,
                                     ctl_connection_unit,
                                     message,
                                     sizeof(struct kernel_module_monitoring),
                                     CTL_DATA_EOR);
        }
        break;

    case NETWORK_TCP_IPV4_DETACH: {
            struct network_tcp_monitoring *tcp_monitoring =
                (struct network_tcp_monitoring *) message;

            result = ctl_enqueuedata(ctl_connection_reference,
                                     ctl_connection_unit,
                                     message,
                                     sizeof(struct network_tcp_monitoring) +
                                     tcp_monitoring->first_in_bytes +
                                     tcp_monitoring->first_out_bytes,
                                     CTL_DATA_EOR);
        }
        break;

    case NETWORK_UDP_DNS_QUERY: {
            struct network_dns_monitoring *dns_monitoring =
                (struct network_dns_monitoring *) message;

            result = ctl_enqueuedata(ctl_connection_reference,
                                     ctl_connection_unit,
                                     message,
                                     sizeof(struct network_dns_monitoring) +
                                     dns_monitoring->dns_question_length,
                                     CTL_DATA_EOR);
        }
        break;

    default:
        //
        // Should I delete this message here?
        //

        result = EINVAL;
        break;
    }

    return result;
}

static
void
insert_message(
    struct nke_log_entry *entry
    )
{
    if (enqueued_event < ENQUEUED_EVENT_LIMIT) {
        lck_mtx_lock(nke_lock);

        TAILQ_INSERT_TAIL(&nke_list, entry, list);

        lck_mtx_unlock(nke_lock);

        OSIncrementAtomic(&enqueued_event);
    } else {
        OSFree(entry, entry->size, gmalloc_tag);

        OSIncrementAtomic(&lost_event);
    }
}

extern
void
send_message(
    struct message_header *message
    )
{
    if (!message) {
        return;
#if FRAMEWORK_TROUBLESHOOTING
    } else {
        dump_message(message);
#endif
    }

    if (!ctl_connection_reference ||
        !ctl_connection_unit ||
        nke_disconnecting)
        return;

    switch (message->type) {
    //
    // We don't care about the FILEOP_OPEN, FILEOP_CLOSE,
    // DEVICE_OPEN and FILEOP_WILL_RENAME in this version
    //

//  case FILEOP_OPEN:
    case FILEOP_CREATE:
//  case FILEOP_CLOSE:
    case FILEOP_RENAME:
    case FILEOP_EXCHANGE:
    case FILEOP_LINK:
    case FILEOP_DELETE:
//  case FILEOP_WILL_RENAME:
    case FILEOP_WRITE_OR_APPEND: {
//  case DEVICE_OPEN:
            char *offset;
            uint32_t size = (uint32_t) (sizeof(struct nke_log_entry) +
                sizeof(struct file_operation_monitoring));

            struct nke_log_entry *entry = OSMalloc(size, gmalloc_tag);
            if (entry) {
                memset(entry, 0, size);

                entry->size = size;

                offset = (char *) (entry + 1);
                memcpy(offset, message,
                       sizeof(struct file_operation_monitoring));

                insert_message(entry);
            } else {
                OSIncrementAtomic(&lost_event);
            }
        }
        break;

    case FILEOP_EXEC: {
            char *offset;
            struct file_operation_monitoring *fileop_message =
                (struct file_operation_monitoring *) message;
            uint32_t size = (uint32_t) (sizeof(struct nke_log_entry) +
                sizeof(struct file_operation_monitoring) +
                fileop_message->body.fileop_exec.command_line_length);

            struct nke_log_entry *entry = OSMalloc(size, gmalloc_tag);
            if (entry) {
                memset(entry, 0, size);

                entry->size = size;

                offset = (char *) (entry + 1);
                memcpy(offset, message,
                       sizeof(struct file_operation_monitoring) +
                       fileop_message->body.fileop_exec.command_line_length);

                insert_message(entry);
            } else {
                OSIncrementAtomic(&lost_event);
            }
        }
        break;

    case MONITORING_DYNAMIC_LIBRARY: {
            char *offset;
            uint32_t size = (uint32_t) (sizeof(struct nke_log_entry) +
                sizeof(struct dynamic_library_monitoring));

            struct nke_log_entry *entry = OSMalloc(size, gmalloc_tag);
            if (entry) {
                memset(entry, 0, size);

                entry->size = size;

                offset = (char *) (entry + 1);
                memcpy(offset, message,
                       sizeof(struct dynamic_library_monitoring));

                insert_message(entry);
            } else {
                OSIncrementAtomic(&lost_event);
            }
        }
        break;

    case MONITORING_KEXT_PRE_CALLBACK:
    case MONITORING_KEXT_POST_CALLBACK: {
            char *offset;
            uint32_t size = (uint32_t) (sizeof(struct nke_log_entry) +
                sizeof(struct kernel_module_monitoring));

            struct nke_log_entry *entry = OSMalloc(size, gmalloc_tag);
            if (entry) {
                memset(entry, 0, size);

                entry->size = size;

                offset = (char *) (entry + 1);
                memcpy(offset, message,
                       sizeof(struct kernel_module_monitoring));

                insert_message(entry);
            } else {
                OSIncrementAtomic(&lost_event);
            }
        }
        break;

    case NETWORK_TCP_IPV4_DETACH: {
            char *offset;
            struct network_tcp_monitoring *tcp_monitoring =
                (struct network_tcp_monitoring *) message;
            uint32_t size = (uint32_t) (sizeof(struct nke_log_entry) +
                sizeof(struct network_tcp_monitoring) +
                tcp_monitoring->first_in_bytes +
                tcp_monitoring->first_out_bytes);

            struct nke_log_entry *entry = OSMalloc(size, gmalloc_tag);
            if (entry) {
                memset(entry, 0, size);

                entry->size = size;

                offset = (char *) (entry + 1);
                memcpy(offset, message,
                       sizeof(struct network_tcp_monitoring) +
                       tcp_monitoring->first_in_bytes +
                       tcp_monitoring->first_out_bytes);

                insert_message(entry);
            } else {
                OSIncrementAtomic(&lost_event);
            }
        }
        break;

    case NETWORK_UDP_DNS_QUERY: {
            char *offset;
            struct network_dns_monitoring *dns_monitoring =
                (struct network_dns_monitoring *) message;
            uint32_t size = (uint32_t) (sizeof(struct nke_log_entry) +
                sizeof(struct network_dns_monitoring) +
                dns_monitoring->dns_question_length);

            struct nke_log_entry *entry = OSMalloc(size, gmalloc_tag);
            if (entry) {
                memset(entry, 0, size);

                entry->size = size;

                offset = (char *) (entry + 1);
                memcpy(offset, message,
                       sizeof(struct network_dns_monitoring) +
                       dns_monitoring->dns_question_length);

                insert_message(entry);
            } else {
                OSIncrementAtomic(&lost_event);
            }
        }
        break;

    default:
        break;
    }
}

static
void
nke_thread(
    void *parameter,
    wait_result_t wait_result
    )
{
#pragma unused(parameter)
#pragma unused(wait_result)

    int timer_chan = 0;
    struct nke_log_entry *entry;
    struct timespec timer = {0, 0};

    do {
        if (ctl_connection_reference &&
            ctl_connection_unit) {
            lck_mtx_lock(nke_lock);

            entry = TAILQ_FIRST(&nke_list);
            if (entry)
                TAILQ_REMOVE(&nke_list, entry, list);

            lck_mtx_unlock(nke_lock);

            //
            // Send event to user space
            //

            if (entry) {
                struct message_header *message =
                    (struct message_header *) (entry + 1);

                if (send_message_internal(message)) {
                    //
                    // ctl_enqueuedata() failed!
                    //

                    lck_mtx_lock(nke_lock);

                    entry->retry += 1;

                    TAILQ_INSERT_HEAD(&nke_list, entry, list);

                    lck_mtx_unlock(nke_lock);
                } else {
                    //
                    // Finally
                    //

                #if FRAMEWORK_TROUBLESHOOTING
                    if (entry->retry)
                        printf("[%s.kext] : message type=%s, retried=%d.\n",
                               DRIVER_NAME,
                               get_message_type(message->type),
                               entry->retry);
                    else
                        printf("[%s.kext] : message type=%s.\n",
                               DRIVER_NAME,
                               get_message_type(message->type));
                #endif

                    OSFree(entry, entry->size, gmalloc_tag);

                    OSDecrementAtomic(&enqueued_event);
                }
            }

            //
            // Sleep for a while
            //

            timer.tv_nsec = 1000;

            msleep(&timer_chan, NULL, PUSER,
                   "send_message_internal", &timer);
        } else {
            timer.tv_nsec = 80000000;

            msleep(&timer_chan, NULL, PUSER,
                   "kernel_thread", &timer);
        }
    } while (!nke_disconnecting);
}

//
// This is not a const structure since the ctl_id field will be set when the ctl_register call succeeds
//

static struct kern_ctl_reg ctl_block = {
    NKE_BUNDLE_ID,       // a bundle ID string of up to MAX_KCTL_NAME bytes
    0,                   // the control ID may be dynamically assigned
    0,                   // this field is ignored for a dynamically assigned control ID
    CTL_FLAG_PRIVILEGED, // CTL_FLAG_PRIVILEGED and/or CTL_FLAG_REG_ID_UNIT
    0,                   // if set to zero, the default send size will be used
    0,                   // if set to zero, the default receive size will be used
    ctl_connect,         // specify the function to be called whenever a client connects to the kernel control
    ctl_disconnect,      // specify the function to be called whenever a client disconnects from the kernel control
    NULL,                // handles data sent from the client to kernel control
    ctl_setopt,          // called when the user process makes the setsockopt call
    ctl_getopt           // called when the user process makes the getsockopt call
};

extern
kern_return_t
nke_initialization(
    boolean_t flag
    )
{
    errno_t result;
    kern_return_t status;

    if (flag) {
        if (!glock_group)
            return KERN_FAILURE;

        nke_lock = lck_mtx_alloc_init(glock_group,
                                      LCK_ATTR_NULL);
        if (!nke_lock)
            return KERN_FAILURE;

        //
        // Initialize the queues which we are going to use
        //

        TAILQ_INIT(&nke_list);

        //
        // The value returned by IOCreateThread (deprecated function) is not 100% reliable:
        // https://developer.apple.com/documentation/kernel/1575312-iocreatethread
        //

        status = kernel_thread_start(nke_thread, NULL,
                                     &nke_thread_reference);
        if (KERN_SUCCESS == status) {
            //
            // Register our control structure so that we can be found by a user process
            //

            result = ctl_register(&ctl_block, &ctl_reference);
            if (result) {
                OSCompareAndSwap(0, 1, &nke_disconnecting);

                if (THREAD_NULL != nke_thread_reference) {
                    thread_deallocate(nke_thread_reference);

                    nke_thread_reference = THREAD_NULL;
                }

            #if FRAMEWORK_TROUBLESHOOTING
                printf("[%s.kext] : Error! ctl_register() failed, status=%d.\n",
                       DRIVER_NAME, status);
            #endif

                status = KERN_FAILURE;
            }
        }
    } else {
        OSCompareAndSwap(0, 1, &nke_disconnecting);

        if (ctl_reference) {
            struct nke_log_entry *entry;

            lck_mtx_lock(nke_lock);

            while (!TAILQ_EMPTY(&nke_list)) {
                entry = TAILQ_FIRST(&nke_list);
                if (entry) {
                    TAILQ_REMOVE(&nke_list, entry, list);

                    OSFree(entry, entry->size, gmalloc_tag);

                    OSDecrementAtomic(&enqueued_event);
                }
            }

            lck_mtx_unlock(nke_lock);

            if (THREAD_NULL != nke_thread_reference) {
                thread_deallocate(nke_thread_reference);

                nke_thread_reference = THREAD_NULL;
            }

            //
            // For EBUSY case
            //

            int retry = 3;
            struct timespec timer;

            timer.tv_sec = 0;
            timer.tv_nsec = 100000;

            do {
                msleep(&retry, NULL, PUSER,
                       "ctl_deregister", &timer);

                result = ctl_deregister(ctl_reference);
                if (!result) {
                    status = KERN_SUCCESS;
                    break;
                } else {
                    status = KERN_FAILURE;

                #if FRAMEWORK_TROUBLESHOOTING
                    printf("[%s.kext] : Error! ctl_deregister() failed, status=%d, retry=%d (events=%d, lost events=%d).\n",
                           DRIVER_NAME, status,
                           retry, enqueued_event,
                           lost_event);
                #endif

                    retry--;
                }
            } while (0 < retry);
        } else {
            status = KERN_SUCCESS;
        }

        if (nke_lock && glock_group) {
            lck_mtx_free(nke_lock, glock_group);

            nke_lock = NULL;
        }
    }

    return status;
}