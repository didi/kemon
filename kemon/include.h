/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    include.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __INCLUDE_DRIVER_H__
#define __INCLUDE_DRIVER_H__


#include <net/ethernet.h>

//
// macOS version
//

enum os_version {
    OS_X_LION = 0xB,
    OS_X_MOUNTAIN_LION,
    OS_X_MAVERICKS,
    OS_X_YOSEMITE,
    OS_X_EL_CAPITAN,
    MACOS_SIERRA,
    MACOS_HIGH_SIERRA,
    MACOS_MOJAVE,
    MACOS_CATALINA
};

//
// Message type
//

enum message_type {
    FILEOP_OPEN = 0x00,
    FILEOP_CREATE,
    FILEOP_CLOSE,
    FILEOP_RENAME,
    FILEOP_EXCHANGE,
    FILEOP_LINK,
    FILEOP_EXEC,
    FILEOP_DELETE,
    FILEOP_WILL_RENAME,
    FILEOP_WRITE_OR_APPEND,
    DEVICE_OPEN = 0x20,
    NETWORK_TCP_IPV4_DETACH = 0x40,
    NETWORK_UDP_IPV4_DETACH,
    NETWORK_UDP_DNS_QUERY,
    MONITORING_DYNAMIC_LIBRARY = 0x60,
    MONITORING_KEXT_PRE_CALLBACK,
    MONITORING_KEXT_POST_CALLBACK
};

//
// Message header
//

struct message_header {
    int type;
    int pid;
    int ppid;
    uid_t uid;
    gid_t gid;
    struct timeval event_time;
    char proc_name_pid[MAXPATHLEN];
    char proc_name_ppid[MAXPATHLEN];
};

//
// File operation monitoring
//

struct file_operation_monitoring {
    struct message_header header;
    union {
        struct {
            char path[MAXPATHLEN];
        } fileop_open;
        struct {
            char path[MAXPATHLEN];
        } fileop_create;
        struct {
            char path[MAXPATHLEN];
            boolean_t modified;
        } fileop_close;
        struct {
            char from[MAXPATHLEN];
            char to[MAXPATHLEN];
        } fileop_rename;
        struct {
            char file1[MAXPATHLEN];
            char file2[MAXPATHLEN];
        } fileop_exchange;
        struct {
            char original[MAXPATHLEN];
            char new_link[MAXPATHLEN];
        } fileop_link;
        struct {
            char path[MAXPATHLEN];
            unsigned long command_line_length;
        //  char command_line[command_line_length];
        } fileop_exec;
        struct {
            char path[MAXPATHLEN];
        } fileop_delete;
        struct {
            char from[MAXPATHLEN];
            char to[MAXPATHLEN];
        } fileop_will_rename;
        struct {
            char path[MAXPATHLEN];
        } fileop_write_or_append;
        struct {
            char path[MAXPATHLEN];
        } device_open;
    } body;
};

//
// Network traffic monitoring
//

struct network_tcp_monitoring {
    struct message_header header;
    struct timeval start_time;
    struct timeval stop_time;
    u_char source_address_string[256];
    u_char destination_address_string[256];
    u_char source_address_ether[ETHER_ADDR_LEN];
    u_char destination_address_ether[ETHER_ADDR_LEN];
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t in_bytes;
    uint32_t in_packets;
    uint32_t out_bytes;
    uint32_t out_packets;
    uint32_t first_in_bytes;
    uint32_t first_out_bytes;
//  char first_in_packet[first_in_bytes];
//  char first_out_packet[first_out_bytes];
};

struct network_udp_monitoring {
    struct message_header header;
    struct timeval start_time;
    struct timeval stop_time;
    u_char source_address_string[256];
    u_char destination_address_string[256];
    u_char source_address_ether[ETHER_ADDR_LEN];
    u_char destination_address_ether[ETHER_ADDR_LEN];
    uint16_t source_port;
    uint16_t destination_port;
};

struct network_dns_monitoring {
    struct message_header header;
    u_char source_address_string[256];
    u_char destination_address_string[256];
    uint16_t source_port;
    uint16_t destination_port;
    unsigned long dns_question_length;
//  char dns_question[dns_question_length];
};

//
// Dynamic library monitoring
//

struct dynamic_library_monitoring {
    struct message_header header;
    char library_path[MAXPATHLEN];
};

//
// Kernel module monitoring
//

struct kernel_module_monitoring {
    struct message_header header;
    unsigned int return_value;
    unsigned long module_base;
    unsigned long module_size;
    char module_name[MAXPATHLEN];
    char module_path[MAXPATHLEN];
    char module_version[MAXPATHLEN];
};

#endif