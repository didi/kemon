/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    nke.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __NKE_DRIVER_H__
#define __NKE_DRIVER_H__


//
// kern_ctl_reg.ctl_name
//

#define NKE_BUNDLE_ID "com.assuresec.kemon.nke"

#define ENQUEUED_EVENT_LIMIT 0x10086

//
// NKE log entry
//

struct nke_log_entry {
    TAILQ_ENTRY(nke_log_entry) list;
    uint32_t size;
    uint32_t retry;
};

//
// Event queue
//

TAILQ_HEAD(nke_entry, nke_log_entry);

static struct nke_entry nke_list;

//
// Declaration
//

extern lck_grp_t *glock_group;

extern OSMallocTag gmalloc_tag;

extern
void
send_message(
    struct message_header *message
    );

extern
kern_return_t
nke_initialization(
    boolean_t flag
    );

#endif