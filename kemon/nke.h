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

static thread_t gnew_kernel_thread = THREAD_NULL;

//
// Declaration
//

extern OSMallocTag gmalloc_tag;

extern lck_mtx_t *gnke_event_log_lock;

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