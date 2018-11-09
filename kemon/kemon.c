/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    kemon.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wsign-conversion"

#include <kern/assert.h>
#include <mach/mach_types.h>
#include <libkern/version.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSMalloc.h>
#include <sys/sysctl.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include "distorm/include/distorm.h"
#include "include.h"
#include "network.h"
#include "policy.h"
#include "inline.h"
#include "nke.h"
#include "trace.h"
#include "kemon.h"

#pragma clang diagnostic pop


#pragma mark ***** Vnode Utilities

//
// Creates a human readable description of a vnode action bitmap.
// "action" is the bitmap.
// "is_dir" is true if the action relates to a directory, and false otherwise.
// "action_string" is a place to store the allocated string pointer, the caller is responsible for freeing this memory using OSFree.
// "action_string_length" is a place to store the size of the resulting allocation.
//

static
int
construct_vnode_action_string(
    kauth_action_t action,
    boolean_t is_dir,
    char **action_string,
    size_t *action_string_length
    )
{
    char *string = NULL;
    unsigned int index = 0;
    int pass = 0, status = 0;
    size_t string_length = 0, total_length = 0;

    //
    // This is a two pass algorithm.
    // In the first pass, string is NULL and we just calculate string_length,
    // at the end of the first pass we actually allocate the string.
    // In the second pass, string is not NULL and we actually initialize the string in that buffer.
    //

    for (pass = calculate_length; pass <= allocate_string; pass++)
    {
        index = string_length = 0;
        kauth_action_t actions_left = action;

        //
        // Process action bits that are described in vnode_action_table
        //

        while (actions_left && (index < vnode_action_count))
        {
            if (actions_left & vnode_action_table[index].mask)
            {
                const char *this_string = NULL;

                if (is_dir && vnode_action_table[index].name_directory)
                    this_string = vnode_action_table[index].name_directory;
                else
                    this_string = vnode_action_table[index].name_file;

                size_t this_string_length = strlen(this_string);

                if (allocate_string == pass && string)
                {
                    memcpy(&string[string_length], this_string, this_string_length);
                }

                //
                // Increment the length of the acion string by the action name
                //

                string_length += this_string_length;

                //
                // Now clear the bit in actions_left, indicating that we've processed this one
                //

                actions_left &= ~vnode_action_table[index].mask;

                //
                // If there's any actions left, account for the intervening '|'
                //

                if (actions_left)
                {
                    if (string) string[string_length] = '|';

                    string_length += 1;
                }
            }

            index += 1;
        }

        //
        // Now include any remaining actions as a hex number
        //

        if (actions_left)
        {
            if (string)
            {
                snprintf(&string[string_length], total_length - string_length, "0x%08x", actions_left);
            }

            //
            // strlen("0x") + 8 chars of hex
            //

            string_length += 10;
        }

        //
        // If we're at the end of the first pass, allocate string based on the size we just calculated
        //

        if (calculate_length == pass)
        {
            if (max_string_length <= string_length)
            {
                status = ENOBUFS;
            }
            else
            {
                total_length = string_length + 1;

                string = (char *) OSMalloc((uint32_t) total_length, gmalloc_tag);

                if (!string) status = ENOMEM;
                else memset(string, 0, total_length);
            }
        }
        else
        {
            string[string_length] = 0;
        }

        if (status) break;
    }

    if (!status)
    {
        *action_string = string;
        *action_string_length = total_length;
    }
    else
    {
        //
        // Cleanup
        //

        *action_string = NULL;
        *action_string_length = 0;
    }

    return status;
}

//
// Creates a full path for a given vnode.
// "node" may be NULL, in which case the returned path is NULL.
// "path" is a place to store the allocated path buffer, the caller is responsible for freeing this memory using OSFree.
//

extern
int
construct_path_from_vnode(
    vnode_t vnode,
    char **path
    )
{
    int status = 0;

    if (vnode)
    {
        *path = (char *) OSMalloc(MAXPATHLEN, gmalloc_tag);

        if (!*path)
        {
            status = ENOMEM;
        }
        else
        {
            int path_length = MAXPATHLEN;

            status = vn_getpath(vnode, *path, &path_length);
        }
    }
    else
    {
        *path = NULL;
    }

    return status;
}

#pragma mark ***** Listener Resources

//
// A Kauth listener that's called to authorize an action in the generic scope (KAUTH_SCOPE_GENERIC).
//

static
int
listener_scope_generic(
    kauth_cred_t credential,
    void *data,
    kauth_action_t action,
    uintptr_t arg0,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3
    )
{
#pragma unused(data)

    OSIncrementAtomic(&gactivation_count);

    int pid = proc_selfpid();
    char proc_name_pid[MAXPATHLEN] = {0};
    memset(proc_name_pid, 0, MAXPATHLEN);
    proc_name(pid, proc_name_pid, MAXPATHLEN);

    int ppid = proc_selfppid();
    char proc_name_ppid[MAXPATHLEN] = {0};
    memset(proc_name_ppid, 0, MAXPATHLEN);
    proc_name(ppid, proc_name_ppid, MAXPATHLEN);

    //
    // Tell the user about this request
    //

    switch (action)
    {
    //
    // The kernel does not currently use this request for all superuser tests
    //

    case KAUTH_GENERIC_ISSUSER:
    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : action=KAUTH_GENERIC_ISSUSER, uid=%ld, process(pid %d)=%s, parent(ppid %d)=%s, arg0=0x%lx, arg1=0x%lx, arg2=0x%lx, arg3=0x%lx.\n",
               DRIVER_NAME, (long) kauth_cred_getuid(credential), pid, proc_name_pid, ppid, proc_name_ppid,
               (long) arg0, (long) arg1, (long) arg2, (long) arg3);
    #endif
        break;

    default:
    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : Unknown action! action=%d.\n", DRIVER_NAME, action);
    #endif
        break;
    }

    OSDecrementAtomic(&gactivation_count);

    return KAUTH_RESULT_DEFER;
}

//
// A Kauth listener that's called to authorize an action in the process scope (KAUTH_SCOPE_PROCESS).
//

static
int
listener_scope_process(
    kauth_cred_t credential,
    void *data,
    kauth_action_t action,
    uintptr_t arg0,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3
    )
{
#pragma unused(data)
#pragma unused(arg2)
#pragma unused(arg3)

    OSIncrementAtomic(&gactivation_count);

    int pid = proc_selfpid();
    char proc_name_pid[MAXPATHLEN] = {0};
    memset(proc_name_pid, 0, MAXPATHLEN);
    proc_name(pid, proc_name_pid, MAXPATHLEN);

    int ppid = proc_selfppid();
    char proc_name_ppid[MAXPATHLEN] = {0};
    memset(proc_name_ppid, 0, MAXPATHLEN);
    proc_name(ppid, proc_name_ppid, MAXPATHLEN);

    int result = KAUTH_RESULT_DEFER;

    //
    // Tell the user about this request
    //

    switch (action)
    {
    //
    // Denying the debugger
    //

    case KAUTH_PROCESS_CANTRACE:
        {
            int debuggee = proc_pid((proc_t) arg0);
            char proc_name_debuggee[MAXPATHLEN] = {0};
            memset(proc_name_debuggee, 0, MAXPATHLEN);
            proc_name(debuggee, proc_name_debuggee, MAXPATHLEN);

        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : action=KAUTH_PROCESS_CANTRACE, uid=%ld, debugger(pid %d)=%s, parent(ppid %d)=%s, debuggee(pid %d)=%s.\n",
                   DRIVER_NAME, (long) kauth_cred_getuid(credential), pid, proc_name_pid, ppid, proc_name_ppid, debuggee, proc_name_debuggee);
        #endif

            result = KAUTH_RESULT_DENY;

            *((int *) arg1) = EPERM;
        }
        break;

    //
    // KAUTH_PROCESS_CANSIGNAL is currently not implemented by any version of Mac OS X
    //

    case KAUTH_PROCESS_CANSIGNAL:
    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : action=KAUTH_PROCESS_CANSIGNAL, uid=%ld, process(pid %d)=%s, parent(ppid %d)=%s, target=%d, signal=%ld.\n",
               DRIVER_NAME, (long) kauth_cred_getuid(credential), pid, proc_name_pid, ppid, proc_name_ppid, proc_pid((proc_t) arg0), (long) arg1);
    #endif
        break;

    default:
    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : Unknown action! action=%d.\n", DRIVER_NAME, action);
    #endif
        break;
    }

    OSDecrementAtomic(&gactivation_count);

    return result;
}

//
// A Kauth listener that's called to authorize an action in the vnode scope (KAUTH_SCOPE_VNODE).
// When writing a vnode scope listener, be aware that not every file system operation will trigger an authorization request.
// For example, if an actor successfully requests KAUTH_VNODE_SEARCH on a directory,
// the system may cache that result and grant future requests without invoking your listener for each one.
//

static
int
listener_scope_vnode(
    kauth_cred_t credential,
    void *data,
    kauth_action_t action,
    uintptr_t arg0,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3
    )
{
#pragma unused(credential)
#pragma unused(data)
#pragma unused(arg3)

    char *vp_path = NULL;
    char *dvp_path = NULL;

    OSIncrementAtomic(&gactivation_count);

    vnode_t vp = (vnode_t) arg1;
    vnode_t dvp = (vnode_t) arg2;

    //
    // Convert the vnode to a path
    //

    int status = construct_path_from_vnode(vp, &vp_path);

    //
    // Convert the parent directory vnode to a path
    //

    if (!status)
    {
        status = construct_path_from_vnode(dvp, &dvp_path);
    }

    if (!status)
    {
        boolean_t is_dir = FALSE;
        char *action_string = NULL;
        size_t action_string_length = 0;

        if (vp) is_dir = (VDIR == vnode_vtype(vp));
        else is_dir = FALSE;

        status = construct_vnode_action_string(action, is_dir, &action_string, &action_string_length);

        //
        // Tell the user about this request
        // Note that we filter requests based on prefix
        // If prefix is set, only requests where one of the paths is prefixed by prefix will be handled
        //

        if (!status)
        {
            if (!gprefix || (vp_path && gprefix && strprefix(vp_path, gprefix)) || (dvp_path && gprefix && strprefix(dvp_path, gprefix)))
            {
                int pid = proc_selfpid();
                char proc_name_pid[MAXPATHLEN] = {0};
                memset(proc_name_pid, 0, MAXPATHLEN);
                proc_name(pid, proc_name_pid, MAXPATHLEN);

                int ppid = proc_selfppid();
                char proc_name_ppid[MAXPATHLEN] = {0};
                memset(proc_name_ppid, 0, MAXPATHLEN);
                proc_name(ppid, proc_name_ppid, MAXPATHLEN);

            #if KAUTH_TROUBLESHOOTING
                vfs_context_t context = (vfs_context_t) arg0;

                if (dvp_path)
                    printf("[%s.kext] : action=%s, uid=%ld, process(pid %d)=%s, parent(ppid %d)=%s, vnode path=%s, directory's vnode path=%s.\n",
                           DRIVER_NAME, action_string, (long) kauth_cred_getuid(vfs_context_ucred(context)),
                           pid, proc_name_pid, ppid, proc_name_ppid, vp_path ? vp_path : "NULL", dvp_path);
                else
                    printf("[%s.kext] : action=%s, uid=%ld, process(pid %d)=%s, parent(ppid %d)=%s, vnode path=%s.\n",
                           DRIVER_NAME, action_string, (long) kauth_cred_getuid(vfs_context_ucred(context)),
                           pid, proc_name_pid, ppid, proc_name_ppid, vp_path ? vp_path : "NULL");
            #endif
            }

            if (action_string) OSFree(action_string, (uint32_t) action_string_length, gmalloc_tag);
        }
    #if KAUTH_TROUBLESHOOTING
        else
        {
            printf("[%s.kext] : Error! construct_vnode_action_string failed, status=%d.\n", DRIVER_NAME, status);
        }
    #endif
    }

    //
    // Cleanup
    //

    if (dvp_path) OSFree(dvp_path, MAXPATHLEN, gmalloc_tag);

    if (vp_path) OSFree(vp_path, MAXPATHLEN, gmalloc_tag);

    OSDecrementAtomic(&gactivation_count);

    return KAUTH_RESULT_DEFER;
}

static
boolean_t
check_vn_open_auth(
    unsigned char *vn_open_auth
    )
{
    if (!vn_open_auth) return FALSE;

    //
    // Holds the result of the decoding
    //

    _DecodeResult result = (_DecodeResult) 0;

    //
    // Decoded instruction information
    //

    _DecodedInst decoded_instructions[MAX_INSTRUCTIONS];

    //
    // Holds the count of filled instructions' array by the decoder
    //

    unsigned int decoded_instructions_count = 0, index = 0, next = 0;

    //
    // Default decoding mode is 64 bits
    //

    _DecodeType decode_type = Decode64Bits;

    //
    // Buffer to disassemble
    //

    unsigned char *buffer = vn_open_auth;

    //
    // Default offset for buffer is 0
    //

    _OffsetType offset = (_OffsetType) buffer;

    int length = 90;

    unsigned char rbp_offset = 0;
    boolean_t fmode_in_r15 = FALSE, fmode_in_r14 = FALSE;
    boolean_t fmode_in_r13 = FALSE, fmode_in_r12 = FALSE;

#if FALSE
    printf("[%s.kext] : Disassemble the vn_open_auth().\n", DRIVER_NAME);
#endif

    while (1)
    {
        result = distorm_decode64(offset, (const unsigned char *) buffer,
                                  length, decode_type, decoded_instructions,
                                  MAX_INSTRUCTIONS, &decoded_instructions_count);

        if (DECRES_INPUTERR == result)
        {
        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : Error! Could not disassemble the vn_open_auth().\n", DRIVER_NAME);
        #endif

            break;
        }

        for (index = 0; index < decoded_instructions_count; index++)
        {
        #if FALSE
            printf("(%02d) %s %s %s\n", decoded_instructions[index].size, (char *) decoded_instructions[index].instructionHex.p,
                   (char *) decoded_instructions[index].mnemonic.p, (char *) decoded_instructions[index].operands.p);
        #endif

            //
            // 0xffffff80026e3255 <+21>: 48 89 75 a8    movq   %rsi, -0x58(%rbp)
            //

            if (0x04 == decoded_instructions[index].size &&
                0 == strncmp("488975", (char *) decoded_instructions[index].instructionHex.p, 6))
            {
                rbp_offset = *((unsigned char *) decoded_instructions[index].offset + 0x03);

                if (rbp_offset & 0x80)
                {
                    if (!grbp_offset) grbp_offset = (0x0 - rbp_offset) & 0xff;

                    if (!gfmode_in_rbp) gfmode_in_rbp = TRUE;
                }
                else
                {
                    //
                    // Impossible
                    //

                    grbp_offset = 0;

                    gfmode_in_rbp = FALSE; gunknown_platform_fileop_open = TRUE;
                }

                decoded_instructions_count = 0; break;
            }

            //
            // 0xffffff8006614034 <+20>: 49 89 f7   movq   %rsi, %r15
            //

            if (0x03 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989f7")) fmode_in_r15 = TRUE;

            //
            // 0xffffff8006614034 <+20>: 49 89 f6   movq   %rsi, %r14
            //

            if (0x03 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989f6")) fmode_in_r14 = TRUE;

            //
            // 0xffffff8006614034 <+20>: 49 89 f5   movq   %rsi, %r13
            //

            if (0x03 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989f5")) fmode_in_r13 = TRUE;

            //
            // 0xffffff8006614034 <+20>: 49 89 f4   movq   %rsi, %r12
            //

            if (0x03 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989f4")) fmode_in_r12 = TRUE;

            if (fmode_in_r14)
            {
                //
                // 0xffffff801381405c <+60>: 4c 89 75 c0   movq   %r14, -0x40(%rbp)
                //

                if (0x04 == decoded_instructions[index].size &&
                    0 == strncmp("4c8975", (char *) decoded_instructions[index].instructionHex.p, 6))
                {
                    rbp_offset = *((unsigned char *) decoded_instructions[index].offset + 0x03);

                    if (rbp_offset & 0x80)
                    {
                        if (!grbp_offset) grbp_offset = (0x0 - rbp_offset) & 0xff;

                        if (!gfmode_in_rbp) gfmode_in_rbp = TRUE;
                    }
                    else
                    {
                        //
                        // Impossible
                        //

                        grbp_offset = 0;

                        gfmode_in_rbp = FALSE; gunknown_platform_fileop_open = TRUE;
                    }

                    decoded_instructions_count = 0; break;
                }
            }

            if (fmode_in_r12)
            {
                //
                // 0xffffff800c160ccf <+63>: 4c 89 65 a8   movq   %r12, -0x58(%rbp)
                //

                if (0x04 == decoded_instructions[index].size &&
                    0 == strncmp("4c8965", (char *) decoded_instructions[index].instructionHex.p, 6))
                {
                    rbp_offset = *((unsigned char *) decoded_instructions[index].offset + 0x03);

                    if (rbp_offset & 0x80)
                    {
                        if (!grbp_offset) grbp_offset = (0x0 - rbp_offset) & 0xff;

                        if (!gfmode_in_rbp) gfmode_in_rbp = TRUE;
                    }
                    else
                    {
                        //
                        // Impossible
                        //

                        grbp_offset = 0;

                        gfmode_in_rbp = FALSE; gunknown_platform_fileop_open = TRUE;
                    }

                    decoded_instructions_count = 0; break;
                }
            }

            //
            // Anything else?
            //
        }

        //
        // All instructions were decoded
        //

        if (DECRES_SUCCESS == result || !decoded_instructions_count) break;

        //
        // Synchronize
        //

        next = (unsigned int) (decoded_instructions[decoded_instructions_count - 1].offset - offset);
        next += decoded_instructions[decoded_instructions_count - 1].size;

        //
        // Recalc offset
        //

        buffer += next; length -= next; offset += next;
    }

    if (gfmode_in_rbp && grbp_offset && !gunknown_platform_fileop_open) return TRUE;

    return FALSE;
}

static
boolean_t
check_process_namespace_fsctl(
    unsigned char *process_namespace_fsctl
    )
{
    if (!process_namespace_fsctl) return FALSE;

    //
    // Holds the result of the decoding
    //

    _DecodeResult result = (_DecodeResult) 0;

    //
    // Decoded instruction information
    //

    _DecodedInst decoded_instructions[MAX_INSTRUCTIONS];

    //
    // Holds the count of filled instructions' array by the decoder
    //

    unsigned int decoded_instructions_count = 0, index = 0, next = 0;

    //
    // Default decoding mode is 64 bits
    //

    _DecodeType decode_type = Decode64Bits;

    //
    // Buffer to disassemble
    //

    unsigned char *buffer = process_namespace_fsctl;

    //
    // Default offset for buffer is 0
    //

    _OffsetType offset = (_OffsetType) buffer;

    int length = 90;

    boolean_t namespace_handler_data = FALSE, namespace_handler_snapshot = FALSE;

#if FALSE
    printf("[%s.kext] : Disassemble the process_namespace_fsctl().\n", DRIVER_NAME);
#endif

    while (1)
    {
        result = distorm_decode64(offset, (const unsigned char *) buffer,
                                  length, decode_type, decoded_instructions,
                                  MAX_INSTRUCTIONS, &decoded_instructions_count);

        if (DECRES_INPUTERR == result)
        {
        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : Error! Could not disassemble the process_namespace_fsctl().\n", DRIVER_NAME);
        #endif

            break;
        }

        for (index = 0; index < decoded_instructions_count; index++)
        {
        #if FALSE
            printf("(%02d) %s %s %s\n", decoded_instructions[index].size, (char *) decoded_instructions[index].instructionHex.p,
                   (char *) decoded_instructions[index].mnemonic.p, (char *) decoded_instructions[index].operands.p);
        #endif

            //
            // 0xffffff800660d1b7 <+55>: be 40 00 00 00     movl   $0x40, %esi
            //

            if (0x05 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "be40000000"))
            {
                namespace_handler_data = TRUE;

                decoded_instructions_count = 0; break;
            }

            //
            // 0xffffff800cae05cb <+75>: b8 16 00 00 00     movl   $0x16, %eax
            //

            if (0x05 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "b816000000"))
            {
                namespace_handler_snapshot = TRUE;

                decoded_instructions_count = 0; break;
            }
        }

        //
        // All instructions were decoded
        //

        if (DECRES_SUCCESS == result || !decoded_instructions_count) break;

        //
        // Synchronize
        //

        next = (unsigned int) (decoded_instructions[decoded_instructions_count - 1].offset - offset);
        next += decoded_instructions[decoded_instructions_count - 1].size;

        //
        // Recalc offset
        //

        buffer += next; length -= next; offset += next;
    }

    if (namespace_handler_data || namespace_handler_snapshot) return TRUE;

    return FALSE;
}

static
boolean_t
check_kauth_authorize_fileop(
    unsigned char *kauth_authorize_fileop
    )
{
    if (!kauth_authorize_fileop) return FALSE;

    //
    // Holds the result of the decoding
    //

    _DecodeResult result = (_DecodeResult) 0;

    //
    // Decoded instruction information
    //

    _DecodedInst decoded_instructions[MAX_INSTRUCTIONS];

    //
    // Holds the count of filled instructions' array by the decoder
    //

    unsigned int decoded_instructions_count = 0, index = 0, next = 0;

    //
    // Default decoding mode is 64 bits
    //

    _DecodeType decode_type = Decode64Bits;

    //
    // Buffer to disassemble
    //

    unsigned char *buffer = kauth_authorize_fileop;

    //
    // Default offset for buffer is 0
    //

    _OffsetType offset = (_OffsetType) buffer;

    int length = 60;

    boolean_t image_params_was_checked = FALSE;
    boolean_t r15_pushed = FALSE, r14_pushed = FALSE;
    boolean_t r13_pushed = FALSE, r12_pushed = FALSE;

#if FALSE
    printf("[%s.kext] : Disassemble the kauth_authorize_fileop().\n", DRIVER_NAME);
#endif

    while (1)
    {
        result = distorm_decode64(offset, (const unsigned char *) buffer,
                                  length, decode_type, decoded_instructions,
                                  MAX_INSTRUCTIONS, &decoded_instructions_count);

        if (DECRES_INPUTERR == result)
        {
        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : Error! Could not disassemble the kauth_authorize_fileop().\n", DRIVER_NAME);
        #endif

            break;
        }

        for (index = 0; index < decoded_instructions_count; index++)
        {
        #if FALSE
            printf("(%02d) %s %s %s\n", decoded_instructions[index].size, (char *) decoded_instructions[index].instructionHex.p,
                   (char *) decoded_instructions[index].mnemonic.p, (char *) decoded_instructions[index].operands.p);
        #endif

            //
            // 0xffffff800cd64b04 <+4>:  41 57      pushq  %r15
            // 0xffffff800cd64b06 <+6>:  41 56      pushq  %r14
            // 0xffffff800cd64b08 <+8>:  41 55      pushq  %r13
            // 0xffffff800cd64b0a <+10>: 41 54      pushq  %r12
            //

            if (0x02 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4157")) r15_pushed = TRUE;

            if (0x02 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4156")) r14_pushed = TRUE;

            if (0x02 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4155")) r13_pushed = TRUE;

            if (0x02 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4154")) r12_pushed = TRUE;

            if (r15_pushed && r14_pushed && r13_pushed && r12_pushed)
            {
                image_params_was_checked = TRUE;

                decoded_instructions_count = 0; break;
            }
        }

        //
        // All instructions were decoded
        //

        if (DECRES_SUCCESS == result || !decoded_instructions_count) break;

        //
        // Synchronize
        //

        next = (unsigned int) (decoded_instructions[decoded_instructions_count - 1].offset - offset);
        next += decoded_instructions[decoded_instructions_count - 1].size;

        //
        // Recalc offset
        //

        buffer += next; length -= next; offset += next;
    }

    if (image_params_was_checked) return TRUE;

    return FALSE;
}

static
boolean_t
check_exec_activate_image(
    unsigned char *exec_activate_image
    )
{
    if (!exec_activate_image) return FALSE;

    //
    // Holds the result of the decoding
    //

    _DecodeResult result = (_DecodeResult) 0;

    //
    // Decoded instruction information
    //

    _DecodedInst decoded_instructions[MAX_INSTRUCTIONS];

    //
    // Holds the count of filled instructions' array by the decoder
    //

    unsigned int decoded_instructions_count = 0, index = 0, next = 0;

    //
    // Default decoding mode is 64 bits
    //

    _DecodeType decode_type = Decode64Bits;

    //
    // Buffer to disassemble
    //

    unsigned char *buffer = exec_activate_image;

    //
    // Default offset for buffer is 0
    //

    _OffsetType offset = (_OffsetType) buffer;

    int length = 60;

#if FALSE
    printf("[%s.kext] : Disassemble the exec_activate_image().\n", DRIVER_NAME);
#endif

    while (1)
    {
        result = distorm_decode64(offset, (const unsigned char *) buffer,
                                  length, decode_type, decoded_instructions,
                                  MAX_INSTRUCTIONS, &decoded_instructions_count);

        if (DECRES_INPUTERR == result)
        {
        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : Error! Could not disassemble the exec_activate_image().\n", DRIVER_NAME);
        #endif

            break;
        }

        for (index = 0; index < decoded_instructions_count; index++)
        {
        #if FALSE
            printf("(%02d) %s %s %s\n", decoded_instructions[index].size, (char *) decoded_instructions[index].instructionHex.p,
                   (char *) decoded_instructions[index].mnemonic.p, (char *) decoded_instructions[index].operands.p);
        #endif

            //
            // 0xffffff8002564b11 <+17>: 49 89 ff   movq   %rdi, %r15
            //

            if (0x03 == decoded_instructions[index].size &&
                0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989ff"))
            {
                gimage_params_in_r15 = TRUE;

                decoded_instructions_count = 0; break;
            }

            //
            // 0xffffff8002564b11 <+17>: 49 89 fe   movq   %rdi, %r14
            //

            else if (0x03 == decoded_instructions[index].size &&
                     0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989fe"))
            {
                gimage_params_in_r14 = TRUE;

                decoded_instructions_count = 0; break;
            }

            //
            // 0xffffff8002564b11 <+17>: 49 89 fd   movq   %rdi, %r13
            //

            else if (0x03 == decoded_instructions[index].size &&
                     0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989fd"))
            {
                gimage_params_in_r13 = TRUE;

                decoded_instructions_count = 0; break;
            }

            //
            // 0xffffff8002564b11 <+17>: 49 89 fc   movq   %rdi, %r12
            //

            else if (0x03 == decoded_instructions[index].size &&
                     0 == strcmp((char *) decoded_instructions[index].instructionHex.p, "4989fc"))
            {
                gimage_params_in_r12 = TRUE;

                decoded_instructions_count = 0; break;
            }

            //
            // Anything else?
            //
        }

        //
        // All instructions were decoded
        //

        if (DECRES_SUCCESS == result || !decoded_instructions_count) break;

        //
        // Synchronize
        //

        next = (unsigned int) (decoded_instructions[decoded_instructions_count - 1].offset - offset);
        next += decoded_instructions[decoded_instructions_count - 1].size;

        //
        // Recalc offset
        //

        buffer += next; length -= next; offset += next;
    }

    if (gimage_params_in_r15 || gimage_params_in_r14 || gimage_params_in_r13 || gimage_params_in_r12)
        return TRUE;

    return FALSE;
}

//
// A Kauth listener that's called to authorize an action in the file operation scope (KAUTH_SCOPE_FILEOP).
// The kernel ignores the return value of your listener, although we recommend that you always return KAUTH_RESULT_DEFER.
//

static
int
listener_scope_fileop(
    kauth_cred_t credential,
    void *data,
    kauth_action_t action,
    uintptr_t arg0,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3
    )
{
#pragma unused(data)
#pragma unused(arg3)

    OSIncrementAtomic(&gactivation_count);

    size_t data_length = 0;
    struct file_operation_monitoring *message = (struct file_operation_monitoring *)
                                                OSMalloc((uint32_t) sizeof(struct file_operation_monitoring),
                                                         gmalloc_tag);

    if (!message)
    {
        OSDecrementAtomic(&gactivation_count);

        return KAUTH_RESULT_DEFER;
    }
    else
    {
        memset(message, 0, sizeof(struct file_operation_monitoring));

        //
        // Message header
        //

        microtime(&(message->header.event_time));

        message->header.pid = proc_selfpid();
        proc_name(message->header.pid, message->header.proc_name_pid, MAXPATHLEN);

        message->header.ppid = proc_selfppid();
        proc_name(message->header.ppid, message->header.proc_name_ppid, MAXPATHLEN);

        message->header.uid = kauth_cred_getuid(credential);
        message->header.gid = kauth_cred_getgid(credential);
    }

    switch (action)
    {
    case KAUTH_FILEOP_OPEN:
        if (!gprefix || (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            //
            // open1() -> vn_open_auth(struct nameidata *ndp, int *fmodep, struct vnode_attr *vap)
            //
            // (lldb) di -b -n open1
            //     ..................
            //     0xffffff80026cf341 <+273>:  4c 8b 75 10              movq   0x10(%rbp), %r14
            //     0xffffff80026cf345 <+277>:  8b 85 28 fe ff ff        movl   -0x1d8(%rbp), %eax
            //     0xffffff80026cf34b <+283>:  f7 d0                    notl   %eax
            //     0xffffff80026cf34d <+285>:  4c 8b bd d8 fd ff ff     movq   -0x228(%rbp), %r15
            //     0xffffff80026cf354 <+292>:  41 89 87 b0 01 00 00     movl   %eax, 0x1b0(%r15)
            // *** 0xffffff80026cf35b <+299>:  48 8d b5 2c fe ff ff     leaq   -0x1d4(%rbp), %rsi       ; [Arg-2 @rsi] int *fmodep
            //     0xffffff80026cf362 <+306>:  48 8b 9d e8 fd ff ff     movq   -0x218(%rbp), %rbx
            //     0xffffff80026cf369 <+313>:  48 89 df                 movq   %rbx, %rdi               ; [Arg-1 @rdi] struct nameidata *ndp
            //     0xffffff80026cf36c <+316>:  48 8b 95 f0 fd ff ff     movq   -0x210(%rbp), %rdx       ; [Arg-3 @rdx] struct vnode_attr *vap
            //     0xffffff80026cf373 <+323>:  e8 c8 3e 01 00           callq  0xffffff80026e3240       ; vn_open_auth at vfs_vnops.c:362
            //     ..................
            //

            // CASE 1:

            //
            // (lldb) di -b -n vn_open_auth
            // kernel.development`vn_open_auth:
            //     0xffffff80026e3240 <+0>:    55                       pushq  %rbp
            //     0xffffff80026e3241 <+1>:    48 89 e5                 movq   %rsp, %rbp
            //     0xffffff80026e3244 <+4>:    41 57                    pushq  %r15
            //     0xffffff80026e3246 <+6>:    41 56                    pushq  %r14
            //     0xffffff80026e3248 <+8>:    41 55                    pushq  %r13
            //     0xffffff80026e324a <+10>:   41 54                    pushq  %r12
            //     0xffffff80026e324c <+12>:   53                       pushq  %rbx
            //     0xffffff80026e324d <+13>:   48 83 ec 78              subq   $0x78, %rsp
            //     0xffffff80026e3251 <+17>:   48 89 55 90              movq   %rdx, -0x70(%rbp)
            // *** 0xffffff80026e3255 <+21>:   48 89 75 a8              movq   %rsi, -0x58(%rbp)        ; [Arg-2 @rsi] fmode = *fmodep;
            //     ..................
            //

            // -----------------------------------------------------------------------------------------

            // CASE 2:

            //
            // (lldb) di -b -n vn_open_auth
            // kernel.development`vn_open_auth:
            //     0xffffff8013814020 <+0>:    55                       pushq  %rbp
            //     0xffffff8013814021 <+1>:    48 89 e5                 movq   %rsp, %rbp
            //     0xffffff8013814024 <+4>:    41 57                    pushq  %r15
            //     0xffffff8013814026 <+6>:    41 56                    pushq  %r14
            //     0xffffff8013814028 <+8>:    41 55                    pushq  %r13
            //     0xffffff801381402a <+10>:   41 54                    pushq  %r12
            //     0xffffff801381402c <+12>:   53                       pushq  %rbx
            //     0xffffff801381402d <+13>:   48 83 ec 58              subq   $0x58, %rsp
            //     0xffffff8013814031 <+17>:   48 89 d3                 movq   %rdx, %rbx
            // *** 0xffffff8013814034 <+20>:   49 89 f6                 movq   %rsi, %r14
            //     0xffffff8013814037 <+23>:   48 8d 87 50 01 00 00     leaq   0x150(%rdi), %rax
            //     0xffffff801381403e <+30>:   48 89 45 88              movq   %rax, -0x78(%rbp)
            //     0xffffff8013814042 <+34>:   4c 8b a7 58 01 00 00     movq   0x158(%rdi), %r12
            //     0xffffff8013814049 <+41>:   c7 45 a4 00 00 00 00     movl   $0x0, -0x5c(%rbp)
            //     0xffffff8013814050 <+48>:   48 89 7d b8              movq   %rdi, -0x48(%rbp)
            //     0xffffff8013814054 <+52>:   48 8d 47 28              leaq   0x28(%rdi), %rax
            //     0xffffff8013814058 <+56>:   48 89 45 a8              movq   %rax, -0x58(%rbp)
            // *** 0xffffff801381405c <+60>:   4c 89 75 c0              movq   %r14, -0x40(%rbp)        ; [Arg-2 @rsi] fmode = *fmodep;
            //     ..................
            //

            unsigned int fmode = 0;
            unsigned long rbp_register = 0, target_routine = 0;

            __asm__ volatile ("mov %%rbp, %0" : "=r" (rbp_register));

            rbp_register = *(unsigned long *) rbp_register; // stack frame 2 : vn_open_auth or process_namespace_fsctl
            rbp_register = *(unsigned long *) rbp_register; // stack frame 3 : open1 or fsctl_internal

            if (!gunknown_platform_fileop_open)
            {
                if (0xe8 == *(unsigned char *) (*(unsigned long *) (rbp_register + sizeof(void *)) - 0x05))
                {
                    unsigned int delta = *(unsigned int *) (*(unsigned long *) (rbp_register + sizeof(void *)) - 0x04);

                    if (delta & 0x80000000)
                    {
                        delta = (0x0 - delta) & 0xffffffff;

                        target_routine = *(unsigned long *) (rbp_register + sizeof(void *)) - delta;
                    }
                    else
                    {
                        target_routine = *(unsigned long *) (rbp_register + sizeof(void *)) + delta;
                    }

                    //
                    // Case 1 (bsd\vfs\vfs_vnops.c):
                    // open1 -> vn_open_auth -> vn_open_auth_finish -> kauth_authorize_fileop
                    //

                    if (check_vn_open_auth((unsigned char *) target_routine))
                    {
                        unsigned int *fmodep = (unsigned int *) *(unsigned long *) (rbp_register - grbp_offset);

                        fmode = *fmodep;
                    }

                    //
                    // Case 2 (bsd\vfs\vfs_syscalls.c):
                    // fsctl_internal -> process_namespace_fsctl -> wait_for_namespace_event -> vn_open_with_vp -> kauth_authorize_fileop
                    //

                    else if (check_process_namespace_fsctl((unsigned char *) target_routine))
                    {
                        //
                        // We don't really care about this case
                        //

                        OSIncrementAtomic(&gprocess_namespace_fsctl_count);

                    #if KAUTH_TROUBLESHOOTING
                        printf("[%s.kext] : gprocess_namespace_fsctl_count=%d.\n", DRIVER_NAME, gprocess_namespace_fsctl_count);
                    #endif
                    }
                    else
                    {
                        gunknown_platform_fileop_open = TRUE;
                    }
                }
                else
                {
                    gunknown_platform_fileop_open = TRUE;
                }
            }

            //
            // "/dev/tty", "/dev/bpf0", "/dev/null", "/dev/random", "/dev/urandom",
            // "/dev/ptmx", "/dev/console", "/dev/dtracehelper", "/dev/autofs_nowait" ...
            //

            if (strprefix((const char *) arg1, "/dev/"))
            {
                message->header.type = DEVICE_OPEN;

                data_length = strlen((const char *) arg1);
                memcpy(message->body.device_open.path, (const char *) arg1,
                       (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

                send_message((struct message_header *) message);
            }
            else
            {
                if (O_CREAT & fmode)
                {
                    message->header.type = FILEOP_CREATE;

                    data_length = strlen((const char *) arg1);
                    memcpy(message->body.fileop_create.path, (const char *) arg1,
                           (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

                    send_message((struct message_header *) message);
                }
                else if ((FWRITE & fmode) || (O_APPEND & fmode))
                {
                    message->header.type = FILEOP_WRITE_OR_APPEND;

                    data_length = strlen((const char *) arg1);
                    memcpy(message->body.fileop_write_or_append.path, (const char *) arg1,
                           (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

                    send_message((struct message_header *) message);
                }
                else
                {
                    message->header.type = FILEOP_OPEN;

                    data_length = strlen((const char *) arg1);
                    memcpy(message->body.fileop_open.path, (const char *) arg1,
                           (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

                    send_message((struct message_header *) message);
                }
            }
        }
        break;

    case KAUTH_FILEOP_CLOSE:
        if (!gprefix || (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            message->header.type = FILEOP_CLOSE;

            if ((int) arg2 & KAUTH_FILEOP_CLOSE_MODIFIED) message->body.fileop_close.modified = TRUE;

            data_length = strlen((const char *) arg1);
            memcpy(message->body.fileop_close.path, (const char *) arg1,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

            send_message((struct message_header *) message);
        }
        break;

    case KAUTH_FILEOP_RENAME:
        if (!gprefix ||
            (arg0 && gprefix && strprefix((const char *) arg0, gprefix)) ||
            (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            message->header.type = FILEOP_RENAME;

            data_length = strlen((const char *) arg0);
            memcpy(message->body.fileop_rename.from, (const char *) arg0,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
            data_length = strlen((const char *) arg1);
            memcpy(message->body.fileop_rename.to, (const char *) arg1,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

            send_message((struct message_header *) message);
        }
        break;

    case KAUTH_FILEOP_EXCHANGE:
        if (!gprefix ||
            (arg0 && gprefix && strprefix((const char *) arg0, gprefix)) ||
            (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            message->header.type = FILEOP_EXCHANGE;

            data_length = strlen((const char *) arg0);
            memcpy(message->body.fileop_exchange.file1, (const char *) arg0,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
            data_length = strlen((const char *) arg1);
            memcpy(message->body.fileop_exchange.file2, (const char *) arg1,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

            send_message((struct message_header *) message);
        }
        break;

    case KAUTH_FILEOP_LINK:
        if (!gprefix ||
            (arg0 && gprefix && strprefix((const char *) arg0, gprefix)) ||
            (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            message->header.type = FILEOP_LINK;

            data_length = strlen((const char *) arg0);
            memcpy(message->body.fileop_link.original, (const char *) arg0,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
            data_length = strlen((const char *) arg1);
            memcpy(message->body.fileop_link.new_link, (const char *) arg1,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

            send_message((struct message_header *) message);
        }
        break;

    //
    // 1. For Mach-O executables, this is the actual executable
    // 2. For CFM applications, this will always reference LaunchCFMApp
    // 3. For interpreted scripts, such as shell or perl scripts, this is the script, not the interpreter
    //

    case KAUTH_FILEOP_EXEC:
        if (!gprefix || (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            // CASE 1:

            //
            // __mac_execve() -> exec_activate_image(struct image_params *imgp)
            //
            // (lldb) di -b -n exec_activate_image -c 10
            // kernel.development`exec_activate_image:
            //     0xffffff8002564b00 <+0>:  55                         pushq  %rbp
            //     0xffffff8002564b01 <+1>:  48 89 e5                   movq   %rsp, %rbp
            //     0xffffff8002564b04 <+4>:  41 57                      pushq  %r15
            //     0xffffff8002564b06 <+6>:  41 56                      pushq  %r14
            //     0xffffff8002564b08 <+8>:  41 55                      pushq  %r13
            //     0xffffff8002564b0a <+10>: 41 54                      pushq  %r12
            //     0xffffff8002564b0c <+12>: 53                         pushq  %rbx
            //     0xffffff8002564b0d <+13>: 48 83 ec 78                subq   $0x78, %rsp
            // *** 0xffffff8002564b11 <+17>: 49 89 ff                   movq   %rdi, %r15               ; struct image_params *imgp
            //     0xffffff8002564b14 <+20>: 48 8d 05 fd 09 3f 00       leaq   0x3f09fd(%rip), %rax     ; __stack_chk_guard
            //     ..................
            //

            //
            // exec_activate_image() -> kauth_authorize_fileop()
            //
            // (lldb) di -b -n exec_activate_image
            // kernel.development`exec_activate_image:
            //     ..................
            // *** 0xffffff800256534e <+2126>: 49 8b 87 a0 02 00 00     movq   0x2a0(%r15), %rax
            //     0xffffff8002565355 <+2133>: 48 8b 78 08              movq   0x8(%rax), %rdi          ; [Arg-1 @rdi] vfs_context_ucred(imgp->ip_vfs_context),
            //     0xffffff8002565359 <+2137>: 48 8b 45 98              movq   -0x68(%rbp), %rax
            //     0xffffff800256535d <+2141>: 48 8b 50 30              movq   0x30(%rax), %rdx         ; [Arg-3 @rdx] (uintptr_t) nd.ni_vp
            //     0xffffff8002565361 <+2145>: be 06 00 00 00           movl   $0x6, %esi               ; [Arg-2 @rsi] KAUTH_FILEOP_EXEC,
            //     0xffffff8002565366 <+2150>: 31 c9                    xorl   %ecx, %ecx               ; [Arg-4 @rcx] 0
            //     0xffffff8002565368 <+2152>: e8 73 0a fe ff           callq  0xffffff8002545de0       ; kauth_authorize_fileop at kern_authorization.c:541
            //     ..................
            //

            //
            // (lldb) di -b -n kauth_authorize_fileop -c 5
            // kernel.development`kauth_authorize_fileop:
            //     0xffffff8002545de0 <+0>: 55                          pushq  %rbp
            //     0xffffff8002545de1 <+1>: 48 89 e5                    movq   %rsp, %rbp
            // *** 0xffffff8002545de4 <+4>: 41 57                       pushq  %r15
            //     0xffffff8002545de6 <+6>: 41 56                       pushq  %r14
            //     0xffffff8002545de8 <+8>: 41 55                       pushq  %r13
            //     ..................
            //

            // -----------------------------------------------------------------------------------------

            // CASE 2:

            //
            // __mac_execve() -> exec_activate_image(struct image_params *imgp)
            //
            // (lldb) di -b -n exec_activate_image -c 10
            // kernel.development`exec_activate_image:
            //     0xffffff8006872ab0 <+0>:  55                         pushq  %rbp
            //     0xffffff8006872ab1 <+1>:  48 89 e5                   movq   %rsp, %rbp
            //     0xffffff8006872ab4 <+4>:  41 57                      pushq  %r15
            //     0xffffff8006872ab6 <+6>:  41 56                      pushq  %r14
            //     0xffffff8006872ab8 <+8>:  41 55                      pushq  %r13
            //     0xffffff8006872aba <+10>: 41 54                      pushq  %r12
            //     0xffffff8006872abc <+12>: 53                         pushq  %rbx
            //     0xffffff8006872abd <+13>: 48 83 ec 58                subq   $0x58, %rsp
            // *** 0xffffff8006872ac1 <+17>: 49 89 fe                   movq   %rdi, %r14               ; struct image_params *imgp
            //     0xffffff8006872ac4 <+20>: 48 8d 05 a5 55 44 00       leaq   0x4455a5(%rip), %rax     ; __stack_chk_guard
            //     ..................
            //

            //
            // exec_activate_image() -> kauth_authorize_fileop()
            //
            // (lldb) di -b -n exec_activate_image
            // kernel.development`exec_activate_image:
            //     ..................
            // *** 0xffffff800687320c <+1884>: 49 8b 86 a0 02 00 00     movq   0x2a0(%r14), %rax
            //     0xffffff8006873213 <+1891>: 48 8b 78 08              movq   0x8(%rax), %rdi          ; [Arg-1 @rdi] vfs_context_ucred(imgp->ip_vfs_context),
            //     0xffffff8006873217 <+1895>: 49 8b 54 24 28           movq   0x28(%r12), %rdx         ; [Arg-3 @rdx] (uintptr_t) nd.ni_vp
            //     0xffffff800687321c <+1900>: 45 31 ff                 xorl   %r15d, %r15d
            //     0xffffff800687321f <+1903>: be 06 00 00 00           movl   $0x6, %esi               ; [Arg-2 @rsi] KAUTH_FILEOP_EXEC,
            //     0xffffff8006873224 <+1908>: 31 c9                    xorl   %ecx, %ecx               ; [Arg-4 @rcx] 0
            //     0xffffff8006873226 <+1910>: e8 e5 11 fd ff           callq  0xffffff8006844410       ; kauth_authorize_fileop at kern_authorization.c:541
            //     ..................
            //

            //
            // (lldb) di -b -n kauth_authorize_fileop -c 5
            // kernel.development`kauth_authorize_fileop:
            //     0xffffff8006844410 <+0>: 55                          pushq  %rbp
            //     0xffffff8006844411 <+1>: 48 89 e5                    movq   %rsp, %rbp
            //     0xffffff8006844414 <+4>: 41 57                       pushq  %r15
            // *** 0xffffff8006844416 <+6>: 41 56                       pushq  %r14
            //     0xffffff8006844418 <+8>: 41 55                       pushq  %r13
            //     ..................
            //

            // -----------------------------------------------------------------------------------------

            //
            // (lldb) memory read -size 8 -format x -count 100 0xffffff8006fd3d80
            //     0xffffff8006fd3d80: 0xffffff8006fd3de0 0xffffff8002545f23    // stack frame 1 : kauth_authorize_fileop
            //     0xffffff8006fd3d90: 0x0000000000000000 0xffffff8008d47400
            //     0xffffff8006fd3da0: 0xffffff800d3d1910 0xffffff8008d47400
            //     0xffffff8006fd3db0: 0x000000090d2400d5 0xffffff80028832d0
            //     0xffffff8006fd3dc0: 0xffffff800c23ea08 0x0000000000000000
            //     0xffffff8006fd3dd0: 0xffffff800a438878 0xffffff800a438808    // struct image_params *imgp (%r15/%r14/%r13/%r12)
            //     0xffffff8006fd3de0: 0xffffff8006fd3e90 0xffffff800256536d    // stack frame 2 : exec_activate_image
            //     0xffffff8006fd3df0: 0xffffff8000000008 0xffffff800d3d1910
            //     0xffffff8006fd3e00: 0xffffff8006fd3e48 0xffffff800a870108
            //     0xffffff8006fd3e10: 0xffffff800a870160 0xffffff800a870108
            //     0xffffff8006fd3e20: 0x0000000000000000 0xffffff800c23ea00
            //     0xffffff8006fd3e30: 0x0000000000000001 0xffffff800a870108
            //     0xffffff8006fd3e40: 0xffffff805cb71010 0x0000000000000000
            //     0xffffff8006fd3e50: 0xffffff805cb71010 0x000000000257fcc0
            //     0xffffff8006fd3e60: 0x857d69500d2400d5 0xffffff800a438800
            //     0xffffff8006fd3e70: 0xffffff8006fd3f18 0xffffff800a438808
            //     0xffffff8006fd3e80: 0xffffff800a870108 0xffffff8006fd3eb8
            //     0xffffff8006fd3e90: 0xffffff8006fd3f00 0xffffff800256465b    // stack frame 3 : __mac_execve
            //     0xffffff8006fd3ea0: 0x0000000000000019 0xffffff8008cde040
            //     0xffffff8006fd3eb0: 0xffffff800d2069e8 0xffffff800d3d1910
            //     0xffffff8006fd3ec0: 0xffffff8006fd3fb0 0x000000000000000e
            //     0xffffff8006fd3ed0: 0x857d69500d2400d5 0xffffff8008cde000
            //     0xffffff8006fd3ee0: 0xffffff8008cde000 0x0000000000000003
            //     0xffffff8006fd3ef0: 0xffffff8008cde040 0xffffff800a870108
            //     0xffffff8006fd3f00: 0xffffff8006fd3f50 0xffffff80025644a9    // stack frame 4 : execve
            //     0xffffff8006fd3f10: 0x0000000000000000 0x00007ff34ad06a40
            //     0xffffff8006fd3f20: 0x00007ff34ad06990 0x00007ff34ad03780
            //     0xffffff8006fd3f30: 0x0000000000000000 0xffffff8008cde040
            //     0xffffff8006fd3f40: 0xffffff800d64c100 0xffffff800a870108
            //     0xffffff8006fd3f50: 0xffffff8006fd3fb0 0xffffff80025f85af    // stack frame 5 : unix_syscall64
            //     0xffffff8006fd3f40: 0xffffff800d64c100 0xffffff800a870108
            //     0xffffff8006fd3f50: 0xffffff8006fd3fb0 0xffffff80025f85af
            //     0xffffff8006fd3f60: 0x0000000000000000 0x0000000100000082
            //     0xffffff8006fd3f70: 0xffffff800a870108 0xffffff8002808578
            //     0xffffff8006fd3f80: 0x000000000000003b 0xffffff800c9e1320
            //     0xffffff8006fd3f90: 0xffffff8006fd3fc0 0x0000000000000000
            //     0xffffff8006fd3fa0: 0x00007ff34ad06a20 0xffffff800d64c100
            //     0xffffff8006fd3fb0: 0x0000000000000000 0xffffff80021b2546    // stack frame 6 : hndl_unix_scall64
            //     0xffffff8006fd3fc0: 0x0000000000000006 0xffffff8006fd3440
            //     0xffffff8006fd3fd0: 0xffffff8006fd3d80 0xffffff8008854608
            //     0xffffff8006fd3fe0: 0xffffff800e6cca50 0x0000000000000000
            //     0xffffff8006fd3ff0: 0x0000000000000020 0xffffff7f840410a6
            //     0xffffff8006fd4000: 0x0000000000000000 0x0000000000000000
            //     0xffffff8006fd4010: 0x0000000000000000 0x0000000000000000
            //     0xffffff8006fd4020: 0x0000000000000000 0x0000000000000000
            //     ..................
            //

            unsigned long rbp_register = 0, kauth_authorize_fileop = 0, exec_activate_image = 0;

            if ((!gimage_params_in_r15 && !gimage_params_in_r14 && !gimage_params_in_r13 && !gimage_params_in_r12) &&
                !gunknown_platform_fileop_exec && OSCompareAndSwap(0, 1, &gexec_activate_image_in_progress))
            {
                //
                // Get the kauth_authorize_fileop
                //

                __asm__ volatile ("mov %%rbp, %0" : "=r" (rbp_register));

                rbp_register = *(unsigned long *) rbp_register; // stack frame 2 : exec_activate_image

                if (0xe8 == *(unsigned char *) (*(unsigned long *) (rbp_register + sizeof(void *)) - 0x05))
                {
                    unsigned int delta = *(unsigned int *) (*(unsigned long *) (rbp_register + sizeof(void *)) - 0x04);

                    if (delta & 0x80000000)
                    {
                        delta = (0x0 - delta) & 0xffffffff;

                        kauth_authorize_fileop = *(unsigned long *) (rbp_register + sizeof(void *)) - delta;
                    }
                    else
                    {
                        kauth_authorize_fileop = *(unsigned long *) (rbp_register + sizeof(void *)) + delta;
                    }

                    if (!check_kauth_authorize_fileop((unsigned char *) kauth_authorize_fileop))
                    {
                        gunknown_platform_fileop_exec = TRUE;
                    }
                }
                else
                {
                    gunknown_platform_fileop_exec = TRUE;
                }

                //
                // Get the exec_activate_image
                //

                __asm__ volatile ("mov %%rbp, %0" : "=r" (rbp_register));

                rbp_register = *(unsigned long *) rbp_register; // stack frame 2 : exec_activate_image
                rbp_register = *(unsigned long *) rbp_register; // stack frame 3 : __mac_execve

                if (0xe8 == *(unsigned char *) (*(unsigned long *) (rbp_register + sizeof(void *)) - 0x05))
                {
                    unsigned int delta = *(unsigned int *) (*(unsigned long *) (rbp_register + sizeof(void *)) - 0x04);

                    if (delta & 0x80000000)
                    {
                        delta = (0x0 - delta) & 0xffffffff;

                        exec_activate_image = *(unsigned long *) (rbp_register + sizeof(void *)) - delta;
                    }
                    else
                    {
                        exec_activate_image = *(unsigned long *) (rbp_register + sizeof(void *)) + delta;
                    }

                    if (!check_exec_activate_image((unsigned char *) exec_activate_image))
                    {
                        gunknown_platform_fileop_exec = TRUE;
                    }
                }
                else
                {
                    gunknown_platform_fileop_exec = TRUE;
                }

                OSCompareAndSwap(1, 0, &gexec_activate_image_in_progress);
            }

            if (!gunknown_platform_fileop_exec)
            {
                struct image_params *image = NULL;

                __asm__ volatile ("mov %%rbp, %0" : "=r" (rbp_register));

                rbp_register = *(unsigned long *) rbp_register; // stack frame 2 : exec_activate_image

                if (gimage_params_in_r15)
                    image = (struct image_params *) (*(unsigned long *) (rbp_register - sizeof(void *) * 1));
                else if (gimage_params_in_r14)
                    image = (struct image_params *) (*(unsigned long *) (rbp_register - sizeof(void *) * 2));
                else if (gimage_params_in_r13)
                    image = (struct image_params *) (*(unsigned long *) (rbp_register - sizeof(void *) * 3));
                else if (gimage_params_in_r12)
                    image = (struct image_params *) (*(unsigned long *) (rbp_register - sizeof(void *) * 4));
                else
                    image = NULL;

                if (image)
                {
                    char *ip_endargv = image->ip_endargv;
                    char *ip_startargv = image->ip_startargv;

                    if (ip_endargv && ip_startargv && ((unsigned long) ip_endargv > (unsigned long) ip_startargv))
                    {
                        unsigned long total = 0;
                        unsigned long total_argv = (unsigned long) ip_endargv - (unsigned long) ip_startargv;
                        char *command_line = (char *) OSMalloc((uint32_t) total_argv + 1, gmalloc_tag);

                    #if KAUTH_TROUBLESHOOTING
                        hex_printf((void *) ip_startargv, total_argv - 1, HEX_PRINTF_B);
                    #endif

                        if (command_line)
                        {
                            char *pointer = command_line;
                            unsigned int index = 0, ip_argc = image->ip_argc;

                            memset(command_line, 0, total_argv + 1);

                            for (index = 0; index < ip_argc; index++)
                            {
                                unsigned long local = strlen(ip_startargv); total += local;

                                if (total > total_argv)
                                {
                                    memset(command_line, 0, total_argv + 1);
                                    unsigned long error_length = strlen("Command line overflow!");

                                    if (total_argv > error_length)
                                        memcpy(command_line, "Command line overflow!", error_length);

                                    break;
                                }

                                memcpy(pointer, ip_startargv, local);

                                if (index + 1 < ip_argc) {command_line[total] = ' '; total += 1;}

                                ip_startargv += (local + 1); pointer += (local + 1);
                            }

                            struct file_operation_monitoring *command_line_message =
                            (struct file_operation_monitoring *) OSMalloc((uint32_t) (sizeof(struct file_operation_monitoring) + total_argv + 1),
                                                                          gmalloc_tag);

                            if (command_line_message)
                            {
                                char *command_line_offset = (char *) command_line_message + sizeof(struct file_operation_monitoring);

                                memset(command_line_message, 0, sizeof(struct file_operation_monitoring) + total_argv + 1);
                                memcpy(command_line_message, message, sizeof(struct file_operation_monitoring));

                                command_line_message->header.type = FILEOP_EXEC;
                                command_line_message->body.fileop_exec.command_line_length = total_argv + 1;

                                data_length = strlen((const char *) arg1);
                                memcpy(command_line_message->body.fileop_exec.path, (const char *) arg1,
                                       (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
                                memcpy(command_line_offset, command_line, total_argv + 1);

                                OSFree(message, (uint32_t) sizeof(struct file_operation_monitoring), gmalloc_tag);

                                message = command_line_message;

                                send_message((struct message_header *) message);
                            }
                            else
                            {
                                goto SKIP_COMMAND_LINE;
                            }

                            OSFree(command_line, (uint32_t) total_argv + 1, gmalloc_tag);
                        }
                        else
                        {
                            goto SKIP_COMMAND_LINE;
                        }
                    }
                }
                else
                {
                    goto SKIP_COMMAND_LINE;
                }
            }
            else
            {
            SKIP_COMMAND_LINE:

                message->header.type = FILEOP_EXEC;
                message->body.fileop_exec.command_line_length = 0;

                data_length = strlen((const char *) arg1);
                memcpy(message->body.fileop_exec.path, (const char *) arg1,
                       (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

                send_message((struct message_header *) message);
            }
        }
        break;

    case KAUTH_FILEOP_DELETE:
        if (!gprefix || (arg1 && gprefix && strprefix((const char *) arg1, gprefix)))
        {
            message->header.type = FILEOP_DELETE;

            data_length = strlen((const char *) arg1);
            memcpy(message->body.fileop_delete.path, (const char *) arg1,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

            send_message((struct message_header *) message);
        }
        break;

    //
    // vn_authorize_renamex_with_paths() -> kauth_authorize_fileop(..., KAUTH_FILEOP_WILL_RENAME, ...)
    //

    case KAUTH_FILEOP_WILL_RENAME:
        if (!gprefix ||
            (arg1 && gprefix && strprefix((const char *) arg1, gprefix)) ||
            (arg2 && gprefix && strprefix((const char *) arg2, gprefix)))
        {
            message->header.type = FILEOP_WILL_RENAME;

            data_length = strlen((const char *) arg1);
            memcpy(message->body.fileop_will_rename.from, (const char *) arg1,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);
            data_length = strlen((const char *) arg2);
            memcpy(message->body.fileop_will_rename.to, (const char *) arg2,
                   (data_length <= MAXPATHLEN - 1) ? data_length : MAXPATHLEN - 1);

            send_message((struct message_header *) message);
        }
        break;

    default:
    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : Unknown action! scope=KAUTH_SCOPE_FILEOP, action=%d.\n", DRIVER_NAME, action);
    #endif
        break;
    }

    if (message)
    {
        if (FILEOP_EXEC == message->header.type)
            OSFree(message, (uint32_t) (sizeof(struct file_operation_monitoring) +
                                        message->body.fileop_exec.command_line_length), gmalloc_tag);
        else
            OSFree(message, (uint32_t) sizeof(struct file_operation_monitoring), gmalloc_tag);
    }

    OSDecrementAtomic(&gactivation_count);

    return KAUTH_RESULT_DEFER;
}

//
// A Kauth listener that's called to authorize an action in any scope that we don't recognize.
// In this case, we just dump out the parameters to the operation and return KAUTH_RESULT_DEFER,
// allowing the other listeners to decide whether the operation is allowed or not.
//

static
int
listener_scope_unknown(
    kauth_cred_t credential,
    void *data,
    kauth_action_t action,
    uintptr_t arg0,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3
    )
{
#pragma unused(data)

    OSIncrementAtomic(&gactivation_count);

    int pid = proc_selfpid();
    char proc_name_pid[MAXPATHLEN] = {0};
    memset(proc_name_pid, 0, MAXPATHLEN);
    proc_name(pid, proc_name_pid, MAXPATHLEN);

    int ppid = proc_selfppid();
    char proc_name_ppid[MAXPATHLEN] = {0};
    memset(proc_name_ppid, 0, MAXPATHLEN);
    proc_name(ppid, proc_name_ppid, MAXPATHLEN);

    //
    // Tell the user about this request
    //

#if KAUTH_TROUBLESHOOTING
    printf("[%s.kext] : scope=%s, action=%d, uid=%ld, process(pid %d)=%s, parent(ppid %d)=%s, arg0=0x%lx, arg1=0x%lx, arg2=0x%lx, arg3=0x%lx.\n",
           DRIVER_NAME, glistener_scope, action, (long) kauth_cred_getuid(credential),
           pid, proc_name_pid, ppid, proc_name_ppid, (long) arg0, (long) arg1, (long) arg2, (long) arg3);
#endif

    OSDecrementAtomic(&gactivation_count);

    return KAUTH_RESULT_DEFER;
}

#pragma mark ***** Listener Install/Remove

//
// Removes the installed scope listener.
// Under almost all circumstances this routine runs under the gkauth_configuration_lock.
// The only time that this might not be the case is when the KEXT's start routine fails prior to gkauth_configuration_lock being created.
//

static
void
remove_listener(
    )
{
    //
    // First prevent any more threads entering our listener
    //

    if (glistener)
    {
        kauth_unlisten_scope(glistener);

        glistener = NULL;

        //
        // Then wait for any threads within our listener to stop
        //
        // Note that there is still a race condition here!
        // There could still be a thread executing between the OSDecrementAtomic and the return from the listener function
        // (for example, listener_scope_fileop). However, there's no way to close this race because of the weak concurrency
        // guarantee for kauth_unlisten_scope. Moreover, the window is very small and, seeing as this only happens during
        // reconfiguration. we always delay the teardown for at least one second waiting for the threads to drain from our listener.
        //

        do
        {
            struct timespec second = {0};

            second.tv_sec = 1;
            second.tv_nsec = 0;

            msleep(&gactivation_count, NULL, PUSER, "remove_listener", &second);
        } while (gactivation_count);
    }

    //
    // glistener_scope and gprefix are both accessed by the listener callbacks without taking any form of lock
    // So, we don't destroy them until after all the listener callbacks have drained
    //

    if (glistener_scope)
    {
        OSFree(glistener_scope, (uint32_t) (strlen(glistener_scope) + 1), gmalloc_tag);

        glistener_scope = NULL;
    }

    //
    // Cleanup
    //

    gprefix = NULL;
}

//
// Installs a listener for the specified scope.
// This routine always runs under the gkauth_configuration_lock.
//

static
void
install_listener(
    const char *scope,
    size_t scope_length,
    const char *prefix
    )
{
    kauth_scope_callback_t kauth_callback = NULL;

    assert (scope);
    assert ((0 < scope_length) && (max_string_length >= scope_length));

    //
    // Allocate memory for the scope string
    //

    assert (!glistener_scope);

    glistener_scope = (char *) OSMalloc((uint32_t) scope_length + 1, gmalloc_tag);

    if (glistener_scope)
    {
        memcpy(glistener_scope, scope, scope_length);

        glistener_scope[scope_length] = 0;

        //
        // Copy the local prefix pointer over to gprefix
        //

        assert (!gprefix);

        gprefix = prefix;

        //
        // Register the appropriate listener with Kauth
        //

        if (!strcmp(glistener_scope, KAUTH_SCOPE_GENERIC))
        {
            kauth_callback = listener_scope_generic;
        }
        else if (!strcmp(glistener_scope, KAUTH_SCOPE_PROCESS))
        {
            kauth_callback = listener_scope_process;
        }
        else if (!strcmp(glistener_scope, KAUTH_SCOPE_VNODE))
        {
            kauth_callback = listener_scope_vnode;
        }
        else if (!strcmp(glistener_scope, KAUTH_SCOPE_FILEOP))
        {
            kauth_callback = listener_scope_fileop;
        }
        else
        {
            kauth_callback = listener_scope_unknown;
        }

        assert (!glistener);

        glistener = kauth_listen_scope(glistener_scope, kauth_callback, NULL);

        if (!glistener)
        {
        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : Error! Could not create glistener.\n", DRIVER_NAME);
        #endif
        }
    }
#if KAUTH_TROUBLESHOOTING
    else
    {
        printf("[%s.kext] : Error! Could not allocate glistener_scope.\n", DRIVER_NAME);
    }
#endif

    //
    // In the event of any failure, call remove_listener which will do all the right cleanup
    //

    if (!glistener_scope || !glistener)
    {
        remove_listener();
    }
}

//
// This routine is called by the sysctl handler when it notices that the configuration has changed.
// It's responsible for parsing the new configuration string and updating the listener.
// This routine always runs under the gkauth_configuration_lock.
//

static
void
configure_kauth(
    const char *configuration_string
    )
{
    assert (configuration_string);

    if (!strcmp(configuration_string, "remove"))
    {
        //
        // Remove the existing listener
        //

        remove_listener();

    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : removed listener.\n", DRIVER_NAME);
    #endif
    }
    else if (strprefix(configuration_string, "add "))
    {
        //
        // Skip the "add " prefix
        //

        const char *cursor = configuration_string + strlen("add ");

        //
        // Work out the span of the scope
        //

        const char *scope = cursor;

        while ((*cursor) && (' ' != *cursor)) cursor += 1;

        assert (cursor >= scope);

        size_t scope_length = (size_t) (cursor - scope);

        if ((!scope_length) || (max_string_length < scope_length))
        {
        #if KAUTH_TROUBLESHOOTING
            printf("[%s.kext] : Error! Bad configuration - scope '%s'.\n", DRIVER_NAME, configuration_string);
        #endif
        }
        else
        {
            const char *prefix = NULL;

            //
            // Look for a path prefix
            //

            while (' ' == *cursor) cursor += 1;

            if (*cursor) prefix = cursor;
            else prefix = NULL;

            //
            // Tell the user what we're doing
            //

        #if KAUTH_TROUBLESHOOTING
            if (prefix)
                printf("[%s.kext] : scope=%s, prefix=%s.\n", DRIVER_NAME, scope, prefix);
            else
                printf("[%s.kext] : scope=%s.\n", DRIVER_NAME, scope);
        #endif

            remove_listener();

            install_listener(scope, scope_length, prefix);
        }
    }
    else
    {
    #if KAUTH_TROUBLESHOOTING
        printf("[%s.kext] : Error! Bad configuration '%s'.\n", DRIVER_NAME, configuration_string);
    #endif
    }
}

//
// This routine is called by the kernel when the user reads or writes our sysctl variable.
//

static
int
sysctl_handler(
    struct sysctl_oid *oid,
    void *arg1,
    int arg2,
    struct sysctl_req *req
    )
{
    if (!gkauth_configuration_lock) return EPERM;

    //
    // Prevent two threads trying to change our configuration at the same time
    //

    lck_mtx_lock(gkauth_configuration_lock);

    //
    // Copy data from user mode to gconfiguration
    //

    int status = sysctl_handle_string(oid, arg1, arg2, req);

    if (!status && req->newptr) configure_kauth(gconfiguration);

    lck_mtx_unlock(gkauth_configuration_lock);

    return status;
}

//
// Declare our sysctl OID
//
// That is a variable that the user can get and set using sysctl.
// Once this OID is registered, user can get and set our configuration variable using the sysctl command line tool.
// We use SYSCTL_OID rather than SYSCTL_STRING because we want to override the handler function.
//
// For example: sudo sysctl -w kern.kemon="add com.apple.kauth.fileop"
//

SYSCTL_OID(
    _kern,                                      // parent OID
    OID_AUTO,                                   // sysctl number, OID_AUTO means we're only accessible by name
    kemon,                                      // our name
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_KERN, // we're a string
    gconfiguration,                             // sysctl_handle_string gets/sets this string
    sizeof(gconfiguration),                     // maximum length
    sysctl_handler,                             // handler
    "A",                                        // because that's what SYSCTL_STRING does
    ""                                          // just a comment
    );

static
kern_return_t
kemon_initialization(
    boolean_t flag
    )
{
    kern_return_t status = KERN_SUCCESS;

    if (flag)
    {
        //
        // Register the sysctl handler
        //

        sysctl_register_oid(&sysctl__kern_kemon);

        OSCompareAndSwap(0, 1, &goid_registered);

        //
        // Register the communication handler
        //

        status = nke_initialization(TRUE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! nke_initialization(true) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        //
        // Register the network filter handler
        //

        status = sflt_initialization(TRUE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! sflt_initialization(true) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        //
        // Register the MAC policy callback handler
        //

        status = mac_initialization(TRUE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! mac_initialization(true) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        //
        // Register the inline hook handlers
        //

        status = inline_initialization(TRUE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! inline_initialization(true) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }
    }
    else
    {
        //
        // Unregister handlers
        //

        status = inline_initialization(FALSE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! inline_initialization(false) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        status = mac_initialization(FALSE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! mac_initialization(false) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        status = sflt_initialization(FALSE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! sflt_initialization(false) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        //
        // Use-After-Free:
        // sodisconnectlocked - (*so->so_proto->pr_usrreqs->pru_disconnect)(so);
        //

        status = nke_initialization(FALSE);

        if (KERN_SUCCESS != status)
        {
        #if FRAMEWORK_TROUBLESHOOTING
            printf("[%s.kext] : Error! nke_initialization(false) failed, status=%d.\n", DRIVER_NAME, status);
        #endif

            return status;
        }

        //
        // Unregister the sysctl handler
        //

        if (OSCompareAndSwap(1, 0, &goid_registered))
        {
            sysctl_unregister_oid(&sysctl__kern_kemon);
        }
    }

    return status;
}

static
boolean_t
search_oskext_start(
    )
{
    boolean_t found = FALSE;

    if (!goskext_start || !goskext_call_func)
        return found;

    //
    // Header signatures of the OSKext::start()
    //

    for (unsigned int index = 0; index < 0x500; index++)
    {
        //
        // 1. kernel.development`OSKext::start:
        //    0xffffff800c0013c0 <+0>:    55            pushq  %rbp
        //    0xffffff800c0013c1 <+1>:    48 89 e5      movq   %rsp, %rbp
        //    0xffffff800c0013c4 <+4>:    41 57         pushq  %r15
        //    0xffffff800c0013c6 <+6>:    41 56         pushq  %r14
        //    0xffffff800c0013c8 <+8>:    41 55         pushq  %r13
        //    ..................
        //

        if (0xe5894855 == *(unsigned int *) (goskext_start - index) &&
            0x56415741 == *(unsigned int *) (goskext_start - index + sizeof(int32_t)) &&
            0x5541 == *(unsigned short *) (goskext_start - index + sizeof(int32_t) * 2))
        {
            goskext_start -= index;

            found = TRUE; break;
        }

        //
        // Anything else?
        //
    }

    return found;
}

static
boolean_t
check_os_version(
    int *major,
    int *minor,
    const char *string
    )
{
    boolean_t status = FALSE;

    string = version;
    *major = version_major;
    *minor = version_minor;

    switch (*major)
    {
    case OS_X_LION:
        printf("[%s.kext] : kernel version=%d.%d - OS X Lion, %s.\n", DRIVER_NAME, *major, *minor, string);

        break;

    case OS_X_MOUNTAIN_LION:
        printf("[%s.kext] : kernel version=%d.%d - OS X Mountain Lion, %s.\n", DRIVER_NAME, *major, *minor, string);

        break;

    case OS_X_MAVERICKS:
        printf("[%s.kext] : kernel version=%d.%d - OS X Mavericks, %s.\n", DRIVER_NAME, *major, *minor, string);

        break;

    case OS_X_YOSEMITE:
        printf("[%s.kext] : kernel version=%d.%d - OS X Yosemite, %s.\n", DRIVER_NAME, *major, *minor, string);

        break;

    case OS_X_EL_CAPITAN:
        printf("[%s.kext] : kernel version=%d.%d - OS X El Capitan, %s.\n", DRIVER_NAME, *major, *minor, string);

        status = TRUE; break;

    case MACOS_SIERRA:
        printf("[%s.kext] : kernel version=%d.%d - macOS Sierra, %s.\n", DRIVER_NAME, *major, *minor, string);

        status = TRUE; break;

    case MACOS_HIGH_SIERRA:
        printf("[%s.kext] : kernel version=%d.%d - macOS High Sierra, %s.\n", DRIVER_NAME, *major, *minor, string);

        status = TRUE; break;

    case MACOS_MOJAVE:
        printf("[%s.kext] : kernel version=%d.%d - macOS Mojave, %s.\n", DRIVER_NAME, *major, *minor, string);

        status = TRUE; break;

    default:
        printf("[%s.kext] : kernel version=%d.%d - Unknown version! %s.\n", DRIVER_NAME, *major, *minor, string);

        break;
    }

    return status;
}

#pragma mark ***** Start/Stop

extern
kern_return_t
kemon_start(
    kmod_info_t *kmod_info,
    void *data
    )
{
#pragma unused(data)

    kern_return_t status = KERN_SUCCESS;

    //
    // Check OS version
    //

    if (!check_os_version(&gmacOS_major, &gmacOS_minor, gmacOS_version))
    {
        return KERN_FAILURE;
    }
#if FRAMEWORK_TROUBLESHOOTING
    else
    {
        printf("[%s.kext] : kernel module was started, version=0x%x.\n", DRIVER_NAME, CURRENT_VERSION);
    }

    //
    // Dump the kernel module list
    //

    kmod_info_t *kmod_item = gkmod_item = kmod_info;

    do
    {
        printf("[%s.kext] : module name=%s, module version=%s, module base=0x%lx, module size=0x%lx, module start=%p, module stop=%p.\n",
               DRIVER_NAME, kmod_item->name, kmod_item->version, kmod_item->address, kmod_item->size, kmod_item->start, kmod_item->stop);

        kmod_item = kmod_item->next;
    } while (kmod_item);
#endif

    //
    // Locate the OSKext::start()
    //

    unsigned long rbp_register = 0;

    __asm__ volatile ("mov %%rbp, %0" : "=r" (rbp_register));

    goskext_start = goskext_call_func = (unsigned char *) (*(unsigned long *) (rbp_register + sizeof(void *)));

    if (search_oskext_start())
    {
        //
        // 1. kernel.development`OSKext::start:
        //    ..................
        //    0xffffff80093c2b14 <+1108>: ff d3   callq   *%rbx   /   ff d1   callq   *%rcx
        //    0xffffff80093c2b16 <+1110>: 89 c3   movl    %eax, %ebx
        //    0xffffff80093c2b18 <+1112>: 85 db   testl   %ebx, %ebx
        //    ..................
        //

        if (0xff == *(goskext_call_func - 2) &&
            0xd0 <= *(goskext_call_func - 1) && 0xd7 >= *(goskext_call_func - 1) &&
            0xc389 == *(unsigned short *) (goskext_call_func - 2 + sizeof(int16_t) * 1) &&
            0xdb85 == *(unsigned short *) (goskext_call_func - 2 + sizeof(int16_t) * 2))
        {
            goskext_call_func_2_bytes = TRUE;
        }

        //
        // 2. kernel.development`OSKext::start:
        //    ..................
        //    0xffffff801a8003c8 <+1144>: ff 55 b0   callq   *-0x50(%rbp)
        //    0xffffff801a8003cb <+1147>: 89 c3      movl    %eax, %ebx
        //    0xffffff801a8003cd <+1149>: 85 db      testl   %ebx, %ebx
        //    ..................
        //

        else if (0x55ff == *(unsigned short *) (goskext_call_func - 3) &&
                 0xc389 == *(unsigned short *) (goskext_call_func + sizeof(int16_t) * 0) &&
                 0xdb85 == *(unsigned short *) (goskext_call_func + sizeof(int16_t) * 1))
        {
            goskext_call_func_3_bytes = TRUE;
        }

        //
        // 3. kernel.development`OSKext::start:
        //    ..................
        //    0xffffff800c575fc4 <+548>: ff 55 c8    callq  *-0x38(%rbp)
        //    0xffffff800c575fc7 <+551>: 41 89 c6    movl   %eax, %r14d
        //    ..................
        //

        else if (0x55ff == *(unsigned short *) (goskext_call_func - 3) &&
                 0x8941 == *(unsigned short *) (goskext_call_func) &&
                 0xc0 <= *(goskext_call_func + sizeof(int16_t)) && 0xc7 >= *(goskext_call_func + sizeof(int16_t)))
        {
            goskext_call_func_3_bytes = TRUE;
        }

        //
        // Anything else?
        //

        else
        {
            goskext_start = goskext_call_func = NULL;
        }
    }
    else
    {
        goskext_start = goskext_call_func = NULL;
    }

    //
    // Allocate global resources
    //

    gmalloc_tag = OSMalloc_Tagalloc(DRIVER_TAG_NAME, OSMT_DEFAULT);

    if (!gmalloc_tag)
    {
        return KERN_NO_SPACE;
    }

    glock_group = lck_grp_alloc_init(DRIVER_TAG_NAME, LCK_GRP_ATTR_NULL);

    if (!glock_group)
    {
        status = KERN_NO_SPACE;
    }

    if (KERN_SUCCESS == status)
    {
        gmac_policy_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
        gnke_event_log_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
        goskext_handler_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
        gnetwork_filter_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
        gkauth_configuration_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);

        if (gmac_policy_lock && gnke_event_log_lock &&
            goskext_handler_lock && gnetwork_filter_lock && gkauth_configuration_lock)
        {
        #if KAUTH_DEFAULT_SETTING
            lck_mtx_lock(gkauth_configuration_lock);

            memset(gconfiguration, 0, sizeof(gconfiguration));
            memcpy(gconfiguration, DEFAULT_SETTING, strlen(DEFAULT_SETTING));

            configure_kauth(gconfiguration);

            lck_mtx_unlock(gkauth_configuration_lock);
        #endif

            status = kemon_initialization(TRUE);
        }
        else
        {
            status = KERN_FAILURE;
        }
    }

    //
    // Cleanup
    //

    if (KERN_SUCCESS != status)
    {
        kemon_stop(kmod_info, data);
    }

    return status;
}

extern
kern_return_t
kemon_stop(
    kmod_info_t *kmod_info,
    void *data
    )
{
#pragma unused(kmod_info)
#pragma unused(data)

    kern_return_t status = kemon_initialization(FALSE);

    if (KERN_SUCCESS != status) return status;

    //
    // Shut down the scope listen
    //

    if (gkauth_configuration_lock)
    {
        lck_mtx_lock(gkauth_configuration_lock);

        remove_listener();

        lck_mtx_unlock(gkauth_configuration_lock);

        //
        // Cleanup the Kauth configuration lock
        //

        if (glock_group)
        {
            lck_mtx_free(gkauth_configuration_lock, glock_group);

            gkauth_configuration_lock = NULL;
        }
    }

    //
    // Cleanup the socket filter lock
    //

    if (gnetwork_filter_lock)
    {
        if (glock_group)
        {
            lck_mtx_free(gnetwork_filter_lock, glock_group);

            gnetwork_filter_lock = NULL;
        }
    }

    //
    // Cleanup the OSKext::start() handler lock
    //

    if (goskext_handler_lock)
    {
        if (glock_group)
        {
            lck_mtx_free(goskext_handler_lock, glock_group);

            goskext_handler_lock = NULL;
        }
    }

    //
    // Cleanup the event log lock
    //

    if (gnke_event_log_lock)
    {
        if (glock_group)
        {
            lck_mtx_free(gnke_event_log_lock, glock_group);

            gnke_event_log_lock = NULL;
        }
    }

    //
    // Cleanup the MAC policy lock
    //

    if (gmac_policy_lock)
    {
        if (glock_group)
        {
            lck_mtx_free(gmac_policy_lock, glock_group);

            gmac_policy_lock = NULL;
        }
    }

    //
    // Free global resources
    //

    if (glock_group)
    {
        lck_grp_free(glock_group);

        glock_group = NULL;
    }

    if (gmalloc_tag)
    {
        OSMalloc_Tagfree(gmalloc_tag);

        gmalloc_tag = NULL;
    }

#if FRAMEWORK_TROUBLESHOOTING
    printf("[%s.kext] : kernel module was stopped, version=0x%x.\n", DRIVER_NAME, CURRENT_VERSION);
#endif

    return KERN_SUCCESS;
}