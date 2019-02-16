/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    policy.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include "distorm/include/distorm.h"
#include "include.h"
#include "nke.h"
#include "trace.h"
#include "policy.h"


//
// MAC policy
//

struct mac_policy_ops mac_ops;
struct mac_policy_conf mac_mpc;

static mac_policy_handle_t mac_handle;

//
// MAC policy Shadow Walker (SW)
//

#if MAC_POLICY_SHADOW_WALKER
#   define SW_NAME "Shadow Walker"
#   define SW_FULL_NAME "Kemon Shadow Walker"

struct mac_policy_ops sw_ops;
struct mac_policy_conf sw_mpc;

static mac_policy_handle_t sw_handle;

//
// Copied from the mac_internal.h
//

struct mac_policy_list_element {
    struct mac_policy_conf *mpc;
};

struct mac_policy_list {
    u_int numloaded;
    u_int max;
    u_int maxindex;
    u_int staticmax;
    u_int chunks;
    u_int freehint;
    struct mac_policy_list_element *entries;
};

struct mac_policy_list *policy_list;

//
// Shadow Walker (SW) policy list
//

struct shadow_walker_list {
    u_int index;
    u_int loaded;
    struct mac_policy_conf *mpc;
    char local_name[MAXPATHLEN];
    char local_fullname[MAXPATHLEN];
    struct mac_policy_ops local_ops;
    struct mac_policy_conf local_mpc;
    struct shadow_walker_list *next;
};

struct shadow_walker_list *sw_list;

//
// Shadow Walker (SW) policy mutex lock
//

static lck_mtx_t *sw_lock;

static
struct mac_policy_list *
search_mac_policy_list(
    unsigned char *policy_register
    )
{
    if (!policy_register)
        return NULL;

    //
    // Holds the result of the decoding
    //

    _DecodeResult result;

    //
    // Decoded instruction information
    //

    _DecodedInst decoded_instructions[MAX_INSTRUCTIONS];

    //
    // Holds the count of filled instructions' array by the decoder
    //

    unsigned int index, next, decoded_instructions_count;

    //
    // Default decoding mode is 64 bits
    //

    _DecodeType decode_type = Decode64Bits;

    //
    // Buffer to disassemble
    //

    unsigned char *buffer = policy_register;

    //
    // Default offset for buffer is 0
    //

    _OffsetType offset = (_OffsetType) buffer;

    int length = 0x200;

    struct mac_policy_list *target_routine = NULL;

#if MAC_TROUBLESHOOTING
    printf("[%s.kext] : Disassemble the mac_policy_register().\n",
           DRIVER_NAME);
#endif

    while (1) {
        result = distorm_decode64(offset,
                                  (const unsigned char *) buffer,
                                  length,
                                  decode_type,
                                  decoded_instructions,
                                  MAX_INSTRUCTIONS,
                                  &decoded_instructions_count);
        if (DECRES_INPUTERR == result) {
        #if MAC_TROUBLESHOOTING
            printf("[%s.kext] : Error! Could not disassemble the mac_policy_register().\n",
                   DRIVER_NAME);
        #endif

            break;
        }

        for (index = 0; index < decoded_instructions_count; index++) {
        #if MAC_TROUBLESHOOTING
            printf("               (%02d) %s %s %s\n",
                   decoded_instructions[index].size,
                   (char *) decoded_instructions[index].instructionHex.p,
                   (char *) decoded_instructions[index].mnemonic.p,
                   (char *) decoded_instructions[index].operands.p);
        #endif

            //
            // Case 1. (\security\mac_base.c):
            //
            // /*
            //  * Policy list array allocation chunk size.
            //  * Trying to set this so that we allocate a page at a time.
            //  */
            //
            // #define MAC_POLICY_LIST_CHUNKSIZE 512
            //
            // mac_policy_list.max += MAC_POLICY_LIST_CHUNKSIZE;
            // mac_policy_list.chunks++;
            //

            //
            // (lldb) di -b -n mac_policy_register
            //     ..................
            //     0xffffff800ceea221 <+337>:  81 05 21 d7 26 00 00 02 00 00    addl   $0x200, 0x26d721(%rip)   ; mac_policy_list, imm = 0x200
            //     0xffffff800ceea22b <+347>:  ff 05 27 d7 26 00                incl   0x26d727(%rip)           ; mac_policy_list + 16
            //     ..................
            //

            if (0x0a == decoded_instructions[index].size &&
                !strncmp("8105",
                         (char *) decoded_instructions[index].instructionHex.p,
                         4) &&
                !strncmp("00020000", // MAC_POLICY_LIST_CHUNKSIZE
                         (char *) decoded_instructions[index].instructionHex.p + 0x0c,
                         8)) {
                unsigned int delta = *(unsigned int *) ((unsigned char *)
                                         decoded_instructions[index].offset + 0x02);
                if (delta & 0x80000000) {
                    delta = (0x0 - delta) & 0xffffffff;

                    target_routine = (struct mac_policy_list *) ((unsigned char *)
                                         decoded_instructions[index].offset +
                                         decoded_instructions[index].size -
                                         delta - sizeof(u_int)); // mac_policy_list.max
                } else {
                    target_routine = (struct mac_policy_list *) ((unsigned char *)
                                         decoded_instructions[index].offset +
                                         decoded_instructions[index].size +
                                         delta - sizeof(u_int)); // mac_policy_list.max
                }

                //
                // !mac_late mode
                //

                if (!target_routine || !mac_handle ||
                    &mac_mpc != target_routine->entries[mac_handle].mpc ||
                    !sw_handle ||
                    &sw_mpc != target_routine->entries[sw_handle].mpc) {
                    target_routine = NULL;
                }

                decoded_instructions_count = 0;
                break;
            }

            //
            // Anything else?
            //
        }

        //
        // All instructions were decoded
        //

        if (DECRES_SUCCESS == result || !decoded_instructions_count)
            break;

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

    return target_routine;
}

static
void
sw_policy_init_handler(
    struct mac_policy_conf *mpc
    )
{
#pragma unused(mpc)

    //
    // We have already held the mac_policy_grab_exclusive/mac_policy_mtx lock
    //

    policy_list = search_mac_policy_list(
                      (unsigned char *) mac_policy_register);
    if (policy_list) {
        size_t name_length;
        struct shadow_walker_list *entry;
        int index = 0, loaded = policy_list->numloaded;

        lck_mtx_lock(sw_lock);

        //
        // Cleanup
        //

        while (sw_list) {
            entry = sw_list;
            sw_list = sw_list->next;

            OSFree(entry, sizeof(*entry),
                   gmalloc_tag);
        }

        while (index < loaded) {
            if (!policy_list->entries[index].mpc)
                continue;

            entry = OSMalloc(sizeof(*entry),
                             gmalloc_tag);
            if (entry) {
                memset(entry, 0, sizeof(*entry));

                entry->index = index;
                entry->loaded = loaded;
                entry->mpc = policy_list->entries[index].mpc;

                name_length = strlen(policy_list->entries[index].mpc->mpc_name);
                memcpy(entry->local_name,
                       policy_list->entries[index].mpc->mpc_name,
                       (name_length <= MAXPATHLEN - 1) ?
                       name_length : MAXPATHLEN - 1);

                name_length = strlen(policy_list->entries[index].mpc->mpc_fullname);
                memcpy(entry->local_fullname,
                       policy_list->entries[index].mpc->mpc_fullname,
                       (name_length <= MAXPATHLEN - 1) ?
                       name_length : MAXPATHLEN - 1);

                memcpy(&entry->local_ops,
                       policy_list->entries[index].mpc->mpc_ops,
                       sizeof(struct mac_policy_ops));
                memcpy(&entry->local_mpc,
                       policy_list->entries[index].mpc,
                       sizeof(struct mac_policy_conf));

                if (sw_list) {
                    struct shadow_walker_list *next = sw_list;

                    while (next->next)
                        next = next->next;

                    next->next = entry;
                } else {
                    sw_list = entry;
                }
            }

            index++;
        }

        lck_mtx_unlock(sw_lock);
    }
}

static
void
sw_policy_initbsd_handler(
    struct mac_policy_conf *mpc
    )
{
#pragma unused(mpc)

    //
    // Dummy
    //

    return;
}

static
void
sw_policy_destroy_handler(
    struct mac_policy_conf *mpc
    )
{
#pragma unused(mpc)

    //
    // Dummy
    //

    return;
}

static
void
dump_mac_policy(
    )
{
    int error;

    memset(&sw_ops, 0, sizeof(struct mac_policy_ops));
    memset(&sw_mpc, 0, sizeof(struct mac_policy_conf));

    //
    // Dump all the MAC policy handlers of macOS system
    // We can also de-register or subvert any policy handler
    //

    sw_ops.mpo_policy_init = sw_policy_init_handler;
    sw_ops.mpo_policy_initbsd = sw_policy_initbsd_handler;
    sw_ops.mpo_policy_destroy = sw_policy_destroy_handler;

    sw_mpc.mpc_ops = &sw_ops;
    sw_mpc.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK;
    sw_mpc.mpc_fullname = SW_FULL_NAME;
    sw_mpc.mpc_name = SW_NAME;

    //
    // In the mac_late mode
    //

    error = mac_policy_register(&sw_mpc, &sw_handle, NULL);
    if (!error && sw_handle) {
        mac_policy_unregister(sw_handle);
    }
}

#if MAC_TROUBLESHOOTING
extern
const char *
get_loadtime_option(
    int flags
    )
{
    char *option;

    switch (flags) {
    case 0x00:
        option = "NULL";
        break;

    case 0x01:
        option = "MPC_LOADTIME_FLAG_NOTLATE";
        break;

    case 0x02:
        option = "MPC_LOADTIME_FLAG_UNLOADOK";
        break;

    case 0x03:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_FLAG_UNLOADOK";
        break;

    case 0x04:
        option = "MPC_LOADTIME_FLAG_LABELMBUFS";
        break;

    case 0x05:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_FLAG_LABELMBUFS";
        break;

    case 0x06:
        option = "MPC_LOADTIME_FLAG_UNLOADOK | MPC_LOADTIME_FLAG_LABELMBUFS";
        break;

    case 0x07:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_FLAG_UNLOADOK | MPC_LOADTIME_FLAG_LABELMBUFS";
        break;

    case 0x08:
        option = "MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x09:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x0A:
        option = "MPC_LOADTIME_FLAG_UNLOADOK | MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x0B:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_FLAG_UNLOADOK | MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x0C:
        option = "MPC_LOADTIME_FLAG_LABELMBUFS | MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x0D:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_FLAG_LABELMBUFS | MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x0E:
        option = "MPC_LOADTIME_FLAG_UNLOADOK | MPC_LOADTIME_FLAG_LABELMBUFS | MPC_LOADTIME_BASE_POLICY";
        break;

    case 0x0F:
        option = "MPC_LOADTIME_FLAG_NOTLATE | MPC_LOADTIME_FLAG_UNLOADOK | MPC_LOADTIME_FLAG_LABELMBUFS | MPC_LOADTIME_BASE_POLICY";
        break;

    default:
        option = "UNKNOWN OPTION";
        break;
    }

    return option;
}

static
boolean_t
get_module_info(
    void *address,
    char **module_name,
    vm_address_t *module_base,
    vm_size_t *module_size
    )
{
    *module_name = NULL;
    *module_base = *module_size = 0;

    if (gkmod_info) {
        kmod_info_t *kmod_item = gkmod_info;

        //
        // Direct Kernel Object Manipulation (DKOM) is not a good idea
        //

        do {
            if ((vm_address_t) address > kmod_item->address &&
                (vm_address_t) address < kmod_item->address +
                                         kmod_item->size) {
                *module_name = kmod_item->name;
                *module_base = kmod_item->address;
                *module_size = kmod_item->size;

                return TRUE;
            }

            kmod_item = kmod_item->next;
        } while (kmod_item);
    }

    return FALSE;
}

static
void
get_handler_info(
    void *address,
    const char *name
    )
{
    if (address) {
        char *module_name;
        vm_address_t module_base;
        vm_size_t module_size;

        //
        // Get kext module information
        //

        char info_buffer[0x100];
        unsigned long info_length;

        info_length = sizeof(info_buffer);
        memset(info_buffer, 0, info_length);

        if (get_module_info(address, &module_name,
                            &module_base, &module_size)) {
            vm_address_t delta = (vm_address_t) address - module_base;

            snprintf(info_buffer, info_length,
                     "[%s.kext] :       handler address: %p, module offset: %s+0x%lX, policy name: %s.\n",
                     DRIVER_NAME, address,
                     module_name, delta, name);
            printf("%s", info_buffer);
        } else {
            if (goskext_handler_lock) {
                lck_mtx_lock(goskext_handler_lock);

                if (gkext_name && gkext_base && gkext_size) {
                    if ((vm_address_t) address > gkext_base &&
                        (vm_address_t) address < gkext_base + gkext_size) {
                        vm_address_t delta = (vm_address_t) address - gkext_base;

                        snprintf(info_buffer, info_length,
                                 "[%s.kext] :       handler address: %p, module offset: %s+0x%lX, policy name: %s.\n",
                                 DRIVER_NAME, address,
                                 gkext_name, delta, name);
                        printf("%s", info_buffer);
                    } else {
                        snprintf(info_buffer, info_length,
                                 "[%s.kext] :       handler address: %p, policy name: %s.\n",
                                 DRIVER_NAME, address,
                                 name);
                        printf("%s", info_buffer);
                    }
                } else {
                    snprintf(info_buffer, info_length,
                             "[%s.kext] :       handler address: %p, policy name: %s.\n",
                             DRIVER_NAME, address,
                             name);
                    printf("%s", info_buffer);
                }

                lck_mtx_unlock(goskext_handler_lock);
            } else {
                snprintf(info_buffer, info_length,
                         "[%s.kext] :       handler address: %p, policy name: %s.\n",
                         DRIVER_NAME, address,
                         name);
                printf("%s", info_buffer);
            }
        }
    }
}

extern
void
show_mac_policy_handlers(
    struct mac_policy_ops *ops
    )
{
    //
    // mpo_audit
    //

    get_handler_info(ops->mpo_audit_check_postselect,
                     "mpo_audit_check_postselect");
    get_handler_info(ops->mpo_audit_check_preselect,
                     "mpo_audit_check_preselect");

    //
    // mpo_bpfdesc
    //

    get_handler_info(ops->mpo_bpfdesc_label_associate,
                     "mpo_bpfdesc_label_associate");
    get_handler_info(ops->mpo_bpfdesc_label_destroy,
                     "mpo_bpfdesc_label_destroy");
    get_handler_info(ops->mpo_bpfdesc_label_init,
                     "mpo_bpfdesc_label_init");
    get_handler_info(ops->mpo_bpfdesc_check_receive,
                     "mpo_bpfdesc_check_receive");

    //
    // mpo_cred
    //

    get_handler_info(ops->mpo_cred_check_label_update_execve,
                     "mpo_cred_check_label_update_execve");
    get_handler_info(ops->mpo_cred_check_label_update,
                     "mpo_cred_check_label_update");
    get_handler_info(ops->mpo_cred_check_visible,
                     "mpo_cred_check_visible");
    get_handler_info(ops->mpo_cred_label_associate_fork,
                     "mpo_cred_label_associate_fork");
    get_handler_info(ops->mpo_cred_label_associate_kernel,
                     "mpo_cred_label_associate_kernel");
    get_handler_info(ops->mpo_cred_label_associate,
                     "mpo_cred_label_associate");
    get_handler_info(ops->mpo_cred_label_associate_user,
                     "mpo_cred_label_associate_user");
    get_handler_info(ops->mpo_cred_label_destroy,
                     "mpo_cred_label_destroy");
    get_handler_info(ops->mpo_cred_label_externalize_audit,
                     "mpo_cred_label_externalize_audit");
    get_handler_info(ops->mpo_cred_label_externalize,
                     "mpo_cred_label_externalize");
    get_handler_info(ops->mpo_cred_label_init,
                     "mpo_cred_label_init");
    get_handler_info(ops->mpo_cred_label_internalize,
                     "mpo_cred_label_internalize");
    get_handler_info(ops->mpo_cred_label_update_execve,
                     "mpo_cred_label_update_execve");
    get_handler_info(ops->mpo_cred_label_update,
                     "mpo_cred_label_update");

    //
    // mpo_devfs
    //

    get_handler_info(ops->mpo_devfs_label_associate_device,
                     "mpo_devfs_label_associate_device");
    get_handler_info(ops->mpo_devfs_label_associate_directory,
                     "mpo_devfs_label_associate_directory");
    get_handler_info(ops->mpo_devfs_label_copy,
                     "mpo_devfs_label_copy");
    get_handler_info(ops->mpo_devfs_label_destroy,
                     "mpo_devfs_label_destroy");
    get_handler_info(ops->mpo_devfs_label_init,
                     "mpo_devfs_label_init");
    get_handler_info(ops->mpo_devfs_label_update,
                     "mpo_devfs_label_update");

    //
    // mpo_file
    //

    get_handler_info(ops->mpo_file_check_change_offset,
                     "mpo_file_check_change_offset");
    get_handler_info(ops->mpo_file_check_create,
                     "mpo_file_check_create");
    get_handler_info(ops->mpo_file_check_dup,
                     "mpo_file_check_dup");
    get_handler_info(ops->mpo_file_check_fcntl,
                     "mpo_file_check_fcntl");
    get_handler_info(ops->mpo_file_check_get_offset,
                     "mpo_file_check_get_offset");
    get_handler_info(ops->mpo_file_check_get,
                     "mpo_file_check_get");
    get_handler_info(ops->mpo_file_check_inherit,
                     "mpo_file_check_inherit");
    get_handler_info(ops->mpo_file_check_ioctl,
                     "mpo_file_check_ioctl");
    get_handler_info(ops->mpo_file_check_lock,
                     "mpo_file_check_lock");
    get_handler_info(ops->mpo_file_check_mmap_downgrade,
                     "mpo_file_check_mmap_downgrade");
    get_handler_info(ops->mpo_file_check_mmap,
                     "mpo_file_check_mmap");
    get_handler_info(ops->mpo_file_check_receive,
                     "mpo_file_check_receive");
    get_handler_info(ops->mpo_file_check_set,
                     "mpo_file_check_set");
    get_handler_info(ops->mpo_file_label_init,
                     "mpo_file_label_init");
    get_handler_info(ops->mpo_file_label_destroy,
                     "mpo_file_label_destroy");
    get_handler_info(ops->mpo_file_label_associate,
                     "mpo_file_label_associate");

    //
    // mpo_ifnet
    //

    get_handler_info(ops->mpo_ifnet_check_label_update,
                     "mpo_ifnet_check_label_update");
    get_handler_info(ops->mpo_ifnet_check_transmit,
                     "mpo_ifnet_check_transmit");
    get_handler_info(ops->mpo_ifnet_label_associate,
                     "mpo_ifnet_label_associate");
    get_handler_info(ops->mpo_ifnet_label_copy,
                     "mpo_ifnet_label_copy");
    get_handler_info(ops->mpo_ifnet_label_destroy,
                     "mpo_ifnet_label_destroy");
    get_handler_info(ops->mpo_ifnet_label_externalize,
                     "mpo_ifnet_label_externalize");
    get_handler_info(ops->mpo_ifnet_label_init,
                     "mpo_ifnet_label_init");
    get_handler_info(ops->mpo_ifnet_label_internalize,
                     "mpo_ifnet_label_internalize");
    get_handler_info(ops->mpo_ifnet_label_update,
                     "mpo_ifnet_label_update");
    get_handler_info(ops->mpo_ifnet_label_recycle,
                     "mpo_ifnet_label_recycle");

    //
    // mpo_inpcb
    //

    get_handler_info(ops->mpo_inpcb_check_deliver,
                     "mpo_inpcb_check_deliver");
    get_handler_info(ops->mpo_inpcb_label_associate,
                     "mpo_inpcb_label_associate");
    get_handler_info(ops->mpo_inpcb_label_destroy,
                     "mpo_inpcb_label_destroy");
    get_handler_info(ops->mpo_inpcb_label_init,
                     "mpo_inpcb_label_init");
    get_handler_info(ops->mpo_inpcb_label_recycle,
                     "mpo_inpcb_label_recycle");
    get_handler_info(ops->mpo_inpcb_label_update,
                     "mpo_inpcb_label_update");

    //
    // mpo_iokit (part 1)
    //

    get_handler_info(ops->mpo_iokit_check_device,
                     "mpo_iokit_check_device");

    //
    // mpo_ipq
    //

    get_handler_info(ops->mpo_ipq_label_associate,
                     "mpo_ipq_label_associate");
    get_handler_info(ops->mpo_ipq_label_compare,
                     "mpo_ipq_label_compare");
    get_handler_info(ops->mpo_ipq_label_destroy,
                     "mpo_ipq_label_destroy");
    get_handler_info(ops->mpo_ipq_label_init,
                     "mpo_ipq_label_init");
    get_handler_info(ops->mpo_ipq_label_update,
                     "mpo_ipq_label_update");

    //
    // mpo_lctx* were replaced by the follows (mpo_file and mpo_vnode)
    //

    get_handler_info(ops->mpo_file_check_library_validation,
                     "mpo_file_check_library_validation");
    get_handler_info(ops->mpo_vnode_notify_setacl,
                     "mpo_vnode_notify_setacl");
    get_handler_info(ops->mpo_vnode_notify_setattrlist,
                     "mpo_vnode_notify_setattrlist");
    get_handler_info(ops->mpo_vnode_notify_setextattr,
                     "mpo_vnode_notify_setextattr");
    get_handler_info(ops->mpo_vnode_notify_setflags,
                     "mpo_vnode_notify_setflags");
    get_handler_info(ops->mpo_vnode_notify_setmode,
                     "mpo_vnode_notify_setmode");
    get_handler_info(ops->mpo_vnode_notify_setowner,
                     "mpo_vnode_notify_setowner");
    get_handler_info(ops->mpo_vnode_notify_setutimes,
                     "mpo_vnode_notify_setutimes");
    get_handler_info(ops->mpo_vnode_notify_truncate,
                     "mpo_vnode_notify_truncate");

    //
    // mpo_mbuf
    //

    get_handler_info(ops->mpo_mbuf_label_associate_bpfdesc,
                     "mpo_mbuf_label_associate_bpfdesc");
    get_handler_info(ops->mpo_mbuf_label_associate_ifnet,
                     "mpo_mbuf_label_associate_ifnet");
    get_handler_info(ops->mpo_mbuf_label_associate_inpcb,
                     "mpo_mbuf_label_associate_inpcb");
    get_handler_info(ops->mpo_mbuf_label_associate_ipq,
                     "mpo_mbuf_label_associate_ipq");
    get_handler_info(ops->mpo_mbuf_label_associate_linklayer,
                     "mpo_mbuf_label_associate_linklayer");
    get_handler_info(ops->mpo_mbuf_label_associate_multicast_encap,
                     "mpo_mbuf_label_associate_multicast_encap");
    get_handler_info(ops->mpo_mbuf_label_associate_netlayer,
                     "mpo_mbuf_label_associate_netlayer");
    get_handler_info(ops->mpo_mbuf_label_associate_socket,
                     "mpo_mbuf_label_associate_socket");
    get_handler_info(ops->mpo_mbuf_label_copy,
                     "mpo_mbuf_label_copy");
    get_handler_info(ops->mpo_mbuf_label_destroy,
                     "mpo_mbuf_label_destroy");
    get_handler_info(ops->mpo_mbuf_label_init,
                     "mpo_mbuf_label_init");

    //
    // mpo_mount
    //

    get_handler_info(ops->mpo_mount_check_fsctl,
                     "mpo_mount_check_fsctl");
    get_handler_info(ops->mpo_mount_check_getattr,
                     "mpo_mount_check_getattr");
    get_handler_info(ops->mpo_mount_check_label_update,
                     "mpo_mount_check_label_update");
    get_handler_info(ops->mpo_mount_check_mount,
                     "mpo_mount_check_mount");
    get_handler_info(ops->mpo_mount_check_remount,
                     "mpo_mount_check_remount");
    get_handler_info(ops->mpo_mount_check_setattr,
                     "mpo_mount_check_setattr");
    get_handler_info(ops->mpo_mount_check_stat,
                     "mpo_mount_check_stat");
    get_handler_info(ops->mpo_mount_check_umount,
                     "mpo_mount_check_umount");
    get_handler_info(ops->mpo_mount_label_associate,
                     "mpo_mount_label_associate");
    get_handler_info(ops->mpo_mount_label_destroy,
                     "mpo_mount_label_destroy");
    get_handler_info(ops->mpo_mount_label_externalize,
                     "mpo_mount_label_externalize");
    get_handler_info(ops->mpo_mount_label_init,
                     "mpo_mount_label_init");
    get_handler_info(ops->mpo_mount_label_internalize,
                     "mpo_mount_label_internalize");

    //
    // mpo_netinet
    //

    get_handler_info(ops->mpo_netinet_fragment,
                     "mpo_netinet_fragment");
    get_handler_info(ops->mpo_netinet_icmp_reply,
                     "mpo_netinet_icmp_reply");
    get_handler_info(ops->mpo_netinet_tcp_reply,
                     "mpo_netinet_tcp_reply");

    //
    // mpo_pipe
    //

    get_handler_info(ops->mpo_pipe_check_ioctl,
                     "mpo_pipe_check_ioctl");
    get_handler_info(ops->mpo_pipe_check_kqfilter,
                     "mpo_pipe_check_kqfilter");
    get_handler_info(ops->mpo_pipe_check_label_update,
                     "mpo_pipe_check_label_update");
    get_handler_info(ops->mpo_pipe_check_read,
                     "mpo_pipe_check_read");
    get_handler_info(ops->mpo_pipe_check_select,
                     "mpo_pipe_check_select");
    get_handler_info(ops->mpo_pipe_check_stat,
                     "mpo_pipe_check_stat");
    get_handler_info(ops->mpo_pipe_check_write,
                     "mpo_pipe_check_write");
    get_handler_info(ops->mpo_pipe_label_associate,
                     "mpo_pipe_label_associate");
    get_handler_info(ops->mpo_pipe_label_copy,
                     "mpo_pipe_label_copy");
    get_handler_info(ops->mpo_pipe_label_destroy,
                     "mpo_pipe_label_destroy");
    get_handler_info(ops->mpo_pipe_label_externalize,
                     "mpo_pipe_label_externalize");
    get_handler_info(ops->mpo_pipe_label_init,
                     "mpo_pipe_label_init");
    get_handler_info(ops->mpo_pipe_label_internalize,
                     "mpo_pipe_label_internalize");
    get_handler_info(ops->mpo_pipe_label_update,
                     "mpo_pipe_label_update");

    //
    // mpo_policy
    //

    get_handler_info(ops->mpo_policy_destroy,
                     "mpo_policy_destroy");
    get_handler_info(ops->mpo_policy_init,
                     "mpo_policy_init");
    get_handler_info(ops->mpo_policy_initbsd,
                     "mpo_policy_initbsd");
    get_handler_info(ops->mpo_policy_syscall,
                     "mpo_policy_syscall");

    //
    // mpo_port* were replaced by the follows
    //

    get_handler_info(ops->mpo_system_check_sysctlbyname,
                     "mpo_system_check_sysctlbyname");
    get_handler_info(ops->mpo_proc_check_inherit_ipc_ports,
                     "mpo_proc_check_inherit_ipc_ports");
    get_handler_info(ops->mpo_vnode_check_rename,
                     "mpo_vnode_check_rename");
    get_handler_info(ops->mpo_kext_check_query,
                     "mpo_kext_check_query");
    get_handler_info(ops->mpo_proc_notify_exec_complete,
                     "mpo_proc_notify_exec_complete"); // mpo_iokit_check_nvram_get, version 53
    get_handler_info(ops->mpo_reserved5,
                     "mpo_reserved5"); // mpo_iokit_check_nvram_set, version 53
    get_handler_info(ops->mpo_reserved6,
                     "mpo_reserved6"); // mpo_iokit_check_nvram_delete, version 53
    get_handler_info(ops->mpo_proc_check_expose_task,
                     "mpo_proc_check_expose_task");
    get_handler_info(ops->mpo_proc_check_set_host_special_port,
                     "mpo_proc_check_set_host_special_port");
    get_handler_info(ops->mpo_proc_check_set_host_exception_port,
                     "mpo_proc_check_set_host_exception_port");
    get_handler_info(ops->mpo_exc_action_check_exception_send,
                     "mpo_exc_action_check_exception_send");
    get_handler_info(ops->mpo_exc_action_label_associate,
                     "mpo_exc_action_label_associate");
    get_handler_info(ops->mpo_exc_action_label_populate,
                     "mpo_exc_action_label_populate"); // mpo_exc_action_label_copy, version 52
    get_handler_info(ops->mpo_exc_action_label_destroy,
                     "mpo_exc_action_label_destroy");
    get_handler_info(ops->mpo_exc_action_label_init,
                     "mpo_exc_action_label_init");
    get_handler_info(ops->mpo_exc_action_label_update,
                     "mpo_exc_action_label_update");
    get_handler_info(ops->mpo_vnode_check_trigger_resolve,
                     "mpo_vnode_check_trigger_resolve"); // version 53
    get_handler_info(ops->mpo_reserved1,
                     "mpo_reserved1");
    get_handler_info(ops->mpo_reserved2,
                     "mpo_reserved2");
    get_handler_info(ops->mpo_reserved3,
                     "mpo_reserved3");
    get_handler_info(ops->mpo_skywalk_flow_check_connect,
                     "mpo_skywalk_flow_check_connect"); // version 52
    get_handler_info(ops->mpo_skywalk_flow_check_listen,
                     "mpo_skywalk_flow_check_listen"); // version 52

    //
    // mpo_posixsem and mpo_posixshm
    //

    get_handler_info(ops->mpo_posixsem_check_create,
                     "mpo_posixsem_check_create");
    get_handler_info(ops->mpo_posixsem_check_open,
                     "mpo_posixsem_check_open");
    get_handler_info(ops->mpo_posixsem_check_post,
                     "mpo_posixsem_check_post");
    get_handler_info(ops->mpo_posixsem_check_unlink,
                     "mpo_posixsem_check_unlink");
    get_handler_info(ops->mpo_posixsem_check_wait,
                     "mpo_posixsem_check_wait");
    get_handler_info(ops->mpo_posixsem_label_associate,
                     "mpo_posixsem_label_associate");
    get_handler_info(ops->mpo_posixsem_label_destroy,
                     "mpo_posixsem_label_destroy");
    get_handler_info(ops->mpo_posixsem_label_init,
                     "mpo_posixsem_label_init");
    get_handler_info(ops->mpo_posixshm_check_create,
                     "mpo_posixshm_check_create");
    get_handler_info(ops->mpo_posixshm_check_mmap,
                     "mpo_posixshm_check_mmap");
    get_handler_info(ops->mpo_posixshm_check_open,
                     "mpo_posixshm_check_open");
    get_handler_info(ops->mpo_posixshm_check_stat,
                     "mpo_posixshm_check_stat");
    get_handler_info(ops->mpo_posixshm_check_truncate,
                     "mpo_posixshm_check_truncate");
    get_handler_info(ops->mpo_posixshm_check_unlink,
                     "mpo_posixshm_check_unlink");
    get_handler_info(ops->mpo_posixshm_label_associate,
                     "mpo_posixshm_label_associate");
    get_handler_info(ops->mpo_posixshm_label_destroy,
                     "mpo_posixshm_label_destroy");
    get_handler_info(ops->mpo_posixshm_label_init,
                     "mpo_posixshm_label_init");

    //
    // mpo_proc
    //

    get_handler_info(ops->mpo_proc_check_debug,
                     "mpo_proc_check_debug");
    get_handler_info(ops->mpo_proc_check_fork,
                     "mpo_proc_check_fork");
    get_handler_info(ops->mpo_proc_check_get_task_name,
                     "mpo_proc_check_get_task_name");
    get_handler_info(ops->mpo_proc_check_get_task,
                     "mpo_proc_check_get_task");
    get_handler_info(ops->mpo_proc_check_getaudit,
                     "mpo_proc_check_getaudit");
    get_handler_info(ops->mpo_proc_check_getauid,
                     "mpo_proc_check_getauid");
    get_handler_info(ops->mpo_proc_check_getlcid,
                     "mpo_proc_check_getlcid");
    get_handler_info(ops->mpo_proc_check_mprotect,
                     "mpo_proc_check_mprotect");
    get_handler_info(ops->mpo_proc_check_sched,
                     "mpo_proc_check_sched");
    get_handler_info(ops->mpo_proc_check_setaudit,
                     "mpo_proc_check_setaudit");
    get_handler_info(ops->mpo_proc_check_setauid,
                     "mpo_proc_check_setauid");
    get_handler_info(ops->mpo_proc_check_setlcid,
                     "mpo_proc_check_setlcid");
    get_handler_info(ops->mpo_proc_check_signal,
                     "mpo_proc_check_signal");
    get_handler_info(ops->mpo_proc_check_wait,
                     "mpo_proc_check_wait");
    get_handler_info(ops->mpo_proc_label_destroy,
                     "mpo_proc_label_destroy");
    get_handler_info(ops->mpo_proc_label_init,
                     "mpo_proc_label_init");

    //
    // mpo_socket
    //

    get_handler_info(ops->mpo_socket_check_accept,
                     "mpo_socket_check_accept");
    get_handler_info(ops->mpo_socket_check_accepted,
                     "mpo_socket_check_accepted");
    get_handler_info(ops->mpo_socket_check_bind,
                     "mpo_socket_check_bind");
    get_handler_info(ops->mpo_socket_check_connect,
                     "mpo_socket_check_connect");
    get_handler_info(ops->mpo_socket_check_create,
                     "mpo_socket_check_create");
    get_handler_info(ops->mpo_socket_check_deliver,
                     "mpo_socket_check_deliver");
    get_handler_info(ops->mpo_socket_check_kqfilter,
                     "mpo_socket_check_kqfilter");
    get_handler_info(ops->mpo_socket_check_label_update,
                     "mpo_socket_check_label_update");
    get_handler_info(ops->mpo_socket_check_listen,
                     "mpo_socket_check_listen");
    get_handler_info(ops->mpo_socket_check_receive,
                     "mpo_socket_check_receive");
    get_handler_info(ops->mpo_socket_check_received,
                     "mpo_socket_check_received");
    get_handler_info(ops->mpo_socket_check_select,
                     "mpo_socket_check_select");
    get_handler_info(ops->mpo_socket_check_send,
                     "mpo_socket_check_send");
    get_handler_info(ops->mpo_socket_check_stat,
                     "mpo_socket_check_stat");
    get_handler_info(ops->mpo_socket_check_setsockopt,
                     "mpo_socket_check_setsockopt");
    get_handler_info(ops->mpo_socket_check_getsockopt,
                     "mpo_socket_check_getsockopt");
    get_handler_info(ops->mpo_socket_label_associate_accept,
                     "mpo_socket_label_associate_accept");
    get_handler_info(ops->mpo_socket_label_associate,
                     "mpo_socket_label_associate");
    get_handler_info(ops->mpo_socket_label_copy,
                     "mpo_socket_label_copy");
    get_handler_info(ops->mpo_socket_label_destroy,
                     "mpo_socket_label_destroy");
    get_handler_info(ops->mpo_socket_label_externalize,
                     "mpo_socket_label_externalize");
    get_handler_info(ops->mpo_socket_label_init,
                     "mpo_socket_label_init");
    get_handler_info(ops->mpo_socket_label_internalize,
                     "mpo_socket_label_internalize");
    get_handler_info(ops->mpo_socket_label_update,
                     "mpo_socket_label_update");

    //
    // mpo_socketpeer
    //

    get_handler_info(ops->mpo_socketpeer_label_associate_mbuf,
                     "mpo_socketpeer_label_associate_mbuf");
    get_handler_info(ops->mpo_socketpeer_label_associate_socket,
                     "mpo_socketpeer_label_associate_socket");
    get_handler_info(ops->mpo_socketpeer_label_destroy,
                     "mpo_socketpeer_label_destroy");
    get_handler_info(ops->mpo_socketpeer_label_externalize,
                     "mpo_socketpeer_label_externalize");
    get_handler_info(ops->mpo_socketpeer_label_init,
                     "mpo_socketpeer_label_init");

    //
    // mpo_system
    //

    get_handler_info(ops->mpo_system_check_acct,
                     "mpo_system_check_acct");
    get_handler_info(ops->mpo_system_check_audit,
                     "mpo_system_check_audit");
    get_handler_info(ops->mpo_system_check_auditctl,
                     "mpo_system_check_auditctl");
    get_handler_info(ops->mpo_system_check_auditon,
                     "mpo_system_check_auditon");
    get_handler_info(ops->mpo_system_check_host_priv,
                     "mpo_system_check_host_priv");
    get_handler_info(ops->mpo_system_check_nfsd,
                     "mpo_system_check_nfsd");
    get_handler_info(ops->mpo_system_check_reboot,
                     "mpo_system_check_reboot");
    get_handler_info(ops->mpo_system_check_settime,
                     "mpo_system_check_settime");
    get_handler_info(ops->mpo_system_check_swapoff,
                     "mpo_system_check_swapoff");
    get_handler_info(ops->mpo_system_check_swapon,
                     "mpo_system_check_swapon");
    get_handler_info(ops->mpo_socket_check_ioctl,
                     "mpo_socket_check_ioctl"); // mpo_system_check_sysctl

    //
    // mpo_sysvmsg, mpo_sysvmsq, mpo_sysvsem and mpo_sysvshm
    //

    get_handler_info(ops->mpo_sysvmsg_label_associate,
                     "mpo_sysvmsg_label_associate");
    get_handler_info(ops->mpo_sysvmsg_label_destroy,
                     "mpo_sysvmsg_label_destroy");
    get_handler_info(ops->mpo_sysvmsg_label_init,
                     "mpo_sysvmsg_label_init");
    get_handler_info(ops->mpo_sysvmsg_label_recycle,
                     "mpo_sysvmsg_label_recycle");
    get_handler_info(ops->mpo_sysvmsq_check_enqueue,
                     "mpo_sysvmsq_check_enqueue");
    get_handler_info(ops->mpo_sysvmsq_check_msgrcv,
                     "mpo_sysvmsq_check_msgrcv");
    get_handler_info(ops->mpo_sysvmsq_check_msgrmid,
                     "mpo_sysvmsq_check_msgrmid");
    get_handler_info(ops->mpo_sysvmsq_check_msqctl,
                     "mpo_sysvmsq_check_msqctl");
    get_handler_info(ops->mpo_sysvmsq_check_msqget,
                     "mpo_sysvmsq_check_msqget");
    get_handler_info(ops->mpo_sysvmsq_check_msqrcv,
                     "mpo_sysvmsq_check_msqrcv");
    get_handler_info(ops->mpo_sysvmsq_check_msqsnd,
                     "mpo_sysvmsq_check_msqsnd");
    get_handler_info(ops->mpo_sysvmsq_label_associate,
                     "mpo_sysvmsq_label_associate");
    get_handler_info(ops->mpo_sysvmsq_label_destroy,
                     "mpo_sysvmsq_label_destroy");
    get_handler_info(ops->mpo_sysvmsq_label_init,
                     "mpo_sysvmsq_label_init");
    get_handler_info(ops->mpo_sysvmsq_label_recycle,
                     "mpo_sysvmsq_label_recycle");
    get_handler_info(ops->mpo_sysvsem_check_semctl,
                     "mpo_sysvsem_check_semctl");
    get_handler_info(ops->mpo_sysvsem_check_semget,
                     "mpo_sysvsem_check_semget");
    get_handler_info(ops->mpo_sysvsem_check_semop,
                     "mpo_sysvsem_check_semop");
    get_handler_info(ops->mpo_sysvsem_label_associate,
                     "mpo_sysvsem_label_associate");
    get_handler_info(ops->mpo_sysvsem_label_destroy,
                     "mpo_sysvsem_label_destroy");
    get_handler_info(ops->mpo_sysvsem_label_init,
                     "mpo_sysvsem_label_init");
    get_handler_info(ops->mpo_sysvsem_label_recycle,
                     "mpo_sysvsem_label_recycle");
    get_handler_info(ops->mpo_sysvshm_check_shmat,
                     "mpo_sysvshm_check_shmat");
    get_handler_info(ops->mpo_sysvshm_check_shmctl,
                     "mpo_sysvshm_check_shmctl");
    get_handler_info(ops->mpo_sysvshm_check_shmdt,
                     "mpo_sysvshm_check_shmdt");
    get_handler_info(ops->mpo_sysvshm_check_shmget,
                     "mpo_sysvshm_check_shmget");
    get_handler_info(ops->mpo_sysvshm_label_associate,
                     "mpo_sysvshm_label_associate");
    get_handler_info(ops->mpo_sysvshm_label_destroy,
                     "mpo_sysvshm_label_destroy");
    get_handler_info(ops->mpo_sysvshm_label_init,
                     "mpo_sysvshm_label_init");
    get_handler_info(ops->mpo_sysvshm_label_recycle,
                     "mpo_sysvshm_label_recycle");

    //
    // mpo_task* and mpo_thread_userret were replaced by the follows
    //

    get_handler_info(ops->mpo_proc_notify_exit,
                     "mpo_proc_notify_exit"); // version 52
    get_handler_info(ops->mpo_mount_check_snapshot_revert,
                     "mpo_mount_check_snapshot_revert"); // version 47
    get_handler_info(ops->mpo_vnode_check_getattr,
                     "mpo_vnode_check_getattr"); // version 46
    get_handler_info(ops->mpo_mount_check_snapshot_create,
                     "mpo_mount_check_snapshot_create");
    get_handler_info(ops->mpo_mount_check_snapshot_delete,
                     "mpo_mount_check_snapshot_delete");
    get_handler_info(ops->mpo_vnode_check_clone,
                     "mpo_vnode_check_clone");
    get_handler_info(ops->mpo_proc_check_get_cs_info,
                     "mpo_proc_check_get_cs_info");
    get_handler_info(ops->mpo_proc_check_set_cs_info,
                     "mpo_proc_check_set_cs_info");
    get_handler_info(ops->mpo_iokit_check_hid_control,
                     "mpo_iokit_check_hid_control");

    //
    // mpo_vnode
    //

    get_handler_info(ops->mpo_vnode_check_access,
                     "mpo_vnode_check_access");
    get_handler_info(ops->mpo_vnode_check_chdir,
                     "mpo_vnode_check_chdir");
    get_handler_info(ops->mpo_vnode_check_chroot,
                     "mpo_vnode_check_chroot");
    get_handler_info(ops->mpo_vnode_check_create,
                     "mpo_vnode_check_create");
    get_handler_info(ops->mpo_vnode_check_deleteextattr,
                     "mpo_vnode_check_deleteextattr");
    get_handler_info(ops->mpo_vnode_check_exchangedata,
                     "mpo_vnode_check_exchangedata");
    get_handler_info(ops->mpo_vnode_check_exec,
                     "mpo_vnode_check_exec");
    get_handler_info(ops->mpo_vnode_check_getattrlist,
                     "mpo_vnode_check_getattrlist");
    get_handler_info(ops->mpo_vnode_check_getextattr,
                     "mpo_vnode_check_getextattr");
    get_handler_info(ops->mpo_vnode_check_ioctl,
                     "mpo_vnode_check_ioctl");
    get_handler_info(ops->mpo_vnode_check_kqfilter,
                     "mpo_vnode_check_kqfilter");
    get_handler_info(ops->mpo_vnode_check_label_update,
                     "mpo_vnode_check_label_update");
    get_handler_info(ops->mpo_vnode_check_link,
                     "mpo_vnode_check_link");
    get_handler_info(ops->mpo_vnode_check_listextattr,
                     "mpo_vnode_check_listextattr");
    get_handler_info(ops->mpo_vnode_check_lookup,
                     "mpo_vnode_check_lookup");
    get_handler_info(ops->mpo_vnode_check_open,
                     "mpo_vnode_check_open");
    get_handler_info(ops->mpo_vnode_check_read,
                     "mpo_vnode_check_read");
    get_handler_info(ops->mpo_vnode_check_readdir,
                     "mpo_vnode_check_readdir");
    get_handler_info(ops->mpo_vnode_check_readlink,
                     "mpo_vnode_check_readlink");
    get_handler_info(ops->mpo_vnode_check_rename_from,
                     "mpo_vnode_check_rename_from");
    get_handler_info(ops->mpo_vnode_check_rename_to,
                     "mpo_vnode_check_rename_to");
    get_handler_info(ops->mpo_vnode_check_revoke,
                     "mpo_vnode_check_revoke");
    get_handler_info(ops->mpo_vnode_check_select,
                     "mpo_vnode_check_select");
    get_handler_info(ops->mpo_vnode_check_setattrlist,
                     "mpo_vnode_check_setattrlist");
    get_handler_info(ops->mpo_vnode_check_setextattr,
                     "mpo_vnode_check_setextattr");
    get_handler_info(ops->mpo_vnode_check_setflags,
                     "mpo_vnode_check_setflags");
    get_handler_info(ops->mpo_vnode_check_setmode,
                     "mpo_vnode_check_setmode");
    get_handler_info(ops->mpo_vnode_check_setowner,
                     "mpo_vnode_check_setowner");
    get_handler_info(ops->mpo_vnode_check_setutimes,
                     "mpo_vnode_check_setutimes");
    get_handler_info(ops->mpo_vnode_check_stat,
                     "mpo_vnode_check_stat");
    get_handler_info(ops->mpo_vnode_check_truncate,
                     "mpo_vnode_check_truncate");
    get_handler_info(ops->mpo_vnode_check_unlink,
                     "mpo_vnode_check_unlink");
    get_handler_info(ops->mpo_vnode_check_write,
                     "mpo_vnode_check_write");
    get_handler_info(ops->mpo_vnode_label_associate_devfs,
                     "mpo_vnode_label_associate_devfs");
    get_handler_info(ops->mpo_vnode_label_associate_extattr,
                     "mpo_vnode_label_associate_extattr");
    get_handler_info(ops->mpo_vnode_label_associate_file,
                     "mpo_vnode_label_associate_file");
    get_handler_info(ops->mpo_vnode_label_associate_pipe,
                     "mpo_vnode_label_associate_pipe");
    get_handler_info(ops->mpo_vnode_label_associate_posixsem,
                     "mpo_vnode_label_associate_posixsem");
    get_handler_info(ops->mpo_vnode_label_associate_posixshm,
                     "mpo_vnode_label_associate_posixshm");
    get_handler_info(ops->mpo_vnode_label_associate_singlelabel,
                     "mpo_vnode_label_associate_singlelabel");
    get_handler_info(ops->mpo_vnode_label_associate_socket,
                     "mpo_vnode_label_associate_socket");
    get_handler_info(ops->mpo_vnode_label_copy,
                     "mpo_vnode_label_copy");
    get_handler_info(ops->mpo_vnode_label_destroy,
                     "mpo_vnode_label_destroy");
    get_handler_info(ops->mpo_vnode_label_externalize_audit,
                     "mpo_vnode_label_externalize_audit");
    get_handler_info(ops->mpo_vnode_label_externalize,
                     "mpo_vnode_label_externalize");
    get_handler_info(ops->mpo_vnode_label_init,
                     "mpo_vnode_label_init");
    get_handler_info(ops->mpo_vnode_label_internalize,
                     "mpo_vnode_label_internalize");
    get_handler_info(ops->mpo_vnode_label_recycle,
                     "mpo_vnode_label_recycle");
    get_handler_info(ops->mpo_vnode_label_store,
                     "mpo_vnode_label_store");
    get_handler_info(ops->mpo_vnode_label_update_extattr,
                     "mpo_vnode_label_update_extattr");
    get_handler_info(ops->mpo_vnode_label_update,
                     "mpo_vnode_label_update");
    get_handler_info(ops->mpo_vnode_notify_create,
                     "mpo_vnode_notify_create");
    get_handler_info(ops->mpo_vnode_check_signature,
                     "mpo_vnode_check_signature");
    get_handler_info(ops->mpo_vnode_check_uipc_bind,
                     "mpo_vnode_check_uipc_bind");
    get_handler_info(ops->mpo_vnode_check_uipc_connect,
                     "mpo_vnode_check_uipc_connect");

    //
    // the others
    //

    get_handler_info(ops->mpo_proc_check_run_cs_invalid,
                     "mpo_proc_check_run_cs_invalid");
    get_handler_info(ops->mpo_proc_check_suspend_resume,
                     "mpo_proc_check_suspend_resume");
    get_handler_info(ops->mpo_thread_userret,
                     "mpo_thread_userret");
    get_handler_info(ops->mpo_iokit_check_set_properties,
                     "mpo_iokit_check_set_properties");
    get_handler_info(ops->mpo_system_check_chud,
                     "mpo_system_check_chud");
    get_handler_info(ops->mpo_vnode_check_searchfs,
                     "mpo_vnode_check_searchfs");
    get_handler_info(ops->mpo_priv_check,
                     "mpo_priv_check");
    get_handler_info(ops->mpo_priv_grant,
                     "mpo_priv_grant");
    get_handler_info(ops->mpo_proc_check_map_anon,
                     "mpo_proc_check_map_anon");
    get_handler_info(ops->mpo_vnode_check_fsgetpath,
                     "mpo_vnode_check_fsgetpath");
    get_handler_info(ops->mpo_iokit_check_open,
                     "mpo_iokit_check_open");
    get_handler_info(ops->mpo_proc_check_ledger,
                     "mpo_proc_check_ledger");
    get_handler_info(ops->mpo_vnode_notify_rename,
                     "mpo_vnode_notify_rename");
    get_handler_info(ops->mpo_vnode_check_setacl,
                     "mpo_vnode_check_setacl");
    get_handler_info(ops->mpo_vnode_notify_deleteextattr,
                     "mpo_vnode_notify_deleteextattr");
    get_handler_info(ops->mpo_system_check_kas_info,
                     "mpo_system_check_kas_info");
    get_handler_info(ops->mpo_vnode_check_lookup_preflight,
                     "mpo_vnode_check_lookup_preflight"); // mpo_proc_check_cpumon, version 52
    get_handler_info(ops->mpo_vnode_notify_open,
                     "mpo_vnode_notify_open");
    get_handler_info(ops->mpo_system_check_info,
                     "mpo_system_check_info");
    get_handler_info(ops->mpo_pty_notify_grant,
                     "mpo_pty_notify_grant");
    get_handler_info(ops->mpo_pty_notify_close,
                     "mpo_pty_notify_close");
    get_handler_info(ops->mpo_vnode_find_sigs,
                     "mpo_vnode_find_sigs");
    get_handler_info(ops->mpo_kext_check_load,
                     "mpo_kext_check_load");
    get_handler_info(ops->mpo_kext_check_unload,
                     "mpo_kext_check_unload");
    get_handler_info(ops->mpo_proc_check_proc_info,
                     "mpo_proc_check_proc_info");
    get_handler_info(ops->mpo_vnode_notify_link,
                     "mpo_vnode_notify_link");
    get_handler_info(ops->mpo_iokit_check_filter_properties,
                     "mpo_iokit_check_filter_properties");
    get_handler_info(ops->mpo_iokit_check_get_property,
                     "mpo_iokit_check_get_property");
}
#endif // MAC_TROUBLESHOOTING

static
void
show_mac_policy(
    )
{
    char policy_buffer[0x100];
    unsigned long policy_length;

    policy_length = sizeof(policy_buffer);

    lck_mtx_lock(sw_lock);

    if (sw_list) {
        struct shadow_walker_list *entry = sw_list;

        do {
            memset(policy_buffer, 0, policy_length);
            struct shadow_walker_list *next = entry->next;

        #if MAC_TROUBLESHOOTING
            int length = snprintf(policy_buffer, policy_length,
                                  "[%s.kext] : macOS MAC policy version=%d, policy name[%d]=%s(%s), load time flags=%d(%s), policy mpc=%p, policy ops=%p.\n",
                                  DRIVER_NAME,
                                  MAC_POLICY_OPS_VERSION, entry->index,
                                  entry->local_name, entry->local_fullname,
                                  entry->local_mpc.mpc_loadtime_flags,
                                  get_loadtime_option(entry->local_mpc.mpc_loadtime_flags),
                                  entry->mpc, entry->local_mpc.mpc_ops);
            if (length < SNPRINTF_LENGTH_LIMIT) {
                printf("%s", policy_buffer);
            } else {
                //
                // For macOS 10.14 Mojave
                //

                memset(policy_buffer, 0, policy_length);

                snprintf(policy_buffer, policy_length,
                         "[%s.kext] : macOS MAC policy version=%d, policy name[%d]=%s(%s), load time flags=%d, policy mpc=%p, policy ops=%p.\n",
                         DRIVER_NAME,
                         MAC_POLICY_OPS_VERSION, entry->index,
                         entry->local_name, entry->local_fullname,
                         entry->local_mpc.mpc_loadtime_flags,
                         entry->mpc, entry->local_mpc.mpc_ops);
                printf("%s", policy_buffer);
            }

            //
            // Please note that the MAC_POLICY_OPS_VERSION is 55 (xnu-4903.221.2)
            //

            show_mac_policy_handlers(&entry->local_ops);
        #endif

            entry = next;
        } while (entry);
    }

    lck_mtx_unlock(sw_lock);
}
#endif // MAC_POLICY_SHADOW_WALKER

static
int
mac_file_check_mmap_handler(
    kauth_cred_t cred,
    struct fileglob *fg,
    struct label *label,
    int prot,
    int flags,
    uint64_t file_pos,
    int *maxprot
    )
{
    int error = 0;

    if ((prot & VM_PROT_EXECUTE) &&
        (flags & (MAP_PRIVATE | MAP_FIXED)) &&
        (cred == fg->fg_cred) && fg->fg_data) {
        char *vp_path;
        struct dynamic_library_monitoring *message;

        error = construct_path_from_vnode((vnode_t) fg->fg_data,
                                          &vp_path);
        if (!error && vp_path) {
            message = OSMalloc(sizeof(*message), gmalloc_tag);
            if (message) {
                memset(message, 0, sizeof(*message));

                //
                // Message header
                //

                microtime(&(message->header.event_time));
                message->header.type = MONITORING_DYNAMIC_LIBRARY;

                message->header.pid = proc_selfpid();
                proc_name(message->header.pid,
                          message->header.proc_name_pid,
                          MAXPATHLEN);

                message->header.ppid = proc_selfppid();
                proc_name(message->header.ppid,
                          message->header.proc_name_ppid,
                          MAXPATHLEN);

                message->header.uid = kauth_getuid();
                message->header.gid = kauth_getgid();

                //
                // Message body
                //

                size_t data_length = strlen((const char *) vp_path);
                memcpy(message->library_path,
                       vp_path,
                       (data_length <= MAXPATHLEN - 1) ?
                       data_length : MAXPATHLEN - 1);

                send_message((struct message_header *) message);

                OSFree(message, sizeof(*message),
                       gmalloc_tag);
            }
        }

        if (vp_path)
            OSFree(vp_path, MAXPATHLEN,
                   gmalloc_tag);
    }

    return error;
}

extern
kern_return_t
mac_initialization(
    boolean_t flag
    )
{
    int error;
    kern_return_t status = KERN_SUCCESS;

    if (flag) {
        if (!glock_group)
            return KERN_FAILURE;

        memset(&mac_ops, 0, sizeof(struct mac_policy_ops));
        memset(&mac_mpc, 0, sizeof(struct mac_policy_conf));

        //
        // mpo_file
        //

        mac_ops.mpo_file_check_mmap = mac_file_check_mmap_handler;

        mac_mpc.mpc_ops = &mac_ops;
        mac_mpc.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK;
        mac_mpc.mpc_fullname = POLICY_FULL_NAME;
        mac_mpc.mpc_name = DRIVER_NAME;

        error = mac_policy_register(&mac_mpc, &mac_handle, NULL);
        if (error) {
            status = KERN_FAILURE;
    #if MAC_POLICY_SHADOW_WALKER
        } else {
            sw_lock = lck_mtx_alloc_init(glock_group,
                                         LCK_ATTR_NULL);
            if (!sw_lock) {
                status = KERN_FAILURE;
            } else {
                dump_mac_policy();
            }
    #endif
        }
    } else {
    #if MAC_POLICY_SHADOW_WALKER
        if (sw_lock) {
            show_mac_policy();

            //
            // Cleanup
            //

            struct shadow_walker_list *entry;

            lck_mtx_lock(sw_lock);

            while (sw_list) {
                entry = sw_list;
                sw_list = sw_list->next;

                OSFree(entry, sizeof(*entry),
                       gmalloc_tag);
            }

            lck_mtx_unlock(sw_lock);

            if (glock_group) {
                lck_mtx_free(sw_lock,
                             glock_group);

                sw_lock = NULL;
            }
        }
    #endif

        //
        // In the mac_late mode
        //

        if (mac_handle) {
            error = mac_policy_unregister(mac_handle);
            if (error)
                status = KERN_FAILURE;
            else
                mac_handle = 0;
        }
    }

    return status;
}