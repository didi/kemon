/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    policy.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __POLICY_DRIVER_H__
#define __POLICY_DRIVER_H__


#define POLICY_FULL_NAME "Kemon MAC Policy"

//
// Shadow Walker
//

#define MAC_SHADOW_WALKER TRUE

//
// Current MAC policy OPS version
//

#define MAC_POLICY_OPS_VERSION 53

//
// MAC policy module operations
//

struct mac_policy_ops
{
    //
    // mpo_audit
    //

    void *mpo_audit_check_postselect;
    void *mpo_audit_check_preselect;

    //
    // mpo_bpfdesc
    //

    void *mpo_bpfdesc_label_associate;
    void *mpo_bpfdesc_label_destroy;
    void *mpo_bpfdesc_label_init;
    void *mpo_bpfdesc_check_receive;

    //
    // mpo_cred
    //

    void *mpo_cred_check_label_update_execve;
    void *mpo_cred_check_label_update;
    void *mpo_cred_check_visible;
    void *mpo_cred_label_associate_fork;
    void *mpo_cred_label_associate_kernel;
    void *mpo_cred_label_associate;
    void *mpo_cred_label_associate_user;
    void *mpo_cred_label_destroy;
    void *mpo_cred_label_externalize_audit;
    void *mpo_cred_label_externalize;
    void *mpo_cred_label_init;
    void *mpo_cred_label_internalize;
    void *mpo_cred_label_update_execve;
    void *mpo_cred_label_update;

    //
    // mpo_devfs
    //

    void *mpo_devfs_label_associate_device;
    void *mpo_devfs_label_associate_directory;
    void *mpo_devfs_label_copy;
    void *mpo_devfs_label_destroy;
    void *mpo_devfs_label_init;
    void *mpo_devfs_label_update;

    //
    // mpo_file
    //

    void *mpo_file_check_change_offset;
    void *mpo_file_check_create;
    void *mpo_file_check_dup;
    void *mpo_file_check_fcntl;
    void *mpo_file_check_get_offset;
    void *mpo_file_check_get;
    void *mpo_file_check_inherit;
    void *mpo_file_check_ioctl;
    void *mpo_file_check_lock;
    void *mpo_file_check_mmap_downgrade;
    void *mpo_file_check_mmap;
    void *mpo_file_check_receive;
    void *mpo_file_check_set;
    void *mpo_file_label_init;
    void *mpo_file_label_destroy;
    void *mpo_file_label_associate;

    //
    // mpo_ifnet
    //

    void *mpo_ifnet_check_label_update;
    void *mpo_ifnet_check_transmit;
    void *mpo_ifnet_label_associate;
    void *mpo_ifnet_label_copy;
    void *mpo_ifnet_label_destroy;
    void *mpo_ifnet_label_externalize;
    void *mpo_ifnet_label_init;
    void *mpo_ifnet_label_internalize;
    void *mpo_ifnet_label_update;
    void *mpo_ifnet_label_recycle;

    //
    // mpo_inpcb
    //

    void *mpo_inpcb_check_deliver;
    void *mpo_inpcb_label_associate;
    void *mpo_inpcb_label_destroy;
    void *mpo_inpcb_label_init;
    void *mpo_inpcb_label_recycle;
    void *mpo_inpcb_label_update;

    //
    // mpo_iokit (part 1)
    //

    void *mpo_iokit_check_device;

    //
    // mpo_ipq
    //

    void *mpo_ipq_label_associate;
    void *mpo_ipq_label_compare;
    void *mpo_ipq_label_destroy;
    void *mpo_ipq_label_init;
    void *mpo_ipq_label_update;

    //
    // mpo_lctx* were replaced by the follows
    //

    void *mpo_file_check_library_validation;
    void *mpo_vnode_notify_setacl;
    void *mpo_vnode_notify_setattrlist;
    void *mpo_vnode_notify_setextattr;
    void *mpo_vnode_notify_setflags;
    void *mpo_vnode_notify_setmode;
    void *mpo_vnode_notify_setowner;
    void *mpo_vnode_notify_setutimes;
    void *mpo_vnode_notify_truncate;

    //
    // mpo_mbuf
    //

    void *mpo_mbuf_label_associate_bpfdesc;
    void *mpo_mbuf_label_associate_ifnet;
    void *mpo_mbuf_label_associate_inpcb;
    void *mpo_mbuf_label_associate_ipq;
    void *mpo_mbuf_label_associate_linklayer;
    void *mpo_mbuf_label_associate_multicast_encap;
    void *mpo_mbuf_label_associate_netlayer;
    void *mpo_mbuf_label_associate_socket;
    void *mpo_mbuf_label_copy;
    void *mpo_mbuf_label_destroy;
    void *mpo_mbuf_label_init;

    //
    // mpo_mount
    //

    void *mpo_mount_check_fsctl;
    void *mpo_mount_check_getattr;
    void *mpo_mount_check_label_update;
    void *mpo_mount_check_mount;
    void *mpo_mount_check_remount;
    void *mpo_mount_check_setattr;
    void *mpo_mount_check_stat;
    void *mpo_mount_check_umount;
    void *mpo_mount_label_associate;
    void *mpo_mount_label_destroy;
    void *mpo_mount_label_externalize;
    void *mpo_mount_label_init;
    void *mpo_mount_label_internalize;

    //
    // mpo_netinet
    //

    void *mpo_netinet_fragment;
    void *mpo_netinet_icmp_reply;
    void *mpo_netinet_tcp_reply;

    //
    // mpo_pipe
    //

    void *mpo_pipe_check_ioctl;
    void *mpo_pipe_check_kqfilter;
    void *mpo_pipe_check_label_update;
    void *mpo_pipe_check_read;
    void *mpo_pipe_check_select;
    void *mpo_pipe_check_stat;
    void *mpo_pipe_check_write;
    void *mpo_pipe_label_associate;
    void *mpo_pipe_label_copy;
    void *mpo_pipe_label_destroy;
    void *mpo_pipe_label_externalize;
    void *mpo_pipe_label_init;
    void *mpo_pipe_label_internalize;
    void *mpo_pipe_label_update;

    //
    // mpo_policy
    //

    void *mpo_policy_destroy;
    void *mpo_policy_init;
    void *mpo_policy_initbsd;
    void *mpo_policy_syscall;

    //
    // mpo_port* were replaced by the follows
    //

    void *mpo_system_check_sysctlbyname;
    void *mpo_proc_check_inherit_ipc_ports;
    void *mpo_vnode_check_rename;
    void *mpo_kext_check_query;
    void *mpo_iokit_check_nvram_get;
    void *mpo_iokit_check_nvram_set;
    void *mpo_iokit_check_nvram_delete;
    void *mpo_proc_check_expose_task;
    void *mpo_proc_check_set_host_special_port;
    void *mpo_proc_check_set_host_exception_port;
    void *mpo_exc_action_check_exception_send;
    void *mpo_exc_action_label_associate;
    void *mpo_exc_action_label_populate;   // mpo_exc_action_label_copy, version 52
    void *mpo_exc_action_label_destroy;
    void *mpo_exc_action_label_init;
    void *mpo_exc_action_label_update;
    void *mpo_vnode_check_trigger_resolve; // version 53
    void *mpo_reserved1;
    void *mpo_reserved2;
    void *mpo_reserved3;
    void *mpo_skywalk_flow_check_connect;  // version 52
    void *mpo_skywalk_flow_check_listen;   // version 52

    //
    // mpo_posixsem and mpo_posixshm
    //

    void *mpo_posixsem_check_create;
    void *mpo_posixsem_check_open;
    void *mpo_posixsem_check_post;
    void *mpo_posixsem_check_unlink;
    void *mpo_posixsem_check_wait;
    void *mpo_posixsem_label_associate;
    void *mpo_posixsem_label_destroy;
    void *mpo_posixsem_label_init;
    void *mpo_posixshm_check_create;
    void *mpo_posixshm_check_mmap;
    void *mpo_posixshm_check_open;
    void *mpo_posixshm_check_stat;
    void *mpo_posixshm_check_truncate;
    void *mpo_posixshm_check_unlink;
    void *mpo_posixshm_label_associate;
    void *mpo_posixshm_label_destroy;
    void *mpo_posixshm_label_init;

    //
    // mpo_proc
    //

    void *mpo_proc_check_debug;
    void *mpo_proc_check_fork;
    void *mpo_proc_check_get_task_name;
    void *mpo_proc_check_get_task;
    void *mpo_proc_check_getaudit;
    void *mpo_proc_check_getauid;
    void *mpo_proc_check_getlcid;
    void *mpo_proc_check_mprotect;
    void *mpo_proc_check_sched;
    void *mpo_proc_check_setaudit;
    void *mpo_proc_check_setauid;
    void *mpo_proc_check_setlcid;
    void *mpo_proc_check_signal;
    void *mpo_proc_check_wait;
    void *mpo_proc_label_destroy;
    void *mpo_proc_label_init;

    //
    // mpo_socket
    //

    void *mpo_socket_check_accept;
    void *mpo_socket_check_accepted;
    void *mpo_socket_check_bind;
    void *mpo_socket_check_connect;
    void *mpo_socket_check_create;
    void *mpo_socket_check_deliver;
    void *mpo_socket_check_kqfilter;
    void *mpo_socket_check_label_update;
    void *mpo_socket_check_listen;
    void *mpo_socket_check_receive;
    void *mpo_socket_check_received;
    void *mpo_socket_check_select;
    void *mpo_socket_check_send;
    void *mpo_socket_check_stat;
    void *mpo_socket_check_setsockopt;
    void *mpo_socket_check_getsockopt;
    void *mpo_socket_label_associate_accept;
    void *mpo_socket_label_associate;
    void *mpo_socket_label_copy;
    void *mpo_socket_label_destroy;
    void *mpo_socket_label_externalize;
    void *mpo_socket_label_init;
    void *mpo_socket_label_internalize;
    void *mpo_socket_label_update;

    //
    // mpo_socketpeer
    //

    void *mpo_socketpeer_label_associate_mbuf;
    void *mpo_socketpeer_label_associate_socket;
    void *mpo_socketpeer_label_destroy;
    void *mpo_socketpeer_label_externalize;
    void *mpo_socketpeer_label_init;

    //
    // mpo_system
    //

    void *mpo_system_check_acct;
    void *mpo_system_check_audit;
    void *mpo_system_check_auditctl;
    void *mpo_system_check_auditon;
    void *mpo_system_check_host_priv;
    void *mpo_system_check_nfsd;
    void *mpo_system_check_reboot;
    void *mpo_system_check_settime;
    void *mpo_system_check_swapoff;
    void *mpo_system_check_swapon;
    void *mpo_socket_check_ioctl; // mpo_system_check_sysctl

    //
    // mpo_sysvmsg, mpo_sysvmsq, mpo_sysvsem and mpo_sysvshm
    //

    void *mpo_sysvmsg_label_associate;
    void *mpo_sysvmsg_label_destroy;
    void *mpo_sysvmsg_label_init;
    void *mpo_sysvmsg_label_recycle;
    void *mpo_sysvmsq_check_enqueue;
    void *mpo_sysvmsq_check_msgrcv;
    void *mpo_sysvmsq_check_msgrmid;
    void *mpo_sysvmsq_check_msqctl;
    void *mpo_sysvmsq_check_msqget;
    void *mpo_sysvmsq_check_msqrcv;
    void *mpo_sysvmsq_check_msqsnd;
    void *mpo_sysvmsq_label_associate;
    void *mpo_sysvmsq_label_destroy;
    void *mpo_sysvmsq_label_init;
    void *mpo_sysvmsq_label_recycle;
    void *mpo_sysvsem_check_semctl;
    void *mpo_sysvsem_check_semget;
    void *mpo_sysvsem_check_semop;
    void *mpo_sysvsem_label_associate;
    void *mpo_sysvsem_label_destroy;
    void *mpo_sysvsem_label_init;
    void *mpo_sysvsem_label_recycle;
    void *mpo_sysvshm_check_shmat;
    void *mpo_sysvshm_check_shmctl;
    void *mpo_sysvshm_check_shmdt;
    void *mpo_sysvshm_check_shmget;
    void *mpo_sysvshm_label_associate;
    void *mpo_sysvshm_label_destroy;
    void *mpo_sysvshm_label_init;
    void *mpo_sysvshm_label_recycle;

    //
    // mpo_task* and mpo_thread_userret were replaced by the follows
    //

    void *mpo_proc_notify_exit;            // version 52
    void *mpo_mount_check_snapshot_revert; // version 47
    void *mpo_vnode_check_getattr;         // version 46
    void *mpo_mount_check_snapshot_create;
    void *mpo_mount_check_snapshot_delete;
    void *mpo_vnode_check_clone;
    void *mpo_proc_check_get_cs_info;
    void *mpo_proc_check_set_cs_info;
    void *mpo_iokit_check_hid_control;

    //
    // mpo_vnode
    //

    void *mpo_vnode_check_access;
    void *mpo_vnode_check_chdir;
    void *mpo_vnode_check_chroot;
    void *mpo_vnode_check_create;
    void *mpo_vnode_check_deleteextattr;
    void *mpo_vnode_check_exchangedata;
    void *mpo_vnode_check_exec;
    void *mpo_vnode_check_getattrlist;
    void *mpo_vnode_check_getextattr;
    void *mpo_vnode_check_ioctl;
    void *mpo_vnode_check_kqfilter;
    void *mpo_vnode_check_label_update;
    void *mpo_vnode_check_link;
    void *mpo_vnode_check_listextattr;
    void *mpo_vnode_check_lookup;
    void *mpo_vnode_check_open;
    void *mpo_vnode_check_read;
    void *mpo_vnode_check_readdir;
    void *mpo_vnode_check_readlink;
    void *mpo_vnode_check_rename_from;
    void *mpo_vnode_check_rename_to;
    void *mpo_vnode_check_revoke;
    void *mpo_vnode_check_select;
    void *mpo_vnode_check_setattrlist;
    void *mpo_vnode_check_setextattr;
    void *mpo_vnode_check_setflags;
    void *mpo_vnode_check_setmode;
    void *mpo_vnode_check_setowner;
    void *mpo_vnode_check_setutimes;
    void *mpo_vnode_check_stat;
    void *mpo_vnode_check_truncate;
    void *mpo_vnode_check_unlink;
    void *mpo_vnode_check_write;
    void *mpo_vnode_label_associate_devfs;
    void *mpo_vnode_label_associate_extattr;
    void *mpo_vnode_label_associate_file;
    void *mpo_vnode_label_associate_pipe;
    void *mpo_vnode_label_associate_posixsem;
    void *mpo_vnode_label_associate_posixshm;
    void *mpo_vnode_label_associate_singlelabel;
    void *mpo_vnode_label_associate_socket;
    void *mpo_vnode_label_copy;
    void *mpo_vnode_label_destroy;
    void *mpo_vnode_label_externalize_audit;
    void *mpo_vnode_label_externalize;
    void *mpo_vnode_label_init;
    void *mpo_vnode_label_internalize;
    void *mpo_vnode_label_recycle;
    void *mpo_vnode_label_store;
    void *mpo_vnode_label_update_extattr;
    void *mpo_vnode_label_update;
    void *mpo_vnode_notify_create;
    void *mpo_vnode_check_signature;
    void *mpo_vnode_check_uipc_bind;
    void *mpo_vnode_check_uipc_connect;

    //
    // the others
    //

    void *mpo_proc_check_run_cs_invalid;
    void *mpo_proc_check_suspend_resume;
    void *mpo_thread_userret;
    void *mpo_iokit_check_set_properties;
    void *mpo_system_check_chud;
    void *mpo_vnode_check_searchfs;
    void *mpo_priv_check;
    void *mpo_priv_grant;
    void *mpo_proc_check_map_anon;
    void *mpo_vnode_check_fsgetpath;
    void *mpo_iokit_check_open;
    void *mpo_proc_check_ledger;
    void *mpo_vnode_notify_rename;
    void *mpo_vnode_check_setacl;
    void *mpo_vnode_notify_deleteextattr;
    void *mpo_system_check_kas_info;
    void *mpo_vnode_check_lookup_preflight; // mpo_proc_check_cpumon, version 52
    void *mpo_vnode_notify_open;
    void *mpo_system_check_info;
    void *mpo_pty_notify_grant;
    void *mpo_pty_notify_close;
    void *mpo_vnode_find_sigs;
    void *mpo_kext_check_load;
    void *mpo_kext_check_unload;
    void *mpo_proc_check_proc_info;
    void *mpo_vnode_notify_link;
    void *mpo_iokit_check_filter_properties;
    void *mpo_iokit_check_get_property;
};

//
// This flag indicates that the policy module must be loaded and initialized early in the boot process.
// If the flag is specified, attempts to register the module following boot will be rejected.
//

#define MPC_LOADTIME_FLAG_NOTLATE    0x00000001

//
// This flag indicates that the policy module may be unloaded.
// If this flag is not set, then the policy framework will reject requests to unload the module.
//

#define MPC_LOADTIME_FLAG_UNLOADOK   0x00000002

//
// This flag is not yet supported.
//

#define MPC_LOADTIME_FLAG_LABELMBUFS 0x00000004

//
// This flag indicates that the policy module is a base policy.
// Only one module can declare itself as base, otherwise the boot process will be halted.
//

#define MPC_LOADTIME_BASE_POLICY     0x00000008

//
// This flag indicates that the policy module has been successfully registered with the TrustedBSD MAC framework.
// The framework will set this flag in the mpc_runtime_flags field of the policy's mac_policy_conf structure after registering the policy.
//

#define MPC_RUNTIME_FLAG_REGISTERED  0x00000001

//
// MAC policy configuration
//

struct mac_policy_conf
{
    char *mpc_name;                     // policy name
    char *mpc_fullname;                 // full name
    char const * const *mpc_labelnames; // managed label namespaces
    unsigned int mpc_labelname_count;   // number of managed label namespaces
    struct mac_policy_ops *mpc_ops;     // operation vector
    int mpc_loadtime_flags;             // load time flags
    int *mpc_field_off;                 // label slot
    int mpc_runtime_flags;              // run time flags
    struct mac_policy_conf *mpc_list;   // list reference
    void *mpc_data;                     // module data
};

//
// The MAC handle is used to uniquely identify a loaded policy within the MAC framework
//

typedef unsigned int mac_policy_handle_t;

//
// File internal
//

struct fileglob
{
    LIST_ENTRY(fileglob) f_msglist;
    int32_t fg_flag;
    int32_t fg_type;
    int32_t fg_count;
    int32_t fg_msgcount;
    kauth_cred_t fg_cred;
    void *fg_ops;
    off_t fg_offset;
    void *fg_data;
};

//
// This function is called to register a policy with the MAC framework.
// A policy module will typically call this from the Darwin KEXT registration routine.
//

extern
int
mac_policy_register(
    struct mac_policy_conf *mpc,
    mac_policy_handle_t *handlep,
    void *xd
    );

//
// This function is called to de-register a policy with the MAC framework.
// A policy module will typically call this from the Darwin KEXT de-registration routine.
//

extern
int
mac_policy_unregister(
    mac_policy_handle_t handle
    );

//
// Declaration
//

extern OSMallocTag gmalloc_tag;

extern lck_mtx_t *gmac_policy_lock;

extern lck_mtx_t *goskext_handler_lock;

extern kmod_info_t *gkmod_item;

extern vm_address_t gkext_base;

extern vm_size_t gkext_size;

extern char *gkext_name;

extern
int
construct_path_from_vnode(
    vnode_t node,
    char **path
    );

extern
kern_return_t
mac_initialization(
    boolean_t flag
    );

#endif