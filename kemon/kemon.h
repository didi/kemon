/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    kemon.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __KEMON_DRIVER_H__
#define __KEMON_DRIVER_H__


//
// macOS version
//

int gmacOS_major;
int gmacOS_minor;
const char *gmacOS_version;

//
// The kmod_info_t linked list
//

kmod_info_t *gkmod_info;

//
// Global resources
//

#define DRIVER_TAG_NAME "com.assuresec.kemon"

OSMallocTag gmalloc_tag;

//
// Lock group
//

lck_grp_t *glock_group;

//
// kauth_configuration[length] holds current configuration string
//

#define kauth_configuration_length 0x1000

static char kauth_configuration[kauth_configuration_length];

//
// Kauth configuration mutex lock
//

static lck_mtx_t *kauth_configuration_lock;

//
// Points into kauth_configuration[length]
//

static const char *kauth_configuration_prefix;

//
// The maximum length of the listener scope and action string
//

#define max_string_length 0x4000

//
// An area of interest for Kauth
//

static char *kauth_listener_scope;

//
// kauth_listener is our handle to the installed scope listener
//

static kauth_listener_t kauth_listener;

//
// Kauth counter
//

static SInt32 kauth_activation_count;

//
// "com.apple.kauth.fileop" is the default setting of our Kauth listener
//

#define KAUTH_DEFAULT_SETTING TRUE

#if KAUTH_DEFAULT_SETTING
#   define DEFAULT_SETTING "add com.apple.kauth.fileop"
#endif

//
// For macOS 10.14 Mojave
//

#ifndef KAUTH_FILEOP_WILL_RENAME
#   define KAUTH_FILEOP_WILL_RENAME 8
#endif

//
// For macOS 10.15 Catalina
//

static boolean_t process_namespace_fsctl_removed;

//
// vnode_action_info describes one of the action bits in the vnode scope's action field
//

struct vnode_action_info {
    kauth_action_t mask;        // only one bit should be set
    const char *name_file;      // descriptive name of the bit for files
    const char *name_directory; // descriptive name of the bit for directories
};

//
// Make it easier to initialize vnode_action_table
//

#define VNODE_ACTION(action) \
    {KAUTH_VNODE_ ## action, #action, NULL}

#define VNODE_ACTION_FILEDIR(action_file, action_directory) \
    {KAUTH_VNODE_ ## action_file, #action_file, #action_directory}

//
// vnode_action_table is a table of all the known action bits and their human readable names
//

static const struct vnode_action_info vnode_action_table[] = {
    VNODE_ACTION_FILEDIR(READ_DATA, LIST_DIRECTORY),     // 1 << 1
                                                         // #define KAUTH_VNODE_LIST_DIRECTORY KAUTH_VNODE_READ_DATA
    VNODE_ACTION_FILEDIR(WRITE_DATA, ADD_FILE),          // 1 << 2
                                                         // #define KAUTH_VNODE_ADD_FILE KAUTH_VNODE_WRITE_DATA
    VNODE_ACTION_FILEDIR(EXECUTE, SEARCH),               // 1 << 3
                                                         // #define KAUTH_VNODE_SEARCH KAUTH_VNODE_EXECUTE
    VNODE_ACTION(DELETE),                                // 1 << 4
    VNODE_ACTION_FILEDIR(APPEND_DATA, ADD_SUBDIRECTORY), // 1 << 5
                                                         // #define KAUTH_VNODE_ADD_SUBDIRECTORY KAUTH_VNODE_APPEND_DATA
    VNODE_ACTION(DELETE_CHILD),                          // 1 << 6
    VNODE_ACTION(READ_ATTRIBUTES),                       // 1 << 7
    VNODE_ACTION(WRITE_ATTRIBUTES),                      // 1 << 8
    VNODE_ACTION(READ_EXTATTRIBUTES),                    // 1 << 9
    VNODE_ACTION(WRITE_EXTATTRIBUTES),                   // 1 << 10
    VNODE_ACTION(READ_SECURITY),                         // 1 << 11
    VNODE_ACTION(WRITE_SECURITY),                        // 1 << 12
    VNODE_ACTION_FILEDIR(TAKE_OWNERSHIP, CHANGE_OWNER),  // 1 << 13
                                                         // #define KAUTH_VNODE_CHANGE_OWNER KAUTH_VNODE_TAKE_OWNERSHIP
    VNODE_ACTION(SYNCHRONIZE),                           // 1 << 20
    VNODE_ACTION(LINKTARGET),                            // 1 << 25
    VNODE_ACTION(CHECKIMMUTABLE),                        // 1 << 26
    VNODE_ACTION(SEARCHBYANYONE),                        // 1 << 29
    VNODE_ACTION(NOIMMUTABLE),                           // 1 << 30
    VNODE_ACTION(ACCESS),                                // 1 << 31
};

#define vnode_action_count (sizeof(vnode_action_table) / sizeof(*vnode_action_table))

enum two_pass_algorithm {
    calculate_length,
    allocate_string
};

//
// For file creation
//

static unsigned char rbp_offset;

static SInt32 process_namespace_fsctl_count;

static boolean_t unknown_platform_fileop_open;

//
// For process command line
//

static boolean_t image_params_in_r15;
static boolean_t image_params_in_r14;
static boolean_t image_params_in_r13;
static boolean_t image_params_in_r12;

static UInt32 exec_activate_image_in_progress;

static boolean_t unknown_platform_fileop_exec;

//
// image_params has been documented (/bsd/sys/imgact.h):
// https://developer.apple.com/reference/kernel/image_params
//

#define IMG_SHELL_SIZE 512

struct image_params {
    user_addr_t ip_user_fname;
    user_addr_t ip_user_argv;
    user_addr_t ip_user_envv;
    int ip_seg;
    struct vnode *ip_vp;
    struct vnode_attr *ip_vattr;
    struct vnode_attr *ip_origvattr;
    cpu_type_t ip_origcputype;
    cpu_subtype_t ip_origcpusubtype;
    char *ip_vdata;
    int ip_flags;
    int ip_argc;
    int ip_envc;
    int ip_applec;
    char *ip_startargv;
    char *ip_endargv;
    char *ip_endenvv;
    char *ip_strings;
    char *ip_strendp;
    int ip_argspace;
    int ip_strspace;
    user_size_t ip_arch_offset;
    user_size_t ip_arch_size;
    char ip_interp_buffer[IMG_SHELL_SIZE];
    int ip_interp_sugid_fd;
    struct vfs_context *ip_vfs_context;
    struct nameidata *ip_ndp;
    thread_t ip_new_thread;
    struct label *ip_execlabelp;
    struct label *ip_scriptlabelp;
    struct vnode *ip_scriptvp;
    unsigned int ip_csflags;
    int ip_mac_return;
    void *ip_px_sa;
    void *ip_px_sfa;
    void *ip_px_spa;
    void *ip_px_smpx;
    void *ip_px_persona;
    void *ip_cs_error;

    //
    // xnu-4570
    //

    uint64_t ip_dyld_fsid;
    uint64_t ip_dyld_fsobjid;
};

//
// oid_registered tracks whether we've registered our OID or not
//

static UInt32 oid_registered;

//
// Declaration
//

extern
kern_return_t
kemon_start(
    kmod_info_t *kmod_info,
    void *data
    );

extern
kern_return_t
kemon_stop(
    kmod_info_t *kmod_info,
    void *data
    );

#endif