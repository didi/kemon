/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    inline.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __INLINE_DRIVER_H__
#define __INLINE_DRIVER_H__


//
// 48 b8 00 00 00 00 00 00 00 00   movabsq $0x0, %rax
// ff e0                           jmpq   *%rax
//

static char mac_policy_register_inline[12] =
"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
"\xff\xe0";

//
// Please be careful if you want to modify the mac_policy_register_trampoline()
//

#define SIZE_OF_MAC_POLICY_REGISTER_TRAMPOLINE 30

static uint64_t jmp_to_mac_policy_register_prologue_handler;
static uint64_t jmp_back_to_mac_policy_register;

static uint32_t mac_policy_register_original_size;
static boolean_t mac_policy_register_inline_hooked;

//
// Returns EEXIST
//

#define MAC_POLICY_REGISTER_INJECTION TRUE

#if MAC_POLICY_REGISTER_INJECTION
static char *gmpc_name_amfi = "AMFI";
static char *gmpc_name_sandbox = "Sandbox";
#endif

//
// 48 b8 00 00 00 00 00 00 00 00   movabsq $0x0, %rax
// ff e0                           jmpq   *%rax
//

static char oskext_start_inline[12] =
"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
"\xff\xe0";

//
// Please be careful if you want to modify the oskext_start_trampoline()
//

#define SIZE_OF_OSKEXT_START_TRAMPOLINE 30

static uint64_t jmp_to_oskext_start_prologue_handler;
static uint64_t jmp_back_to_oskext_start;

static uint32_t oskext_start_original_size;
static boolean_t oskext_start_inline_hooked;

//
// ff 25 00 00 00 00   jmpq   *(%rip)
//

static char oskext_call_inline[6] =
"\xff\x25\x00\x00\x00\x00";

//
// Please be careful if you want to modify the oskext_call_trampoline()
//

#define OFFSET_OF_OSKEXT_CALL_TRAMPOLINE 60

static uint64_t jmp_to_oskext_call_pre_handler;
static uint64_t jmp_to_oskext_call_post_handler;
static uint64_t jmp_back_to_oskext_call;

static uint32_t oskext_call_original_size;
static boolean_t oskext_call_inline_hooked;

//
// b8 05 00 00 00   movl   $0x5, %eax
// c3               retq
//

static char returns_five[6] =
"\xb8\x05\x00\x00\x00"
"\xc3";

//
// 31 c0   xorl   %eax, %eax
// c3      retq
//

static char returns_zero[3] =
"\x31\xc0"
"\xc3";

//
// OSString
//

struct osstring_el_capitan {
    void *osobject;
    unsigned long retain_count;
    unsigned int length;
    unsigned int flags;
    char *string;
};

struct osstring_macos_sierra {
    void *osobject;
    unsigned long retain_count;
    char *string;
    unsigned int length;
    unsigned int flags;
};

struct osstring_macos_high_sierra {
    void *osobject;
    unsigned long retain_count;
    char *string;
    unsigned int flags;
    unsigned int length;
};

struct osstring_macos_mojave {
    void *osobject;
    unsigned long retain_count;
    char *string;
    unsigned int flags;
    unsigned int length;
};

//
// OSKext
//

struct oskext {
    void *osobject;
    unsigned long retain_count;
    void *info_dict;
    void *bundle_id;
    void *path;
    void *executable_path;
    unsigned long version;
    unsigned long compatible_version;
    unsigned long load_tag;
    kmod_info_t *kmod_info;
};

//
// Base address of the OSKext::start()
//

extern unsigned char *goskext_start;
extern unsigned char *goskext_call_func;

//
// Call hook mode
//

extern boolean_t goskext_call_func_2_bytes;
extern boolean_t goskext_call_func_3_bytes;

//
// Declaration
//

extern int gmacOS_major;

extern lck_grp_t *glock_group;

extern OSMallocTag gmalloc_tag;

#if MAC_POLICY_SHADOW_WALKER
extern
const char *
get_loadtime_option(
    int flags
    );

extern
void
show_mac_policy_handlers(
    struct mac_policy_ops *ops
    );
#endif // MAC_POLICY_SHADOW_WALKER

//
// This function is called to register a policy with the MAC framework
// A policy module will typically call this from the Darwin KEXT registration routine
//

extern
int
mac_policy_register(
    struct mac_policy_conf *mpc,
    mac_policy_handle_t *handlep,
    void *xd
    );

extern
kern_return_t
inline_initialization(
    boolean_t flag
    );

#endif