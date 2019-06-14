/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    inline.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#include <i386/proc_reg.h>
#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include "distorm/include/distorm.h"
#include "include.h"
#include "nke.h"
#include "policy.h"
#include "trace.h"
#include "inline.h"


//
// Base address of the OSKext::start()
//

unsigned char *goskext_start;
unsigned char *goskext_call_func;

//
// Call hook mode
//

boolean_t goskext_call_func_2_bytes;
boolean_t goskext_call_func_3_bytes;

//
// OSKext::start() module information and mutex lock
//

char *gkext_name;
vm_address_t gkext_base;
vm_size_t gkext_size;

lck_mtx_t *goskext_handler_lock;

//
// Enable and disable interrupts
//

#define disable_interrupts() __asm__ volatile ("cli");

#define enable_interrupts() __asm__ volatile ("sti");

//
// CR0 and mutex lock
//

static unsigned long cr0;

static lck_mtx_t *cr0_lock;

//
// Disable the write protection bit in CR0 register
//

static
void
disable_write_protection(
    )
{
    //
    // Retrieve current value
    //

    lck_mtx_lock(cr0_lock);

    unsigned long local_cr0 = cr0 = get_cr0();

    //
    // Remove the CR0_WP bit
    //

    local_cr0 &= ~CR0_WP;

    //
    // Write CR0 back
    //

    set_cr0(local_cr0);
}

//
// Enable the write protection bit in CR0 register
//

static
void
enable_write_protection(
    )
{
    //
    // Write CR0 back
    //

    set_cr0(cr0);

    lck_mtx_unlock(cr0_lock);
}

//
// Trampoline of the mac_policy_register()
//

__attribute__ ((naked))
void
mac_policy_register_trampoline(
    )
{
    __asm__ volatile ("nop"); // 01
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 10
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 20
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 30

    __asm__ volatile ("pushfq");
    __asm__ volatile ("push %rax");
    __asm__ volatile ("push %rbx"); // Callee
    __asm__ volatile ("push %rcx");
    __asm__ volatile ("push %rdx");
    __asm__ volatile ("push %rbp"); // Callee
    __asm__ volatile ("push %rsi");
    __asm__ volatile ("push %rdi");
    __asm__ volatile ("push %r8");
    __asm__ volatile ("push %r9");
    __asm__ volatile ("push %r10");
    __asm__ volatile ("push %r11");
    __asm__ volatile ("push %r12"); // Callee
    __asm__ volatile ("push %r13"); // Callee
    __asm__ volatile ("push %r14"); // Callee
    __asm__ volatile ("push %r15"); // Callee
    __asm__ volatile ("call *%0\n"
                      :
                      : "m" (jmp_to_mac_policy_register_prologue_handler));
    __asm__ volatile ("pop %r15");  // Callee
    __asm__ volatile ("pop %r14");  // Callee
    __asm__ volatile ("pop %r13");  // Callee
    __asm__ volatile ("pop %r12");  // Callee
    __asm__ volatile ("pop %r11");
    __asm__ volatile ("pop %r10");
    __asm__ volatile ("pop %r9");
    __asm__ volatile ("pop %r8");
    __asm__ volatile ("pop %rdi");
    __asm__ volatile ("pop %rsi");
    __asm__ volatile ("pop %rbp");  // Callee
    __asm__ volatile ("pop %rdx");
    __asm__ volatile ("pop %rcx");
    __asm__ volatile ("pop %rbx");  // Callee
    __asm__ volatile ("pop %rax");
    __asm__ volatile ("popfq");

    __asm__ volatile ("jmp *%0\n"
                      :
                      : "m" (jmp_back_to_mac_policy_register));
    __asm__ volatile ("int3");
}

static
void
mac_policy_register_prologue_handler(
    struct mac_policy_conf *mpc,
    mac_policy_handle_t *handlep,
    void *xd
    )
{
    if (mpc) {
    #if MAC_TROUBLESHOOTING
        printf("[%s.kext] : In the mac_policy_register callback handler. %s\n",
               DRIVER_NAME,
               MAC_POLICY_REGISTER_INJECTION ?
               "<blocking it!>" : "");
    #   if MAC_POLICY_SHADOW_WALKER
        char policy_buffer[0x100];
        unsigned long policy_length;

        policy_length = sizeof(policy_buffer);
        memset(policy_buffer, 0, policy_length);

        int length = snprintf(policy_buffer, policy_length,
                              "[%s.kext] : macOS MAC policy version=%d, policy name=%s(%s), load time flags=%d(%s), policy mpc=%p, policy ops=%p.\n",
                              DRIVER_NAME,
                              MAC_POLICY_OPS_VERSION,
                              mpc->mpc_name, mpc->mpc_fullname,
                              mpc->mpc_loadtime_flags,
                              get_loadtime_option(mpc->mpc_loadtime_flags),
                              mpc, mpc->mpc_ops);
        if (length < SNPRINTF_LENGTH_LIMIT) {
            printf("%s", policy_buffer);
        } else {
            //
            // For macOS 10.14 Mojave
            //

            memset(policy_buffer, 0, policy_length);

            snprintf(policy_buffer, policy_length,
                     "[%s.kext] : macOS MAC policy version=%d, policy name=%s(%s), load time flags=%d, policy mpc=%p, policy ops=%p.\n",
                     DRIVER_NAME,
                     MAC_POLICY_OPS_VERSION,
                     mpc->mpc_name, mpc->mpc_fullname,
                     mpc->mpc_loadtime_flags,
                     mpc, mpc->mpc_ops);
            printf("%s", policy_buffer);
        }

        //
        // Please note that the MAC_POLICY_OPS_VERSION is 55 (xnu-4903.221.2)
        //

        if (mpc->mpc_ops)
            show_mac_policy_handlers(mpc->mpc_ops);
    #   endif // MAC_POLICY_SHADOW_WALKER
    #endif // MAC_TROUBLESHOOTING

    #if MAC_POLICY_REGISTER_INJECTION
        //
        // Returns EEXIST :P
        //

        mpc->mpc_name = gmpc_name_amfi;
    #endif
    }
}

static
void
unhook_mac_policy_register_prologue(
    void *target,
    unsigned int size
    )
{
    void *prologue = (void *) mac_policy_register_trampoline;

    disable_interrupts();
    disable_write_protection();

    //
    // Unhook the mac_policy_register's prologue
    //

    memcpy(target, prologue, size);

    enable_write_protection();
    enable_interrupts();

    mac_policy_register_original_size = 0;
    mac_policy_register_inline_hooked = FALSE;
}

static
void
inline_hook_mac_policy_register_prologue(
    void *target,
    unsigned int size
    )
{
    void *prologue = (void *) mac_policy_register_trampoline;

    disable_interrupts();
    disable_write_protection();

    memcpy(prologue, target, size);

    jmp_to_mac_policy_register_prologue_handler =
        (uint64_t) mac_policy_register_prologue_handler;

    jmp_back_to_mac_policy_register =
        (uint64_t) ((char *) target + size);

    *(uint64_t *) (mac_policy_register_inline + 2) =
        (uint64_t) prologue;

    //
    // Inline hook the mac_policy_register's prologue
    //

    memcpy(target, mac_policy_register_inline,
           sizeof(mac_policy_register_inline));

    enable_write_protection();
    enable_interrupts();

    mac_policy_register_inline_hooked = TRUE;
}

static
kern_return_t
inline_hook_mac_policy_register(
    boolean_t flag
    )
{
    kern_return_t status = KERN_FAILURE;

    if (flag && !mac_policy_register_original_size &&
        !mac_policy_register_inline_hooked) {
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

        unsigned char *buffer = (unsigned char *) mac_policy_register;

        //
        // Default offset for buffer is 0
        //

        _OffsetType offset = (_OffsetType) buffer;

        int length = SIZE_OF_MAC_POLICY_REGISTER_TRAMPOLINE;

        unsigned int total_bytes = 0;

    #if FRAMEWORK_TROUBLESHOOTING
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
            #if FRAMEWORK_TROUBLESHOOTING
                printf("[%s.kext] : Error! Could not disassemble the mac_policy_register().\n",
                       DRIVER_NAME);
            #endif

                break;
            }

            for (index = 0; index < decoded_instructions_count; index++) {
            #if FRAMEWORK_TROUBLESHOOTING
                printf("               (%02d) %s %s %s\n",
                       decoded_instructions[index].size,
                       (char *) decoded_instructions[index].instructionHex.p,
                       (char *) decoded_instructions[index].mnemonic.p,
                       (char *) decoded_instructions[index].operands.p);
            #endif

                total_bytes += decoded_instructions[index].size;

                if ((sizeof(mac_policy_register_inline)) <= total_bytes &&
                    SIZE_OF_MAC_POLICY_REGISTER_TRAMPOLINE > total_bytes) {
                    mac_policy_register_original_size = total_bytes;

                    inline_hook_mac_policy_register_prologue(mac_policy_register,
                                                             mac_policy_register_original_size);

                    status = KERN_SUCCESS;

                    decoded_instructions_count = 0;
                    break;
                }
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
    } else if (!flag && mac_policy_register_original_size &&
               mac_policy_register_inline_hooked) {
        unhook_mac_policy_register_prologue(mac_policy_register,
                                            mac_policy_register_original_size);

        status = KERN_SUCCESS;
    } else if (!flag && !mac_policy_register_original_size &&
               !mac_policy_register_inline_hooked) {
        status = KERN_SUCCESS;
    }

    return status;
}

//
// Trampoline of the OSKext::start()
//

__attribute__ ((naked))
void
oskext_start_trampoline(
    )
{
    __asm__ volatile ("nop"); // 01
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 10
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 20
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 30

    __asm__ volatile ("pushfq");
    __asm__ volatile ("push %rax");
    __asm__ volatile ("push %rbx"); // Callee
    __asm__ volatile ("push %rcx");
    __asm__ volatile ("push %rdx");
    __asm__ volatile ("push %rbp"); // Callee
    __asm__ volatile ("push %rsi");
    __asm__ volatile ("push %rdi");
    __asm__ volatile ("push %r8");
    __asm__ volatile ("push %r9");
    __asm__ volatile ("push %r10");
    __asm__ volatile ("push %r11");
    __asm__ volatile ("push %r12"); // Callee
    __asm__ volatile ("push %r13"); // Callee
    __asm__ volatile ("push %r14"); // Callee
    __asm__ volatile ("push %r15"); // Callee
    __asm__ volatile ("call *%0\n"
                      :
                      : "m" (jmp_to_oskext_start_prologue_handler));
    __asm__ volatile ("pop %r15");  // Callee
    __asm__ volatile ("pop %r14");  // Callee
    __asm__ volatile ("pop %r13");  // Callee
    __asm__ volatile ("pop %r12");  // Callee
    __asm__ volatile ("pop %r11");
    __asm__ volatile ("pop %r10");
    __asm__ volatile ("pop %r9");
    __asm__ volatile ("pop %r8");
    __asm__ volatile ("pop %rdi");
    __asm__ volatile ("pop %rsi");
    __asm__ volatile ("pop %rbp");  // Callee
    __asm__ volatile ("pop %rdx");
    __asm__ volatile ("pop %rcx");
    __asm__ volatile ("pop %rbx");  // Callee
    __asm__ volatile ("pop %rax");
    __asm__ volatile ("popfq");

    __asm__ volatile ("jmp *%0\n"
                      :
                      : "m" (jmp_back_to_oskext_start));
    __asm__ volatile ("int3");
}

//
// Trampoline of the "OSKext::start() -> startfunc(kmod_info, kmodStartData)"
//

__attribute__ ((naked))
void
oskext_call_trampoline(
    )
{
    //
    // Pre callback handler
    //

    __asm__ volatile ("pushfq");
    __asm__ volatile ("push %rax");
    __asm__ volatile ("push %rbx"); // Callee
    __asm__ volatile ("push %rcx");
    __asm__ volatile ("push %rdx");
    __asm__ volatile ("push %rbp"); // Callee
    __asm__ volatile ("push %rsi");
    __asm__ volatile ("push %rdi");
    __asm__ volatile ("push %r8");
    __asm__ volatile ("push %r9");
    __asm__ volatile ("push %r10");
    __asm__ volatile ("push %r11");
    __asm__ volatile ("push %r12"); // Callee
    __asm__ volatile ("push %r13"); // Callee
    __asm__ volatile ("push %r14"); // Callee
    __asm__ volatile ("push %r15"); // Callee
    __asm__ volatile ("call *%0\n"
                      :
                      : "m" (jmp_to_oskext_call_pre_handler));
    __asm__ volatile ("pop %r15");  // Callee
    __asm__ volatile ("pop %r14");  // Callee
    __asm__ volatile ("pop %r13");  // Callee
    __asm__ volatile ("pop %r12");  // Callee
    __asm__ volatile ("pop %r11");
    __asm__ volatile ("pop %r10");
    __asm__ volatile ("pop %r9");
    __asm__ volatile ("pop %r8");
    __asm__ volatile ("pop %rdi");
    __asm__ volatile ("pop %rsi");
    __asm__ volatile ("pop %rbp");  // Callee
    __asm__ volatile ("pop %rdx");
    __asm__ volatile ("pop %rcx");
    __asm__ volatile ("pop %rbx");  // Callee
    __asm__ volatile ("pop %rax");
    __asm__ volatile ("popfq");

    //
    // OSKext::start() -> startfunc(kmod_info, kmodStartData)
    //

    __asm__ volatile ("push %rsi");
    __asm__ volatile ("push %rdi");
    __asm__ volatile ("nop"); // 01
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 10
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop"); // 20
    __asm__ volatile ("pop %rdi");
    __asm__ volatile ("pop %rsi");

    //
    // Post callback handler
    //

    __asm__ volatile ("pushfq");
//  __asm__ volatile ("push %rax"); // Subvert the return value if needed
    __asm__ volatile ("push %rbx"); // Callee
    __asm__ volatile ("push %rcx");
    __asm__ volatile ("push %rdx");
    __asm__ volatile ("push %rbp"); // Callee
    __asm__ volatile ("push %rsi");
    __asm__ volatile ("push %rdi");
    __asm__ volatile ("push %r8");
    __asm__ volatile ("push %r9");
    __asm__ volatile ("push %r10");
    __asm__ volatile ("push %r11");
    __asm__ volatile ("push %r12"); // Callee
    __asm__ volatile ("push %r13"); // Callee
    __asm__ volatile ("push %r14"); // Callee
    __asm__ volatile ("push %r15"); // Callee
    __asm__ volatile ("xor %rsi, %rsi");
    __asm__ volatile ("mov %eax, %esi");
    __asm__ volatile ("call *%0\n"
                      :
                      : "m" (jmp_to_oskext_call_post_handler));
    __asm__ volatile ("pop %r15");  // Callee
    __asm__ volatile ("pop %r14");  // Callee
    __asm__ volatile ("pop %r13");  // Callee
    __asm__ volatile ("pop %r12");  // Callee
    __asm__ volatile ("pop %r11");
    __asm__ volatile ("pop %r10");
    __asm__ volatile ("pop %r9");
    __asm__ volatile ("pop %r8");
    __asm__ volatile ("pop %rdi");
    __asm__ volatile ("pop %rsi");
    __asm__ volatile ("pop %rbp");  // Callee
    __asm__ volatile ("pop %rdx");
    __asm__ volatile ("pop %rcx");
    __asm__ volatile ("pop %rbx");  // Callee
//  __asm__ volatile ("pop %rax");  // Subvert the return value if needed
    __asm__ volatile ("popfq");

    __asm__ volatile ("jmp *%0\n"
                      :
                      : "m" (jmp_back_to_oskext_call));
    __asm__ volatile ("int3");
}

static
boolean_t
check_kext_policy(
    kmod_info_t *info
    )
{
    //
    // Check policy
    //

    ;

    return TRUE;
}

static
kern_return_t
oskext_call_post_handler(
    kmod_info_t *info,
    kern_return_t status
    )
{
    size_t data_length;
    struct kernel_module_monitoring *message;

    message = OSMalloc((uint32_t) sizeof(*message),
                       gmalloc_tag);
    if (message) {
        memset(message, 0, sizeof(*message));

        //
        // Message header
        //

        microtime(&(message->header.event_time));
        message->header.type = MONITORING_KEXT_POST_CALLBACK;

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

        message->return_value = status;
        message->module_base = info->address;
        message->module_size = info->size;

        data_length = strlen((const char *) info->name);
        memcpy(message->module_name,
               (const char *) info->name,
               (data_length <= MAXPATHLEN - 1) ?
               data_length : MAXPATHLEN - 1);

        data_length = strlen((const char *) info->version);
        memcpy(message->module_version,
               (const char *) info->version,
               (data_length <= MAXPATHLEN - 1) ?
               data_length : MAXPATHLEN - 1);

        send_message((struct message_header *) message);
    }

    char kext_buffer[0x100];
    unsigned long kext_length;

    kext_length = sizeof(kext_buffer);
    memset(kext_buffer, 0, kext_length);

    snprintf(kext_buffer, kext_length,
             "[%s.kext] : In the kext post callback handler. status=%d, name=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
             DRIVER_NAME, status,
             info->name, info->version,
             info->address, info->size);
    printf("%s", kext_buffer);

    if (message)
        OSFree(message,
               (uint32_t) sizeof(*message),
               gmalloc_tag);

    //
    // For MAC policy monitoring
    //

    lck_mtx_lock(goskext_handler_lock);

    gkext_name = NULL;
    gkext_base = gkext_size = 0;

    lck_mtx_unlock(goskext_handler_lock);

    //
    // Subvert the return value if needed
    //

    return status;
}

static
void
oskext_call_pre_handler(
    kmod_info_t *info,
    void *data
    )
{
#pragma unused(data)

    char kext_buffer[0x100];
    unsigned long kext_length;

    kext_length = sizeof(kext_buffer);
    memset(kext_buffer, 0, kext_length);

    if (!check_kext_policy(info)) {
        disable_interrupts();
        disable_write_protection();

        //
        // Does it have enough room for KERN_FAILURE or KERN_SUCCESS?
        //

        memcpy(info->start, returns_five,
               sizeof(returns_five));

        enable_write_protection();
        enable_interrupts();

        snprintf(kext_buffer, kext_length,
                 "[%s.kext] : In the kext pre callback handler. Patching the driver entry point! name=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
                 DRIVER_NAME, info->name, info->version,
                 info->address, info->size);
        printf("%s", kext_buffer);
    } else {
        snprintf(kext_buffer, kext_length,
                 "[%s.kext] : In the kext pre callback handler. name=%s, version=%s, module base=0x%lx, module size=0x%lx.\n",
                 DRIVER_NAME, info->name, info->version,
                 info->address, info->size);
        printf("%s", kext_buffer);

        //
        // For MAC policy monitoring
        //

        lck_mtx_lock(goskext_handler_lock);

        gkext_name = info->name;
        gkext_base = info->address;
        gkext_size = info->size;

        lck_mtx_unlock(goskext_handler_lock);
    }
}

static
void
unhook_oskext_call(
    void *target,
    unsigned int size
    )
{
    void *trampoline = (void *) oskext_call_trampoline;

    disable_interrupts();
    disable_write_protection();

    //
    // Unhook the call instruction
    //

    memcpy(target,
           (void *) ((char *) trampoline +
           OFFSET_OF_OSKEXT_CALL_TRAMPOLINE),
           size);

    enable_write_protection();
    enable_interrupts();

    oskext_call_original_size = 0;
    oskext_call_inline_hooked = FALSE;
}

static
void
inline_hook_oskext_call(
    void *target,
    unsigned int size
    )
{
    void *trampoline = (void *) oskext_call_trampoline;

    disable_interrupts();
    disable_write_protection();

    //
    // Find an appropriate offset
    //

    memcpy((void *) ((char *) trampoline +
           OFFSET_OF_OSKEXT_CALL_TRAMPOLINE),
           target, size);

    jmp_to_oskext_call_pre_handler =
        (uint64_t) oskext_call_pre_handler;
    jmp_to_oskext_call_post_handler =
        (uint64_t) oskext_call_post_handler;

    jmp_back_to_oskext_call =
        (uint64_t) ((char *) target + size);

    //
    // Inline hook the call instruction
    //

    memcpy(target, oskext_call_inline,
           sizeof(oskext_call_inline));

    enable_write_protection();
    enable_interrupts();

    oskext_call_inline_hooked = TRUE;
}

static
void
oskext_start_prologue_handler(
    struct oskext *kext,
    boolean_t start_dependencies_flag
    )
{
#pragma unused(start_dependencies_flag)

    kmod_info_t *info;
    struct kernel_module_monitoring *message;

    struct osstring_el_capitan *path_el_capitan = NULL;
    struct osstring_macos_sierra *path_macos_sierra = NULL;
    struct osstring_macos_high_sierra *path_macos_high_sierra = NULL;
    struct osstring_macos_mojave *path_macos_mojave = NULL;
    struct osstring_macos_catalina *path_macos_catalina = NULL;

    if (kext) {
        if (MACOS_CATALINA == gmacOS_major)
            info = ((struct oskext_macos_catalina *) kext)->kmod_info;
        else
            info = kext->kmod_info;

        if (OS_X_EL_CAPITAN == gmacOS_major)
            path_el_capitan = kext->path;
        else if (MACOS_SIERRA == gmacOS_major)
            path_macos_sierra = kext->path;
        else if (MACOS_HIGH_SIERRA == gmacOS_major)
            path_macos_high_sierra = kext->path;
        else if (MACOS_MOJAVE == gmacOS_major)
            path_macos_mojave = kext->path;
        else if (MACOS_CATALINA == gmacOS_major)
            path_macos_catalina =
                ((struct oskext_macos_catalina *) kext)->path;
        else
            info = NULL;

        if ((path_el_capitan || path_macos_sierra ||
            path_macos_high_sierra || path_macos_mojave ||
            path_macos_catalina) && info) {
            size_t data_length;

            message = OSMalloc((uint32_t) sizeof(*message),
                               gmalloc_tag);
            if (message) {
                memset(message, 0, sizeof(*message));

                //
                // Message header
                //

                microtime(&(message->header.event_time));
                message->header.type = MONITORING_KEXT_PRE_CALLBACK;

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

                message->module_base = info->address;
                message->module_size = info->size;

                data_length = strlen((const char *) info->name);
                memcpy(message->module_name,
                       (const char *) info->name,
                       (data_length <= MAXPATHLEN - 1) ?
                       data_length : MAXPATHLEN - 1);

                if (OS_X_EL_CAPITAN == gmacOS_major &&
                    path_el_capitan) {
                    data_length = strlen((const char *) path_el_capitan->string);
                    memcpy(message->module_path,
                           (const char *) path_el_capitan->string,
                           (data_length <= MAXPATHLEN - 1) ?
                           data_length : MAXPATHLEN - 1);
                } else if (MACOS_SIERRA == gmacOS_major &&
                           path_macos_sierra) {
                    data_length = strlen((const char *) path_macos_sierra->string);
                    memcpy(message->module_path,
                           (const char *) path_macos_sierra->string,
                           (data_length <= MAXPATHLEN - 1) ?
                           data_length : MAXPATHLEN - 1);
                } else if (MACOS_HIGH_SIERRA == gmacOS_major &&
                           path_macos_high_sierra) {
                    data_length = strlen((const char *) path_macos_high_sierra->string);
                    memcpy(message->module_path,
                           (const char *) path_macos_high_sierra->string,
                           (data_length <= MAXPATHLEN - 1) ?
                           data_length : MAXPATHLEN - 1);
                } else if (MACOS_MOJAVE == gmacOS_major &&
                           path_macos_mojave) {
                    data_length = strlen((const char *) path_macos_mojave->string);
                    memcpy(message->module_path,
                           (const char *) path_macos_mojave->string,
                           (data_length <= MAXPATHLEN - 1) ?
                           data_length : MAXPATHLEN - 1);
                } else if (MACOS_CATALINA == gmacOS_major &&
                           path_macos_catalina) {
                    data_length = strlen((const char *) path_macos_catalina->string);
                    memcpy(message->module_path,
                           (const char *) path_macos_catalina->string,
                           (data_length <= MAXPATHLEN - 1) ?
                           data_length : MAXPATHLEN - 1);
                }

                data_length = strlen((const char *) info->version);
                memcpy(message->module_version,
                       (const char *) info->version,
                       (data_length <= MAXPATHLEN - 1) ?
                       data_length : MAXPATHLEN - 1);

                send_message((struct message_header *) message);
            }
        } else {
            //
            // EINVAL
            //

            return;
        }
    } else {
        //
        // EINVAL
        //

        return;
    }

    if (message)
        OSFree(message,
               (uint32_t) sizeof(*message),
               gmalloc_tag);

    //
    // Disassemble the "OSKext::start() -> startfunc(kmod_info, kmodStartData)"
    //

    if (!oskext_call_inline_hooked) {
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

        unsigned char *buffer;
        if (goskext_call_func_3_bytes)
            buffer = goskext_call_func - 3;
        else if (goskext_call_func_2_bytes)
            buffer = goskext_call_func - 2;
        else
            buffer = NULL;

        if (!buffer)
            return;

        //
        // Default offset for buffer is 0
        //

        _OffsetType offset = (_OffsetType) buffer;

        int length = 10;

        unsigned int total_bytes = 0;

    #if FRAMEWORK_TROUBLESHOOTING
        printf("[%s.kext] : Disassemble the OSKext::start(%s) -> startfunc(kmod_info, kmodStartData).\n",
               DRIVER_NAME, info->name);
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
            #if FRAMEWORK_TROUBLESHOOTING
                printf("[%s.kext] : Error! Could not disassemble the OSKext::start(%s) -> startfunc(kmod_info, kmodStartData).\n",
                       DRIVER_NAME, info->name);
            #endif

                break;
            }

            for (index = 0; index < decoded_instructions_count; index++) {
            #if FRAMEWORK_TROUBLESHOOTING
                printf("               (%02d) %s %s %s\n",
                       decoded_instructions[index].size,
                       (char *) decoded_instructions[index].instructionHex.p,
                       (char *) decoded_instructions[index].mnemonic.p,
                       (char *) decoded_instructions[index].operands.p);
            #endif

                total_bytes += decoded_instructions[index].size;

                //
                // Please be careful
                //

                if (sizeof(oskext_call_inline) <= total_bytes) {
                    oskext_call_original_size = total_bytes;

                    if (oskext_start_original_size &&
                        oskext_start_inline_hooked) {
                        if (goskext_call_func_3_bytes)
                            inline_hook_oskext_call(
                                (void *) (goskext_call_func - 3),
                                oskext_call_original_size);
                        else if (goskext_call_func_2_bytes)
                            inline_hook_oskext_call(
                                (void *) (goskext_call_func - 2),
                                oskext_call_original_size);
                    }

                    decoded_instructions_count = 0;
                    break;
                }
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
    }
}

static
void
unhook_oskext_start_prologue(
    void *target,
    unsigned int size
    )
{
    void *prologue = (void *) oskext_start_trampoline;

    disable_interrupts();
    disable_write_protection();

    //
    // Unhook the OSKext::start's prologue
    //

    memcpy(target, prologue, size);

    enable_write_protection();
    enable_interrupts();

    oskext_start_original_size = 0;
    oskext_start_inline_hooked = FALSE;
}

static
void
inline_hook_oskext_start_prologue(
    void *target,
    unsigned int size
    )
{
    void *prologue = (void *) oskext_start_trampoline;

    disable_interrupts();
    disable_write_protection();

    memcpy(prologue, target, size);

    jmp_to_oskext_start_prologue_handler =
        (uint64_t) oskext_start_prologue_handler;

    jmp_back_to_oskext_start =
        (uint64_t) ((char *) target + size);

    *(uint64_t *) (oskext_start_inline + 2) =
        (uint64_t) prologue;

    //
    // Inline hook the OSKext::start's prologue
    //

    memcpy(target, oskext_start_inline,
           sizeof(oskext_start_inline));

    //
    // Dig an eight-byte hole for call hook
    //

    *(uint64_t *) ((char *) target + sizeof(oskext_start_inline)) =
        (uint64_t) oskext_call_trampoline;

    //
    // Calculate offset
    //

    if (goskext_call_func_3_bytes)
        *(unsigned int *) (oskext_call_inline + 2) =
            (unsigned int) (0 - (goskext_call_func + 3 - // 3 + 3 = 6
            (goskext_start + sizeof(oskext_start_inline))));
    else if (goskext_call_func_2_bytes)
        *(unsigned int *) (oskext_call_inline + 2) =
            (unsigned int) (0 - (goskext_call_func + 4 - // 2 + 4 = 6
            (goskext_start + sizeof(oskext_start_inline))));

    enable_write_protection();
    enable_interrupts();

    oskext_start_inline_hooked = TRUE;
}

static
kern_return_t
inline_hook_oskext_start(
    boolean_t flag
    )
{
    kern_return_t status = KERN_FAILURE;

    if (flag && goskext_start && goskext_call_func &&
        !oskext_start_original_size && !oskext_start_inline_hooked &&
        !oskext_call_original_size && !oskext_call_inline_hooked &&
        (goskext_call_func_2_bytes || goskext_call_func_3_bytes)) {
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

        unsigned char *buffer = goskext_start;

        //
        // Default offset for buffer is 0
        //

        _OffsetType offset = (_OffsetType) buffer;

        int length = SIZE_OF_OSKEXT_START_TRAMPOLINE;

        unsigned int total_bytes = 0;

    #if FRAMEWORK_TROUBLESHOOTING
        printf("[%s.kext] : Disassemble the OSKext::start().\n",
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
            #if FRAMEWORK_TROUBLESHOOTING
                printf("[%s.kext] : Error! Could not disassemble the OSKext::start().\n",
                       DRIVER_NAME);
            #endif

                break;
            }

            for (index = 0; index < decoded_instructions_count; index++) {
            #if FRAMEWORK_TROUBLESHOOTING
                printf("               (%02d) %s %s %s\n",
                       decoded_instructions[index].size,
                       (char *) decoded_instructions[index].instructionHex.p,
                       (char *) decoded_instructions[index].mnemonic.p,
                       (char *) decoded_instructions[index].operands.p);
            #endif

                total_bytes += decoded_instructions[index].size;

                if ((sizeof(oskext_start_inline) + sizeof(void *)) <= total_bytes &&
                    SIZE_OF_OSKEXT_START_TRAMPOLINE > total_bytes) {
                    oskext_start_original_size = total_bytes;

                    inline_hook_oskext_start_prologue(goskext_start,
                                                      oskext_start_original_size);

                    status = KERN_SUCCESS;

                    decoded_instructions_count = 0;
                    break;
                }
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
    } else if (!flag && goskext_start && goskext_call_func &&
               oskext_start_original_size &&
               oskext_start_inline_hooked) {
        unhook_oskext_start_prologue(goskext_start,
                                     oskext_start_original_size);

        if (oskext_call_original_size &&
            oskext_call_inline_hooked) {
            if (goskext_call_func_3_bytes)
                unhook_oskext_call((void *) (goskext_call_func - 3),
                                   oskext_call_original_size);
            else if (goskext_call_func_2_bytes)
                unhook_oskext_call((void *) (goskext_call_func - 2),
                                   oskext_call_original_size);
        }

        status = KERN_SUCCESS;
    } else if (!flag && goskext_start && goskext_call_func &&
               !oskext_start_original_size &&
               !oskext_start_inline_hooked) {
        status = KERN_SUCCESS;
    } else if (!flag && !goskext_start && !goskext_call_func) {
        //
        // Unknown platform
        //

        status = KERN_SUCCESS;
    }

    return status;
}

extern
kern_return_t
inline_initialization(
    boolean_t flag
    )
{
    kern_return_t status;

    if (flag) {
        if (!glock_group)
            return KERN_FAILURE;

        cr0_lock = lck_mtx_alloc_init(glock_group,
                                      LCK_ATTR_NULL);
        if (!cr0_lock)
            return KERN_FAILURE;

        goskext_handler_lock = lck_mtx_alloc_init(glock_group,
                                                  LCK_ATTR_NULL);
        if (!goskext_handler_lock)
            return KERN_FAILURE;
    }

    //
    // 1. OSKext::start()
    //
    // TODO: Use the KeSetAffinityThread + KeGetCurrentProcessorNumber +
    //       KeSetTargetProcessorDpc + KeInsertQueueDpc or similar method
    //

    status = inline_hook_oskext_start(flag);
    if (KERN_SUCCESS != status) {
    #if FRAMEWORK_TROUBLESHOOTING
        printf("[%s.kext] : Error! inline_hook_oskext_start(%s) failed, status=%d.\n",
               DRIVER_NAME, flag ? "true" : "false",
               status);
    #endif

        goto out_lck_mtx_free;
    }

    //
    // 2. mac_policy_register()
    //
    // TODO: Use the KeSetAffinityThread + KeGetCurrentProcessorNumber +
    //       KeSetTargetProcessorDpc + KeInsertQueueDpc or similar method
    //

    status = inline_hook_mac_policy_register(flag);
    if (KERN_SUCCESS != status) {
    #if FRAMEWORK_TROUBLESHOOTING
        printf("[%s.kext] : Error! inline_hook_mac_policy_register(%s) failed, status=%d.\n",
               DRIVER_NAME, flag ? "true" : "false",
               status);
    #endif

        goto out_lck_mtx_free;
    }

out_lck_mtx_free:
    if (!flag) {
        if (goskext_handler_lock && glock_group) {
            lck_mtx_free(goskext_handler_lock,
                         glock_group);

            goskext_handler_lock = NULL;
        }

        if (cr0_lock && glock_group) {
            lck_mtx_free(cr0_lock,
                         glock_group);

            cr0_lock = NULL;
        }
    }

    return status;
}