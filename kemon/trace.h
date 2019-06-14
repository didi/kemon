/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    trace.h

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#ifndef __TRACE_DRIVER_H__
#define __TRACE_DRIVER_H__


//
// Driver name and version
//

#define DRIVER_NAME "Kemon"

enum driver_version {
    ALPHA_VERSION_08_FEB_2017 = 0x01000001,
    ALPHA_VERSION_12_DEC_2018 = 0x01000010,
    ALPHA_VERSION_05_JUN_2019 = 0x01000011,
    RELEASE_VERSION
};

#define CURRENT_VERSION RELEASE_VERSION - 1

//
// Kemon framework troubleshooting
//

#define FRAMEWORK_TROUBLESHOOTING TRUE

//
// Kernel authorization troubleshooting
//

#define KAUTH_TROUBLESHOOTING FALSE

//
// Socket filter troubleshooting
//

#define SFLT_TROUBLESHOOTING FALSE
#define SFLT_TRAFFIC_TROUBLESHOOTING FALSE

//
// MAC policy troubleshooting
//

#define MAC_TROUBLESHOOTING TRUE

//
// Breakpoint instruction
//

#define BreakPoint() __asm__ volatile ("int3");

//
// For macOS 10.14 Mojave
//

#define SNPRINTF_LENGTH_LIMIT 0xF2

//
// Hex printf
//

#define HEX_PRINTF_B 0x01
#define HEX_PRINTF_W 0x02
#define HEX_PRINTF_D 0x04
#define HEX_PRINTF_Q 0x08

//
// Declaration
//

extern
void
hex_printf(
    void *buffer,
    unsigned long length,
    unsigned long flag
    );

#endif