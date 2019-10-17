/*++

Copyright (c) Didi Research America. All rights reserved.

Module Name:

    trace.c

Author:

    Yu Wang, 08-Feb-2017

Revision History:

--*/


#include <libkern/libkern.h>
#include <sys/systm.h>
#include "trace.h"


extern
void
hex_printf(
    void *buffer,
    unsigned long length,
    unsigned long flag
    )
{
    int timer_chan;
    struct timespec timer;
    unsigned char hex_buffer[0x80];
    unsigned char *tmp_buffer = buffer;
    unsigned long hex_length = sizeof(hex_buffer);
    unsigned long line, index, character;

    if (!buffer || !length ||
        ((flag & HEX_PRINTF_W) && (length % sizeof(uint16_t))) ||
        ((flag & HEX_PRINTF_D) && (length % sizeof(uint32_t))) ||
        ((flag & HEX_PRINTF_Q) && (length % sizeof(uint64_t)))) return;

    timer_chan = 0;
    timer.tv_sec = 0; timer.tv_nsec = 800000;

    if (flag & HEX_PRINTF_B) {
        printf("                                     -*> MEMORY DUMP <*-                                      \n");
        printf("+---------------------+--------------------------------------------------+-------------------+\n");
        printf("|       ADDRESS       |  0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F | 0123456789ABCDEF  |\n");
        printf("| --------------------+--------------------------------------------------+------------------ |\n");

        for (index = 0; index < length; index += 0x10) {
            memset(hex_buffer, 0, hex_length);

            line = length - index > 0x10 ? 0x10 : length - index;

            snprintf((char *) hex_buffer, hex_length, "|  %16p | ", tmp_buffer + index);

            for (character = 0; character < line; character++) {
                if (sizeof(char) * 7 == character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%02x  ",
                             tmp_buffer[index + character]);
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%02x ",
                             tmp_buffer[index + character]);
            }

            for (; character < 0x10; character++) {
                if (sizeof(char) * 7 == character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%s",
                             "    ");
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%s",
                             "   ");
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "| ");

            for (character = 0; character < line; character++) {
                if (tmp_buffer[index + character] < 0x20 || tmp_buffer[index + character] > 0x7E)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             '.');
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             tmp_buffer[index + character]);
            }

            for (; character < 0x10; character++) {
                snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                         hex_length - strlen((char *) hex_buffer), "%c", ' ');
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "  |\n");

            printf("%s", hex_buffer);
        }

        printf("+---------------------+--------------------------------------------------+-------------------+\n");

        msleep(&timer_chan, NULL, PUSER, "hex_printf_b", &timer);
    } else if (flag & HEX_PRINTF_W) {
        printf("                                 -*> MEMORY DUMP <*-                                  \n");
        printf("+---------------------+------------------------------------------+-------------------+\n");
        printf("|       ADDRESS       |  1 0  3 2  5 4  7 6   9 8  B A  D C  F E | 0123456789ABCDEF  |\n");
        printf("| --------------------+------------------------------------------+------------------ |\n");

        for (index = 0; index < length; index += 0x10) {
            memset(hex_buffer, 0, hex_length);

            line = length - index > 0x10 ? 0x10 : length - index;

            snprintf((char *) hex_buffer, hex_length, "|  %16p | ", tmp_buffer + index);

            for (character = 0; character < line; character += sizeof(uint16_t)) {
                if (sizeof(uint16_t) * 3 == character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%04x  ",
                             *(unsigned short *) (tmp_buffer + index + character));
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%04x ",
                             *(unsigned short *) (tmp_buffer + index + character));
            }

            for (; character < 0x10; character += sizeof(uint16_t)) {
                if (sizeof(uint16_t) * 3 == character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%s",
                             "      ");
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%s",
                             "     ");
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "| ");

            for (character = 0; character < line; character++) {
                if (tmp_buffer[index + character] < 0x20 || tmp_buffer[index + character] > 0x7E)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             '.');
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             tmp_buffer[index + character]);
            }

            for (; character < 0x10; character++) {
                snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                         hex_length - strlen((char *) hex_buffer), "%c", ' ');
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "  |\n");

            printf("%s", hex_buffer);
        }

        printf("+---------------------+------------------------------------------+-------------------+\n");

        msleep(&timer_chan, NULL, PUSER, "hex_printf_w", &timer);
    } else if (flag & HEX_PRINTF_D) {
        printf("                               -*> MEMORY DUMP <*-                                \n");
        printf("+---------------------+--------------------------------------+-------------------+\n");
        printf("|       ADDRESS       |  3 2 1 0  7 6 5 4   B A 9 8  F E D C | 0123456789ABCDEF  |\n");
        printf("| --------------------+--------------------------------------+------------------ |\n");

        for (index = 0; index < length; index += 0x10) {
            memset(hex_buffer, 0, hex_length);

            line = length - index > 0x10 ? 0x10 : length - index;

            snprintf((char *) hex_buffer, hex_length, "|  %16p | ", tmp_buffer + index);

            for (character = 0; character < line; character += sizeof(uint32_t)) {
                if (sizeof(uint32_t) == character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%08x  ",
                             *(unsigned int *) (tmp_buffer + index + character));
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%08x ",
                             *(unsigned int *) (tmp_buffer + index + character));
            }

            for (; character < 0x10; character += sizeof(uint32_t)) {
                if (sizeof(uint32_t) == character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%s",
                             "          ");
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%s",
                             "         ");
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "| ");

            for (character = 0; character < line; character++) {
                if (tmp_buffer[index + character] < 0x20 || tmp_buffer[index + character] > 0x7E)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             '.');
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             tmp_buffer[index + character]);
            }

            for (; character < 0x10; character++) {
                snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                         hex_length - strlen((char *) hex_buffer), "%c", ' ');
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "  |\n");

            printf("%s", hex_buffer);
        }

        printf("+---------------------+--------------------------------------+-------------------+\n");

        msleep(&timer_chan, NULL, PUSER, "hex_printf_d", &timer);
    } else if (flag & HEX_PRINTF_Q) {
        printf("                               -*> MEMORY DUMP <*-                                \n");
        printf("+---------------------+--------------------------------------+-------------------+\n");
        printf("|       ADDRESS       |  7 6 5 4  3 2 1 0   F E D C  B A 9 8 | 0123456789ABCDEF  |\n");
        printf("| --------------------+--------------------------------------+------------------ |\n");

        for (index = 0; index < length; index += 0x10) {
            memset(hex_buffer, 0, hex_length);

            line = length - index > 0x10 ? 0x10 : length - index;

            snprintf((char *) hex_buffer, hex_length, "|  %16p | ", tmp_buffer + index);

            for (character = 0; character < line; character += sizeof(uint64_t)) {
                if (!character)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%08x`%08x  ",
                             *(unsigned int *) (tmp_buffer + index + character + sizeof(uint32_t) * 1),
                             *(unsigned int *) (tmp_buffer + index + character + sizeof(uint32_t) * 0));
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%08x`%08x ",
                             *(unsigned int *) (tmp_buffer + index + character + sizeof(uint32_t) * 1),
                             *(unsigned int *) (tmp_buffer + index + character + sizeof(uint32_t) * 0));
            }

            for (; character < 0x10; character += sizeof(uint64_t)) {
                snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                         hex_length - strlen((char *) hex_buffer), "%s",
                         "                  ");
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "| ");

            for (character = 0; character < line; character++) {
                if (tmp_buffer[index + character] < 0x20 || tmp_buffer[index + character] > 0x7E)
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             '.');
                else
                    snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                             hex_length - strlen((char *) hex_buffer), "%c",
                             tmp_buffer[index + character]);
            }

            for (; character < 0x10; character++) {
                snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                         hex_length - strlen((char *) hex_buffer), "%c", ' ');
            }

            snprintf(((char *) hex_buffer + strlen((char *) hex_buffer)),
                     hex_length - strlen((char *) hex_buffer), "%s", "  |\n");

            printf("%s", hex_buffer);
        }

        printf("+---------------------+--------------------------------------+-------------------+\n");

        msleep(&timer_chan, NULL, PUSER, "hex_printf_q", &timer);
    }
}