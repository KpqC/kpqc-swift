/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdint.h>

void kpqc_secure_zero(uint8_t *bytes, size_t length) {
    volatile uint8_t *cursor = bytes;
    while (length-- > 0) *cursor++ = 0;
}
