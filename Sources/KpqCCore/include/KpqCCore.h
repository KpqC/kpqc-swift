/* SPDX-License-Identifier: MIT */
#ifndef KPQC_CORE_H
#define KPQC_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__has_attribute)
#if __has_attribute(swift_private)
#define KPQC_SWIFT_PRIVATE __attribute__((swift_private))
#endif
#endif
#ifndef KPQC_SWIFT_PRIVATE
#define KPQC_SWIFT_PRIVATE
#endif

#define KPQC_DECLARE_SIGNATURE(name)                                         \
    int kpqc_##name##_keypair(uint8_t *, uint8_t *) KPQC_SWIFT_PRIVATE;      \
    int kpqc_##name##_sign(uint8_t *, size_t *, const uint8_t *, size_t,     \
                           const uint8_t *, size_t, const uint8_t *)          \
        KPQC_SWIFT_PRIVATE;                                                   \
    int kpqc_##name##_verify(const uint8_t *, size_t, const uint8_t *,       \
                             size_t, const uint8_t *, size_t, const uint8_t *) \
        KPQC_SWIFT_PRIVATE

#define KPQC_DECLARE_KEM(name)                                               \
    int kpqc_##name##_keypair(uint8_t *, uint8_t *) KPQC_SWIFT_PRIVATE;      \
    int kpqc_##name##_encapsulate(uint8_t *, uint8_t *, const uint8_t *)     \
        KPQC_SWIFT_PRIVATE;                                                   \
    int kpqc_##name##_decapsulate(uint8_t *, const uint8_t *, const uint8_t *) \
        KPQC_SWIFT_PRIVATE

KPQC_DECLARE_SIGNATURE(aimer128f);
KPQC_DECLARE_SIGNATURE(aimer128s);
KPQC_DECLARE_SIGNATURE(aimer192f);
KPQC_DECLARE_SIGNATURE(aimer192s);
KPQC_DECLARE_SIGNATURE(aimer256f);
KPQC_DECLARE_SIGNATURE(aimer256s);
KPQC_DECLARE_SIGNATURE(haetae2);
KPQC_DECLARE_SIGNATURE(haetae3);
KPQC_DECLARE_SIGNATURE(haetae5);

KPQC_DECLARE_KEM(ntruplus768);
KPQC_DECLARE_KEM(ntruplus864);
KPQC_DECLARE_KEM(ntruplus1152);
KPQC_DECLARE_KEM(smaugt128);
KPQC_DECLARE_KEM(smaugt192);
KPQC_DECLARE_KEM(smaugt256);
KPQC_DECLARE_KEM(timer);

void kpqc_secure_zero(uint8_t *, size_t) KPQC_SWIFT_PRIVATE;

#undef KPQC_DECLARE_SIGNATURE
#undef KPQC_DECLARE_KEM
#undef KPQC_SWIFT_PRIVATE

#ifdef __cplusplus
}
#endif

#endif
