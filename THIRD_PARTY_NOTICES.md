# Third-party notices

The native sources compiled by this package contain code from the following KpqC
reference implementations:

- AIMer reference implementation, by the AIMer team / Samsung SDS
- HAETAE reference implementation, Copyright (c) 2026 Team HAETAE
- NTRU+ reference implementation, Copyright (c) 2024–2026 NTRU+ TEAM
- SMAUG-T reference implementation, Copyright (c) 2026 Team SMAUG-T

These components are distributed under the MIT License. Full original license
texts are included in the package source distribution.

Imported on 2026-09-06. `vendor/SOURCES.json` records the SHA-256 of each
source file before the shared KpqC binding adaptations, under its destination
path. Original NIST notices in AIMer headers are preserved; we acknowledge
NIST as the source of the software identified by those notices.

The SHA-3/SHAKE code is based on public-domain implementations by Ronny Van
Keer and on TweetFips202 by Gilles Van Assche, Daniel J. Bernstein and Peter
Schwabe.

## Source and Swift binding adaptations

- Production entropy uses operating-system random-number sources through
  `native/csrc/randombytes.c`. Upstream RNG/CTR-DRBG/AES implementations and
  benchmark/KAT executables are not compiled or shipped as runtime components.
- AIMer, HAETAE, NTRU+, and SMAUG-T public operations check RNG return codes.
  NTRU+ RNG declarations return `int` to propagate failure. The optional
  random-seed branch in SMAUG-T's `indcpa_enc` also stops on RNG failure.
- AIMer and NTRU+ SHA-3/SHAKE contexts use embedded storage and wipe it on
  release, avoiding process termination when heap allocation fails. AIMer
  signing and verification allocation failures propagate to Swift as
  `KpqCError`.
- The imported SMAUG-T sources include full-vector initialization in `key.c`,
  corrected output indexing in `dg.c`, and the correct output buffer size in
  `packring.c`.
- Unused HAETAE helper code and local variables were removed, and a SMAUG-T
  loop counter was changed to `size_t` to match its bound.
- Parameter sets are compiled with their upstream configuration macros and
  isolated C symbols. The binding validates input sizes before entering C and
  wipes unpublished outputs on failure.

The bundled implementations are the same adapted cores used to generate the
npm package's JavaScript runtime.

## Known-answer tests

`Tests/KpqCTests/kat` contains the first KAT record for every parameter set.
AIMer, HAETAE, and NTRU+ records come from their reference implementations. SMAUG-T
records reflect the documented source fixes also used by the npm and PyPI
packages. The tests reproduce the NIST AES-256 CTR DRBG and compare keys,
signatures, ciphertexts, and shared secrets byte-for-byte.
