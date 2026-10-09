"""Byte-for-byte checks against embedded and shared KAT records."""
from __future__ import annotations

import ctypes
from pathlib import Path
import re
import sys

from kat_drbg import CtrDrbg, aes256_encrypt


KAT_DIR = Path(__file__).with_name("kat")
SIGNATURES = (
    ("aimer128f", 32, 48, 6_944),
    ("aimer128s", 32, 48, 4_704),
    ("aimer192f", 48, 72, 15_408),
    ("aimer192s", 48, 72, 10_320),
    ("aimer256f", 64, 96, 31_360),
    ("aimer256s", 64, 96, 20_224),
    ("haetae2", 992, 1_408, 1_474),
    ("haetae3", 1_472, 2_112, 2_349),
    ("haetae5", 2_080, 2_752, 2_948),
)
KEMS = (
    ("ntruplus768", 1_152, 2_336, 1_152, 32),
    ("ntruplus864", 1_296, 2_624, 1_296, 32),
    ("ntruplus1152", 1_728, 3_488, 1_728, 32),
    ("smaugt128", 672, 832, 672, 32),
    ("smaugt192", 1_088, 1_312, 992, 32),
    ("smaugt256", 1_440, 1_728, 1_376, 32),
    ("timer", 672, 832, 608, 32),
)
VECTOR_PATHS = {
    "aimer128f": "aimer/128f/kat.rsp",
    "aimer128s": "aimer/128s/kat.rsp",
    "aimer192f": "aimer/192f/kat.rsp",
    "aimer192s": "aimer/192s/kat.rsp",
    "aimer256f": "aimer/256f/kat.rsp",
    "aimer256s": "aimer/256s/kat.rsp",
    "haetae2": "haetae/mode2/kat.rsp",
    "haetae3": "haetae/mode3/kat.rsp",
    "haetae5": "haetae/mode5/kat.rsp",
    "ntruplus768": "ntruplus/768/kat.rsp",
    "ntruplus864": "ntruplus/864/kat.rsp",
    "ntruplus1152": "ntruplus/1152/kat.rsp",
    "smaugt128": "smaugt/mode1/kat.rsp",
    "smaugt192": "smaugt/mode3/kat.rsp",
    "smaugt256": "smaugt/mode5/kat.rsp",
    "timer": "smaugt/modet/kat.rsp",
}

BytePointer = ctypes.POINTER(ctypes.c_ubyte)
EntropyCallback = ctypes.CFUNCTYPE(ctypes.c_int, BytePointer, ctypes.c_size_t)


def read_vectors(path: Path) -> list[dict[str, str]]:
    vectors = []
    fields = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([a-z]+) = ([0-9A-Fa-f]*)", line)
        if match:
            if match.group(1) == "count" and fields:
                vectors.append(fields)
                fields = {}
            fields[match.group(1)] = match.group(2)
    if fields:
        vectors.append(fields)
    if not vectors:
        raise ValueError(f"no vectors found in {path}")
    return vectors


def binary(vector: dict[str, str], name: str) -> bytes:
    return bytes.fromhex(vector[name])


def byte_buffer(value: int | bytes):
    if isinstance(value, int):
        return (ctypes.c_ubyte * value)()
    return (ctypes.c_ubyte * len(value)).from_buffer_copy(value)


def operation(library, name: str, arguments):
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = ctypes.c_int
    return function


def install_entropy(library, name: str, seed: bytes):
    drbg = CtrDrbg(seed)

    @EntropyCallback
    def provide(output, length):
        try:
            ctypes.memmove(output, drbg.random_bytes(length), length)
            return 0
        except Exception:
            return -1

    setter = getattr(library, f"kpqc_{name}_set_randombytes")
    setter.argtypes = [EntropyCallback]
    setter.restype = None
    setter(provide)
    return drbg, provide


def check_signature(library, parameters, vector: dict[str, str]) -> None:
    name, pk_size, sk_size, sig_size = parameters
    label = f"{name} count {vector.get('count', 'embedded')}"
    drbg, callback = install_entropy(library, name, binary(vector, "seed"))
    prefix = f"kpqc_{name}_"
    keypair = operation(library, prefix + "keypair", [BytePointer, BytePointer])
    sign = operation(
        library,
        prefix + "sign",
        [BytePointer, ctypes.POINTER(ctypes.c_size_t), BytePointer,
         ctypes.c_size_t, BytePointer, ctypes.c_size_t, BytePointer],
    )
    verify = operation(
        library,
        prefix + "verify",
        [BytePointer, ctypes.c_size_t, BytePointer, ctypes.c_size_t,
         BytePointer, ctypes.c_size_t, BytePointer],
    )
    public_key, secret_key = byte_buffer(pk_size), byte_buffer(sk_size)
    assert keypair(public_key, secret_key) == 0
    assert bytes(public_key) == binary(vector, "pk"), f"{label} public key"
    assert bytes(secret_key) == binary(vector, "sk"), f"{label} secret key"

    context = b""
    if name.startswith("haetae"):
        preview = drbg.copy()
        preview.random_bytes(32)
        context = preview.random_bytes(preview.random_bytes(1)[0])

    message_bytes = binary(vector, "msg")
    message = byte_buffer(message_bytes)
    context_buffer = byte_buffer(context)
    signature, length = byte_buffer(sig_size), ctypes.c_size_t()
    assert sign(signature, ctypes.byref(length), message, len(message),
                context_buffer, len(context_buffer), secret_key) == 0
    expected = (binary(vector, "sig") if "sig" in vector
                else binary(vector, "sm")[len(message):])
    assert length.value == sig_size
    assert bytes(signature) == expected, f"{label} signature"
    assert verify(signature, length, message, len(message), context_buffer,
                  len(context_buffer), public_key) == 0
    assert callback is not None


def check_kem(library, parameters, vector: dict[str, str]) -> None:
    name, pk_size, sk_size, ct_size, ss_size = parameters
    label = f"{name} count {vector.get('count', 'embedded')}"
    _, callback = install_entropy(library, name, binary(vector, "seed"))
    prefix = f"kpqc_{name}_"
    keypair = operation(library, prefix + "keypair", [BytePointer, BytePointer])
    encapsulate = operation(
        library, prefix + "encapsulate", [BytePointer, BytePointer, BytePointer])
    decapsulate = operation(
        library, prefix + "decapsulate", [BytePointer, BytePointer, BytePointer])
    public_key, secret_key = byte_buffer(pk_size), byte_buffer(sk_size)
    ciphertext, shared_secret = byte_buffer(ct_size), byte_buffer(ss_size)
    recovered = byte_buffer(ss_size)

    assert keypair(public_key, secret_key) == 0
    assert bytes(public_key) == binary(vector, "pk"), f"{label} public key"
    assert bytes(secret_key) == binary(vector, "sk"), f"{label} secret key"
    assert encapsulate(ciphertext, shared_secret, public_key) == 0
    assert bytes(ciphertext) == binary(vector, "ct"), f"{label} ciphertext"
    assert bytes(shared_secret) == binary(vector, "ss"), f"{label} shared secret"
    assert decapsulate(recovered, ciphertext, secret_key) == 0
    assert bytes(recovered) == bytes(shared_secret), f"{name} decapsulation"
    assert callback is not None


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(
            "usage: test_kat.py PATH_TO_TEST_KPQC_LIBRARY [VECTOR_REPOSITORY]")
    assert aes256_encrypt(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                      "101112131415161718191a1b1c1d1e1f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    ) == bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    library = ctypes.CDLL(str(Path(sys.argv[1]).resolve()))
    vector_root = Path(sys.argv[2]) if len(sys.argv) == 3 else None
    expected_per_set = 100 if vector_root else 1
    checked = 0
    for parameters in SIGNATURES:
        name = parameters[0]
        path = ((vector_root / VECTOR_PATHS[name]) if vector_root
                else KAT_DIR / f"{name}.rsp")
        vectors = read_vectors(path)
        assert len(vectors) == expected_per_set, (
            f"expected {expected_per_set} vectors for {name}, "
            f"found {len(vectors)}")
        for vector in vectors:
            check_signature(library, parameters, vector)
            checked += 1
    for parameters in KEMS:
        name = parameters[0]
        path = ((vector_root / VECTOR_PATHS[name]) if vector_root
                else KAT_DIR / f"{name}.rsp")
        vectors = read_vectors(path)
        assert len(vectors) == expected_per_set, (
            f"expected {expected_per_set} vectors for {name}, "
            f"found {len(vectors)}")
        for vector in vectors:
            check_kem(library, parameters, vector)
            checked += 1
    expected = expected_per_set * (len(SIGNATURES) + len(KEMS))
    assert checked == expected, f"expected {expected} vectors, checked {checked}"
    print(f"{checked} known-answer vectors passed for all 16 parameter sets")


if __name__ == "__main__":
    main()
