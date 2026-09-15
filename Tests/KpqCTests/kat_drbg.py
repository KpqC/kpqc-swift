"""NIST AES-256 CTR DRBG used by the upstream PQC KAT generators."""


def _gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def _gf_pow(value, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1
    return result


def _rotl8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _substitute(value):
    inverse = _gf_pow(value, 254) if value else 0
    return (inverse ^ _rotl8(inverse, 1) ^ _rotl8(inverse, 2) ^
            _rotl8(inverse, 3) ^ _rotl8(inverse, 4) ^ 0x63)


_SBOX = tuple(_substitute(value) for value in range(256))


def _round_keys(key):
    words = [list(key[offset:offset + 4]) for offset in range(0, 32, 4)]
    rcon = 1
    for index in range(8, 60):
        temp = words[index - 1].copy()
        if index % 8 == 0:
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]],
                    _SBOX[temp[0]]]
            temp[0] ^= rcon
            rcon = _gf_mul(rcon, 2)
        elif index % 8 == 4:
            temp = [_SBOX[value] for value in temp]
        words.append([left ^ right for left, right in zip(words[index - 8], temp)])
    return [sum(words[index:index + 4], []) for index in range(0, 60, 4)]


def _add_round_key(state, key):
    for index, value in enumerate(key):
        state[index] ^= value


def _mix_columns(state):
    for offset in range(0, 16, 4):
        a, b, c, d = state[offset:offset + 4]
        state[offset] = _gf_mul(a, 2) ^ _gf_mul(b, 3) ^ c ^ d
        state[offset + 1] = a ^ _gf_mul(b, 2) ^ _gf_mul(c, 3) ^ d
        state[offset + 2] = a ^ b ^ _gf_mul(c, 2) ^ _gf_mul(d, 3)
        state[offset + 3] = _gf_mul(a, 3) ^ b ^ c ^ _gf_mul(d, 2)


def aes256_encrypt(key, block):
    """Encrypt one block with AES-256; exposed for a standard-vector self-test."""
    if len(key) != 32 or len(block) != 16:
        raise ValueError("AES-256 requires a 32-byte key and 16-byte block")
    keys = _round_keys(key)
    state = list(block)
    _add_round_key(state, keys[0])
    for round_index in range(1, 14):
        state = [_SBOX[value] for value in state]
        state = [state[0], state[5], state[10], state[15],
                 state[4], state[9], state[14], state[3],
                 state[8], state[13], state[2], state[7],
                 state[12], state[1], state[6], state[11]]
        _mix_columns(state)
        _add_round_key(state, keys[round_index])
    state = [_SBOX[value] for value in state]
    state = [state[0], state[5], state[10], state[15],
             state[4], state[9], state[14], state[3],
             state[8], state[13], state[2], state[7],
             state[12], state[1], state[6], state[11]]
    _add_round_key(state, keys[14])
    return bytes(state)


def _increment(counter):
    value = bytearray(counter)
    for index in range(15, -1, -1):
        value[index] = (value[index] + 1) & 0xFF
        if value[index]:
            break
    return bytes(value)


class CtrDrbg:
    """Minimal implementation of the randombytes.c KAT generator."""

    def __init__(self, entropy_input):
        if len(entropy_input) != 48:
            raise ValueError("CTR DRBG entropy input must be 48 bytes")
        self.key = bytes(32)
        self.counter = bytes(16)
        self._update(entropy_input)

    def copy(self):
        result = object.__new__(type(self))
        result.key = self.key
        result.counter = self.counter
        return result

    def _update(self, provided_data=None):
        blocks = []
        for _ in range(3):
            self.counter = _increment(self.counter)
            blocks.append(aes256_encrypt(self.key, self.counter))
        material = b"".join(blocks)
        if provided_data is not None:
            material = bytes(a ^ b for a, b in zip(material, provided_data))
        self.key = material[:32]
        self.counter = material[32:]

    def random_bytes(self, length):
        output = bytearray()
        while len(output) < length:
            self.counter = _increment(self.counter)
            output.extend(aes256_encrypt(self.key, self.counter))
        self._update()
        return bytes(output[:length])
