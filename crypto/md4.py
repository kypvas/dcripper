import struct

def md4(data: bytes) -> bytes:
    """Pure Python MD4 implementation."""

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def left_rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    # Pre-processing: adding padding bits
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)

    # Pad to 56 mod 64 bytes
    while len(msg) % 64 != 56:
        msg.append(0)

    # Append original length in bits as 64-bit little-endian
    msg += struct.pack('<Q', msg_len * 8)

    # Initialize hash values
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476

    # Process each 64-byte block
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        M = struct.unpack('<16I', block)

        a, b, c, d = h0, h1, h2, h3

        # Round 1
        for j in range(16):
            if j % 4 == 0:
                a = left_rotate((a + F(b, c, d) + M[j]) & 0xffffffff, 3)
            elif j % 4 == 1:
                d = left_rotate((d + F(a, b, c) + M[j]) & 0xffffffff, 7)
            elif j % 4 == 2:
                c = left_rotate((c + F(d, a, b) + M[j]) & 0xffffffff, 11)
            else:
                b = left_rotate((b + F(c, d, a) + M[j]) & 0xffffffff, 19)

        # Round 2
        for j in range(16):
            idx = (j % 4) * 4 + j // 4
            if j % 4 == 0:
                a = left_rotate((a + G(b, c, d) + M[idx] + 0x5a827999) & 0xffffffff, 3)
            elif j % 4 == 1:
                d = left_rotate((d + G(a, b, c) + M[idx] + 0x5a827999) & 0xffffffff, 5)
            elif j % 4 == 2:
                c = left_rotate((c + G(d, a, b) + M[idx] + 0x5a827999) & 0xffffffff, 9)
            else:
                b = left_rotate((b + G(c, d, a) + M[idx] + 0x5a827999) & 0xffffffff, 13)

        # Round 3
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            idx = order[j]
            if j % 4 == 0:
                a = left_rotate((a + H(b, c, d) + M[idx] + 0x6ed9eba1) & 0xffffffff, 3)
            elif j % 4 == 1:
                d = left_rotate((d + H(a, b, c) + M[idx] + 0x6ed9eba1) & 0xffffffff, 9)
            elif j % 4 == 2:
                c = left_rotate((c + H(d, a, b) + M[idx] + 0x6ed9eba1) & 0xffffffff, 11)
            else:
                b = left_rotate((b + H(c, d, a) + M[idx] + 0x6ed9eba1) & 0xffffffff, 15)

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff

    return struct.pack('<4I', h0, h1, h2, h3)
