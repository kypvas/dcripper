class RC4:
    def __init__(self, key: bytes):
        self.key = key
        self.S = list(range(256))
        self._key_schedule()
        
    def _key_schedule(self):
        j = 0
        key_len = len(self.key)
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_len]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0
        
    def _prga(self) -> int:
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]
        
    def encrypt(self, plaintext: bytes) -> bytes:
        return bytes(p ^ self._prga() for p in plaintext)
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)
        
    def reset(self):
        self.S = list(range(256))
        self._key_schedule()


def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    return RC4(key).encrypt(data)


def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    return RC4(key).decrypt(data)
