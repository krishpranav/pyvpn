import hashlib, os, random, hmac
from Crypto.Cipher import AES, ChaCha20_Poly1305
from . import enums

class Prf:
    DIGESTS_1 = {
        enums.HashId_1.MD5: (hashlib.md5, 16),
        enums.HashId_1.SHA: (hashlib.sha1, 20),
        enums.HashId_1.SHA2_256: (hashlib.sha256, 32),
        enums.HashId_1.SHA2_384: (hashlib.sha384, 48),
        enums.HashId_1.SHA2_512: (hashlib.sha512, 64),
    }
    DIGESTS = {
        enums.PrfId.PRF_HMAC_MD5: (hashlib.md5, 16),
        enums.PrfId.PRF_HMAC_SHA1: (hashlib.sha1, 20),
        enums.PrfId.PRF_HMAC_SHA2_256: (hashlib.sha256, 32),
        enums.PrfId.PRF_HMAC_SHA2_384: (hashlib.sha384, 48),
        enums.PrfId.PRF_HMAC_SHA2_512: (hashlib.sha512, 64),
    }
    def __init__(self, transform):
        self.hasher, self.key_size = self.DIGESTS[transform] if type(transform) is enums.PrfId else self.DIGESTS_1[transform]
    def prf(self, key, data):
        return hmac.HMAC(key, data, digestmod=self.hasher).digest()
    def prfplus(self, key, seed, count=True):
        temp = bytes()
        for i in range(1, 1024):
            temp = self.prf(key, temp + seed + (bytes([i]) if count else b''))
            yield from temp

class Integrity:
    DIGESTS_1 = {
        enums.IntegId_1.AUTH_HMAC_MD5: (hashlib.md5, 16, 12),
        enums.IntegId_1.AUTH_HMAC_SHA1: (hashlib.sha1, 20, 12),
        enums.IntegId_1.AUTH_HMAC_SHA2_256: (hashlib.sha256, 32, 16),
        enums.IntegId_1.AUTH_HMAC_SHA2_384: (hashlib.sha384, 48, 24),
        enums.IntegId_1.AUTH_HMAC_SHA2_512: (hashlib.sha512, 64, 32),
    }
    DIGESTS = {
        enums.IntegId.AUTH_HMAC_MD5_96: (hashlib.md5, 16, 12),
        enums.IntegId.AUTH_HMAC_SHA1_96: (hashlib.sha1, 20, 12),
        enums.IntegId.AUTH_HMAC_MD5_128: (hashlib.md5, 16, 16),
        enums.IntegId.AUTH_HMAC_SHA1_160: (hashlib.sha1, 20, 20),
        enums.IntegId.AUTH_HMAC_SHA2_256_128: (hashlib.sha256, 32, 16),
        enums.IntegId.AUTH_HMAC_SHA2_384_192: (hashlib.sha384, 48, 24),
        enums.IntegId.AUTH_HMAC_SHA2_512_256: (hashlib.sha512, 64, 32),
    }
    def __init__(self, transform):
        self.hasher, self.key_size, self.hash_size = self.DIGESTS[transform] if type(transform) is enums.IntegId else self.DIGESTS_1[transform]
    def compute(self, key, data):
        return hmac.HMAC(key, data, digestmod=self.hasher).digest()[:self.hash_size]