"""
crypto/modern.py - modern authenticated encryption, STREAMING (chunked).

File layout of a .encx file. Nothing is readable: no magic bytes, no file
name, no algorithm name - the whole file looks like random data.

    salt (16) | header nonce (12) | encrypted header (1024 + 16 tag)
    | chunk record 0 | chunk record 1 | ... | trailer record

    chunk record   = nonce | AEAD( chunk , AAD = H(prefix) + index + is_last )
    trailer record = nonce | AEAD( fixed 256-byte block , AAD = H(prefix) + "T" )

* The header (file name, algorithm, kind, compression) is encrypted.
* The trailer holds the checksum of the ORIGINAL data (see core/file_operations).
* index + is_last in the AAD stop re-ordering, removal and truncation of chunks.

Complexity:  time O(n)   memory O(chunk size) = ~1 MiB, whatever the file size.
"""

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM, AESGCM, AESOCB3, ChaCha20Poly1305)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CHUNK_SIZE = 1 << 20          # 1 MiB of plaintext per chunk
HEADER_SIZE = 1024            # fixed size => the length of the file name is hidden
TRAILER_SIZE = 256
SALT_LEN, HNONCE_LEN, TAG_LEN = 16, 12, 16
PREFIX_LEN = SALT_LEN + HNONCE_LEN + HEADER_SIZE + TAG_LEN


# ----------------------------------------------------------------------------
# Algorithms. Every class has:  encrypt(nonce, data, aad) / decrypt(nonce, data, aad)
# ----------------------------------------------------------------------------
class EncryptThenMac:
    """Plain cipher + HMAC-SHA256. Needs a 64-byte key (32 encrypt + 32 MAC)."""

    algorithm = algorithms.AES
    mode = modes.CBC
    needs_padding = True            # CBC needs padding, CTR does not

    def __init__(self, key: bytes):
        self.enc_key, self.mac_key = key[:32], key[32:]

    def _mac(self, nonce, aad, ciphertext):
        h = crypto_hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(aad + nonce + ciphertext)
        return h

    def encrypt(self, nonce, data, aad):
        if self.needs_padding:
            padder = padding.PKCS7(128).padder()
            data = padder.update(data) + padder.finalize()
        encryptor = Cipher(self.algorithm(self.enc_key), self.mode(nonce)).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + self._mac(nonce, aad, ciphertext).finalize()

    def decrypt(self, nonce, blob, aad):
        ciphertext, tag = blob[:-32], blob[-32:]
        self._mac(nonce, aad, ciphertext).verify(tag)        # raises InvalidSignature
        decryptor = Cipher(self.algorithm(self.enc_key), self.mode(nonce)).decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()
        if self.needs_padding:
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(data) + unpadder.finalize()
        return data


class AesCbcHmac(EncryptThenMac):
    pass


class AesCtrHmac(EncryptThenMac):
    mode = modes.CTR
    needs_padding = False


class CamelliaCbcHmac(EncryptThenMac):
    algorithm = algorithms.Camellia


@dataclass(frozen=True)
class Algorithm:
    name: str
    factory: type
    key_len: int        # bytes
    nonce_len: int      # bytes
    overhead: int       # ciphertext bytes added to a chunk whose size is a multiple of 16


ALGORITHMS = {a.name: a for a in [
    Algorithm("AES-256-GCM", AESGCM, 32, 12, 16),
    Algorithm("AES-192-GCM", AESGCM, 24, 12, 16),
    Algorithm("AES-128-GCM", AESGCM, 16, 12, 16),
    Algorithm("ChaCha20-Poly1305", ChaCha20Poly1305, 32, 12, 16),
    Algorithm("AES-256-CCM", AESCCM, 32, 12, 16),
    Algorithm("AES-256-OCB3", AESOCB3, 32, 12, 16),
    Algorithm("AES-256-CBC + HMAC-SHA256", AesCbcHmac, 64, 16, 48),
    Algorithm("AES-256-CTR + HMAC-SHA256", AesCtrHmac, 64, 16, 32),
    Algorithm("Camellia-256-CBC + HMAC-SHA256", CamelliaCbcHmac, 64, 16, 48),
]}
DEFAULT_ALGORITHM = "AES-256-GCM"
KDFS = ("Scrypt", "PBKDF2-SHA256")


# ----------------------------------------------------------------------------
# Keys: password --(slow KDF, once)--> master --(HKDF)--> header key / body key
# ----------------------------------------------------------------------------
def derive_key(password: str, salt: bytes, kdf: str, length: int) -> bytes:
    data = password.encode("utf-8")
    if kdf == "Scrypt":
        return Scrypt(salt=salt, length=length, n=2**15, r=8, p=1).derive(data)
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=length,
                      salt=salt, iterations=600_000).derive(data)


def _hkdf(master: bytes, length: int, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(master)


def pack_block(data: dict, size: int) -> bytes:
    """dict -> fixed-size block: 2-byte length + JSON + random padding."""
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > size - 2:
        raise ValueError("The file name is too long.")
    return struct.pack(">H", len(raw)) + raw + secrets.token_bytes(size - 2 - len(raw))


def unpack_block(block: bytes) -> dict:
    (length,) = struct.unpack(">H", block[:2])
    return json.loads(block[2:2 + length].decode("utf-8"))


# ----------------------------------------------------------------------------
# Writing
# ----------------------------------------------------------------------------
class StreamEncryptor:
    """Push-style encryptor:   write(data) ... write(data)  finish(trailer)

    Only ONE chunk is buffered, so memory does not grow with the file size.
    """

    def __init__(self, out, password: str, algo_name: str, kdf: str,
                 header: dict, chunk_size: int = CHUNK_SIZE):
        self._algo = ALGORITHMS[algo_name]
        self._out = out
        self._chunk = chunk_size
        self._index = 0
        self._buf = bytearray()

        salt = secrets.token_bytes(SALT_LEN)
        header_nonce = secrets.token_bytes(HNONCE_LEN)
        master = derive_key(password, salt, kdf, 32)             # the ONLY slow step

        header = {**header, "algo": algo_name, "chunk": chunk_size}
        enc_header = AESGCM(_hkdf(master, 32, b"EncryptX header")).encrypt(
            header_nonce, pack_block(header, HEADER_SIZE), salt)
        prefix = salt + header_nonce + enc_header
        out.write(prefix)

        self._aad = hashlib.sha256(prefix).digest()
        self._cipher = self._algo.factory(_hkdf(master, self._algo.key_len, b"EncryptX body"))

    def write(self, data) -> None:
        self._buf += data
        # '>' (not '>=') keeps the last chunk buffered, so we know which one is last.
        while len(self._buf) > self._chunk:
            self._emit(bytes(self._buf[:self._chunk]), last=False)
            del self._buf[:self._chunk]

    def finish(self, trailer: dict) -> None:
        self._emit(bytes(self._buf), last=True)
        self._buf.clear()
        nonce = secrets.token_bytes(self._algo.nonce_len)
        block = pack_block(trailer, TRAILER_SIZE)
        self._out.write(nonce + self._cipher.encrypt(nonce, block, self._aad + b"T"))

    def _emit(self, chunk: bytes, last: bool) -> None:
        nonce = secrets.token_bytes(self._algo.nonce_len)
        aad = self._aad + struct.pack(">QB", self._index, last)
        self._out.write(nonce + self._cipher.encrypt(nonce, chunk, aad))
        self._index += 1


# ----------------------------------------------------------------------------
# Reading
# ----------------------------------------------------------------------------
class Decryptor:
    """Opens a .encx file object. Raises ValueError for a wrong password.

    .header   dict stored by the encryptor (name, kind, compressed, ...)
    .trailer  dict with the checksum of the original data
    .pieces() generator of plaintext chunks (each chunk is authenticated)
    """

    def __init__(self, f, password: str):
        self._f = f
        size = f.seek(0, 2)
        f.seek(0)
        if size < PREFIX_LEN:
            raise ValueError("This is not an EncryptX file (too small).")
        prefix = f.read(PREFIX_LEN)
        salt = prefix[:SALT_LEN]
        header_nonce = prefix[SALT_LEN:SALT_LEN + HNONCE_LEN]
        enc_header = prefix[SALT_LEN + HNONCE_LEN:]

        # The KDF is not stored anywhere, so try each one until the header opens.
        header = master = None
        for kdf in KDFS:
            candidate = derive_key(password, salt, kdf, 32)
            try:
                header = unpack_block(AESGCM(_hkdf(candidate, 32, b"EncryptX header"))
                                      .decrypt(header_nonce, enc_header, salt))
                master = candidate
                break
            except InvalidTag:
                continue
        if header is None:
            raise ValueError("Wrong password, or this is not an EncryptX file.")

        algo = ALGORITHMS.get(header.get("algo"))
        if algo is None:
            raise ValueError("Unsupported algorithm: %s" % header.get("algo"))
        self.header = header
        self.chunk_size = header["chunk"]
        self._algo = algo
        self._aad = hashlib.sha256(prefix).digest()
        self._cipher = algo.factory(_hkdf(master, algo.key_len, b"EncryptX body"))

        # The trailer is a fixed-size record at the very end of the file.
        trailer_len = algo.nonce_len + TRAILER_SIZE + algo.overhead
        self._data_end = size - trailer_len
        if self._data_end - PREFIX_LEN < algo.nonce_len + algo.overhead:
            raise ValueError("The file is truncated or damaged.")
        f.seek(self._data_end)
        record = f.read(trailer_len)
        try:
            block = self._cipher.decrypt(record[:algo.nonce_len], record[algo.nonce_len:],
                                         self._aad + b"T")
        except (InvalidTag, InvalidSignature):
            raise ValueError("The file is truncated or damaged.")
        self.trailer = unpack_block(block)

    def pieces(self):
        f, algo = self._f, self._algo
        record_size = algo.nonce_len + self.chunk_size + algo.overhead
        pos, index = PREFIX_LEN, 0
        f.seek(pos)
        while pos < self._data_end:
            remaining = self._data_end - pos
            last = remaining <= record_size        # the last record is the shorter/final one
            size = min(record_size, remaining)
            record = f.read(size)
            if len(record) != size:
                raise ValueError("The file is truncated.")
            aad = self._aad + struct.pack(">QB", index, last)
            try:
                plain = self._cipher.decrypt(record[:algo.nonce_len],
                                             record[algo.nonce_len:], aad)
            except (InvalidTag, InvalidSignature):
                raise ValueError("The file is damaged or was modified.")
            yield plain
            pos += size
            index += 1
