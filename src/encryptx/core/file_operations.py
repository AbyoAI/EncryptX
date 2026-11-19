"""
core/file_operations.py - everything that touches files (no GUI code).

    Checksum   hash_path(), matching_algorithms()
    Encrypt    encrypt_path()   file/folder -> NAME.encx
    Decrypt    decrypt_path()   NAME.encx  -> file/folder (+ checksum check)

Design (why it is fast and light):

* STREAMING. Data flows  disk -> [hash] -> [compress] -> encrypt -> disk  in 1 MiB
  pieces, so memory stays ~constant (O(1)) and the time is a single O(n) pass.
* FOLDERS are streamed through an in-memory TAR into the encryptor - no temporary
  .zip file (saves a full extra write + read and O(n) disk space).
* The checksum is computed in the SAME pass that reads the data (no second read).
  When restoring, it is computed while writing (no second read either).
* Plain checksum of a file/folder reads the data ONCE and feeds every algorithm
  (hashlib releases the GIL, so the algorithms run in parallel threads).
"""

import hashlib
import hmac
import io
import os
import re
import secrets
import shutil
import tarfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

from ..crypto.modern import ALGORITHMS, CHUNK_SIZE, DEFAULT_ALGORITHM, KDFS, Decryptor, StreamEncryptor

EXTENSION = ".encx"
READ_BLOCK = 1 << 20
COMPRESSION_LEVEL = 6          # level 9 is ~3-5x slower for only a few % smaller output

# Already-compressed formats: compressing them again only wastes CPU time.
INCOMPRESSIBLE = {
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".jpg", ".jpeg", ".png",
    ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac", ".aac", ".ogg",
    ".docx", ".xlsx", ".pptx", ".pdf", EXTENSION,
}

Progress = Optional[Callable[[float], None]]


class OperationCancelled(Exception):
    pass


def _check(cancel) -> None:
    if cancel is not None and cancel.is_set():
        raise OperationCancelled("Cancelled")


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def unique_path(path: Path) -> Path:
    """If the path exists, return 'name (1).ext', 'name (2).ext', ..."""
    if not path.exists():
        return path
    i = 1
    while True:
        candidate = path.with_name(f"{path.stem} ({i}){path.suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def delete_path(path) -> None:
    path = str(path)
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    elif os.path.exists(path):
        os.remove(path)


def read_blocks(path, cancel=None, size: int = READ_BLOCK) -> Iterator[bytes]:
    with open(path, "rb", buffering=0) as f:
        while True:
            _check(cancel)
            block = f.read(size)
            if not block:
                return
            yield block


def iter_folder_entries(root) -> Iterator[tuple]:
    """Yield (relative_posix_path, absolute_path, is_dir, size) in ONE fixed order.

    Depth-first, names sorted inside every folder, symlinks skipped. Encrypting,
    restoring and checksumming a folder all use this order, so the folder checksum
    is identical everywhere.
    """
    def walk(abs_dir: str, rel_dir: str):
        with os.scandir(abs_dir) as it:
            entries = sorted(it, key=lambda e: e.name)
        for e in entries:
            if e.is_symlink():
                continue
            rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
            if e.is_dir(follow_symlinks=False):
                yield rel, e.path, True, 0
                yield from walk(e.path, rel)
            elif e.is_file(follow_symlinks=False):
                yield rel, e.path, False, e.stat(follow_symlinks=False).st_size
    yield from walk(str(root), "")


def path_size(path) -> int:
    if os.path.isdir(path):
        return sum(size for _, _, is_dir, size in iter_folder_entries(path) if not is_dir)
    return os.path.getsize(path)


# ----------------------------------------------------------------------------
# Checksums
# ----------------------------------------------------------------------------
class Crc32:
    """Same interface as hashlib objects."""

    def __init__(self):
        self.value = 0

    def update(self, data) -> None:
        self.value = zlib.crc32(data, self.value)

    def hexdigest(self) -> str:
        return f"{self.value & 0xFFFFFFFF:08x}"


CHECKSUM_ALGOS = {
    "MD5": "md5", "SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
    "SHA-384": "sha384", "SHA-512": "sha512", "SHA3-256": "sha3_256",
    "SHA3-512": "sha3_512", "BLAKE2b": "blake2b", "BLAKE2s": "blake2s", "CRC32": None,
}


def new_hasher(name: str):
    return Crc32() if name == "CRC32" else hashlib.new(CHECKSUM_ALGOS[name])


def entry_header(rel: str, is_dir: bool, size: int) -> bytes:
    """What is hashed for a folder entry BEFORE its content (names + sizes count)."""
    name = rel.encode("utf-8")
    if is_dir:
        return b"D\0" + name + b"\0"
    return b"F\0" + name + b"\0" + size.to_bytes(8, "big")


class HashGroup:
    """Feeds the same data to several hashers (in parallel for big blocks)."""

    PARALLEL_MIN = 64 * 1024

    def __init__(self, names):
        self.hashers = {n: new_hasher(n) for n in names}
        self._pool = ThreadPoolExecutor(len(self.hashers)) if len(self.hashers) > 1 else None

    def update(self, data) -> None:
        if self._pool and len(data) >= self.PARALLEL_MIN:
            for f in [self._pool.submit(h.update, data) for h in self.hashers.values()]:
                f.result()
        else:
            for h in self.hashers.values():
                h.update(data)

    def hexdigests(self) -> Dict[str, str]:
        return {n: h.hexdigest() for n, h in self.hashers.items()}

    def close(self) -> None:
        if self._pool:
            self._pool.shutdown()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def hash_path(path, names=None, progress: Progress = None, cancel=None) -> Dict[str, str]:
    """Checksum of a file (standard hash of its bytes) or of a folder
    (hash of every entry's name, size and content in a fixed order).
    Reads the data once for all algorithms."""
    names = list(names or CHECKSUM_ALGOS)
    total = max(path_size(path), 1)
    done = 0

    def advance(n: int) -> None:
        nonlocal done
        done += n
        if progress:
            progress(min(done / total, 1.0))

    with HashGroup(names) as group:
        if os.path.isdir(path):
            for rel, abs_path, is_dir, size in iter_folder_entries(path):
                group.update(entry_header(rel, is_dir, size))
                if not is_dir:
                    for block in read_blocks(abs_path, cancel, 4 * READ_BLOCK):
                        group.update(block)
                        advance(len(block))
        else:
            for block in read_blocks(path, cancel, 4 * READ_BLOCK):
                group.update(block)
                advance(len(block))
        return group.hexdigests()


def extract_candidates(text: str) -> List[str]:
    """Hex strings found in the text. Accepts '0xABC', 'sha256:ABC', or a whole
    'sha256sum' output line ('<hash>  file.txt')."""
    found = []
    for token in re.split(r"[\s:=,;]+", text.strip().lower()):
        token = token[2:] if token.startswith("0x") else token
        if token and re.fullmatch(r"[0-9a-f]+", token):
            found.append(token)
    return found


def matching_algorithms(digests: Dict[str, str], text: str) -> List[str]:
    """Names of the algorithms whose digest equals the hash typed by the user."""
    candidates = set(extract_candidates(text))
    return [name for name, digest in digests.items() if digest.lower() in candidates]


# ----------------------------------------------------------------------------
# Encrypt
# ----------------------------------------------------------------------------
class _CountingReader:
    """File wrapper used by tarfile: hashes + counts the bytes it hands out."""

    def __init__(self, f, hasher, advance, cancel):
        self._f, self._hasher, self._advance, self._cancel = f, hasher, advance, cancel

    def read(self, n=-1):
        _check(self._cancel)
        data = self._f.read(n)
        if self._hasher:
            self._hasher.update(data)
        self._advance(len(data))
        return data


class _TarSink:
    """File-like object that forwards what tarfile writes to a callback."""

    def __init__(self, feed):
        self._feed = feed

    def write(self, data) -> int:
        self._feed(bytes(data))
        return len(data)


def _pack_folder(src: Path, feed, hasher, advance, cancel) -> None:
    with tarfile.open(fileobj=_TarSink(feed), mode="w|", format=tarfile.PAX_FORMAT,
                      bufsize=CHUNK_SIZE) as tar:
        for rel, abs_path, is_dir, _ in iter_folder_entries(src):
            _check(cancel)
            info = tar.gettarinfo(abs_path, arcname=rel)
            if info is None:
                continue
            info.uid = info.gid = 0                    # do not store owner names
            info.uname = info.gname = ""
            if is_dir:
                if hasher:
                    hasher.update(entry_header(rel, True, 0))
                tar.addfile(info)
            else:
                if hasher:
                    hasher.update(entry_header(rel, False, info.size))
                with open(abs_path, "rb") as fh:
                    tar.addfile(info, _CountingReader(fh, hasher, advance, cancel))


def encrypt_path(src, out_dir, password: str, algo: str = DEFAULT_ALGORITHM,
                 kdf: str = KDFS[0], compress: bool = True, hide_name: bool = True,
                 checksum_algo: Optional[str] = None, progress: Progress = None,
                 cancel=None, on_checksum: Optional[Callable[[str, str], None]] = None) -> str:
    """Encrypt a file or folder into  out_dir/NAME.encx  and return that path.

    checksum_algo: e.g. "SHA-256". The checksum of the original data is stored
    (encrypted) inside the file and checked again by decrypt_path().
    on_checksum(algorithm, hex_digest) is called once the checksum is known.
    """
    src = Path(src)
    if not src.exists():
        raise FileNotFoundError(str(src))
    is_dir = src.is_dir()
    if compress and not is_dir and src.suffix.lower() in INCOMPRESSIBLE:
        compress = False

    total = max(path_size(src), 1)
    hasher = new_hasher(checksum_algo) if checksum_algo else None
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = (secrets.token_hex(8) if hide_name else src.name) + EXTENSION
    out_path = unique_path(out_dir / name)
    part = out_path.with_name(out_path.name + ".part")     # written first, renamed at the end
    done = 0

    def advance(n: int) -> None:
        nonlocal done
        done += n
        if progress:
            progress(min(done / total, 1.0))

    try:
        with open(part, "wb") as out:
            enc = StreamEncryptor(out, password, algo, kdf, {
                "name": src.name, "kind": "tar" if is_dir else "file", "compressed": compress})
            compressor = zlib.compressobj(COMPRESSION_LEVEL) if compress else None

            def feed(data: bytes) -> None:
                enc.write(compressor.compress(data) if compressor else data)

            if is_dir:
                _pack_folder(src, feed, hasher, advance, cancel)
            else:
                for block in read_blocks(src, cancel):
                    if hasher:
                        hasher.update(block)
                    feed(block)
                    advance(len(block))
            if compressor:
                enc.write(compressor.flush())
            enc.finish({"alg": checksum_algo, "digest": hasher.hexdigest()} if hasher
                       else {"alg": None})
            if hasher and on_checksum:
                on_checksum(checksum_algo, hasher.hexdigest())
        os.replace(part, out_path)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return str(out_path)


# ----------------------------------------------------------------------------
# Decrypt
# ----------------------------------------------------------------------------
@dataclass
class DecryptResult:
    path: str
    checksum: str                    # "verified" | "mismatch" | "none"
    algorithm: Optional[str] = None


class PieceReader(io.RawIOBase):
    """Turns an iterator of byte pieces into a readable file object (for tarfile)."""

    def __init__(self, pieces):
        self._it = iter(pieces)
        self._piece, self._pos = b"", 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while self._pos >= len(self._piece):
            try:
                self._piece, self._pos = next(self._it), 0
            except StopIteration:
                return 0
        n = min(len(b), len(self._piece) - self._pos)
        b[:n] = self._piece[self._pos:self._pos + n]
        self._pos += n
        return n

    def drain(self) -> None:
        for _ in self._it:       # reading to the end makes sure EVERY chunk is verified
            pass


def _decompress(pieces) -> Iterator[bytes]:
    d = zlib.decompressobj()
    for piece in pieces:
        data = piece
        while data:
            out = d.decompress(data, 4 * READ_BLOCK)     # bounded output => bounded memory
            if out:
                yield out
            data = d.unconsumed_tail
    tail = d.flush()
    if tail:
        yield tail


def _unpack_folder(pieces, dest: Path, hasher, cancel) -> None:
    dest.mkdir()
    root = dest.resolve()
    reader = PieceReader(pieces)
    with tarfile.open(fileobj=reader, mode="r|") as tar:
        for member in tar:
            _check(cancel)
            target = (root / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError("Unsafe path inside the archive.")
            if member.isdir():
                if hasher:
                    hasher.update(entry_header(member.name, True, 0))
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                if hasher:
                    hasher.update(entry_header(member.name, False, member.size))
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                with open(target, "wb") as out:
                    while True:
                        block = source.read(READ_BLOCK)
                        if not block:
                            break
                        if hasher:
                            hasher.update(block)
                        out.write(block)
                try:
                    os.utime(target, (member.mtime, member.mtime))
                except OSError:
                    pass
            else:
                raise ValueError("Unsupported entry inside the archive.")
    reader.drain()


def decrypt_path(src, out_dir, password: str, progress: Progress = None,
                 cancel=None) -> DecryptResult:
    """Decrypt NAME.encx into out_dir, restoring the original name. If a checksum
    was stored, compare it with the checksum of the restored data."""
    src = Path(src)
    total = max(src.stat().st_size, 1)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(src, "rb") as f:
        dec = Decryptor(f, password)                         # ValueError if wrong password
        header, trailer = dec.header, dec.trailer
        algorithm = trailer.get("alg")
        hasher = new_hasher(algorithm) if algorithm else None
        name = Path(header.get("name") or "decrypted").name or "decrypted"

        def pieces() -> Iterator[bytes]:
            for piece in dec.pieces():
                _check(cancel)
                if progress:
                    progress(min(f.tell() / total, 1.0))
                yield piece

        stream = _decompress(pieces()) if header["compressed"] else pieces()
        out_path = unique_path(out_dir / name)

        if header["kind"] == "tar":
            try:
                _unpack_folder(stream, out_path, hasher, cancel)
            except BaseException:
                shutil.rmtree(out_path, ignore_errors=True)
                raise
        else:
            part = out_path.with_name(out_path.name + ".part")
            try:
                with open(part, "wb") as out:
                    for block in stream:
                        if hasher:
                            hasher.update(block)
                        out.write(block)
                os.replace(part, out_path)
            except BaseException:
                part.unlink(missing_ok=True)
                raise

    if progress:
        progress(1.0)                                        # the trailer is not counted above
    if hasher is None:
        return DecryptResult(str(out_path), "none")
    same = hmac.compare_digest(hasher.hexdigest(), trailer.get("digest", ""))
    return DecryptResult(str(out_path), "verified" if same else "mismatch", algorithm)
