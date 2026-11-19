import hashlib
import os
import threading
import tracemalloc
import zlib

import pytest

from encryptx.core import file_operations as ops
from encryptx.crypto.modern import ALGORITHMS, CHUNK_SIZE, KDFS

PW = "correct horse"


def make_tree(root):
    (root / "sub" / "deep").mkdir(parents=True)
    (root / "empty").mkdir()
    (root / "a.txt").write_bytes(b"hello " * 1000)
    (root / "sub" / "b.bin").write_bytes(os.urandom(300_000))
    (root / "sub" / "deep" / "ملف.txt").write_text("unicode name ✓", encoding="utf-8")
    return root


@pytest.mark.parametrize("algo", list(ALGORITHMS))
@pytest.mark.parametrize("kdf", KDFS)
def test_roundtrip_every_algorithm(tmp_path, algo, kdf):
    src = tmp_path / "secret.bat"
    data = b"@echo off\n" * 5000
    src.write_bytes(data)
    out = ops.encrypt_path(src, tmp_path / "o", PW, algo, kdf, checksum_algo="SHA-256")
    res = ops.decrypt_path(out, tmp_path / "r", PW)
    assert open(res.path, "rb").read() == data
    assert os.path.basename(res.path) == "secret.bat"
    assert (res.checksum, res.algorithm) == ("verified", "SHA-256")


@pytest.mark.parametrize("size", [0, 1, 15, 16, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1,
                                  2 * CHUNK_SIZE, 3 * CHUNK_SIZE + 77])
@pytest.mark.parametrize("algo", ["AES-256-GCM", "AES-256-CBC + HMAC-SHA256"])
def test_chunk_boundaries(tmp_path, size, algo):
    src = tmp_path / "f.dat"
    data = os.urandom(size)
    src.write_bytes(data)
    out = ops.encrypt_path(src, tmp_path / "o", PW, algo, compress=False)
    res = ops.decrypt_path(out, tmp_path / "r", PW)
    assert open(res.path, "rb").read() == data


def test_compression_roundtrip(tmp_path):
    src = tmp_path / "t.txt"
    src.write_bytes(b"abc" * 2_000_000)
    out = ops.encrypt_path(src, tmp_path / "o", PW, compress=True)
    assert os.path.getsize(out) < 200_000
    assert open(ops.decrypt_path(out, tmp_path / "r", PW).path, "rb").read() == src.read_bytes()


def test_folder_roundtrip_and_checksum(tmp_path):
    src = make_tree(tmp_path / "MyFolder")
    before = ops.hash_path(src)
    out = ops.encrypt_path(src, tmp_path / "o", PW, checksum_algo="SHA3-256")
    res = ops.decrypt_path(out, tmp_path / "r", PW)
    assert res.checksum == "verified"
    assert os.path.basename(res.path) == "MyFolder"
    assert ops.hash_path(res.path) == before            # identical content + names
    assert (tmp_path / "r" / "MyFolder" / "empty").is_dir()


def test_folder_checksum_changes_with_content(tmp_path):
    src = make_tree(tmp_path / "F")
    h1 = ops.hash_path(src, ["SHA-256"])
    (src / "a.txt").write_bytes(b"changed")
    assert ops.hash_path(src, ["SHA-256"]) != h1


def test_file_checksums_match_standard_tools(tmp_path):
    p = tmp_path / "x.bin"
    data = os.urandom(5_000_000)
    p.write_bytes(data)
    h = ops.hash_path(p)
    assert h["SHA-256"] == hashlib.sha256(data).hexdigest()
    assert h["MD5"] == hashlib.md5(data).hexdigest()
    assert h["BLAKE2b"] == hashlib.blake2b(data).hexdigest()
    assert h["CRC32"] == f"{zlib.crc32(data) & 0xffffffff:08x}"


def test_matching(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"data")
    h = ops.hash_path(p)
    sha = h["SHA-256"]
    assert ops.matching_algorithms(h, sha) == ["SHA-256"]
    assert ops.matching_algorithms(h, sha.upper()) == ["SHA-256"]
    assert ops.matching_algorithms(h, f"{sha}  x") == ["SHA-256"]          # sha256sum line
    assert ops.matching_algorithms(h, "SHA256: " + sha) == ["SHA-256"]
    assert ops.matching_algorithms(h, "deadbeef") == []
    assert ops.matching_algorithms(h, "") == []


def test_wrong_password_leaves_nothing(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"x" * 100)
    out = ops.encrypt_path(src, tmp_path / "o", PW)
    with pytest.raises(ValueError):
        ops.decrypt_path(out, tmp_path / "r", "wrong")
    assert not list((tmp_path / "r").iterdir())


def test_file_is_unreadable(tmp_path):
    src = tmp_path / "Pz_client_mods.bat"
    src.write_bytes(b"@echo off\nrem secret\n" * 100)
    out = ops.encrypt_path(src, tmp_path / "o", PW, hide_name=True)
    blob = open(out, "rb").read()
    assert b"Pz_client" not in blob and b"echo" not in blob and b"AES" not in blob
    assert b"Pz_client" not in os.path.basename(out).encode()


def test_tamper_reorder_truncate(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(os.urandom(3 * CHUNK_SIZE + 5))
    out = ops.encrypt_path(src, tmp_path / "o", PW, compress=False)
    good = open(out, "rb").read()

    def attempt(blob):
        bad = tmp_path / "bad.encx"
        bad.write_bytes(blob)
        with pytest.raises(ValueError):
            ops.decrypt_path(bad, tmp_path / "r", PW)
        assert not list((tmp_path / "r").glob("*"))

    flipped = bytearray(good)
    flipped[len(good) // 2] ^= 1
    attempt(bytes(flipped))                         # modified byte in the middle
    attempt(good[:-5])                              # cut the end (trailer damaged)
    rec = 12 + CHUNK_SIZE + 16
    p = 1068
    swapped = good[:p] + good[p + rec:p + 2 * rec] + good[p:p + rec] + good[p + 2 * rec:]
    attempt(swapped)                                # chunks 0 and 1 swapped
    dropped = good[:p + rec] + good[p + 2 * rec:]
    attempt(dropped)                                # chunk 1 removed


def test_cancel_cleans_up(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(os.urandom(3 * CHUNK_SIZE))
    ev = threading.Event()
    ev.set()
    with pytest.raises(ops.OperationCancelled):
        ops.encrypt_path(src, tmp_path / "o", PW, cancel=ev)
    assert not list((tmp_path / "o").glob("*"))


def test_memory_is_constant(tmp_path):
    src = tmp_path / "big"
    with open(src, "wb") as f:
        for _ in range(32):
            f.write(os.urandom(CHUNK_SIZE))                 # 32 MiB
    tracemalloc.start()
    out = ops.encrypt_path(src, tmp_path / "o", PW, compress=False, checksum_algo="SHA-256")
    ops.decrypt_path(out, tmp_path / "r", PW)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 14 * 1024 * 1024, peak                    # far below the 32 MiB file
    assert open(tmp_path / "r" / "big", "rb").read() == src.read_bytes()


def test_progress_reaches_one(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(os.urandom(2 * CHUNK_SIZE))
    seen = []
    out = ops.encrypt_path(src, tmp_path / "o", PW, progress=seen.append)
    assert seen[-1] == 1.0
    seen.clear()
    ops.decrypt_path(out, tmp_path / "r", PW, progress=seen.append)
    assert seen[-1] == 1.0


def test_on_checksum_callback(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"hello")
    got = []
    ops.encrypt_path(src, tmp_path / "o", PW, checksum_algo="SHA-256",
                     on_checksum=lambda alg, digest: got.append((alg, digest)))
    assert got == [("SHA-256", hashlib.sha256(b"hello").hexdigest())]
