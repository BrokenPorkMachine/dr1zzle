"""RSA and certificates (pure Python).

Key generation uses Miller-Rabin with a fixed small-prime sieve, which is
plenty for a key the user mints locally and never publishes. Signing and
verification are PKCS#1 v1.5 over SHA-256, matching src/goat/rsa.c.

The certificate here is deliberately minimal: issuer, subject, validity, the
public key, and a self-signature. That is the "certificate style embedding"
the container format uses -- the verifying key travels with the payload and
vouches for itself, so the device needs nothing but the device.
"""

import hashlib
import os
import secrets
from math import gcd

from .der import (DER_INTEGER, DER_OCTET_STRING, DER_SEQUENCE,
                  der_octets, der_seq, der_str, der_uint)

DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def keygen(bits=2048, e=65537):
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2 - (bits % 2))
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue
        d = pow(e, -1, phi)
        return {"n": n, "e": e, "d": d, "bits": bits}


def pkcs1_encode(digest, em_length):
    """EMSA-PKCS1-v1_5 encoding for a SHA-256 digest (the signature case)."""
    t = DIGESTINFO_SHA256 + digest
    if em_length < len(t) + 11:
        raise ValueError("key too small for this digest")
    return b"\x00\x01" + b"\xff" * (em_length - len(t) - 3) + b"\x00" + t


def pkcs1_wrap(data, em_length):
    """RSAES-PKCS1-v1_5: 00 02 <non-zero padding> 00 <data>.

    Deliberately a different block type from pkcs1_encode: a signature block
    and a key-transport block are not the same thing, even though both are
    called "PKCS#1 v1.5".
    """
    if len(data) > em_length - 11:
        raise ValueError("key too small to wrap this much data")
    pad_len = em_length - len(data) - 3
    # os.urandom rather than secrets.randbytes: it is the same CSPRNG, and it
    # is present on every Python this tool runs on (randbytes is not, on some
    # bundled interpreters).
    pad = bytes(b if b != 0 else 1 for b in os.urandom(pad_len))
    return b"\x00\x02" + pad + b"\x00" + data


def pkcs1_unwrap(block, expected_len):
    """Recover data from a 00 02 ... 00 <data> block. Raises if malformed."""
    if len(block) < 11:
        raise ValueError("wrapped key block is too short")
    if block[0] != 0x00 or block[1] != 0x02:
        raise ValueError("wrapped key block is not a PKCS#1 v1.5 type-2 block")
    sep = block.index(b"\x00", 2)
    if sep < 10:
        raise ValueError("wrapped key block has no padding")
    data = block[sep + 1:]
    if len(data) != expected_len:
        raise ValueError("unwrapped %d bytes, want %d"
                         % (len(data), expected_len))
    return data


def sign(priv, data):
    k = (priv["n"].bit_length() + 7) // 8
    em = pkcs1_encode(hashlib.sha256(data).digest(), k)
    return pow(int.from_bytes(em, "big"), priv["d"], priv["n"]).to_bytes(k, "big")


def verify(n, e, signature, data):
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(k, "big")
    return em == pkcs1_encode(hashlib.sha256(data).digest(), k)


# --- certificate -----------------------------------------------------------

def _int_octets(value):
    if value < 0:
        raise ValueError("negative")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    while len(body) > 1 and body[0] == 0 and not (body[1] & 0x80):
        body = body[1:]
    return body


def _hex_octets(value):
    """Big-endian octets for a key component: int, or hex string, or bytes."""
    if isinstance(value, int):
        value = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    elif isinstance(value, str):
        value = bytes.fromhex(value)
    else:
        value = bytes(value)
    while len(value) > 1 and value[0] == 0:
        value = value[1:]
    return value


def cert_children(identity):
    """The certificate's members: the TBS SEQUENCE and the self-signature.

    TBS is its own SEQUENCE, so the bytes the signature covers are a
    well-formed TLV the device can point at -- the same shape X.509 uses. The
    fields live one level deeper, which is deliberate: it makes the signature
    boundary unambiguous instead of depending on where a field happens to end.
    """
    pub = der_seq(der_octets(_hex_octets(identity["n"])),
                  der_octets(_int_octets(identity["e"])))
    tbs = der_seq(der_uint(identity["serial"]),
                  der_str(identity["issuer"]),
                  der_str(identity["subject"]),
                  der_uint(identity["not_before"]),
                  der_uint(identity["not_after"]),
                  pub)
    return tbs, pub


def cert_tbs(identity):
    tbs, _ = cert_children(identity)
    return tbs


def build_cert(identity, priv):
    """Self-signed certificate. Returns (cert_der, tbs_der)."""
    tbs, _ = cert_children(identity)
    selfsig = sign(priv, tbs)
    return der_seq(tbs, der_octets(selfsig)), tbs
