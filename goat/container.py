"""The GOAT container: seal, parse, verify, decrypt.

Constants here must match include/goat/goat.h; tests/goat_test.py checks the
two against each other so a drift on either side fails the test rather than
the device.
"""

import hashlib
import secrets

from . import rsa
from .der import (DER_INTEGER, DER_OCTET_STRING, DER_SEQUENCE, DER_UTF8_STRING,
                  DerError, der_children, der_octets, der_parse_one, der_seq,
                  der_str, der_uint)
from .aes import cbc_decrypt, cbc_encrypt

GOAT_MAGIC = b"GOAT\x01"
GOAT_VERSION = 1

GOAT_STAGE_BASE = 0x180100000
GOAT_STAGE_SIZE = 0xE8000
GOAT_DEFAULT_LOAD_BASE = 0x180180000
GOAT_SRAM_END = GOAT_STAGE_BASE + GOAT_STAGE_SIZE

KEYWRAP_RSA = 1


class Container:
    """A parsed container. Everything in here came out of a TLV walk, so it is
    untrusted until verify() and the digest check have both passed."""

    def __init__(self):
        self.version = GOAT_VERSION
        self.payload_sha = b""
        self.payload_len = 0
        self.load_base = 0
        self.entry_off = 0
        self.iv = b""
        self.cipher = b""
        self.has_keywrap = False
        self.keywrap_algo = 0
        self.keywrap_blob = b""
        self.cert_serial = 0
        self.issuer = ""
        self.subject = ""
        self.not_before = 0
        self.not_after = 0
        self.modulus = b""
        self.exponent = b""
        self.cert_selfsig = b""
        self.signed_region = b""
        self.cert_tbs = b""
        self.signature = b""

    # -- checks ------------------------------------------------------------

    def cert_ok(self):
        n = int.from_bytes(self.modulus, "big")
        e = int.from_bytes(self.exponent, "big")
        return rsa.verify(n, e, self.cert_selfsig, self.cert_tbs)

    def verify(self):
        if not self.cert_ok():
            return False
        n = int.from_bytes(self.modulus, "big")
        e = int.from_bytes(self.exponent, "big")
        return rsa.verify(n, e, self.signature, self.signed_region)

    def digest_ok(self, payload):
        return hashlib.sha256(payload).digest() == self.payload_sha

    def unwrap_key(self, priv):
        """Recover the AES key a wrapped container carries, using the
        identity's private key. Only meaningful when has_keywrap is set."""
        n = priv["n"]
        k = (n.bit_length() + 7) // 8
        if len(self.keywrap_blob) != k:
            raise ValueError("wrapped key is %d bytes, modulus is %d"
                             % (len(self.keywrap_blob), k))
        m = pow(int.from_bytes(self.keywrap_blob, "big"), priv["d"], n)
        em = m.to_bytes(k, "big")
        # seal() writes a type-2 (key transport) block, so unwrap the type-2
        # block. Expecting the signature block type here is how a wrapped
        # container ends up unopenable with its own private key.
        return rsa.pkcs1_unwrap(em, 32)

    def decrypt(self, aes_key):
        plaintext = cbc_decrypt(aes_key, self.iv, self.cipher)
        if len(plaintext) != self.payload_len:
            raise ValueError("decrypted %d bytes, container says %d"
                             % (len(plaintext), self.payload_len))
        if not self.digest_ok(plaintext):
            raise ValueError("digest mismatch on the decrypted payload")
        return plaintext


def seal(payload, aes_key, identity, load_base, entry_off, wrap=False):
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes")
    if not payload:
        raise ValueError("refusing to seal an empty payload")
    if len(payload) > 0x8000000:
        raise ValueError("payload is too large for this format")
    if entry_off >= len(payload):
        raise ValueError("entry offset is past the end of the payload")
    if load_base < GOAT_STAGE_BASE:
        raise ValueError("load base overlaps the container staging window")
    if load_base + len(payload) > GOAT_SRAM_END:
        raise ValueError("load base + payload runs past the SRAM window")

    priv = {"n": identity["n"], "e": identity["e"], "d": identity["d"]}

    digest = hashlib.sha256(payload).digest()
    iv = secrets.token_bytes(16)
    ciphertext = cbc_encrypt(aes_key, iv, payload)

    payload_seq = der_seq(der_octets(digest),
                          der_uint(len(payload)),
                          der_uint(load_base),
                          der_uint(entry_off))

    enc_children = [der_octets(iv), der_octets(ciphertext)]
    if wrap:
        k = (identity["n"].bit_length() + 7) // 8
        blob = pow(int.from_bytes(rsa.pkcs1_wrap(aes_key, k), "big"),
                   identity["e"], identity["n"]).to_bytes(k, "big")
        enc_children.append(der_seq(der_uint(KEYWRAP_RSA), der_octets(blob)))
    encryption = der_seq(*enc_children)

    cert, _ = rsa.build_cert(identity, priv)
    body = der_seq(payload_seq, encryption, cert)
    signature = rsa.sign(priv, body)

    return der_seq(der_octets(GOAT_MAGIC), der_uint(GOAT_VERSION), body,
                   der_octets(signature))


def parse(data):
    buf = bytes(data)

    top = der_parse_one(buf)
    if top.tag != DER_SEQUENCE:
        raise DerError("container is not a SEQUENCE")
    children = der_children(top)
    if len(children) != 4:
        raise DerError("container has %d members, want 4" % len(children))
    magic, version, body, sig = children

    if magic.tag != DER_OCTET_STRING or magic.content != GOAT_MAGIC:
        raise DerError("bad magic")
    if version.tag != DER_INTEGER:
        raise DerError("version is not an INTEGER")
    if int.from_bytes(version.content, "big") != GOAT_VERSION:
        raise DerError("unsupported container version")
    if body.tag != DER_SEQUENCE:
        raise DerError("body is not a SEQUENCE")
    if sig.tag != DER_OCTET_STRING:
        raise DerError("signature is not an OCTET STRING")

    c = Container()
    c.version = GOAT_VERSION
    c.signature = sig.content
    # The signature covers the body TLV *including* its tag and length, which
    # is what src/goat/goat.c points signed_region at. Getting this wrong is
    # how you end up with a container that verifies on the host and fails on
    # the device, so it is asserted against in tests/goat_test.py.
    c.signed_region = top.content[body.start:body.start + body.total]

    parts = der_children(body)
    if len(parts) != 3:
        raise DerError("body has %d members, want 3" % len(parts))
    payload_seq, encryption, cert = parts

    pf = der_children(payload_seq)
    if len(pf) != 4:
        raise DerError("payload block has %d members, want 4" % len(pf))
    if pf[0].tag != DER_OCTET_STRING or len(pf[0].content) != 32:
        raise DerError("payload digest must be 32 bytes")
    c.payload_sha = pf[0].content
    c.payload_len = int.from_bytes(pf[1].content, "big")
    c.load_base = int.from_bytes(pf[2].content, "big")
    c.entry_off = int.from_bytes(pf[3].content, "big")

    ef = der_children(encryption)
    if len(ef) not in (2, 3):
        raise DerError("encryption block has %d members" % len(ef))
    if ef[0].tag != DER_OCTET_STRING or len(ef[0].content) != 16:
        raise DerError("IV must be 16 bytes")
    c.iv = ef[0].content
    if ef[1].tag != DER_OCTET_STRING:
        raise DerError("ciphertext is not an OCTET STRING")
    c.cipher = ef[1].content
    if len(ef) == 3:
        kf = der_children(ef[2])
        if len(kf) != 2:
            raise DerError("keyWrap has %d members" % len(kf))
        c.keywrap_algo = int.from_bytes(kf[0].content, "big")
        c.keywrap_blob = kf[1].content
        c.has_keywrap = True

    cf = der_children(cert)
    if len(cf) != 2:
        raise DerError("certificate has %d members, want 2" % len(cf))
    tbs, selfsig = cf
    if tbs.tag != DER_SEQUENCE:
        raise DerError("certificate TBS is not a SEQUENCE")
    if selfsig.tag != DER_OCTET_STRING:
        raise DerError("cert self-signature is not an OCTET STRING")

    # cert_tbs is the TBS TLV, which is exactly what the self-signature
    # covers -- tag and length included, for the same reason as the body.
    # child offsets are relative to cert.content.
    c.cert_tbs = cert.content[tbs.start:tbs.start + tbs.total]

    tf = der_children(tbs)
    if len(tf) != 6:
        raise DerError("certificate TBS has %d members, want 6" % len(tf))
    c.cert_serial = int.from_bytes(tf[0].content, "big")
    if tf[1].tag != DER_UTF8_STRING or tf[2].tag != DER_UTF8_STRING:
        raise DerError("issuer/subject must be UTF8String")
    c.issuer = tf[1].content.decode("utf-8", "replace")
    c.subject = tf[2].content.decode("utf-8", "replace")
    c.not_before = int.from_bytes(tf[3].content, "big")
    c.not_after = int.from_bytes(tf[4].content, "big")
    if tf[5].tag != DER_SEQUENCE:
        raise DerError("public key is not a SEQUENCE")
    pub = der_children(tf[5])
    if len(pub) != 2:
        raise DerError("public key has %d members" % len(pub))
    c.modulus = pub[0].content
    c.exponent = pub[1].content
    c.cert_selfsig = selfsig.content

    return c

    return c
