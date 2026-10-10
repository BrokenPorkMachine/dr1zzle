"""DER encoding and decoding for the goat container (X.690 subset).

Mirrors src/goat/asn1.c exactly: definite lengths only, low tag numbers only,
and no length that runs past the enclosing buffer. The host and the device
must agree byte for byte on what "valid" means, or a container that verifies
on one side would be rejected by the other.
"""

DER_INTEGER = 0x02
DER_OCTET_STRING = 0x04
DER_UTF8_STRING = 0x0C
DER_SEQUENCE = 0x30


class DerError(ValueError):
    pass


def der_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def der_seq(*parts):
    return der_tlv(DER_SEQUENCE, b"".join(parts))


def der_uint(value):
    if value < 0:
        raise DerError("negative integers are not used by this container")
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 8) // 8, "big")
        while len(body) > 1 and body[0] == 0 and not (body[1] & 0x80):
            body = body[1:]
    return der_tlv(DER_INTEGER, body)


def der_octets(data):
    return der_tlv(DER_OCTET_STRING, bytes(data))


def der_str(text):
    return der_tlv(DER_UTF8_STRING, text.encode("utf-8"))


class TLV:
    __slots__ = ("tag", "content", "start", "total")

    def __init__(self, tag, content, start, total):
        self.tag = tag
        self.content = content
        self.start = start
        self.total = total


def der_parse_one(buf, off=0):
    if len(buf) - off < 2:
        raise DerError("truncated TLV")
    tag = buf[off]
    if (tag & 0x1F) == 0x1F:
        raise DerError("high tag numbers are not used by this container")
    idx = off + 1
    l0 = buf[idx]
    if l0 < 0x80:
        length, idx = l0, idx + 1
    elif l0 == 0x80:
        raise DerError("indefinite length is BER, not DER")
    else:
        octets = l0 & 0x7F
        if octets > 4:
            raise DerError("absurd length")
        if len(buf) - idx < octets:
            raise DerError("truncated length")
        length = 0
        for b in buf[idx + 1:idx + 1 + octets]:
            length = (length << 8) | b
        idx += 1 + octets
        if octets > 1 and buf[off + 2] == 0:
            raise DerError("non-minimal length encoding")
    if length > len(buf) - idx:
        raise DerError("TLV runs past the buffer")
    return TLV(tag, buf[idx:idx + length], off, idx - off + length)


def der_children(tlv):
    out = []
    off = 0
    while off < len(tlv.content):
        child = der_parse_one(tlv.content, off)
        out.append(child)
        off += child.total
    if off != len(tlv.content):
        raise DerError("trailing bytes inside SEQUENCE")
    return out
