use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::io;
#[derive(Debug)]
pub struct Node<'a> {
    pub tag: u8,
    pub start: usize,
    pub total: usize,
    pub content: &'a [u8],
}
fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}
pub fn parse<'a>(b: &'a [u8]) -> io::Result<Node<'a>> {
    if b.len() < 2 {
        return Err(bad("truncated DER header"));
    };
    let tag = b[0];
    let x = b[1];
    let (head, len) = if x & 0x80 == 0 {
        (2, x as usize)
    } else {
        let n = (x & 0x7f) as usize;
        if n == 0 || n > 8 || b.len() < 2 + n {
            return Err(bad("invalid DER length"));
        };
        let mut v: usize = 0;
        for z in &b[2..2 + n] {
            v = v
                .checked_mul(256)
                .and_then(|q| q.checked_add(*z as usize))
                .ok_or_else(|| bad("DER length overflow"))?
        }
        (2 + n, v)
    };
    let end = head
        .checked_add(len)
        .ok_or_else(|| bad("DER length overflow"))?;
    if end > b.len() {
        return Err(bad("DER value exceeds input"));
    }
    Ok(Node {
        tag,
        start: 0,
        total: end,
        content: &b[head..end],
    })
}
pub fn children<'a>(n: &Node<'a>) -> io::Result<Vec<Node<'a>>> {
    let mut v = Vec::new();
    let (mut rest, mut off) = (n.content, 0);
    while !rest.is_empty() {
        let mut x = parse(rest)?;
        x.start = off;
        off += x.total;
        rest = &rest[x.total..];
        v.push(x)
    }
    Ok(v)
}
pub fn uint(n: &Node<'_>) -> io::Result<u64> {
    if n.tag != 2 || n.content.len() > 8 {
        return Err(bad("invalid integer"));
    };
    let mut v = 0;
    for b in n.content {
        v = (v << 8) | u64::from(*b)
    }
    Ok(v)
}
fn text(n: &Node<'_>) -> io::Result<String> {
    if n.tag != 0x0c {
        return Err(bad("expected UTF8String"));
    }
    Ok(String::from_utf8_lossy(n.content).into_owned())
}
fn hx(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
const DIGESTINFO_SHA256: &[u8] =
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
fn verify_pkcs1(n_bytes: &[u8], e_bytes: &[u8], sig: &[u8], data: &[u8]) -> bool {
    let n = BigUint::from_bytes_be(n_bytes);
    let e = BigUint::from_bytes_be(e_bytes);
    let k = (n.bits() as usize + 7) / 8;
    if k == 0 || sig.len() != k {
        return false;
    }
    let m = BigUint::from_bytes_be(sig).modpow(&e, &n);
    let raw = m.to_bytes_be();
    let mut em = vec![0u8; k - raw.len()];
    em.extend_from_slice(&raw);
    let mut expected = Vec::with_capacity(k);
    expected.extend_from_slice(b"\x00\x01");
    if k < DIGESTINFO_SHA256.len() + 32 + 11 {
        return false;
    }
    expected.extend(std::iter::repeat_n(
        0xff,
        k - DIGESTINFO_SHA256.len() - 32 - 3,
    ));
    expected.push(0);
    expected.extend_from_slice(DIGESTINFO_SHA256);
    expected.extend_from_slice(&Sha256::digest(data));
    em == expected
}
pub fn verify_signatures(b: &[u8]) -> io::Result<(bool, bool)> {
    let top = parse(b)?;
    if top.total != b.len() || top.tag != 0x30 {
        return Err(bad("container is not an exact SEQUENCE"));
    };
    let tc = children(&top)?;
    if tc.len() != 4 || tc[0].content != b"GOAT\x01" || uint(&tc[1])? != 1 {
        return Err(bad("invalid GOAT header"));
    };
    let parts = children(&tc[2])?;
    if parts.len() != 3 {
        return Err(bad("invalid container body"));
    };
    let cf = children(&parts[2])?;
    if cf.len() != 2 {
        return Err(bad("invalid certificate"));
    };
    let tf = children(&cf[0])?;
    if tf.len() != 6 {
        return Err(bad("invalid certificate TBS"));
    };
    let pk = children(&tf[5])?;
    if pk.len() != 2 {
        return Err(bad("invalid public key"));
    };
    let body = &top.content[tc[2].start..tc[2].start + tc[2].total];
    let tbs = &parts[2].content[cf[0].start..cf[0].start + cf[0].total];
    let cert_ok = verify_pkcs1(pk[0].content, pk[1].content, cf[1].content, tbs);
    let outer_ok = verify_pkcs1(pk[0].content, pk[1].content, tc[3].content, body);
    Ok((cert_ok, outer_ok))
}
pub fn inspect(b: &[u8]) -> io::Result<String> {
    let top = parse(b)?;
    if top.total != b.len() || top.tag != 0x30 {
        return Err(bad("container is not an exact SEQUENCE"));
    };
    let tc = children(&top)?;
    if tc.len() != 4 {
        return Err(bad("container must have four members"));
    };
    if tc[0].tag != 4 || tc[0].content != b"GOAT\x01" {
        return Err(bad("bad GOAT magic"));
    };
    if uint(&tc[1])? != 1 {
        return Err(bad("unsupported container version"));
    };
    let parts = children(&tc[2])?;
    if parts.len() != 3 {
        return Err(bad("invalid container body"));
    };
    let pf = children(&parts[0])?;
    if pf.len() != 4 || pf[0].tag != 4 || pf[0].content.len() != 32 {
        return Err(bad("invalid payload descriptor"));
    };
    let ef = children(&parts[1])?;
    if ef.len() < 2 || ef.len() > 3 || ef[0].tag != 4 || ef[0].content.len() != 16 || ef[1].tag != 4
    {
        return Err(bad("invalid encryption descriptor"));
    };
    let cf = children(&parts[2])?;
    if cf.len() != 2 {
        return Err(bad("invalid certificate"));
    };
    let tf = children(&cf[0])?;
    if tf.len() != 6 {
        return Err(bad("invalid certificate TBS"));
    };
    let pk = children(&tf[5])?;
    if pk.len() != 2 {
        return Err(bad("invalid public key"));
    };
    Ok(format!("goat container: {} bytes\n  version       : 1\n  payload sha256: {}\n  payload length: {} (0x{:x})\n  load base     : 0x{:x}\n  entry offset  : 0x{:x} -> entry 0x{:x}\n  iv            : {}\n  ciphertext    : {} bytes\n  certificate   :\n    subject     : {}\n    issuer      : {}\n    serial      : 0x{:x}\n    not before  : {}\n    not after   : {}\n    key         : {} bit\n  keywrap       : {}\n  signature     : {} bytes\n",b.len(),hx(pf[0].content),uint(&pf[1])?,uint(&pf[1])?,uint(&pf[2])?,uint(&pf[3])?,uint(&pf[2])?+uint(&pf[3])?,hx(ef[0].content),ef[1].content.len(),text(&tf[2])?,text(&tf[1])?,uint(&tf[0])?,uint(&tf[3])?,uint(&tf[4])?,pk[0].content.len()*8,if ef.len()==3{"present"}else{"none"},tc[3].content.len()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncated() {
        assert!(parse(&[0x30, 3, 1]).is_err())
    }
    #[test]
    fn parses_integer() {
        assert_eq!(uint(&parse(&[2, 1, 7]).unwrap()).unwrap(), 7)
    }
    #[test]
    fn rejects_bad_signature() {
        assert!(!verify_pkcs1(&[0x01], [].as_slice(), &[], &[]))
    }
}

pub fn decrypt_payload(b: &[u8], key: &[u8]) -> io::Result<Vec<u8>> {
    let top = parse(b)?;
    if top.total != b.len() || top.tag != 0x30 {
        return Err(bad("container is not an exact SEQUENCE"));
    };
    let tc = children(&top)?;
    if tc.len() != 4 || tc[0].content != b"GOAT\x01" || uint(&tc[1])? != 1 {
        return Err(bad("invalid GOAT header"));
    };
    let parts = children(&tc[2])?;
    if parts.len() != 3 {
        return Err(bad("invalid container body"));
    };
    let pf = children(&parts[0])?;
    let ef = children(&parts[1])?;
    if pf.len() != 4 || ef.len() < 2 || ef[0].content.len() != 16 || ef[1].tag != 4 {
        return Err(bad("invalid encrypted payload"));
    };
    let plain = crate::crypto::decrypt_cbc(key, ef[0].content, ef[1].content)?;
    let want = uint(&pf[1])? as usize;
    if plain.len() != want {
        return Err(bad("payload length mismatch"));
    };
    if crate::crypto::sha256(&plain) != pf[0].content {
        return Err(bad("payload digest mismatch"));
    };
    Ok(plain)
}
