use std::io;

#[derive(Clone, Debug)]
pub struct Node<'a> { pub tag: u8, pub start: usize, pub total: usize, pub content: &'a [u8] }
fn bad(s: impl Into<String>) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, s.into()) }
pub fn parse<'a>(b: &'a [u8]) -> io::Result<Node<'a>> {
    if b.len() < 2 { return Err(bad("truncated DER header")); }
    let n = b[1];
    let (head, len) = if n & 0x80 == 0 { (2, n as usize) } else {
        let count = (n & 0x7f) as usize;
        if count == 0 || count > 8 || b.len() < count + 2 { return Err(bad("invalid DER length")); }
        let mut len = 0usize;
        for x in &b[2..2 + count] { len = len.checked_mul(256).and_then(|v| v.checked_add(*x as usize)).ok_or_else(|| bad("DER length overflow"))?; }
        (count + 2, len)
    };
    let end = head.checked_add(len).ok_or_else(|| bad("DER length overflow"))?;
    if end > b.len() { return Err(bad("DER value exceeds input")); }
    Ok(Node { tag: b[0], start: 0, total: end, content: &b[head..end] })
}
pub fn children<'a>(n: &Node<'a>) -> io::Result<Vec<Node<'a>>> {
    let mut out = Vec::new(); let mut rest = n.content; let mut off = 0;
    while !rest.is_empty() { let mut x = parse(rest)?; x.start = off; off += x.total; rest = &rest[x.total..]; out.push(x); }
    Ok(out)
}
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> { let mut v = vec![tag]; let n = content.len(); if n < 128 { v.push(n as u8); } else { let bytes = (n as u64).to_be_bytes(); let first = bytes.iter().position(|x| *x != 0).unwrap_or(7); v.push(0x80 | (8 - first) as u8); v.extend_from_slice(&bytes[first..]); } v.extend_from_slice(content); v }
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> { let body: Vec<u8> = parts.iter().flatten().copied().collect(); tlv(0x30, &body) }
pub fn octets(v: &[u8]) -> Vec<u8> { tlv(4, v) }
pub fn utf8(v: &str) -> Vec<u8> { tlv(0x0c, v.as_bytes()) }
pub fn uint(mut v: u64) -> Vec<u8> { let mut b = Vec::new(); while v > 0 { b.push(v as u8); v >>= 8; } if b.is_empty() { b.push(0); } b.reverse(); if b[0] & 0x80 != 0 { b.insert(0, 0); } tlv(2, &b) }
pub fn read_uint(n: &Node<'_>) -> io::Result<u64> { if n.tag != 2 || n.content.is_empty() || n.content.len() > 9 { return Err(bad("invalid integer")); } let mut v=0u64; for x in n.content { v = v.checked_mul(256).and_then(|q| q.checked_add(*x as u64)).ok_or_else(|| bad("integer overflow"))?; } Ok(v) }
