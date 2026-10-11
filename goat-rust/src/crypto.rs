use aes::Aes256;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use sha2::{Digest, Sha256};
use std::io;
fn bad(m:impl Into<String>)->io::Error{io::Error::new(io::ErrorKind::InvalidData,m.into())}
pub fn decrypt_cbc(key:&[u8],iv:&[u8],cipher:&[u8])->io::Result<Vec<u8>>{if key.len()!=32||iv.len()!=16||cipher.len()%16!=0{return Err(bad("AES-256-CBC requires a 32-byte key, 16-byte IV, and block-aligned ciphertext"))};let c=Aes256::new_from_slice(key).map_err(|_|bad("invalid AES key"))?;let mut out=Vec::with_capacity(cipher.len());let mut prev=[0u8;16];prev.copy_from_slice(iv);for block in cipher.chunks_exact(16){let mut b=GenericArray::clone_from_slice(block);c.decrypt_block(&mut b);for i in 0..16{out.push(b[i]^prev[i])};prev.copy_from_slice(block)}let pad=*out.last().ok_or_else(||bad("empty ciphertext"))? as usize;if pad==0||pad>16||out.len()<pad||out[out.len()-pad..].iter().any(|x|*x as usize!=pad){return Err(bad("invalid PKCS#7 padding"))};out.truncate(out.len()-pad);Ok(out)}
pub fn sha256(data:&[u8])->[u8;32]{let mut h=Sha256::new();h.update(data);h.finalize().into()}
