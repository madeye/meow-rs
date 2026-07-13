//! Reference **server** port of Xray/mihomo `encryption/server.go`, used only by
//! the loopback integration test to verify the client against an independent
//! implementation of the same wire protocol. Not compiled into shipped builds.

use std::collections::HashMap;

use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use ctr::cipher::StreamCipher;
use meow_common::{MeowError, Result};
use meow_transport::Stream;

use super::aead::{
    blake3_sum256, create_padding, decode_length, encode_length, new_ctr, parse_padding, Aead,
    Padding, MLKEM768_CT_LEN, MLKEM768_EK_LEN, X25519_LEN,
};
use super::client::{spawn_relay, DataPhase};

/// A long-term server key with its public encoding cached alongside.
pub(crate) enum ServerKey {
    X25519(StaticSecret, [u8; 32]),
    MlKem(Box<DecapsulationKey<MlKem768>>, Vec<u8>),
}

impl ServerKey {
    /// Generate a fresh X25519 server key.
    pub(crate) fn new_x25519() -> Self {
        let sk = StaticSecret::from(rand_array::<32>());
        let pk = PublicKey::from(&sk).to_bytes();
        ServerKey::X25519(sk, pk)
    }

    /// Generate a fresh ML-KEM-768 server key.
    pub(crate) fn new_mlkem() -> Self {
        let (dk, ek) = MlKem768::generate_keypair();
        ServerKey::MlKem(Box::new(dk), ek.to_bytes().as_slice().to_vec())
    }

    /// The public bytes a client uses in its `encryption` string.
    pub(crate) fn public_bytes(&self) -> Vec<u8> {
        match self {
            ServerKey::X25519(_, pk) => pk.to_vec(),
            ServerKey::MlKem(_, ek) => ek.clone(),
        }
    }
}

/// A minimal reference `ServerInstance` (client-facing role only).
pub(crate) struct ServerInstance {
    keys: Vec<ServerKey>,
    nfs_pkeys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    seconds_from: i64,
    seconds_to: i64,
    padding: Padding,
    sessions: Mutex<HashMap<[u8; 16], Vec<u8>>>,
}

impl ServerInstance {
    pub(crate) fn init(
        keys: Vec<ServerKey>,
        xor_mode: u32,
        seconds_from: i64,
        seconds_to: i64,
        padding: &str,
    ) -> std::result::Result<Self, String> {
        let mut nfs_pkeys_bytes = Vec::with_capacity(keys.len());
        let mut hash32s = Vec::with_capacity(keys.len());
        let mut relays_length = 0usize;
        for k in &keys {
            let pk = k.public_bytes();
            match k {
                ServerKey::X25519(..) => relays_length += X25519_LEN + 32,
                ServerKey::MlKem(..) => relays_length += MLKEM768_CT_LEN + 32,
            }
            hash32s.push(blake3_sum256(&pk));
            nfs_pkeys_bytes.push(pk);
        }
        relays_length -= 32;
        Ok(Self {
            keys,
            nfs_pkeys_bytes,
            hash32s,
            relays_length,
            xor_mode,
            seconds_from,
            seconds_to,
            padding: parse_padding(padding)?,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) async fn handshake(&self, mut stream: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let mut use_aes = true;

        // ── Read iv + relays and recover nfsKey ───────────────────────────────
        let mut iv_and_relays = vec![0u8; 16 + self.relays_length];
        stream
            .read_exact(&mut iv_and_relays)
            .await
            .map_err(MeowError::Io)?;
        let iv: [u8; 16] = iv_and_relays[..16].try_into().unwrap();
        let mut relays = iv_and_relays[16..].to_vec();

        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr = None;
        let mut pos = 0usize;
        let n = self.keys.len();
        for (j, key) in self.keys.iter().enumerate() {
            if let Some(lc) = last_ctr.as_mut() {
                let (a, _) = relays.split_at_mut(pos + 32);
                StreamCipher::apply_keystream(lc, &mut a[pos..pos + 32]);
            }
            let index = match key {
                ServerKey::X25519(..) => X25519_LEN,
                ServerKey::MlKem(..) => MLKEM768_CT_LEN,
            };
            if self.xor_mode > 0 {
                new_ctr(&self.nfs_pkeys_bytes[j], &iv)
                    .apply_keystream(&mut relays[pos..pos + index]);
            }
            match key {
                ServerKey::X25519(sk, _) => {
                    let peer: [u8; 32] = relays[pos..pos + X25519_LEN].try_into().unwrap();
                    if peer[31] > 127 {
                        return Err(server_err("X25519 public key high bit set"));
                    }
                    nfs_key = sk
                        .diffie_hellman(&PublicKey::from(peer))
                        .to_bytes()
                        .to_vec();
                }
                ServerKey::MlKem(dk, _) => {
                    nfs_key = dk
                        .decapsulate_slice(&relays[pos..pos + MLKEM768_CT_LEN])
                        .map_err(|_| server_err("ML-KEM decapsulation failed"))?
                        .as_slice()
                        .to_vec();
                }
            }
            if j == n - 1 {
                break;
            }
            let mut lc = new_ctr(&nfs_key, &iv);
            let hash_pos = pos + index;
            lc.apply_keystream(&mut relays[hash_pos..hash_pos + 32]);
            if relays[hash_pos..hash_pos + 32] != self.hash32s[j + 1] {
                return Err(server_err("unexpected relay hash32"));
            }
            last_ctr = Some(lc);
            pos += index + 32;
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key, use_aes);

        // ── Read the client's length prefix (with AES/ChaCha auto-detect) ─────
        let mut enc_length = vec![0u8; 18];
        stream
            .read_exact(&mut enc_length)
            .await
            .map_err(MeowError::Io)?;
        let dec = match nfs_aead.open(&enc_length) {
            Ok(d) => d,
            Err(_) => {
                use_aes = !use_aes;
                nfs_aead = Aead::new(&iv, &nfs_key, use_aes);
                nfs_aead
                    .open(&enc_length)
                    .map_err(|_| server_err("length AEAD open failed"))?
            }
        };
        let length = decode_length(&dec[..2]);

        if length == 32 {
            return self
                .handshake_0rtt(stream, iv, nfs_aead, nfs_key, use_aes)
                .await;
        }

        // ── 1-RTT: read the client's PFS public key ───────────────────────────
        if length < MLKEM768_EK_LEN + X25519_LEN + 16 {
            return Err(server_err("PFS key exchange too short"));
        }
        let mut enc_pfs = vec![0u8; length];
        stream
            .read_exact(&mut enc_pfs)
            .await
            .map_err(MeowError::Io)?;
        let client_pfs = nfs_aead
            .open(&enc_pfs)
            .map_err(|_| server_err("client PFS AEAD open failed"))?;

        let client_ek =
            EncapsulationKey::<MlKem768>::new_from_slice(&client_pfs[..MLKEM768_EK_LEN])
                .map_err(|_| server_err("bad client ML-KEM key"))?;
        let (ct, mlkem_shared) = client_ek.encapsulate();
        let peer_x: [u8; 32] = client_pfs[MLKEM768_EK_LEN..MLKEM768_EK_LEN + X25519_LEN]
            .try_into()
            .unwrap();
        let x_sk = StaticSecret::from(rand_array::<32>());
        let x_shared = x_sk.diffie_hellman(&PublicKey::from(peer_x)).to_bytes();

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(mlkem_shared.as_slice());
        pfs_key.extend_from_slice(&x_shared);
        let mut server_pfs_public = Vec::with_capacity(MLKEM768_CT_LEN + X25519_LEN);
        server_pfs_public.extend_from_slice(ct.as_slice());
        server_pfs_public.extend_from_slice(&PublicKey::from(&x_sk).to_bytes());

        let mut united_key = pfs_key.clone();
        united_key.extend_from_slice(&nfs_key);
        let mut aead = Aead::new(&server_pfs_public, &united_key, use_aes);
        let peer_aead = Aead::new(&client_pfs, &united_key, use_aes);

        // ── Ticket + optional session caching ─────────────────────────────────
        let mut ticket = rand_array::<16>();
        let seconds = if self.seconds_to == 0 {
            self.seconds_from * rand_between(50, 100) / 100
        } else {
            rand_between(self.seconds_from, self.seconds_to)
        };
        ticket[..2].copy_from_slice(&encode_length(seconds as usize));
        if seconds > 0 {
            self.sessions.lock().insert(ticket, pfs_key.clone());
        }

        // ── Assemble + fragment-write serverHello (raw, pre-XOR) ──────────────
        let (padding_length, mut padding_lens, padding_gaps) = create_padding(&self.padding);
        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&nfs_aead.seal_max(&server_pfs_public));
        server_hello.extend_from_slice(&aead.seal(&ticket));
        server_hello.extend_from_slice(&aead.seal(&encode_length(padding_length - 18)));
        server_hello.extend_from_slice(&aead.seal(&vec![0u8; padding_length - 18 - 16]));

        let pfs_exchange_len = MLKEM768_CT_LEN + X25519_LEN + 16;
        padding_lens[0] += pfs_exchange_len + 32;
        let mut rest = server_hello.as_slice();
        for (i, &l) in padding_lens.iter().enumerate() {
            if l > 0 {
                let take = l.min(rest.len());
                stream
                    .write_all(&rest[..take])
                    .await
                    .map_err(MeowError::Io)?;
                rest = &rest[take..];
            }
            if let Some(gap) = padding_gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        if !rest.is_empty() {
            stream.write_all(rest).await.map_err(MeowError::Io)?;
        }
        stream.flush().await.map_err(MeowError::Io)?;

        // ── Read the client's clientHello padding (discard) ───────────────────
        let mut enc_len2 = vec![0u8; 18];
        stream
            .read_exact(&mut enc_len2)
            .await
            .map_err(MeowError::Io)?;
        let dec2 = nfs_aead
            .open(&enc_len2)
            .map_err(|_| server_err("client padding length open failed"))?;
        let mut pad = vec![0u8; decode_length(&dec2[..2])];
        stream.read_exact(&mut pad).await.map_err(MeowError::Io)?;
        nfs_aead
            .open(&pad)
            .map_err(|_| server_err("client padding open failed"))?;

        let (write_ctr, read_ctr) = if self.xor_mode == 2 {
            (
                Some(new_ctr(&united_key, &ticket)),
                Some(new_ctr(&united_key, &iv)),
            )
        } else {
            (None, None)
        };

        Ok(spawn_relay(
            stream,
            DataPhase {
                aead,
                peer_aead: Some(peer_aead),
                united_key,
                use_aes,
                pre_write: Vec::new(),
                peer_padding_len: 0,
                write_ctr,
                read_ctr,
                xor: self.xor_mode == 2,
                reset_cache: None,
            },
        ))
    }

    async fn handshake_0rtt(
        &self,
        mut stream: Box<dyn Stream>,
        iv: [u8; 16],
        mut nfs_aead: Aead,
        nfs_key: Vec<u8>,
        use_aes: bool,
    ) -> Result<Box<dyn Stream>> {
        let mut enc_ticket = vec![0u8; 32];
        stream
            .read_exact(&mut enc_ticket)
            .await
            .map_err(MeowError::Io)?;
        let ticket = nfs_aead
            .open(&enc_ticket)
            .map_err(|_| server_err("0-RTT ticket open failed"))?;
        let ticket_arr: [u8; 16] = ticket[..16].try_into().unwrap();
        let pfs_key = self
            .sessions
            .lock()
            .get(&ticket_arr)
            .cloned()
            .ok_or_else(|| server_err("0-RTT: unknown ticket"))?;

        let mut united_key = pfs_key;
        united_key.extend_from_slice(&nfs_key);
        let pre_write = rand_array::<16>().to_vec();
        let aead = Aead::new(&pre_write, &united_key, use_aes);
        let peer_aead = Aead::new(&enc_ticket, &united_key, use_aes);

        let (write_ctr, read_ctr) = if self.xor_mode == 2 {
            let sr: [u8; 16] = pre_write[..16].try_into().unwrap();
            (
                Some(new_ctr(&united_key, &sr)),
                Some(new_ctr(&united_key, &iv)),
            )
        } else {
            (None, None)
        };

        Ok(spawn_relay(
            stream,
            DataPhase {
                aead,
                peer_aead: Some(peer_aead),
                united_key,
                use_aes,
                pre_write,
                peer_padding_len: 0,
                write_ctr,
                read_ctr,
                xor: self.xor_mode == 2,
                reset_cache: None,
            },
        ))
    }
}

fn rand_array<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::Rng::fill(&mut rand::rng(), &mut b[..]);
    b
}

fn rand_between(from: i64, to: i64) -> i64 {
    if to <= from {
        return from;
    }
    from + (rand::random::<u64>() % (to - from) as u64) as i64
}

fn server_err(msg: &str) -> MeowError {
    MeowError::Proxy(format!("vless-encryption(server): {msg}"))
}
