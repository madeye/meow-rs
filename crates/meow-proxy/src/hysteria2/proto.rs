use super::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const MAX_UDP_SIZE: usize = 4096;
pub const DEFAULT_UDP_MTU: usize = 1200 - 3;

const AUTH_PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Random padding for the hysteria2 auth HTTP/3 request (256..2048 bytes).
pub fn auth_request_padding() -> String {
    let len = 256 + (rand::random::<u16>() as usize % (2048 - 256));
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = usize::from(rand::random::<u8>()) % AUTH_PADDING_CHARS.len();
        out.push(AUTH_PADDING_CHARS[idx] as char);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

pub fn encode_tcp_request(addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    if addr.is_empty() || addr.len() > MAX_ADDRESS_LENGTH {
        return Err(Error::protocol("invalid TCP request address length"));
    }

    let mut out = Vec::with_capacity(
        varint_len(FRAME_TYPE_TCP_REQUEST)
            + varint_len(addr.len() as u64)
            + addr.len()
            + 1
            + payload.len(),
    );
    put_varint(FRAME_TYPE_TCP_REQUEST, &mut out)?;
    put_varint(addr.len() as u64, &mut out)?;
    out.extend_from_slice(addr.as_bytes());
    put_varint(0, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub async fn read_tcp_response<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let status = reader.read_u8().await?;
    let message_len = read_varint_async(reader).await? as usize;
    if message_len > MAX_MESSAGE_LENGTH {
        return Err(Error::protocol("invalid TCP response message length"));
    }

    let mut message = vec![0u8; message_len];
    if message_len > 0 {
        reader.read_exact(&mut message).await?;
    }

    let padding_len = read_varint_async(reader).await? as usize;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(Error::protocol("invalid TCP response padding length"));
    }
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        reader.read_exact(&mut padding).await?;
    }

    match status {
        0 => Ok(()),
        1 => Err(Error::protocol(format!(
            "remote TCP error: {}",
            String::from_utf8_lossy(&message)
        ))),
        _ => Err(Error::protocol("invalid TCP response status")),
    }
}

pub fn udp_header_len(addr: &str) -> Result<usize> {
    if addr.is_empty() || addr.len() > MAX_ADDRESS_LENGTH {
        return Err(Error::protocol("invalid UDP address length"));
    }
    Ok(8 + varint_len(addr.len() as u64) + addr.len())
}

pub fn encode_udp_message(message: &UdpMessage) -> Result<Vec<u8>> {
    let header_len = udp_header_len(&message.addr)?;
    let size = header_len
        .checked_add(message.data.len())
        .ok_or_else(|| Error::protocol("UDP message size overflow"))?;
    if size > MAX_UDP_SIZE + header_len {
        return Err(Error::protocol("UDP payload is too large"));
    }

    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&message.session_id.to_be_bytes());
    out.extend_from_slice(&message.packet_id.to_be_bytes());
    out.push(message.frag_id);
    out.push(message.frag_count);
    put_varint(message.addr.len() as u64, &mut out)?;
    out.extend_from_slice(message.addr.as_bytes());
    out.extend_from_slice(&message.data);
    Ok(out)
}

pub fn decode_udp_message(input: &[u8]) -> Result<UdpMessage> {
    if input.len() < 9 {
        return Err(Error::protocol("UDP message too short"));
    }

    let session_id = u32::from_be_bytes(input[0..4].try_into().expect("fixed slice"));
    let packet_id = u16::from_be_bytes(input[4..6].try_into().expect("fixed slice"));
    let frag_id = input[6];
    let frag_count = input[7];
    let mut pos = 8;
    let addr_len = read_varint(input, &mut pos)? as usize;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return Err(Error::protocol("invalid UDP address length"));
    }
    let addr_end = pos
        .checked_add(addr_len)
        .ok_or_else(|| Error::protocol("UDP address length overflow"))?;
    if addr_end > input.len() {
        return Err(Error::protocol("truncated UDP address"));
    }
    let addr = std::str::from_utf8(&input[pos..addr_end])
        .map_err(|_| Error::protocol("UDP address is not UTF-8"))?
        .to_string();
    Ok(UdpMessage {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr,
        data: input[addr_end..].to_vec(),
    })
}

pub fn put_varint(value: u64, out: &mut Vec<u8>) -> Result<()> {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => {
            out.push(((value >> 8) as u8) | 0x40);
            out.push(value as u8);
        }
        16_384..=1_073_741_823 => {
            out.push(((value >> 24) as u8) | 0x80);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            out.push(((value >> 56) as u8) | 0xc0);
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => return Err(Error::protocol("QUIC varint overflow")),
    }
    Ok(())
}

pub fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

pub fn read_varint(input: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos >= input.len() {
        return Err(Error::protocol("truncated QUIC varint"));
    }
    let first = input[*pos];
    let len = 1usize << (first >> 6);
    if input.len().saturating_sub(*pos) < len {
        return Err(Error::protocol("truncated QUIC varint"));
    }
    let mut value = u64::from(first & 0x3f);
    for b in &input[*pos + 1..*pos + len] {
        value = (value << 8) | u64::from(*b);
    }
    *pos += len;
    Ok(value)
}

async fn read_varint_async<R>(reader: &mut R) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    let first = reader.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varint_round_trip_boundaries() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut encoded = Vec::new();
            put_varint(value, &mut encoded).unwrap();
            let mut pos = 0;
            assert_eq!(read_varint(&encoded, &mut pos).unwrap(), value);
            assert_eq!(pos, encoded.len());
        }
    }

    #[test]
    fn tcp_request_layout_starts_with_frame_type() {
        let encoded = encode_tcp_request("example.com:443", b"hello").unwrap();
        let mut pos = 0;
        assert_eq!(
            read_varint(&encoded, &mut pos).unwrap(),
            FRAME_TYPE_TCP_REQUEST
        );
        assert_eq!(read_varint(&encoded, &mut pos).unwrap(), 15);
        assert_eq!(&encoded[pos..pos + 15], b"example.com:443");
    }

    #[test]
    fn udp_message_round_trip() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 9,
            frag_id: 1,
            frag_count: 2,
            addr: "127.0.0.1:53".into(),
            data: b"payload".to_vec(),
        };
        let encoded = encode_udp_message(&message).unwrap();
        assert_eq!(decode_udp_message(&encoded).unwrap(), message);
    }
}
