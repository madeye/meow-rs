use crate::sniffer::SnifferRuntime;
use meow_common::{AuthConfig, ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, ConnectionGuard, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const USER_PASS_AUTH: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

pub async fn handle_socks5(
    tunnel: &Tunnel,
    mut stream: TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<&SnifferRuntime>,
    auth: Option<&AuthConfig>,
    in_name: &str,
    in_port: u16,
) {
    match handle_socks5_inner(
        tunnel,
        &mut stream,
        src_addr,
        sniffer,
        auth,
        in_name,
        in_port,
    )
    .await
    {
        Ok(PostHandshake::Done) => {}
        Ok(PostHandshake::UdpAssociate {
            requested_ip,
            requested_port,
        }) => {
            // The handshake (auth + request) is consumed; the control conn is
            // now ours for the association's lifetime.
            if let Err(e) = crate::socks5_udp::handle_udp_associate(
                tunnel,
                stream,
                src_addr,
                requested_ip,
                requested_port,
                in_name,
                in_port,
            )
            .await
            {
                debug!("SOCKS5 UDP ASSOCIATE error from {}: {}", src_addr, e);
            }
        }
        Err(e) => debug!("SOCKS5 error from {}: {}", src_addr, e),
    }
}

/// Outcome of the SOCKS5 handshake: a CONNECT was fully relayed, or the client
/// requested UDP ASSOCIATE and the (owned) control connection must be handed to
/// the UDP relay.
enum PostHandshake {
    Done,
    UdpAssociate {
        requested_ip: Option<IpAddr>,
        requested_port: u16,
    },
}

async fn handle_socks5_inner(
    tunnel: &Tunnel,
    stream: &mut TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<&SnifferRuntime>,
    auth: Option<&AuthConfig>,
    in_name: &str,
    in_port: u16,
) -> Result<PostHandshake, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + crate::DEFAULT_HANDSHAKE_TIMEOUT;
    // 1. Version/method negotiation
    let mut header = [0u8; 2];
    read_exact_before(stream, &mut header, deadline).await?;
    if header[0] != SOCKS5_VERSION {
        return Err("invalid SOCKS version".into());
    }
    let nmethods = header[1] as usize;
    let mut methods_buf = [0u8; 255];
    read_exact_before(stream, &mut methods_buf[..nmethods], deadline).await?;
    let methods = &methods_buf[..nmethods];

    let in_user: Option<String> = if let Some(auth) = auth
        .filter(|a| !a.credentials.is_empty())
        .filter(|a| !a.should_skip(&src_addr.ip()))
    {
        if !methods.contains(&USER_PASS_AUTH) {
            stream
                .write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHODS])
                .await?;
            return Err("client does not support username/password auth".into());
        }
        stream.write_all(&[SOCKS5_VERSION, USER_PASS_AUTH]).await?;

        // RFC 1929 sub-negotiation: [0x01, ulen, user..., plen, pass...]
        let mut sub_ver = [0u8; 1];
        read_exact_before(stream, &mut sub_ver, deadline).await?;
        if sub_ver[0] != 0x01 {
            return Err("invalid auth sub-negotiation version".into());
        }
        // Borrow username/password from stack buffers; the username is only
        // copied to the heap after a successful verify (audit #182 — the
        // failure/empty path previously allocated two Strings regardless).
        let mut ulen = [0u8; 1];
        read_exact_before(stream, &mut ulen, deadline).await?;
        let mut user_buf = [0u8; 255];
        read_exact_before(stream, &mut user_buf[..ulen[0] as usize], deadline).await?;
        let mut plen = [0u8; 1];
        read_exact_before(stream, &mut plen, deadline).await?;
        let mut pass_buf = [0u8; 255];
        read_exact_before(stream, &mut pass_buf[..plen[0] as usize], deadline).await?;
        let Ok(username) = std::str::from_utf8(&user_buf[..ulen[0] as usize]) else {
            stream.write_all(&[0x01, 0x01]).await?;
            return Err("invalid SOCKS5 username encoding".into());
        };
        let Ok(password) = std::str::from_utf8(&pass_buf[..plen[0] as usize]) else {
            stream.write_all(&[0x01, 0x01]).await?;
            return Err("invalid SOCKS5 password encoding".into());
        };

        if !auth.credentials.verify(username, password) {
            stream.write_all(&[0x01, 0x01]).await?;
            return Err(format!("SOCKS5 auth failed for user {username:?}").into());
        }
        stream.write_all(&[0x01, 0x00]).await?;
        Some(username.to_string())
    } else {
        if !methods.contains(&NO_AUTH) {
            stream
                .write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHODS])
                .await?;
            return Err("client does not support no-auth SOCKS5".into());
        }
        stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;
        None
    };

    // 2. Request
    let mut req = [0u8; 4];
    read_exact_before(stream, &mut req, deadline).await?;
    if req[0] != SOCKS5_VERSION {
        return Err("invalid SOCKS version in request".into());
    }

    let cmd = req[1];
    let atyp = req[3];

    // Parse address (for UDP ASSOCIATE this is the client's advertised source).
    let (host, dst_ip, dst_port) = parse_socks5_address(stream, atyp, deadline).await?;

    if cmd == CMD_UDP_ASSOCIATE {
        // Hand the control connection to the UDP relay; it writes its own reply.
        return Ok(PostHandshake::UdpAssociate {
            requested_ip: dst_ip,
            requested_port: dst_port,
        });
    }

    if cmd != CMD_CONNECT {
        // Send command not supported
        let reply = [SOCKS5_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream.write_all(&reply).await?;
        return Err(format!("unsupported SOCKS5 command: {cmd}").into());
    }

    // 3. Send success reply
    let reply = [
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0, // Bind addr
        0,
        0, // Bind port
    ];
    stream.write_all(&reply).await?;

    // 4. Build metadata and hand off to tunnel
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Socks5,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip,
        dst_port,
        host: Metadata::lower_host(&host),
        in_name: in_name.into(),
        in_port,
        in_user: in_user.as_deref().map(Into::into),
        ..Default::default()
    };

    // Sniff TLS SNI or HTTP Host header from the initial payload bytes.
    if let Some(rt) = sniffer {
        rt.sniff(stream, &mut metadata).await;
    }

    debug!("SOCKS5 CONNECT to {}", metadata.remote_address());

    let inner = tunnel.inner();

    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from the
    // snooping-cache hostname fill-in). Without this, a fake-IP TCP flow
    // reaches rule matching still carrying the 28.x/198.18.x placeholder,
    // matches no DOMAIN/GEOSITE/GEOIP rule, and falls through to
    // MATCH()/final — so domain rules are silently bypassed for TCP under
    // fake-IP. Mirrors `handle_tcp` (meow-tunnel/src/tcp.rs) and the UDP
    // ASSOCIATE path (socks5_udp.rs).
    inner.pre_handle_metadata(&mut metadata);

    // Match rules with lazy enrichment: host → real-IP resolution happens
    // inside only if the scan reaches an IP-based rule that demands it.
    let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy_lazy(&mut metadata).await
    else {
        return Err("no matching rule".into());
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    // RAII-tracked so the entry is removed from `Statistics.connections` even
    // if the relay future is cancelled (listener shutdown, iOS idle sweeper,
    // panic-unwind).
    let _guard = ConnectionGuard::track(
        &inner.stats,
        metadata.pure(),
        rule_name,
        rule_payload,
        smallvec![Arc::from(proxy.name())],
    );

    // Relay buffers on the future's stack — zero per-relay heap allocation (ADR-0011 T6).
    let mut relay_buf_up = [0u8; RELAY_BUF_SIZE];
    let mut relay_buf_dn = [0u8; RELAY_BUF_SIZE];

    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            let up = Arc::clone(_guard.counters());
            let dn = Arc::clone(_guard.counters());
            match copy_bidirectional_buf_tracked(
                stream,
                &mut remote,
                &mut relay_buf_up,
                &mut relay_buf_dn,
                |n| {
                    inner
                        .stats
                        .record_upload(&up, n as meow_common::atomic::Int)
                },
                |n| {
                    inner
                        .stats
                        .record_download(&dn, n as meow_common::atomic::Int)
                },
            )
            .await
            {
                Ok((up, down)) => {
                    debug!("SOCKS5 relay closed: up={up} down={down}");
                }
                Err(e) => debug!("SOCKS5 relay error: {}", e),
            }
        }
        Err(e) => warn!("{} SOCKS5 dial error: {}", metadata.remote_address(), e),
    }

    Ok(PostHandshake::Done)
}

async fn parse_socks5_address(
    stream: &mut TcpStream,
    atyp: u8,
    deadline: tokio::time::Instant,
) -> Result<(String, Option<IpAddr>, u16), Box<dyn std::error::Error + Send + Sync>> {
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            read_exact_before(stream, &mut addr, deadline).await?;
            let mut port_buf = [0u8; 2];
            read_exact_before(stream, &mut port_buf, deadline).await?;
            let ip = IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            let port = u16::from_be_bytes(port_buf);
            Ok((String::new(), Some(ip), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact_before(stream, &mut len, deadline).await?;
            let dlen = len[0] as usize;
            let mut domain_buf = [0u8; 255];
            read_exact_before(stream, &mut domain_buf[..dlen], deadline).await?;
            let mut port_buf = [0u8; 2];
            read_exact_before(stream, &mut port_buf, deadline).await?;
            let host = std::str::from_utf8(&domain_buf[..dlen])
                .map_err(|_| "invalid domain name encoding")?
                .to_string();
            let port = u16::from_be_bytes(port_buf);
            Ok((host, None, port))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            read_exact_before(stream, &mut addr, deadline).await?;
            let mut port_buf = [0u8; 2];
            read_exact_before(stream, &mut port_buf, deadline).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(addr));
            let port = u16::from_be_bytes(port_buf);
            Ok((String::new(), Some(ip), port))
        }
        _ => Err(format!("unsupported address type: {atyp}").into()),
    }
}

async fn read_exact_before(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout_at(deadline, stream.read_exact(buf))
        .await
        .map_err(|_| "SOCKS5 handshake timed out")??;
    Ok(())
}
