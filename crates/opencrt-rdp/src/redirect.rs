//! Server Redirection ([MS-RDPBCGR] 2.2.13) and RDSTLS ([MS-RDPBCGR] 5.4.5.3).
//!
//! GNOME Remote Desktop in system mode ("remote login") authenticates the
//! user, then redirects the client to the GDM login screen, and after login to
//! the user's desktop: each time a Server Redirection PDU names a routing
//! token, a one-time user name and password, and the certificate the next
//! server will show. The client connects again (same host and port), puts the
//! routing token in its X.224 Connection Request, asks for RDSTLS, and sends
//! those credentials in an RDSTLS Authentication Request. Windows connection
//! brokers use the same PDU, mostly with a plain password and NLA.

use anyhow::{Context as _, anyhow, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The Share Control PDU type of a Server Redirection Packet.
const PDUTYPE_SERVER_REDIR_PKT: u16 = 0xA;
/// The flags of the redirection itself (`RDP_SERVER_REDIRECTION_PACKET`).
const SEC_REDIRECTION_PKT: u16 = 0x0400;

// The fields a redirection carries ([MS-RDPBCGR] 2.2.13.1).
const LB_TARGET_NET_ADDRESS: u32 = 0x0000_0001;
const LB_LOAD_BALANCE_INFO: u32 = 0x0000_0002;
const LB_USERNAME: u32 = 0x0000_0004;
const LB_DOMAIN: u32 = 0x0000_0008;
const LB_PASSWORD: u32 = 0x0000_0010;
const LB_NOREDIRECT: u32 = 0x0000_0080;
const LB_TARGET_FQDN: u32 = 0x0000_0100;
const LB_TARGET_NETBIOS_NAME: u32 = 0x0000_0200;
const LB_TARGET_NET_ADDRESSES: u32 = 0x0000_0800;
const LB_CLIENT_TSV_URL: u32 = 0x0000_1000;
const LB_PASSWORD_IS_PK_ENCRYPTED: u32 = 0x0000_4000;
const LB_REDIRECTION_GUID: u32 = 0x0000_8000;
const LB_TARGET_CERTIFICATE: u32 = 0x0001_0000;

/// The optional fields in the order they follow each other on the wire
/// (each a 32-bit length and that many bytes).
const FIELD_ORDER: [u32; 11] = [
    LB_TARGET_NET_ADDRESS,
    LB_LOAD_BALANCE_INFO,
    LB_USERNAME,
    LB_DOMAIN,
    LB_PASSWORD,
    LB_TARGET_FQDN,
    LB_TARGET_NETBIOS_NAME,
    LB_CLIENT_TSV_URL,
    LB_REDIRECTION_GUID,
    LB_TARGET_CERTIFICATE,
    LB_TARGET_NET_ADDRESSES,
];

/// Where and how to connect next.
#[derive(Clone, Default)]
pub struct Redirect {
    /// The routing token for the X.224 Connection Request (without
    /// "Cookie: msts=" and the line end), if the server gave one.
    pub routing_token: Option<String>,
    /// Another server to connect to; None keeps the current one.
    pub host: Option<String>,
    pub user: Option<String>,
    pub domain: Option<String>,
    /// The password as sent: UTF-16LE text, or an opaque token for RDSTLS.
    pub password: Option<Vec<u8>>,
    /// The password is a one-time token for RDSTLS, not for NLA.
    pub rdstls: bool,
    pub guid: Vec<u8>,
    /// The next server's certificate (DER), when the server named it.
    pub certificate: Option<Vec<u8>>,
}

impl std::fmt::Debug for Redirect {
    // For rdp.log: never the password, nor the user name (with RDSTLS a
    // one-time name generated with the password).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redirect")
            .field("routing_token", &self.routing_token)
            .field("host", &self.host)
            .field("user", &self.user.as_ref().map(|_| "(given)"))
            .field("domain", &self.domain)
            .field("password", &self.password.as_ref().map(|p| format!("{} bytes", p.len())))
            .field("rdstls", &self.rdstls)
            .field("guid", &format!("{} bytes", self.guid.len()))
            .field("certificate", &self.certificate.as_ref().map(|c| format!("{} bytes", c.len())))
            .finish()
    }
}

impl Redirect {
    /// The plain-text password of a (non-RDSTLS) redirection.
    pub fn password_text(&self) -> Option<String> {
        let bytes = self.password.as_ref()?;
        Some(utf16(bytes))
    }

    /// The server this redirection sends us to, when it is not `host`.
    /// OpenCRT does not follow those yet (a connection broker's redirection):
    /// the certificate would be checked against the saved one of `host`.
    pub fn other_host(&self, host: &str) -> Option<&str> {
        self.host.as_deref().filter(|named| !named.trim().eq_ignore_ascii_case(host.trim()))
    }
}

/// A Server Redirection in a slow-path PDU from the server (a whole TPKT
/// frame), or None for any other PDU.
pub fn find(frame: &[u8]) -> anyhow::Result<Option<Redirect>> {
    let Ok(data) = ironrdp::pdu::mcs::decode_send_data_indication(frame) else {
        return Ok(None);
    };
    let pdu = data.user_data;
    // Share Control Header: totalLength, pduType (type in the low 4 bits), pduSource.
    if pdu.len() < 6 || u16::from_le_bytes([pdu[2], pdu[3]]) & 0xF != PDUTYPE_SERVER_REDIR_PKT {
        return Ok(None);
    }
    // Then pad2Octets, then the redirection.
    let body = pdu.get(8..).ok_or_else(|| anyhow!("Server Redirection PDU too short"))?;
    parse(body).map(Some)
}

/// An `RDP_SERVER_REDIRECTION_PACKET`.
fn parse(body: &[u8]) -> anyhow::Result<Redirect> {
    let mut r = Reader(body);
    let flags = r.u16()?;
    ensure!(flags == SEC_REDIRECTION_PKT, "Server Redirection flags {flags:#06x}");
    let _length = r.u16()?;
    let _session_id = r.u32()?;
    let redir_flags = r.u32()?;
    let mut out = Redirect { rdstls: redir_flags & LB_PASSWORD_IS_PK_ENCRYPTED != 0, ..Redirect::default() };
    for field in FIELD_ORDER {
        if redir_flags & field == 0 {
            continue;
        }
        let len = r.u32()? as usize;
        let value = r.bytes(len).with_context(|| format!("Server Redirection field {field:#x}"))?;
        match field {
            LB_TARGET_NET_ADDRESS => out.host = Some(utf16(value)),
            LB_LOAD_BALANCE_INFO => out.routing_token = Some(routing_token(value)),
            LB_USERNAME => out.user = Some(utf16(value)),
            LB_DOMAIN => out.domain = Some(utf16(value)),
            LB_PASSWORD => out.password = Some(value.to_vec()),
            LB_TARGET_FQDN if out.host.is_none() => out.host = Some(utf16(value)),
            LB_REDIRECTION_GUID => out.guid = value.to_vec(),
            LB_TARGET_CERTIFICATE => out.certificate = target_certificate(value),
            _ => {}
        }
    }
    // A load-balancing token goes back to the same server, whatever else is named.
    if out.routing_token.is_some() || redir_flags & LB_NOREDIRECT != 0 {
        out.host = None;
    }
    Ok(out)
}

/// The routing token from a Load Balance Info: "Cookie: msts=<token>\r\n" as
/// FreeRDP-based servers send it, or the bare token.
fn routing_token(value: &[u8]) -> String {
    let text = String::from_utf8_lossy(value);
    let text = text.trim_end_matches(['\r', '\n', '\0']);
    text.strip_prefix("Cookie: msts=").unwrap_or(text).to_owned()
}

/// UTF-16LE text, up to its terminating NUL.
fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// The DER certificate in a Target Certificate field: UTF-16 base64 of a
/// container of elements (type, encoding, length, data), of which type 32 is
/// the certificate ([MS-RDPBCGR] 2.2.13.1.1). None when it cannot be read.
fn target_certificate(value: &[u8]) -> Option<Vec<u8>> {
    let container = base64(&utf16(value))?;
    let mut r = Reader(&container);
    while !r.0.is_empty() {
        let (kind, _encoding, len) = (r.u32().ok()?, r.u32().ok()?, r.u32().ok()? as usize);
        let data = r.bytes(len).ok()?;
        if kind == 32 {
            return Some(data.to_vec());
        }
    }
    None
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "Server Redirection PDU too short");
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into()?))
    }
    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into()?))
    }
}

// RDSTLS ([MS-RDPBCGR] 2.2.17), sent as is inside TLS.
const RDSTLS_VERSION_1: u16 = 1;
const RDSTLS_TYPE_CAPABILITIES: u16 = 1;
const RDSTLS_TYPE_AUTHREQ: u16 = 2;
const RDSTLS_TYPE_AUTHRSP: u16 = 4;
const RDSTLS_DATA_CAPABILITIES: u16 = 1;
const RDSTLS_DATA_PASSWORD_CREDS: u16 = 1;
const RDSTLS_DATA_RESULT_CODE: u16 = 1;

/// The RDSTLS exchange, right after the TLS handshake: the server's
/// capabilities, our credentials from the redirection, the server's verdict.
pub async fn rdstls(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), redirect: &Redirect, domain: &str) -> anyhow::Result<()> {
    let mut caps = [0u8; 8];
    stream.read_exact(&mut caps).await.context("RDSTLS capabilities")?;
    let word = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
    ensure!(
        word(&caps, 2) == RDSTLS_TYPE_CAPABILITIES && word(&caps, 4) == RDSTLS_DATA_CAPABILITIES,
        "RDSTLS: expected the server's capabilities"
    );
    ensure!(word(&caps, 6) & (1 << (RDSTLS_VERSION_1 - 1)) != 0, "RDSTLS: the server does not support version 1");

    let mut request = Vec::new();
    for v in [RDSTLS_VERSION_1, RDSTLS_TYPE_AUTHREQ, RDSTLS_DATA_PASSWORD_CREDS] {
        request.extend_from_slice(&v.to_le_bytes());
    }
    let mut data = |bytes: &[u8]| -> anyhow::Result<()> {
        request.extend_from_slice(&u16::try_from(bytes.len()).context("RDSTLS field too long")?.to_le_bytes());
        request.extend_from_slice(bytes);
        Ok(())
    };
    let text = |s: &str| s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
    data(&redirect.guid)?;
    data(&text(redirect.user.as_deref().unwrap_or_default()))?;
    data(&text(redirect.domain.as_deref().unwrap_or(domain)))?;
    data(redirect.password.as_deref().unwrap_or_default())?;
    stream.write_all(&request).await.context("RDSTLS authentication request")?;
    stream.flush().await?;

    let mut response = [0u8; 10];
    stream.read_exact(&mut response).await.context("RDSTLS authentication response")?;
    ensure!(
        word(&response, 2) == RDSTLS_TYPE_AUTHRSP && word(&response, 4) == RDSTLS_DATA_RESULT_CODE,
        "RDSTLS: expected the authentication response"
    );
    match u32::from_le_bytes(response[6..10].try_into()?) {
        0 => Ok(()),
        5 => bail!("RDSTLS: access denied by the redirected server"),
        0x52e => bail!("RDSTLS: the redirected server refused the one-time login"),
        code => bail!("RDSTLS: the redirected server refused the login (code {code:#x})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn wide(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn reads_a_gnome_redirection() {
        // A certificate container: element type 32, DER encoding 1, 3 bytes.
        let mut container = Vec::new();
        for v in [32u32, 1, 3] {
            container.extend_from_slice(&v.to_le_bytes());
        }
        container.extend_from_slice(&[0x30, 0x01, 0x00]);
        let b64 = "IAAAAAEAAAADAAAAMAEA"; // base64 of the container above
        assert_eq!(base64(b64).unwrap(), container);

        let flags = LB_LOAD_BALANCE_INFO
            | LB_USERNAME
            | LB_PASSWORD
            | LB_PASSWORD_IS_PK_ENCRYPTED
            | LB_REDIRECTION_GUID
            | LB_TARGET_CERTIFICATE;
        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&flags.to_le_bytes());
        field(&mut body, b"Cookie: msts=12345\r\n");
        field(&mut body, &wide("gdm-user"));
        field(&mut body, &wide("secret"));
        field(&mut body, &wide("R1VJRA=="));
        field(&mut body, &wide(b64));
        body.extend_from_slice(&[0; 8]);

        let r = parse(&body).unwrap();
        assert_eq!(r.routing_token.as_deref(), Some("12345"));
        assert_eq!(r.user.as_deref(), Some("gdm-user"));
        assert_eq!(r.password.as_deref(), Some(&wide("secret")[..]));
        assert!(r.rdstls);
        assert_eq!(r.guid, wide("R1VJRA=="));
        assert_eq!(r.certificate.as_deref(), Some(&[0x30, 0x01, 0x00][..]));
        assert_eq!(r.host, None);
        assert_eq!(r.other_host("gnome.example"), None);
        assert!(!format!("{r:?}").contains("secret"));
    }

    #[test]
    fn names_another_host() {
        // A connection broker's redirection: another server, plain password.
        let flags = LB_TARGET_NET_ADDRESS | LB_USERNAME | LB_PASSWORD;
        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&flags.to_le_bytes());
        field(&mut body, &wide("192.0.2.7"));
        field(&mut body, &wide("user"));
        field(&mut body, &wide("pass"));

        let r = parse(&body).unwrap();
        assert!(!r.rdstls);
        assert_eq!(r.other_host("broker.example"), Some("192.0.2.7"));
        assert_eq!(r.other_host("192.0.2.7"), None);
    }

    #[test]
    fn rdstls_exchange() {
        let redirect = Redirect {
            user: Some("u".into()),
            password: Some(vec![1, 2, 3, 4]),
            guid: vec![9, 9],
            rdstls: true,
            ..Redirect::default()
        };
        let server = async {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let task = async move {
                server.write_all(&[1, 0, 1, 0, 1, 0, 3, 0]).await.unwrap();
                let mut req = [0u8; 6 + 4 + 6 + 4 + 6];
                server.read_exact(&mut req).await.unwrap();
                server.write_all(&[1, 0, 4, 0, 1, 0, 0, 0, 0, 0]).await.unwrap();
                req
            };
            let (result, req) = tokio::join!(rdstls(&mut client, &redirect, ""), task);
            result.unwrap();
            req
        };
        let req = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(server);
        assert_eq!(
            req.to_vec(),
            [
                &[1u8, 0, 2, 0, 1, 0][..],
                &[2, 0, 9, 9],
                &[4, 0, b'u', 0, 0, 0],
                &[2, 0, 0, 0],
                &[4, 0, 1, 2, 3, 4],
            ]
            .concat()
        );
    }
}
