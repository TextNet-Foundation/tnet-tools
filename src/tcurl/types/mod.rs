pub const MAX_RESPONSE_HEADER: usize = 64 * 1024;
pub const MAX_RESPONSE_BODY: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tmutp,
    Tbip,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tmutp => "tmutp",
            Self::Tbip => "tbip",
        }
    }

    pub fn version(self, v1: bool) -> &'static str {
        match (self, v1) {
            (Self::Tmutp, true) => "TMUTP/1.0",
            (Self::Tmutp, false) => "TMUTP/2.0",
            (Self::Tbip, true) => "TBIP/1.0",
            (Self::Tbip, false) => "TBIP/2.0",
        }
    }

    pub fn version_number(v1: bool) -> &'static str {
        if v1 { "1.0" } else { "2.0" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Head,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
    TlsThenTcp,
    SshThenTlsThenTcp,
    TcpOnly,
}

#[derive(Debug, Clone, Copy)]
pub enum TransportTarget {
    Utnp,
    Tmutp,
    Tbip,
}

#[derive(Debug, Clone, Copy)]
pub enum FrameKind {
    Protocol { head: bool },
    Utnp,
}

#[derive(Debug)]
pub struct Target {
    pub protocol: Protocol,
    pub host: String,
    pub path_query: String,
    pub direct_port: Option<u16>,
    pub utnp_port: Option<u16>,
}

#[derive(Debug)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug)]
pub enum AttemptError {
    Unavailable(String),
    Fatal(anyhow::Error),
}

#[derive(Debug)]
pub enum SshAttemptError {
    Unavailable(String),
    Untrusted(String),
    Failed(anyhow::Error),
}
