//! DNS field values with explicit variants for recognized and unknown wire codes.
//!
//! Representing a code does not imply support for the operation it requests.
//! Query policy decides support; unknown record types/classes remain forwardable.

/// Identifies one exchange; client and upstream IDs have separate lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransactionId(pub(crate) u16);

/// The header QR bit, checked before replying to unsolicited traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageType {
    Query,
    Response,
}

/// Header operation code; this service forwards only standard queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Opcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Unknown(u8),
}
impl Opcode {
    pub(super) fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            n => Self::Unknown(n),
        }
    }
}

/// Combined header and EDNS response code, including extended values such as BADVERS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    BadVersion,
    Unknown(u16),
}
impl ResponseCode {
    pub(super) fn from_wire(value: u16) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            16 => Self::BadVersion,
            n => Self::Unknown(n),
        }
    }
    pub(super) fn wire(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::BadVersion => 16,
            Self::Unknown(n) => n,
        }
    }
}

/// Question/record type; unknown values keep their numeric code for transparent relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordType {
    A,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Opt,
    Sig,
    Tkey,
    Tsig,
    Ixfr,
    Axfr,
    Unknown(u16),
}
impl RecordType {
    pub(super) fn from_wire(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            24 => Self::Sig,
            28 => Self::Aaaa,
            33 => Self::Srv,
            41 => Self::Opt,
            249 => Self::Tkey,
            250 => Self::Tsig,
            251 => Self::Ixfr,
            252 => Self::Axfr,
            n => Self::Unknown(n),
        }
    }
    pub(super) fn wire(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Sig => 24,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Opt => 41,
            Self::Tkey => 249,
            Self::Tsig => 250,
            Self::Ixfr => 251,
            Self::Axfr => 252,
            Self::Unknown(n) => n,
        }
    }
}

/// Question/record class; OPT's CLASS field is instead interpreted as UDP capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordClass {
    In,
    Ch,
    Hs,
    Unknown(u16),
}
impl RecordClass {
    pub(super) fn from_wire(value: u16) -> Self {
        match value {
            1 => Self::In,
            3 => Self::Ch,
            4 => Self::Hs,
            n => Self::Unknown(n),
        }
    }
    pub(super) fn wire(self) -> u16 {
        match self {
            Self::In => 1,
            Self::Ch => 3,
            Self::Hs => 4,
            Self::Unknown(n) => n,
        }
    }
}
