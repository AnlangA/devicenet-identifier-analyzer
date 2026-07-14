//! Shared DeviceNet Explicit Messaging primitives.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageBodyFormat {
    DeviceNet8_8,
    DeviceNet8_16,
    DeviceNet16_16,
    DeviceNet16_8,
    CipPath,
    Reserved(u8),
}

impl MessageBodyFormat {
    pub(crate) fn from_value(value: u8) -> Self {
        match value {
            0 => Self::DeviceNet8_8,
            1 => Self::DeviceNet8_16,
            2 => Self::DeviceNet16_16,
            3 => Self::DeviceNet16_8,
            4 => Self::CipPath,
            value => Self::Reserved(value),
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::DeviceNet8_8 => "DeviceNet 8/8".into(),
            Self::DeviceNet8_16 => "DeviceNet 8/16".into(),
            Self::DeviceNet16_16 => "DeviceNet 16/16".into(),
            Self::DeviceNet16_8 => "DeviceNet 16/8".into(),
            Self::CipPath => "CIP Path".into(),
            Self::Reserved(value) => format!("Reserved ({value})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExplicitHeader {
    pub fragmented: bool,
    pub xid: u8,
    pub peer_mac: u8,
}

impl ExplicitHeader {
    pub(crate) fn decode(value: u8) -> Self {
        Self {
            fragmented: value & 0x80 != 0,
            xid: (value >> 6) & 0x01,
            peer_mac: value & 0x3f,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FragmentKind {
    First,
    Middle,
    Last,
    Acknowledge,
}

impl FragmentKind {
    pub(crate) fn decode(protocol: u8) -> (Self, u8) {
        let kind = match protocol >> 6 {
            0 => Self::First,
            1 => Self::Middle,
            2 => Self::Last,
            3 => Self::Acknowledge,
            _ => unreachable!("a two-bit value is always covered"),
        };
        (kind, protocol & 0x3f)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::First => "First",
            Self::Middle => "Middle",
            Self::Last => "Last",
            Self::Acknowledge => "Acknowledge",
        }
    }
}

pub(crate) fn fragment_ack_status(value: u8) -> String {
    match value {
        0 => "0x00 - Success".into(),
        1 => "0x01 - Too Much Data".into(),
        value => format!("0x{value:02X} - Reserved"),
    }
}
