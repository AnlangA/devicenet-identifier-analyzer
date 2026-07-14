//! DeviceNet trace, 11-bit CAN Identifier, and Message Group data parser.

use std::cmp::Ordering;
use std::fmt;

mod analysis;
mod assembly;
mod explicit;
mod group2;
mod mfc_explicit;
mod path;
mod protocol;
mod services;
mod status;

pub use analysis::DecodedField;
pub use assembly::{
    INPUT_ASSEMBLIES, IoAssemblyDirection, IoAssemblyInstance, IoAssemblyNumericFormat,
    OUTPUT_ASSEMBLIES,
};
pub use explicit::MessageBodyFormat;
#[allow(deprecated)]
pub use group2::{
    Group2Analysis, Group2Function, decode_group2_trace, decode_group2_trace_ordered,
};
#[allow(deprecated)]
pub use protocol::{
    DEFAULT_HOST_MAC_ID, FrameAnalysis, FrameFunction, IoAssemblySelection, decode_trace,
    decode_trace_ordered, decode_trace_ordered_with_io,
};
pub use services::{service_description, service_name};

pub const MAX_STANDARD_IDENTIFIER: u16 = 0x7ff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceMessageError {
    IdentifierOutOfRange(u32),
    DlcOutOfRange(usize),
    DlcMismatch { dlc: usize, data_len: usize },
    InvalidTime,
}

impl fmt::Display for TraceMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentifierOutOfRange(identifier) => write!(
                f,
                "CAN Identifier 0x{identifier:X} exceeds the 11-bit range 0x000-0x7FF"
            ),
            Self::DlcOutOfRange(dlc) => {
                write!(f, "Classic CAN DLC {dlc} exceeds the maximum of 8")
            }
            Self::DlcMismatch { dlc, data_len } => write!(
                f,
                "declared DLC {dlc} does not match the {data_len} supplied data bytes"
            ),
            Self::InvalidTime => {
                write!(f, "time offset must be a finite, non-negative value")
            }
        }
    }
}

impl std::error::Error for TraceMessageError {}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceMessage {
    pub number: u64,
    /// Milliseconds from the trace start. Manually entered frames may omit it.
    pub time_offset_ms: Option<f64>,
    pub bus: u32,
    pub direction: String,
    pub identifier: u32,
    pub dlc: usize,
    pub data: Vec<u8>,
}

impl TraceMessage {
    pub fn try_new(
        number: u64,
        time_offset_ms: Option<f64>,
        bus: u32,
        direction: impl Into<String>,
        identifier: u32,
        dlc: usize,
        data: Vec<u8>,
    ) -> Result<Self, TraceMessageError> {
        let message = Self {
            number,
            time_offset_ms,
            bus,
            direction: direction.into(),
            identifier,
            dlc,
            data,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<(), TraceMessageError> {
        if self.identifier > MAX_STANDARD_IDENTIFIER as u32 {
            return Err(TraceMessageError::IdentifierOutOfRange(self.identifier));
        }
        if self.dlc > 8 {
            return Err(TraceMessageError::DlcOutOfRange(self.dlc));
        }
        if self.dlc != self.data.len() {
            return Err(TraceMessageError::DlcMismatch {
                dlc: self.dlc,
                data_len: self.data.len(),
            });
        }
        if self
            .time_offset_ms
            .is_some_and(|time| !time.is_finite() || time < 0.0)
        {
            return Err(TraceMessageError::InvalidTime);
        }
        Ok(())
    }

    pub fn decoded_identifier(&self) -> Result<DecodedIdentifier, ParseError> {
        if self.identifier > MAX_STANDARD_IDENTIFIER as u32 {
            return Err(ParseError::OutOfRange(self.identifier));
        }
        DecodedIdentifier::decode(self.identifier as u16)
    }

    pub fn data_hex(&self) -> String {
        self.data
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceLog {
    pub start_time: Option<String>,
    pub messages: Vec<TraceMessage>,
    pub skipped_message_lines: usize,
}

/// Parse a PCAN-Explorer text trace and return all recognizable message rows.
/// Header/comment lines are ignored. Messages are ordered by time offset and
/// then by their original message number.
pub fn parse_trace_log(contents: &str) -> TraceLog {
    let start_time = contents.lines().find_map(|line| {
        line.trim()
            .strip_prefix(';')
            .map(str::trim)
            .and_then(|line| line.strip_prefix("Start time:"))
            .map(str::trim)
            .map(str::to_owned)
    });

    let mut messages = Vec::new();
    let mut skipped_message_lines = 0;
    let mut next_auto_number = 1_u64;

    for line in contents.lines() {
        if line.split(',').any(|field| {
            field
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("ID"))
        }) {
            match parse_key_value_trace_message(line, next_auto_number) {
                Some(message) => {
                    next_auto_number = next_auto_number.max(message.number.saturating_add(1));
                    messages.push(message);
                }
                None => skipped_message_lines += 1,
            }
            continue;
        }

        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(number_text) = fields.first() else {
            continue;
        };
        if !number_text
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            continue;
        }
        if fields.len() < 6 {
            skipped_message_lines += 1;
            continue;
        }

        let parsed = (|| {
            let number = fields[0].parse::<u64>().ok()?;
            let time_offset_ms = fields[1].parse::<f64>().ok()?;
            if !time_offset_ms.is_finite() {
                return None;
            }
            let bus = fields[2].parse::<u32>().ok()?;
            let identifier = u32::from_str_radix(fields[4], 16).ok()?;
            let dlc = fields[5].parse::<usize>().ok()?;
            if fields.len() != 6 + dlc {
                return None;
            }
            let data = fields
                .iter()
                .skip(6)
                .take(dlc)
                .map(|value| u8::from_str_radix(value, 16))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;

            TraceMessage::try_new(
                number,
                Some(time_offset_ms),
                bus,
                fields[3],
                identifier,
                dlc,
                data,
            )
            .ok()
        })();

        match parsed {
            Some(message) => {
                next_auto_number = next_auto_number.max(message.number.saturating_add(1));
                messages.push(message);
            }
            None => skipped_message_lines += 1,
        }
    }

    messages.sort_by(|left, right| {
        compare_optional_time(left.time_offset_ms, right.time_offset_ms)
            .then_with(|| left.number.cmp(&right.number))
    });

    TraceLog {
        start_time,
        messages,
        skipped_message_lines,
    }
}

/// Compare optional timestamps chronologically while always placing missing
/// timestamps after known timestamps.
pub fn compare_optional_time(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.total_cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn parse_key_value_trace_message(line: &str, fallback_number: u64) -> Option<TraceMessage> {
    let mut number = None;
    let mut time_offset_ms = None;
    let mut bus = 1_u32;
    let mut direction = "Tx".to_owned();
    let mut identifier = None;
    let mut declared_dlc = None;
    let mut data = Vec::new();

    for field in line.split(',') {
        let Some((key, value)) = field.trim().split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("No") || key.eq_ignore_ascii_case("Number") {
            number = value.parse::<u64>().ok();
        } else if key.eq_ignore_ascii_case("Time") || key.eq_ignore_ascii_case("TimeMs") {
            if !value.is_empty() {
                let parsed = value.parse::<f64>().ok()?;
                if !parsed.is_finite() {
                    return None;
                }
                time_offset_ms = Some(parsed);
            }
        } else if key.eq_ignore_ascii_case("Bus") {
            bus = value.parse::<u32>().ok()?;
        } else if key.eq_ignore_ascii_case("Dir") || key.eq_ignore_ascii_case("Direction") {
            direction = value.to_owned();
        } else if key.eq_ignore_ascii_case("ID") {
            identifier = Some(parse_can_identifier(value)?);
        } else if key.eq_ignore_ascii_case("DLC") {
            declared_dlc = Some(value.parse::<usize>().ok()?);
        } else if key.eq_ignore_ascii_case("Data") {
            data = value
                .split_whitespace()
                .map(|byte| u8::from_str_radix(byte, 16))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
        }
    }

    let identifier = identifier?;
    let dlc = declared_dlc.unwrap_or(data.len());
    TraceMessage::try_new(
        number.unwrap_or(fallback_number),
        time_offset_ms,
        bus,
        direction,
        identifier,
        dlc,
        data,
    )
    .ok()
}

fn parse_can_identifier(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else if value
        .chars()
        .any(|character| character.is_ascii_alphabetic())
    {
        u32::from_str_radix(value, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageGroup {
    Group1,
    Group2,
    Group3,
    Group4,
    Invalid,
}

impl MessageGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Group1 => "Group 1",
            Self::Group2 => "Group 2",
            Self::Group3 => "Group 3",
            Self::Group4 => "Group 4",
            Self::Invalid => "Invalid identifier",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierFields {
    Group1 { message_id: u8, source_mac_id: u8 },
    Group2 { mac_id: u8, message_id: u8 },
    Group3 { message_id: u8, source_mac_id: u8 },
    Group4 { message_id: u8 },
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedIdentifier {
    pub raw: u16,
    pub group: MessageGroup,
    pub fields: IdentifierFields,
}

impl DecodedIdentifier {
    pub fn decode(raw: u16) -> Result<Self, ParseError> {
        if raw > MAX_STANDARD_IDENTIFIER {
            return Err(ParseError::OutOfRange(raw as u32));
        }

        let (group, fields) = match raw {
            0x000..=0x3ff => (
                MessageGroup::Group1,
                IdentifierFields::Group1 {
                    message_id: ((raw >> 6) & 0x0f) as u8,
                    source_mac_id: (raw & 0x3f) as u8,
                },
            ),
            0x400..=0x5ff => (
                MessageGroup::Group2,
                IdentifierFields::Group2 {
                    mac_id: ((raw >> 3) & 0x3f) as u8,
                    message_id: (raw & 0x07) as u8,
                },
            ),
            0x600..=0x7bf => (
                MessageGroup::Group3,
                IdentifierFields::Group3 {
                    message_id: ((raw >> 6) & 0x07) as u8,
                    source_mac_id: (raw & 0x3f) as u8,
                },
            ),
            0x7c0..=0x7ef => (
                MessageGroup::Group4,
                IdentifierFields::Group4 {
                    message_id: (raw & 0x3f) as u8,
                },
            ),
            0x7f0..=0x7ff => (MessageGroup::Invalid, IdentifierFields::Invalid),
            _ => unreachable!("all 11-bit values are covered"),
        };

        Ok(Self { raw, group, fields })
    }

    pub fn binary(self) -> String {
        format!("{:011b}", self.raw)
    }

    pub fn field_summary(self) -> String {
        match self.fields {
            IdentifierFields::Group1 {
                message_id,
                source_mac_id,
            } => format!(
                "Message ID: 0x{message_id:X} ({message_id})  |  Source MAC ID: {source_mac_id}"
            ),
            IdentifierFields::Group2 { mac_id, message_id } => {
                format!("MAC ID: {mac_id}  |  Message ID: 0x{message_id:X} ({message_id})")
            }
            IdentifierFields::Group3 {
                message_id,
                source_mac_id,
            } => format!(
                "Message ID: 0x{message_id:X} ({message_id})  |  Source MAC ID: {source_mac_id}"
            ),
            IdentifierFields::Group4 { message_id } => {
                format!("Message ID: 0x{message_id:02X} ({message_id})")
            }
            IdentifierFields::Invalid => {
                "0x7F0-0x7FF is the invalid CAN Identifier range reserved by DeviceNet".into()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    InvalidFormat(String),
    OutOfRange(u32),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "No CAN Identifier found"),
            Self::InvalidFormat(value) => write!(f, "Unrecognized Identifier: {value}"),
            Self::OutOfRange(value) => write!(
                f,
                "0x{value:X} is outside the 11-bit standard CAN Identifier range (0x000-0x7FF)"
            ),
        }
    }
}

/// Parse one input line. Supported examples:
/// `123`, `0x123`, `0b00100100011`, `d:291`, `123#AABB`, `can0 123#AABB`,
/// and `Bus=1,ID=1038,Type=D,DLC=6,Data=0 75 3 1 1 0 ,`.
pub fn parse_line(line: &str) -> Result<DecodedIdentifier, ParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    // Key/value exports use a decimal ID field. Other fields, including Data,
    // are intentionally ignored.
    if let Some(id) = trimmed.split(',').find_map(|field| {
        let (key, value) = field.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("ID")
            .then_some(value.trim())
    }) {
        return parse_identifier_token(id, 10);
    }

    let token = if let Some(hash_index) = trimmed.find('#') {
        trimmed[..hash_index]
            .split_whitespace()
            .last()
            .unwrap_or_default()
    } else {
        trimmed.split_whitespace().next().unwrap_or_default()
    };

    let token = token.trim_matches(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',' | ';'));
    if token.is_empty() {
        return Err(ParseError::Empty);
    }

    parse_identifier_token(token, 16)
}

fn parse_identifier_token(
    token: &str,
    unprefixed_radix: u32,
) -> Result<DecodedIdentifier, ParseError> {
    let normalized = token.replace('_', "");
    let (digits, radix) = if let Some(value) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        (value, 16)
    } else if let Some(value) = normalized
        .strip_prefix("0b")
        .or_else(|| normalized.strip_prefix("0B"))
    {
        (value, 2)
    } else if let Some(value) = normalized
        .strip_prefix("d:")
        .or_else(|| normalized.strip_prefix("D:"))
    {
        (value, 10)
    } else {
        (normalized.as_str(), unprefixed_radix)
    };

    let raw = u32::from_str_radix(digits, radix)
        .map_err(|_| ParseError::InvalidFormat(token.to_owned()))?;
    if raw > MAX_STANDARD_IDENTIFIER as u32 {
        return Err(ParseError::OutOfRange(raw));
    }

    DecodedIdentifier::decode(raw as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_group_boundaries() {
        assert_eq!(
            DecodedIdentifier::decode(0x000).unwrap().group,
            MessageGroup::Group1
        );
        assert_eq!(
            DecodedIdentifier::decode(0x3ff).unwrap().group,
            MessageGroup::Group1
        );
        assert_eq!(
            DecodedIdentifier::decode(0x400).unwrap().group,
            MessageGroup::Group2
        );
        assert_eq!(
            DecodedIdentifier::decode(0x5ff).unwrap().group,
            MessageGroup::Group2
        );
        assert_eq!(
            DecodedIdentifier::decode(0x600).unwrap().group,
            MessageGroup::Group3
        );
        assert_eq!(
            DecodedIdentifier::decode(0x7bf).unwrap().group,
            MessageGroup::Group3
        );
        assert_eq!(
            DecodedIdentifier::decode(0x7c0).unwrap().group,
            MessageGroup::Group4
        );
        assert_eq!(
            DecodedIdentifier::decode(0x7ef).unwrap().group,
            MessageGroup::Group4
        );
        assert_eq!(
            DecodedIdentifier::decode(0x7f0).unwrap().group,
            MessageGroup::Invalid
        );
        assert_eq!(
            DecodedIdentifier::decode(0x7ff).unwrap().group,
            MessageGroup::Invalid
        );
    }

    #[test]
    fn extracts_each_groups_fields() {
        assert_eq!(
            DecodedIdentifier::decode(0x2aa).unwrap().fields,
            IdentifierFields::Group1 {
                message_id: 0x0a,
                source_mac_id: 0x2a,
            }
        );
        assert_eq!(
            DecodedIdentifier::decode(0x555).unwrap().fields,
            IdentifierFields::Group2 {
                mac_id: 0x2a,
                message_id: 0x05,
            }
        );
        assert_eq!(
            DecodedIdentifier::decode(0x6aa).unwrap().fields,
            IdentifierFields::Group3 {
                message_id: 0x02,
                source_mac_id: 0x2a,
            }
        );
        assert_eq!(
            DecodedIdentifier::decode(0x7ef).unwrap().fields,
            IdentifierFields::Group4 { message_id: 0x2f }
        );
    }

    #[test]
    fn accepts_common_capture_formats_and_ignores_data() {
        assert_eq!(parse_line("0x400").unwrap().raw, 0x400);
        assert_eq!(parse_line("0b10000000000").unwrap().raw, 0x400);
        assert_eq!(parse_line("d:1024").unwrap().raw, 0x400);
        assert_eq!(parse_line("123#DEADBEEF").unwrap().raw, 0x123);
        assert_eq!(parse_line("can0 7EF#01 02").unwrap().raw, 0x7ef);
        assert_eq!(
            parse_line("Bus=1,ID=1038,Type=D,DLC=6,Data=0 75 3 1 1 0 ,")
                .unwrap()
                .raw,
            0x40e
        );
        assert_eq!(
            parse_line("bus=1, id = 0x40E, type=D, data=ignored")
                .unwrap()
                .raw,
            0x40e
        );
    }

    #[test]
    fn rejects_extended_identifiers() {
        assert!(matches!(
            parse_line("800"),
            Err(ParseError::OutOfRange(0x800))
        ));
    }

    #[test]
    fn parses_and_time_sorts_pcan_explorer_trace_messages() {
        let trace = r#"
;  Start time: 2026/7/13 14:28:55.139.8
         2        39.7 1  Rx    40B      3    00 CB 00
         1        38.4 1  Tx    40E      6    00 4B 03 01 01 00
"#;

        let parsed = parse_trace_log(trace);
        assert_eq!(
            parsed.start_time.as_deref(),
            Some("2026/7/13 14:28:55.139.8")
        );
        assert_eq!(parsed.skipped_message_lines, 0);
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].number, 1);
        assert_eq!(parsed.messages[0].identifier, 0x40e);
        assert_eq!(parsed.messages[0].direction, "Tx");
        assert_eq!(
            parsed.messages[0].data,
            [0x00, 0x4b, 0x03, 0x01, 0x01, 0x00]
        );
        assert_eq!(
            parsed.messages[0].decoded_identifier().unwrap().group,
            MessageGroup::Group2
        );
        assert_eq!(parsed.messages[1].number, 2);
    }

    #[test]
    fn parses_saved_key_value_frames_and_keeps_missing_time_last() {
        let trace = r#"
No=3,Time=,Bus=1,Dir=Tx,ID=0x40E,Type=D,DLC=2,Data=00 75 ,Source=Manual
No=2,Time=8.5,Bus=1,Dir=Tx,ID=1035,Type=D,DLC=3,Data=00 CB 00 ,Source=AI
No=1,Time=2.0,Bus=1,Dir=Rx,ID=0x40B,Type=D,DLC=1,Data=AA ,Source=File
"#;

        let parsed = parse_trace_log(trace);
        assert_eq!(parsed.skipped_message_lines, 0);
        assert_eq!(parsed.messages.len(), 3);
        assert_eq!(parsed.messages[0].time_offset_ms, Some(2.0));
        assert_eq!(parsed.messages[1].time_offset_ms, Some(8.5));
        assert_eq!(parsed.messages[2].time_offset_ms, None);
        assert_eq!(parsed.messages[2].identifier, 0x40e);
        assert_eq!(parsed.messages[2].data, [0x00, 0x75]);
    }

    #[test]
    fn optional_time_comparison_always_places_missing_values_last() {
        assert_eq!(
            compare_optional_time(Some(1.0), None),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_optional_time(None, Some(1.0)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(compare_optional_time(None, None), std::cmp::Ordering::Equal);
    }

    #[test]
    fn rejects_invalid_whitespace_trace_rows_consistently() {
        let trace = r#"
1 -1.0 1 Tx 400 0
2  1.0 1 Tx 800 0
3  2.0 1 Tx 400 9 00 01 02 03 04 05 06 07 08
4  3.0 1 Tx 400 2 AA
5  4.0 1 Tx 400 1 BB CC
6  5.0 1 Tx 400 1 DD
"#;

        let parsed = parse_trace_log(trace);
        assert_eq!(parsed.skipped_message_lines, 5);
        assert_eq!(parsed.messages.len(), 1);
        assert_eq!(parsed.messages[0].number, 6);
        assert_eq!(parsed.messages[0].data, [0xdd]);
    }
}
