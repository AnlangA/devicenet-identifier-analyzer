use devicenet_identifier_analyzer::{MAX_STANDARD_IDENTIFIER, TraceMessage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameOrigin {
    File,
    Manual,
    Ai,
}

impl FrameOrigin {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::File => "File",
            Self::Manual => "Manual",
            Self::Ai => "AI",
        }
    }

    pub(crate) fn is_user_created(self) -> bool {
        matches!(self, Self::Manual | Self::Ai)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NewCanFrame {
    #[serde(default)]
    pub(crate) time_ms: Option<f64>,
    pub(crate) can_id: u32,
    pub(crate) can_data: Vec<u8>,
    pub(crate) can_dlc: usize,
}

impl NewCanFrame {
    pub(crate) fn from_manual(time: &str, can_id: &str, data: &str) -> Result<Self, String> {
        let time_ms = parse_optional_time(time)?;
        let can_id = parse_can_id(can_id)?;
        let can_data = parse_can_data(data)?;
        let frame = Self {
            time_ms,
            can_id,
            can_dlc: can_data.len(),
            can_data,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.can_id > MAX_STANDARD_IDENTIFIER as u32 {
            return Err(format!(
                "CAN ID 0x{:X} is outside the standard 11-bit range",
                self.can_id
            ));
        }
        if self.can_data.len() > 8 {
            return Err("Classic CAN data may contain at most 8 bytes".into());
        }
        if self.can_dlc != self.can_data.len() {
            return Err(format!(
                "DLC {} does not match {} data bytes",
                self.can_dlc,
                self.can_data.len()
            ));
        }
        if let Some(time) = self.time_ms
            && (!time.is_finite() || time < 0.0)
        {
            return Err("Time must be a finite, non-negative millisecond value".into());
        }
        Ok(())
    }

    pub(crate) fn into_trace_message(self, number: u64) -> TraceMessage {
        TraceMessage {
            number,
            time_offset_ms: self.time_ms,
            bus: 1,
            direction: "Tx".into(),
            identifier: self.can_id,
            dlc: self.can_dlc,
            data: self.can_data,
        }
    }
}

pub(crate) fn format_saved_frame(message: &TraceMessage, origin: FrameOrigin) -> String {
    let time = message
        .time_offset_ms
        .map(|time| format!("{time:.6}"))
        .unwrap_or_default();
    format!(
        "No={},Time={},Bus={},Dir={},ID=0x{:03X},Type=D,DLC={},Data={} ,Source={}",
        message.number,
        time,
        message.bus,
        message.direction,
        message.identifier,
        message.dlc,
        message.data_hex(),
        origin.label()
    )
}

fn parse_optional_time(value: &str) -> Result<Option<f64>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let time = value
        .parse::<f64>()
        .map_err(|_| "Time must be a millisecond number or left empty".to_owned())?;
    if !time.is_finite() || time < 0.0 {
        return Err("Time must be a finite, non-negative millisecond value".into());
    }
    Ok(Some(time))
}

fn parse_can_id(value: &str) -> Result<u32, String> {
    let value = value.trim().replace('_', "");
    if value.is_empty() {
        return Err("CAN ID is required".into());
    }
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else if value
        .chars()
        .any(|character| character.is_ascii_alphabetic())
    {
        u32::from_str_radix(&value, 16)
    } else {
        value.parse::<u32>()
    }
    .map_err(|_| "CAN ID must be decimal or 0x-prefixed hexadecimal".to_owned())?;

    if parsed > MAX_STANDARD_IDENTIFIER as u32 {
        return Err(format!("CAN ID 0x{parsed:X} exceeds 0x7FF"));
    }
    Ok(parsed)
}

fn parse_can_data(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = value
        .split(|character: char| character.is_whitespace() || matches!(character, ',' | ';'))
        .filter(|token| !token.is_empty())
        .map(|token| {
            let token = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .unwrap_or(token);
            u8::from_str_radix(token, 16)
                .map_err(|_| format!("Invalid hexadecimal data byte: {token}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if bytes.len() > 8 {
        return Err("Classic CAN data may contain at most 8 bytes".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_input_supports_empty_time_and_hex_data() {
        let frame = NewCanFrame::from_manual("", "0x40E", "00 4b 03 01").unwrap();
        assert_eq!(frame.time_ms, None);
        assert_eq!(frame.can_id, 0x40e);
        assert_eq!(frame.can_dlc, 4);
        assert_eq!(frame.can_data, vec![0, 0x4b, 3, 1]);
    }

    #[test]
    fn rejects_dlc_mismatch_and_invalid_ranges() {
        let frame = NewCanFrame {
            time_ms: Some(1.0),
            can_id: 0x800,
            can_data: vec![1],
            can_dlc: 2,
        };
        assert!(frame.validate().is_err());
    }
}
