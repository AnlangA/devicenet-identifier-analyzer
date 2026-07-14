//! Shared decoding for logical segments in a Packed EPATH.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LogicalPath {
    pub(crate) class_id: Option<u32>,
    pub(crate) instance_id: Option<u32>,
    pub(crate) display: Option<String>,
}

pub(crate) fn decode_logical_path(path: &[u8]) -> LogicalPath {
    let mut decoded = LogicalPath::default();
    let mut offset = 0;
    let mut items = Vec::new();
    while offset < path.len() {
        let segment = path[offset];
        if segment & 0xe0 != 0x20 {
            break;
        }
        let logical_type = (segment >> 2) & 0x07;
        let format = segment & 0x03;
        let extended_type = (logical_type == 7)
            .then(|| path.get(offset + 1).copied())
            .flatten();
        let value_offset = offset + 1 + usize::from(extended_type.is_some());
        let (value, used) = match format {
            0 if value_offset < path.len() => {
                (u32::from(path[value_offset]), value_offset + 1 - offset)
            }
            1 if value_offset + 1 < path.len() => (
                u32::from(u16::from_le_bytes([
                    path[value_offset],
                    path[value_offset + 1],
                ])),
                value_offset + 2 - offset,
            ),
            2 if value_offset + 3 < path.len() => (
                u32::from_le_bytes([
                    path[value_offset],
                    path[value_offset + 1],
                    path[value_offset + 2],
                    path[value_offset + 3],
                ]),
                value_offset + 4 - offset,
            ),
            _ => break,
        };

        if extended_type.is_none() {
            match logical_type {
                0 => decoded.class_id = Some(value),
                1 => decoded.instance_id = Some(value),
                _ => {}
            }
        }
        items.push(format!(
            "{}=0x{value:X} ({value})",
            extended_type.map_or_else(
                || logical_segment_name(logical_type),
                extended_logical_segment_name
            )
        ));
        offset += used;
    }
    decoded.display = (!items.is_empty()).then(|| items.join(", "));
    decoded
}

fn logical_segment_name(value: u8) -> &'static str {
    match value {
        0 => "Class",
        1 => "Instance",
        2 => "Member",
        3 => "Connection Point",
        4 => "Attribute",
        5 => "Special",
        6 => "Service",
        7 => "Extended Logical",
        _ => unreachable!("a three-bit value is always covered"),
    }
}

fn extended_logical_segment_name(value: u8) -> &'static str {
    match value {
        0 => "Reserved Extended Logical",
        1 => "Array Index",
        2 => "Indirect Array Index",
        3 => "Bit Index",
        4 => "Indirect Bit Index",
        5 => "Structure Member Number",
        6 => "Structure Member Handle",
        _ => "Reserved Extended Logical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_packed_class_and_instance_without_padding() {
        let decoded = decode_logical_path(&[0x21, 0x34, 0x12, 0x25, 0x78, 0x56]);
        assert_eq!(decoded.class_id, Some(0x1234));
        assert_eq!(decoded.instance_id, Some(0x5678));
        assert_eq!(
            decoded.display.as_deref(),
            Some("Class=0x1234 (4660), Instance=0x5678 (22136)")
        );
    }
}
