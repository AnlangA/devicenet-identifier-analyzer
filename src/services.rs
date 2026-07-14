//! CIP common service metadata and link-independent service-data decoding.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServiceDetails {
    pub fields: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

impl ServiceDetails {
    fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push((name.into(), value.into()));
    }

    fn warn(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

/// Name assigned by Volume 1 Appendix A, or the allocation range for codes
/// whose meaning depends on the target object/vendor.
pub fn service_name(code: u8) -> &'static str {
    match code {
        0x01 => "Get_Attributes_All",
        0x02 => "Set_Attributes_All",
        0x03 => "Get_Attribute_List",
        0x04 => "Set_Attribute_List",
        0x05 => "Reset",
        0x06 => "Start",
        0x07 => "Stop",
        0x08 => "Create",
        0x09 => "Delete",
        0x0a => "Multiple_Service_Packet",
        0x0d => "Apply_Attributes",
        0x0e => "Get_Attribute_Single",
        0x10 => "Set_Attribute_Single",
        0x11 => "Find_Next_Object_Instance",
        0x14 => "Error_Response",
        0x15 => "Restore",
        0x16 => "Save",
        0x17 => "No_Operation",
        0x18 => "Get_Member",
        0x19 => "Set_Member",
        0x1a => "Insert_Member",
        0x1b => "Remove_Member",
        0x1c => "GroupSync",
        0x1d => "Get_Connection_Point_Member_List",
        0x00 | 0x0b..=0x0c | 0x0f | 0x12..=0x13 | 0x1e..=0x31 => "Reserved_Common_Service",
        0x32..=0x4a => "Reserved_Service",
        0x4b..=0x63 => "Object_Class_Specific_Service",
        0x64..=0x7f => "Vendor_Specific_Service",
        0x80..=0xff => "Reply_Service_Code",
    }
}

/// Concise purpose/allocation description for a CIP or DeviceNet service code.
pub fn service_description(code: u8) -> &'static str {
    match code {
        0x01 => "Returns the class or instance attributes defined by the target object.",
        0x02 => "Modifies the class or instance attributes defined by the target object.",
        0x03 => "Returns the selected readable attributes listed in the request.",
        0x04 => "Writes the selected attributes listed in the request.",
        0x05 => "Resets the target class or object, typically to a default state or mode.",
        0x06 => "Starts the target class or object, typically entering a running state.",
        0x07 => "Stops the target class or object, typically entering an idle state.",
        0x08 => "Creates and initializes a new instance in the target object class.",
        0x09 => "Deletes the target object instance and releases its resources.",
        0x0a => "Executes several Message Router services synchronously as one sequence.",
        0x0d => "Validates pending attribute values and makes them actively used.",
        0x0e => "Reads one specified attribute or addressed logical element.",
        0x10 => "Validates and writes one specified attribute value.",
        0x11 => "Returns the next existing object instance IDs in ascending order.",
        0x14 => "Reports that a DeviceNet explicit request failed and carries status details.",
        0x15 => "Restores class or object attributes from previously saved storage.",
        0x16 => "Saves class or object attributes for a later Restore operation.",
        0x17 => "Checks that an object responds without changing its internal state.",
        0x18 => "Reads one or more members within an attribute.",
        0x19 => "Writes one or more members within an attribute.",
        0x1a => "Inserts one or more members into an attribute.",
        0x1b => "Removes one or more members from an attribute.",
        0x1c => "Verifies that every member of a group is synchronized to System Time.",
        0x1d => "Returns the EPATH and bit size of each member in a connection point.",
        0x00 | 0x0b..=0x0c | 0x0f | 0x12..=0x13 | 0x1e..=0x31 => {
            "Reserved within the CIP common-service range."
        }
        0x32..=0x4a => "Reserved service-code range.",
        0x4b..=0x63 => "Meaning is defined by the addressed object class.",
        0x64..=0x7f => "Vendor-specific service; consult the device definition.",
        0x80..=0xff => "Reply encoding: bit 7 is set on the request service code.",
    }
}

pub(crate) fn is_reserved_service(code: u8) -> bool {
    matches!(
        code,
        0x00 | 0x0b..=0x0c | 0x0f | 0x12..=0x13 | 0x1e..=0x4a
    )
}

/// Decode the parameters whose layout is fixed by Volume 1 Appendix A.
/// Object/class-specific tails are deliberately retained as raw bytes.
pub(crate) fn decode_common_service_data(
    code: u8,
    is_response: bool,
    data: &[u8],
    member_address_in_service_data: bool,
) -> ServiceDetails {
    let mut details = ServiceDetails::default();
    if is_reserved_service(code) {
        details.warn(format!("Service code 0x{code:02X} is reserved"));
    }

    match code {
        0x01 => raw_if_any(
            &mut details,
            if is_response {
                "Attribute values"
            } else {
                "Unexpected request data"
            },
            data,
        ),
        0x02 => raw_if_any(
            &mut details,
            if is_response {
                "Unexpected response data"
            } else {
                "Attribute values"
            },
            data,
        ),
        0x03 => decode_get_attribute_list(is_response, data, &mut details),
        0x04 => decode_set_attribute_list(is_response, data, &mut details),
        0x05..=0x07 | 0x09 | 0x0d | 0x15..=0x16 => {
            raw_if_any(&mut details, "Object-specific data", data)
        }
        0x08 if is_response => {
            if let Some(instance) = read_u16(data, 0) {
                details.push("Created Instance ID (default UINT)", format_u16(instance));
                raw_if_any(&mut details, "Object-specific data", &data[2..]);
            } else {
                details.warn("Create response is missing the 16-bit Instance ID");
                raw_if_any(&mut details, "Object-specific data", data);
            }
        }
        0x08 => raw_if_any(&mut details, "Object-specific data", data),
        0x0a => decode_multiple_service_packet(is_response, data, &mut details),
        0x0e => raw_if_any(
            &mut details,
            if is_response {
                "Attribute data"
            } else {
                "Unexpected request data"
            },
            data,
        ),
        0x10 => raw_if_any(
            &mut details,
            if is_response {
                "Object-specific response data"
            } else {
                "Attribute data"
            },
            data,
        ),
        0x11 => decode_find_next(is_response, data, &mut details),
        0x17 => {
            if !data.is_empty() {
                details.warn("No Operation has no service-data parameters");
                details.push("Unexpected data", hex_bytes(data));
            }
        }
        0x18..=0x1b if is_response || member_address_in_service_data => {
            decode_member_service(code, is_response, data, &mut details)
        }
        0x18..=0x1b => raw_if_any(&mut details, "Member data", data),
        0x1c if is_response => {
            if let Some(value) = data.first() {
                details.push(
                    "Is synchronized",
                    match value {
                        0 => "0 - No".into(),
                        1 => "1 - Yes".into(),
                        value => format!("{value} - Invalid BOOL value"),
                    },
                );
                raw_if_any(&mut details, "Object-specific data", &data[1..]);
            } else {
                details.warn("GroupSync response is missing IsSynchronized");
            }
        }
        0x1c => raw_if_any(&mut details, "Object-specific data", data),
        0x1d if is_response => decode_connection_point_members(data, &mut details),
        0x1d => {
            if !data.is_empty() {
                details.warn("Get_Connection_Point_Member_List request has no service data");
                details.push("Unexpected data", hex_bytes(data));
            }
        }
        _ => raw_if_any(&mut details, "Service data", data),
    }
    details
}

fn decode_get_attribute_list(is_response: bool, data: &[u8], details: &mut ServiceDetails) {
    let Some(count) = read_u16(data, 0) else {
        details.warn("Attribute list is missing the 16-bit attribute count");
        raw_if_any(details, "Service data", data);
        return;
    };
    details.push("Attribute count", count.to_string());
    if !is_response {
        let available = data.len().saturating_sub(2) / 2;
        let used = usize::from(count).min(available);
        let ids = (0..used)
            .filter_map(|index| read_u16(data, 2 + index * 2))
            .map(format_u16)
            .collect::<Vec<_>>();
        details.push("Attribute ID list", list_or_none(&ids));
        if available < usize::from(count) {
            details.warn(format!(
                "Attribute ID list is truncated: expected {count}, found {available}"
            ));
        }
        raw_if_any(details, "Trailing data", &data[2 + used * 2..]);
    } else {
        raw_if_any(details, "Attribute response structures", &data[2..]);
    }
}

fn decode_set_attribute_list(is_response: bool, data: &[u8], details: &mut ServiceDetails) {
    let Some(count) = read_u16(data, 0) else {
        details.warn("Attribute list is missing the 16-bit attribute count");
        raw_if_any(details, "Service data", data);
        return;
    };
    details.push("Attribute count", count.to_string());
    if !is_response {
        raw_if_any(details, "Attribute request structures", &data[2..]);
        return;
    }
    // Each response structure begins with ID/status/reserved but may contain a
    // class-specific, variable-length success payload. Without the addressed
    // object's schema, structure boundaries cannot be inferred safely.
    raw_if_any(details, "Attribute response structures", &data[2..]);
}

fn decode_multiple_service_packet(is_response: bool, data: &[u8], details: &mut ServiceDetails) {
    let Some(count) = read_u16(data, 0) else {
        details.warn("Multiple Service Packet is missing the 16-bit service count");
        raw_if_any(details, "Service data", data);
        return;
    };
    details.push(
        if is_response {
            "Response count"
        } else {
            "Service count"
        },
        count.to_string(),
    );
    let count = usize::from(count);
    let offset_bytes = count.saturating_mul(2);
    if data.len() < 2 + offset_bytes {
        details.warn("Multiple Service Packet offset table is truncated");
        raw_if_any(details, "Service data", &data[2..]);
        return;
    }
    let offsets = (0..count)
        .map(|index| read_u16(data, 2 + index * 2).unwrap())
        .collect::<Vec<_>>();
    let table_end = 2 + offset_bytes;
    if offsets
        .first()
        .is_some_and(|offset| usize::from(*offset) != table_end)
    {
        details.warn(format!("First embedded item offset must be {table_end}"));
    }
    if offsets.windows(2).any(|pair| pair[0] >= pair[1]) {
        details.warn("Embedded item offsets must be strictly increasing");
    }
    details.push(
        if is_response {
            "Response offsets"
        } else {
            "Service offsets"
        },
        offsets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    );
    for (index, offset) in offsets.iter().copied().enumerate() {
        let start = usize::from(offset);
        let end = offsets
            .get(index + 1)
            .map_or(data.len(), |next| usize::from(*next))
            .min(data.len());
        if start < 2 + offset_bytes || start >= end || start >= data.len() {
            details.warn(format!("Embedded item {} has an invalid offset", index + 1));
            continue;
        }
        let item = &data[start..end];
        if is_response {
            if item.len() >= 4 {
                let reply = item[0] & 0x7f;
                let status = item[2];
                let additional_words = item[3];
                if item[0] & 0x80 == 0 {
                    details.warn(format!(
                        "Embedded response {} does not set the Reply Service bit",
                        index + 1
                    ));
                }
                if item[1] != 0 {
                    details.warn(format!(
                        "Embedded response {} reserved byte must be zero",
                        index + 1
                    ));
                }
                let minimum = 4 + usize::from(additional_words) * 2;
                if item.len() < minimum {
                    details.warn(format!(
                        "Embedded response {} additional status is truncated",
                        index + 1
                    ));
                    continue;
                }
                details.push(
                    format!("Embedded response {}", index + 1),
                    format!(
                        "0x{reply:02X} - {}, general status 0x{status:02X}, additional status {additional_words} word(s)",
                        service_name(reply)
                    ),
                );
            } else {
                details.warn(format!("Embedded response {} is truncated", index + 1));
            }
        } else if item.len() >= 2 {
            let service = item[0] & 0x7f;
            if item[0] & 0x80 != 0 {
                details.warn(format!(
                    "Embedded request {} sets the Reply Service bit",
                    index + 1
                ));
            }
            let minimum = 2 + usize::from(item[1]) * 2;
            if item.len() < minimum {
                details.warn(format!("Embedded request {} path is truncated", index + 1));
                continue;
            }
            details.push(
                format!("Embedded request {}", index + 1),
                format!(
                    "0x{service:02X} - {}, path {} word(s), {}",
                    service_name(service),
                    item[1],
                    hex_bytes(item)
                ),
            );
        } else {
            details.warn(format!("Embedded request {} is truncated", index + 1));
        }
    }
}

fn decode_find_next(is_response: bool, data: &[u8], details: &mut ServiceDetails) {
    let Some(count) = data.first().copied() else {
        details.warn(if is_response {
            "Find_Next response is missing the list-member count"
        } else {
            "Find_Next request is missing Maximum Returned Values"
        });
        return;
    };
    details.push(
        if is_response {
            "Number of list members"
        } else {
            "Maximum returned values"
        },
        count.to_string(),
    );
    if is_response {
        let available = data.len().saturating_sub(1) / 2;
        let used = usize::from(count).min(available);
        let values = (0..used)
            .filter_map(|index| read_u16(data, 1 + index * 2))
            .map(format_u16)
            .collect::<Vec<_>>();
        details.push("Instance ID list", list_or_none(&values));
        if available < usize::from(count) {
            details.warn(format!(
                "Instance ID list is truncated: expected {count}, found {available}"
            ));
        }
        raw_if_any(details, "Trailing data", &data[1 + used * 2..]);
    } else {
        raw_if_any(details, "Unexpected request data", &data[1..]);
    }
}

fn decode_member_service(code: u8, is_response: bool, data: &[u8], details: &mut ServiceDetails) {
    if is_response {
        raw_if_any(details, "Member response data", data);
        return;
    }
    let Some(attribute) = data.first().copied() else {
        details.warn("Member request is missing the DeviceNet Attribute ID");
        return;
    };
    details.push("Attribute ID", format_u16(u16::from(attribute)));
    let Some(member) = read_u16(data, 1) else {
        details.warn("Member request is missing the 16-bit Member ID/EX field");
        raw_if_any(details, "Member data", &data[1..]);
        return;
    };
    details.push("Member ID", (member & 0x7fff).to_string());
    details.push(
        "Member protocol",
        if member & 0x8000 == 0 {
            "Basic"
        } else {
            "Extended"
        },
    );
    let mut offset = 3;
    if member & 0x8000 != 0 {
        if let Some(protocol) = data.get(offset).copied() {
            details.push(
                "Extended protocol",
                format!("0x{protocol:02X} - {}", extended_protocol_name(protocol)),
            );
            offset += 1;
            if protocol == 1 {
                if let Some(count) = read_u16(data, offset) {
                    details.push("Number of members", count.to_string());
                    offset += 2;
                } else {
                    details.warn("Multiple Sequential Members count is truncated");
                }
            }
        } else {
            details.warn("Extended member request is missing its protocol ID");
        }
    }
    let member_data = data.get(offset..).unwrap_or_default();
    match code {
        0x18 | 0x1b if !member_data.is_empty() => {
            details.warn(format!(
                "{} request must not contain Member Data",
                service_name(code)
            ));
        }
        0x19 if member_data.is_empty() => {
            details.warn(format!(
                "{} request requires Member Data",
                service_name(code)
            ));
        }
        _ => {}
    }
    raw_if_any(details, "Member data", member_data);
}

fn decode_connection_point_members(data: &[u8], details: &mut ServiceDetails) {
    let Some(count) = read_u16(data, 0) else {
        details.warn("Member list response is missing Item Count");
        raw_if_any(details, "Service data", data);
        return;
    };
    details.push("Item count", count.to_string());
    let mut offset = 2;
    for index in 0..usize::from(count) {
        let Some(size_bits) = read_u16(data, offset) else {
            details.warn(format!(
                "Connection-point member {} is truncated",
                index + 1
            ));
            break;
        };
        let Some(path_size) = read_u16(data, offset + 2) else {
            details.warn(format!(
                "Connection-point member {} path size is truncated",
                index + 1
            ));
            break;
        };
        offset += 4;
        let path_size = usize::from(path_size);
        let available = data.len().saturating_sub(offset);
        let used = path_size.min(available);
        details.push(
            format!("Member {}", index + 1),
            format!(
                "{size_bits} bits, path {} byte(s): {}",
                path_size,
                hex_bytes(&data[offset..offset + used])
            ),
        );
        offset += used;
        if used != path_size {
            details.warn(format!(
                "Connection-point member {} path is truncated",
                index + 1
            ));
            break;
        }
    }
    raw_if_any(
        details,
        "Trailing data",
        data.get(offset..).unwrap_or_default(),
    );
}

fn extended_protocol_name(value: u8) -> &'static str {
    match value {
        0x00 => "Reserved",
        0x01 => "Multiple Sequential Members",
        0x02 => "International String Selection",
        0x03..=0x63 | 0xc8..=0xff => "Reserved",
        0x64..=0xc7 => "Vendor-specific",
    }
}

fn raw_if_any(details: &mut ServiceDetails, name: &str, data: &[u8]) {
    if !data.is_empty() {
        details.push(name, hex_bytes(data));
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".into()
    } else {
        values.join(", ")
    }
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(none)".into();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn format_u16(value: u16) -> String {
    format!("0x{value:04X} ({value})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cover_all_defined_common_services_and_ranges() {
        for code in 0_u8..=0x7f {
            assert_ne!(service_name(code), "");
            assert_ne!(service_description(code), "");
        }
        assert_eq!(service_name(0x1d), "Get_Connection_Point_Member_List");
        assert_eq!(service_name(0x4b), "Object_Class_Specific_Service");
        assert_eq!(service_name(0x64), "Vendor_Specific_Service");
    }

    #[test]
    fn decodes_fixed_common_service_parameters() {
        let list = decode_common_service_data(0x03, false, &[2, 0, 1, 0, 9, 0], true);
        assert_eq!(list.fields[0].1, "2");
        assert!(list.fields[1].1.contains("0x0009"));

        let find = decode_common_service_data(0x11, true, &[2, 1, 0, 8, 0], false);
        assert_eq!(find.fields[1].1, "0x0001 (1), 0x0008 (8)");
    }

    #[test]
    fn validates_multiple_service_packet_and_member_boundaries() {
        // Volume 1, A-4.20: Insert_Member data is optional, while Set_Member
        // requires it. Get/Remove requests must not carry Member Data.
        let insert = decode_common_service_data(0x1a, false, &[1, 2, 0], true);
        assert!(insert.warnings.is_empty());
        let set = decode_common_service_data(0x19, false, &[1, 2, 0], true);
        assert!(
            set.warnings
                .iter()
                .any(|warning| warning.contains("requires Member Data"))
        );

        // One embedded request at offset 4 whose service byte incorrectly
        // carries the reply bit.
        let multiple = decode_common_service_data(0x0a, false, &[1, 0, 4, 0, 0x8e, 0], false);
        assert!(
            multiple
                .warnings
                .iter()
                .any(|warning| warning.contains("Reply Service bit"))
        );
    }
}
