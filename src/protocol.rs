//! Unified DeviceNet Message Group 1-4 decoder.

use crate::group2::{
    DecodedField, Group2Analysis, Group2Function, MessageBodyFormat, decode_group2_trace_ordered,
};
use crate::services::{
    ServiceDetails, decode_common_service_data, format_u16, hex_bytes, service_name,
};
use crate::{IdentifierFields, MessageGroup, TraceMessage, compare_optional_time};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFunction {
    Group1Connection,
    Group2(Group2Function),
    ConnectedExplicitRequest,
    ConnectedExplicitResponse,
    Group3Connection,
    Group3UnconnectedRequest,
    Group3UnconnectedResponse,
    Group3Invalid,
    Group4Reserved,
    Group4CommunicationFaultedResponse,
    Group4CommunicationFaultedRequest,
    Group4OfflineOwnershipResponse,
    Group4OfflineOwnershipRequest,
    InvalidIdentifier,
}

impl FrameFunction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Group1Connection => "Group 1 Connection Message",
            Self::Group2(function) => function.label(),
            Self::ConnectedExplicitRequest => "Connected Explicit Request",
            Self::ConnectedExplicitResponse => "Connected Explicit Response",
            Self::Group3Connection => "Group 3 Connection Message",
            Self::Group3UnconnectedRequest => "UCMM Unconnected Request",
            Self::Group3UnconnectedResponse => "UCMM Unconnected Response",
            Self::Group3Invalid => "Invalid Group 3 Message ID",
            Self::Group4Reserved => "Reserved Group 4 Message",
            Self::Group4CommunicationFaultedResponse => "Communication Faulted Response",
            Self::Group4CommunicationFaultedRequest => "Communication Faulted Request",
            Self::Group4OfflineOwnershipResponse => "Offline Ownership Response",
            Self::Group4OfflineOwnershipRequest => "Offline Ownership Request",
            Self::InvalidIdentifier => "Invalid DeviceNet Identifier",
        }
    }

    pub fn is_explicit(self) -> bool {
        matches!(
            self,
            Self::ConnectedExplicitRequest
                | Self::ConnectedExplicitResponse
                | Self::Group3UnconnectedRequest
                | Self::Group3UnconnectedResponse
                | Self::Group2(
                    Group2Function::ExplicitRequest
                        | Group2Function::ExplicitOrUnconnectedResponse
                        | Group2Function::UnconnectedExplicitRequest
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameAnalysis {
    pub group: MessageGroup,
    pub function: FrameFunction,
    pub title: String,
    pub fields: Vec<DecodedField>,
    pub warnings: Vec<String>,
}

impl FrameAnalysis {
    fn new(group: MessageGroup, function: FrameFunction, title: impl Into<String>) -> Self {
        Self {
            group,
            function,
            title: title.into(),
            fields: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push(DecodedField {
            name: name.into(),
            value: value.into(),
        });
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }

    fn append_service_details(&mut self, details: ServiceDetails) {
        for (name, value) in details.fields {
            self.push(name, value);
        }
        self.warnings.extend(details.warnings);
    }
}

impl From<Group2Analysis> for FrameAnalysis {
    fn from(analysis: Group2Analysis) -> Self {
        Self {
            group: MessageGroup::Group2,
            function: FrameFunction::Group2(analysis.function),
            title: analysis.title,
            fields: analysis.fields,
            warnings: analysis.warnings,
        }
    }
}

pub fn decode_trace(messages: &[TraceMessage]) -> HashMap<u64, FrameAnalysis> {
    messages
        .iter()
        .zip(decode_trace_ordered(messages))
        .filter_map(|(message, analysis)| analysis.map(|analysis| (message.number, analysis)))
        .collect()
}

/// Decode all DeviceNet groups while retaining one result slot per source frame.
pub fn decode_trace_ordered(messages: &[TraceMessage]) -> Vec<Option<FrameAnalysis>> {
    let group2 = decode_group2_trace_ordered(messages);
    let mut ordered = messages.iter().enumerate().collect::<Vec<_>>();
    ordered.sort_by(|(left_index, left), (right_index, right)| {
        compare_optional_time(left.time_offset_ms, right.time_offset_ms)
            .then_with(|| left.number.cmp(&right.number))
            .then_with(|| left_index.cmp(right_index))
    });

    let mut decoder = ProtocolDecoder::default();
    let mut results = vec![None; messages.len()];
    for (source_index, message) in ordered {
        results[source_index] = decoder.decode(message, group2[source_index].clone());
    }
    results
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    identifier: u32,
    peer_mac: u8,
}

#[derive(Debug, Clone)]
struct ConnectedContext {
    is_response: bool,
    format: MessageBodyFormat,
    client_mac: u8,
    server_mac: u8,
    connection_instance: u16,
    open_frame: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UcmmKey {
    client_mac: u8,
    server_mac: u8,
    xid: u8,
}

#[derive(Debug, Clone)]
struct PendingOpen {
    group_select: u8,
    source_message_id: u8,
    requested_format: MessageBodyFormat,
    request_frame: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExplicitRequestKey {
    client_mac: u8,
    server_mac: u8,
    connection_instance: u16,
    xid: u8,
}

#[derive(Debug, Clone)]
struct ExplicitRequestContext {
    frame: u64,
    service: u8,
    class_id: Option<u32>,
    instance_id: Option<u32>,
    attribute_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragmentKey {
    identifier: u32,
    peer_mac: u8,
    header: u8,
    direction: String,
}

#[derive(Debug, Clone)]
struct FragmentState {
    first_frame: u64,
    last_count: u8,
    fragments: usize,
    body: Vec<u8>,
}

#[derive(Default)]
struct ProtocolDecoder {
    connections: HashMap<ConnectionKey, ConnectedContext>,
    pending_opens: HashMap<UcmmKey, PendingOpen>,
    pending_closes: HashMap<UcmmKey, (u16, u64)>,
    requests: HashMap<ExplicitRequestKey, ExplicitRequestContext>,
    fragments: HashMap<FragmentKey, FragmentState>,
}

impl ProtocolDecoder {
    fn decode(
        &mut self,
        message: &TraceMessage,
        group2: Option<Group2Analysis>,
    ) -> Option<FrameAnalysis> {
        let decoded = message.decoded_identifier().ok()?;
        let header = message.data.first().copied();
        if let Some(header) = header {
            let key = ConnectionKey {
                identifier: message.identifier,
                peer_mac: header & 0x3f,
            };
            if let Some(context) = self.connections.get(&key).cloned() {
                return Some(self.decode_connected(message, decoded.group, context));
            }
        }

        match decoded.fields {
            IdentifierFields::Group1 {
                message_id,
                source_mac_id,
            } => Some(connection_specific(
                MessageGroup::Group1,
                FrameFunction::Group1Connection,
                message_id,
                source_mac_id,
                message,
            )),
            IdentifierFields::Group2 { .. } => group2.map(Into::into),
            IdentifierFields::Group3 {
                message_id,
                source_mac_id,
            } => match message_id {
                0..=4 => Some(connection_specific(
                    MessageGroup::Group3,
                    FrameFunction::Group3Connection,
                    message_id,
                    source_mac_id,
                    message,
                )),
                5 | 6 => Some(self.decode_ucmm(message, message_id, source_mac_id)),
                7 => {
                    let mut analysis = FrameAnalysis::new(
                        MessageGroup::Group3,
                        FrameFunction::Group3Invalid,
                        "Invalid Group 3 Message ID 7",
                    );
                    analysis.push("Message ID", "7");
                    analysis.push("Source MAC ID", source_mac_id.to_string());
                    analysis.push("Data", hex_bytes(&message.data));
                    analysis
                        .warnings
                        .push("Group 3 Message ID 7 is invalid and shall not be used".into());
                    Some(analysis)
                }
                _ => unreachable!(),
            },
            IdentifierFields::Group4 { message_id } => Some(decode_group4(message, message_id)),
            IdentifierFields::Invalid => {
                let mut analysis = FrameAnalysis::new(
                    MessageGroup::Invalid,
                    FrameFunction::InvalidIdentifier,
                    "Invalid DeviceNet CAN Identifier",
                );
                analysis.push("Identifier", format!("0x{:03X}", message.identifier));
                analysis.push("Data", hex_bytes(&message.data));
                analysis
                    .warnings
                    .push("0x7F0-0x7FF is the invalid Identifier range".into());
                Some(analysis)
            }
        }
    }

    fn decode_ucmm(
        &mut self,
        message: &TraceMessage,
        message_id: u8,
        source_mac: u8,
    ) -> FrameAnalysis {
        let is_response_port = message_id == 5;
        let function = if is_response_port {
            FrameFunction::Group3UnconnectedResponse
        } else {
            FrameFunction::Group3UnconnectedRequest
        };
        let mut analysis = FrameAnalysis::new(MessageGroup::Group3, function, function.label());
        analysis.push("Message ID", message_id.to_string());
        analysis.push("Source MAC ID", source_mac.to_string());
        let Some(header) = message.data.first().copied() else {
            analysis.warnings.push("Missing UCMM Message Header".into());
            return analysis;
        };
        analysis.push("Fragmented", yes_no(header & 0x80 != 0));
        analysis.push("XID", ((header >> 6) & 1).to_string());
        analysis.push("Destination MAC ID", (header & 0x3f).to_string());
        if header & 0x80 != 0 {
            analysis
                .warnings
                .push("UCMM Open/Close messages shall not be fragmented".into());
        }
        let Some(service_field) = message.data.get(1).copied() else {
            analysis.warnings.push("Missing UCMM Service Field".into());
            return analysis;
        };
        let service = service_field & 0x7f;
        let is_response = service_field & 0x80 != 0;
        let name = ucmm_service_name(service);
        analysis.title = format!(
            "{name} {}",
            if is_response { "Response" } else { "Request" }
        );
        analysis.push("Service", format!("0x{service:02X} - {name}"));
        analysis.push("R/R", if is_response { "Response" } else { "Request" });
        if is_response != is_response_port {
            analysis
                .warnings
                .push("R/R flag does not agree with the Group 3 UCMM Message ID".into());
        }

        let xid = (header >> 6) & 1;
        let peer = header & 0x3f;
        if !is_response_port {
            let key = UcmmKey {
                client_mac: source_mac,
                server_mac: peer,
                xid,
            };
            match service {
                0x4b => {
                    let Some(format_byte) = message.data.get(2).copied() else {
                        analysis
                            .warnings
                            .push("Open request is missing Message Body Format".into());
                        return analysis;
                    };
                    let format = MessageBodyFormat::from_value(format_byte & 0x0f);
                    analysis.push("Requested Message Body Format", format.label());
                    if format_byte & 0xf0 != 0 {
                        analysis
                            .warnings
                            .push("Open request reserved format bits are nonzero".into());
                    }
                    let Some(group_and_id) = message.data.get(3).copied() else {
                        analysis
                            .warnings
                            .push("Open request is missing Group Select/Source Message ID".into());
                        return analysis;
                    };
                    let group_select = group_and_id >> 4;
                    let source_message_id = group_and_id & 0x0f;
                    analysis.push("Group Select", group_select_name(group_select));
                    analysis.push("Source Message ID", source_message_id.to_string());
                    if !matches!(group_select, 0 | 1 | 3 | 0x0f) {
                        analysis.warnings.push("Reserved Group Select value".into());
                    }
                    self.pending_opens.insert(
                        key,
                        PendingOpen {
                            group_select,
                            source_message_id,
                            requested_format: format,
                            request_frame: message.number,
                        },
                    );
                    raw_tail(&mut analysis, "Trailing data", &message.data[4..]);
                }
                0x4c => {
                    if let Some(instance) = read_u16(&message.data, 2) {
                        analysis.push("Connection Instance ID", format_u16(instance));
                        self.pending_closes.insert(key, (instance, message.number));
                    } else {
                        analysis
                            .warnings
                            .push("Close request is missing Connection Instance ID".into());
                    }
                    raw_tail(
                        &mut analysis,
                        "Trailing data",
                        message.data.get(4..).unwrap_or_default(),
                    );
                }
                _ => analysis
                    .warnings
                    .push("Only Open (0x4B) and Close (0x4C) are valid UCMM requests".into()),
            }
        } else {
            let key = UcmmKey {
                client_mac: peer,
                server_mac: source_mac,
                xid,
            };
            match service {
                0x4b => self.decode_open_response(message, key, &mut analysis),
                0x4c => {
                    if let Some((instance, request_frame)) = self.pending_closes.remove(&key) {
                        analysis.push("Close request frame", format!("#{request_frame}"));
                        analysis.push("Connection Instance ID", format_u16(instance));
                        self.connections.retain(|_, context| {
                            context.connection_instance != instance
                                || context.client_mac != key.client_mac
                                || context.server_mac != key.server_mac
                        });
                    } else {
                        analysis
                            .warnings
                            .push("Matching Close request was not found in the trace".into());
                    }
                    raw_tail(
                        &mut analysis,
                        "Unexpected response data",
                        &message.data[2..],
                    );
                }
                0x14 => {
                    decode_devicenet_error(&message.data[1..], &mut analysis);
                    if let Some(open) = self.pending_opens.remove(&key) {
                        analysis.push(
                            "Failed Open request frame",
                            format!("#{}", open.request_frame),
                        );
                    }
                    if let Some((instance, frame)) = self.pending_closes.remove(&key) {
                        analysis.push("Failed Close request frame", format!("#{frame}"));
                        analysis.push("Connection Instance ID", format_u16(instance));
                    }
                }
                0x4d => decode_heartbeat(&message.data[1..], &mut analysis),
                0x4e => decode_shutdown(&message.data[1..], &mut analysis),
                _ => analysis.warnings.push(
                    "UCMM responses are limited to Open, Close, Error, Heartbeat, or Shutdown"
                        .into(),
                ),
            }
        }
        analysis
    }

    fn decode_open_response(
        &mut self,
        message: &TraceMessage,
        key: UcmmKey,
        analysis: &mut FrameAnalysis,
    ) {
        let Some(format_byte) = message.data.get(2).copied() else {
            analysis
                .warnings
                .push("Open response is missing Message Body Format".into());
            return;
        };
        let format = MessageBodyFormat::from_value(format_byte & 0x0f);
        analysis.push("Actual Message Body Format", format.label());
        if format_byte & 0xf0 != 0 {
            analysis
                .warnings
                .push("Open response reserved format bits are nonzero".into());
        }
        let Some(message_ids) = message.data.get(3).copied() else {
            analysis
                .warnings
                .push("Open response is missing allocated Message IDs".into());
            return;
        };
        let destination_message_id = message_ids >> 4;
        let source_message_id = message_ids & 0x0f;
        analysis.push("Destination Message ID", destination_message_id.to_string());
        analysis.push("Source Message ID", source_message_id.to_string());
        let Some(connection_instance) = read_u16(&message.data, 4) else {
            analysis
                .warnings
                .push("Open response is missing Connection Instance ID".into());
            return;
        };
        analysis.push("Connection Instance ID", format_u16(connection_instance));
        let Some(pending) = self.pending_opens.remove(&key) else {
            analysis
                .warnings
                .push("Matching Open request was not found in the trace".into());
            return;
        };
        analysis.push("Open request frame", format!("#{}", pending.request_frame));
        analysis.push(
            "Requested Message Body Format",
            pending.requested_format.label(),
        );
        if matches!(format, MessageBodyFormat::Reserved(_)) {
            analysis
                .warnings
                .push("Reserved Actual Message Body Format".into());
            return;
        }
        let Some((request_identifier, response_identifier)) = connection_identifiers(
            pending.group_select,
            pending.source_message_id,
            destination_message_id,
            source_message_id,
            key.client_mac,
            key.server_mac,
        ) else {
            if pending.group_select != 0x0f {
                analysis
                    .warnings
                    .push("Open response cannot create a connection for this Group Select".into());
            }
            return;
        };
        let request_context = ConnectedContext {
            is_response: false,
            format,
            client_mac: key.client_mac,
            server_mac: key.server_mac,
            connection_instance,
            open_frame: message.number,
        };
        let response_context = ConnectedContext {
            is_response: true,
            ..request_context.clone()
        };
        self.connections.insert(
            ConnectionKey {
                identifier: request_identifier,
                peer_mac: if pending.group_select == 1 {
                    key.client_mac
                } else {
                    key.server_mac
                },
            },
            request_context,
        );
        self.connections.insert(
            ConnectionKey {
                identifier: response_identifier,
                peer_mac: key.client_mac,
            },
            response_context,
        );
        analysis.push(
            "Request Connection ID",
            format!("0x{request_identifier:03X}"),
        );
        analysis.push(
            "Response Connection ID",
            format!("0x{response_identifier:03X}"),
        );
        raw_tail(
            &mut *analysis,
            "Trailing data",
            message.data.get(6..).unwrap_or_default(),
        );
    }

    fn decode_connected(
        &mut self,
        message: &TraceMessage,
        group: MessageGroup,
        context: ConnectedContext,
    ) -> FrameAnalysis {
        let function = if context.is_response {
            FrameFunction::ConnectedExplicitResponse
        } else {
            FrameFunction::ConnectedExplicitRequest
        };
        let mut analysis = FrameAnalysis::new(group, function, function.label());
        analysis.push("Connection ID", format!("0x{:03X}", message.identifier));
        analysis.push(
            "Connection Instance ID",
            format_u16(context.connection_instance),
        );
        analysis.push("Message Body Format", context.format.label());
        analysis.push(
            "Learned from Open frame",
            format!("#{}", context.open_frame),
        );
        let Some(header) = message.data.first().copied() else {
            analysis
                .warnings
                .push("Missing Explicit Message Header".into());
            return analysis;
        };
        let peer = header & 0x3f;
        let xid = (header >> 6) & 1;
        analysis.push("XID", xid.to_string());
        analysis.push(
            if context.is_response {
                "Destination MAC ID"
            } else {
                "Peer MAC ID"
            },
            peer.to_string(),
        );
        if header & 0x80 == 0 {
            return self.decode_connected_body(message, context, xid, &message.data[1..], analysis);
        }
        let Some(protocol) = message.data.get(1).copied() else {
            analysis
                .warnings
                .push("Missing Fragmentation Protocol byte".into());
            return analysis;
        };
        let kind = protocol >> 6;
        let count = protocol & 0x3f;
        analysis.push("Fragment type", fragment_type(kind));
        analysis.push("Fragment count", count.to_string());
        if kind == 3 {
            analysis.title = "Explicit Fragment Acknowledge".into();
            if let Some(status) = message.data.get(2) {
                analysis.push(
                    "Acknowledge status",
                    match status {
                        0 => "0x00 - Success".into(),
                        1 => "0x01 - Too Much Data".into(),
                        value => format!("0x{value:02X} - Reserved"),
                    },
                );
            } else {
                analysis
                    .warnings
                    .push("Missing fragment acknowledge status".into());
            }
            return analysis;
        }
        let key = FragmentKey {
            identifier: message.identifier,
            peer_mac: peer,
            header: header & 0x7f,
            direction: message.direction.to_ascii_lowercase(),
        };
        let bytes = message.data.get(2..).unwrap_or_default();
        match (kind, count) {
            (0, 0x3f) => {
                analysis.push("Reassembly", "Single-fragment complete message");
                self.decode_connected_body(message, context, xid, bytes, analysis)
            }
            (0, 0) => {
                self.fragments.insert(
                    key,
                    FragmentState {
                        first_frame: message.number,
                        last_count: 0,
                        fragments: 1,
                        body: bytes.to_vec(),
                    },
                );
                analysis.title = "First Explicit Message Fragment".into();
                analysis.push("Fragment data", hex_bytes(bytes));
                analysis
            }
            (1 | 2, _) => {
                let Some(state) = self.fragments.get_mut(&key) else {
                    analysis
                        .warnings
                        .push("Fragment received before a first fragment".into());
                    return analysis;
                };
                let expected = (state.last_count + 1) & 0x3f;
                if count == state.last_count {
                    analysis.title = "Repeated Explicit Message Fragment".into();
                    analysis.push("Reassembly", "Duplicate/retry ignored");
                    return analysis;
                }
                if count != expected {
                    self.fragments.remove(&key);
                    analysis.warnings.push(format!(
                        "Expected fragment count {expected}, received {count}; reassembly reset"
                    ));
                    return analysis;
                }
                state.body.extend_from_slice(bytes);
                state.last_count = count;
                state.fragments += 1;
                if kind == 1 {
                    analysis.title = "Middle Explicit Message Fragment".into();
                    analysis.push("Reassembled bytes", state.body.len().to_string());
                    return analysis;
                }
                let state = self.fragments.remove(&key).unwrap();
                analysis.push("First fragment frame", format!("#{}", state.first_frame));
                analysis.push("Fragments", state.fragments.to_string());
                analysis.push("Reassembled body", hex_bytes(&state.body));
                let mut decoded =
                    self.decode_connected_body(message, context, xid, &state.body, analysis);
                decoded.title.push_str(" (Reassembled)");
                decoded
            }
            _ => {
                self.fragments.remove(&key);
                analysis
                    .warnings
                    .push("Invalid first fragment count or reserved fragment type".into());
                analysis
            }
        }
    }

    fn decode_connected_body(
        &mut self,
        message: &TraceMessage,
        context: ConnectedContext,
        xid: u8,
        body: &[u8],
        mut analysis: FrameAnalysis,
    ) -> FrameAnalysis {
        let Some(service_field) = body.first().copied() else {
            analysis
                .warnings
                .push("Missing Explicit Message Service Field".into());
            return analysis;
        };
        let service = service_field & 0x7f;
        let response_flag = service_field & 0x80 != 0;
        analysis.title = format!(
            "{} {}",
            service_name(service),
            if response_flag { "Response" } else { "Request" }
        );
        analysis.push(
            "Service",
            format!("0x{service:02X} - {}", service_name(service)),
        );
        analysis.push("R/R", if response_flag { "Response" } else { "Request" });
        if response_flag != context.is_response {
            analysis
                .warnings
                .push("R/R flag does not agree with the learned connection direction".into());
        }
        let request_key = ExplicitRequestKey {
            client_mac: context.client_mac,
            server_mac: context.server_mac,
            connection_instance: context.connection_instance,
            xid,
        };
        if context.is_response {
            let request = self.requests.remove(&request_key);
            if service == 0x14 {
                decode_devicenet_error(body, &mut analysis);
            } else {
                analysis.append_service_details(decode_common_service_data(
                    service,
                    true,
                    &body[1..],
                    false,
                ));
            }
            if let Some(request) = request {
                analysis.push("Request frame", format!("#{}", request.frame));
                analysis.push(
                    "Request service",
                    format!(
                        "0x{:02X} - {}",
                        request.service,
                        service_name(request.service)
                    ),
                );
                if let Some(value) = request.class_id {
                    analysis.push("Class ID", format_value(value));
                }
                if let Some(value) = request.instance_id {
                    analysis.push("Instance ID", format_value(value));
                }
                if let Some(value) = request.attribute_id {
                    analysis.push("Attribute ID", format_value(value));
                }
            } else if service != 0x14 {
                analysis
                    .warnings
                    .push("Matching request was not found in the trace".into());
            }
            return analysis;
        }

        let address = parse_request_address(body, context.format, &mut analysis);
        let mut service_data = body.get(address.offset..).unwrap_or_default();
        let mut attribute_id = None;
        if matches!(service, 0x0e | 0x10) && context.format != MessageBodyFormat::CipPath {
            if let Some(attribute) = service_data.first().copied() {
                attribute_id = Some(u32::from(attribute));
                analysis.push("Attribute ID", format_value(u32::from(attribute)));
                service_data = &service_data[1..];
            } else {
                analysis
                    .warnings
                    .push("Missing DeviceNet Attribute ID".into());
            }
        }
        analysis.append_service_details(decode_common_service_data(
            service,
            false,
            service_data,
            context.format != MessageBodyFormat::CipPath,
        ));
        self.requests.insert(
            request_key,
            ExplicitRequestContext {
                frame: message.number,
                service,
                class_id: address.class_id,
                instance_id: address.instance_id,
                attribute_id,
            },
        );
        analysis
    }
}

#[derive(Default)]
struct ParsedAddress {
    class_id: Option<u32>,
    instance_id: Option<u32>,
    offset: usize,
}

fn parse_request_address(
    body: &[u8],
    format: MessageBodyFormat,
    analysis: &mut FrameAnalysis,
) -> ParsedAddress {
    let mut address = ParsedAddress {
        offset: 1,
        ..Default::default()
    };
    match format {
        MessageBodyFormat::DeviceNet8_8 if body.len() >= 3 => {
            address.class_id = Some(u32::from(body[1]));
            address.instance_id = Some(u32::from(body[2]));
            address.offset = 3;
        }
        MessageBodyFormat::DeviceNet8_16 if body.len() >= 4 => {
            address.class_id = Some(u32::from(body[1]));
            address.instance_id = read_u16(body, 2).map(u32::from);
            address.offset = 4;
        }
        MessageBodyFormat::DeviceNet16_16 if body.len() >= 5 => {
            address.class_id = read_u16(body, 1).map(u32::from);
            address.instance_id = read_u16(body, 3).map(u32::from);
            address.offset = 5;
        }
        MessageBodyFormat::DeviceNet16_8 if body.len() >= 4 => {
            address.class_id = read_u16(body, 1).map(u32::from);
            address.instance_id = Some(u32::from(body[3]));
            address.offset = 4;
        }
        MessageBodyFormat::CipPath => {
            let Some(words) = body.get(1).copied() else {
                analysis.warnings.push("Missing CIP Path length".into());
                return address;
            };
            let expected = usize::from(words) * 2;
            let available = body.len().saturating_sub(2);
            let used = expected.min(available);
            let path = &body[2..2 + used];
            analysis.push("Path size", format!("{words} word(s) / {expected} byte(s)"));
            analysis.push("Packed EPATH", hex_bytes(path));
            decode_logical_path(path, analysis);
            address.offset = 2 + used;
            if used != expected {
                analysis.warnings.push(format!(
                    "Packed EPATH is truncated: expected {expected} bytes, found {available}"
                ));
            }
            return address;
        }
        MessageBodyFormat::Reserved(value) => {
            analysis
                .warnings
                .push(format!("Reserved Message Body Format {value}"));
            return address;
        }
        _ => {
            analysis.warnings.push("Object address is truncated".into());
            address.offset = body.len();
            return address;
        }
    }
    if let Some(value) = address.class_id {
        analysis.push("Class ID", format_value(value));
    }
    if let Some(value) = address.instance_id {
        analysis.push("Instance ID", format_value(value));
    }
    address
}

fn decode_logical_path(path: &[u8], analysis: &mut FrameAnalysis) {
    let mut offset = 0;
    let mut items = Vec::new();
    while offset < path.len() {
        let segment = path[offset];
        if segment & 0xe0 != 0x20 {
            break;
        }
        let logical_type = (segment >> 2) & 0x07;
        let format = segment & 0x03;
        let (value, used) = match format {
            0 if offset + 1 < path.len() => (u32::from(path[offset + 1]), 2),
            1 if offset + 3 < path.len() => (
                u32::from(u16::from_le_bytes([path[offset + 2], path[offset + 3]])),
                4,
            ),
            2 if offset + 5 < path.len() => (
                u32::from_le_bytes([
                    path[offset + 2],
                    path[offset + 3],
                    path[offset + 4],
                    path[offset + 5],
                ]),
                6,
            ),
            _ => break,
        };
        items.push(format!(
            "{}={}",
            logical_segment_name(logical_type),
            format_value(value)
        ));
        offset += used;
    }
    if !items.is_empty() {
        analysis.push("Logical path", items.join(", "));
    }
}

fn decode_group4(message: &TraceMessage, message_id: u8) -> FrameAnalysis {
    let function = match message_id {
        0x00..=0x2b => FrameFunction::Group4Reserved,
        0x2c => FrameFunction::Group4CommunicationFaultedResponse,
        0x2d => FrameFunction::Group4CommunicationFaultedRequest,
        0x2e => FrameFunction::Group4OfflineOwnershipResponse,
        0x2f => FrameFunction::Group4OfflineOwnershipRequest,
        _ => unreachable!("Group 4 is limited to 0x00-0x2F"),
    };
    let mut analysis = FrameAnalysis::new(MessageGroup::Group4, function, function.label());
    analysis.push("Message ID", format!("0x{message_id:02X}"));
    match message_id {
        0x00..=0x2b => {
            analysis.push("Data", hex_bytes(&message.data));
            analysis
                .warnings
                .push("Group 4 Message IDs 0x00-0x2B are reserved".into());
        }
        0x2e | 0x2f => decode_offline_ownership(message_id == 0x2e, &message.data, &mut analysis),
        0x2d => decode_faulted_request(&message.data, &mut analysis),
        0x2c => decode_faulted_response(&message.data, &mut analysis),
        _ => unreachable!(),
    }
    analysis
}

fn decode_offline_ownership(is_response: bool, data: &[u8], analysis: &mut FrameAnalysis) {
    if data.len() != 8 {
        analysis.warnings.push(format!(
            "Offline Ownership message must contain 8 bytes, found {}",
            data.len()
        ));
    }
    let Some(header) = data.first().copied() else {
        return;
    };
    analysis.push("Client MAC ID", (header & 0x3f).to_string());
    if header & 0xc0 != 0 {
        analysis
            .warnings
            .push("Offline Ownership reserved header bits are nonzero".into());
    }
    decode_group4_service(data, 0x4b, is_response, analysis);
    decode_vendor_serial(data, 2, analysis);
    raw_tail(analysis, "Trailing data", data.get(8..).unwrap_or_default());
}

fn decode_faulted_request(data: &[u8], analysis: &mut FrameAnalysis) {
    let Some(service_field) = data.get(1).copied() else {
        analysis
            .warnings
            .push("Communication Faulted request is missing Service".into());
        return;
    };
    let service = service_field & 0x7f;
    let name = faulted_service_name(service);
    analysis.title = format!("{name} Request");
    decode_group4_service(data, service, false, analysis);
    let header = data[0];
    match service {
        0x4b => {
            analysis.push(
                "Match mode",
                if header & 0x40 != 0 {
                    "Exact MAC ID"
                } else {
                    "MAC ID mask"
                },
            );
            analysis.push("Match/mask value", (header & 0x3f).to_string());
            if let Some(offset) = data.get(2) {
                analysis.push("Time Delay Byte Offset", offset.to_string());
                if *offset > 6 {
                    analysis
                        .warnings
                        .push("Time Delay Byte Offset must be 0-6".into());
                }
            } else {
                analysis
                    .warnings
                    .push("Who request is missing Time Delay Byte Offset".into());
            }
            if data.len() != 3 {
                analysis
                    .warnings
                    .push("Who request must contain 3 bytes".into());
            }
        }
        0x4c => {
            analysis.push(
                "Match mode",
                if header & 0x40 != 0 {
                    "Exact MAC ID"
                } else {
                    "MAC ID mask"
                },
            );
            analysis.push("Match/mask value", (header & 0x3f).to_string());
            match data.len() {
                2 => analysis.push("Protocol", "Multicast"),
                8 => {
                    analysis.push("Protocol", "Point-to-point");
                    decode_vendor_serial(data, 2, analysis);
                }
                length => analysis.warnings.push(format!(
                    "Identify request must contain 2 or 8 bytes, found {length}"
                )),
            }
        }
        0x4d => {
            analysis.push("New MAC ID", (header & 0x3f).to_string());
            if header & 0xc0 != 0 {
                analysis
                    .warnings
                    .push("Change MAC ID reserved header bits are nonzero".into());
            }
            decode_vendor_serial(data, 2, analysis);
            if data.len() != 8 {
                analysis
                    .warnings
                    .push("Change MAC ID request must contain 8 bytes".into());
            }
        }
        _ => {
            analysis
                .warnings
                .push("Unknown Communication Faulted service".into());
            analysis.push("Data", hex_bytes(data));
        }
    }
}

fn decode_faulted_response(data: &[u8], analysis: &mut FrameAnalysis) {
    if data.len() == 7 && data.first().is_some_and(|header| header & 0x80 == 0) {
        analysis.title = "Who Communication Faulted Response".into();
        analysis.push("Physical port", (data[0] & 0x7f).to_string());
        decode_vendor_serial(data, 1, analysis);
        return;
    }
    let Some(service) = data.get(1).map(|value| value & 0x7f) else {
        analysis
            .warnings
            .push("Communication Faulted response is missing Service".into());
        return;
    };
    analysis.title = format!("{} Response", faulted_service_name(service));
    decode_group4_service(data, service, true, analysis);
    if service == 0x4c {
        analysis.push(
            "Match mode",
            if data[0] & 0x40 != 0 {
                "Exact MAC ID"
            } else {
                "MAC ID mask"
            },
        );
        analysis.push("Match/mask value", (data[0] & 0x3f).to_string());
        if data.len() != 2 {
            analysis
                .warnings
                .push("Identify response must contain 2 bytes".into());
        }
    } else {
        analysis
            .warnings
            .push("Only Who or Identify responses are defined at Group 4 Message ID 0x2C".into());
        analysis.push("Data", hex_bytes(data));
    }
}

fn decode_group4_service(data: &[u8], expected: u8, response: bool, analysis: &mut FrameAnalysis) {
    let Some(field) = data.get(1).copied() else {
        analysis
            .warnings
            .push("Missing Group 4 Service Field".into());
        return;
    };
    let code = field & 0x7f;
    let is_response = field & 0x80 != 0;
    let name = if code == 0x4b
        && matches!(
            analysis.function,
            FrameFunction::Group4OfflineOwnershipRequest
                | FrameFunction::Group4OfflineOwnershipResponse
        ) {
        "Allocate_Offline_Connection_Set"
    } else {
        faulted_service_name(code)
    };
    analysis.push("Service", format!("0x{code:02X} - {name}"));
    analysis.push("R/R", if is_response { "Response" } else { "Request" });
    if code != expected {
        analysis.warnings.push(format!(
            "Expected service 0x{expected:02X}, found 0x{code:02X}"
        ));
    }
    if is_response != response {
        analysis
            .warnings
            .push("R/R flag does not agree with the Group 4 Message ID".into());
    }
}

fn decode_vendor_serial(data: &[u8], offset: usize, analysis: &mut FrameAnalysis) {
    if let Some(vendor) = read_u16(data, offset) {
        analysis.push("Vendor ID", format_u16(vendor));
    } else {
        analysis.warnings.push("Missing 16-bit Vendor ID".into());
    }
    if data.len() >= offset + 6 {
        let serial = u32::from_le_bytes([
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
        ]);
        analysis.push("Serial number", format!("0x{serial:08X} ({serial})"));
    } else {
        analysis
            .warnings
            .push("Missing 32-bit Serial Number".into());
    }
}

fn connection_specific(
    group: MessageGroup,
    function: FrameFunction,
    message_id: u8,
    source_mac: u8,
    message: &TraceMessage,
) -> FrameAnalysis {
    let mut analysis = FrameAnalysis::new(group, function, function.label());
    analysis.push("Message ID", message_id.to_string());
    analysis.push("Source MAC ID", source_mac.to_string());
    analysis.push("Connection data", hex_bytes(&message.data));
    analysis.push(
        "Interpretation",
        "Connection-specific I/O or Explicit data; no matching UCMM Open was seen",
    );
    analysis
}

fn connection_identifiers(
    group_select: u8,
    client_source_id: u8,
    destination_id: u8,
    server_source_id: u8,
    client_mac: u8,
    server_mac: u8,
) -> Option<(u32, u32)> {
    match group_select {
        0 if client_source_id <= 0x0f && server_source_id <= 0x0f => Some((
            (u32::from(client_source_id) << 6) | u32::from(client_mac),
            (u32::from(server_source_id) << 6) | u32::from(server_mac),
        )),
        1 if destination_id <= 7 && server_source_id <= 7 => Some((
            0x400 | (u32::from(server_mac) << 3) | u32::from(destination_id),
            0x400 | (u32::from(server_mac) << 3) | u32::from(server_source_id),
        )),
        3 if client_source_id <= 4 && server_source_id <= 4 => Some((
            0x600 | (u32::from(client_source_id) << 6) | u32::from(client_mac),
            0x600 | (u32::from(server_source_id) << 6) | u32::from(server_mac),
        )),
        _ => None,
    }
}

fn decode_devicenet_error(body: &[u8], analysis: &mut FrameAnalysis) {
    analysis.title = "Explicit Error Response".into();
    if let Some(general) = body.get(1) {
        analysis.push(
            "General error",
            format!("0x{general:02X} - {}", general_error(*general)),
        );
    } else {
        analysis.warnings.push("Missing General Error code".into());
    }
    if let Some(additional) = body.get(2) {
        analysis.push("Additional code", format!("0x{additional:02X}"));
    } else {
        analysis
            .warnings
            .push("Missing Additional Error code".into());
    }
    raw_tail(
        analysis,
        "Trailing error data",
        body.get(3..).unwrap_or_default(),
    );
}

fn decode_heartbeat(body: &[u8], analysis: &mut FrameAnalysis) {
    analysis.title = "Device Heartbeat".into();
    if body.len() < 7 {
        analysis
            .warnings
            .push("Heartbeat payload is truncated".into());
        return;
    }
    analysis.push("Identity instance", format_u16(read_u16(body, 1).unwrap()));
    analysis.push(
        "Device state",
        format!("0x{:02X} - {}", body[3], device_state(body[3])),
    );
    analysis.push("Fault flags", format!("0x{:02X}", body[4]));
    analysis.push(
        "Configuration consistency",
        format_u16(read_u16(body, 5).unwrap()),
    );
    raw_tail(analysis, "Trailing data", &body[7..]);
}

fn decode_shutdown(body: &[u8], analysis: &mut FrameAnalysis) {
    analysis.title = "Device Shutdown".into();
    if body.len() < 7 {
        analysis
            .warnings
            .push("Shutdown payload is truncated".into());
        return;
    }
    analysis.push(
        "Responsible Class ID",
        format_u16(read_u16(body, 1).unwrap()),
    );
    analysis.push(
        "Responsible Instance ID",
        format_u16(read_u16(body, 3).unwrap()),
    );
    let code = read_u16(body, 5).unwrap();
    analysis.push(
        "Shutdown code",
        format!("0x{code:04X} - {}", shutdown_code_range(code)),
    );
    raw_tail(analysis, "Trailing data", &body[7..]);
}

fn ucmm_service_name(code: u8) -> &'static str {
    match code {
        0x4b => "Open_Explicit_Messaging_Connection",
        0x4c => "Close_Connection",
        0x4d => "Device_Heartbeat",
        0x4e => "Device_Shutdown",
        _ => service_name(code),
    }
}

fn faulted_service_name(code: u8) -> &'static str {
    match code {
        0x4b => "Who/Allocate",
        0x4c => "Identify",
        0x4d => "Change_MAC_ID",
        _ => "Unknown_Offline_Service",
    }
}

fn group_select_name(value: u8) -> String {
    match value {
        0 => "0 - Message Group 1".into(),
        1 => "1 - Message Group 2".into(),
        2 => "2 - Reserved".into(),
        3 => "3 - Message Group 3".into(),
        4..=0x0e => format!("{value} - Reserved"),
        0x0f => "15 - Node ping (no resources)".into(),
        _ => unreachable!(),
    }
}

fn fragment_type(value: u8) -> &'static str {
    match value {
        0 => "First",
        1 => "Middle",
        2 => "Last",
        3 => "Acknowledge",
        _ => unreachable!(),
    }
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
        _ => "Reserved",
    }
}

fn general_error(code: u8) -> &'static str {
    match code {
        0x01 => "Connection failure",
        0x02 => "Resource unavailable",
        0x03 => "Invalid parameter value",
        0x04 => "Path segment error",
        0x05 => "Path destination unknown",
        0x06 => "Partial transfer",
        0x08 => "Service not supported",
        0x09 => "Invalid attribute value",
        0x0a => "Attribute list error",
        0x0b => "Already in requested mode/state",
        0x0c => "Cannot perform service in current mode/state",
        0x0e => "Attribute not settable",
        0x10 => "Device state conflict",
        0x13 => "Not enough data",
        0x14 => "Attribute not supported",
        0x15 => "Too much data",
        0x16 => "Object does not exist",
        0x20 => "Invalid parameter",
        0xff => "Object-specific error",
        _ => "Unknown general status",
    }
}

fn device_state(code: u8) -> &'static str {
    match code {
        0 => "Nonexistent",
        1 => "Self-testing",
        2 => "Standby",
        3 => "Operational",
        4 => "Major recoverable fault",
        5 => "Major unrecoverable fault",
        _ => "Vendor-specific/reserved",
    }
}

fn shutdown_code_range(code: u16) -> &'static str {
    match code {
        0x0000..=0x01ff => "Open",
        0x0200..=0x02ff => "Vendor-specific",
        0x0300..=0x04ff => "Object-class-specific",
        _ => "Reserved by DeviceNet",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

fn format_value(value: u32) -> String {
    format!("0x{value:X} ({value})")
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

fn raw_tail(analysis: &mut FrameAnalysis, name: &str, data: &[u8]) {
    if !data.is_empty() {
        analysis.push(name, hex_bytes(data));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(number: u64, identifier: u32, data: &[u8]) -> TraceMessage {
        TraceMessage {
            number,
            time_offset_ms: Some(number as f64),
            bus: 1,
            direction: "Rx".into(),
            identifier,
            dlc: data.len(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn decodes_every_group_and_reserved_boundaries() {
        let messages = vec![
            message(1, 0x000, &[1]),
            message(2, 0x400, &[2]),
            message(3, 0x7c0, &[3]),
            message(4, 0x7ef, &[0, 0x4b, 1, 0, 2, 0, 0, 0]),
            message(5, 0x7f0, &[]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert_eq!(decoded[0].as_ref().unwrap().group, MessageGroup::Group1);
        assert_eq!(decoded[1].as_ref().unwrap().group, MessageGroup::Group2);
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::Group4Reserved
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().function,
            FrameFunction::Group4OfflineOwnershipRequest
        );
        assert_eq!(
            decoded[4].as_ref().unwrap().function,
            FrameFunction::InvalidIdentifier
        );
    }

    #[test]
    fn learns_group3_connected_explicit_ids_from_ucmm_open() {
        let messages = vec![
            message(1, 0x780, &[5, 0x4b, 2, 0x34]),
            message(2, 0x745, &[0, 0xcb, 2, 0, 2, 0]),
            message(3, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
            message(4, 0x605, &[0, 0x8e, 0xaa]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitRequest
        );
        assert_eq!(
            decoded[2].as_ref().unwrap().field("Class ID"),
            Some("0x1 (1)")
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitResponse
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().field("Attribute data"),
            Some("AA")
        );
    }

    #[test]
    fn derives_connection_ids_for_all_selectable_message_groups() {
        assert_eq!(
            connection_identifiers(0, 0x0a, 0, 3, 0, 5),
            Some((0x280, 0x0c5))
        );
        assert_eq!(
            connection_identifiers(1, 0, 1, 4, 0, 5),
            Some((0x429, 0x42c))
        );
        assert_eq!(
            connection_identifiers(3, 4, 0, 0, 0, 5),
            Some((0x700, 0x605))
        );
    }

    #[test]
    fn successful_ucmm_close_stops_connected_decoding() {
        let messages = vec![
            message(1, 0x780, &[5, 0x4b, 2, 0x34]),
            message(2, 0x745, &[0, 0xcb, 2, 0, 2, 0]),
            message(3, 0x700, &[5, 0x17, 1, 0, 2, 0]),
            message(4, 0x780, &[5, 0x4c, 2, 0]),
            message(5, 0x745, &[0, 0xcc]),
            message(6, 0x700, &[5, 0x17, 1, 0, 2, 0]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitRequest
        );
        assert_eq!(
            decoded[5].as_ref().unwrap().function,
            FrameFunction::Group3Connection
        );
    }

    #[test]
    fn decodes_all_group4_offline_message_shapes() {
        let messages = vec![
            message(1, 0x7ef, &[1, 0x4b, 6, 0, 8, 7, 6, 5]),
            message(2, 0x7ee, &[1, 0xcb, 6, 0, 8, 7, 6, 5]),
            message(3, 0x7ed, &[0x3f, 0x4c]),
            message(4, 0x7ec, &[0x3f, 0xcc]),
            message(5, 0x7ed, &[0x3f, 0x4b, 2]),
            message(6, 0x7ec, &[0, 6, 0, 8, 7, 6, 5]),
            message(7, 0x7ed, &[3, 0x4d, 6, 0, 8, 7, 6, 5]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert!(decoded.iter().all(Option::is_some));
        assert_eq!(
            decoded[5].as_ref().unwrap().title,
            "Who Communication Faulted Response"
        );
        assert_eq!(decoded[6].as_ref().unwrap().field("New MAC ID"), Some("3"));
    }
}
