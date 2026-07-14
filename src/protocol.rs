//! Unified DeviceNet Message Group 1-4 decoder.

use crate::assembly::{IoAssemblyDirection, assembly_instance, decode_assembly};
use crate::explicit::{ExplicitHeader, FragmentKind, MessageBodyFormat, fragment_ack_status};
use crate::group2::{Group2Analysis, Group2Decoder, Group2Function};
use crate::path::decode_logical_path;
use crate::services::{
    ServiceDetails, decode_common_service_data, format_u16, hex_bytes, service_name,
};
use crate::status::general_status_name;
use crate::{DecodedField, IdentifierFields, MessageGroup, TraceMessage, compare_optional_time};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFunction {
    Group1Connection,
    Group1IoMulticastPollResponse,
    Group1IoChangeOfStateOrCyclic,
    Group1IoBitStrobeResponse,
    Group1IoPollResponseOrChangeOfStateAck,
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
            Self::Group1IoMulticastPollResponse => {
                "Predefined-set I/O Multicast Poll Response role"
            }
            Self::Group1IoChangeOfStateOrCyclic => "Predefined-set I/O Change of State/Cyclic role",
            Self::Group1IoBitStrobeResponse => "Predefined-set I/O Bit-Strobe Response role",
            Self::Group1IoPollResponseOrChangeOfStateAck => {
                "Predefined-set I/O Poll Response or Change of State/Cyclic Acknowledge role"
            }
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

    pub fn is_io(self) -> bool {
        matches!(
            self,
            Self::Group1IoMulticastPollResponse
                | Self::Group1IoChangeOfStateOrCyclic
                | Self::Group1IoBitStrobeResponse
                | Self::Group1IoPollResponseOrChangeOfStateAck
                | Self::Group2(
                    Group2Function::IoBitStrobeCommand
                        | Group2Function::IoMulticastPollCommand
                        | Group2Function::ChangeOfStateOrCyclicAck
                        | Group2Function::IoPollOrChangeOfStateOrCyclic
                )
        )
    }

    /// Returns whether this predefined identifier function can carry an
    /// application Assembly payload. Protocol-only I/O commands/acknowledgments
    /// and context-free Group 1 connection IDs are intentionally excluded.
    pub fn has_io_assembly_payload(self) -> bool {
        matches!(
            self,
            Self::Group1IoMulticastPollResponse
                | Self::Group1IoChangeOfStateOrCyclic
                | Self::Group1IoBitStrobeResponse
                | Self::Group1IoPollResponseOrChangeOfStateAck
                | Self::Group2(
                    Group2Function::IoMulticastPollCommand
                        | Group2Function::IoPollOrChangeOfStateOrCyclic
                )
        )
    }
}

pub const DEFAULT_HOST_MAC_ID: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoAssemblySelection {
    pub host_mac_id: u8,
    pub input_instance: Option<u8>,
    pub output_instance: Option<u8>,
}

impl IoAssemblySelection {
    fn instance_for(self, direction: IoAssemblyDirection) -> Option<u8> {
        match direction {
            IoAssemblyDirection::Input => self.input_instance,
            IoAssemblyDirection::Output => self.output_instance,
        }
    }

    fn formats_are_compatible(self) -> bool {
        let input = self
            .input_instance
            .and_then(|number| assembly_instance(IoAssemblyDirection::Input, number));
        let output = self
            .output_instance
            .and_then(|number| assembly_instance(IoAssemblyDirection::Output, number));
        match (input, output) {
            (Some(input), Some(output)) => input
                .numeric_format()
                .is_compatible_with(output.numeric_format()),
            _ => true,
        }
    }
}

impl Default for IoAssemblySelection {
    fn default() -> Self {
        Self {
            host_mac_id: DEFAULT_HOST_MAC_ID,
            input_instance: None,
            output_instance: None,
        }
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
        self.fields.push(DecodedField::new(name, value));
    }

    fn push_service(&mut self, name: impl Into<String>, code: u8, value: impl Into<String>) {
        self.fields.push(DecodedField::service(name, code, value));
    }

    fn push_detailed(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        unit: impl Into<String>,
        description: impl Into<String>,
    ) {
        self.fields
            .push(DecodedField::detailed(name, value, unit, description));
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

/// Decode a trace into a compatibility map keyed by display frame number.
///
/// Repeated frame numbers overwrite earlier entries. New code should use
/// [`decode_trace_ordered`], which preserves one result slot per source frame.
#[deprecated(
    since = "0.1.0",
    note = "use decode_trace_ordered to preserve duplicate frame numbers"
)]
pub fn decode_trace(messages: &[TraceMessage]) -> HashMap<u64, FrameAnalysis> {
    messages
        .iter()
        .zip(decode_trace_ordered(messages))
        .filter_map(|(message, analysis)| analysis.map(|analysis| (message.number, analysis)))
        .collect()
}

/// Decode all DeviceNet groups while retaining one result slot per source frame.
pub fn decode_trace_ordered(messages: &[TraceMessage]) -> Vec<Option<FrameAnalysis>> {
    decode_trace_ordered_with_config(messages, None)
}

/// Decode all DeviceNet groups and apply the selected Volume 1 I/O Assembly mapping.
pub fn decode_trace_ordered_with_io(
    messages: &[TraceMessage],
    selection: IoAssemblySelection,
) -> Vec<Option<FrameAnalysis>> {
    decode_trace_ordered_with_config(messages, Some(selection))
}

fn decode_trace_ordered_with_config(
    messages: &[TraceMessage],
    io_assembly: Option<IoAssemblySelection>,
) -> Vec<Option<FrameAnalysis>> {
    let mut ordered = messages.iter().enumerate().collect::<Vec<_>>();
    ordered.sort_by(|(left_index, left), (right_index, right)| {
        compare_optional_time(left.time_offset_ms, right.time_offset_ms)
            .then_with(|| left.number.cmp(&right.number))
            .then_with(|| left_index.cmp(right_index))
    });

    let mut decoder = ProtocolDecoder {
        io_assembly,
        ..ProtocolDecoder::default()
    };
    let mut results = vec![None; messages.len()];
    for (source_index, message) in ordered {
        results[source_index] = decoder.decode(message);
    }
    results
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    bus: u32,
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
    bus: u32,
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
    bus: u32,
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
    bus: u32,
    identifier: u32,
    peer_mac: u8,
    header: u8,
    direction: String,
}

#[derive(Debug, Clone)]
struct FragmentState {
    first_frame: u64,
    last_kind: FragmentKind,
    last_count: u8,
    fragments: usize,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IoFragmentKey {
    bus: u32,
    identifier: u32,
    instance: u8,
    direction: IoAssemblyDirection,
}

#[derive(Debug, Clone)]
struct IoFragmentState {
    first_frame: u64,
    last_count: u8,
    payload: Vec<u8>,
}

#[derive(Default)]
struct ProtocolDecoder {
    group2: Group2Decoder,
    connections: HashMap<ConnectionKey, ConnectedContext>,
    pending_opens: HashMap<UcmmKey, PendingOpen>,
    pending_closes: HashMap<UcmmKey, (u16, u64)>,
    requests: HashMap<ExplicitRequestKey, ExplicitRequestContext>,
    fragments: HashMap<FragmentKey, FragmentState>,
    io_assembly: Option<IoAssemblySelection>,
    io_fragments: HashMap<IoFragmentKey, IoFragmentState>,
}

impl ProtocolDecoder {
    fn decode(&mut self, message: &TraceMessage) -> Option<FrameAnalysis> {
        let decoded = message.decoded_identifier().ok()?;
        let header = message.data.first().copied();
        if let Some(header) = header {
            let key = ConnectionKey {
                bus: message.bus,
                identifier: message.identifier,
                peer_mac: header & 0x3f,
            };
            if let Some(context) = self.connections.get(&key).cloned() {
                return Some(self.decode_connected(message, decoded.group, context));
            }
        }

        let analysis = match decoded.fields {
            IdentifierFields::Group1 {
                message_id,
                source_mac_id,
            } => Some(connection_specific(
                MessageGroup::Group1,
                group1_function(message_id),
                message_id,
                source_mac_id,
                message,
            )),
            IdentifierFields::Group2 { .. } => self.group2.decode(message).map(Into::into),
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
        };
        analysis.map(|analysis| self.attach_io_assembly(message, decoded.fields, analysis))
    }

    fn attach_io_assembly(
        &mut self,
        message: &TraceMessage,
        identifier: IdentifierFields,
        mut analysis: FrameAnalysis,
    ) -> FrameAnalysis {
        let Some(selection) = self.io_assembly else {
            return analysis;
        };
        if !analysis.function.has_io_assembly_payload() {
            return analysis;
        }
        if selection.host_mac_id > 63 {
            analysis.warnings.push(format!(
                "Host MAC ID {} is outside the DeviceNet range 0-63; Assembly mapping was skipped",
                selection.host_mac_id
            ));
            return analysis;
        }
        if !selection.formats_are_compatible() {
            analysis.warnings.push(
                "Selected Input and Output Assemblies mix INT and REAL numeric families. Volume 1 uses the first successfully established I/O connection to select the family; because a trace does not prove that connection order, the selected direction is decoded independently"
                    .into(),
            );
        }
        let Some((direction, direction_basis)) = io_payload_direction(
            analysis.function,
            identifier,
            message,
            selection.host_mac_id,
        ) else {
            analysis.push(
                "Assembly mapping",
                "No selectable Assembly payload is present in this I/O message",
            );
            if matches!(
                analysis.function,
                FrameFunction::Group2(Group2Function::IoPollOrChangeOfStateOrCyclic)
            ) {
                analysis.warnings.push(
                    "Group 2 Message ID 5 can carry either a controller command or a device message; use a Tx/Rx capture direction to establish the producer"
                        .into(),
                );
            } else if matches!(
                (analysis.function, identifier),
                (
                    FrameFunction::Group1IoMulticastPollResponse
                        | FrameFunction::Group1IoChangeOfStateOrCyclic
                        | FrameFunction::Group1IoBitStrobeResponse
                        | FrameFunction::Group1IoPollResponseOrChangeOfStateAck,
                    IdentifierFields::Group1 { source_mac_id, .. }
                ) if source_mac_id == selection.host_mac_id
            ) {
                analysis.warnings.push(
                    "Predefined Group 1 I/O messages are device-produced, but the Source MAC ID equals the configured host; Assembly mapping was skipped"
                        .into(),
                );
            }
            return analysis;
        };
        analysis.push(
            "I/O direction",
            match direction {
                IoAssemblyDirection::Input => "Input - device to host",
                IoAssemblyDirection::Output => "Output - host to device",
            },
        );
        analysis.push("Direction basis", direction_basis);
        let Some(instance_number) = selection.instance_for(direction) else {
            analysis.push("Assembly instance", "Not selected - raw I/O data retained");
            return analysis;
        };
        let Some(instance) = assembly_instance(direction, instance_number) else {
            analysis.warnings.push(format!(
                "Instance {instance_number} is not a supported Volume 1 6-29/6-39 or GT-1000-D EDS {} Assembly",
                direction.label()
            ));
            return analysis;
        };
        analysis.push(
            "Assembly instance",
            format!(
                "{} (0x{:02X}) - {}",
                instance.number, instance.number, instance.name
            ),
        );
        analysis.push("Assembly profile", instance.profile);
        analysis.push("Support declaration", instance.requirements);
        if instance.requirements.contains("(N)") {
            analysis.push(
                "Requirement note",
                "N means optional, not unsupported; actual supported instances are declared by the device manufacturer",
            );
        }
        analysis.push(
            "Selected I/O connection size",
            format!("{} bytes", instance.byte_len),
        );

        if analysis.function == FrameFunction::Group1IoBitStrobeResponse && instance.byte_len > 8 {
            analysis.warnings.push(format!(
                "Bit-Strobe Response data cannot carry the {}-byte selected Assembly; mapping was skipped",
                instance.byte_len
            ));
            return analysis;
        }

        // Every supported profile/EDS entry is a fixed static mapping whose
        // declared total I/O size is also its Produced/Consumed Connection
        // Size. That connection size, rather than an observed DLC, selects
        // the unacknowledged I/O fragmentation protocol.
        if instance.byte_len > 8 {
            self.decode_fragmented_io(message, direction, instance_number, analysis)
        } else {
            self.append_assembly_payload(direction, instance_number, &message.data, analysis)
        }
    }

    fn decode_fragmented_io(
        &mut self,
        message: &TraceMessage,
        direction: IoAssemblyDirection,
        instance: u8,
        mut analysis: FrameAnalysis,
    ) -> FrameAnalysis {
        let Some(protocol) = message.data.first().copied() else {
            analysis
                .warnings
                .push("Missing I/O Fragmentation Protocol byte".into());
            return analysis;
        };
        let fragment_type = protocol >> 6;
        let fragment_count = protocol & 0x3f;
        let fragment_name = match fragment_type {
            0 => "First",
            1 => "Middle",
            2 => "Last",
            _ => "Acknowledge (invalid for I/O)",
        };
        analysis.push("I/O fragment type", fragment_name);
        analysis.push("I/O fragment count", fragment_count.to_string());
        let fragment_data = message.data.get(1..).unwrap_or_default();
        let key = IoFragmentKey {
            bus: message.bus,
            identifier: message.identifier,
            instance,
            direction,
        };
        const MAX_IO_REASSEMBLY_BYTES: usize = 7 * 64;
        if fragment_data.len() > MAX_IO_REASSEMBLY_BYTES {
            self.io_fragments.remove(&key);
            analysis.warnings.push(format!(
                "I/O fragment data exceeds the protocol-sized safety limit ({} > {MAX_IO_REASSEMBLY_BYTES} bytes); transfer discarded",
                fragment_data.len()
            ));
            return analysis;
        }
        analysis.push("I/O fragment data", hex_bytes(fragment_data));

        match (fragment_type, fragment_count) {
            (0, 0x3f) => {
                self.io_fragments.remove(&key);
                analysis.push("Reassembled I/O data", hex_bytes(fragment_data));
                self.append_assembly_payload(direction, instance, fragment_data, analysis)
            }
            (0, 0) => {
                if self
                    .io_fragments
                    .insert(
                        key,
                        IoFragmentState {
                            first_frame: message.number,
                            last_count: 0,
                            payload: fragment_data.to_vec(),
                        },
                    )
                    .is_some()
                {
                    analysis
                        .warnings
                        .push("A new first I/O fragment replaced an incomplete series".into());
                }
                analysis.push("Assembly decode", "Waiting for remaining I/O fragments");
                analysis
            }
            (1 | 2, _) => {
                let Some(previous_count) =
                    self.io_fragments.get(&key).map(|state| state.last_count)
                else {
                    analysis
                        .warnings
                        .push("I/O fragment received before a first fragment".into());
                    return analysis;
                };
                if previous_count == 0x3f {
                    self.io_fragments.remove(&key);
                    analysis.warnings.push(
                        "I/O fragment count cannot advance beyond the 6-bit value 0x3F; reassembly reset"
                            .into(),
                    );
                    return analysis;
                }
                let expected = previous_count + 1;
                if fragment_count != expected {
                    self.io_fragments.remove(&key);
                    analysis.warnings.push(format!(
                        "Expected I/O fragment count {expected}, received {fragment_count}; reassembly reset"
                    ));
                    return analysis;
                }
                let state = self
                    .io_fragments
                    .get_mut(&key)
                    .expect("fragment state was checked above");
                if state.payload.len().saturating_add(fragment_data.len()) > MAX_IO_REASSEMBLY_BYTES
                {
                    let received = state.payload.len().saturating_add(fragment_data.len());
                    self.io_fragments.remove(&key);
                    analysis.warnings.push(format!(
                        "Reassembled I/O data exceeds the protocol-sized safety limit ({received} > {MAX_IO_REASSEMBLY_BYTES} bytes); transfer discarded"
                    ));
                    return analysis;
                }
                state.payload.extend_from_slice(fragment_data);
                state.last_count = fragment_count;
                if fragment_type == 1 {
                    analysis.push("Reassembled bytes", state.payload.len().to_string());
                    analysis.push("Assembly decode", "Waiting for remaining I/O fragments");
                    return analysis;
                }
                let state = self
                    .io_fragments
                    .remove(&key)
                    .expect("last fragment has an active series");
                analysis.push(
                    "First I/O fragment frame",
                    format!("#{}", state.first_frame),
                );
                analysis.push("Reassembled I/O data", hex_bytes(&state.payload));
                self.append_assembly_payload(direction, instance, &state.payload, analysis)
            }
            (0, _) => {
                self.io_fragments.remove(&key);
                analysis
                    .warnings
                    .push("First I/O fragment count must be 0x00 or 0x3F; reassembly reset".into());
                analysis
            }
            (3, _) => {
                self.io_fragments.remove(&key);
                analysis.warnings.push(
                    "Fragment acknowledgments are not valid for unacknowledged I/O fragmentation"
                        .into(),
                );
                analysis
            }
            _ => unreachable!(),
        }
    }

    fn append_assembly_payload(
        &self,
        direction: IoAssemblyDirection,
        instance: u8,
        payload: &[u8],
        mut analysis: FrameAnalysis,
    ) -> FrameAnalysis {
        match decode_assembly(direction, instance, payload) {
            Ok(decoded) => {
                analysis.push(
                    "Numeric conversion",
                    "CIP INT/REAL values use little-endian encoding. No implicit EDS multiplier, divider, base, or offset is applied; converting Counts requires the device's active Data Units and Full Scale configuration",
                );
                for component in decoded.components {
                    analysis.push_detailed(
                        component.name,
                        component.value,
                        component.unit,
                        component.description,
                    );
                }
                analysis.warnings.extend(decoded.warnings);
            }
            Err(error) => analysis.warnings.push(error),
        }
        analysis
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
                .push("UCMM management messages shall not be fragmented".into());
            return analysis;
        }
        let Some(service_field) = message.data.get(1).copied() else {
            analysis.warnings.push("Missing UCMM Service Field".into());
            return analysis;
        };
        let service = service_field & 0x7f;
        let is_response = service_field & 0x80 != 0;
        let valid_broadcast = is_response_port
            && is_response
            && matches!(service, 0x4d | 0x4e)
            && header & 0x3f == source_mac
            && message.data.len() == 8;
        let name = if matches!(service, 0x4d | 0x4e) && !valid_broadcast {
            service_name(service)
        } else {
            ucmm_service_name(service)
        };
        analysis.title = format!(
            "{name} {}",
            if is_response { "Response" } else { "Request" }
        );
        analysis.push_service("Service", service, format!("0x{service:02X} - {name}"));
        analysis.push("R/R", if is_response { "Response" } else { "Request" });
        if valid_broadcast {
            if let Some(field) = analysis
                .fields
                .iter_mut()
                .find(|field| field.name == "Destination MAC ID")
            {
                field.name = "Header Source MAC ID".into();
            }
        } else if is_response_port && is_response && matches!(service, 0x4d | 0x4e) {
            analysis.warnings.push(
                "Object-class-specific response does not have the fixed DeviceNet broadcast header and length"
                    .into(),
            );
        }
        if is_response != is_response_port {
            analysis
                .warnings
                .push("R/R flag does not agree with the Group 3 UCMM Message ID".into());
        }
        let state_valid = is_response == is_response_port;

        let xid = (header >> 6) & 1;
        let peer = header & 0x3f;
        if !is_response_port {
            let key = UcmmKey {
                bus: message.bus,
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
                    if matches!(format, MessageBodyFormat::Reserved(_)) {
                        analysis
                            .warnings
                            .push("Open request uses a reserved Message Body Format".into());
                    }
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
                    let message_id_valid = match group_select {
                        1 if source_message_id != 0 => {
                            analysis.warnings.push(
                                "Group 2 Open request Source Message ID is ignored and must be zero"
                                    .into(),
                            );
                            false
                        }
                        3 if source_message_id > 4 => {
                            analysis.warnings.push(
                                "Group 3 Open request Source Message ID must be in the 0-4 pool"
                                    .into(),
                            );
                            false
                        }
                        0 | 1 | 3 | 0x0f => true,
                        _ => false,
                    };
                    if state_valid
                        && message_id_valid
                        && !matches!(format, MessageBodyFormat::Reserved(_))
                    {
                        self.pending_opens.insert(
                            key,
                            PendingOpen {
                                group_select,
                                source_message_id,
                                requested_format: format,
                                request_frame: message.number,
                            },
                        );
                    }
                    raw_tail(&mut analysis, "Trailing data", &message.data[4..]);
                }
                0x4c => {
                    if let Some(instance) = read_u16(&message.data, 2) {
                        analysis.push("Connection Instance ID", format_u16(instance));
                        if state_valid {
                            self.pending_closes.insert(key, (instance, message.number));
                        }
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
                bus: message.bus,
                client_mac: peer,
                server_mac: source_mac,
                xid,
            };
            match service {
                0x4b => self.decode_open_response(message, key, &mut analysis, state_valid),
                0x4c => {
                    let close = self.pending_closes.get(&key).copied();
                    if state_valid {
                        self.pending_closes.remove(&key);
                    }
                    if let Some((instance, request_frame)) = close {
                        analysis.push("Close request frame", format!("#{request_frame}"));
                        analysis.push("Connection Instance ID", format_u16(instance));
                        if state_valid {
                            self.connections.retain(|connection_key, context| {
                                connection_key.bus != message.bus
                                    || context.connection_instance != instance
                                    || context.client_mac != key.client_mac
                                    || context.server_mac != key.server_mac
                            });
                        }
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
                    let open = self.pending_opens.get(&key).cloned();
                    let close = self.pending_closes.get(&key).copied();
                    if state_valid {
                        self.pending_opens.remove(&key);
                        self.pending_closes.remove(&key);
                    }
                    if let Some(open) = open {
                        analysis.push(
                            "Failed Open request frame",
                            format!("#{}", open.request_frame),
                        );
                    }
                    if let Some((instance, frame)) = close {
                        analysis.push("Failed Close request frame", format!("#{frame}"));
                        analysis.push("Connection Instance ID", format_u16(instance));
                    }
                }
                0x4d if valid_broadcast => decode_heartbeat(&message.data[1..], &mut analysis),
                0x4e if valid_broadcast => decode_shutdown(&message.data[1..], &mut analysis),
                _ => {
                    analysis.warnings.push(
                        "UCMM responses are limited to Open, Close, Error, Heartbeat, or Shutdown"
                            .into(),
                    );
                    raw_tail(&mut analysis, "Response data", &message.data[2..]);
                }
            }
        }
        analysis
    }

    fn decode_open_response(
        &mut self,
        message: &TraceMessage,
        key: UcmmKey,
        analysis: &mut FrameAnalysis,
        state_valid: bool,
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
        let pending = self.pending_opens.get(&key).cloned();
        if state_valid {
            self.pending_opens.remove(&key);
        }
        let Some(pending) = pending else {
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
        if !state_valid {
            return;
        }
        let message_ids_valid = match pending.group_select {
            0 | 3 if destination_message_id != 0 => {
                analysis.warnings.push(format!(
                    "Group {} Open response Destination Message ID is ignored and must be zero",
                    pending.group_select
                ));
                false
            }
            1 if destination_message_id > 5 || source_message_id > 5 => {
                analysis.warnings.push(
                    "Group 2 dynamic Message IDs must be 0-5; IDs 6 and 7 are reserved by DeviceNet"
                        .into(),
                );
                false
            }
            1 if destination_message_id == source_message_id => {
                analysis
                    .warnings
                    .push("Group 2 request and response must use two different Message IDs".into());
                false
            }
            3 if source_message_id > 4 => {
                analysis
                    .warnings
                    .push("Group 3 Open response Source Message ID must be in the 0-4 pool".into());
                false
            }
            _ => true,
        };
        if !message_ids_valid {
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
                bus: message.bus,
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
                bus: message.bus,
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
        let decoded_header = ExplicitHeader::decode(header);
        let peer = decoded_header.peer_mac;
        let xid = decoded_header.xid;
        analysis.push("XID", xid.to_string());
        analysis.push(
            if context.is_response {
                "Destination MAC ID"
            } else {
                "Peer MAC ID"
            },
            peer.to_string(),
        );
        if !decoded_header.fragmented {
            self.fragments.remove(&FragmentKey {
                bus: message.bus,
                identifier: message.identifier,
                peer_mac: peer,
                header: header & 0x7f,
                direction: message.direction.to_ascii_lowercase(),
            });
            return self.decode_connected_body(message, context, xid, &message.data[1..], analysis);
        }
        let Some(protocol) = message.data.get(1).copied() else {
            analysis
                .warnings
                .push("Missing Fragmentation Protocol byte".into());
            return analysis;
        };
        let (kind, count) = FragmentKind::decode(protocol);
        analysis.push("Fragment type", kind.label());
        analysis.push("Fragment count", count.to_string());
        if kind == FragmentKind::Acknowledge {
            analysis.title = "Explicit Fragment Acknowledge".into();
            if let Some(status) = message.data.get(2) {
                analysis.push("Acknowledge status", fragment_ack_status(*status));
            } else {
                analysis
                    .warnings
                    .push("Missing fragment acknowledge status".into());
            }
            return analysis;
        }
        let key = FragmentKey {
            bus: message.bus,
            identifier: message.identifier,
            peer_mac: peer,
            header: header & 0x7f,
            direction: message.direction.to_ascii_lowercase(),
        };
        let bytes = message.data.get(2..).unwrap_or_default();
        match (kind, count) {
            (FragmentKind::First, 0x3f) => {
                self.fragments.remove(&key);
                analysis.push("Reassembly", "Single-fragment complete message");
                self.decode_connected_body(message, context, xid, bytes, analysis)
            }
            (FragmentKind::First, 0) => {
                self.fragments.insert(
                    key,
                    FragmentState {
                        first_frame: message.number,
                        last_kind: FragmentKind::First,
                        last_count: 0,
                        fragments: 1,
                        body: bytes.to_vec(),
                    },
                );
                analysis.title = "First Explicit Message Fragment".into();
                analysis.push("Fragment data", hex_bytes(bytes));
                analysis
            }
            (FragmentKind::Middle | FragmentKind::Last, _) => {
                let Some(state) = self.fragments.get_mut(&key) else {
                    analysis
                        .warnings
                        .push("Fragment received before a first fragment".into());
                    return analysis;
                };
                let expected = (state.last_count + 1) & 0x3f;
                if kind == state.last_kind && count == state.last_count {
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
                state.last_kind = kind;
                state.last_count = count;
                state.fragments += 1;
                if kind == FragmentKind::Middle {
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
            (FragmentKind::First, _) => {
                self.fragments.remove(&key);
                analysis
                    .warnings
                    .push("Invalid first fragment count or reserved fragment type".into());
                analysis
            }
            (FragmentKind::Acknowledge, _) => unreachable!("acknowledgments returned above"),
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
        analysis.push_service(
            "Service",
            service,
            format!("0x{service:02X} - {}", service_name(service)),
        );
        analysis.push("R/R", if response_flag { "Response" } else { "Request" });
        if response_flag != context.is_response {
            analysis
                .warnings
                .push("R/R flag does not agree with the learned connection direction".into());
        }
        let state_valid = response_flag == context.is_response;
        let request_key = ExplicitRequestKey {
            bus: message.bus,
            client_mac: context.client_mac,
            server_mac: context.server_mac,
            connection_instance: context.connection_instance,
            xid,
        };
        if context.is_response {
            let request = self.requests.get(&request_key).cloned();
            let response_matches_request = request
                .as_ref()
                .is_some_and(|request| request.service == service);
            if state_valid && (response_matches_request || service == 0x14) {
                self.requests.remove(&request_key);
            }
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
                analysis.push_service(
                    "Request service",
                    request.service,
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
                if request.service != service && service != 0x14 {
                    analysis.warnings.push(format!(
                        "Response service 0x{service:02X} does not match request service 0x{:02X}",
                        request.service
                    ));
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
        if state_valid {
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
        }
        analysis
    }
}

fn io_payload_direction(
    function: FrameFunction,
    identifier: IdentifierFields,
    message: &TraceMessage,
    host_mac_id: u8,
) -> Option<(IoAssemblyDirection, &'static str)> {
    if message.data.is_empty() {
        return None;
    }
    match (function, identifier) {
        (
            FrameFunction::Group1IoMulticastPollResponse
            | FrameFunction::Group1IoChangeOfStateOrCyclic
            | FrameFunction::Group1IoBitStrobeResponse
            | FrameFunction::Group1IoPollResponseOrChangeOfStateAck,
            IdentifierFields::Group1 { source_mac_id, .. },
        ) => (source_mac_id != host_mac_id).then_some((
            IoAssemblyDirection::Input,
            "User selection assumes the Section 3-7 predefined-set role; the trace identifier does not prove allocation",
        )),
        (
            FrameFunction::Group2(Group2Function::IoMulticastPollCommand),
            IdentifierFields::Group2 { .. },
        ) => Some((
            IoAssemblyDirection::Output,
            "Predefined Group 2 Multicast Poll Command is controller-produced",
        )),
        (
            FrameFunction::Group2(Group2Function::IoPollOrChangeOfStateOrCyclic),
            IdentifierFields::Group2 { .. },
        ) => match message.direction.trim().to_ascii_lowercase().as_str() {
            "tx" | "transmit" => Some((
                IoAssemblyDirection::Output,
                "Capture direction Tx; Group 2 Message ID 5 MAC role is connection-dependent",
            )),
            "rx" | "receive" => Some((
                IoAssemblyDirection::Input,
                "Capture direction Rx; Group 2 Message ID 5 MAC role is connection-dependent",
            )),
            _ => None,
        },
        _ => None,
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
            let logical_path = decode_logical_path(path);
            address.class_id = logical_path.class_id;
            address.instance_id = logical_path.instance_id;
            if let Some(display) = logical_path.display {
                analysis.push("Logical path", display);
            }
            if let Some(value) = address.class_id {
                analysis.push("Class ID", format_value(value));
            }
            if let Some(value) = address.instance_id {
                analysis.push("Instance ID", format_value(value));
            }
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
    if header & 0x80 != 0 {
        analysis
            .warnings
            .push("Communication Faulted request header bit 7 is reserved and must be zero".into());
    }
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
                    if header != 0x3f {
                        analysis
                            .warnings
                            .push("Point-to-point Identify request header must be 0x3F".into());
                    }
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
        if data[0] & 0x80 != 0 {
            analysis
                .warnings
                .push("Identify response header bit 7 is reserved and must be zero".into());
        }
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
    analysis.push_service("Service", code, format!("0x{code:02X} - {name}"));
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
    let predefined_io = matches!(
        function,
        FrameFunction::Group1IoMulticastPollResponse
            | FrameFunction::Group1IoChangeOfStateOrCyclic
            | FrameFunction::Group1IoBitStrobeResponse
            | FrameFunction::Group1IoPollResponseOrChangeOfStateAck
    );
    analysis.push(
        if predefined_io {
            "I/O data"
        } else {
            "Connection data"
        },
        hex_bytes(&message.data),
    );
    analysis.push(
        "Interpretation",
        if predefined_io {
            "Section 3-7 Predefined Controller/Device Connection Set role; the identifier alone does not prove that the connection set is allocated"
        } else {
            "Connection-specific I/O or Explicit data; no matching UCMM Open was seen"
        },
    );
    analysis
}

/// Volume 3, 3-7, Figure 3-7.1 assigns the upper four Group 1
/// Message IDs to the Predefined Controller/Device Connection Set.
fn group1_function(message_id: u8) -> FrameFunction {
    match message_id {
        0x0c => FrameFunction::Group1IoMulticastPollResponse,
        0x0d => FrameFunction::Group1IoChangeOfStateOrCyclic,
        0x0e => FrameFunction::Group1IoBitStrobeResponse,
        0x0f => FrameFunction::Group1IoPollResponseOrChangeOfStateAck,
        _ => FrameFunction::Group1Connection,
    }
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
        1 if destination_id <= 5 && server_source_id <= 5 && destination_id != server_source_id => {
            Some((
                0x400 | (u32::from(server_mac) << 3) | u32::from(destination_id),
                0x400 | (u32::from(server_mac) << 3) | u32::from(server_source_id),
            ))
        }
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
            format!("0x{general:02X} - {}", general_status_name(*general)),
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
    if body[4] & 0xf8 != 0 {
        analysis
            .warnings
            .push("Heartbeat Fault Flags bits 7-3 must be zero".into());
    }
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

    fn message_on_bus(number: u64, bus: u32, identifier: u32, data: &[u8]) -> TraceMessage {
        TraceMessage {
            bus,
            ..message(number, identifier, data)
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
    fn decodes_predefined_connection_set_identifiers_from_section_3_7() {
        let messages = vec![
            message(1, 0x300 | 7, &[1]),
            message(2, 0x340 | 7, &[2]),
            message(3, 0x380 | 7, &[3]),
            message(4, 0x3c0 | 7, &[4]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert_eq!(
            decoded[0].as_ref().unwrap().function,
            FrameFunction::Group1IoMulticastPollResponse
        );
        assert_eq!(
            decoded[1].as_ref().unwrap().function,
            FrameFunction::Group1IoChangeOfStateOrCyclic
        );
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::Group1IoBitStrobeResponse
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().function,
            FrameFunction::Group1IoPollResponseOrChangeOfStateAck
        );
        assert!(
            decoded
                .iter()
                .all(|item| item.as_ref().unwrap().field("Source MAC ID") == Some("7"))
        );
        assert_eq!(
            group1_function(0x0c).label(),
            "Predefined-set I/O Multicast Poll Response role"
        );
        assert_eq!(
            group1_function(0x0f).label(),
            "Predefined-set I/O Poll Response or Change of State/Cyclic Acknowledge role"
        );
        assert!(
            decoded[0]
                .as_ref()
                .unwrap()
                .field("Interpretation")
                .unwrap()
                .contains("does not prove")
        );
        assert_eq!(
            messages[0].decoded_identifier().unwrap().fields,
            IdentifierFields::Group1 {
                message_id: 0x0c,
                source_mac_id: 7,
            }
        );
        assert_eq!(
            TraceMessage {
                identifier: 0x3ff,
                ..message(5, 0, &[])
            }
            .decoded_identifier()
            .unwrap()
            .fields,
            IdentifierFields::Group1 {
                message_id: 0x0f,
                source_mac_id: 63,
            }
        );
    }

    #[test]
    fn learned_dynamic_group2_connections_override_section_3_7_defaults() {
        let messages = vec![
            message(1, 0x780, &[5, 0x4b, 2, 0x10]),
            message(2, 0x745, &[0, 0xcb, 2, 0x45, 2, 0]),
            message(3, 0x42c, &[0, 0x0e, 1, 1, 1]),
            message(4, 0x42d, &[0, 0x8e, 0xaa]),
            message(5, 0x780, &[5, 0x4c, 2, 0]),
            message(6, 0x745, &[0, 0xcc]),
            message(7, 0x42b, &[0, 0x8e, 0xbb]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitRequest
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitResponse
        );
        assert_eq!(
            decoded[6].as_ref().unwrap().function,
            FrameFunction::Group2(Group2Function::ExplicitOrUnconnectedResponse)
        );
        assert_eq!(decoded[6].as_ref().unwrap().field("Request frame"), None);
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
        assert_eq!(connection_identifiers(1, 0, 6, 4, 0, 5), None);
        assert_eq!(connection_identifiers(1, 0, 1, 7, 0, 5), None);
        assert_eq!(connection_identifiers(1, 0, 2, 2, 0, 5), None);
        assert_eq!(
            connection_identifiers(3, 4, 0, 0, 0, 5),
            Some((0x700, 0x605))
        );
    }

    #[test]
    fn validates_ucmm_open_message_id_fields_before_changing_state() {
        let messages = vec![
            // Group 2 Request Source Message ID is ignored and shall be zero.
            message(1, 0x780, &[5, 0x4b, 2, 0x12]),
            message(2, 0x745, &[0, 0xcb, 2, 0x14, 2, 0]),
            // Group 3 response Destination Message ID is ignored and shall be zero.
            message(3, 0x780, &[0x45, 0x4b, 2, 0x34]),
            message(4, 0x745, &[0x40, 0xcb, 2, 0x14, 3, 0]),
            message(5, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert!(
            decoded[0]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("must be zero"))
        );
        assert!(
            decoded[3]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("Destination Message ID"))
        );
        assert_eq!(
            decoded[4].as_ref().unwrap().function,
            FrameFunction::Group3Connection
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
    fn keeps_learned_connections_isolated_per_bus() {
        // Volume 3, 2-7.2: an Open establishes connection identifiers only
        // on the DeviceNet link where the transaction occurred.
        let messages = vec![
            message_on_bus(1, 1, 0x780, &[5, 0x4b, 2, 0x34]),
            message_on_bus(2, 1, 0x745, &[0, 0xcb, 2, 0, 2, 0]),
            message_on_bus(3, 2, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
            message_on_bus(4, 1, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
        ];

        let decoded = decode_trace_ordered(&messages);
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::Group3Connection
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitRequest
        );
    }

    #[test]
    fn malformed_ucmm_response_does_not_establish_a_connection() {
        let messages = vec![
            message(1, 0x780, &[5, 0x4b, 2, 0x34]),
            // Message ID 5 is the response port, but R/R is incorrectly zero.
            message(2, 0x745, &[0, 0x4b, 2, 0, 2, 0]),
            message(3, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
        ];

        let decoded = decode_trace_ordered(&messages);
        assert!(
            decoded[1]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("R/R flag"))
        );
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::Group3Connection
        );
    }

    #[test]
    fn fragmented_ucmm_open_does_not_modify_connection_state() {
        let messages = vec![
            message(1, 0x780, &[0x85, 0x4b, 2, 0x34]),
            message(2, 0x745, &[0, 0xcb, 2, 0, 2, 0]),
            message(3, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert!(
            decoded[0]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("shall not be fragmented"))
        );
        assert_eq!(
            decoded[2].as_ref().unwrap().function,
            FrameFunction::Group3Connection
        );
    }

    #[test]
    fn complete_connected_message_resets_fragment_reassembly() {
        let messages = vec![
            message(1, 0x780, &[5, 0x4b, 2, 0x34]),
            message(2, 0x745, &[0, 0xcb, 2, 0, 2, 0]),
            message(3, 0x700, &[0x85, 0x00, 0x0e, 1]),
            message(4, 0x700, &[0x05, 0x0e, 1, 0, 2, 0, 7]),
            message(5, 0x700, &[0x85, 0x81, 0xaa]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert!(
            decoded[4]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("before a first"))
        );
    }

    #[test]
    fn only_decodes_well_formed_ucmm_broadcasts() {
        let messages = vec![
            // Header Source MAC 4 does not match Identifier Source MAC 5.
            message(1, 0x745, &[4, 0xcd, 1, 0, 0, 0, 0, 0]),
            // The same fixed-shape response with a matching Source MAC is a
            // Device Heartbeat; EV (bit 3) is required to be zero.
            message(2, 0x745, &[5, 0xcd, 1, 0, 3, 8, 0, 0]),
        ];
        let decoded = decode_trace_ordered(&messages);
        assert!(!decoded[0].as_ref().unwrap().title.contains("Heartbeat"));
        assert_eq!(decoded[1].as_ref().unwrap().title, "Device Heartbeat");
        assert!(
            decoded[1]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("bits 7-3"))
        );
    }

    #[test]
    fn mismatched_connected_response_preserves_the_request_context() {
        let messages = vec![
            message(1, 0x780, &[5, 0x4b, 2, 0x34]),
            message(2, 0x745, &[0, 0xcb, 2, 0, 2, 0]),
            message(3, 0x700, &[5, 0x0e, 1, 0, 2, 0, 7]),
            message(4, 0x605, &[0, 0x90]),
            message(5, 0x605, &[0, 0x8e, 0xaa]),
        ];

        let decoded = decode_trace_ordered(&messages);
        assert!(
            decoded[3]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("does not match request service"))
        );
        assert_eq!(
            decoded[4].as_ref().unwrap().field("Request frame"),
            Some("#3")
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

    #[test]
    fn decodes_packed_epath_logical_values_without_padding() {
        let mut analysis = FrameAnalysis::new(
            MessageGroup::Group1,
            FrameFunction::ConnectedExplicitRequest,
            "test",
        );
        let logical_path = decode_logical_path(&[0x21, 0x34, 0x12, 0x25, 0x78, 0x56]);
        analysis.push("Logical path", logical_path.display.unwrap());
        assert_eq!(
            analysis.field("Logical path"),
            Some("Class=0x1234 (4660), Instance=0x5678 (22136)")
        );
    }

    #[test]
    fn decodes_selected_io_assemblies_from_the_host_mac_perspective() {
        let selection = IoAssemblySelection {
            host_mac_id: 0,
            input_instance: Some(2),
            output_instance: Some(7),
        };
        let messages = vec![
            // Group 1 source MAC 1: device-produced Input Assembly.
            message(1, 0x341, &[0x81, 0x34, 0x12]),
            // Group 2 multicast poll command: controller-produced Output Assembly.
            message(2, 0x429, &[0x78, 0x56]),
            // Group 2 ID 5 addressed to host MAC 0: device-to-host input.
            message(3, 0x405, &[0x80, 0xfe, 0xff]),
            // Group 2 ID 5 addressed to device MAC 5: host-to-device output.
            TraceMessage {
                direction: "Tx".into(),
                ..message(4, 0x42d, &[0x02, 0x00])
            },
        ];
        let decoded = decode_trace_ordered_with_io(&messages, selection);

        assert_eq!(
            decoded[0].as_ref().unwrap().field("I/O direction"),
            Some("Input - device to host")
        );
        assert_eq!(decoded[0].as_ref().unwrap().field("Flow"), Some("4660"));
        assert_eq!(
            decoded[1].as_ref().unwrap().field("I/O direction"),
            Some("Output - host to device")
        );
        assert_eq!(
            decoded[1].as_ref().unwrap().field("Setpoint"),
            Some("22136")
        );
        assert_eq!(decoded[2].as_ref().unwrap().field("Flow"), Some("-2"));
        assert_eq!(decoded[3].as_ref().unwrap().field("Setpoint"), Some("2"));

        let flow = decoded[0]
            .as_ref()
            .unwrap()
            .fields
            .iter()
            .find(|field| field.name == "Flow")
            .unwrap();
        assert!(
            flow.unit
                .as_deref()
                .unwrap()
                .contains("Vol1 default: Counts")
        );
        assert!(flow.description.as_deref().unwrap().contains("class 0x31"));
        assert!(
            decoded[0]
                .as_ref()
                .unwrap()
                .field("Numeric conversion")
                .unwrap()
                .contains("No implicit EDS")
        );
    }

    #[test]
    fn predefined_group1_source_equal_to_host_is_a_topology_conflict() {
        let decoded = decode_trace_ordered_with_io(
            &[message(1, 0x340, &[0x78, 0x56])],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(2),
                output_instance: Some(7),
            },
        );
        let analysis = decoded[0].as_ref().unwrap();

        assert_eq!(analysis.field("Assembly instance"), None);
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("device-produced"))
        );
    }

    #[test]
    fn decodes_selected_direction_when_input_and_output_families_differ() {
        let decoded = decode_trace_ordered_with_io(
            &[message(1, 0x341, &[0x80, 0x34, 0x12])],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(2),
                output_instance: Some(19),
            },
        );
        let analysis = decoded[0].as_ref().unwrap();

        assert_eq!(analysis.field("Flow"), Some("4660"));
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("mix INT and REAL"))
        );

        let neutral = decode_trace_ordered_with_io(
            &[message(2, 0x341, &[0x80])],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(9),
                output_instance: Some(19),
            },
        );
        assert!(neutral[0].as_ref().unwrap().field("Status").is_some());
    }

    #[test]
    fn group2_message_id_5_uses_capture_direction_instead_of_the_mac_role() {
        let selection = IoAssemblySelection {
            host_mac_id: 0,
            input_instance: Some(2),
            output_instance: Some(7),
        };
        let messages = [
            TraceMessage {
                direction: "Rx".into(),
                ..message(1, 0x42d, &[0x80, 0x34, 0x12])
            },
            TraceMessage {
                direction: "Tx".into(),
                ..message(2, 0x42d, &[0x78, 0x56])
            },
            TraceMessage {
                direction: "unknown".into(),
                ..message(3, 0x42d, &[0x80, 0x34, 0x12])
            },
        ];
        let decoded = decode_trace_ordered_with_io(&messages, selection);

        assert_eq!(decoded[0].as_ref().unwrap().field("Flow"), Some("4660"));
        assert_eq!(
            decoded[1].as_ref().unwrap().field("Setpoint"),
            Some("22136")
        );
        assert_eq!(
            decoded[2].as_ref().unwrap().field("Assembly instance"),
            None
        );
        assert!(
            decoded[2]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("Tx/Rx capture direction"))
        );
    }

    #[test]
    fn context_free_group1_connection_is_not_assumed_to_be_io() {
        let decoded = decode_trace_ordered_with_io(
            &[message(1, 0x201, &[0x80, 0x34, 0x12])],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(2),
                output_instance: Some(7),
            },
        );
        let analysis = decoded[0].as_ref().unwrap();

        assert_eq!(analysis.function, FrameFunction::Group1Connection);
        assert!(!analysis.function.has_io_assembly_payload());
        assert_eq!(analysis.field("Flow"), None);
        assert_eq!(analysis.field("Assembly instance"), None);
    }

    #[test]
    fn legacy_decode_keeps_io_payload_raw_without_a_selection_context() {
        let decoded = decode_trace_ordered(&[message(1, 0x341, &[0x80, 1, 0])]);
        let analysis = decoded[0].as_ref().unwrap();
        assert_eq!(analysis.field("I/O data"), Some("80 01 00"));
        assert_eq!(analysis.field("I/O direction"), None);
        assert_eq!(analysis.field("Assembly instance"), None);
    }

    #[test]
    fn reassembles_unacknowledged_io_fragments_before_assembly_decode() {
        let payload = [0x80, 2, 1, 2, 1, 3, 1, 4, 2, 5, 6, 1, 7, 1, 8];
        let messages = vec![
            message(1, 0x341, &[0x00, 0x80, 2, 1, 2, 1, 3, 1]),
            message(2, 0x341, &[0x41, 4, 2, 5, 6, 1, 7, 1]),
            message(3, 0x341, &[0x82, 8]),
        ];
        let decoded = decode_trace_ordered_with_io(
            &messages,
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(12),
                output_instance: None,
            },
        );

        assert_eq!(
            decoded[0].as_ref().unwrap().field("Assembly decode"),
            Some("Waiting for remaining I/O fragments")
        );
        assert_eq!(
            decoded[1].as_ref().unwrap().field("Reassembled bytes"),
            Some("14")
        );
        let final_analysis = decoded[2].as_ref().unwrap();
        assert_eq!(
            final_analysis.field("Reassembled I/O data"),
            Some(hex_bytes(&payload).as_str())
        );
        assert!(
            final_analysis
                .field("Warning device detail byte 0")
                .unwrap()
                .contains("Reading Valid")
        );
        assert!(final_analysis.warnings.is_empty());
    }

    #[test]
    fn resets_io_reassembly_after_a_missed_fragment() {
        let decoded = decode_trace_ordered_with_io(
            &[
                message(1, 0x341, &[0x00, 1, 2, 3]),
                message(2, 0x341, &[0x82, 4]),
                message(3, 0x341, &[0x81, 5]),
            ],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(12),
                output_instance: None,
            },
        );
        assert!(
            decoded[1]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("Expected I/O fragment count 1"))
        );
        assert!(
            decoded[2]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("before a first fragment"))
        );
    }

    #[test]
    fn decodes_complete_fragmented_application_data_independently_of_connection_size() {
        let decoded = decode_trace_ordered_with_io(
            &[
                message(1, 0x341, &[0x00, 1, 2, 3, 4, 5, 6, 7]),
                message(2, 0x341, &[0x41, 8, 9, 10, 11, 12, 13, 14]),
                message(3, 0x341, &[0x82, 15, 16]),
                message(4, 0x341, &[0x83, 17]),
            ],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(12),
                output_instance: None,
            },
        );

        assert_eq!(
            decoded[2].as_ref().unwrap().field("Status"),
            Some(
                "0x01 (Basic; bits 0-6 are device-specific, 6-29/6-39 fallback Expanded map: common alarm)"
            )
        );
        assert!(
            decoded[2]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("1 trailing byte(s) were ignored"))
        );
        assert!(
            decoded[3]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("before a first fragment"))
        );
    }

    #[test]
    fn decodes_complete_short_fragment_like_a_short_unfragmented_payload() {
        let decoded = decode_trace_ordered_with_io(
            &[message(1, 0x341, &[0x3f, 0x80, 2, 0x01, 0x00, 1, 0x02, 0])],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(12),
                output_instance: None,
            },
        );
        let analysis = decoded[0].as_ref().unwrap();

        assert!(analysis.field("Status").is_some());
        assert!(analysis.field("Alarm common detail byte 0").is_some());
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("expects 15 bytes"))
        );
    }

    #[test]
    fn rejects_oversized_first_and_single_io_fragments_before_copying_or_formatting() {
        let mut oversized_first = vec![0; 450];
        oversized_first[0] = 0x00;
        let mut oversized_single = vec![0; 450];
        oversized_single[0] = 0x3f;
        let decoded = decode_trace_ordered_with_io(
            &[
                message(1, 0x341, &oversized_first),
                message(2, 0x341, &oversized_single),
            ],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(12),
                output_instance: None,
            },
        );

        for analysis in decoded.into_iter().flatten() {
            assert_eq!(analysis.field("I/O fragment data"), None);
            assert_eq!(analysis.field("Status"), None);
            assert!(
                analysis
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("449 > 448 bytes"))
            );
        }
    }

    #[test]
    fn does_not_treat_bit_strobe_command_or_dynamic_explicit_data_as_an_assembly() {
        let selection = IoAssemblySelection {
            host_mac_id: 0,
            input_instance: Some(2),
            output_instance: Some(7),
        };
        let messages = vec![
            message(1, 0x400, &[0xff; 8]),
            message(2, 0x780, &[5, 0x4b, 2, 0x10]),
            message(3, 0x745, &[0, 0xcb, 2, 0x45, 2, 0]),
            message(4, 0x42c, &[0, 0x0e, 1, 1, 1]),
        ];
        let decoded = decode_trace_ordered_with_io(&messages, selection);

        assert_eq!(
            decoded[0].as_ref().unwrap().field("Assembly instance"),
            None
        );
        assert_eq!(decoded[0].as_ref().unwrap().field("Assembly mapping"), None);
        assert_eq!(
            decoded[3].as_ref().unwrap().function,
            FrameFunction::ConnectedExplicitRequest
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().field("Assembly instance"),
            None
        );
    }

    #[test]
    fn rejects_a_fragmented_size_assembly_for_bit_strobe_response() {
        let decoded = decode_trace_ordered_with_io(
            &[message(1, 0x381, &[0; 8])],
            IoAssemblySelection {
                host_mac_id: 0,
                input_instance: Some(12),
                output_instance: None,
            },
        );
        let analysis = decoded[0].as_ref().unwrap();

        assert_eq!(analysis.function, FrameFunction::Group1IoBitStrobeResponse);
        assert_eq!(analysis.field("Status"), None);
        assert_eq!(analysis.field("I/O fragment type"), None);
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("Bit-Strobe Response data cannot carry"))
        );
    }

    #[test]
    fn rejects_an_invalid_host_mac_for_assembly_direction_inference() {
        let decoded = decode_trace_ordered_with_io(
            &[message(1, 0x341, &[0, 1, 0])],
            IoAssemblySelection {
                host_mac_id: 64,
                input_instance: Some(2),
                output_instance: Some(7),
            },
        );
        assert!(
            decoded[0]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("outside the DeviceNet range"))
        );
    }
}
