use crate::explicit::{ExplicitHeader, FragmentKind, MessageBodyFormat, fragment_ack_status};
use crate::mfc_explicit::{AttributeDecode, DeviceKey, MfcExplicitState, PendingAttributeUpdate};
use crate::path::decode_logical_path;
use crate::services::{decode_common_service_data, service_name};
use crate::status::general_status_name;
use crate::{DecodedField, TraceMessage, compare_optional_time};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group2Function {
    IoBitStrobeCommand,
    IoMulticastPollCommand,
    ChangeOfStateOrCyclicAck,
    ExplicitOrUnconnectedResponse,
    ExplicitRequest,
    IoPollOrChangeOfStateOrCyclic,
    UnconnectedExplicitRequest,
    DuplicateMacIdCheck,
}

impl Group2Function {
    pub fn label(self) -> &'static str {
        match self {
            Self::IoBitStrobeCommand => "Controller I/O Bit-Strobe Command",
            Self::IoMulticastPollCommand => "Controller I/O Multicast Poll Command",
            Self::ChangeOfStateOrCyclicAck => "Controller Change of State/Cyclic Acknowledge",
            Self::ExplicitOrUnconnectedResponse => "Device Explicit/Unconnected Response",
            Self::ExplicitRequest => "Controller Explicit Request",
            Self::IoPollOrChangeOfStateOrCyclic => {
                "Controller I/O Poll Command or Change of State/Cyclic Message"
            }
            Self::UnconnectedExplicitRequest => "Group 2 Only Unconnected Request",
            Self::DuplicateMacIdCheck => "Duplicate MAC ID Check",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group2Analysis {
    pub function: Group2Function,
    pub title: String,
    pub fields: Vec<DecodedField>,
    pub warnings: Vec<String>,
}

impl Group2Analysis {
    fn new(function: Group2Function, title: impl Into<String>) -> Self {
        Self {
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

    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragmentKey {
    bus: u32,
    identifier: u32,
    header_without_frag: u8,
    direction: String,
}

#[derive(Debug, Clone)]
struct FragmentState {
    first_message: u64,
    last_kind: FragmentKind,
    last_count: u8,
    fragments: usize,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestKey {
    bus: u32,
    device_mac: u8,
    client_mac: u8,
    xid: u8,
}

#[derive(Debug, Clone)]
struct RequestContext {
    message_number: u64,
    message_id: u8,
    service_code: u8,
    service_name: String,
    class_id: Option<u32>,
    instance_id: Option<u32>,
    attribute_id: Option<u32>,
    pending_attribute_update: Option<PendingAttributeUpdate>,
    kind: RequestKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Generic,
    AllocateControllerDevice,
    ReleaseControllerDevice { choice: Option<u8> },
}

#[derive(Default)]
pub(crate) struct Group2Decoder {
    body_formats: HashMap<(u32, u8), MessageBodyFormat>,
    fragments: HashMap<FragmentKey, FragmentState>,
    requests: HashMap<RequestKey, RequestContext>,
}

/// Decode only the predefined/static Group 2 interpretation into a frame-number map.
///
/// This compatibility API is lossy when display frame numbers repeat and does not
/// have the UCMM context required to recognize dynamically allocated Group 2
/// connections. Prefer [`decode_group2_trace_ordered`] for static Group 2 work,
/// or the crate-level unified ordered decoder for complete traces.
#[deprecated(
    since = "0.1.0",
    note = "use decode_group2_trace_ordered, or decode_trace_ordered for UCMM-aware decoding"
)]
pub fn decode_group2_trace(messages: &[TraceMessage]) -> HashMap<u64, Group2Analysis> {
    let mut ordered: Vec<_> = messages.iter().collect();
    ordered.sort_by(|left, right| {
        compare_optional_time(left.time_offset_ms, right.time_offset_ms)
            .then_with(|| left.number.cmp(&right.number))
    });

    let mut decoder = Group2Decoder::default();
    let mut mfc_explicit = MfcExplicitState::default();
    let mut analyses = HashMap::new();
    for message in ordered {
        if let Some(analysis) = decoder.decode(message, &mut mfc_explicit) {
            analyses.insert(message.number, analysis);
        }
    }
    analyses
}

/// Decode Group 2 messages while preserving one result slot per input frame.
///
/// This representation is safe for trace files whose display message numbers
/// repeat, and is therefore preferred by user interfaces and other consumers
/// that already address frames by their position in the source trace.
pub fn decode_group2_trace_ordered(messages: &[TraceMessage]) -> Vec<Option<Group2Analysis>> {
    let mut ordered: Vec<_> = messages.iter().enumerate().collect();
    ordered.sort_by(|(left_index, left), (right_index, right)| {
        compare_optional_time(left.time_offset_ms, right.time_offset_ms)
            .then_with(|| left.number.cmp(&right.number))
            .then_with(|| left_index.cmp(right_index))
    });

    let mut decoder = Group2Decoder::default();
    let mut mfc_explicit = MfcExplicitState::default();
    let mut analyses = vec![None; messages.len()];
    for (source_index, message) in ordered {
        analyses[source_index] = decoder.decode(message, &mut mfc_explicit);
    }
    analyses
}

impl Group2Decoder {
    pub(crate) fn decode(
        &mut self,
        message: &TraceMessage,
        mfc_explicit: &mut MfcExplicitState,
    ) -> Option<Group2Analysis> {
        if !(0x400..=0x5ff).contains(&message.identifier) {
            return None;
        }

        let message_id = (message.identifier & 0x07) as u8;
        let mac_id = ((message.identifier >> 3) & 0x3f) as u8;
        let function = function_for_message_id(message_id);

        match message_id {
            0 | 1 | 2 | 5 => Some(self.decode_io(message, function, mac_id, message_id)),
            3 | 4 | 6 => {
                Some(self.decode_explicit(message, function, mac_id, message_id, mfc_explicit))
            }
            7 => Some(self.decode_duplicate_mac(message, function, mac_id)),
            _ => unreachable!(),
        }
    }

    fn decode_io(
        &self,
        message: &TraceMessage,
        function: Group2Function,
        mac_id: u8,
        message_id: u8,
    ) -> Group2Analysis {
        let mut analysis = Group2Analysis::new(function, function.label());
        analysis.push("Message ID", format!("{message_id}"));
        analysis.push(mac_role(message_id), format!("{mac_id}"));
        analysis.push("I/O data", hex_bytes(&message.data));
        analysis.push(
            "Interpretation",
            "Application-/connection-specific I/O payload (not defined by the identifier mapping)",
        );
        analysis
    }

    fn decode_duplicate_mac(
        &self,
        message: &TraceMessage,
        function: Group2Function,
        mac_id: u8,
    ) -> Group2Analysis {
        let mut analysis = Group2Analysis::new(function, function.label());
        analysis.push("Destination MAC ID", format!("{mac_id}"));
        if message.data.len() != 7 {
            analysis.warnings.push(format!(
                "Duplicate MAC ID Check must contain exactly 7 bytes, found {}",
                message.data.len()
            ));
        }
        let Some(flags) = message.data.first().copied() else {
            analysis
                .warnings
                .push("Missing Request/Response and port byte".into());
            return analysis;
        };
        analysis.push(
            "Message type",
            if flags & 0x80 == 0 {
                "Request"
            } else {
                "Response"
            },
        );
        analysis.push("Physical port", format!("{}", flags & 0x7f));
        if message.data.len() >= 3 {
            analysis.push(
                "Vendor ID",
                format_u16(u16::from_le_bytes([message.data[1], message.data[2]])),
            );
        } else {
            analysis.warnings.push("Missing 16-bit Vendor ID".into());
        }
        if message.data.len() >= 7 {
            analysis.push(
                "Serial number",
                format_u32(u32::from_le_bytes([
                    message.data[3],
                    message.data[4],
                    message.data[5],
                    message.data[6],
                ])),
            );
        } else {
            analysis
                .warnings
                .push("Missing 32-bit Serial Number".into());
        }
        if message.data.len() > 7 {
            analysis.push("Trailing data", hex_bytes(&message.data[7..]));
        }
        analysis
    }

    fn decode_explicit(
        &mut self,
        message: &TraceMessage,
        function: Group2Function,
        mac_id: u8,
        message_id: u8,
        mfc_explicit: &mut MfcExplicitState,
    ) -> Group2Analysis {
        let mut base = Group2Analysis::new(function, function.label());
        base.push("Message ID", format!("{message_id}"));
        base.push(mac_role(message_id), format!("{mac_id}"));
        let Some(header) = message.data.first().copied() else {
            base.warnings.push("Missing Explicit Message Header".into());
            return base;
        };

        let decoded_header = ExplicitHeader::decode(header);
        base.push("XID", format!("{}", decoded_header.xid));
        base.push(
            if message_id == 3 {
                "Destination MAC ID"
            } else {
                "Source MAC ID"
            },
            format!("{}", decoded_header.peer_mac),
        );

        if !decoded_header.fragmented {
            self.fragments.remove(&FragmentKey {
                bus: message.bus,
                identifier: message.identifier,
                header_without_frag: header & 0x7f,
                direction: message.direction.to_ascii_lowercase(),
            });
            return self.decode_explicit_body(
                message,
                function,
                mac_id,
                message_id,
                header,
                &message.data[1..],
                base,
                mfc_explicit,
            );
        }

        let Some(protocol) = message.data.get(1).copied() else {
            base.warnings
                .push("Missing Fragmentation Protocol byte".into());
            return base;
        };
        let (fragment_kind, fragment_count) = FragmentKind::decode(protocol);
        base.push("Fragment type", fragment_kind.label());
        base.push("Fragment count", format!("{fragment_count}"));

        if fragment_kind == FragmentKind::Acknowledge {
            base.title = "Explicit Fragment Acknowledge".into();
            if let Some(status) = message.data.get(2).copied() {
                base.push("Ack status", fragment_ack_status(status));
            } else {
                base.warnings
                    .push("Missing fragment acknowledgment status".into());
            }
            return base;
        }

        let key = FragmentKey {
            bus: message.bus,
            identifier: message.identifier,
            header_without_frag: header & 0x7f,
            direction: message.direction.to_ascii_lowercase(),
        };
        let fragment_body = message.data.get(2..).unwrap_or_default();

        match (fragment_kind, fragment_count) {
            (FragmentKind::First, 0) => {
                self.fragments.insert(
                    key,
                    FragmentState {
                        first_message: message.number,
                        last_kind: FragmentKind::First,
                        last_count: 0,
                        fragments: 1,
                        body: fragment_body.to_vec(),
                    },
                );
                base.title = "First Explicit Message Fragment".into();
                base.push("Fragment data", hex_bytes(fragment_body));
                base
            }
            (FragmentKind::First, _) => {
                self.fragments.remove(&key);
                base.warnings
                    .push("Explicit first fragment count must be 0; reassembly was reset".into());
                base
            }
            (FragmentKind::Middle | FragmentKind::Last, _) => {
                let Some(state) = self.fragments.get_mut(&key) else {
                    base.warnings
                        .push("Fragment received before a first fragment".into());
                    return base;
                };
                let expected = (state.last_count + 1) & 0x3f;
                if fragment_kind == state.last_kind && fragment_count == state.last_count {
                    base.title = "Repeated Explicit Message Fragment".into();
                    base.push("Reassembly", "Duplicate/retry ignored");
                    return base;
                }
                if fragment_count != expected {
                    self.fragments.remove(&key);
                    base.warnings.push(format!(
                        "Expected fragment count {expected}, received {fragment_count}; reassembly was reset"
                    ));
                    return base;
                }
                state.body.extend_from_slice(fragment_body);
                state.last_kind = fragment_kind;
                state.last_count = fragment_count;
                state.fragments += 1;
                if fragment_kind == FragmentKind::Middle {
                    base.title = "Middle Explicit Message Fragment".into();
                    base.push("Reassembled bytes", format!("{}", state.body.len()));
                    return base;
                }

                let state = self.fragments.remove(&key).expect("fragment state exists");
                base.push("First fragment frame", format!("#{}", state.first_message));
                base.push("Fragments", format!("{}", state.fragments));
                base.push("Reassembled bytes", format!("{}", state.body.len()));
                base.push("Reassembled body", hex_bytes(&state.body));
                let mut decoded = self.decode_explicit_body(
                    message,
                    function,
                    mac_id,
                    message_id,
                    header,
                    &state.body,
                    base,
                    mfc_explicit,
                );
                decoded.title.push_str(" (Reassembled)");
                decoded
            }
            (FragmentKind::Acknowledge, _) => unreachable!("acknowledgments returned above"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_explicit_body(
        &mut self,
        message: &TraceMessage,
        function: Group2Function,
        device_mac: u8,
        message_id: u8,
        header: u8,
        body: &[u8],
        mut analysis: Group2Analysis,
        mfc_explicit: &mut MfcExplicitState,
    ) -> Group2Analysis {
        let Some(service_field) = body.first().copied() else {
            analysis
                .warnings
                .push("Missing Explicit Message service byte".into());
            return analysis;
        };
        let is_response = service_field & 0x80 != 0;
        let service_code = service_field & 0x7f;
        let name = if message_id == 6 && matches!(service_code, 0x4b | 0x4c) {
            device_net_service_name(service_code)
        } else {
            service_name(service_code)
        };
        analysis.title = format!(
            "{} {}",
            name,
            if is_response { "Response" } else { "Request" }
        );
        analysis.push_service(
            "Service",
            service_code,
            format!("0x{service_code:02X} - {name}"),
        );
        analysis.push("R/R", if is_response { "Response" } else { "Request" });
        let state_valid = is_response == (message_id == 3);

        if message_id == 3 {
            self.decode_response(
                message,
                device_mac,
                header,
                service_code,
                body,
                analysis,
                state_valid,
                mfc_explicit,
            )
        } else {
            self.decode_request(
                message,
                function,
                device_mac,
                message_id,
                header,
                service_code,
                body,
                analysis,
                state_valid,
                mfc_explicit,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_request(
        &mut self,
        message: &TraceMessage,
        function: Group2Function,
        device_mac: u8,
        message_id: u8,
        header: u8,
        service_code: u8,
        body: &[u8],
        mut analysis: Group2Analysis,
        state_valid: bool,
        mfc_explicit: &MfcExplicitState,
    ) -> Group2Analysis {
        if body[0] & 0x80 != 0 {
            analysis
                .warnings
                .push("Response flag set on a request identifier".into());
        }

        let body_format = if message_id == 6 {
            Some(MessageBodyFormat::DeviceNet8_8)
        } else {
            self.body_formats.get(&(message.bus, device_mac)).copied()
        };
        if let Some(format) = body_format {
            analysis.push("Message body format", format.label());
        } else {
            analysis.push(
                "Message body format",
                "Unknown (allocation response not seen)",
            );
        }

        let address = parse_request_address(body, body_format, &mut analysis);
        let mut service_data = body.get(address.data_offset..).unwrap_or_default();
        let mut attribute_id = address.attribute_id;

        if matches!(service_code, 0x0e | 0x10)
            && attribute_id.is_none()
            && body_format.is_some_and(|format| {
                !matches!(
                    format,
                    MessageBodyFormat::CipPath | MessageBodyFormat::Reserved(_)
                )
            })
        {
            if let Some(attribute) = service_data.first().copied() {
                attribute_id = Some(attribute as u32);
                analysis.push("Attribute ID", format_u32(attribute as u32));
                service_data = &service_data[1..];
            } else {
                analysis.warnings.push("Missing Attribute ID".into());
            }
        }

        let targets_devicenet_object =
            address.class_id == Some(0x03) && address.instance_id == Some(0x01);
        let request_kind = match (service_code, targets_devicenet_object) {
            (0x4b, true) => RequestKind::AllocateControllerDevice,
            (0x4c, true) => RequestKind::ReleaseControllerDevice {
                choice: service_data.first().copied(),
            },
            _ => RequestKind::Generic,
        };
        if message_id == 6 && !targets_devicenet_object {
            analysis.warnings.push(
                "Group 2 Only connection management must target DeviceNet Object Class 0x03, Instance 1"
                    .into(),
            );
        }

        match request_kind {
            RequestKind::AllocateControllerDevice => {
                set_service_identity(
                    &mut analysis,
                    service_code,
                    device_net_service_name(service_code),
                    false,
                );
                decode_allocation_request(service_data, message_id == 6, &mut analysis);
            }
            RequestKind::ReleaseControllerDevice { .. } => {
                set_service_identity(
                    &mut analysis,
                    service_code,
                    device_net_service_name(service_code),
                    false,
                );
                decode_release_request(service_data, &mut analysis);
            }
            _ if body_format.is_some() => append_service_details(
                &mut analysis,
                decode_common_service_data(
                    service_code,
                    false,
                    service_data,
                    body_format != Some(MessageBodyFormat::CipPath),
                ),
            ),
            _ if !service_data.is_empty() => analysis.push("Service data", hex_bytes(service_data)),
            _ => {}
        }

        if service_code == 0x0e
            && let (Some(class_id), Some(instance_id), Some(attribute_id)) =
                (address.class_id, address.instance_id, attribute_id)
        {
            append_attribute_decode(
                &mut analysis,
                mfc_explicit.describe_get_request(class_id, instance_id, attribute_id),
            );
        }

        let mut pending_attribute_update = if service_code == 0x10 {
            match (address.class_id, address.instance_id, attribute_id) {
                (Some(class_id), Some(instance_id), Some(attribute_id)) => append_attribute_decode(
                    &mut analysis,
                    mfc_explicit.decode_set_request(
                        DeviceKey {
                            bus: message.bus,
                            mac_id: device_mac,
                        },
                        class_id,
                        instance_id,
                        attribute_id,
                        service_data,
                    ),
                ),
                _ => None,
            }
        } else {
            None
        };

        if message_id == 6 && !matches!(service_code, 0x4b | 0x4c) {
            analysis
                .warnings
                .push("Only Allocate (0x4B) and Release (0x4C) are valid on Message ID 6".into());
        }

        let xid = (header >> 6) & 1;
        let client_mac = header & 0x3f;
        let request_key = RequestKey {
            bus: message.bus,
            device_mac,
            client_mac,
            xid,
        };
        let existing_request_frame = state_valid
            .then(|| {
                self.requests
                    .get(&request_key)
                    .map(|request| request.message_number)
            })
            .flatten();
        if let Some(existing_frame) = existing_request_frame {
            pending_attribute_update = None;
            analysis.warnings.push(format!(
                "Request frame #{existing_frame} is still pending for this Group 2 device/client/XID; the new request was not stored and any pending Set update from it was discarded"
            ));
        }
        if state_valid && existing_request_frame.is_none() {
            self.requests.insert(
                request_key,
                RequestContext {
                    message_number: message.number,
                    message_id,
                    service_code,
                    service_name: match request_kind {
                        RequestKind::AllocateControllerDevice
                        | RequestKind::ReleaseControllerDevice { .. } => {
                            device_net_service_name(service_code).into()
                        }
                        RequestKind::Generic => service_name(service_code).into(),
                    },
                    class_id: address.class_id,
                    instance_id: address.instance_id,
                    attribute_id,
                    pending_attribute_update,
                    kind: request_kind,
                },
            );
        }
        analysis.function = function;
        analysis
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_response(
        &mut self,
        message: &TraceMessage,
        device_mac: u8,
        header: u8,
        service_code: u8,
        body: &[u8],
        mut analysis: Group2Analysis,
        state_valid: bool,
        mfc_explicit: &mut MfcExplicitState,
    ) -> Group2Analysis {
        if body[0] & 0x80 == 0 {
            analysis
                .warnings
                .push("Request flag set on a response identifier".into());
        }
        let key = RequestKey {
            bus: message.bus,
            device_mac,
            client_mac: header & 0x3f,
            xid: (header >> 6) & 1,
        };
        let request = self.requests.get(&key).cloned();
        let response_matches_request = request
            .as_ref()
            .is_some_and(|request| request.service_code == service_code);
        if state_valid && (response_matches_request || service_code == 0x14) {
            self.requests.remove(&key);
        }

        if service_code == 0x14 {
            analysis.title = "Explicit Error Response".into();
            if let Some(general) = body.get(1).copied() {
                analysis.push(
                    "General error",
                    format!("0x{general:02X} - {}", general_status_name(general)),
                );
            } else {
                analysis.warnings.push("Missing General Error code".into());
            }
            if let Some(additional) = body.get(2).copied() {
                analysis.push(
                    "Additional code",
                    format!(
                        "0x{additional:02X} - {}",
                        additional_error_name(additional, request.as_ref())
                    ),
                );
            } else {
                analysis
                    .warnings
                    .push("Missing Additional Error code".into());
            }
            attach_request_context(&mut analysis, request.as_ref());
            return analysis;
        }

        match (service_code, request.as_ref().map(|request| request.kind)) {
            (0x4b, Some(RequestKind::AllocateControllerDevice)) => {
                set_service_identity(
                    &mut analysis,
                    service_code,
                    device_net_service_name(service_code),
                    true,
                );
                if let Some(format_byte) = body.get(1).copied() {
                    let format = MessageBodyFormat::from_value(format_byte & 0x0f);
                    analysis.push("Message body format", format.label());
                    if matches!(format, MessageBodyFormat::Reserved(_)) {
                        analysis
                            .warnings
                            .push("Reserved Message Body Format value".into());
                    } else if state_valid && response_matches_request {
                        self.body_formats.insert((message.bus, device_mac), format);
                    }
                    if format_byte & 0xf0 != 0 {
                        analysis.push("Reserved format bits", format!("0x{:X}", format_byte >> 4));
                    }
                } else {
                    analysis.warnings.push("Missing Message Body Format".into());
                }
            }
            (0x4c, Some(RequestKind::ReleaseControllerDevice { choice })) => {
                set_service_identity(
                    &mut analysis,
                    service_code,
                    device_net_service_name(service_code),
                    true,
                );
                if body.len() > 1 {
                    analysis.push("Unexpected response data", hex_bytes(&body[1..]));
                }
                if state_valid
                    && response_matches_request
                    && choice.is_some_and(|value| value & 1 != 0)
                {
                    self.body_formats.remove(&(message.bus, device_mac));
                }
            }
            (0x4d, None) if is_valid_broadcast(message, header, device_mac, body) => {
                set_service_identity(
                    &mut analysis,
                    service_code,
                    device_net_service_name(service_code),
                    true,
                );
                mark_broadcast_source_header(&mut analysis, header, device_mac);
                decode_heartbeat(body, &mut analysis);
            }
            (0x4e, None) if is_valid_broadcast(message, header, device_mac, body) => {
                set_service_identity(
                    &mut analysis,
                    service_code,
                    device_net_service_name(service_code),
                    true,
                );
                mark_broadcast_source_header(&mut analysis, header, device_mac);
                decode_shutdown(body, &mut analysis);
            }
            _ => append_service_details(
                &mut analysis,
                decode_common_service_data(service_code, true, &body[1..], false),
            ),
        }
        if state_valid && response_matches_request {
            if let Some(request) = request.as_ref() {
                if service_code == 0x0e {
                    if let (Some(class_id), Some(instance_id), Some(attribute_id)) =
                        (request.class_id, request.instance_id, request.attribute_id)
                    {
                        append_attribute_decode(
                            &mut analysis,
                            mfc_explicit.decode_get_response(
                                DeviceKey {
                                    bus: message.bus,
                                    mac_id: device_mac,
                                },
                                class_id,
                                instance_id,
                                attribute_id,
                                &body[1..],
                            ),
                        );
                    }
                } else if service_code == 0x10 {
                    if let Some(pending) = request.pending_attribute_update.clone() {
                        mfc_explicit.commit(pending);
                    }
                }
            }
        }
        attach_request_context(&mut analysis, request.as_ref());
        if let Some(request) = request
            && request.service_code != service_code
        {
            analysis.warnings.push(format!(
                "Response service 0x{service_code:02X} does not match request service 0x{:02X}",
                request.service_code
            ));
        }
        analysis
    }
}

#[derive(Default)]
struct ParsedAddress {
    class_id: Option<u32>,
    instance_id: Option<u32>,
    attribute_id: Option<u32>,
    data_offset: usize,
}

fn parse_request_address(
    body: &[u8],
    format: Option<MessageBodyFormat>,
    analysis: &mut Group2Analysis,
) -> ParsedAddress {
    let mut parsed = ParsedAddress {
        data_offset: 1,
        ..Default::default()
    };
    let Some(format) = format else {
        return parsed;
    };

    match format {
        MessageBodyFormat::DeviceNet8_8 => {
            if body.len() >= 3 {
                parsed.class_id = Some(body[1] as u32);
                parsed.instance_id = Some(body[2] as u32);
                parsed.data_offset = 3;
            }
        }
        MessageBodyFormat::DeviceNet8_16 => {
            if body.len() >= 4 {
                parsed.class_id = Some(body[1] as u32);
                parsed.instance_id = Some(u16::from_le_bytes([body[2], body[3]]) as u32);
                parsed.data_offset = 4;
            }
        }
        MessageBodyFormat::DeviceNet16_16 => {
            if body.len() >= 5 {
                parsed.class_id = Some(u16::from_le_bytes([body[1], body[2]]) as u32);
                parsed.instance_id = Some(u16::from_le_bytes([body[3], body[4]]) as u32);
                parsed.data_offset = 5;
            }
        }
        MessageBodyFormat::DeviceNet16_8 => {
            if body.len() >= 4 {
                parsed.class_id = Some(u16::from_le_bytes([body[1], body[2]]) as u32);
                parsed.instance_id = Some(body[3] as u32);
                parsed.data_offset = 4;
            }
        }
        MessageBodyFormat::CipPath => {
            if let Some(words) = body.get(1).copied() {
                let path_bytes = words as usize * 2;
                let available = body.len().saturating_sub(2);
                let used = path_bytes.min(available);
                analysis.push("Path size", format!("{words} words / {path_bytes} bytes"));
                let path = &body[2..2 + used];
                analysis.push("Packed EPATH", hex_bytes(path));
                let logical_path = decode_logical_path(path);
                parsed.class_id = logical_path.class_id;
                parsed.instance_id = logical_path.instance_id;
                parsed.attribute_id = logical_path.attribute_id;
                if let Some(display) = logical_path.display {
                    analysis.push("Logical path", display);
                }
                parsed.data_offset = 2 + used;
                if used != path_bytes {
                    analysis.warnings.push(format!(
                        "Packed EPATH is truncated: expected {path_bytes} bytes, found {available}"
                    ));
                }
            }
        }
        MessageBodyFormat::Reserved(value) => {
            analysis
                .warnings
                .push(format!("Reserved Message Body Format {value}"));
        }
    }

    if let Some(class_id) = parsed.class_id {
        analysis.push("Class ID", format_u32(class_id));
    }
    if let Some(instance_id) = parsed.instance_id {
        analysis.push("Instance ID", format_u32(instance_id));
    }
    if let Some(attribute_id) = parsed.attribute_id {
        analysis.push("Attribute ID", format_u32(attribute_id));
    }
    if parsed.class_id.is_none()
        && !matches!(
            format,
            MessageBodyFormat::CipPath | MessageBodyFormat::Reserved(_)
        )
    {
        analysis.warnings.push("Object address is truncated".into());
        parsed.data_offset = body.len();
    }
    parsed
}

fn decode_allocation_request(data: &[u8], require_explicit: bool, analysis: &mut Group2Analysis) {
    let Some(choice) = data.first().copied() else {
        analysis.warnings.push("Missing Allocation Choice".into());
        return;
    };
    analysis.push("Allocation Choice", choice_description(choice, true));
    validate_choice(choice, true, analysis);
    if require_explicit && choice & 0x01 == 0 {
        analysis
            .warnings
            .push("Group 2 Only allocation must include the Explicit Messaging connection".into());
    }
    if let Some(allocator) = data.get(1).copied() {
        analysis.push("Allocator MAC ID", format!("{}", allocator & 0x3f));
        if allocator & 0xc0 != 0 {
            analysis
                .warnings
                .push("Allocator MAC ID reserved bits 7-6 must be zero".into());
        }
    } else {
        analysis.warnings.push("Missing Allocator MAC ID".into());
    }
    if data.len() > 2 {
        analysis.push("Trailing data", hex_bytes(&data[2..]));
    }
}

fn decode_release_request(data: &[u8], analysis: &mut Group2Analysis) {
    let Some(choice) = data.first().copied() else {
        analysis.warnings.push("Missing Release Choice".into());
        return;
    };
    analysis.push("Release Choice", choice_description(choice, false));
    validate_choice(choice, false, analysis);
    if data.len() > 1 {
        analysis.push("Trailing data", hex_bytes(&data[1..]));
    }
}

fn validate_choice(choice: u8, allocation: bool, analysis: &mut Group2Analysis) {
    if choice == 0 {
        analysis.warnings.push("Choice value 0 is invalid".into());
    }
    if choice & 0x80 != 0 {
        analysis
            .warnings
            .push("Reserved choice bit 7 is set".into());
    }
    if allocation && choice & 0x30 == 0x30 {
        analysis
            .warnings
            .push("Change of State and Cyclic are mutually exclusive".into());
    }
    if allocation && choice & 0x40 != 0 && choice & 0x30 == 0 {
        analysis
            .warnings
            .push("Acknowledge Suppression requires Change of State or Cyclic".into());
    }
    if !allocation && choice & 0x40 != 0 {
        analysis
            .warnings
            .push("Release Choice bit 6 must be zero".into());
    }
}

fn choice_description(choice: u8, allocation: bool) -> String {
    let labels = [
        "Explicit Messaging",
        "Polled",
        "Bit-Strobed",
        "Multicast Poll",
        "Change of State",
        "Cyclic",
        if allocation {
            "Acknowledge Suppression"
        } else {
            "Reserved/Note"
        },
        "Reserved",
    ];
    let selected = labels
        .iter()
        .enumerate()
        .filter(|(bit, _)| choice & (1 << bit) != 0)
        .map(|(_, label)| *label)
        .collect::<Vec<_>>();
    format!(
        "0x{choice:02X} [{}]",
        if selected.is_empty() {
            "none".into()
        } else {
            selected.join(", ")
        }
    )
}

fn decode_heartbeat(body: &[u8], analysis: &mut Group2Analysis) {
    analysis.title = "Device Heartbeat".into();
    if body.len() < 7 {
        analysis
            .warnings
            .push("Heartbeat payload is truncated".into());
        return;
    }
    analysis.push(
        "Identity instance",
        format_u16(u16::from_le_bytes([body[1], body[2]])),
    );
    analysis.push(
        "Device state",
        format!("0x{:02X} - {}", body[3], device_state_name(body[3])),
    );
    let flags = body[4];
    if flags & 0xf8 != 0 {
        analysis
            .warnings
            .push("Heartbeat Fault Flags bits 7-3 must be zero".into());
    }
    analysis.push(
        "Fault flags",
        format!(
            "0x{flags:02X} [DF={}, UF={}, SF={}, EV={}]",
            bit(flags, 0),
            bit(flags, 1),
            bit(flags, 2),
            bit(flags, 3)
        ),
    );
    analysis.push(
        "Configuration consistency",
        format_u16(u16::from_le_bytes([body[5], body[6]])),
    );
}

fn is_valid_broadcast(message: &TraceMessage, header: u8, device_mac: u8, body: &[u8]) -> bool {
    header & 0x80 == 0 && header & 0x3f == device_mac && body.len() == 7 && message.data.len() == 8
}

fn decode_shutdown(body: &[u8], analysis: &mut Group2Analysis) {
    analysis.title = "Device Shutdown".into();
    if body.len() < 7 {
        analysis
            .warnings
            .push("Shutdown payload is truncated".into());
        return;
    }
    analysis.push(
        "Responsible Class ID",
        format_u16(u16::from_le_bytes([body[1], body[2]])),
    );
    analysis.push(
        "Responsible Instance ID",
        format_u16(u16::from_le_bytes([body[3], body[4]])),
    );
    let code = u16::from_le_bytes([body[5], body[6]]);
    let range = match code {
        0x0000..=0x01ff => "Open",
        0x0200..=0x02ff => "Vendor-specific",
        0x0300..=0x04ff => "Object-class-specific",
        _ => "Reserved by DeviceNet",
    };
    analysis.push("Shutdown code", format!("0x{code:04X} - {range}"));
}

fn attach_request_context(analysis: &mut Group2Analysis, request: Option<&RequestContext>) {
    let Some(request) = request else {
        if !matches!(
            analysis.title.as_str(),
            "Device Heartbeat" | "Device Shutdown"
        ) {
            analysis
                .warnings
                .push("Matching request was not found in the loaded trace".into());
        }
        return;
    };
    analysis.push("Request frame", format!("#{}", request.message_number));
    analysis.push_service(
        "Request service",
        request.service_code,
        format!("0x{:02X} - {}", request.service_code, request.service_name),
    );
    if let Some(class_id) = request.class_id {
        analysis.push("Class ID", format_u32(class_id));
    }
    if let Some(instance_id) = request.instance_id {
        analysis.push("Instance ID", format_u32(instance_id));
    }
    if let Some(attribute_id) = request.attribute_id {
        analysis.push("Attribute ID", format_u32(attribute_id));
    }
}

fn append_attribute_decode(
    analysis: &mut Group2Analysis,
    decoded: AttributeDecode,
) -> Option<PendingAttributeUpdate> {
    let AttributeDecode {
        fields,
        warnings,
        pending_update,
    } = decoded;
    analysis.fields.extend(fields);
    analysis.warnings.extend(warnings);
    pending_update
}

fn function_for_message_id(message_id: u8) -> Group2Function {
    match message_id {
        0 => Group2Function::IoBitStrobeCommand,
        1 => Group2Function::IoMulticastPollCommand,
        2 => Group2Function::ChangeOfStateOrCyclicAck,
        3 => Group2Function::ExplicitOrUnconnectedResponse,
        4 => Group2Function::ExplicitRequest,
        5 => Group2Function::IoPollOrChangeOfStateOrCyclic,
        6 => Group2Function::UnconnectedExplicitRequest,
        7 => Group2Function::DuplicateMacIdCheck,
        _ => unreachable!(),
    }
}

fn mac_role(message_id: u8) -> &'static str {
    match message_id {
        0 | 3 => "Source MAC ID",
        1 => "Multicast MAC ID",
        _ => "Destination MAC ID",
    }
}

fn device_net_service_name(code: u8) -> &'static str {
    match code {
        0x4b => "Allocate_Controller/Device_Connection_Set",
        0x4c => "Release_Controller/Device_Connection_Set",
        0x4d => "Device_Heartbeat",
        0x4e => "Device_Shutdown",
        _ => service_name(code),
    }
}

fn set_service_identity(
    analysis: &mut Group2Analysis,
    code: u8,
    name: &'static str,
    is_response: bool,
) {
    analysis.title = format!(
        "{name} {}",
        if is_response { "Response" } else { "Request" }
    );
    if let Some(field) = analysis
        .fields
        .iter_mut()
        .find(|field| field.name == "Service")
    {
        field.value = format!("0x{code:02X} - {name}");
        field.service_code = Some(code);
    }
}

fn mark_broadcast_source_header(
    analysis: &mut Group2Analysis,
    header: u8,
    identifier_source_mac: u8,
) {
    let header_source_mac = header & 0x3f;
    if let Some(field) = analysis
        .fields
        .iter_mut()
        .find(|field| field.name == "Destination MAC ID")
    {
        field.name = "Header Source MAC ID".into();
    }
    if header_source_mac != identifier_source_mac {
        analysis.warnings.push(format!(
            "Broadcast header Source MAC ID {header_source_mac} does not match Identifier Source MAC ID {identifier_source_mac}"
        ));
    }
    if header & 0x80 != 0 {
        analysis
            .warnings
            .push("Heartbeat and Shutdown messages shall not be fragmented".into());
    }
}

fn append_service_details(analysis: &mut Group2Analysis, details: crate::services::ServiceDetails) {
    for (name, value) in details.fields {
        analysis.push(
            if matches!(name.as_str(), "Attribute data" | "Attribute values") {
                "Service data".to_owned()
            } else {
                name
            },
            value,
        );
    }
    analysis.warnings.extend(details.warnings);
}

fn additional_error_name(code: u8, request: Option<&RequestContext>) -> &'static str {
    if code == 0xff {
        return "No additional information";
    }
    if code == 0x03 && request.is_some_and(|request| request.message_id == 6) {
        return "Invalid service on Group 2 Only unconnected port";
    }
    let is_devicenet_management = request.is_some_and(|request| {
        matches!(
            request.kind,
            RequestKind::AllocateControllerDevice | RequestKind::ReleaseControllerDevice { .. }
        )
    });
    if !is_devicenet_management {
        return "Object/service-specific additional status";
    }
    match code {
        0x01 => "Allocation conflict",
        0x02 => "Invalid Allocation/Release Choice",
        0x03 => "Invalid service on Group 2 Only unconnected port",
        0x04 => "Required connection resource unavailable",
        _ => "DeviceNet Object-specific additional status",
    }
}

fn device_state_name(value: u8) -> &'static str {
    match value {
        0 => "Nonexistent",
        1 => "Device self-testing",
        2 => "Standby",
        3 => "Operational",
        4 => "Major recoverable fault",
        5 => "Major unrecoverable fault",
        _ => "Vendor-specific/reserved",
    }
}

fn bit(value: u8, position: u8) -> u8 {
    (value >> position) & 1
}

fn hex_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(none)".into();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_u16(value: u16) -> String {
    format!("0x{value:04X} ({value})")
}

fn format_u32(value: u32) -> String {
    format!("0x{value:X} ({value})")
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    fn message(number: u64, id: u32, data: &[u8]) -> TraceMessage {
        TraceMessage {
            number,
            time_offset_ms: Some(number as f64),
            bus: 1,
            direction: if id & 7 == 3 { "Rx" } else { "Tx" }.into(),
            identifier: id,
            dlc: data.len(),
            data: data.to_vec(),
        }
    }

    fn message_on_bus(number: u64, bus: u32, id: u32, data: &[u8]) -> TraceMessage {
        TraceMessage {
            bus,
            ..message(number, id, data)
        }
    }

    fn group2_id(mac: u32, message_id: u32) -> u32 {
        0x400 | (mac << 3) | message_id
    }

    #[test]
    fn covers_all_eight_group2_message_functions() {
        let messages = vec![
            message(1, group2_id(1, 0), &[1]),
            message(2, group2_id(1, 1), &[2]),
            message(3, group2_id(1, 2), &[]),
            message(4, group2_id(1, 3), &[0, 0x8e, 1]),
            message(5, group2_id(1, 4), &[0, 0x0e, 1, 1, 1]),
            message(6, group2_id(1, 5), &[3]),
            message(7, group2_id(1, 6), &[2, 0x4c, 3, 1, 1]),
            message(8, group2_id(1, 7), &[0, 5, 0, 4, 3, 2, 1]),
        ];
        let decoded = decode_group2_trace(&messages);
        let functions = (1..=8)
            .map(|number| decoded[&number].function)
            .collect::<Vec<_>>();
        assert_eq!(
            functions,
            vec![
                Group2Function::IoBitStrobeCommand,
                Group2Function::IoMulticastPollCommand,
                Group2Function::ChangeOfStateOrCyclicAck,
                Group2Function::ExplicitOrUnconnectedResponse,
                Group2Function::ExplicitRequest,
                Group2Function::IoPollOrChangeOfStateOrCyclic,
                Group2Function::UnconnectedExplicitRequest,
                Group2Function::DuplicateMacIdCheck,
            ]
        );
    }

    #[test]
    fn maps_section_3_7_group2_identifiers_and_mac_roles() {
        let messages = (0_u32..=7)
            .map(|message_id| message(u64::from(message_id) + 1, group2_id(21, message_id), &[0]))
            .collect::<Vec<_>>();
        let decoded = decode_group2_trace_ordered(&messages);
        let roles = [
            "Source MAC ID",
            "Multicast MAC ID",
            "Destination MAC ID",
            "Source MAC ID",
            "Destination MAC ID",
            "Destination MAC ID",
            "Destination MAC ID",
            "Destination MAC ID",
        ];
        for (message_id, expected_role) in roles.into_iter().enumerate() {
            let analysis = decoded[message_id].as_ref().unwrap();
            assert_eq!(messages[message_id].identifier, 0x4a8 + message_id as u32);
            assert_eq!(analysis.field(expected_role), Some("21"));
        }

        assert_eq!(group2_id(0, 0), 0x400);
        assert_eq!(group2_id(63, 7), 0x5ff);
    }

    #[test]
    fn tracks_allocation_format_and_correlates_explicit_response() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 7, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message(3, group2_id(3, 4), &[0x0a, 0x0e, 5, 2, 9]),
            message(4, group2_id(3, 3), &[0x0a, 0x8e, 0x0a, 0]),
        ];
        let decoded = decode_group2_trace(&messages);

        assert!(
            decoded[&1]
                .field("Allocation Choice")
                .unwrap()
                .contains("Explicit Messaging")
        );
        assert_eq!(
            decoded[&2].field("Message body format"),
            Some("DeviceNet 8/8")
        );
        assert_eq!(decoded[&3].field("Class ID"), Some("0x5 (5)"));
        assert_eq!(decoded[&3].field("Instance ID"), Some("0x2 (2)"));
        assert_eq!(decoded[&3].field("Attribute ID"), Some("0x9 (9)"));
        assert_eq!(decoded[&4].field("Request frame"), Some("#3"));
        assert_eq!(decoded[&4].field("Attribute ID"), Some("0x9 (9)"));
        assert_eq!(decoded[&4].field("Service data"), Some("0A 00"));
    }

    #[test]
    fn decodes_correlated_identity_vendor_information() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message(3, group2_id(3, 4), &[0x0a, 0x0e, 1, 1, 1]),
            message(4, group2_id(3, 3), &[0x0a, 0x8e, 0x15, 0x07]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);
        let response = decoded[3].as_ref().unwrap();

        assert_eq!(
            decoded[2].as_ref().unwrap().field("Read target"),
            Some("Identity instance 1 / Vendor ID")
        );
        assert_eq!(response.field("Service data"), Some("15 07"));
        assert_eq!(
            response.field("Read target"),
            Some("Identity instance 1 / Vendor ID")
        );
        assert!(
            response
                .field("Vendor ID")
                .is_some_and(|value| value.contains("BLUE DYNAMICS"))
        );
    }

    #[test]
    fn decodes_mbf4_attribute_from_reassembled_packed_epath() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 4]),
            message(3, group2_id(3, 4), &[0x8a, 0x00, 0x0e, 3, 0x20, 1, 0x24, 1]),
            message(4, group2_id(3, 4), &[0x8a, 0x81, 0x30, 1]),
            message(5, group2_id(3, 3), &[0x0a, 0x8e, 0x15, 0x07]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);

        assert_eq!(
            decoded[3].as_ref().unwrap().field("Attribute ID"),
            Some("0x1 (1)")
        );
        assert!(
            decoded[4]
                .as_ref()
                .unwrap()
                .field("Vendor ID")
                .is_some_and(|value| value.contains("BLUE DYNAMICS"))
        );
    }

    #[test]
    fn applies_set_data_type_only_after_a_success_response() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message(3, group2_id(3, 4), &[0x0a, 0x0e, 0x31, 1, 3]),
            message(4, group2_id(3, 3), &[0x0a, 0x8e, 0xc3]),
            message(5, group2_id(3, 4), &[0x0a, 0x10, 0x31, 1, 3, 0xca]),
            message(6, group2_id(3, 3), &[0x0a, 0x94, 0x14, 0xff]),
            message(7, group2_id(3, 4), &[0x0a, 0x0e, 0x31, 1, 6]),
            message(8, group2_id(3, 3), &[0x0a, 0x8e, 7, 0]),
            message(9, group2_id(3, 4), &[0x0a, 0x10, 0x31, 1, 3, 0xca]),
            message(10, group2_id(3, 3), &[0x0a, 0x90]),
            message(11, group2_id(3, 4), &[0x0a, 0x0e, 0x31, 1, 6]),
            message(12, group2_id(3, 3), &[0x0a, 0x8e, 0, 0, 0x48, 0x41]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);

        assert_eq!(
            decoded[4].as_ref().unwrap().field("Write target"),
            Some("S-Analog Sensor instance 1 / Data type")
        );
        assert_eq!(decoded[7].as_ref().unwrap().field("Flow"), Some("7"));
        assert_eq!(decoded[11].as_ref().unwrap().field("Flow"), Some("12.5"));
    }

    #[test]
    fn keeps_first_pending_request_when_group2_xid_is_reused() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message(3, group2_id(3, 4), &[0x0a, 0x0e, 0x31, 1, 3]),
            message(4, group2_id(3, 3), &[0x0a, 0x8e, 0xc3]),
            message(5, group2_id(3, 4), &[0x0a, 0x10, 0x31, 1, 3, 0xca]),
            message(6, group2_id(3, 4), &[0x0a, 0x10, 0x31, 1, 3, 0xc3]),
            message(7, group2_id(3, 3), &[0x0a, 0x90]),
            message(8, group2_id(3, 4), &[0x0a, 0x0e, 0x31, 1, 6]),
            message(9, group2_id(3, 3), &[0x0a, 0x8e, 0x00, 0x00, 0x48, 0x41]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);

        let collision = decoded[5].as_ref().unwrap();
        assert!(collision.warnings.iter().any(|warning| {
            warning.contains("frame #5")
                && warning.contains("still pending")
                && warning.contains("not stored")
        }));
        assert_eq!(
            decoded[6].as_ref().unwrap().field("Request frame"),
            Some("#5")
        );
        assert_eq!(decoded[8].as_ref().unwrap().field("Flow"), Some("12.5"));
    }

    #[test]
    fn reassembles_explicit_fragments_and_decodes_acknowledgments() {
        let messages = vec![
            message(1, group2_id(1, 3), &[0x80, 0x00, 0x8e, 1, 2, 3, 4, 5]),
            message(2, group2_id(1, 4), &[0x80, 0xc0, 0]),
            message(3, group2_id(1, 3), &[0x80, 0x81, 6, 7]),
        ];
        let decoded = decode_group2_trace(&messages);
        assert_eq!(decoded[&2].title, "Explicit Fragment Acknowledge");
        assert_eq!(decoded[&2].field("Ack status"), Some("0x00 - Success"));
        assert!(decoded[&3].title.contains("Get_Attribute_Single Response"));
        assert_eq!(decoded[&3].field("Fragments"), Some("2"));
        assert_eq!(
            decoded[&3].field("Service data"),
            Some("01 02 03 04 05 06 07")
        );
    }

    #[test]
    fn rejects_io_single_fragment_marker_in_explicit_messages() {
        let decoded =
            decode_group2_trace_ordered(&[message(1, group2_id(1, 3), &[0x80, 0x3f, 0x8e, 0xaa])]);
        let analysis = decoded[0].as_ref().unwrap();

        assert_eq!(analysis.field("Service"), None);
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("first fragment count must be 0"))
        );
    }

    #[test]
    fn complete_messages_reset_fragment_reassembly() {
        let messages = vec![
            message(1, group2_id(1, 3), &[0x80, 0x00, 0x8e, 1]),
            message(2, group2_id(1, 3), &[0x00, 0x8e, 0xaa]),
            message(3, group2_id(1, 3), &[0x80, 0x81, 0xbb]),
            message(4, group2_id(2, 3), &[0x80, 0x00, 0x8e, 1]),
            message(5, group2_id(2, 3), &[0x80, 0x41, 2]),
            message(6, group2_id(2, 3), &[0x80, 0x81, 3]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);
        assert!(
            decoded[2]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("before a first"))
        );
        assert!(
            decoded[5]
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("Expected fragment count"))
        );
    }

    #[test]
    fn decodes_duplicate_mac_heartbeat_shutdown_and_error() {
        let messages = vec![
            message(1, group2_id(10, 7), &[0x80, 6, 0, 8, 7, 6, 5]),
            message(2, group2_id(3, 3), &[3, 0xcd, 1, 0, 3, 5, 0x34, 0x12]),
            message(3, group2_id(3, 3), &[3, 0xce, 4, 0, 2, 0, 1, 2]),
            message(4, group2_id(3, 3), &[0x0a, 0x94, 2, 3]),
        ];
        let decoded = decode_group2_trace(&messages);
        assert_eq!(decoded[&1].field("Message type"), Some("Response"));
        assert_eq!(decoded[&1].field("Vendor ID"), Some("0x0006 (6)"));
        assert_eq!(
            decoded[&1].field("Serial number"),
            Some("0x5060708 (84281096)")
        );
        assert_eq!(decoded[&2].title, "Device Heartbeat");
        assert_eq!(
            decoded[&2].field("Device state"),
            Some("0x03 - Operational")
        );
        assert_eq!(decoded[&3].title, "Device Shutdown");
        assert_eq!(
            decoded[&3].field("Shutdown code"),
            Some("0x0201 - Vendor-specific")
        );
        assert_eq!(
            decoded[&4].field("General error"),
            Some("0x02 - Resource unavailable")
        );
        assert_eq!(
            decoded[&4].field("Additional code"),
            Some("0x03 - Object/service-specific additional status")
        );
    }

    #[test]
    fn only_decodes_well_formed_unsolicited_broadcasts() {
        let messages = vec![
            // Header Source MAC 4 does not match Identifier Source MAC 3.
            message(1, group2_id(3, 3), &[4, 0xcd, 1, 0, 0, 0, 0, 0]),
            // EV (bit 3) shall be zero in a Device Heartbeat.
            message(2, group2_id(3, 3), &[3, 0xcd, 1, 0, 3, 8, 0, 0]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);
        assert_ne!(decoded[0].as_ref().unwrap().title, "Device Heartbeat");
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
    fn ordered_results_do_not_overwrite_duplicate_message_numbers() {
        let messages = vec![
            message(7, group2_id(1, 0), &[0x11]),
            message(7, group2_id(1, 5), &[0x22]),
        ];

        let decoded = decode_group2_trace_ordered(&messages);
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded[0].as_ref().unwrap().function,
            Group2Function::IoBitStrobeCommand
        );
        assert_eq!(
            decoded[1].as_ref().unwrap().function,
            Group2Function::IoPollOrChangeOfStateOrCyclic
        );
    }

    #[test]
    fn keeps_message_body_format_state_isolated_per_bus() {
        // Volume 3, 3-5.1 and 3-5.2: allocation selects the format for the
        // target DeviceNet connection. A trace may contain several CAN buses.
        let messages = vec![
            message_on_bus(1, 1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message_on_bus(2, 1, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message_on_bus(3, 2, group2_id(3, 4), &[0x0a, 0x0e, 5, 2, 9]),
            message_on_bus(4, 1, group2_id(3, 4), &[0x0a, 0x0e, 5, 2, 9]),
        ];

        let decoded = decode_group2_trace_ordered(&messages);
        assert_eq!(
            decoded[2].as_ref().unwrap().field("Message body format"),
            Some("Unknown (allocation response not seen)")
        );
        assert_eq!(
            decoded[3].as_ref().unwrap().field("Message body format"),
            Some("DeviceNet 8/8")
        );
    }

    #[test]
    fn keeps_object_specific_services_distinct_from_devicenet_management() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message(3, group2_id(3, 4), &[0x0a, 0x4b, 5, 2, 0xaa]),
            message(4, group2_id(3, 3), &[0x0a, 0xcb, 0xbb]),
        ];

        let decoded = decode_group2_trace_ordered(&messages);
        assert!(
            decoded[2]
                .as_ref()
                .unwrap()
                .title
                .contains("Object_Class_Specific_Service")
        );
        assert!(
            decoded[2]
                .as_ref()
                .unwrap()
                .field("Allocation Choice")
                .is_none()
        );
        assert!(
            decoded[3]
                .as_ref()
                .unwrap()
                .title
                .contains("Object_Class_Specific_Service")
        );
    }

    #[test]
    fn release_of_explicit_connection_clears_learned_body_format() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 0]),
            message(3, group2_id(3, 6), &[0x0a, 0x4c, 3, 1, 1]),
            message(4, group2_id(3, 3), &[0x0a, 0xcc]),
            message(5, group2_id(3, 4), &[0x0a, 0x0e, 5, 2, 9]),
        ];

        let decoded = decode_group2_trace_ordered(&messages);
        assert_eq!(
            decoded[4].as_ref().unwrap().field("Message body format"),
            Some("Unknown (allocation response not seen)")
        );
    }

    #[test]
    fn cip_path_management_request_updates_connection_state() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 1, 0x0a]),
            message(2, group2_id(3, 3), &[0x0a, 0xcb, 4]),
            message(3, group2_id(3, 4), &[0x0a, 0x4c, 2, 0x20, 3, 0x24, 1, 1]),
            message(4, group2_id(3, 3), &[0x0a, 0xcc]),
            message(5, group2_id(3, 4), &[0x0a, 0x0e, 5, 2, 9]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);
        let release = decoded[2].as_ref().unwrap();
        assert!(release.title.contains("Release_Controller"));
        assert_eq!(release.field("Class ID"), Some("0x3 (3)"));
        assert_eq!(release.field("Instance ID"), Some("0x1 (1)"));
        assert_eq!(
            decoded[4].as_ref().unwrap().field("Message body format"),
            Some("Unknown (allocation response not seen)")
        );
    }

    #[test]
    fn validates_group2_only_allocation_constraints() {
        let messages = vec![message(1, group2_id(3, 6), &[0x0a, 0x4b, 3, 1, 2, 0xca])];
        let decoded = decode_group2_trace_ordered(&messages);
        let analysis = decoded[0].as_ref().unwrap();
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("must include"))
        );
        assert!(
            analysis
                .warnings
                .iter()
                .any(|warning| warning.contains("reserved bits"))
        );
        assert_eq!(analysis.field("Allocator MAC ID"), Some("10"));
    }

    #[test]
    fn labels_group2_only_invalid_service_error_from_request_context() {
        let messages = vec![
            message(1, group2_id(3, 6), &[0x0a, 0x0e, 3, 1, 1]),
            message(2, group2_id(3, 3), &[0x0a, 0x94, 2, 3]),
            message(3, group2_id(3, 3), &[0x0b, 0x94, 2, 0xff]),
        ];
        let decoded = decode_group2_trace_ordered(&messages);
        assert_eq!(
            decoded[1].as_ref().unwrap().field("Additional code"),
            Some("0x03 - Invalid service on Group 2 Only unconnected port")
        );
        assert_eq!(
            decoded[2].as_ref().unwrap().field("Additional code"),
            Some("0xFF - No additional information")
        );
    }

    #[test]
    fn does_not_invent_an_attribute_when_body_format_is_unknown() {
        let messages = vec![message(1, group2_id(3, 4), &[0x0a, 0x0e, 5, 2, 9])];
        let decoded = decode_group2_trace_ordered(&messages);
        let analysis = decoded[0].as_ref().unwrap();
        assert_eq!(
            analysis.field("Message body format"),
            Some("Unknown (allocation response not seen)")
        );
        assert_eq!(analysis.field("Attribute ID"), None);
        assert_eq!(analysis.field("Service data"), Some("05 02 09"));
    }
}
