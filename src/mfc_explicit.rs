//! Profile-scoped Explicit attribute decoding for MFC and EMFC devices.
//!
//! Volume 3 defines the wire envelope and requires successful responses to be
//! correlated with their requests. Volume 1 and the supplied industry object
//! table define the object attributes, elementary types, units, and access rules.
//! Industry-object interpretation is independent of the Identity vendor.

use std::collections::HashMap;

use crate::{
    AnalysisSubject, DecodedField, DecodedFieldRole, ExplicitOperation, path::decode_logical_path,
    profile::explicit_attribute,
};

const BLUE_DYNAMICS_VENDOR_ID: u16 = 1813;
const TYPE_BOOL: u8 = 0xc1;
const TYPE_INT: u8 = 0xc3;
const TYPE_USINT: u8 = 0xc6;
const TYPE_UINT: u8 = 0xc7;
const TYPE_UDINT: u8 = 0xc8;
const TYPE_ULINT: u8 = 0xc9;
const TYPE_REAL: u8 = 0xca;
const TYPE_BYTE: u8 = 0xd1;

const UNIT_COUNTS: u16 = 0x1001;
const UNIT_PERCENT: u16 = 0x1007;
const UNIT_CELSIUS: u16 = 0x1200;
const UNIT_KELVIN: u16 = 0x1202;
const UNIT_PSI: u16 = 0x1300;
const UNIT_TORR: u16 = 0x1301;
const UNIT_KPA: u16 = 0x130a;
const UNIT_SCCM: u16 = 0x1400;
const UNIT_SLM: u16 = 0x1401;

const SENSOR_FLOW_UNITS: &[u16] = &[UNIT_COUNTS, UNIT_SCCM, UNIT_SLM];
const SENSOR_PRESSURE_UNITS: &[u16] = &[UNIT_COUNTS, UNIT_PSI, UNIT_TORR, UNIT_KPA];
const SENSOR_TEMPERATURE_UNITS: &[u16] = &[UNIT_COUNTS, UNIT_CELSIUS, UNIT_KELVIN];
const ACTUATOR_CONTROLLER_UNITS: &[u16] = &[UNIT_COUNTS, UNIT_PERCENT];
const FLOW_CONFIGURED_FULL_SCALE_UNITS: &[u16] = &[UNIT_SCCM, UNIT_SLM];
const PRESSURE_CONFIGURED_FULL_SCALE_UNITS: &[u16] = &[UNIT_PSI, UNIT_TORR, UNIT_KPA];
const TEMPERATURE_CONFIGURED_FULL_SCALE_UNITS: &[u16] = &[UNIT_CELSIUS, UNIT_KELVIN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DeviceKey {
    pub(crate) bus: u32,
    pub(crate) mac_id: u8,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingAttributeUpdate {
    key: DeviceKey,
    mutations: Vec<StateMutation>,
}

#[derive(Debug, Default)]
pub(crate) struct AttributeDecode {
    pub(crate) fields: Vec<DecodedField>,
    pub(crate) warnings: Vec<String>,
    pub(crate) pending_update: Option<PendingAttributeUpdate>,
    pub(crate) subject: Option<AnalysisSubject>,
}

#[derive(Debug, Default)]
pub(crate) struct MfcExplicitState {
    devices: HashMap<DeviceKey, DeviceState>,
}

#[derive(Debug, Clone, Default)]
struct DeviceState {
    profile: Option<String>,
    numeric: HashMap<(u32, u32), NumericContext>,
}

impl DeviceState {
    fn numeric(&self, class_id: u32, instance_id: u32) -> NumericContext {
        self.numeric
            .get(&(class_id, instance_id))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default)]
struct NumericContext {
    data_type: Option<NumericType>,
    units: Option<u16>,
    numeric_full_scale: Option<f64>,
    configured_full_scale: Option<ConfiguredFullScale>,
}

#[derive(Debug, Clone, Copy)]
struct ConfiguredFullScale {
    amount: f64,
    unit: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumericType {
    Int,
    Real,
}

impl NumericType {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            TYPE_INT => Some(Self::Int),
            TYPE_REAL => Some(Self::Real),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Int => TYPE_INT,
            Self::Real => TYPE_REAL,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Int => "INT",
            Self::Real => "REAL",
        }
    }
}

#[derive(Debug, Clone)]
enum StateMutation {
    Profile(String),
    DataType {
        class_id: u32,
        instance_id: u32,
        value: NumericType,
    },
    ClearDataType {
        class_id: u32,
        instance_id: u32,
    },
    Units {
        class_id: u32,
        instance_id: u32,
        value: u16,
    },
    ClearUnits {
        class_id: u32,
        instance_id: u32,
    },
    NumericFullScale {
        class_id: u32,
        instance_id: u32,
        value: f64,
    },
    ClearNumericFullScale {
        class_id: u32,
        instance_id: u32,
    },
    ConfiguredFullScale {
        class_id: u32,
        instance_id: u32,
        value: ConfiguredFullScale,
    },
    ClearConfiguredFullScale {
        class_id: u32,
        instance_id: u32,
    },
}

#[derive(Debug, Default)]
struct InternalDecode {
    fields: Vec<DecodedField>,
    warnings: Vec<String>,
    mutations: Vec<StateMutation>,
}

impl MfcExplicitState {
    /// Describe a Get_Attribute_Single target before response data is available.
    ///
    /// Successful responses do not repeat their object path, so callers should
    /// retain the same request context for the later typed value decode.
    pub(crate) fn describe_get_request(
        &self,
        class_id: u32,
        instance_id: u32,
        attribute_id: u32,
    ) -> AttributeDecode {
        let metadata = explicit_attribute(class_id, instance_id, attribute_id);
        AttributeDecode {
            fields: request_target_field(class_id, instance_id, attribute_id, false)
                .into_iter()
                .collect(),
            subject: metadata.map(|metadata| {
                AnalysisSubject::Explicit(metadata.subject(ExplicitOperation::Read))
            }),
            ..AttributeDecode::default()
        }
    }

    pub(crate) fn decode_get_response(
        &mut self,
        key: DeviceKey,
        class_id: u32,
        instance_id: u32,
        attribute_id: u32,
        data: &[u8],
    ) -> AttributeDecode {
        let state = self.devices.get(&key).cloned().unwrap_or_default();
        let mut decoded =
            decode_attribute(&state, class_id, instance_id, attribute_id, data, false);
        if let Some(target) = request_target_field(class_id, instance_id, attribute_id, false) {
            decoded.fields.insert(0, target);
        }
        if !decoded.mutations.is_empty() {
            let device = self.devices.entry(key).or_default();
            apply_mutations(device, decoded.mutations.iter().cloned());
        }
        AttributeDecode {
            fields: decoded.fields,
            warnings: decoded.warnings,
            pending_update: None,
            subject: explicit_attribute(class_id, instance_id, attribute_id).map(|metadata| {
                AnalysisSubject::Explicit(metadata.subject(ExplicitOperation::Read))
            }),
        }
    }

    pub(crate) fn decode_set_request(
        &self,
        key: DeviceKey,
        class_id: u32,
        instance_id: u32,
        attribute_id: u32,
        data: &[u8],
    ) -> AttributeDecode {
        let state = self.devices.get(&key).cloned().unwrap_or_default();
        let mut decoded = decode_attribute(&state, class_id, instance_id, attribute_id, data, true);
        if let Some(target) = request_target_field(class_id, instance_id, attribute_id, true) {
            decoded.fields.insert(0, target);
        }
        let pending_update = (!decoded.mutations.is_empty()).then(|| PendingAttributeUpdate {
            key,
            mutations: std::mem::take(&mut decoded.mutations),
        });
        AttributeDecode {
            fields: decoded.fields,
            warnings: decoded.warnings,
            pending_update,
            subject: explicit_attribute(class_id, instance_id, attribute_id).map(|metadata| {
                AnalysisSubject::Explicit(metadata.subject(ExplicitOperation::Write))
            }),
        }
    }

    pub(crate) fn commit(&mut self, pending: PendingAttributeUpdate) {
        let device = self.devices.entry(pending.key).or_default();
        apply_mutations(device, pending.mutations);
    }
}

fn apply_mutations(device: &mut DeviceState, mutations: impl IntoIterator<Item = StateMutation>) {
    for mutation in mutations {
        match mutation {
            StateMutation::Profile(value) => device.profile = Some(value),
            StateMutation::DataType {
                class_id,
                instance_id,
                value,
            } => {
                let numeric = device.numeric.entry((class_id, instance_id)).or_default();
                if numeric.data_type != Some(value) {
                    numeric.numeric_full_scale = None;
                }
                numeric.data_type = Some(value);
            }
            StateMutation::ClearDataType {
                class_id,
                instance_id,
            } => {
                let numeric = device.numeric.entry((class_id, instance_id)).or_default();
                numeric.data_type = None;
                numeric.numeric_full_scale = None;
            }
            StateMutation::Units {
                class_id,
                instance_id,
                value,
            } => {
                let numeric = device.numeric.entry((class_id, instance_id)).or_default();
                if numeric.units != Some(value) {
                    numeric.numeric_full_scale = None;
                }
                numeric.units = Some(value);
            }
            StateMutation::ClearUnits {
                class_id,
                instance_id,
            } => {
                let numeric = device.numeric.entry((class_id, instance_id)).or_default();
                numeric.units = None;
                numeric.numeric_full_scale = None;
            }
            StateMutation::NumericFullScale {
                class_id,
                instance_id,
                value,
            } => {
                device
                    .numeric
                    .entry((class_id, instance_id))
                    .or_default()
                    .numeric_full_scale = Some(value);
            }
            StateMutation::ClearNumericFullScale {
                class_id,
                instance_id,
            } => {
                device
                    .numeric
                    .entry((class_id, instance_id))
                    .or_default()
                    .numeric_full_scale = None;
            }
            StateMutation::ConfiguredFullScale {
                class_id,
                instance_id,
                value,
            } => {
                device
                    .numeric
                    .entry((class_id, instance_id))
                    .or_default()
                    .configured_full_scale = Some(value);
            }
            StateMutation::ClearConfiguredFullScale {
                class_id,
                instance_id,
            } => {
                device
                    .numeric
                    .entry((class_id, instance_id))
                    .or_default()
                    .configured_full_scale = None;
            }
        }
    }
}

fn decode_attribute(
    state: &DeviceState,
    class_id: u32,
    instance_id: u32,
    attribute_id: u32,
    data: &[u8],
    is_set: bool,
) -> InternalDecode {
    let mut decoded = match (class_id, instance_id) {
        (0x01, 1) => decode_identity(attribute_id, data),
        (0x03, 1) => decode_devicenet(attribute_id, data),
        (0x05, 1 | 2) => decode_connection(instance_id, attribute_id, data),
        (0x30, 1) => decode_supervisor(state, attribute_id, data),
        (0x31, 1..=3) => decode_sensor(state, instance_id, attribute_id, data),
        (0x32, 1) => decode_actuator(state, attribute_id, data),
        (0x33, 1) => decode_controller(state, attribute_id, data),
        (0x34, 1..=5) => decode_gas_calibration(instance_id, attribute_id, data),
        _ => InternalDecode::default(),
    };

    if is_set
        && explicit_attribute(class_id, instance_id, attribute_id).is_some()
        && !explicit_attribute(class_id, instance_id, attribute_id)
            .is_some_and(|metadata| metadata.writable)
    {
        decoded.mutations.clear();
        let target = explicit_attribute(class_id, instance_id, attribute_id)
            .expect("table target was checked above")
            .target_label();
        decoded.warnings.push(format!(
            "Set_Attribute_Single targets read-only {}; the supplied value was decoded for display, but no decoder context will be updated",
            target
        ));
    }
    decoded
}

fn request_target_field(
    class_id: u32,
    instance_id: u32,
    attribute_id: u32,
    is_write: bool,
) -> Option<DecodedField> {
    let target = explicit_attribute(class_id, instance_id, attribute_id)?.target_label();
    Some(DecodedField::target(
        if is_write {
            "Write target"
        } else {
            "Read target"
        },
        target,
        if is_write {
            "Set_Attribute_Single writes the supplied value to this table-defined attribute."
        } else {
            "Get_Attribute_Single reads this table-defined attribute; the correlated response carries its value."
        },
    ))
}

fn decode_identity(attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    match attribute_id {
        1 => {
            if let Some(value) = exact_u16(data, "Identity Vendor ID", &mut out.warnings) {
                let vendor = if value == BLUE_DYNAMICS_VENDOR_ID {
                    "BLUE DYNAMICS"
                } else {
                    "Unknown vendor"
                };
                out.fields.push(detail(
                    "Vendor ID",
                    format!("{value} (0x{value:04X}) - {vendor}"),
                    None,
                    "CIP Identity Object attribute 1. The known vendor name is display metadata only and does not select industry-object semantics.",
                ));
            }
        }
        2 => fixed_u16_field(
            &mut out,
            data,
            "Device type",
            |value| {
                if value == 26 {
                    format!("{value} - Mass Flow Controller")
                } else {
                    value.to_string()
                }
            },
            None,
            "CIP Identity Object product type; DeviceNet profile type 26 is Mass Flow Controller.",
        ),
        3 => fixed_u16_field(
            &mut out,
            data,
            "Product code",
            |value| format!("{value} (0x{value:04X})"),
            None,
            "CIP Identity Object product code assigned by the vendor.",
        ),
        4 => {
            if exact_len(data, 2, "Identity revision", &mut out.warnings) {
                out.fields.push(detail(
                    "Revision",
                    format!("{}.{}", data[0], data[1]),
                    None,
                    "CIP Identity revision structure: USINT major followed by USINT minor.",
                ));
            }
        }
        5 => fixed_u16_field(
            &mut out,
            data,
            "Identity status",
            |value| format!("0x{value:04X} - {}", identity_status(value)),
            None,
            "CIP Identity status WORD with Owned, Configured, and recoverable/unrecoverable fault bits.",
        ),
        6 => fixed_u32_field(
            &mut out,
            data,
            "Serial number",
            |value| format!("{value} (0x{value:08X})"),
            None,
            "CIP Identity Object UDINT serial number.",
        ),
        7 => short_string_field(
            &mut out,
            data,
            "Product name",
            "CIP Identity Object SHORT_STRING product name.",
            None,
        ),
        8 => fixed_u8_field(
            &mut out,
            data,
            "Identity state",
            |value| value.to_string(),
            None,
            "Optional CIP Identity state USINT.",
        ),
        9 => fixed_u16_field(
            &mut out,
            data,
            "Configuration consistency value",
            |value| format!("{value} (0x{value:04X})"),
            None,
            "Optional CIP Identity configuration consistency UINT.",
        ),
        10 => fixed_u8_field(
            &mut out,
            data,
            "Heartbeat interval",
            |value| value.to_string(),
            Some("s"),
            "Optional CIP Identity heartbeat interval USINT.",
        ),
        _ => {}
    }
    out
}

fn decode_supervisor(state: &DeviceState, attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    match attribute_id {
        1 => fixed_u8_field(
            &mut out,
            data,
            "Number of attributes",
            |value| value.to_string(),
            None,
            "S-Device Supervisor attribute count (USINT).",
        ),
        2 => attribute_list_field(&mut out, data),
        3..=10 => {
            let (name, description) = match attribute_id {
                3 => (
                    "Device type",
                    "Profile device type such as MFC, MFM, EMFC, or EMFM.",
                ),
                4 => (
                    "SEMI standard revision",
                    "SEMI standard revision SHORT_STRING.",
                ),
                5 => (
                    "Manufacturer name",
                    "Manufacturer information returned by the device.",
                ),
                6 => (
                    "Manufacturer model",
                    "Manufacturer model information returned by the device.",
                ),
                7 => ("Software revision", "Manufacturer software revision."),
                8 => ("Hardware revision", "Manufacturer hardware revision."),
                9 => ("Device serial number", "Manufacturer serial SHORT_STRING."),
                10 => (
                    "Device configuration",
                    "Manufacturer configuration SHORT_STRING.",
                ),
                _ => unreachable!(),
            };
            if let Some(value) = decode_short_string(data, name, &mut out.warnings) {
                out.fields
                    .push(detail(name, value.clone(), None, description));
                if attribute_id == 3 {
                    out.mutations.push(StateMutation::Profile(value));
                }
            }
        }
        11 => fixed_u8_field(
            &mut out,
            data,
            "Device status",
            |value| format!("{value} - {}", supervisor_status(value)),
            None,
            "S-Device Supervisor Device Status enumeration.",
        ),
        12 => {
            if let Some(value) = exact_u8(data, "Exception Status", &mut out.warnings) {
                out.fields.push(detail(
                    "Exception status",
                    format!("0x{value:02X} - {}", supervisor_exception_bits(value)),
                    None,
                    "Volume 1 common/device/manufacturer alarm and warning summary bits; bit 7 selects expanded detail.",
                ));
            }
        }
        13 | 14 => decode_exception_detail(state, attribute_id, data, &mut out),
        15 | 16 | 22 | 24 => bool_field(
            &mut out,
            data,
            match attribute_id {
                15 => "Alarm enable",
                16 => "Warning enable",
                22 => "Maintenance warning enable",
                24 => "Endpoint",
                _ => unreachable!(),
            },
            "S-Device Supervisor BOOL attribute.",
        ),
        18 => fixed_u8_field(
            &mut out,
            data,
            "Clock power-cycle behavior",
            |value| value.to_string(),
            None,
            "S-Device Supervisor Clock Power Cycle Behavior USINT.",
        ),
        21 => fixed_i16_field(
            &mut out,
            data,
            "Maintenance expiration",
            |value| value.to_string(),
            Some("h"),
            "Signed maintenance-expiration timer in hours.",
        ),
        23 => fixed_u32_field(
            &mut out,
            data,
            "Run hours",
            |value| value.to_string(),
            Some("h"),
            "S-Device Supervisor UDINT accumulated run hours.",
        ),
        25 | 99 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 25 {
                "Recipe"
            } else {
                "Subclass"
            },
            |value| value.to_string(),
            None,
            "S-Device Supervisor UINT attribute.",
        ),
        _ => {}
    }
    out
}

fn decode_exception_detail(
    state: &DeviceState,
    attribute_id: u32,
    data: &[u8],
    out: &mut InternalDecode,
) {
    let mut offset = 0usize;
    let mut groups = Vec::new();
    for label in ["Common", "Device", "Manufacturer"] {
        let Some(size) = data.get(offset).copied() else {
            out.warnings.push(format!(
                "Exception detail is truncated before the {label} size field"
            ));
            return;
        };
        offset += 1;
        let end = offset.saturating_add(usize::from(size));
        let Some(bytes) = data.get(offset..end) else {
            out.warnings.push(format!(
                "Exception detail {label} block declares {size} byte(s), but the response is truncated"
            ));
            return;
        };
        groups.push((label, bytes));
        offset = end;
    }
    if offset != data.len() {
        out.warnings.push(format!(
            "Exception detail contains {} trailing byte(s); raw data was retained",
            data.len() - offset
        ));
        return;
    }
    let kind = if attribute_id == 13 {
        "alarm"
    } else {
        "warning"
    };
    for (label, bytes) in &groups {
        let value = if *label == "Device" {
            device_exception_description(state.profile.as_deref(), bytes, kind)
        } else {
            hex_bytes(bytes)
        };
        out.fields.push(detail(
            format!("{label} exception detail"),
            value,
            None,
            if *label == "Manufacturer" {
                "Manufacturer-specific exception bits are preserved without assigning undocumented meanings."
            } else {
                "Length-prefixed S-Device Supervisor exception detail block."
            },
        ));
    }
    if let Some((_, device)) = groups.iter().find(|(label, _)| *label == "Device")
        && let Some(profile) = state.profile.as_deref()
    {
        let expected = if profile.starts_with('E') { 2 } else { 1 };
        if !device.is_empty() && device.len() != expected {
            out.warnings.push(format!(
                "{profile} profile expects {expected} Device Exception Detail byte(s), but the device returned {}; the extra bytes remain vendor/device-specific",
                device.len()
            ));
        }
    }
}

fn supervisor_status(value: u8) -> &'static str {
    match value {
        0 => "Undefined",
        1 => "Self Testing",
        2 => "Idle",
        3 => "Self-Test Exception",
        4 => "Executing",
        5 => "Abort",
        6 => "Critical Fault",
        7..=50 => "Reserved",
        51..=99 => "Device-specific",
        _ => "Manufacturer-specific",
    }
}

fn supervisor_exception_bits(value: u8) -> String {
    let labels = [
        "Common Alarm",
        "Device Alarm",
        "Manufacturer Alarm",
        "Reserved bit 3",
        "Common Warning",
        "Device Warning",
        "Manufacturer Warning",
        "Expanded detail",
    ];
    active_bits(value, &labels)
}

fn device_exception_description(profile: Option<&str>, bytes: &[u8], kind: &str) -> String {
    let Some(first) = bytes.first().copied() else {
        return "None".into();
    };
    let first_labels = [
        if profile.is_some_and(|value| value.starts_with('E')) {
            "Not Reading Valid"
        } else {
            "Reading Valid"
        },
        "Flow Low",
        "Flow High",
        "Flow Control",
        "Valve Low",
        "Valve High",
        "Reserved bit 6",
        "Reserved bit 7",
    ];
    let mut parts = vec![format!("byte 0: {}", active_bits(first, &first_labels))];
    if profile.is_some_and(|value| value.starts_with('E'))
        && let Some(second) = bytes.get(1).copied()
    {
        let labels = [
            "Pressure Low",
            "Pressure High",
            "Gas Temperature Low",
            "Gas Temperature High",
            "Pressure Not Reading Valid",
            "Temperature Not Reading Valid",
            "Reserved bit 6",
            "Reserved bit 7",
        ];
        parts.push(format!("byte 1: {}", active_bits(second, &labels)));
    }
    let named = if profile.is_some_and(|value| value.starts_with('E')) {
        2
    } else {
        1
    };
    if bytes.len() > named {
        parts.push(format!(
            "additional vendor/device bytes: {}",
            hex_bytes(&bytes[named..])
        ));
    }
    format!("{} ({kind})", parts.join("; "))
}

fn decode_devicenet(attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    match attribute_id {
        1 | 4 | 8 => {
            let name = match attribute_id {
                1 => "MAC ID",
                4 => "Bus-off counter",
                8 => "MAC ID switch value",
                _ => unreachable!(),
            };
            if let Some(value) = exact_u8(data, name, &mut out.warnings) {
                out.fields.push(detail(
                    name,
                    value.to_string(),
                    None,
                    if attribute_id == 4 {
                        "Number of times the CAN controller entered bus-off state."
                    } else {
                        "DeviceNet MAC ID; valid node addresses are 0 through 63."
                    },
                ));
                if attribute_id != 4 && value > 63 {
                    out.warnings.push(format!(
                        "DeviceNet MAC ID {value} is outside the 0-63 range"
                    ));
                }
            }
        }
        2 | 9 => fixed_u8_field(
            &mut out,
            data,
            if attribute_id == 2 {
                "Baud rate"
            } else {
                "Baud-rate switch value"
            },
            |value| format!("{value} - {}", baud_rate_label(value)),
            None,
            "DeviceNet Object baud-rate enumeration: 0=125 kbit/s, 1=250 kbit/s, 2=500 kbit/s, 3=PGM.",
        ),
        3 => fixed_u8_field(
            &mut out,
            data,
            "Bus-off interrupt behavior",
            |value| match value {
                0 => "0 - Hold CAN controller in bus-off".into(),
                1 => "1 - Reset CAN controller".into(),
                _ => format!("{value} - Undefined"),
            },
            None,
            "DeviceNet Object BOI behavior after a bus-off event.",
        ),
        5 => {
            if exact_len(data, 2, "Allocation Information", &mut out.warnings) {
                out.fields.push(detail(
                    "Allocation choice",
                    format!("0x{:02X} - {}", data[0], allocation_choice(data[0])),
                    None,
                    "Allocation bitmap from the supplied table: bit 0 Explicit Messaging, bit 1 Polled I/O, remaining bits are expected clear.",
                ));
                out.fields.push(detail(
                    "Allocator MAC ID",
                    data[1].to_string(),
                    None,
                    "DeviceNet controller/allocator MAC ID from the Allocation Information structure.",
                ));
                if data[0] & !0x03 != 0 {
                    out.warnings.push(format!(
                        "Allocation Information has table-reserved bits set: 0x{:02X}",
                        data[0] & !0x03
                    ));
                }
                if data[1] > 63 {
                    out.warnings.push(format!(
                        "Allocator MAC ID {} is outside the 0-63 range",
                        data[1]
                    ));
                }
            }
        }
        6 | 7 => bool_field(
            &mut out,
            data,
            if attribute_id == 6 {
                "MAC ID switch changed"
            } else {
                "Baud-rate switch changed"
            },
            "BOOL indicating whether the corresponding hardware switch changed since reset.",
        ),
        _ => {}
    }
    out
}

fn decode_connection(instance_id: u32, attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    match attribute_id {
        1 => fixed_u8_field(
            &mut out,
            data,
            "Connection state",
            |value| {
                format!(
                    "{value} - {}",
                    match value {
                        0 => "Non-existent",
                        1 => "Configuring",
                        3 => "Established",
                        4 => "Timed out",
                        _ => "Reserved/undefined",
                    }
                )
            },
            None,
            "Connection Object state for the Explicit (instance 1) or Polled I/O (instance 2) connection.",
        ),
        2 => fixed_u8_field(
            &mut out,
            data,
            "Instance type",
            |value| value.to_string(),
            None,
            "Connection Object Instance Type USINT.",
        ),
        3 | 6 => fixed_u8_field(
            &mut out,
            data,
            if attribute_id == 3 {
                "Transport class trigger"
            } else {
                "Initial communication characteristics"
            },
            |value| format!("0x{value:02X}"),
            None,
            "Connection Object BYTE; raw bits are retained for protocol diagnosis.",
        ),
        4 | 5 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 4 {
                "Produced connection ID"
            } else {
                "Consumed connection ID"
            },
            |value| format!("0x{value:03X} ({value})"),
            None,
            "DeviceNet Connection ID encoded as UINT by the supplied device dictionary.",
        ),
        7 | 8 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 7 {
                "Produced connection size"
            } else {
                "Consumed connection size"
            },
            |value| value.to_string(),
            Some("bytes"),
            "Configured Connection Object payload size.",
        ),
        9 | 17 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 9 {
                "Expected packet rate"
            } else {
                "Production inhibit time"
            },
            |value| value.to_string(),
            Some("ms"),
            "Connection timing UINT from the supplied table.",
        ),
        12 => fixed_u8_field(
            &mut out,
            data,
            "Watchdog timeout action",
            |value| {
                format!(
                    "{value} - {}",
                    match value {
                        0 => "Timeout",
                        1 => "Auto-delete",
                        2 => "Auto-reset",
                        _ => "Undefined",
                    }
                )
            },
            None,
            "Watchdog action enumeration from the supplied table.",
        ),
        13 | 15 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 13 {
                "Produced connection path length"
            } else {
                "Consumed connection path length"
            },
            |value| value.to_string(),
            Some("bytes"),
            "Connection path length UINT. Explicit instance 1 uses zero; Polled I/O instance 2 uses a six-byte path.",
        ),
        14 | 16 => {
            let path_name = if attribute_id == 14 {
                "Produced connection path"
            } else {
                "Consumed connection path"
            };
            out.fields.push(detail(
                path_name,
                if data.is_empty() {
                    "Empty".into()
                } else {
                    hex_bytes(data)
                },
                None,
                "Packed EPATH byte array from the Connection Object; original bytes are shown without inventing missing path members.",
            ));
            if let Some(target) = decode_logical_path(data).display {
                out.fields.push(detail(
                    format!("{path_name} target"),
                    target,
                    None,
                    "Logical members decoded from the Packed EPATH; the raw path remains available above.",
                ));
            }
            if instance_id == 1 && !data.is_empty() {
                out.warnings.push(
                    "Explicit connection instance 1 normally declares an empty connection path"
                        .into(),
                );
            }
        }
        _ => {}
    }
    out
}

fn decode_sensor(
    state: &DeviceState,
    instance_id: u32,
    attribute_id: u32,
    data: &[u8],
) -> InternalDecode {
    let mut out = InternalDecode::default();
    let context = state.numeric(0x31, instance_id);
    match attribute_id {
        1 => fixed_u8_field(
            &mut out,
            data,
            "Number of attributes",
            |value| value.to_string(),
            None,
            "S-Analog Sensor attribute count (USINT).",
        ),
        2 => attribute_list_field(&mut out, data),
        3 => decode_data_type(&mut out, data, 0x31, instance_id, "Sensor data type"),
        4 => decode_data_units(&mut out, data, 0x31, instance_id, "Sensor data units"),
        5 => bool_field(
            &mut out,
            data,
            "Reading valid",
            "S-Analog Sensor Reading Valid: 1 Operating, 0 Error.",
        ),
        6 => {
            let name = match instance_id {
                1 => "Flow",
                2 => "Pressure",
                3 => "Temperature",
                _ => unreachable!(),
            };
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                name,
                context.units.map(unit_label),
                "S-Analog Sensor Value; wire type follows attribute 3 and units follow attribute 4.",
            ) {
                add_sensor_engineering(instance_id, &context, value, name, &mut out);
            }
        }
        7 => status_field(
            &mut out,
            data,
            "Sensor status",
            &["High Alarm", "Low Alarm", "High Warning", "Low Warning"],
        ),
        8 | 9 => bool_field(
            &mut out,
            data,
            if attribute_id == 8 {
                "Alarm enable"
            } else {
                "Warning enable"
            },
            "S-Analog Sensor alarm/warning enable BOOL.",
        ),
        10 => {
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                "Numeric full scale",
                context.units.map(unit_label),
                "S-Analog Sensor Full Scale; wire type follows Data Type.",
            ) {
                if value.inferred_type {
                    out.warnings.push(
                        "Numeric Full Scale was decoded from payload length only and is not stored until Data Type attribute 3 has been observed"
                            .into(),
                    );
                } else if value.number.is_finite() && value.number != 0.0 {
                    out.mutations.push(StateMutation::NumericFullScale {
                        class_id: 0x31,
                        instance_id,
                        value: value.number,
                    });
                } else {
                    out.mutations.push(StateMutation::ClearNumericFullScale {
                        class_id: 0x31,
                        instance_id,
                    });
                    out.warnings.push(
                        "Numeric Full Scale must be finite and non-zero for conversion; the previous Numeric Full Scale is invalidated"
                            .into(),
                    );
                }
            }
        }
        17..=19 | 21..=23 => {
            let name = match attribute_id {
                17 => "Alarm trip point high",
                18 => "Alarm trip point low",
                19 => "Alarm hysteresis",
                21 => "Warning trip point high",
                22 => "Warning trip point low",
                23 => "Warning hysteresis",
                _ => unreachable!(),
            };
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                name,
                context.units.map(unit_label),
                "Sensor threshold value; wire type and units follow the Sensor Value attributes.",
            ) {
                if context
                    .units
                    .is_some_and(|unit| data_unit_is_allowed(0x31, instance_id, unit))
                {
                    add_percent_full_scale(&context, value.number, name, &mut out);
                } else {
                    out.warnings.push(format!(
                        "{name} percent-of-full-scale conversion requires an observed, compatible Sensor Data Units value"
                    ));
                }
            }
        }
        20 | 24 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 20 {
                "Alarm settling time"
            } else {
                "Warning settling time"
            },
            |value| value.to_string(),
            Some("ms"),
            "S-Analog Sensor settling-time UINT.",
        ),
        27 | 28 => bool_field(
            &mut out,
            data,
            if attribute_id == 27 {
                "Autozero enable"
            } else {
                "Autozero status"
            },
            "S-Analog Sensor Autozero BOOL.",
        ),
        35 => {
            if let Some(value) =
                exact_u16(data, "Gas Calibration Object Instance", &mut out.warnings)
            {
                out.fields.push(detail(
                    "Gas calibration object instance",
                    value.to_string(),
                    None,
                    "Associated S-Gas Calibration Object instance (UINT).",
                ));
                if instance_id != 1 && value != 0 {
                    out.warnings.push(format!(
                        "The supplied industry table says Sensor instance {instance_id} attribute 35 is 0, but the device returned {value}"
                    ));
                }
            }
        }
        99 => {
            if let Some(value) = exact_u16(data, "Sensor Subclass", &mut out.warnings) {
                out.fields.push(detail(
                    "Subclass",
                    value.to_string(),
                    None,
                    "S-Analog Sensor subclass UINT.",
                ));
                let expected = if instance_id == 2 { 0 } else { 1 };
                if value != expected {
                    out.warnings.push(format!(
                        "The supplied industry table describes Sensor instance {instance_id} subclass as {expected}, but the device returned {value}"
                    ));
                }
            }
        }
        0x6e => decode_configured_full_scale(instance_id, data, &mut out),
        _ => {}
    }
    out
}

fn decode_actuator(state: &DeviceState, attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    let context = state.numeric(0x32, 1);
    match attribute_id {
        1 => fixed_u8_field(
            &mut out,
            data,
            "Number of attributes",
            |value| value.to_string(),
            None,
            "S-Analog Actuator attribute count (USINT).",
        ),
        2 => attribute_list_field(&mut out, data),
        3 => decode_data_type(&mut out, data, 0x32, 1, "Actuator data type"),
        4 => decode_data_units(&mut out, data, 0x32, 1, "Actuator data units"),
        5 => {
            if let Some(value) = exact_u8(data, "Override", &mut out.warnings) {
                let label = match value {
                    0 => "Normal",
                    1 => "Close",
                    2 => "Open",
                    3 => "Hold",
                    _ => "Undefined by the supplied industry table",
                };
                out.fields.push(detail(
                    "Override",
                    format!("{value} - {label}"),
                    None,
                    "S-Analog Actuator Override enumeration from the supplied industry table.",
                ));
            }
        }
        6 => {
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                "Valve",
                context.units.map(unit_label),
                "S-Analog Actuator Value; wire type and units follow attributes 3 and 4.",
            ) && context.units == Some(UNIT_COUNTS)
                && value.number.is_finite()
            {
                out.fields.push(detail(
                    "Valve position",
                    format_number(value.number / 32767.0 * 100.0),
                    Some("%"),
                    "Industry-table Counts conversion: raw / 32767 × 100.",
                ));
            }
        }
        7 => status_field(
            &mut out,
            data,
            "Actuator status",
            &["High Alarm", "Low Alarm", "High Warning", "Low Warning"],
        ),
        8 | 9 => bool_field(
            &mut out,
            data,
            if attribute_id == 8 {
                "Alarm enable"
            } else {
                "Warning enable"
            },
            "S-Analog Actuator alarm/warning enable BOOL.",
        ),
        15..=20 => {
            let name = match attribute_id {
                15 => "Alarm trip point high",
                16 => "Alarm trip point low",
                17 => "Alarm hysteresis",
                18 => "Warning trip point high",
                19 => "Warning trip point low",
                20 => "Warning hysteresis",
                _ => unreachable!(),
            };
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                name,
                context.units.map(unit_label),
                "Actuator threshold; wire type and units follow Data Type and Data Units.",
            ) && value.number.is_finite()
            {
                let percent = match context.units {
                    Some(UNIT_PERCENT) => Some(value.number),
                    Some(UNIT_COUNTS) => Some(value.number / 32767.0 * 100.0),
                    _ => None,
                };
                if let Some(percent) = percent {
                    out.fields.push(detail(
                        format!("{name} (%FS)"),
                        format_number(percent),
                        Some("%FS"),
                        "Industry-table Actuator full scale is 32767 Counts or 100 percent.",
                    ));
                } else {
                    out.warnings.push(format!(
                        "{name} %FS conversion requires compatible Counts or Percent Data Units"
                    ));
                }
            }
        }
        _ => {}
    }
    out
}

fn decode_controller(state: &DeviceState, attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    let context = state.numeric(0x33, 1);
    let flow = state.numeric(0x31, 1);
    match attribute_id {
        1 => fixed_u8_field(
            &mut out,
            data,
            "Number of attributes",
            |value| value.to_string(),
            None,
            "S-Single Stage Controller attribute count (USINT).",
        ),
        2 => attribute_list_field(&mut out, data),
        3 => decode_data_type(&mut out, data, 0x33, 1, "Controller data type"),
        4 => decode_data_units(&mut out, data, 0x33, 1, "Controller data units"),
        6 => {
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                "Setpoint",
                context.units.map(unit_label),
                "S-Single Stage Controller Setpoint; wire type and units follow attributes 3 and 4.",
            ) && context.units == Some(UNIT_COUNTS)
            {
                add_flow_based_engineering(&flow, value.number, "Setpoint", &mut out);
            }
        }
        10 => status_field(
            &mut out,
            data,
            "Controller status",
            &["High Alarm", "Low Alarm", "High Warning", "Low Warning"],
        ),
        11 | 12 => bool_field(
            &mut out,
            data,
            if attribute_id == 11 {
                "Alarm enable"
            } else {
                "Warning enable"
            },
            "S-Single Stage Controller alarm/warning enable BOOL.",
        ),
        13 | 15 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 13 {
                "Alarm settling time"
            } else {
                "Warning settling time"
            },
            |value| value.to_string(),
            Some("ms"),
            "Controller settling-time UINT.",
        ),
        14 | 16 => {
            let name = if attribute_id == 14 {
                "Alarm error band"
            } else {
                "Warning error band"
            };
            if let Some(value) = dynamic_field(
                &mut out,
                data,
                &context,
                name,
                context.units.map(unit_label),
                "Controller error band; wire type and units follow Controller attributes 3 and 4.",
            ) {
                if value.number.is_finite() {
                    match context.units {
                        Some(UNIT_PERCENT) => out.fields.push(detail(
                            format!("{name} (%FS)"),
                            format_number(value.number),
                            Some("%FS"),
                            "Controller Percent Data Units carry the percent-of-full-scale value directly.",
                        )),
                        Some(UNIT_COUNTS) => {
                            if flow.units == Some(UNIT_COUNTS) {
                                add_percent_full_scale(&flow, value.number, name, &mut out)
                            } else {
                                out.warnings.push(format!(
                                    "{name} Counts conversion requires Flow Sensor Data Units to be observed as Counts"
                                ));
                            }
                        }
                        _ => out.warnings.push(format!(
                            "{name} %FS conversion requires compatible Counts or Percent Controller Data Units"
                        )),
                    }
                }
            }
        }
        19 => fixed_u32_field(
            &mut out,
            data,
            "Ramp rate",
            |value| value.to_string(),
            Some("ms"),
            "S-Single Stage Controller Ramp Rate UDINT.",
        ),
        _ => {}
    }
    out
}

fn decode_gas_calibration(instance_id: u32, attribute_id: u32, data: &[u8]) -> InternalDecode {
    let mut out = InternalDecode::default();
    match attribute_id {
        1 => fixed_u8_field(
            &mut out,
            data,
            "Number of attributes",
            |value| value.to_string(),
            None,
            "S-Gas Calibration attribute count (USINT).",
        ),
        2 => attribute_list_field(&mut out, data),
        3 | 9 => fixed_u16_field(
            &mut out,
            data,
            if attribute_id == 3 {
                "Gas number"
            } else {
                "Calibration gas number"
            },
            |value| {
                if value == 13 {
                    format!("{value} - N2")
                } else {
                    value.to_string()
                }
            },
            None,
            "SEMI gas number UINT; the supplied industry table identifies 13 as N2.",
        ),
        4 => fixed_u16_field(
            &mut out,
            data,
            "Sensor instance",
            |value| value.to_string(),
            None,
            "S-Analog Sensor instance associated with this calibration record.",
        ),
        5 => short_string_field(
            &mut out,
            data,
            "Gas name",
            "Gas symbol/name SHORT_STRING from the calibration record.",
            None,
        ),
        6 => {
            if exact_len(data, 6, "Calibration Amount and Units", &mut out.warnings) {
                let amount = f32::from_le_bytes(data[0..4].try_into().unwrap()) as f64;
                let unit = u16::from_le_bytes([data[4], data[5]]);
                let unit = unit_label(unit);
                out.fields.push(detail(
                    "Calibration full scale",
                    format_number(amount),
                    Some(unit.as_str()),
                    "S-Gas Calibration STRUCT: REAL amount followed by ENGUNIT (UINT), little-endian.",
                ));
            }
        }
        7 | 10 | 95 | 96 => {
            let (name, unit, description) = match attribute_id {
                7 => (
                    "Additional scaler",
                    None,
                    "REAL scaler applied by the calibration object.",
                ),
                10 => ("Gas correction factor", None, "REAL gas correction factor."),
                95 => (
                    "Calibration pressure",
                    Some("kPa(A)"),
                    "REAL calibration pressure.",
                ),
                96 => (
                    "Calibration temperature",
                    Some("°C"),
                    "REAL calibration temperature.",
                ),
                _ => unreachable!(),
            };
            fixed_f32_field(&mut out, data, name, unit, description);
        }
        8 => decode_calibration_date(data, instance_id, &mut out),
        99 => fixed_u16_field(
            &mut out,
            data,
            "Subclass",
            |value| value.to_string(),
            None,
            "S-Gas Calibration subclass UINT.",
        ),
        _ => {}
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct NumericValue {
    number: f64,
    inferred_type: bool,
}

fn decode_data_type(
    out: &mut InternalDecode,
    data: &[u8],
    class_id: u32,
    instance_id: u32,
    name: &str,
) {
    let Some(code) = exact_u8(data, name, &mut out.warnings) else {
        return;
    };
    let label = cip_type_label(code);
    out.fields.push(detail(
        name,
        format!("0x{code:02X} - {label}"),
        None,
        "Dynamic profile values use the CIP elementary type selected by this attribute. MFC/EMFC supports INT and REAL.",
    ));
    if let Some(value) = NumericType::from_code(code) {
        out.mutations.push(StateMutation::DataType {
            class_id,
            instance_id,
            value,
        });
    } else {
        out.mutations.push(StateMutation::ClearDataType {
            class_id,
            instance_id,
        });
        out.warnings.push(format!(
            "Dynamic MFC/EMFC values cannot be decoded for unsupported Data Type 0x{code:02X}; any previously learned type and Numeric Full Scale are invalidated"
        ));
    }
}

fn decode_data_units(
    out: &mut InternalDecode,
    data: &[u8],
    class_id: u32,
    instance_id: u32,
    name: &str,
) {
    let Some(value) = exact_u16(data, name, &mut out.warnings) else {
        return;
    };
    let label = unit_label(value);
    out.fields.push(detail(
        name,
        format!("0x{value:04X} - {label}"),
        None,
        "CIP ENGUNIT is a UINT. The code identifies a unit but does not by itself define a scale or offset.",
    ));
    if data_unit_is_allowed(class_id, instance_id, value) {
        out.mutations.push(StateMutation::Units {
            class_id,
            instance_id,
            value,
        });
    } else {
        out.mutations.push(StateMutation::ClearUnits {
            class_id,
            instance_id,
        });
        if let Some(allowed) = data_unit_whitelist(class_id, instance_id) {
            out.warnings.push(format!(
                "{name} 0x{value:04X} is incompatible with the supplied industry table; allowed units are {}. Any previously learned units and Numeric Full Scale are invalidated",
                format_unit_whitelist(allowed)
            ));
        }
    }
}

fn data_unit_whitelist(class_id: u32, instance_id: u32) -> Option<&'static [u16]> {
    match (class_id, instance_id) {
        (0x31, 1) => Some(SENSOR_FLOW_UNITS),
        (0x31, 2) => Some(SENSOR_PRESSURE_UNITS),
        (0x31, 3) => Some(SENSOR_TEMPERATURE_UNITS),
        (0x32 | 0x33, 1) => Some(ACTUATOR_CONTROLLER_UNITS),
        _ => None,
    }
}

fn data_unit_is_allowed(class_id: u32, instance_id: u32, unit: u16) -> bool {
    data_unit_whitelist(class_id, instance_id).is_some_and(|allowed| allowed.contains(&unit))
}

fn configured_full_scale_unit_whitelist(instance_id: u32) -> Option<&'static [u16]> {
    match instance_id {
        1 => Some(FLOW_CONFIGURED_FULL_SCALE_UNITS),
        2 => Some(PRESSURE_CONFIGURED_FULL_SCALE_UNITS),
        3 => Some(TEMPERATURE_CONFIGURED_FULL_SCALE_UNITS),
        _ => None,
    }
}

fn configured_full_scale_unit_is_allowed(instance_id: u32, unit: u16) -> bool {
    configured_full_scale_unit_whitelist(instance_id).is_some_and(|allowed| allowed.contains(&unit))
}

fn format_unit_whitelist(units: &[u16]) -> String {
    units
        .iter()
        .map(|unit| format!("0x{unit:04X} ({})", unit_label(*unit)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn dynamic_field(
    out: &mut InternalDecode,
    data: &[u8],
    context: &NumericContext,
    name: &str,
    unit: Option<String>,
    description: &str,
) -> Option<NumericValue> {
    let (data_type, inferred_type) = if let Some(data_type) = context.data_type {
        (data_type, false)
    } else {
        let inferred = match data.len() {
            2 => NumericType::Int,
            4 => NumericType::Real,
            length => {
                out.warnings.push(format!(
                    "{name} cannot be inferred without Data Type attribute 3: the industry table permits a 2-byte INT or 4-byte REAL, but this payload has {length} byte(s)"
                ));
                return None;
            }
        };
        out.warnings.push(format!(
            "{name} Data Type attribute 3 was not observed; {} is inferred from this payload length for display only and is not stored in device state",
            inferred.label()
        ));
        (inferred, true)
    };
    let value = match data_type {
        NumericType::Int => {
            let value = exact_i16(data, name, &mut out.warnings)?;
            NumericValue {
                number: f64::from(value),
                inferred_type,
            }
        }
        NumericType::Real => {
            if !exact_len(data, 4, name, &mut out.warnings) {
                return None;
            }
            let value = f32::from_le_bytes(data.try_into().unwrap());
            NumericValue {
                number: f64::from(value),
                inferred_type,
            }
        }
    };
    let value_text = match data_type {
        NumericType::Int => (value.number as i16).to_string(),
        NumericType::Real => (value.number as f32).to_string(),
    };
    let unit = unit.unwrap_or_else(|| "unit not observed".into());
    out.fields.push(detail(
        name,
        value_text,
        Some(unit.as_str()),
        format!(
            "{description} Decoded as CIP {} (0x{:02X}), little-endian.",
            data_type.label(),
            data_type.code()
        ),
    ));
    if !value.number.is_finite() {
        out.warnings.push(format!(
            "{name} contains a non-finite REAL value; it is displayed verbatim but cannot be used for Full Scale, engineering, or percent-of-full-scale calculations"
        ));
    }
    Some(value)
}

fn decode_configured_full_scale(instance_id: u32, data: &[u8], out: &mut InternalDecode) {
    if !exact_len(data, 6, "Configured Full Scale", &mut out.warnings) {
        return;
    }
    let amount = f32::from_le_bytes(data[0..4].try_into().unwrap()) as f64;
    let unit = u16::from_le_bytes([data[4], data[5]]);
    let label = unit_label(unit);
    out.fields.push(detail(
        "Configured full scale",
        format_number(amount),
        Some(label.as_str()),
        "Industry Sensor attribute 0x6E: REAL full-scale amount followed by UINT ENGUNIT, both little-endian.",
    ));
    let unit_allowed = configured_full_scale_unit_is_allowed(instance_id, unit);
    if !unit_allowed {
        let allowed = configured_full_scale_unit_whitelist(instance_id).unwrap_or_default();
        out.warnings.push(format!(
            "Configured Full Scale unit 0x{unit:04X} is incompatible with Sensor instance {instance_id}; allowed units are {}",
            format_unit_whitelist(allowed)
        ));
    }
    if amount.is_finite() && amount != 0.0 && unit_allowed {
        out.mutations.push(StateMutation::ConfiguredFullScale {
            class_id: 0x31,
            instance_id,
            value: ConfiguredFullScale { amount, unit },
        });
    } else {
        out.mutations.push(StateMutation::ClearConfiguredFullScale {
            class_id: 0x31,
            instance_id,
        });
        if !amount.is_finite() || amount == 0.0 {
            out.warnings.push(
                "Configured Full Scale must be finite and non-zero for conversion; the previous configured scale is invalidated"
                    .into(),
            );
        }
    }
}

fn add_sensor_engineering(
    instance_id: u32,
    context: &NumericContext,
    value: NumericValue,
    name: &str,
    out: &mut InternalDecode,
) {
    if context.units != Some(UNIT_COUNTS) {
        return;
    }
    if !value.number.is_finite() {
        return;
    }
    let (Some(numeric_full_scale), Some(configured)) =
        (context.numeric_full_scale, context.configured_full_scale)
    else {
        out.warnings.push(format!(
            "{name} Counts conversion requires both Numeric Full Scale and Sensor attribute 0x6E Configured Full Scale"
        ));
        return;
    };
    if !numeric_full_scale.is_finite() || numeric_full_scale == 0.0 {
        out.warnings.push(format!(
            "{name} Counts conversion cannot use a zero or non-finite Numeric Full Scale"
        ));
        return;
    }
    if !configured_full_scale_unit_is_allowed(instance_id, configured.unit) {
        out.warnings.push(format!(
            "{name} Counts conversion is blocked because Configured Full Scale unit 0x{:04X} is incompatible with Sensor instance {instance_id}",
            configured.unit
        ));
        return;
    }
    let engineering = value.number / numeric_full_scale * configured.amount;
    let unit = unit_label(configured.unit);
    out.fields.push(detail(
        format!("{name} engineering value"),
        format_number(engineering),
        Some(unit.as_str()),
        "Industry-table Counts conversion: raw / Numeric Full Scale × Configured Full Scale (Sensor attribute 0x6E).",
    ));
}

fn add_flow_based_engineering(
    flow: &NumericContext,
    raw: f64,
    name: &str,
    out: &mut InternalDecode,
) {
    if !raw.is_finite() {
        return;
    }
    if flow.units != Some(UNIT_COUNTS) {
        out.warnings.push(format!(
            "{name} Counts conversion requires Flow Sensor Data Units to be observed as Counts"
        ));
        return;
    }
    let Some(numeric_full_scale) = flow.numeric_full_scale else {
        out.warnings.push(format!(
            "{name} Counts conversion requires Flow Sensor Numeric Full Scale"
        ));
        return;
    };
    if !numeric_full_scale.is_finite() || numeric_full_scale == 0.0 {
        out.warnings.push(format!(
            "{name} Counts conversion cannot use a zero or non-finite Flow Numeric Full Scale"
        ));
        return;
    }
    let percent = raw / numeric_full_scale * 100.0;
    out.fields.push(detail(
        format!("{name} percent of full scale"),
        format_number(percent),
        Some("%FS"),
        "Controller Counts conversion uses the Flow Sensor Numeric Full Scale.",
    ));
    if let Some(configured) = flow.configured_full_scale {
        if !configured_full_scale_unit_is_allowed(1, configured.unit) {
            out.warnings.push(format!(
                "{name} engineering conversion is blocked because Flow Configured Full Scale unit 0x{:04X} is incompatible",
                configured.unit
            ));
            return;
        }
        let engineering = raw / numeric_full_scale * configured.amount;
        let unit = unit_label(configured.unit);
        out.fields.push(detail(
            format!("{name} engineering value"),
            format_number(engineering),
            Some(unit.as_str()),
            "Setpoint conversion: raw / Flow Numeric Full Scale × Flow Configured Full Scale.",
        ));
    } else {
        out.warnings.push(format!(
            "{name} engineering conversion requires Flow Sensor attribute 0x6E"
        ));
    }
}

fn add_percent_full_scale(
    context: &NumericContext,
    raw: f64,
    name: &str,
    out: &mut InternalDecode,
) {
    if !raw.is_finite() {
        return;
    }
    let Some(full_scale) = context.numeric_full_scale else {
        out.warnings.push(format!(
            "{name} %FS conversion requires the applicable Numeric Full Scale"
        ));
        return;
    };
    if !full_scale.is_finite() || full_scale == 0.0 {
        out.warnings.push(format!(
            "{name} %FS conversion cannot use zero/non-finite full scale"
        ));
        return;
    }
    out.fields.push(detail(
        format!("{name} (%FS)"),
        format_number(raw / full_scale * 100.0),
        Some("%FS"),
        "Industry-table threshold conversion: raw / Numeric Full Scale × 100.",
    ));
}

fn decode_calibration_date(data: &[u8], instance_id: u32, out: &mut InternalDecode) {
    if data.len() == 2 {
        let days = u16::from_le_bytes([data[0], data[1]]);
        out.fields.push(detail(
            "Calibration date",
            format!(
                "{} ({days} days since 1972-01-01)",
                calendar_date_from_1972(days)
            ),
            None,
            "Volume 1 DATE is a UINT day count from 1972-01-01.",
        ));
        return;
    }
    if let Some(value) = decode_short_string(data, "Calibration Date", &mut Vec::new()) {
        out.fields.push(detail(
            "Calibration date",
            value,
            None,
            "The device returned a length-prefixed date string even though the supplied industry table and Volume 1 declare DATE.",
        ));
        out.warnings.push(format!(
            "Gas Calibration instance {instance_id} attribute 8 uses firmware SHORT_STRING data that conflicts with the declared DATE type; raw bytes were retained"
        ));
        return;
    }
    out.warnings.push(
        "Calibration Date is neither a 2-byte DATE nor a complete firmware SHORT_STRING; raw bytes were retained"
            .into(),
    );
}

fn calendar_date_from_1972(days: u16) -> String {
    let mut remaining = u32::from(days);
    let mut year = 1972u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let month_lengths = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for length in month_lengths {
        if remaining < length {
            break;
        }
        remaining -= length;
        month += 1;
    }
    format!("{year:04}-{month:02}-{:02}", remaining + 1)
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn detail(
    name: impl Into<String>,
    value: impl Into<String>,
    unit: Option<&str>,
    description: impl Into<String>,
) -> DecodedField {
    DecodedField {
        name: name.into(),
        value: value.into(),
        role: DecodedFieldRole::Value,
        service_code: None,
        unit: unit.map(str::to_owned),
        description: Some(description.into()),
    }
}

fn fixed_u8_field(
    out: &mut InternalDecode,
    data: &[u8],
    name: &str,
    format: impl FnOnce(u8) -> String,
    unit: Option<&str>,
    description: &str,
) {
    if let Some(value) = exact_u8(data, name, &mut out.warnings) {
        out.fields
            .push(detail(name, format(value), unit, description));
    }
}

fn fixed_u16_field(
    out: &mut InternalDecode,
    data: &[u8],
    name: &str,
    format: impl FnOnce(u16) -> String,
    unit: Option<&str>,
    description: &str,
) {
    if let Some(value) = exact_u16(data, name, &mut out.warnings) {
        out.fields
            .push(detail(name, format(value), unit, description));
    }
}

fn fixed_i16_field(
    out: &mut InternalDecode,
    data: &[u8],
    name: &str,
    format: impl FnOnce(i16) -> String,
    unit: Option<&str>,
    description: &str,
) {
    if let Some(value) = exact_i16(data, name, &mut out.warnings) {
        out.fields
            .push(detail(name, format(value), unit, description));
    }
}

fn fixed_u32_field(
    out: &mut InternalDecode,
    data: &[u8],
    name: &str,
    format: impl FnOnce(u32) -> String,
    unit: Option<&str>,
    description: &str,
) {
    if !exact_len(data, 4, name, &mut out.warnings) {
        return;
    }
    let value = u32::from_le_bytes(data.try_into().unwrap());
    out.fields
        .push(detail(name, format(value), unit, description));
}

fn fixed_f32_field(
    out: &mut InternalDecode,
    data: &[u8],
    name: &str,
    unit: Option<&str>,
    description: &str,
) {
    if !exact_len(data, 4, name, &mut out.warnings) {
        return;
    }
    let value = f32::from_le_bytes(data.try_into().unwrap());
    out.fields
        .push(detail(name, value.to_string(), unit, description));
    if !value.is_finite() {
        out.warnings
            .push(format!("{name} contains a non-finite REAL value"));
    }
}

fn bool_field(out: &mut InternalDecode, data: &[u8], name: &str, description: &str) {
    if let Some(value) = exact_u8(data, name, &mut out.warnings) {
        let label = match value {
            0 => "False / Disabled / No",
            1 => "True / Enabled / Yes",
            _ => "Invalid CIP BOOL encoding",
        };
        out.fields.push(detail(
            name,
            format!("{value} - {label}"),
            None,
            description,
        ));
        if value > 1 {
            out.warnings
                .push(format!("{name} contains invalid CIP BOOL value {value}"));
        }
    }
}

fn status_field(out: &mut InternalDecode, data: &[u8], name: &str, labels: &[&str]) {
    if let Some(value) = exact_u8(data, name, &mut out.warnings) {
        out.fields.push(detail(
            name,
            format!("0x{value:02X} - {}", active_bits(value, labels)),
            None,
            "Status BYTE; named active bits are decoded and the hexadecimal value preserves all reserved/vendor bits.",
        ));
        let named_mask = if labels.len() >= 8 {
            u8::MAX
        } else {
            (1u16.checked_shl(labels.len() as u32).unwrap_or(0) - 1) as u8
        };
        if value & !named_mask != 0 {
            out.warnings.push(format!(
                "{name} has reserved or vendor bits set: 0x{:02X}",
                value & !named_mask
            ));
        }
    }
}

fn attribute_list_field(out: &mut InternalDecode, data: &[u8]) {
    out.fields.push(detail(
        "Attribute list",
        if data.is_empty() {
            "None".into()
        } else {
            data.iter()
                .map(|value| format!("0x{value:02X}"))
                .collect::<Vec<_>>()
                .join(", ")
        },
        None,
        "ARRAY OF USINT attribute identifiers returned in wire order.",
    ));
}

fn short_string_field(
    out: &mut InternalDecode,
    data: &[u8],
    name: &str,
    description: &str,
    unit: Option<&str>,
) {
    if let Some(value) = decode_short_string(data, name, &mut out.warnings) {
        out.fields.push(detail(name, value, unit, description));
    }
}

fn decode_short_string(data: &[u8], name: &str, warnings: &mut Vec<String>) -> Option<String> {
    let Some(length) = data.first().copied() else {
        warnings.push(format!("{name} is missing its SHORT_STRING length byte"));
        return None;
    };
    let expected = usize::from(length) + 1;
    if data.len() != expected {
        warnings.push(format!(
            "{name} SHORT_STRING declares {length} byte(s), but {} byte(s) follow the length",
            data.len().saturating_sub(1)
        ));
        return None;
    }
    match std::str::from_utf8(&data[1..]) {
        Ok(value) => Some(value.into()),
        Err(_) => {
            warnings.push(format!(
                "{name} SHORT_STRING is not valid UTF-8/ASCII; raw bytes were retained"
            ));
            None
        }
    }
}

fn exact_len(data: &[u8], expected: usize, name: &str, warnings: &mut Vec<String>) -> bool {
    if data.len() == expected {
        true
    } else {
        warnings.push(format!(
            "{name} expects exactly {expected} byte(s), found {}; raw bytes were retained",
            data.len()
        ));
        false
    }
}

fn exact_u8(data: &[u8], name: &str, warnings: &mut Vec<String>) -> Option<u8> {
    exact_len(data, 1, name, warnings).then(|| data[0])
}

fn exact_u16(data: &[u8], name: &str, warnings: &mut Vec<String>) -> Option<u16> {
    exact_len(data, 2, name, warnings).then(|| u16::from_le_bytes([data[0], data[1]]))
}

fn exact_i16(data: &[u8], name: &str, warnings: &mut Vec<String>) -> Option<i16> {
    exact_len(data, 2, name, warnings).then(|| i16::from_le_bytes([data[0], data[1]]))
}

fn unit_label(value: u16) -> String {
    match value {
        0x1001 => "Counts".into(),
        0x1007 => "%".into(),
        0x1200 => "°C".into(),
        0x1202 => "K".into(),
        0x1300 => "psi".into(),
        0x1301 => "torr".into(),
        0x130a => "kPa".into(),
        0x1400 => "sccm".into(),
        0x1401 => "SLM".into(),
        _ => format!("ENGUNIT 0x{value:04X} (not named by the supported subset)"),
    }
}

fn cip_type_label(value: u8) -> &'static str {
    match value {
        TYPE_BOOL => "BOOL",
        TYPE_INT => "INT",
        TYPE_USINT => "USINT",
        TYPE_UINT => "UINT",
        TYPE_UDINT => "UDINT",
        TYPE_ULINT => "ULINT",
        TYPE_REAL => "REAL",
        TYPE_BYTE => "BYTE",
        0xda => "SHORT_STRING",
        0xdd => "ENGUNIT",
        _ => "Unsupported/unknown type",
    }
}

fn active_bits(value: u8, labels: &[&str]) -> String {
    let active = labels
        .iter()
        .enumerate()
        .filter(|(bit, _)| value & (1 << bit) != 0)
        .map(|(_, label)| *label)
        .collect::<Vec<_>>();
    if active.is_empty() {
        "None".into()
    } else {
        active.join(", ")
    }
}

fn baud_rate_label(value: u8) -> &'static str {
    match value {
        0 => "125 kbit/s",
        1 => "250 kbit/s",
        2 => "500 kbit/s",
        3 => "PGM",
        _ => "Undefined",
    }
}

fn identity_status(value: u16) -> String {
    let flags = [
        (0x0001, "Owned"),
        (0x0004, "Configured"),
        (0x0100, "Minor Recoverable Fault"),
        (0x0200, "Minor Unrecoverable Fault"),
        (0x0400, "Major Recoverable Fault"),
        (0x0800, "Major Unrecoverable Fault"),
    ]
    .into_iter()
    .filter(|(mask, _)| value & mask != 0)
    .map(|(_, label)| label)
    .collect::<Vec<_>>();
    if flags.is_empty() {
        "None".into()
    } else {
        flags.join(", ")
    }
}

fn allocation_choice(value: u8) -> String {
    let mut labels = Vec::new();
    if value & 0x01 != 0 {
        labels.push("Explicit Messaging");
    }
    if value & 0x02 != 0 {
        labels.push("Polled I/O");
    }
    if labels.is_empty() {
        "None".into()
    } else {
        labels.join(", ")
    }
}

fn hex_bytes(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_number(value: f64) -> String {
    if !value.is_finite() {
        return value.to_string();
    }
    let formatted = format!("{value:.4}");
    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
    if matches!(trimmed, "0" | "-0") {
        if value == 0.0 {
            "0".into()
        } else {
            value.to_string()
        }
    } else {
        trimmed.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DeviceKey {
        DeviceKey { bus: 1, mac_id: 3 }
    }

    fn field<'a>(decoded: &'a AttributeDecode, name: &str) -> Option<&'a DecodedField> {
        decoded.fields.iter().find(|field| field.name == name)
    }

    fn get(
        state: &mut MfcExplicitState,
        class_id: u32,
        instance_id: u32,
        attribute_id: u32,
        data: &[u8],
    ) -> AttributeDecode {
        state.decode_get_response(key(), class_id, instance_id, attribute_id, data)
    }

    #[test]
    fn decodes_identity_and_directly_required_devicenet_values() {
        let mut state = MfcExplicitState::default();
        let vendor = get(&mut state, 1, 1, 1, &1813u16.to_le_bytes());
        assert!(
            field(&vendor, "Vendor ID")
                .unwrap()
                .value
                .contains("BLUE DYNAMICS")
        );

        let product = get(&mut state, 1, 1, 3, &101u16.to_le_bytes());
        assert_eq!(
            field(&product, "Product code").unwrap().value,
            "101 (0x0065)"
        );

        let baud = get(&mut state, 3, 1, 2, &[2]);
        assert!(
            field(&baud, "Baud rate")
                .unwrap()
                .value
                .contains("500 kbit/s")
        );

        let connection = get(&mut state, 5, 2, 9, &1000u16.to_le_bytes());
        let rate = field(&connection, "Expected packet rate").unwrap();
        assert_eq!(rate.value, "1000");
        assert_eq!(rate.unit.as_deref(), Some("ms"));

        let path = get(&mut state, 5, 2, 14, &[0x20, 0x04, 0x24, 0x02, 0x30, 0x03]);
        assert_eq!(
            field(&path, "Produced connection path target")
                .unwrap()
                .value,
            "Class=0x4 (4), Instance=0x2 (2), Attribute=0x3 (3)"
        );
    }

    #[test]
    fn converts_industry_values_without_vendor_identity_gate() {
        let mut state = MfcExplicitState::default();

        get(&mut state, 0x31, 3, 3, &[TYPE_INT]);
        get(&mut state, 0x31, 3, 4, &UNIT_COUNTS.to_le_bytes());
        get(&mut state, 0x31, 3, 10, &24576i16.to_le_bytes());
        let mut temperature_scale = 100f32.to_le_bytes().to_vec();
        temperature_scale.extend_from_slice(&0x1200u16.to_le_bytes());
        get(&mut state, 0x31, 3, 0x6e, &temperature_scale);
        let temperature = get(&mut state, 0x31, 3, 6, &8247i16.to_le_bytes());
        let engineering = field(&temperature, "Temperature engineering value").unwrap();
        assert_eq!(engineering.value, "33.5571");
        assert_eq!(engineering.unit.as_deref(), Some("°C"));

        get(&mut state, 0x31, 1, 3, &[TYPE_INT]);
        get(&mut state, 0x31, 1, 4, &UNIT_COUNTS.to_le_bytes());
        get(&mut state, 0x31, 1, 10, &24576i16.to_le_bytes());
        let mut flow_scale = 10_000f32.to_le_bytes().to_vec();
        flow_scale.extend_from_slice(&0x1400u16.to_le_bytes());
        get(&mut state, 0x31, 1, 0x6e, &flow_scale);
        get(&mut state, 0x33, 1, 3, &[TYPE_INT]);
        get(&mut state, 0x33, 1, 4, &UNIT_COUNTS.to_le_bytes());
        let setpoint = get(&mut state, 0x33, 1, 6, &4369i16.to_le_bytes());
        assert_eq!(
            field(&setpoint, "Setpoint percent of full scale")
                .unwrap()
                .value,
            "17.7775"
        );
        assert_eq!(
            field(&setpoint, "Setpoint engineering value")
                .unwrap()
                .value,
            "1777.7507"
        );
    }

    #[test]
    fn set_context_changes_only_after_explicit_commit() {
        let mut state = MfcExplicitState::default();
        get(&mut state, 0x31, 1, 3, &[TYPE_INT]);

        let pending = state.decode_set_request(key(), 0x31, 1, 3, &[TYPE_REAL]);
        let before_commit = get(&mut state, 0x31, 1, 6, &7i16.to_le_bytes());
        assert_eq!(field(&before_commit, "Flow").unwrap().value, "7");

        state.commit(pending.pending_update.unwrap());
        let after_commit = get(&mut state, 0x31, 1, 6, &12.5f32.to_le_bytes());
        assert_eq!(field(&after_commit, "Flow").unwrap().value, "12.5");
        assert_eq!(
            field(&after_commit, "Flow").unwrap().unit.as_deref(),
            Some("unit not observed")
        );
    }

    #[test]
    fn configured_scale_is_industry_defined_and_gas_instances_stop_at_five() {
        let mut state = MfcExplicitState::default();
        let mut scale = 100f32.to_le_bytes().to_vec();
        scale.extend_from_slice(&UNIT_CELSIUS.to_le_bytes());
        let configured = get(&mut state, 0x31, 3, 0x6e, &scale);
        assert_eq!(
            field(&configured, "Configured full scale").unwrap().value,
            "100"
        );

        let gas_five = get(&mut state, 0x34, 5, 3, &13u16.to_le_bytes());
        assert_eq!(field(&gas_five, "Gas number").unwrap().value, "13 - N2");
        let gas_six = get(&mut state, 0x34, 6, 3, &13u16.to_le_bytes());
        assert!(gas_six.fields.is_empty());

        let encoded_date = get(&mut state, 0x34, 1, 8, &18993u16.to_le_bytes());
        assert_eq!(
            field(&encoded_date, "Calibration date").unwrap().value,
            "2024-01-01 (18993 days since 1972-01-01)"
        );

        let date = get(&mut state, 0x34, 1, 8, b"\x0a01/01/2025");
        assert_eq!(
            field(&date, "Calibration date").unwrap().value,
            "01/01/2025"
        );
        assert!(
            date.warnings
                .iter()
                .any(|warning| warning.contains("conflicts"))
        );
    }

    #[test]
    fn describes_table_targets_and_infers_unobserved_dynamic_types_for_display() {
        let mut state = MfcExplicitState::default();
        let request = state.describe_get_request(0x31, 1, 6);
        assert_eq!(
            field(&request, "Read target").unwrap().value,
            "Flow sensor / Flow (Class 0x31, Instance 1, Attribute 0x06)"
        );
        assert!(state.describe_get_request(0x30, 1, 25).fields.is_empty());

        let flow_int = get(&mut state, 0x31, 1, 6, &123i16.to_le_bytes());
        assert_eq!(field(&flow_int, "Flow").unwrap().value, "123");
        assert_eq!(
            field(&flow_int, "Flow").unwrap().unit.as_deref(),
            Some("unit not observed")
        );
        assert!(
            flow_int
                .warnings
                .iter()
                .any(|warning| warning.contains("inferred from this payload length"))
        );

        let flow_real = get(&mut state, 0x31, 1, 6, &12.5f32.to_le_bytes());
        assert_eq!(field(&flow_real, "Flow").unwrap().value, "12.5");

        let setpoint = state.decode_set_request(key(), 0x33, 1, 6, &321i16.to_le_bytes());
        assert_eq!(
            field(&setpoint, "Write target").unwrap().value,
            "Flow controller / Setpoint (Class 0x33, Instance 1, Attribute 0x06)"
        );
        assert_eq!(field(&setpoint, "Setpoint").unwrap().value, "321");
    }

    #[test]
    fn enforces_table_write_access_and_does_not_commit_read_only_context() {
        let state = MfcExplicitState::default();
        let writable = state.decode_set_request(key(), 0x31, 1, 3, &[TYPE_REAL]);
        assert!(writable.pending_update.is_some());
        assert!(
            writable
                .warnings
                .iter()
                .all(|warning| !warning.contains("read-only"))
        );

        let read_only = state.decode_set_request(key(), 0x31, 1, 10, &100i16.to_le_bytes());
        assert!(read_only.pending_update.is_none());
        assert!(
            read_only
                .warnings
                .iter()
                .any(|warning| warning.contains("read-only"))
        );
        assert_eq!(
            field(&read_only, "Write target").unwrap().value,
            "Flow sensor / Numeric full scale (Class 0x31, Instance 1, Attribute 0x0A)"
        );

        assert!(explicit_attribute(0x05, 1, 9).unwrap().writable);
        assert!(!explicit_attribute(0x05, 1, 14).unwrap().writable);
        assert!(explicit_attribute(0x05, 2, 14).unwrap().writable);
        assert!(!explicit_attribute(0x34, 1, 6).unwrap().writable);
    }

    #[test]
    fn rejects_incompatible_units_and_invalidates_stale_numeric_context() {
        let mut state = MfcExplicitState::default();
        get(&mut state, 0x31, 1, 3, &[TYPE_INT]);
        get(&mut state, 0x31, 1, 4, &UNIT_COUNTS.to_le_bytes());
        get(&mut state, 0x31, 1, 10, &24576i16.to_le_bytes());

        let invalid_unit = get(&mut state, 0x31, 1, 4, &UNIT_CELSIUS.to_le_bytes());
        assert!(
            invalid_unit
                .warnings
                .iter()
                .any(|warning| warning.contains("incompatible"))
        );
        let numeric = state
            .devices
            .get(&key())
            .unwrap()
            .numeric
            .get(&(0x31, 1))
            .unwrap();
        assert_eq!(numeric.units, None);
        assert_eq!(numeric.numeric_full_scale, None);

        let invalid_type = get(&mut state, 0x31, 1, 3, &[TYPE_USINT]);
        assert!(
            invalid_type
                .warnings
                .iter()
                .any(|warning| warning.contains("unsupported Data Type"))
        );
        assert_eq!(
            state
                .devices
                .get(&key())
                .unwrap()
                .numeric
                .get(&(0x31, 1))
                .unwrap()
                .data_type,
            None
        );

        let mut wrong_scale = 100f32.to_le_bytes().to_vec();
        wrong_scale.extend_from_slice(&UNIT_CELSIUS.to_le_bytes());
        let configured = get(&mut state, 0x31, 1, 0x6e, &wrong_scale);
        assert!(
            configured
                .warnings
                .iter()
                .any(|warning| warning.contains("incompatible"))
        );
    }

    #[test]
    fn non_finite_real_is_displayed_but_never_used_for_conversion() {
        let mut state = MfcExplicitState::default();
        get(&mut state, 0x31, 1, 3, &[TYPE_REAL]);
        get(&mut state, 0x31, 1, 4, &UNIT_COUNTS.to_le_bytes());
        get(&mut state, 0x31, 1, 10, &100f32.to_le_bytes());
        let mut scale = 1000f32.to_le_bytes().to_vec();
        scale.extend_from_slice(&UNIT_SCCM.to_le_bytes());
        get(&mut state, 0x31, 1, 0x6e, &scale);

        let value = get(&mut state, 0x31, 1, 6, &f32::NAN.to_le_bytes());
        assert_eq!(field(&value, "Flow").unwrap().value, "NaN");
        assert!(field(&value, "Flow engineering value").is_none());
        assert!(
            value
                .warnings
                .iter()
                .any(|warning| warning.contains("non-finite REAL"))
        );

        let full_scale = get(&mut state, 0x31, 1, 10, &f32::INFINITY.to_le_bytes());
        assert!(
            full_scale
                .warnings
                .iter()
                .any(|warning| warning.contains("invalidated"))
        );
        assert_eq!(
            state
                .devices
                .get(&key())
                .unwrap()
                .numeric
                .get(&(0x31, 1))
                .unwrap()
                .numeric_full_scale,
            None
        );
    }

    #[test]
    fn number_formatting_does_not_round_nonzero_values_to_zero() {
        assert_eq!(format_number(0.00001), "0.00001");
        assert_eq!(format_number(-0.00001), "-0.00001");
        assert_eq!(calendar_date_from_1972(0), "1972-01-01");
        assert_eq!(calendar_date_from_1972(59), "1972-02-29");
    }
}
