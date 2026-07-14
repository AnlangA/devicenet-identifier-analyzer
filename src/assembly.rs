//! DeviceNet Mass Flow Controller I/O Assembly metadata and payload decoding.
//!
//! The layouts in this module combine the standard Mass Flow Controller (MFC)
//! assemblies from Volume 1, section 6-29, with the Enhanced Mass Flow
//! Controller (EMFC) assemblies from section 6-39. Multi-byte values use CIP
//! little-endian byte order. Engineering units remain device-configured; an I/O
//! payload alone does not identify the active unit configuration.

/// Direction of an I/O Assembly from the host's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoAssemblyDirection {
    /// Data produced by a device and consumed by the host.
    Input,
    /// Data produced by the host and consumed by a device.
    Output,
}

impl IoAssemblyDirection {
    /// Short, user-facing direction label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Input => "Input",
            Self::Output => "Output",
        }
    }
}

/// Numeric family selected by an Assembly connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoAssemblyNumericFormat {
    Int,
    Real,
    NoNumericValue,
}

impl IoAssemblyNumericFormat {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Int => "INT",
            Self::Real => "REAL",
            Self::NoNumericValue => "status/exception only",
        }
    }

    pub const fn is_compatible_with(self, other: Self) -> bool {
        matches!(self, Self::NoNumericValue)
            || matches!(other, Self::NoNumericValue)
            || matches!(
                (self, other),
                (Self::Int, Self::Int) | (Self::Real, Self::Real)
            )
    }
}

/// Supported profile or supplied device-table I/O Assembly instance metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoAssemblyInstance {
    pub number: u8,
    pub direction: IoAssemblyDirection,
    pub name: &'static str,
    pub profile: &'static str,
    /// Fixed Produced/Consumed Connection Size declared for this static
    /// Assembly mapping. DeviceNet I/O fragmentation is required when this
    /// selected connection size exceeds one eight-byte CAN data field.
    pub byte_len: usize,
    /// Required/default metadata copied from Tables 6-29.6 and 6-39.6.
    /// `N` means optional, not unsupported.
    pub requirements: &'static str,
}

impl IoAssemblyInstance {
    pub const fn numeric_format(&self) -> IoAssemblyNumericFormat {
        match self.number {
            1..=8 | 21 | 22 | 150..=152 => IoAssemblyNumericFormat::Int,
            13..=20 | 23 | 24 => IoAssemblyNumericFormat::Real,
            9..=12 | 25 => IoAssemblyNumericFormat::NoNumericValue,
            _ => IoAssemblyNumericFormat::NoNumericValue,
        }
    }
}

/// One decoded component of an I/O Assembly payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoAssemblyComponent {
    pub name: String,
    pub value: String,
    pub unit: String,
    pub description: String,
}

/// Decoded I/O Assembly components and non-fatal payload warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoAssemblyDecode {
    pub components: Vec<IoAssemblyComponent>,
    pub warnings: Vec<String>,
}

const MFC_EMFC: &str = "Vol1 6-29 MFC / 6-39 EMFC/EMFM";
const MFC: &str = "Vol1 6-29 MFC";
const EMFC: &str = "Vol1 6-39 EMFC/EMFM";
const SUPPLIED_DEVICE_TABLE: &str = "MFC/EMFC user-provided device table / R02 mapping";

const REQ_ALL_N: &str = "6-29 MFC: optional (N) · 6-39 EMFC: optional (N) · EMFM: optional (N)";
const REQ_ALL_DEFAULT: &str = "6-29 MFC: default (D) · 6-39 EMFC: default (D) · EMFM: default (D)";
const REQ_MFC_EMFC_Y_EMFM_N: &str =
    "6-29 MFC: required (Y) · 6-39 EMFC: required (Y) · EMFM: optional (N)";
const REQ_ALL_Y: &str = "6-29 MFC: required (Y) · 6-39 EMFC: required (Y) · EMFM: required (Y)";
const REQ_MFC_N_639_UNUSED: &str = "6-29 MFC: optional (N) · 6-39 EMFC/EMFM: Assembly not used";
const REQ_EMFC_EMFM_Y: &str = "6-39 EMFC: required (Y) · EMFM: required (Y)";
const REQ_EMFC_EMFM_N: &str = "6-39 EMFC: optional (N) · EMFM: optional (N)";
const DEVICE_TABLE_POLL: &str = "User-provided device table: declared Poll-compatible Assembly";

/// Supported device-to-host I/O Assembly instances.
pub const INPUT_ASSEMBLIES: &[IoAssemblyInstance] = &[
    IoAssemblyInstance {
        number: 1,
        direction: IoAssemblyDirection::Input,
        name: "Flow",
        profile: MFC_EMFC,
        byte_len: 2,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 2,
        direction: IoAssemblyDirection::Input,
        name: "Status and Flow",
        profile: MFC_EMFC,
        byte_len: 3,
        requirements: REQ_ALL_DEFAULT,
    },
    IoAssemblyInstance {
        number: 3,
        direction: IoAssemblyDirection::Input,
        name: "Status, Flow and Valve",
        profile: MFC_EMFC,
        byte_len: 5,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 4,
        direction: IoAssemblyDirection::Input,
        name: "Status, Flow, and Setpoint",
        profile: MFC_EMFC,
        byte_len: 5,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 5,
        direction: IoAssemblyDirection::Input,
        name: "Status, Flow, Setpoint and Valve",
        profile: MFC_EMFC,
        byte_len: 7,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 6,
        direction: IoAssemblyDirection::Input,
        name: "Status, Flow, Setpoint, Override and Valve",
        profile: MFC_EMFC,
        byte_len: 8,
        requirements: REQ_MFC_EMFC_Y_EMFM_N,
    },
    IoAssemblyInstance {
        number: 9,
        direction: IoAssemblyDirection::Input,
        name: "Status",
        profile: MFC_EMFC,
        byte_len: 1,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 10,
        direction: IoAssemblyDirection::Input,
        name: "Exception Detail Alarm",
        profile: MFC,
        byte_len: 8,
        requirements: REQ_MFC_N_639_UNUSED,
    },
    IoAssemblyInstance {
        number: 11,
        direction: IoAssemblyDirection::Input,
        name: "Exception Detail Warning",
        profile: MFC,
        byte_len: 8,
        requirements: REQ_MFC_N_639_UNUSED,
    },
    IoAssemblyInstance {
        number: 12,
        direction: IoAssemblyDirection::Input,
        name: "Exception Detail Alarm and Exception Detail Warning",
        profile: MFC,
        byte_len: 15,
        requirements: REQ_MFC_N_639_UNUSED,
    },
    IoAssemblyInstance {
        number: 13,
        direction: IoAssemblyDirection::Input,
        name: "FP-Flow",
        profile: MFC_EMFC,
        byte_len: 4,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 14,
        direction: IoAssemblyDirection::Input,
        name: "Status and FP-Flow",
        profile: MFC_EMFC,
        byte_len: 5,
        requirements: REQ_ALL_Y,
    },
    IoAssemblyInstance {
        number: 15,
        direction: IoAssemblyDirection::Input,
        name: "Status, FP-Flow and FP-Valve",
        profile: MFC_EMFC,
        byte_len: 9,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 16,
        direction: IoAssemblyDirection::Input,
        name: "Status, FP-Flow and FP-Setpoint",
        profile: MFC_EMFC,
        byte_len: 9,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 17,
        direction: IoAssemblyDirection::Input,
        name: "Status, FP-Flow, FP-Setpoint and FP-Valve",
        profile: MFC_EMFC,
        byte_len: 13,
        requirements: REQ_ALL_N,
    },
    IoAssemblyInstance {
        number: 18,
        direction: IoAssemblyDirection::Input,
        name: "Status, FP-Flow, FP-Setpoint, Override and FP-Valve",
        profile: MFC_EMFC,
        byte_len: 14,
        requirements: REQ_MFC_EMFC_Y_EMFM_N,
    },
    IoAssemblyInstance {
        number: 21,
        direction: IoAssemblyDirection::Input,
        name: "Status, Flow, Pressure and Temperature",
        profile: EMFC,
        byte_len: 7,
        requirements: REQ_EMFC_EMFM_Y,
    },
    IoAssemblyInstance {
        number: 22,
        direction: IoAssemblyDirection::Input,
        name: "Status, Flow, Valve, Pressure and Temperature",
        profile: EMFC,
        byte_len: 9,
        requirements: REQ_EMFC_EMFM_N,
    },
    IoAssemblyInstance {
        number: 23,
        direction: IoAssemblyDirection::Input,
        name: "Status, FP-Flow, FP-Pressure and FP-Temperature",
        profile: EMFC,
        byte_len: 13,
        requirements: REQ_EMFC_EMFM_Y,
    },
    IoAssemblyInstance {
        number: 24,
        direction: IoAssemblyDirection::Input,
        name: "Status, FP-Flow, FP-Valve, FP-Pressure and FP-Temperature",
        profile: EMFC,
        byte_len: 17,
        requirements: REQ_EMFC_EMFM_N,
    },
    IoAssemblyInstance {
        number: 25,
        direction: IoAssemblyDirection::Input,
        name: "Exception Detail Alarm and Exception Detail Warning",
        profile: EMFC,
        byte_len: 17,
        requirements: REQ_EMFC_EMFM_N,
    },
    IoAssemblyInstance {
        number: 150,
        direction: IoAssemblyDirection::Input,
        name: "Flow, Valve, Temperature and Pressure",
        profile: SUPPLIED_DEVICE_TABLE,
        byte_len: 8,
        requirements: "R02 I/O mapping from the user-provided device table",
    },
    IoAssemblyInstance {
        number: 151,
        direction: IoAssemblyDirection::Input,
        name: "Flow, Valve and Temperature",
        profile: SUPPLIED_DEVICE_TABLE,
        byte_len: 6,
        requirements: DEVICE_TABLE_POLL,
    },
];

/// Supported host-to-device I/O Assembly instances.
pub const OUTPUT_ASSEMBLIES: &[IoAssemblyInstance] = &[
    IoAssemblyInstance {
        number: 7,
        direction: IoAssemblyDirection::Output,
        name: "Setpoint",
        profile: MFC_EMFC,
        byte_len: 2,
        requirements: "6-29 MFC: default (D) · 6-39 EMFC: default (D) · EMFM: optional (N)",
    },
    IoAssemblyInstance {
        number: 8,
        direction: IoAssemblyDirection::Output,
        name: "Override and Setpoint",
        profile: MFC_EMFC,
        byte_len: 3,
        requirements: REQ_MFC_EMFC_Y_EMFM_N,
    },
    IoAssemblyInstance {
        number: 19,
        direction: IoAssemblyDirection::Output,
        name: "FP-Setpoint",
        profile: MFC_EMFC,
        byte_len: 4,
        requirements: REQ_MFC_EMFC_Y_EMFM_N,
    },
    IoAssemblyInstance {
        number: 20,
        direction: IoAssemblyDirection::Output,
        name: "Override and FP-Setpoint",
        profile: MFC_EMFC,
        byte_len: 5,
        requirements: REQ_MFC_EMFC_Y_EMFM_N,
    },
    IoAssemblyInstance {
        number: 152,
        direction: IoAssemblyDirection::Output,
        name: "Override and Valve",
        profile: SUPPLIED_DEVICE_TABLE,
        byte_len: 3,
        requirements: DEVICE_TABLE_POLL,
    },
];

/// Looks up a supported Assembly instance in the requested direction.
pub fn assembly_instance(
    direction: IoAssemblyDirection,
    number: u8,
) -> Option<&'static IoAssemblyInstance> {
    let instances = match direction {
        IoAssemblyDirection::Input => INPUT_ASSEMBLIES,
        IoAssemblyDirection::Output => OUTPUT_ASSEMBLIES,
    };
    instances.iter().find(|instance| instance.number == number)
}

/// Decodes a standard MFC/EMFC I/O Assembly payload.
///
/// A short payload produces every complete leading component and a warning. A
/// long payload decodes the standard prefix and reports ignored trailing bytes.
/// Direction/instance mismatches are returned as errors.
pub fn decode_assembly(
    direction: IoAssemblyDirection,
    instance: u8,
    payload: &[u8],
) -> Result<IoAssemblyDecode, String> {
    let metadata = assembly_instance(direction, instance).ok_or_else(|| {
        format!(
            "{} I/O Assembly instance {} is not defined by the supported MFC/EMFC profiles or user-provided device table",
            direction.label(),
            instance
        )
    })?;

    let mut cursor = DecodeCursor::new(payload);
    decode_layout(direction, instance, &mut cursor)?;

    let mut warnings = Vec::new();
    if payload.len() < metadata.byte_len {
        warnings.push(format!(
            "{} Assembly instance {} expects {} bytes, but the payload contains {}; only complete leading components were decoded",
            direction.label(),
            instance,
            metadata.byte_len,
            payload.len()
        ));
    } else if payload.len() > metadata.byte_len {
        warnings.push(format!(
            "{} Assembly instance {} expects {} bytes, but the payload contains {}; {} trailing byte(s) were ignored",
            direction.label(),
            instance,
            metadata.byte_len,
            payload.len(),
            payload.len() - metadata.byte_len
        ));
    }
    warnings.extend(validate_exception_sizes(direction, instance, payload));

    Ok(IoAssemblyDecode {
        components: cursor.components,
        warnings,
    })
}

fn validate_exception_sizes(
    direction: IoAssemblyDirection,
    instance: u8,
    payload: &[u8],
) -> Vec<String> {
    if direction != IoAssemblyDirection::Input {
        return Vec::new();
    }
    let (bases, device_size): (&[usize], u8) = match instance {
        10 | 11 => (&[1], 1),
        12 => (&[1, 8], 1),
        25 => (&[1, 9], 2),
        _ => return Vec::new(),
    };
    let mut warnings = Vec::new();
    for base in bases {
        for (relative_offset, expected, section) in [
            (0, 2, "common"),
            (3, device_size, "device"),
            (4 + usize::from(device_size), 1, "manufacturer"),
        ] {
            let Some(value) = payload.get(base + relative_offset).copied() else {
                continue;
            };
            if value != 0 && value != expected {
                warnings.push(format!(
                    "Exception Detail {section} size is {value}; the selected profile reserves {expected} byte(s), or 0 when that detail is not implemented"
                ));
            }
        }
    }
    warnings
}

fn decode_layout(
    direction: IoAssemblyDirection,
    instance: u8,
    cursor: &mut DecodeCursor<'_>,
) -> Result<(), String> {
    use IoAssemblyDirection::{Input, Output};

    match (direction, instance) {
        (Input, 1) => flow_i16(cursor),
        (Input, 2) => {
            status(cursor);
            flow_i16(cursor);
        }
        (Input, 3) => {
            status(cursor);
            flow_i16(cursor);
            valve_i16(cursor);
        }
        (Input, 4) => {
            status(cursor);
            flow_i16(cursor);
            setpoint_i16(cursor);
        }
        (Input, 5) => {
            status(cursor);
            flow_i16(cursor);
            setpoint_i16(cursor);
            valve_i16(cursor);
        }
        (Input, 6) => {
            status(cursor);
            flow_i16(cursor);
            setpoint_i16(cursor);
            override_value(cursor);
            valve_i16(cursor);
        }
        (Input, 9) => status(cursor),
        (Input, 10) => {
            status(cursor);
            exception_detail(cursor, ExceptionKind::Alarm, ExceptionProfile::Mfc);
        }
        (Input, 11) => {
            status(cursor);
            exception_detail(cursor, ExceptionKind::Warning, ExceptionProfile::Mfc);
        }
        (Input, 12) => {
            status(cursor);
            exception_detail(cursor, ExceptionKind::Alarm, ExceptionProfile::Mfc);
            exception_detail(cursor, ExceptionKind::Warning, ExceptionProfile::Mfc);
        }
        (Input, 13) => flow_f32(cursor),
        (Input, 14) => {
            status(cursor);
            flow_f32(cursor);
        }
        (Input, 15) => {
            status(cursor);
            flow_f32(cursor);
            valve_f32(cursor);
        }
        (Input, 16) => {
            status(cursor);
            flow_f32(cursor);
            setpoint_f32(cursor);
        }
        (Input, 17) => {
            status(cursor);
            flow_f32(cursor);
            setpoint_f32(cursor);
            valve_f32(cursor);
        }
        (Input, 18) => {
            status(cursor);
            flow_f32(cursor);
            setpoint_f32(cursor);
            override_value(cursor);
            valve_f32(cursor);
        }
        (Input, 21) => {
            status(cursor);
            flow_i16(cursor);
            pressure_i16(cursor);
            temperature_i16(cursor);
        }
        (Input, 22) => {
            status(cursor);
            flow_i16(cursor);
            valve_i16(cursor);
            pressure_i16(cursor);
            temperature_i16(cursor);
        }
        (Input, 23) => {
            status(cursor);
            flow_f32(cursor);
            pressure_f32(cursor);
            temperature_f32(cursor);
        }
        (Input, 24) => {
            status(cursor);
            flow_f32(cursor);
            valve_f32(cursor);
            // Table 6-39.7 prints "Pressure (high value)" at byte 12;
            // the surrounding four-byte REAL sequence makes this its high byte.
            pressure_f32(cursor);
            temperature_f32(cursor);
        }
        (Input, 25) => {
            status(cursor);
            exception_detail(cursor, ExceptionKind::Alarm, ExceptionProfile::Emfc);
            exception_detail(cursor, ExceptionKind::Warning, ExceptionProfile::Emfc);
        }
        (Input, 150) => {
            device_table_flow_i16(cursor);
            device_table_valve_i16(cursor);
            device_table_temperature_i16(cursor);
            device_table_pressure_i16(cursor);
        }
        (Input, 151) => {
            device_table_flow_i16(cursor);
            device_table_valve_i16(cursor);
            device_table_temperature_i16(cursor);
        }
        (Output, 7) => setpoint_i16(cursor),
        (Output, 8) => {
            override_value(cursor);
            setpoint_i16(cursor);
        }
        (Output, 19) => setpoint_f32(cursor),
        (Output, 20) => {
            override_value(cursor);
            setpoint_f32(cursor);
        }
        (Output, 152) => {
            device_table_override_value(cursor);
            device_table_valve_i16(cursor);
        }
        _ => {
            return Err(format!(
                "{} I/O Assembly instance {} has no payload layout",
                direction.label(),
                instance
            ));
        }
    }
    Ok(())
}

struct DecodeCursor<'a> {
    payload: &'a [u8],
    offset: usize,
    truncated: bool,
    components: Vec<IoAssemblyComponent>,
}

impl<'a> DecodeCursor<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            offset: 0,
            truncated: false,
            components: Vec::new(),
        }
    }

    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.truncated || self.offset.saturating_add(N) > self.payload.len() {
            self.truncated = true;
            return None;
        }
        let mut bytes = [0; N];
        bytes.copy_from_slice(&self.payload[self.offset..self.offset + N]);
        self.offset += N;
        Some(bytes)
    }

    fn push_u8(
        &mut self,
        name: impl Into<String>,
        unit: impl Into<String>,
        description: impl Into<String>,
        format_value: impl FnOnce(u8) -> String,
    ) {
        if let Some([value]) = self.take::<1>() {
            self.components.push(IoAssemblyComponent {
                name: name.into(),
                value: format_value(value),
                unit: unit.into(),
                description: description.into(),
            });
        }
    }

    fn push_i16(&mut self, name: &'static str, unit: &'static str, description: &'static str) {
        if let Some(bytes) = self.take::<2>() {
            self.components.push(IoAssemblyComponent {
                name: name.into(),
                value: i16::from_le_bytes(bytes).to_string(),
                unit: unit.into(),
                description: description.into(),
            });
        }
    }

    fn push_f32(&mut self, name: &'static str, unit: &'static str, description: &'static str) {
        if let Some(bytes) = self.take::<4>() {
            self.components.push(IoAssemblyComponent {
                name: name.into(),
                value: f32::from_le_bytes(bytes).to_string(),
                unit: unit.into(),
                description: description.into(),
            });
        }
    }
}

const STATUS_DESCRIPTION: &str = "Exception Status BYTE mapped to the S-Device Supervisor Object class 0x30, instance 1, attribute 12. Bit 7 selects Basic (0) or Expanded (1). In Basic format bits 0-6 are device-specific; Sections 6-29/6-39 do not redefine them, so the decoder also shows the base profile's Expanded-map fallback.";
const OVERRIDE_DESCRIPTION: &str = "Override mapped to the S-Analog Actuator Object class 0x32, instance 1, attribute 5. Values: 0 Normal, 1 Zero, 2 Maximum Value, 3 Hold, 4 Safe State; higher ranges are reserved, device-specific, or vendor-specific.";

const FLOW_INT_DESCRIPTION: &str = "CIP INT (signed 16-bit two's-complement, little-endian) flow mapped to the S-Analog Sensor Object class 0x31, instance 1, attribute 6. The profiles require Counts and sccm support and default to Counts; the active Data Units and Full Scale values are not carried in the I/O payload.";
const FLOW_REAL_DESCRIPTION: &str = "CIP REAL (IEEE 754 binary32, little-endian) flow mapped to the S-Analog Sensor Object class 0x31, instance 1, attribute 6. The profiles require Counts and sccm support and default to Counts; the active Data Units and Full Scale values are not carried in the I/O payload.";
const VALVE_INT_DESCRIPTION: &str = "CIP INT (signed 16-bit two's-complement, little-endian) valve value mapped to the S-Analog Actuator Object class 0x32, instance 1, attribute 6. The profiles require Counts and percent support and default to Counts; the active Data Units and device-specific Counts full scale are not carried in the I/O payload.";
const VALVE_REAL_DESCRIPTION: &str = "CIP REAL (IEEE 754 binary32, little-endian) valve value mapped to the S-Analog Actuator Object class 0x32, instance 1, attribute 6. The profiles require Counts and percent support and default to Counts; the active Data Units and device-specific Counts full scale are not carried in the I/O payload.";
const SETPOINT_INT_DESCRIPTION: &str = "CIP INT (signed 16-bit two's-complement, little-endian) setpoint mapped to the S-Single Stage Controller Object class 0x33, instance 1, attribute 6. The profiles require Counts and percent support and default to Counts; the active Data Units and Full Scale values are not carried in the I/O payload.";
const SETPOINT_REAL_DESCRIPTION: &str = "CIP REAL (IEEE 754 binary32, little-endian) setpoint mapped to the S-Single Stage Controller Object class 0x33, instance 1, attribute 6. The profiles require Counts and percent support and default to Counts; the active Data Units and Full Scale values are not carried in the I/O payload.";
const PRESSURE_INT_DESCRIPTION: &str = "CIP INT (signed 16-bit two's-complement, little-endian) pressure mapped to the S-Analog Sensor Object class 0x31, instance 2, attribute 6. Section 6-39 requires Counts and psi support and defaults to Counts; the active Data Units and Full Scale values are not carried in the I/O payload.";
const PRESSURE_REAL_DESCRIPTION: &str = "CIP REAL (IEEE 754 binary32, little-endian) pressure mapped to the S-Analog Sensor Object class 0x31, instance 2, attribute 6. Section 6-39 requires Counts and psi support and defaults to Counts; the active Data Units and Full Scale values are not carried in the I/O payload.";
const TEMPERATURE_INT_DESCRIPTION: &str = "CIP INT (signed 16-bit two's-complement, little-endian) temperature mapped to the S-Analog Sensor Object class 0x31, instance 3, attribute 6. Section 6-39 does not fix one temperature unit; the active Data Units and Full Scale values must be read from the device configuration.";
const TEMPERATURE_REAL_DESCRIPTION: &str = "CIP REAL (IEEE 754 binary32, little-endian) temperature mapped to the S-Analog Sensor Object class 0x31, instance 3, attribute 6. Section 6-39 does not fix one temperature unit; the active Data Units and Full Scale values must be read from the device configuration.";
const DEVICE_TABLE_FLOW_INT_DESCRIPTION: &str = "User-provided device-table Assemblies 150/151 Flow. CIP INT (signed 16-bit two's-complement, little-endian), mapped to MFC/EMFC S-Analog Sensor class 0x31 instance 1 attribute 6. Data units are Counts (0x1001), sccm (0x1400), or SLM (0x1401). In Counts mode the documented numeric full scale is 0x6000 and engineering value = raw / 24576 × the configured full scale from class 0x31 instance 1 attribute 0x6E; engineering-unit modes carry their value directly.";
const DEVICE_TABLE_VALVE_INT_DESCRIPTION: &str = "User-provided device-table Assemblies 150-152 valve value. CIP INT (signed 16-bit two's-complement, little-endian), mapped to MFC/EMFC S-Analog Actuator class 0x32 instance 1 attribute 6. Data units are Counts (0x1001) or percent (0x1007). The supplied table defines a Counts full scale of 0x7FFF; percent = raw / 32767 × 100 when converting a Counts value.";
const DEVICE_TABLE_TEMPERATURE_INT_DESCRIPTION: &str = "User-provided device-table Assemblies 150/151 Temperature. CIP INT (signed 16-bit two's-complement, little-endian), mapped to MFC/EMFC S-Analog Sensor class 0x31 instance 3 attribute 6. Data units are Counts (0x1001), degrees Celsius (0x1200), or kelvin (0x1202). In Counts mode the documented numeric full scale is 0x6000 and conversion also requires the configured engineering full scale from class 0x31 instance 3 attribute 0x6E.";
const DEVICE_TABLE_PRESSURE_INT_DESCRIPTION: &str = "User-provided R02 Assembly 150 Pressure. CIP INT (signed 16-bit two's-complement, little-endian), mapped to MFC/EMFC S-Analog Sensor class 0x31 instance 2 attribute 6. Data units are Counts (0x1001), kPa (0x130A), psi (0x1300), or torr (0x1301). Counts conversion requires the instance 2 Numeric Full Scale and configured full scale attribute 0x6E; neither is carried in the I/O payload.";
const DEVICE_TABLE_OVERRIDE_DESCRIPTION: &str = "User-provided device-table Assembly 152 Override, mapped to MFC/EMFC S-Analog Actuator class 0x32 instance 1 attribute 5. The supplied table defines 0 Normal, 1 Close, 2 Open, and 3 Hold; values 4-255 are not defined by that table.";

fn status(cursor: &mut DecodeCursor<'_>) {
    cursor.push_u8(
        "Status",
        "bit field (BYTE)",
        STATUS_DESCRIPTION,
        format_exception_status,
    );
}

fn override_value(cursor: &mut DecodeCursor<'_>) {
    cursor.push_u8(
        "Override",
        "enumerated value (USINT)",
        OVERRIDE_DESCRIPTION,
        |value| format!("{value} ({})", override_label(value)),
    );
}

fn flow_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Flow",
        "device-configured Data Units (Vol1 default: Counts)",
        FLOW_INT_DESCRIPTION,
    );
}

fn flow_f32(cursor: &mut DecodeCursor<'_>) {
    cursor.push_f32(
        "Flow",
        "device-configured Data Units (Vol1 default: Counts)",
        FLOW_REAL_DESCRIPTION,
    );
}

fn valve_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Valve",
        "device-configured Data Units (Vol1 default: Counts)",
        VALVE_INT_DESCRIPTION,
    );
}

fn valve_f32(cursor: &mut DecodeCursor<'_>) {
    cursor.push_f32(
        "Valve",
        "device-configured Data Units (Vol1 default: Counts)",
        VALVE_REAL_DESCRIPTION,
    );
}

fn setpoint_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Setpoint",
        "device-configured Data Units (Vol1 default: Counts)",
        SETPOINT_INT_DESCRIPTION,
    );
}

fn setpoint_f32(cursor: &mut DecodeCursor<'_>) {
    cursor.push_f32(
        "Setpoint",
        "device-configured Data Units (Vol1 default: Counts)",
        SETPOINT_REAL_DESCRIPTION,
    );
}

fn pressure_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Pressure",
        "device-configured Data Units (Vol1 default: Counts)",
        PRESSURE_INT_DESCRIPTION,
    );
}

fn pressure_f32(cursor: &mut DecodeCursor<'_>) {
    cursor.push_f32(
        "Pressure",
        "device-configured Data Units (Vol1 default: Counts)",
        PRESSURE_REAL_DESCRIPTION,
    );
}

fn temperature_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Temperature",
        "device-configured Data Units (not present in payload)",
        TEMPERATURE_INT_DESCRIPTION,
    );
}

fn temperature_f32(cursor: &mut DecodeCursor<'_>) {
    cursor.push_f32(
        "Temperature",
        "device-configured Data Units (not present in payload)",
        TEMPERATURE_REAL_DESCRIPTION,
    );
}

fn device_table_flow_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Flow",
        "device-configured Data Units (table default: Counts)",
        DEVICE_TABLE_FLOW_INT_DESCRIPTION,
    );
}

fn device_table_valve_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Valve",
        "device-configured Data Units (table default: Counts)",
        DEVICE_TABLE_VALVE_INT_DESCRIPTION,
    );
}

fn device_table_temperature_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Temperature",
        "device-configured Data Units (table default: Counts)",
        DEVICE_TABLE_TEMPERATURE_INT_DESCRIPTION,
    );
}

fn device_table_pressure_i16(cursor: &mut DecodeCursor<'_>) {
    cursor.push_i16(
        "Pressure",
        "device-configured Data Units (table default: Counts)",
        DEVICE_TABLE_PRESSURE_INT_DESCRIPTION,
    );
}

fn device_table_override_value(cursor: &mut DecodeCursor<'_>) {
    cursor.push_u8(
        "Override",
        "enumerated value (USINT)",
        DEVICE_TABLE_OVERRIDE_DESCRIPTION,
        |value| format!("{value} ({})", device_table_override_label(value)),
    );
}

fn format_exception_status(value: u8) -> String {
    let flags = format_flags(
        value,
        &[
            (0x40, "manufacturer warning"),
            (0x20, "device warning"),
            (0x10, "common warning"),
            (0x08, "reserved bit 3 set"),
            (0x04, "manufacturer alarm"),
            (0x02, "device alarm"),
            (0x01, "common alarm"),
        ],
    );
    if value & 0x80 == 0 {
        return format!(
            "0x{value:02X} (Basic; bits 0-6 are device-specific, 6-29/6-39 fallback Expanded map: {flags})"
        );
    }

    format!("0x{value:02X} (Expanded; {flags})")
}

fn format_flags(value: u8, definitions: &[(u8, &'static str)]) -> String {
    let flags = definitions
        .iter()
        .filter_map(|(mask, label)| (value & mask != 0).then_some(*label))
        .collect::<Vec<_>>();
    if flags.is_empty() {
        "no flags set".into()
    } else {
        flags.join(", ")
    }
}

fn format_flag_byte(value: u8, definitions: &[(u8, &'static str)]) -> String {
    format!("0x{value:02X} ({})", format_flags(value, definitions))
}

fn override_label(value: u8) -> &'static str {
    match value {
        0 => "Normal",
        1 => "Zero",
        2 => "Maximum Value",
        3 => "Hold",
        4 => "Safe State",
        5..=63 => "Reserved",
        64..=127 => "Device-specific",
        128..=255 => "Vendor-specific",
    }
}

fn device_table_override_label(value: u8) -> &'static str {
    match value {
        0 => "Normal",
        1 => "Close",
        2 => "Open",
        3 => "Hold",
        4..=255 => "Undefined by supplied device table",
    }
}

#[derive(Clone, Copy)]
enum ExceptionKind {
    Alarm,
    Warning,
}

impl ExceptionKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Alarm => "Alarm",
            Self::Warning => "Warning",
        }
    }

    const fn attribute(self) -> u8 {
        match self {
            Self::Alarm => 13,
            Self::Warning => 14,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExceptionProfile {
    Mfc,
    Emfc,
}

fn exception_detail(cursor: &mut DecodeCursor<'_>, kind: ExceptionKind, profile: ExceptionProfile) {
    exception_size(cursor, kind, "common");
    exception_common_byte(cursor, kind, 0);
    exception_common_byte(cursor, kind, 1);
    exception_size(cursor, kind, "device");
    exception_device_byte(cursor, kind, profile, 0);
    if profile == ExceptionProfile::Emfc {
        exception_device_byte(cursor, kind, profile, 1);
    }
    exception_size(cursor, kind, "manufacturer");
    exception_raw_byte(
        cursor,
        kind,
        "manufacturer",
        0,
        "Raw manufacturer-specific exception-detail byte 0.",
    );
}

fn exception_common_byte(cursor: &mut DecodeCursor<'_>, kind: ExceptionKind, index: u8) {
    const BYTE_0: &[(u8, &str)] = &[
        (0x01, "Internal diagnostic exception"),
        (0x02, "Microprocessor exception"),
        (0x04, "EPROM exception"),
        (0x08, "EEPROM exception"),
        (0x10, "RAM exception"),
        (0x20, "reserved by CIP bit 5 set"),
        (0x40, "Internal real-time exception"),
        (0x80, "reserved by CIP bit 7 set"),
    ];
    const BYTE_1: &[(u8, &str)] = &[
        (0x01, "power supply overcurrent"),
        (0x02, "reserved power supply condition"),
        (0x04, "power supply output voltage"),
        (0x08, "power supply input voltage"),
        (0x10, "scheduled maintenance due"),
        (0x20, "notify manufacturer"),
        (0x40, "reset exception"),
        (0x80, "reserved by CIP bit 7 set"),
    ];
    let definitions = if index == 0 { BYTE_0 } else { BYTE_1 };
    let label = kind.label();
    cursor.push_u8(
        format!("{label} common detail byte {index}"),
        "bit field (BYTE)",
        format!(
            "{label} Exception Detail STRUCT mapped to the S-Device Supervisor Object class 0x30, instance 1, attribute {}. Common Exception Detail byte {index}; each displayed flag means that condition is present.",
            kind.attribute()
        ),
        |value| format_flag_byte(value, definitions),
    );
}

fn exception_size(cursor: &mut DecodeCursor<'_>, kind: ExceptionKind, section: &'static str) {
    let label = kind.label();
    cursor.push_u8(
        format!("{label} {section} detail size"),
        "bytes",
        format!(
            "{label} Exception Detail STRUCT mapped to the S-Device Supervisor Object class 0x30, instance 1, attribute {}; fixed-offset {section}-detail size field.",
            kind.attribute()
        ),
        |value| value.to_string(),
    );
}

fn exception_raw_byte(
    cursor: &mut DecodeCursor<'_>,
    kind: ExceptionKind,
    section: &'static str,
    index: u8,
    detail: &'static str,
) {
    let label = kind.label();
    cursor.push_u8(
        format!("{label} {section} detail byte {index}"),
        "bit field (BYTE)",
        format!(
            "{label} Exception Detail STRUCT mapped to the S-Device Supervisor Object class 0x30, instance 1, attribute {}. {detail}",
            kind.attribute()
        ),
        |value| format!("0x{value:02X}"),
    );
}

fn exception_device_byte(
    cursor: &mut DecodeCursor<'_>,
    kind: ExceptionKind,
    profile: ExceptionProfile,
    index: u8,
) {
    let label = kind.label();
    const MFC_ALARM: &[(u8, &str)] = &[
        (0x01, "reserved Alarm bit 0 set"),
        (0x02, "Flow Low"),
        (0x04, "Flow High"),
        (0x08, "Flow Control"),
        (0x10, "Valve Low"),
        (0x20, "Valve High"),
        (0x40, "reserved bit 6 set"),
        (0x80, "reserved bit 7 set"),
    ];
    const MFC_WARNING: &[(u8, &str)] = &[
        (0x01, "Reading Valid"),
        (0x02, "Flow Low"),
        (0x04, "Flow High"),
        (0x08, "Flow Control"),
        (0x10, "Valve Low"),
        (0x20, "Valve High"),
        (0x40, "reserved bit 6 set"),
        (0x80, "reserved bit 7 set"),
    ];
    const EMFC_WARNING: &[(u8, &str)] = &[
        (0x01, "Not Reading Valid"),
        (0x02, "Flow Low"),
        (0x04, "Flow High"),
        (0x08, "Flow Control"),
        (0x10, "Valve Low"),
        (0x20, "Valve High"),
        (0x40, "reserved bit 6 set"),
        (0x80, "reserved bit 7 set"),
    ];
    const EMFC_DEVICE_1: &[(u8, &str)] = &[
        (0x01, "Pressure Low"),
        (0x02, "Pressure High"),
        (0x04, "Gas Temperature Low"),
        (0x08, "Gas Temperature High"),
        (0x10, "Pressure Not Reading Valid"),
        (0x20, "Temperature Not Reading Valid"),
        (0x40, "reserved bit 6 set"),
        (0x80, "reserved bit 7 set"),
    ];
    let (detail, definitions) = match (profile, index, kind) {
        (ExceptionProfile::Mfc, 0, ExceptionKind::Alarm) => {
            ("MFC device Alarm bits follow Table 6-29.10.", MFC_ALARM)
        }
        (ExceptionProfile::Mfc, 0, ExceptionKind::Warning) => (
            "MFC device Warning bits follow Table 6-29.10. Bit 0 is shown exactly as the PDF's 'Reading Valid', which differs from the EMFC wording 'Not Reading Valid'.",
            MFC_WARNING,
        ),
        (ExceptionProfile::Emfc, 0, ExceptionKind::Alarm) => {
            ("EMFC device Alarm byte 0 follows Table 6-39.10.", MFC_ALARM)
        }
        (ExceptionProfile::Emfc, 0, ExceptionKind::Warning) => (
            "EMFC device Warning byte 0 follows Table 6-39.10.",
            EMFC_WARNING,
        ),
        (ExceptionProfile::Emfc, 1, _) => (
            "EMFC device byte 1 follows the pressure and temperature bit mapping in Section 6-39.",
            EMFC_DEVICE_1,
        ),
        _ => ("Raw device exception-detail byte.", &[] as &[(u8, &str)]),
    };
    cursor.push_u8(
        format!("{label} device detail byte {index}"),
        "bit field (BYTE)",
        format!(
            "{label} Exception Detail STRUCT mapped to the S-Device Supervisor Object class 0x30, instance 1, attribute {}. {detail}",
            kind.attribute()
        ),
        |value| format_flag_byte(value, definitions),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component<'a>(decode: &'a IoAssemblyDecode, name: &str) -> &'a IoAssemblyComponent {
        decode
            .components
            .iter()
            .find(|component| component.name == name)
            .unwrap_or_else(|| panic!("missing component {name:?}"))
    }

    #[test]
    fn metadata_covers_all_standard_instances_and_lengths() {
        let input = [
            (1, 2),
            (2, 3),
            (3, 5),
            (4, 5),
            (5, 7),
            (6, 8),
            (9, 1),
            (10, 8),
            (11, 8),
            (12, 15),
            (13, 4),
            (14, 5),
            (15, 9),
            (16, 9),
            (17, 13),
            (18, 14),
            (21, 7),
            (22, 9),
            (23, 13),
            (24, 17),
            (25, 17),
            (150, 8),
            (151, 6),
        ];
        let output = [(7, 2), (8, 3), (19, 4), (20, 5), (152, 3)];

        assert_eq!(INPUT_ASSEMBLIES.len(), input.len());
        assert_eq!(OUTPUT_ASSEMBLIES.len(), output.len());
        for (number, byte_len) in input {
            let metadata = assembly_instance(IoAssemblyDirection::Input, number).unwrap();
            assert_eq!(metadata.byte_len, byte_len, "input instance {number}");
            let decoded =
                decode_assembly(IoAssemblyDirection::Input, number, &vec![0; byte_len]).unwrap();
            assert!(decoded.warnings.is_empty(), "input instance {number}");
        }
        for (number, byte_len) in output {
            let metadata = assembly_instance(IoAssemblyDirection::Output, number).unwrap();
            assert_eq!(metadata.byte_len, byte_len, "output instance {number}");
            let decoded =
                decode_assembly(IoAssemblyDirection::Output, number, &vec![0; byte_len]).unwrap();
            assert!(decoded.warnings.is_empty(), "output instance {number}");
        }

        assert!(
            assembly_instance(IoAssemblyDirection::Input, 2)
                .unwrap()
                .requirements
                .contains("default (D)")
        );
        assert!(
            assembly_instance(IoAssemblyDirection::Input, 10)
                .unwrap()
                .requirements
                .contains("Assembly not used")
        );
        assert!(
            assembly_instance(IoAssemblyDirection::Input, 21)
                .unwrap()
                .requirements
                .contains("EMFM: required (Y)")
        );
        assert!(
            assembly_instance(IoAssemblyDirection::Input, 151)
                .unwrap()
                .requirements
                .contains("Poll-compatible")
        );
    }

    #[test]
    fn numeric_families_reject_mixed_int_and_real_connections() {
        let int_input = assembly_instance(IoAssemblyDirection::Input, 2).unwrap();
        let real_output = assembly_instance(IoAssemblyDirection::Output, 19).unwrap();
        let status_input = assembly_instance(IoAssemblyDirection::Input, 9).unwrap();

        assert_eq!(int_input.numeric_format(), IoAssemblyNumericFormat::Int);
        assert_eq!(real_output.numeric_format(), IoAssemblyNumericFormat::Real);
        assert!(
            !int_input
                .numeric_format()
                .is_compatible_with(real_output.numeric_format())
        );
        assert!(
            status_input
                .numeric_format()
                .is_compatible_with(real_output.numeric_format())
        );
    }

    #[test]
    fn decodes_supplied_device_table_assemblies_with_full_scale_context() {
        let input = decode_assembly(
            IoAssemblyDirection::Input,
            151,
            &[0x00, 0x60, 0xff, 0x7f, 0x00, 0x60],
        )
        .unwrap();
        assert_eq!(component(&input, "Flow").value, "24576");
        assert_eq!(component(&input, "Valve").value, "32767");
        assert_eq!(component(&input, "Temperature").value, "24576");
        assert!(
            component(&input, "Flow")
                .description
                .contains("raw / 24576")
        );
        assert!(component(&input, "Valve").description.contains("0x7FFF"));

        let r02 =
            decode_assembly(IoAssemblyDirection::Input, 150, &[1, 0, 2, 0, 3, 0, 4, 0]).unwrap();
        assert_eq!(component(&r02, "Flow").value, "1");
        assert_eq!(component(&r02, "Valve").value, "2");
        assert_eq!(component(&r02, "Temperature").value, "3");
        assert_eq!(component(&r02, "Pressure").value, "4");

        let output = decode_assembly(IoAssemblyDirection::Output, 152, &[3, 0xff, 0x7f]).unwrap();
        assert_eq!(component(&output, "Override").value, "3 (Hold)");
        assert_eq!(component(&output, "Valve").value, "32767");
        assert!(
            component(&output, "Override")
                .description
                .contains("device-table Assembly 152")
        );
    }

    #[test]
    fn basic_status_preserves_device_specific_caveat_and_fallback_map() {
        let decoded = decode_assembly(IoAssemblyDirection::Input, 9, &[0x21]).unwrap();
        let status = component(&decoded, "Status");

        assert!(status.value.contains("Basic"));
        assert!(status.value.contains("device-specific"));
        assert!(status.value.contains("common alarm"));
        assert!(status.value.contains("device warning"));
    }

    #[test]
    fn decodes_int_layout_in_little_endian_order() {
        let payload = [0xC1, 0xFE, 0xFF, 0x34, 0x12, 0x03, 0x00, 0x80];
        let decoded = decode_assembly(IoAssemblyDirection::Input, 6, &payload).unwrap();

        assert_eq!(component(&decoded, "Flow").value, "-2");
        assert_eq!(component(&decoded, "Setpoint").value, "4660");
        assert_eq!(component(&decoded, "Override").value, "3 (Hold)");
        assert_eq!(component(&decoded, "Valve").value, "-32768");
        assert!(
            component(&decoded, "Flow")
                .unit
                .contains("Vol1 default: Counts")
        );
        assert!(
            component(&decoded, "Flow")
                .description
                .contains("class 0x31")
        );
    }

    #[test]
    fn decodes_real_layout_in_little_endian_order() {
        let mut payload = vec![0x80];
        payload.extend_from_slice(&1.5_f32.to_le_bytes());
        payload.extend_from_slice(&(-2.25_f32).to_le_bytes());
        payload.push(4);
        payload.extend_from_slice(&3.25_f32.to_le_bytes());
        let decoded = decode_assembly(IoAssemblyDirection::Input, 18, &payload).unwrap();

        assert_eq!(component(&decoded, "Flow").value, "1.5");
        assert_eq!(component(&decoded, "Setpoint").value, "-2.25");
        assert_eq!(component(&decoded, "Override").value, "4 (Safe State)");
        assert_eq!(component(&decoded, "Valve").value, "3.25");
    }

    #[test]
    fn decodes_mfc_alarm_warning_structures_at_fixed_offsets() {
        let alarm = decode_assembly(
            IoAssemblyDirection::Input,
            10,
            &[0x80, 2, 0x11, 0x22, 1, 0x33, 1, 0x44],
        )
        .unwrap();
        assert_eq!(alarm.components.len(), 8);
        assert!(
            component(&alarm, "Alarm common detail byte 1")
                .value
                .contains("notify manufacturer")
        );
        assert!(
            component(&alarm, "Alarm device detail byte 0")
                .value
                .contains("Flow Low")
        );
        assert_eq!(
            component(&alarm, "Alarm manufacturer detail byte 0").value,
            "0x44"
        );

        let both = decode_assembly(
            IoAssemblyDirection::Input,
            12,
            &[0, 2, 1, 2, 1, 3, 1, 4, 2, 5, 6, 1, 7, 1, 8],
        )
        .unwrap();
        assert_eq!(both.components.len(), 15);
        assert_eq!(component(&both, "Warning common detail size").value, "2");
        assert!(
            component(&both, "Warning device detail byte 0")
                .value
                .contains("Reading Valid")
        );
    }

    #[test]
    fn decodes_emfc_two_byte_exception_details() {
        let decoded = decode_assembly(
            IoAssemblyDirection::Input,
            25,
            &[0x80, 2, 1, 2, 2, 3, 4, 1, 5, 2, 6, 7, 2, 8, 9, 1, 10],
        )
        .unwrap();

        assert_eq!(decoded.components.len(), 17);
        assert!(
            component(&decoded, "Alarm device detail byte 1")
                .value
                .contains("Gas Temperature Low")
        );
        assert!(
            component(&decoded, "Warning device detail byte 1")
                .value
                .contains("Gas Temperature High")
        );
        assert!(
            component(&decoded, "Warning device detail byte 1")
                .description
                .contains("Section 6-39")
        );
    }

    #[test]
    fn validates_profiled_exception_detail_size_slots_without_moving_offsets() {
        let mut payload = [0; 17];
        payload[1] = 3;
        payload[4] = 1;
        payload[7] = 2;
        payload[9] = 2;
        payload[12] = 2;
        payload[15] = 1;
        let decoded = decode_assembly(IoAssemblyDirection::Input, 25, &payload).unwrap();

        assert_eq!(decoded.components.len(), 17);
        assert_eq!(decoded.warnings.len(), 3);
        assert!(
            decoded
                .warnings
                .iter()
                .any(|warning| warning.contains("common size is 3"))
        );
        assert!(
            decoded
                .warnings
                .iter()
                .any(|warning| warning.contains("device size is 1"))
        );
        assert!(
            decoded
                .warnings
                .iter()
                .any(|warning| warning.contains("manufacturer size is 2"))
        );
    }

    #[test]
    fn reports_short_and_trailing_payloads_without_partial_components() {
        let short = decode_assembly(IoAssemblyDirection::Input, 2, &[0x80, 0x34]).unwrap();
        assert_eq!(short.components.len(), 1);
        assert_eq!(short.components[0].name, "Status");
        assert_eq!(short.warnings.len(), 1);
        assert!(short.warnings[0].contains("only complete leading components"));

        let long = decode_assembly(IoAssemblyDirection::Output, 7, &[1, 0, 0xAA]).unwrap();
        assert_eq!(long.components.len(), 1);
        assert_eq!(long.warnings.len(), 1);
        assert!(long.warnings[0].contains("1 trailing byte(s)"));
    }

    #[test]
    fn rejects_unknown_and_wrong_direction_instances() {
        assert!(decode_assembly(IoAssemblyDirection::Input, 7, &[]).is_err());
        assert!(decode_assembly(IoAssemblyDirection::Output, 1, &[]).is_err());
        assert!(decode_assembly(IoAssemblyDirection::Input, 0, &[]).is_err());
        assert!(assembly_instance(IoAssemblyDirection::Output, 25).is_none());
    }

    #[test]
    fn direction_labels_are_stable() {
        assert_eq!(IoAssemblyDirection::Input.label(), "Input");
        assert_eq!(IoAssemblyDirection::Output.label(), "Output");
    }
}
