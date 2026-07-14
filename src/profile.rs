//! Table-driven MFC/EMFC Explicit object metadata.
//!
//! The protocol decoder and presentation layer both consume this catalog so
//! object, instance, attribute, access, and data-type names cannot drift apart.

use crate::analysis::{ExplicitOperation, ExplicitSubject};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExplicitAttribute {
    pub(crate) class_id: u32,
    pub(crate) instance_id: u32,
    pub(crate) attribute_id: u32,
    pub(crate) object_name: &'static str,
    pub(crate) instance_name: &'static str,
    pub(crate) attribute_name: &'static str,
    pub(crate) data_type: &'static str,
    pub(crate) writable: bool,
}

impl ExplicitAttribute {
    pub(crate) fn subject(self, operation: ExplicitOperation) -> ExplicitSubject {
        ExplicitSubject {
            operation,
            class_id: self.class_id,
            instance_id: self.instance_id,
            attribute_id: self.attribute_id,
            object_name: self.object_name,
            instance_name: self.instance_name,
            attribute_name: self.attribute_name,
            data_type: self.data_type,
            writable: self.writable,
        }
    }

    pub(crate) fn target_label(self) -> String {
        format!(
            "{} / {} (Class 0x{:02X}, Instance {}, Attribute 0x{:02X})",
            self.instance_name,
            self.attribute_name,
            self.class_id,
            self.instance_id,
            self.attribute_id
        )
    }
}

pub(crate) fn explicit_attribute(
    class_id: u32,
    instance_id: u32,
    attribute_id: u32,
) -> Option<ExplicitAttribute> {
    let (object_name, instance_name, attribute_name, data_type) = match (class_id, instance_id) {
        (0x01, 1) => {
            let (name, data_type) = match attribute_id {
                1 => ("Vendor ID", "UINT"),
                2 => ("Device type", "UINT"),
                3 => ("Product code", "UINT"),
                4 => ("Revision", "USINT + USINT"),
                5 => ("Identity status", "WORD"),
                6 => ("Serial number", "UDINT"),
                7 => ("Product name", "SHORT_STRING"),
                _ => return None,
            };
            ("Identity Object", "Device identity", name, data_type)
        }
        (0x03, 1) => {
            let (name, data_type) = match attribute_id {
                1 => ("MAC ID", "USINT"),
                2 => ("Baud rate", "USINT"),
                3 => ("Bus-off interrupt behavior", "USINT"),
                4 => ("Bus-off counter", "USINT"),
                5 => ("Allocation information", "STRUCT"),
                6 => ("MAC ID switch changed", "BOOL"),
                7 => ("Baud-rate switch changed", "BOOL"),
                8 => ("MAC ID switch value", "USINT"),
                9 => ("Baud-rate switch value", "USINT"),
                _ => return None,
            };
            ("DeviceNet Object", "DeviceNet node", name, data_type)
        }
        (0x05, 1 | 2) => {
            let (name, data_type) = match attribute_id {
                1 => ("Connection state", "USINT"),
                2 => ("Instance type", "USINT"),
                3 => ("Transport class trigger", "BYTE"),
                4 => ("Produced connection ID", "UINT"),
                5 => ("Consumed connection ID", "UINT"),
                6 => ("Initial communication characteristics", "BYTE"),
                7 => ("Produced connection size", "UINT"),
                8 => ("Consumed connection size", "UINT"),
                9 => ("Expected packet rate", "UINT"),
                12 => ("Watchdog timeout action", "USINT"),
                13 => ("Produced connection path length", "UINT"),
                14 => ("Produced connection path", "USINT[]"),
                15 => ("Consumed connection path length", "UINT"),
                16 => ("Consumed connection path", "USINT[]"),
                17 => ("Production inhibit time", "UINT"),
                _ => return None,
            };
            let instance_name = if instance_id == 1 {
                "Explicit Message connection"
            } else {
                "I/O connection"
            };
            ("Connection Object", instance_name, name, data_type)
        }
        (0x30, 1) => {
            let (name, data_type) = match attribute_id {
                1 => ("Number of attributes", "USINT"),
                2 => ("Attribute list", "USINT[]"),
                3 => ("Device type", "SHORT_STRING"),
                4 => ("SEMI standard revision", "SHORT_STRING"),
                5 => ("Manufacturer name", "SHORT_STRING"),
                6 => ("Manufacturer model", "SHORT_STRING"),
                7 => ("Software revision", "SHORT_STRING"),
                8 => ("Hardware revision", "SHORT_STRING"),
                9 => ("Device serial number", "SHORT_STRING"),
                10 => ("Device configuration", "SHORT_STRING"),
                11 => ("Device status", "USINT"),
                12 => ("Exception status", "BYTE"),
                13 => ("Exception detail alarm", "STRUCT"),
                14 => ("Exception detail warning", "STRUCT"),
                15 => ("Alarm enable", "BOOL"),
                16 => ("Warning enable", "BOOL"),
                23 => ("Run hours", "UDINT"),
                _ => return None,
            };
            (
                "S-Device Supervisor Object",
                "Device supervisor",
                name,
                data_type,
            )
        }
        (0x31, 1..=3) => {
            let instance_name = match instance_id {
                1 => "Flow sensor",
                2 => "Pressure sensor",
                3 => "Temperature sensor",
                _ => unreachable!(),
            };
            let (name, data_type) = match attribute_id {
                1 => ("Number of attributes", "USINT"),
                2 => ("Attribute list", "USINT[]"),
                3 => ("Data type", "USINT (CIP type code)"),
                4 => ("Data units", "ENGUNIT (UINT)"),
                5 => ("Reading valid", "BOOL"),
                6 => (
                    match instance_id {
                        1 => "Flow",
                        2 => "Pressure",
                        3 => "Temperature",
                        _ => unreachable!(),
                    },
                    "Configured INT or REAL",
                ),
                7 => ("Sensor status", "BYTE"),
                8 => ("Alarm enable", "BOOL"),
                9 => ("Warning enable", "BOOL"),
                10 => ("Numeric full scale", "Configured INT or REAL"),
                17 => ("Alarm trip point high", "Configured INT or REAL"),
                18 => ("Alarm trip point low", "Configured INT or REAL"),
                19 => ("Alarm hysteresis", "Configured INT or REAL"),
                20 => ("Alarm settling time", "UINT"),
                21 => ("Warning trip point high", "Configured INT or REAL"),
                22 => ("Warning trip point low", "Configured INT or REAL"),
                23 => ("Warning hysteresis", "Configured INT or REAL"),
                24 => ("Warning settling time", "UINT"),
                27 => ("Autozero enable", "BOOL"),
                28 => ("Autozero status", "BOOL"),
                35 => ("Gas calibration object instance", "UINT"),
                99 => ("Subclass", "UINT"),
                0x6e => ("Configured full scale", "REAL + ENGUNIT"),
                _ => return None,
            };
            ("S-Analog Sensor Object", instance_name, name, data_type)
        }
        (0x32, 1) => {
            let (name, data_type) = match attribute_id {
                1 => ("Number of attributes", "USINT"),
                2 => ("Attribute list", "USINT[]"),
                3 => ("Data type", "USINT (CIP type code)"),
                4 => ("Data units", "ENGUNIT (UINT)"),
                5 => ("Override", "USINT"),
                6 => ("Valve", "Configured INT or REAL"),
                7 => ("Actuator status", "BYTE"),
                8 => ("Alarm enable", "BOOL"),
                9 => ("Warning enable", "BOOL"),
                15 => ("Alarm trip point high", "Configured INT or REAL"),
                16 => ("Alarm trip point low", "Configured INT or REAL"),
                17 => ("Alarm hysteresis", "Configured INT or REAL"),
                18 => ("Warning trip point high", "Configured INT or REAL"),
                19 => ("Warning trip point low", "Configured INT or REAL"),
                20 => ("Warning hysteresis", "Configured INT or REAL"),
                _ => return None,
            };
            (
                "S-Analog Actuator Object",
                "Valve actuator",
                name,
                data_type,
            )
        }
        (0x33, 1) => {
            let (name, data_type) = match attribute_id {
                1 => ("Number of attributes", "USINT"),
                2 => ("Attribute list", "USINT[]"),
                3 => ("Data type", "USINT (CIP type code)"),
                4 => ("Data units", "ENGUNIT (UINT)"),
                6 => ("Setpoint", "Configured INT or REAL"),
                10 => ("Controller status", "BYTE"),
                11 => ("Alarm enable", "BOOL"),
                12 => ("Warning enable", "BOOL"),
                13 => ("Alarm settling time", "UINT"),
                14 => ("Alarm error band", "Configured INT or REAL"),
                15 => ("Warning settling time", "UINT"),
                16 => ("Warning error band", "Configured INT or REAL"),
                19 => ("Ramp rate", "UDINT"),
                _ => return None,
            };
            (
                "S-Single Stage Controller Object",
                "Flow controller",
                name,
                data_type,
            )
        }
        (0x34, 1..=5) => {
            let (name, data_type) = match attribute_id {
                1 => ("Number of attributes", "USINT"),
                2 => ("Attribute list", "USINT[]"),
                3 => ("Gas number", "UINT"),
                4 => ("Sensor instance", "UINT"),
                5 => ("Gas name", "SHORT_STRING"),
                6 => ("Calibration full scale", "REAL + ENGUNIT"),
                8 => ("Calibration date", "DATE (UINT days since 1972-01-01)"),
                9 => ("Calibration gas number", "UINT"),
                95 => ("Calibration pressure", "REAL"),
                _ => return None,
            };
            let instance_name = match instance_id {
                1 => "Gas calibration channel 1",
                2 => "Gas calibration channel 2",
                3 => "Gas calibration channel 3",
                4 => "Gas calibration channel 4",
                5 => "Gas calibration channel 5",
                _ => unreachable!(),
            };
            ("S-Gas Calibration Object", instance_name, name, data_type)
        }
        _ => return None,
    };

    Some(ExplicitAttribute {
        class_id,
        instance_id,
        attribute_id,
        object_name,
        instance_name,
        attribute_name,
        data_type,
        writable: is_settable(class_id, instance_id, attribute_id),
    })
}

fn is_settable(class_id: u32, instance_id: u32, attribute_id: u32) -> bool {
    match (class_id, instance_id) {
        (0x05, 1) => matches!(attribute_id, 9 | 12),
        (0x05, 2) => matches!(attribute_id, 9 | 14 | 16),
        (0x30, 1) => matches!(attribute_id, 15 | 16),
        (0x31, 1) => matches!(attribute_id, 3 | 4 | 8 | 9 | 17..=24 | 27 | 35),
        (0x31, 2 | 3) => matches!(attribute_id, 3 | 4 | 8 | 9 | 17..=24 | 27),
        (0x32, 1) => matches!(attribute_id, 3 | 4 | 5 | 8 | 9 | 15..=20),
        (0x33, 1) => matches!(attribute_id, 3 | 4 | 6 | 11..=16 | 19),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_names_instances_and_access_from_the_supplied_table() {
        let flow = explicit_attribute(0x31, 1, 6).unwrap();
        assert_eq!(flow.instance_name, "Flow sensor");
        assert_eq!(flow.attribute_name, "Flow");
        assert_eq!(flow.data_type, "Configured INT or REAL");
        assert!(!flow.writable);

        let setpoint = explicit_attribute(0x33, 1, 6).unwrap();
        assert_eq!(setpoint.instance_name, "Flow controller");
        assert!(setpoint.writable);

        let io_path = explicit_attribute(0x05, 2, 14).unwrap();
        assert_eq!(io_path.instance_name, "I/O connection");
        assert!(io_path.writable);

        assert!(explicit_attribute(0x34, 6, 3).is_none());
    }
}
