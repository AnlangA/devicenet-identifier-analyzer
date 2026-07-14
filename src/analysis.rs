//! Shared protocol-analysis presentation models.

/// Semantic role of a decoded field.
///
/// Keeping this information in the analysis model lets every UI render the
/// same protocol result without matching translated field labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedFieldRole {
    /// Protocol envelope, addressing, and correlation information.
    Context,
    /// Service selector such as Get_Attribute_Single.
    Service,
    /// Human-readable object/instance/attribute target.
    Target,
    /// Typed application value, unit, and description.
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplicitOperation {
    Read,
    Write,
}

impl ExplicitOperation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Write => "Write",
        }
    }
}

/// Structured subject for a table-defined Explicit attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitSubject {
    pub operation: ExplicitOperation,
    pub class_id: u32,
    pub instance_id: u32,
    pub attribute_id: u32,
    pub object_name: &'static str,
    pub instance_name: &'static str,
    pub attribute_name: &'static str,
    pub data_type: &'static str,
    pub writable: bool,
}

impl ExplicitSubject {
    pub fn target_label(self) -> String {
        format!("{} / {}", self.instance_name, self.attribute_name)
    }

    pub fn address_label(self) -> String {
        format!(
            "Class 0x{:02X} · Instance {} · Attribute 0x{:02X}",
            self.class_id, self.instance_id, self.attribute_id
        )
    }
}

/// Structured subject for a user-selected I/O Assembly mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoAssemblySubject {
    pub direction: crate::assembly::IoAssemblyDirection,
    pub number: u8,
    pub name: &'static str,
    pub profile: &'static str,
    pub byte_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisSubject {
    Explicit(ExplicitSubject),
    IoAssembly(IoAssemblySubject),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedField {
    pub name: String,
    pub value: String,
    pub role: DecodedFieldRole,
    pub service_code: Option<u8>,
    pub unit: Option<String>,
    pub description: Option<String>,
}

impl DecodedField {
    pub(crate) fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            role: DecodedFieldRole::Context,
            service_code: None,
            unit: None,
            description: None,
        }
    }

    pub(crate) fn service(name: impl Into<String>, code: u8, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            role: DecodedFieldRole::Service,
            service_code: Some(code),
            unit: None,
            description: None,
        }
    }

    pub(crate) fn detailed(
        name: impl Into<String>,
        value: impl Into<String>,
        unit: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            role: DecodedFieldRole::Value,
            service_code: None,
            unit: Some(unit.into()),
            description: Some(description.into()),
        }
    }

    pub(crate) fn target(
        name: impl Into<String>,
        value: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            role: DecodedFieldRole::Target,
            service_code: None,
            unit: None,
            description: Some(description.into()),
        }
    }
}
