//! Shared protocol-analysis presentation models.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedField {
    pub name: String,
    pub value: String,
    pub service_code: Option<u8>,
}

impl DecodedField {
    pub(crate) fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            service_code: None,
        }
    }

    pub(crate) fn service(name: impl Into<String>, code: u8, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            service_code: Some(code),
        }
    }
}
