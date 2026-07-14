//! Persisted desktop settings, separated from transient application state.

use crate::ai_import::AiEndpoint;
use serde::{Deserialize, Serialize};

pub(crate) const AI_CONFIG_KEY: &str = "ai-config";
pub(crate) const IO_ASSEMBLY_CONFIG_KEY: &str = "io-assembly-config";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AiConfig {
    pub(crate) api_key: String,
    pub(crate) endpoint: AiEndpoint,
    pub(crate) custom_base_url: String,
}

impl AiConfig {
    pub(crate) fn encrypt(&self) -> Option<String> {
        let json = serde_json::to_string(self).ok()?;
        crate::secret::encrypt(&json)
    }

    pub(crate) fn decrypt(encoded: &str) -> Option<Self> {
        let json = crate::secret::decrypt(encoded)?;
        serde_json::from_str(&json).ok()
    }
}
