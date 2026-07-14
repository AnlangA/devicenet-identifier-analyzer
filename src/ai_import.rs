use crate::frame_input::NewCanFrame;
use serde::{Deserialize, Serialize};
use zai_rs::{
    client::{ApiFamily, ZaiClient},
    model::{chat::ChatCompletion, chat_base_response::ChatCompletionResponse, *},
};

pub(crate) const DEFAULT_BASE_URL: &str = ApiFamily::PaasV4.default_base();
pub(crate) const DEFAULT_CODING_PLAN_URL: &str = ApiFamily::CodingPaasV4.default_base();

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AiEndpoint {
    #[default]
    Standard,
    CodingPlan,
    CustomBase,
}

impl AiEndpoint {
    pub(crate) const ALL: [Self; 3] = [Self::Standard, Self::CodingPlan, Self::CustomBase];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Standard => "Standard URL",
            Self::CodingPlan => "Coding Plan URL",
            Self::CustomBase => "Base URL",
        }
    }
}

pub(crate) const AI_IMPORT_SYSTEM_PROMPT: &str = r#"
You are a deterministic Classic CAN frame extraction engine embedded in a DeviceNet trace
analyzer. Extract frames only from the user's latest message.

Your only valid action is to call `insert_can_messages` exactly once. Never answer with prose,
Markdown, a JSON code block, or a different tool. Put every frame in the `messages` array and
preserve the user's original frame order.

Record detection:
1. Treat each line, semicolon-delimited segment, or repeated ID=/CAN-ID label as a possible frame.
2. A frame is usable only when it has an explicit CAN ID. CAN data may be empty.
3. Preserve duplicates and preserve source order. Do not merge or deduplicate frames.

Normalization rules:
1. Each message must contain time_ms, can_id, can_data, and can_dlc.
2. If a time is absent, set time_ms to null. Never invent a time or infer timing intervals.
3. Convert time values to milliseconds. Accept labels such as ms or milliseconds. If seconds are
   explicitly supplied, convert seconds to milliseconds.
4. can_id must be an integer in 0..2047. A 0x prefix means hexadecimal. Tokens containing A-F in
   a CAN-ID context are hexadecimal. Bare digit-only IDs are decimal unless the user explicitly
   says they are hexadecimal.
5. can_data must be an array of byte integers in 0..255. CAN data tokens are hexadecimal by
   default (for example `10` means 0x10) unless the user explicitly labels them decimal.
6. can_dlc must equal the number of bytes in can_data and must be in 0..8. If an explicitly written
   DLC disagrees with the supplied bytes, do not add or remove bytes: use the actual byte count.
7. Empty CAN data is valid and has can_dlc 0.
8. Never invent a CAN ID or data byte. Ignore surrounding explanations that are not frames.
9. The function supports a single frame or any number of frames through the messages array.
10. Emit JSON numbers, never hexadecimal strings. Ignore Bus, Type, and direction fields because
    the function does not accept them.

Examples of normalization:
- `ID 0x40E data 00 4B 03 01` -> time_ms null, can_id 1038,
  can_data [0,75,3,1], can_dlc 4.
- `Bus=1,ID=1038,Type=D,DLC=6,Data=0 75 3 1 1 0 ,` -> time_ms null,
  can_id 1038, can_data [0,117,3,1,1,0], can_dlc 6.
- `at 1.5 s, decimal id 1038, data AA 00` -> time_ms 1500,
  can_id 1038, can_data [170,0], can_dlc 2.
"#;

const FUNCTION_NAME: &str = "insert_can_messages";

#[derive(Debug, Clone)]
pub(crate) struct AiImportRequest {
    pub(crate) api_key: String,
    pub(crate) endpoint: AiEndpoint,
    pub(crate) custom_base_url: String,
    pub(crate) user_input: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AiImportOutput {
    pub(crate) frames: Vec<NewCanFrame>,
    pub(crate) pretty_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InsertCanMessagesArgs {
    messages: Vec<NewCanFrame>,
}

pub(crate) async fn request_can_frames(request: AiImportRequest) -> Result<AiImportOutput, String> {
    if request.api_key.trim().is_empty() {
        return Err("API Key is required".into());
    }
    if request.user_input.trim().is_empty() {
        return Err("Describe one or more CAN frames first".into());
    }

    let function = Function::new(
        FUNCTION_NAME,
        "Insert one or more validated Classic CAN frames into the local DeviceNet trace. Call once with every extracted frame.",
        function_schema(),
    );
    let zai_client = build_zai_client(request.api_key, request.endpoint, &request.custom_base_url)?;
    let messages = TextMessage::system(AI_IMPORT_SYSTEM_PROMPT);
    let completion = ChatCompletion::new(GLM5_turbo {}, messages)
        .add_message(TextMessage::user(request.user_input))
        .with_thinking(ThinkingType::disabled())
        .with_do_sample(false)
        .with_max_tokens(4096)
        .with_tool_choice(ToolChoice::auto())
        .add_tool(Tools::Function { function });

    let response: ChatCompletionResponse = if request.endpoint == AiEndpoint::CodingPlan {
        completion.send_via_coding_plan(&zai_client).await
    } else {
        completion.send_via(&zai_client).await
    }
    .map_err(|error| format!("GLM request failed: {error}"))?;
    parse_tool_calls(response)
}

fn build_zai_client(
    api_key: String,
    endpoint: AiEndpoint,
    custom_base_url: &str,
) -> Result<ZaiClient, String> {
    let mut client_builder = ZaiClient::builder(api_key)
        .endpoint(ApiFamily::PaasV4, DEFAULT_BASE_URL)
        .endpoint(ApiFamily::CodingPaasV4, DEFAULT_CODING_PLAN_URL);
    if endpoint == AiEndpoint::CustomBase {
        let custom_base_url = custom_base_url.trim();
        if custom_base_url.is_empty() {
            return Err("Base URL is required".into());
        }
        client_builder = client_builder
            .endpoint(ApiFamily::PaasV4, custom_base_url.to_owned())
            .allow_insecure_transport(true);
    }
    client_builder
        .build()
        .map_err(|error| format!("Could not configure the Z.ai client: {error}"))
}

fn parse_tool_calls(response: ChatCompletionResponse) -> Result<AiImportOutput, String> {
    let tool_calls = response
        .choices
        .as_deref()
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.message.as_ref())
        .and_then(|message| message.tool_calls.as_deref())
        .ok_or_else(|| {
            "GLM did not return the required insert_can_messages function call".to_owned()
        })?;

    if tool_calls.len() != 1 {
        return Err(format!(
            "GLM must call insert_can_messages exactly once, but returned {} tool calls",
            tool_calls.len()
        ));
    }

    let mut frames = Vec::new();
    for call in tool_calls {
        let function = call
            .function
            .as_ref()
            .ok_or_else(|| "GLM returned a non-function tool call".to_owned())?;
        if function.name != FUNCTION_NAME {
            return Err(format!(
                "GLM called an unexpected function: {}",
                function.name
            ));
        }
        let arguments = function.arguments.as_str();
        if arguments.trim().is_empty() {
            return Err("Function call arguments are missing".to_owned());
        }
        let parsed: InsertCanMessagesArgs = serde_json::from_str(arguments)
            .map_err(|error| format!("Invalid function-call JSON: {error}"))?;
        frames.extend(parsed.messages);
    }

    if frames.is_empty() {
        return Err("GLM returned an empty message array".into());
    }
    for (index, frame) in frames.iter().enumerate() {
        frame
            .validate()
            .map_err(|error| format!("Frame {} is invalid: {error}", index + 1))?;
    }
    let pretty_json = serde_json::to_string_pretty(&InsertCanMessagesArgs {
        messages: frames.clone(),
    })
    .map_err(|error| format!("Could not format function-call JSON: {error}"))?;

    Ok(AiImportOutput {
        frames,
        pretty_json,
    })
}

fn function_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "messages": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "time_ms": {
                            "anyOf": [
                                {"type": "number", "minimum": 0},
                                {"type": "null"}
                            ],
                            "description": "Milliseconds from trace start, or null when absent"
                        },
                        "can_id": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 2047,
                            "description": "Normalized 11-bit CAN identifier as an integer"
                        },
                        "can_data": {
                            "type": "array",
                            "maxItems": 8,
                            "items": {"type": "integer", "minimum": 0, "maximum": 255}
                        },
                        "can_dlc": {"type": "integer", "minimum": 0, "maximum": 8}
                    },
                    "required": ["time_ms", "can_id", "can_data", "can_dlc"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["messages"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_enforces_null_time_arrays_and_no_invention() {
        assert!(AI_IMPORT_SYSTEM_PROMPT.contains("time_ms to null"));
        assert!(AI_IMPORT_SYSTEM_PROMPT.contains("messages array"));
        assert!(AI_IMPORT_SYSTEM_PROMPT.contains("Never invent"));
    }

    #[test]
    fn function_schema_requires_all_frame_fields() {
        let schema = function_schema();
        let required = schema
            .pointer("/properties/messages/items/required")
            .unwrap();
        assert!(required.as_array().unwrap().len() == 4);
    }

    #[test]
    fn endpoint_defaults_match_zai_rs_0_6() {
        assert_eq!(DEFAULT_BASE_URL, "https://open.bigmodel.cn/api/paas/v4");
        assert_eq!(
            DEFAULT_CODING_PLAN_URL,
            "https://open.bigmodel.cn/api/coding/paas/v4"
        );
    }

    #[test]
    fn custom_base_url_is_applied_and_validated() {
        let client = build_zai_client(
            "test-key".into(),
            AiEndpoint::CustomBase,
            "https://example.com/api/paas/v4",
        )
        .unwrap();
        assert_eq!(
            client.endpoints().base(ApiFamily::PaasV4).as_str(),
            "https://example.com/api/paas/v4"
        );
        assert!(build_zai_client("test-key".into(), AiEndpoint::CustomBase, "").is_err());
        assert!(
            build_zai_client(
                "test-key".into(),
                AiEndpoint::CustomBase,
                "http://example.com/api/paas/v4"
            )
            .is_err()
        );
    }
}
