use crate::ai_import::{AiEndpoint, AiImportOutput, AiImportRequest, request_can_frames};
use crate::frame_input::{FrameOrigin, NewCanFrame, format_saved_frame};
use crate::theme;
use devicenet_identifier_analyzer::{
    FrameAnalysis, IoAssemblySelection, MessageGroup, TraceMessage, compare_optional_time,
    decode_trace_ordered_with_io, parse_trace_log,
};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortOrder {
    Ascending,
    Descending,
}

impl SortOrder {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ascending => "Time ASC",
            Self::Descending => "Time DESC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectionFilter {
    All,
    Tx,
    Rx,
}

impl DirectionFilter {
    pub(crate) const ALL: [Self; 3] = [Self::All, Self::Tx, Self::Rx];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Tx => "Tx",
            Self::Rx => "Rx",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameScope {
    All,
    Group1,
    Group2,
    Group3,
    Group4,
    Explicit,
}

impl FrameScope {
    pub(crate) const ALL: [Self; 6] = [
        Self::All,
        Self::Group1,
        Self::Group2,
        Self::Group3,
        Self::Group4,
        Self::Explicit,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::All => "All frames",
            Self::Group1 => "Group 1",
            Self::Group2 => "Group 2",
            Self::Group3 => "Group 3",
            Self::Group4 => "Group 4",
            Self::Explicit => "Explicit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageFilters {
    pub(crate) query: String,
    pub(crate) direction: DirectionFilter,
    pub(crate) scope: FrameScope,
}

impl Default for MessageFilters {
    fn default() -> Self {
        Self {
            query: String::new(),
            direction: DirectionFilter::All,
            scope: FrameScope::All,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TraceStats {
    pub(crate) tx: usize,
    pub(crate) rx: usize,
    pub(crate) group1: usize,
    pub(crate) group2: usize,
    pub(crate) group3: usize,
    pub(crate) group4: usize,
    pub(crate) io_assembly_candidates: usize,
    pub(crate) warnings: usize,
    pub(crate) user_created: usize,
    pub(crate) duration_ms: f64,
}

impl TraceStats {
    fn from_frames(frames: &[AnalyzedFrame]) -> Self {
        let tx = frames
            .iter()
            .filter(|frame| frame.message.direction.eq_ignore_ascii_case("Tx"))
            .count();
        let rx = frames
            .iter()
            .filter(|frame| frame.message.direction.eq_ignore_ascii_case("Rx"))
            .count();
        let count_group = |group| {
            frames
                .iter()
                .filter_map(|frame| frame.analysis.as_ref())
                .filter(|analysis| analysis.group == group)
                .count()
        };
        let group1 = count_group(MessageGroup::Group1);
        let group2 = count_group(MessageGroup::Group2);
        let group3 = count_group(MessageGroup::Group3);
        let group4 = count_group(MessageGroup::Group4);
        let io_assembly_candidates = frames
            .iter()
            .filter(|frame| {
                !frame.message.data.is_empty()
                    && frame
                        .analysis
                        .as_ref()
                        .is_some_and(|analysis| analysis.function.has_io_assembly_payload())
            })
            .count();
        let warnings = frames
            .iter()
            .filter_map(|frame| frame.analysis.as_ref())
            .map(|analysis| analysis.warnings.len())
            .sum();
        let user_created = frames
            .iter()
            .filter(|frame| frame.origin.is_user_created())
            .count();
        let mut times = frames
            .iter()
            .filter_map(|frame| frame.message.time_offset_ms);
        let duration_ms = times.next().map_or(0.0, |first| {
            let (minimum, maximum) = times.fold((first, first), |(minimum, maximum), time| {
                (minimum.min(time), maximum.max(time))
            });
            maximum - minimum
        });

        Self {
            tx,
            rx,
            group1,
            group2,
            group3,
            group4,
            io_assembly_candidates,
            warnings,
            user_created,
            duration_ms,
        }
    }
}

pub(crate) struct AnalyzedFrame {
    pub(crate) message: TraceMessage,
    pub(crate) analysis: Option<FrameAnalysis>,
    pub(crate) origin: FrameOrigin,
    search_text: String,
}

pub(crate) struct TraceDocument {
    pub(crate) path: PathBuf,
    pub(crate) frames: Vec<AnalyzedFrame>,
    pub(crate) skipped_message_lines: usize,
    pub(crate) stats: TraceStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputTab {
    Manual,
    Ai,
}

#[derive(Debug, Default)]
pub(crate) struct ManualInputForm {
    pub(crate) time_ms: String,
    pub(crate) can_id: String,
    pub(crate) can_data: String,
    pub(crate) message: Option<Result<String, String>>,
}

#[derive(Debug, Default)]
pub(crate) struct AiInputForm {
    pub(crate) api_key: String,
    pub(crate) endpoint: AiEndpoint,
    pub(crate) custom_base_url: String,
    pub(crate) user_input: String,
    pub(crate) last_json: String,
    pub(crate) message: Option<Result<String, String>>,
}

/// `eframe` 持久化使用的 `Storage` 键。整个应用仅保存一份 AI 配置。
pub(crate) const AI_CONFIG_KEY: &str = "ai-config";

/// 需要在本地持久化的 AI 相关配置。
///
/// 仅包含用户一次配置后应跨会话保留的字段（`api_key`、`endpoint`、
/// `custom_base_url`）；`user_input` / `last_json` / `message` 等属于会话级状态，
/// 不需要持久化，因此不在此结构中。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AiConfig {
    pub(crate) api_key: String,
    pub(crate) endpoint: AiEndpoint,
    pub(crate) custom_base_url: String,
}

impl AiConfig {
    /// 从当前表单状态中提取需要持久化的配置。
    pub(crate) fn from_form(form: &AiInputForm) -> Self {
        Self {
            api_key: form.api_key.clone(),
            endpoint: form.endpoint,
            custom_base_url: form.custom_base_url.clone(),
        }
    }

    /// 将持久化的配置回填到表单字段。
    pub(crate) fn apply_to(self, form: &mut AiInputForm) {
        form.api_key = self.api_key;
        form.endpoint = self.endpoint;
        form.custom_base_url = self.custom_base_url;
    }

    /// 序列化为 JSON 后加密，返回 Base64 密文字符串。失败返回 `None`。
    /// 该字符串随后通过 eframe 的 `Storage` 落盘。
    pub(crate) fn encrypt(&self) -> Option<String> {
        let json = serde_json::to_string(self).ok()?;
        crate::secret::encrypt(&json)
    }

    /// 解密 Base64 密文字符串并反序列化为 `AiConfig`。
    /// 任何环节失败都返回 `None`（调用方按“无保存配置”处理）。
    pub(crate) fn decrypt(encoded: &str) -> Option<Self> {
        let json = crate::secret::decrypt(encoded)?;
        serde_json::from_str(&json).ok()
    }
}

struct AiJob {
    receiver: Receiver<Result<AiImportOutput, String>>,
}

impl TraceDocument {
    fn from_messages(
        path: PathBuf,
        messages: Vec<TraceMessage>,
        origins: Vec<FrameOrigin>,
        io_assembly: IoAssemblySelection,
    ) -> Self {
        let frames = analyze_frames(messages, origins, io_assembly);
        let stats = TraceStats::from_frames(&frames);
        Self {
            path,
            frames,
            skipped_message_lines: 0,
            stats,
        }
    }

    fn reanalyze(&mut self, io_assembly: IoAssemblySelection) {
        let (messages, origins) = std::mem::take(&mut self.frames)
            .into_iter()
            .map(|frame| (frame.message, frame.origin))
            .unzip();
        self.frames = analyze_frames(messages, origins, io_assembly);
        self.stats = TraceStats::from_frames(&self.frames);
    }

    pub(crate) fn file_name(&self) -> &str {
        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Trace file")
    }
}

pub(crate) struct AnalyzerApp {
    pub(crate) document: Option<TraceDocument>,
    pub(crate) selected_index: Option<usize>,
    pub(crate) visible_indices: Vec<usize>,
    pub(crate) rendered_row_range: std::ops::Range<usize>,
    pub(crate) scroll_to_position: Option<usize>,
    pub(crate) filters: MessageFilters,
    pub(crate) sort_order: SortOrder,
    pub(crate) io_assembly: IoAssemblySelection,
    pub(crate) load_error: Option<String>,
    pub(crate) operation_message: Option<Result<String, String>>,
    pub(crate) show_input_window: bool,
    pub(crate) input_needs_focus: bool,
    pub(crate) input_tab: InputTab,
    pub(crate) manual_input: ManualInputForm,
    pub(crate) ai_input: AiInputForm,
    ai_job: Option<AiJob>,
}

impl AnalyzerApp {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::configure(&cc.egui_ctx);
        let mut app = Self {
            document: None,
            selected_index: None,
            visible_indices: Vec::new(),
            rendered_row_range: 0..0,
            scroll_to_position: None,
            filters: MessageFilters::default(),
            sort_order: SortOrder::Ascending,
            io_assembly: IoAssemblySelection::default(),
            load_error: None,
            operation_message: None,
            show_input_window: false,
            input_needs_focus: false,
            input_tab: InputTab::Manual,
            manual_input: ManualInputForm::default(),
            ai_input: AiInputForm::default(),
            ai_job: None,
        };

        // 恢复上次保存的 AI 配置。
        // 存储中的内容是“加密后的 Base64 字符串”，因此用 `get_string` 取出后
        // 再调用 `AiConfig::decrypt` 解密；任何失败（无存储/格式错误/密钥不匹配）
        // 都视为「无保存配置」，直接使用默认值。
        if let Some(storage) = cc.storage.as_ref() {
            if let Some(encoded) = storage.get_string(AI_CONFIG_KEY) {
                if let Some(config) = AiConfig::decrypt(&encoded) {
                    config.apply_to(&mut app.ai_input);
                }
            }
        }

        if let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) {
            app.load_file(path);
        }
        app
    }

    pub(crate) fn load_file(&mut self, path: PathBuf) {
        self.load_error = None;
        self.operation_message = None;
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trace = parse_trace_log(&contents);
                if trace.messages.is_empty() {
                    self.load_error = Some(self.retained_trace_error(format!(
                        "No valid PCAN trace messages were found in {}",
                        path.display()
                    )));
                    return;
                }

                let origins = vec![FrameOrigin::File; trace.messages.len()];
                let io_assembly = IoAssemblySelection::default();
                let mut document =
                    TraceDocument::from_messages(path, trace.messages, origins, io_assembly);
                document.skipped_message_lines = trace.skipped_message_lines;
                self.io_assembly = io_assembly;
                self.document = Some(document);
                self.filters = MessageFilters::default();
                self.sort_order = SortOrder::Ascending;
                self.selected_index = Some(0);
                self.load_error = None;
                self.refresh_visible_indices();
            }
            Err(error) => {
                self.load_error =
                    Some(self.retained_trace_error(format!(
                        "Could not read {}: {error}",
                        path.display()
                    )));
            }
        }
    }

    fn retained_trace_error(&self, error: String) -> String {
        self.document.as_ref().map_or(error.clone(), |document| {
            format!(
                "{error}. The current trace ({}) is still displayed.",
                document.file_name()
            )
        })
    }

    pub(crate) fn toggle_sort_order(&mut self) {
        self.sort_order = match self.sort_order {
            SortOrder::Ascending => SortOrder::Descending,
            SortOrder::Descending => SortOrder::Ascending,
        };
        self.refresh_visible_indices();
    }

    pub(crate) fn refresh_visible_indices(&mut self) {
        let Some(document) = &self.document else {
            self.visible_indices.clear();
            self.selected_index = None;
            self.rendered_row_range = 0..0;
            self.scroll_to_position = None;
            return;
        };

        let query = self.filters.query.trim().to_ascii_uppercase();
        self.visible_indices = document
            .frames
            .iter()
            .enumerate()
            .filter(|(_, frame)| {
                direction_matches(&frame.message, self.filters.direction)
                    && scope_matches(&frame.message, frame.analysis.as_ref(), self.filters.scope)
                    && frame.search_text.contains(query.as_str())
            })
            .map(|(index, _)| index)
            .collect();
        self.visible_indices.sort_by(|left_index, right_index| {
            let left = &document.frames[*left_index].message;
            let right = &document.frames[*right_index].message;
            let chronological = compare_optional_time(left.time_offset_ms, right.time_offset_ms);
            let ordered = match (left.time_offset_ms, right.time_offset_ms, self.sort_order) {
                (Some(_), Some(_), SortOrder::Descending) => chronological.reverse(),
                _ => chronological,
            };
            ordered.then_with(|| left_index.cmp(right_index))
        });
        if !self
            .selected_index
            .is_some_and(|selected| self.visible_indices.contains(&selected))
        {
            self.selected_index = self.visible_indices.first().copied();
        }
        self.scroll_to_position = self.selected_position();
    }

    pub(crate) fn selected_position(&self) -> Option<usize> {
        let selected = self.selected_index?;
        self.visible_indices
            .iter()
            .position(|index| *index == selected)
    }

    pub(crate) fn select_relative(&mut self, delta: isize) {
        if self.visible_indices.is_empty() {
            self.selected_index = None;
            return;
        }
        let current = self.selected_position().unwrap_or(0) as isize;
        let last = self.visible_indices.len().saturating_sub(1) as isize;
        let next = (current + delta).clamp(0, last) as usize;
        self.selected_index = Some(self.visible_indices[next]);
        if !self.rendered_row_range.contains(&next) {
            self.scroll_to_position = Some(next);
        }
    }

    pub(crate) fn select_boundary(&mut self, first: bool) {
        let position = if first {
            0
        } else {
            self.visible_indices.len().saturating_sub(1)
        };
        self.selected_index = self.visible_indices.get(position).copied();
        self.scroll_to_position = self.selected_index.map(|_| position);
    }

    pub(crate) fn selected_source_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub(crate) fn set_io_assembly_selection(&mut self, selection: IoAssemblySelection) {
        if self.io_assembly == selection {
            return;
        }
        self.io_assembly = selection;
        if let Some(document) = &mut self.document {
            document.reanalyze(self.io_assembly);
        }
        self.refresh_visible_indices();
    }

    pub(crate) fn add_manual_frame(&mut self) {
        let parsed = NewCanFrame::from_manual(
            &self.manual_input.time_ms,
            &self.manual_input.can_id,
            &self.manual_input.can_data,
        );
        match parsed {
            Ok(frame) => {
                let visible = self.insert_frames(vec![frame], FrameOrigin::Manual);
                self.manual_input.message = Some(Ok(if visible {
                    "Frame inserted".into()
                } else {
                    "Frame inserted, but hidden by the current filters".into()
                }));
                self.manual_input.time_ms.clear();
                self.manual_input.can_id.clear();
                self.manual_input.can_data.clear();
            }
            Err(error) => self.manual_input.message = Some(Err(error)),
        }
    }

    pub(crate) fn start_ai_import(&mut self, ctx: egui::Context) {
        if self.ai_job.is_some() {
            return;
        }
        if self.ai_input.api_key.trim().is_empty() {
            self.ai_input.message = Some(Err("API Key is required".into()));
            return;
        }
        if self.ai_input.user_input.trim().is_empty() {
            self.ai_input.message = Some(Err("Describe one or more CAN frames first".into()));
            return;
        }

        let request = AiImportRequest {
            api_key: self.ai_input.api_key.clone(),
            endpoint: self.ai_input.endpoint,
            custom_base_url: self.ai_input.custom_base_url.clone(),
            user_input: self.ai_input.user_input.clone(),
        };
        let (sender, receiver) = mpsc::channel();
        self.ai_input.message = Some(Ok("GLM-5-Turbo is structuring the messages...".into()));
        self.ai_job = Some(AiJob { receiver });
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("Could not start the AI runtime: {error}"))
                .and_then(|runtime| runtime.block_on(request_can_frames(request)));
            let _ = sender.send(result);
            ctx.request_repaint();
        });
    }

    pub(crate) fn poll_ai_job(&mut self) {
        let Some(result) = self.ai_job.as_ref().map(|job| job.receiver.try_recv()) else {
            return;
        };
        match result {
            Ok(Ok(output)) => {
                let count = output.frames.len();
                self.ai_input.last_json = output.pretty_json;
                let visible = self.insert_frames(output.frames, FrameOrigin::Ai);
                self.ai_input.message = Some(Ok(format!(
                    "Inserted {count} AI-structured frame(s){}",
                    if visible {
                        ""
                    } else {
                        ", but the first is hidden by the current filters"
                    }
                )));
                self.ai_job = None;
            }
            Ok(Err(error)) => {
                self.ai_input.message = Some(Err(error));
                self.ai_job = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.ai_input.message = Some(Err("AI worker stopped unexpectedly".into()));
                self.ai_job = None;
            }
        }
    }

    pub(crate) fn ai_busy(&self) -> bool {
        self.ai_job.is_some()
    }

    pub(crate) fn user_created_count(&self) -> usize {
        self.document
            .as_ref()
            .map_or(0, |document| document.stats.user_created)
    }

    pub(crate) fn save_user_frames(&mut self, mut path: PathBuf) {
        path.set_extension("log");
        let Some(document) = &self.document else {
            self.operation_message = Some(Err("There are no messages to save".into()));
            return;
        };
        let lines = document
            .frames
            .iter()
            .filter(|frame| frame.origin.is_user_created())
            .map(|frame| format_saved_frame(&frame.message, frame.origin))
            .collect::<Vec<_>>();
        if lines.is_empty() {
            self.operation_message = Some(Err(
                "There are no manually or AI-created messages to save".into(),
            ));
            return;
        }
        let contents = format!(
            "; DeviceNet Trace Analyzer user-created messages\n; Time may be empty; missing times sort after known times.\n{}\n",
            lines.join("\n")
        );
        match std::fs::write(&path, contents) {
            Ok(()) => {
                self.operation_message = Some(Ok(format!(
                    "Saved {} user-created frame(s) to {}",
                    lines.len(),
                    path.display()
                )))
            }
            Err(error) => {
                self.operation_message =
                    Some(Err(format!("Could not save {}: {error}", path.display())))
            }
        }
    }

    fn insert_frames(&mut self, frames: Vec<NewCanFrame>, origin: FrameOrigin) -> bool {
        if frames.is_empty() {
            return false;
        }
        if self.document.is_none() {
            self.document = Some(TraceDocument {
                path: PathBuf::from("Untitled messages"),
                frames: Vec::new(),
                skipped_message_lines: 0,
                stats: TraceStats::default(),
            });
        }

        let document = self.document.as_mut().expect("document was initialized");
        let mut next_number = document
            .frames
            .iter()
            .map(|frame| frame.message.number)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let first_inserted = document.frames.len();
        for frame in frames {
            document.frames.push(AnalyzedFrame {
                message: frame.into_trace_message(next_number),
                analysis: None,
                origin,
                search_text: String::new(),
            });
            next_number = next_number.saturating_add(1);
        }
        document.reanalyze(self.io_assembly);
        self.selected_index = Some(first_inserted);
        self.refresh_visible_indices();
        self.visible_indices.contains(&first_inserted)
    }
}

fn analyze_frames(
    messages: Vec<TraceMessage>,
    origins: Vec<FrameOrigin>,
    io_assembly: IoAssemblySelection,
) -> Vec<AnalyzedFrame> {
    assert_eq!(
        messages.len(),
        origins.len(),
        "every trace message must have exactly one origin"
    );
    let analyses = decode_trace_ordered_with_io(&messages, io_assembly);
    messages
        .into_iter()
        .zip(analyses)
        .zip(origins)
        .map(|((message, analysis), origin)| {
            let search_text = build_search_text(&message, analysis.as_ref());
            AnalyzedFrame {
                message,
                analysis,
                origin,
                search_text,
            }
        })
        .collect()
}

fn direction_matches(message: &TraceMessage, filter: DirectionFilter) -> bool {
    match filter {
        DirectionFilter::All => true,
        DirectionFilter::Tx => message.direction.eq_ignore_ascii_case("Tx"),
        DirectionFilter::Rx => message.direction.eq_ignore_ascii_case("Rx"),
    }
}

fn scope_matches(
    message: &TraceMessage,
    analysis: Option<&FrameAnalysis>,
    scope: FrameScope,
) -> bool {
    match scope {
        FrameScope::All => true,
        FrameScope::Group1 => (0x000..=0x3ff).contains(&message.identifier),
        FrameScope::Group2 => (0x400..=0x5ff).contains(&message.identifier),
        FrameScope::Group3 => (0x600..=0x7bf).contains(&message.identifier),
        FrameScope::Group4 => (0x7c0..=0x7ef).contains(&message.identifier),
        FrameScope::Explicit => analysis.is_some_and(|analysis| analysis.function.is_explicit()),
    }
}

fn build_search_text(message: &TraceMessage, analysis: Option<&FrameAnalysis>) -> String {
    let mut text = format!(
        "{:03X}\n{}\n{}\n{}\n{}",
        message.identifier,
        message.number,
        message.bus,
        message.direction.to_ascii_uppercase(),
        message.data_hex()
    );
    if let Some(analysis) = analysis {
        text.push('\n');
        text.push_str(&analysis.title.to_ascii_uppercase());
        for field in &analysis.fields {
            text.push('\n');
            text.push_str(&field.name.to_ascii_uppercase());
            text.push('\n');
            text.push_str(&field.value.to_ascii_uppercase());
            if let Some(unit) = &field.unit {
                text.push('\n');
                text.push_str(&unit.to_ascii_uppercase());
            }
            if let Some(description) = &field.description {
                text.push('\n');
                text.push_str(&description.to_ascii_uppercase());
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(number: u64, identifier: u32, direction: &str, data: &[u8]) -> TraceMessage {
        TraceMessage {
            number,
            time_offset_ms: Some(number as f64),
            bus: 1,
            direction: direction.into(),
            identifier,
            dlc: data.len(),
            data: data.into(),
        }
    }

    #[test]
    fn filters_direction_scope_and_decoded_text() {
        let explicit = message(1, 0x40e, "Tx", &[0, 0x4b, 3, 1, 1, 0]);
        let io = message(2, 0x40d, "Rx", &[0xaa]);
        let decoded = decode_trace_ordered_with_io(
            &[explicit.clone(), io.clone()],
            IoAssemblySelection::default(),
        );
        assert!(direction_matches(&explicit, DirectionFilter::Tx));
        assert!(!direction_matches(&explicit, DirectionFilter::Rx));
        assert!(scope_matches(
            &explicit,
            decoded[0].as_ref(),
            FrameScope::Explicit
        ));
        assert!(!scope_matches(
            &io,
            decoded[1].as_ref(),
            FrameScope::Explicit
        ));
        let search_text = build_search_text(&explicit, decoded[0].as_ref());
        assert!(search_text.contains("40E"));
        assert!(search_text.contains("00 4B"));
    }

    #[test]
    fn sort_uses_source_indices_when_message_numbers_repeat() {
        let messages = vec![message(7, 0x400, "Tx", &[0x11]), {
            let mut message = message(7, 0x405, "Rx", &[0x22]);
            message.time_offset_ms = Some(8.0);
            message
        }];
        let frames = analyze_frames(
            messages,
            vec![FrameOrigin::File; 2],
            IoAssemblySelection::default(),
        );
        let stats = TraceStats::from_frames(&frames);
        let mut app = AnalyzerApp {
            document: Some(TraceDocument {
                path: "duplicate-numbers.log".into(),
                frames,
                skipped_message_lines: 0,
                stats,
            }),
            selected_index: Some(0),
            visible_indices: Vec::new(),
            rendered_row_range: 0..0,
            scroll_to_position: None,
            filters: MessageFilters::default(),
            sort_order: SortOrder::Ascending,
            io_assembly: IoAssemblySelection::default(),
            load_error: None,
            operation_message: None,
            show_input_window: false,
            input_needs_focus: false,
            input_tab: InputTab::Manual,
            manual_input: ManualInputForm::default(),
            ai_input: AiInputForm::default(),
            ai_job: None,
        };

        app.refresh_visible_indices();
        assert_eq!(app.visible_indices, vec![0, 1]);
        app.toggle_sort_order();
        assert_eq!(app.visible_indices, vec![1, 0]);
        assert_eq!(app.selected_index, Some(0));

        app.document.as_mut().unwrap().frames[0]
            .message
            .time_offset_ms = None;
        app.sort_order = SortOrder::Ascending;
        app.refresh_visible_indices();
        assert_eq!(app.visible_indices, vec![1, 0]);
        app.toggle_sort_order();
        assert_eq!(app.visible_indices, vec![1, 0]);
    }

    #[test]
    fn duration_uses_timestamp_range_after_out_of_order_inserts() {
        let mut late = message(1, 0x400, "Tx", &[]);
        late.time_offset_ms = Some(10.0);
        let mut early = message(2, 0x400, "Tx", &[]);
        early.time_offset_ms = Some(2.0);
        let mut missing = message(3, 0x400, "Tx", &[]);
        missing.time_offset_ms = None;
        let frames = analyze_frames(
            vec![late, early, missing],
            vec![FrameOrigin::File, FrameOrigin::Manual, FrameOrigin::Ai],
            IoAssemblySelection::default(),
        );
        let stats = TraceStats::from_frames(&frames);

        assert_eq!(stats.duration_ms, 8.0);
        assert_eq!(stats.user_created, 2);
    }

    #[test]
    fn changing_io_instance_reanalyzes_fields_and_search_text_in_place() {
        let document = TraceDocument::from_messages(
            "io.log".into(),
            vec![message(1, 0x341, "Tx", &[0x80, 0x34, 0x12])],
            vec![FrameOrigin::File],
            IoAssemblySelection::default(),
        );
        let mut app = AnalyzerApp {
            document: Some(document),
            selected_index: Some(0),
            visible_indices: vec![0],
            rendered_row_range: 0..1,
            scroll_to_position: None,
            filters: MessageFilters::default(),
            sort_order: SortOrder::Ascending,
            io_assembly: IoAssemblySelection::default(),
            load_error: None,
            operation_message: None,
            show_input_window: false,
            input_needs_focus: false,
            input_tab: InputTab::Manual,
            manual_input: ManualInputForm::default(),
            ai_input: AiInputForm::default(),
            ai_job: None,
        };

        assert_eq!(app.io_assembly.host_mac_id, 0);
        assert_eq!(
            app.document.as_ref().unwrap().stats.io_assembly_candidates,
            1
        );
        assert_eq!(
            app.document.as_ref().unwrap().frames[0]
                .analysis
                .as_ref()
                .unwrap()
                .field("Flow"),
            None
        );

        app.set_io_assembly_selection(IoAssemblySelection {
            host_mac_id: 0,
            input_instance: Some(2),
            output_instance: None,
        });

        let frame = &app.document.as_ref().unwrap().frames[0];
        assert_eq!(frame.analysis.as_ref().unwrap().field("Flow"), Some("4660"));
        assert!(frame.search_text.contains("DEVICE-CONFIGURED DATA UNITS"));
        assert!(frame.search_text.contains("FULL SCALE"));
        assert!(frame.search_text.contains("S-ANALOG SENSOR OBJECT"));
        assert_eq!(app.selected_index, Some(0));
        assert_eq!(frame.origin, FrameOrigin::File);

        app.set_io_assembly_selection(IoAssemblySelection::default());
        assert_eq!(
            app.document.as_ref().unwrap().frames[0]
                .analysis
                .as_ref()
                .unwrap()
                .field("Flow"),
            None
        );
    }

    #[test]
    fn only_application_io_payloads_enable_assembly_selection() {
        let frames = analyze_frames(
            vec![
                message(1, 0x400, "Tx", &[0xff; 8]),
                message(2, 0x410, "Rx", &[]),
                message(3, 0x201, "Rx", &[1, 2, 3]),
            ],
            vec![FrameOrigin::File; 3],
            IoAssemblySelection::default(),
        );
        assert_eq!(TraceStats::from_frames(&frames).io_assembly_candidates, 0);

        let frames = analyze_frames(
            vec![message(4, 0x341, "Rx", &[0x80, 1, 0])],
            vec![FrameOrigin::File],
            IoAssemblySelection::default(),
        );
        assert_eq!(TraceStats::from_frames(&frames).io_assembly_candidates, 1);
    }
}
