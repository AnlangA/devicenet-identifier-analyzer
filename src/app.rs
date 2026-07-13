use crate::ai_import::{AiEndpoint, AiImportOutput, AiImportRequest, request_can_frames};
use crate::frame_input::{FrameOrigin, NewCanFrame, format_saved_frame};
use crate::theme;
use devicenet_identifier_analyzer::{
    FrameAnalysis, MessageGroup, TraceLog, TraceMessage, compare_optional_time,
    decode_trace_ordered, parse_trace_log,
};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

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
    pub(crate) warnings: usize,
    pub(crate) duration_ms: f64,
}

impl TraceStats {
    fn from_trace(trace: &TraceLog, analyses: &[Option<FrameAnalysis>]) -> Self {
        let tx = trace
            .messages
            .iter()
            .filter(|message| message.direction.eq_ignore_ascii_case("Tx"))
            .count();
        let rx = trace
            .messages
            .iter()
            .filter(|message| message.direction.eq_ignore_ascii_case("Rx"))
            .count();
        let count_group = |group| {
            analyses
                .iter()
                .flatten()
                .filter(|analysis| analysis.group == group)
                .count()
        };
        let group1 = count_group(MessageGroup::Group1);
        let group2 = count_group(MessageGroup::Group2);
        let group3 = count_group(MessageGroup::Group3);
        let group4 = count_group(MessageGroup::Group4);
        let warnings = analyses
            .iter()
            .flatten()
            .map(|analysis| analysis.warnings.len())
            .sum();
        let mut times = trace
            .messages
            .iter()
            .filter_map(|message| message.time_offset_ms);
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
            warnings,
            duration_ms,
        }
    }
}

pub(crate) struct TraceDocument {
    pub(crate) path: PathBuf,
    pub(crate) trace: TraceLog,
    pub(crate) analyses: Vec<Option<FrameAnalysis>>,
    pub(crate) origins: Vec<FrameOrigin>,
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

struct AiJob {
    receiver: Receiver<Result<AiImportOutput, String>>,
}

impl TraceDocument {
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
    pub(crate) filters: MessageFilters,
    pub(crate) sort_order: SortOrder,
    pub(crate) load_error: Option<String>,
    pub(crate) operation_message: Option<Result<String, String>>,
    pub(crate) show_input_window: bool,
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
            filters: MessageFilters::default(),
            sort_order: SortOrder::Ascending,
            load_error: None,
            operation_message: None,
            show_input_window: false,
            input_tab: InputTab::Manual,
            manual_input: ManualInputForm::default(),
            ai_input: AiInputForm::default(),
            ai_job: None,
        };

        if let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) {
            app.load_file(path);
        }
        app
    }

    pub(crate) fn load_file(&mut self, path: PathBuf) {
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trace = parse_trace_log(&contents);
                if trace.messages.is_empty() {
                    self.load_error = Some(format!(
                        "No PCAN trace messages were found in {}",
                        path.display()
                    ));
                    return;
                }

                let analyses = decode_trace_ordered(&trace.messages);
                let stats = TraceStats::from_trace(&trace, &analyses);
                self.document = Some(TraceDocument {
                    path,
                    origins: vec![FrameOrigin::File; trace.messages.len()],
                    trace,
                    analyses,
                    stats,
                });
                self.filters = MessageFilters::default();
                self.sort_order = SortOrder::Ascending;
                self.selected_index = Some(0);
                self.load_error = None;
                self.refresh_visible_indices();
            }
            Err(error) => {
                self.load_error = Some(format!("Could not read {}: {error}", path.display()));
            }
        }
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
            return;
        };

        let query = self.filters.query.trim().to_ascii_uppercase();
        self.visible_indices = document
            .trace
            .messages
            .iter()
            .enumerate()
            .filter(|(index, message)| {
                direction_matches(message, self.filters.direction)
                    && scope_matches(
                        message,
                        document.analyses[*index].as_ref(),
                        self.filters.scope,
                    )
                    && query_matches(message, document.analyses[*index].as_ref(), query.as_str())
            })
            .map(|(index, _)| index)
            .collect();
        self.visible_indices.sort_by(|left_index, right_index| {
            let left = &document.trace.messages[*left_index];
            let right = &document.trace.messages[*right_index];
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
    }

    pub(crate) fn select_boundary(&mut self, first: bool) {
        self.selected_index = if first {
            self.visible_indices.first().copied()
        } else {
            self.visible_indices.last().copied()
        };
    }

    pub(crate) fn selected_source_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub(crate) fn add_manual_frame(&mut self) {
        let parsed = NewCanFrame::from_manual(
            &self.manual_input.time_ms,
            &self.manual_input.can_id,
            &self.manual_input.can_data,
        );
        match parsed {
            Ok(frame) => {
                self.insert_frames(vec![frame], FrameOrigin::Manual);
                self.manual_input.message = Some(Ok("Frame inserted".into()));
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

    pub(crate) fn poll_ai_job(&mut self, ctx: &egui::Context) {
        let Some(result) = self.ai_job.as_ref().map(|job| job.receiver.try_recv()) else {
            return;
        };
        match result {
            Ok(Ok(output)) => {
                let count = output.frames.len();
                self.ai_input.last_json = output.pretty_json;
                self.insert_frames(output.frames, FrameOrigin::Ai);
                self.ai_input.message =
                    Some(Ok(format!("Inserted {count} AI-structured frame(s)")));
                self.ai_job = None;
            }
            Ok(Err(error)) => {
                self.ai_input.message = Some(Err(error));
                self.ai_job = None;
            }
            Err(TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(100)),
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
        self.document.as_ref().map_or(0, |document| {
            document
                .origins
                .iter()
                .filter(|origin| origin.is_user_created())
                .count()
        })
    }

    pub(crate) fn save_user_frames(&mut self, mut path: PathBuf) {
        path.set_extension("log");
        let Some(document) = &self.document else {
            self.operation_message = Some(Err("There are no messages to save".into()));
            return;
        };
        let lines = document
            .trace
            .messages
            .iter()
            .zip(&document.origins)
            .filter(|(_, origin)| origin.is_user_created())
            .map(|(message, origin)| format_saved_frame(message, *origin))
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

    fn insert_frames(&mut self, frames: Vec<NewCanFrame>, origin: FrameOrigin) {
        if frames.is_empty() {
            return;
        }
        if self.document.is_none() {
            self.document = Some(TraceDocument {
                path: PathBuf::from("Untitled messages"),
                trace: TraceLog {
                    start_time: None,
                    messages: Vec::new(),
                    skipped_message_lines: 0,
                },
                analyses: Vec::new(),
                origins: Vec::new(),
                stats: TraceStats::default(),
            });
        }

        let document = self.document.as_mut().expect("document was initialized");
        let mut next_number = document
            .trace
            .messages
            .iter()
            .map(|message| message.number)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let first_inserted = document.trace.messages.len();
        for frame in frames {
            document
                .trace
                .messages
                .push(frame.into_trace_message(next_number));
            document.origins.push(origin);
            next_number = next_number.saturating_add(1);
        }
        document.analyses = decode_trace_ordered(&document.trace.messages);
        document.stats = TraceStats::from_trace(&document.trace, &document.analyses);
        self.selected_index = Some(first_inserted);
        self.refresh_visible_indices();
    }
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

fn query_matches(message: &TraceMessage, analysis: Option<&FrameAnalysis>, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }

    let id_hex = format!("{:03X}", message.identifier);
    let number = message.number.to_string();
    let bus = message.bus.to_string();
    if id_hex.contains(query)
        || number.contains(query)
        || bus.contains(query)
        || message.direction.to_ascii_uppercase().contains(query)
        || message.data_hex().contains(query)
    {
        return true;
    }

    analysis.is_some_and(|analysis| {
        analysis.title.to_ascii_uppercase().contains(query)
            || analysis.fields.iter().any(|field| {
                field.name.to_ascii_uppercase().contains(query)
                    || field.value.to_ascii_uppercase().contains(query)
            })
    })
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
        let decoded = decode_trace_ordered(&[explicit.clone(), io.clone()]);
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
        assert!(query_matches(&explicit, None, "40E"));
        assert!(query_matches(&explicit, None, "00 4B"));
    }

    #[test]
    fn sort_uses_source_indices_when_message_numbers_repeat() {
        let messages = vec![message(7, 0x400, "Tx", &[0x11]), {
            let mut message = message(7, 0x405, "Rx", &[0x22]);
            message.time_offset_ms = Some(8.0);
            message
        }];
        let trace = TraceLog {
            start_time: None,
            skipped_message_lines: 0,
            messages,
        };
        let analyses = decode_trace_ordered(&trace.messages);
        let stats = TraceStats::from_trace(&trace, &analyses);
        let mut app = AnalyzerApp {
            document: Some(TraceDocument {
                path: "duplicate-numbers.log".into(),
                trace,
                analyses,
                origins: vec![FrameOrigin::File; 2],
                stats,
            }),
            selected_index: Some(0),
            visible_indices: Vec::new(),
            filters: MessageFilters::default(),
            sort_order: SortOrder::Ascending,
            load_error: None,
            operation_message: None,
            show_input_window: false,
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

        app.document.as_mut().unwrap().trace.messages[0].time_offset_ms = None;
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
        let trace = TraceLog {
            start_time: None,
            skipped_message_lines: 0,
            messages: vec![late, early, missing],
        };
        let analyses = decode_trace_ordered(&trace.messages);

        assert_eq!(TraceStats::from_trace(&trace, &analyses).duration_ms, 8.0);
    }
}
