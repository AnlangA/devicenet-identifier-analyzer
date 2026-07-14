//! Trace document model and analysis/search indexing pipeline.

use crate::frame_input::FrameOrigin;
use devicenet_identifier_analyzer::{
    FrameAnalysis, IoAssemblySelection, MessageGroup, TraceMessage, decode_trace_ordered_with_io,
};
use std::path::PathBuf;

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
    pub(crate) fn from_frames(frames: &[AnalyzedFrame]) -> Self {
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
            group1: count_group(MessageGroup::Group1),
            group2: count_group(MessageGroup::Group2),
            group3: count_group(MessageGroup::Group3),
            group4: count_group(MessageGroup::Group4),
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
    pub(crate) search_text: String,
}

pub(crate) struct TraceDocument {
    pub(crate) path: PathBuf,
    pub(crate) frames: Vec<AnalyzedFrame>,
    pub(crate) skipped_message_lines: usize,
    pub(crate) stats: TraceStats,
}

impl TraceDocument {
    pub(crate) fn from_messages(
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

    pub(crate) fn reanalyze(&mut self, io_assembly: IoAssemblySelection) {
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

pub(crate) fn analyze_frames(
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

pub(crate) fn build_search_text(
    message: &TraceMessage,
    analysis: Option<&FrameAnalysis>,
) -> String {
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
