use crate::ai_import::AiEndpoint;
use crate::app::{AnalyzerApp, DirectionFilter, FrameScope, InputTab, MessageFilters};
use crate::frame_input::FrameOrigin;
use crate::settings::{AI_CONFIG_KEY, AiConfig, IO_ASSEMBLY_CONFIG_KEY};
use crate::theme::{
    ACCENT, AMBER, BG, BLUE, BORDER, MUTED, PANEL, PANEL_SOFT, PURPLE, RED, SURFACE, TEXT,
};
use devicenet_identifier_analyzer::{
    AnalysisSubject, DecodedField, DecodedFieldRole, DecodedIdentifier, FrameAnalysis,
    FrameFunction, Group2Function, INPUT_ASSEMBLIES, IdentifierFields, IoAssemblyInstance,
    IoAssemblySelection, MessageGroup, OUTPUT_ASSEMBLIES, TraceMessage, service_description,
};
use eframe::egui::{
    self, Align2, Color32, FontFamily, FontId, Pos2, RichText, Sense, Stroke, Vec2,
};
use rfd::FileDialog;

const MESSAGE_TABLE_WIDTH: f32 = 980.0;
const MESSAGE_ROW_HEIGHT: f32 = 28.0;
const AI_INPUT_HEIGHT: f32 = 150.0;

impl eframe::App for AnalyzerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_ai_job();
        if let Some(path) = ui.ctx().input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        }) {
            self.load_file(path);
        }

        handle_keyboard_navigation(ui, self);

        let compact_header = ui.available_width() < 1050.0;
        egui::Panel::top("application_header")
            .exact_size(if compact_header { 116.0 } else { 80.0 })
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .stroke(Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(22, 14)),
            )
            .show(ui, |ui| header(ui, self));

        let browser_max_width = (ui.available_width() - 430.0).clamp(500.0, 850.0);
        egui::Panel::left("message_browser")
            .resizable(true)
            .default_size(680.0)
            .size_range(500.0..=browser_max_width)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(16, 14)),
            )
            .show(ui, |ui| message_list_panel(ui, self));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(egui::Margin::symmetric(18, 14)),
            )
            .show(ui, |ui| selected_message_panel(ui, self));

        message_input_window(ui.ctx(), self);
    }

    /// 通过 eframe 的持久化接口将 AI 配置写入本地存储。
    ///
    /// `App::save` 会在退出以及 `auto_save_interval` 的周期内被调用。
    /// 为了避免 `api_key` 明文落盘，这里先把配置序列化为 JSON，再用
    /// `crate::secret` 加密为 Base64 字符串，最后以字符串形式写入 `Storage`。
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let config = AiConfig {
            api_key: self.ai_input.api_key.clone(),
            endpoint: self.ai_input.endpoint,
            custom_base_url: self.ai_input.custom_base_url.clone(),
        };
        if let Some(encoded) = config.encrypt() {
            storage.set_string(AI_CONFIG_KEY, encoded);
        }
        if let Ok(encoded) = serde_json::to_string(&self.io_assembly) {
            storage.set_string(IO_ASSEMBLY_CONFIG_KEY, encoded);
        }
    }
}

fn handle_keyboard_navigation(ui: &egui::Ui, app: &mut AnalyzerApp) {
    if ui.ctx().egui_wants_keyboard_input() {
        return;
    }
    if ui.input(|input| input.key_pressed(egui::Key::ArrowDown)) {
        app.select_relative(1);
    }
    if ui.input(|input| input.key_pressed(egui::Key::ArrowUp)) {
        app.select_relative(-1);
    }
    if ui.input(|input| input.key_pressed(egui::Key::Home)) {
        app.select_boundary(true);
    }
    if ui.input(|input| input.key_pressed(egui::Key::End)) {
        app.select_boundary(false);
    }
}

fn header(ui: &mut egui::Ui, app: &mut AnalyzerApp) {
    let compact = ui.available_width() < 1050.0;
    if compact {
        ui.horizontal(|ui| {
            header_title(ui);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                header_file(ui, app);
            });
        });
        ui.add_space(4.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            header_actions(ui, app, false);
        });
    } else {
        ui.horizontal(|ui| {
            header_title(ui);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                header_actions(ui, app, true);
            });
        });
    }
}

fn header_title(ui: &mut egui::Ui) {
    ui.vertical(|ui| {
        ui.label(
            RichText::new("DeviceNet Trace Analyzer")
                .size(24.0)
                .color(TEXT)
                .strong(),
        );
        ui.label(
            RichText::new("Message Groups 1-4 | PCAN trace diagnostics")
                .size(11.0)
                .color(MUTED),
        );
    });
}

fn header_actions(ui: &mut egui::Ui, app: &mut AnalyzerApp, include_file: bool) {
    let open = egui::Button::new(RichText::new("Open trace...").strong())
        .fill(ACCENT)
        .corner_radius(7.0)
        .min_size(Vec2::new(126.0, 36.0));
    if ui
        .push_id("open_trace_control", |ui| ui.add(open))
        .inner
        .on_hover_text("Open .log, .trc, or .txt")
        .clicked()
        && let Some(path) = FileDialog::new()
            .add_filter("PCAN trace", &["log", "trc"])
            .add_filter("Text file", &["txt"])
            .pick_file()
    {
        app.load_file(path);
    }

    ui.add_space(6.0);
    if ui
        .push_id("add_messages_control", |ui| {
            ui.add(
                egui::Button::new("Add messages")
                    .fill(PANEL_SOFT)
                    .corner_radius(7.0)
                    .min_size(Vec2::new(112.0, 36.0)),
            )
        })
        .inner
        .on_hover_text("Insert CAN frames manually or with GLM-5-Turbo")
        .clicked()
    {
        app.show_input_window = true;
        app.input_needs_focus = true;
    }

    ui.add_space(6.0);
    let user_count = app.user_created_count();
    if ui
        .push_id("save_entered_messages_control", |ui| {
            ui.add_enabled(
                user_count > 0,
                egui::Button::new(format!("Save entered ({user_count})"))
                    .fill(PANEL_SOFT)
                    .corner_radius(7.0)
                    .min_size(Vec2::new(132.0, 36.0)),
            )
        })
        .inner
        .on_hover_text("Save manual and AI-created messages as a .log file")
        .clicked()
        && let Some(path) = FileDialog::new()
            .add_filter("DeviceNet log", &["log"])
            .set_file_name("devicenet-user-messages.log")
            .save_file()
    {
        app.save_user_frames(path);
    }

    if include_file {
        ui.add_space(8.0);
        header_file(ui, app);
    }
}

fn header_file(ui: &mut egui::Ui, app: &AnalyzerApp) {
    if let Some(document) = &app.document {
        let file = ui.add_sized(
            [180.0, 20.0],
            egui::Label::new(RichText::new(document.file_name()).size(11.0).color(MUTED))
                .truncate(),
        );
        file.on_hover_text(document.path.display().to_string());
    }
}

fn message_input_window(ctx: &egui::Context, app: &mut AnalyzerApp) {
    if !app.show_input_window {
        return;
    }

    let mut open = app.show_input_window;
    let maximum_height = (ctx.input(|input| input.content_rect().height()) - 40.0).max(280.0);
    egui::Window::new("Add CAN messages")
        .id(egui::Id::new("can_message_input_window"))
        .open(&mut open)
        .default_width(620.0)
        .default_height(maximum_height.min(680.0))
        .max_height(maximum_height)
        .min_width(600.0)
        .resizable(true)
        .collapsible(false)
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("can_message_input_content_scroll")
                .max_height(maximum_height - 48.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let changed = ui
                            .selectable_value(&mut app.input_tab, InputTab::Manual, "Manual entry")
                            .changed()
                            | ui.selectable_value(
                                &mut app.input_tab,
                                InputTab::Ai,
                                "AI structured entry",
                            )
                            .changed();
                        if changed {
                            app.input_needs_focus = true;
                        }
                    });
                    ui.separator();
                    ui.add_space(5.0);

                    match app.input_tab {
                        InputTab::Manual => manual_input_panel(ui, app),
                        InputTab::Ai => ai_input_panel(ui, app),
                    }
                });
        });
    app.show_input_window = open;
}

fn manual_input_panel(ui: &mut egui::Ui, app: &mut AnalyzerApp) {
    ui.label(
        RichText::new("Insert one Classic CAN frame")
            .size(15.0)
            .color(TEXT)
            .strong(),
    );
    ui.label(
        RichText::new(
            "Time is optional. CAN ID accepts decimal or 0x-prefixed hex; data bytes are hex.",
        )
        .size(10.5)
        .color(MUTED),
    );
    ui.add_space(9.0);

    egui::Grid::new("manual_can_message_fields")
        .num_columns(2)
        .min_col_width(118.0)
        .spacing([12.0, 9.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Time (ms)").color(MUTED));
            let response = ui.add(
                egui::TextEdit::singleline(&mut app.manual_input.time_ms)
                    .id(ui.make_persistent_id("manual_time_ms_input"))
                    .desired_width(430.0)
                    .hint_text("Optional; leave empty"),
            );
            if app.input_needs_focus {
                response.request_focus();
                app.input_needs_focus = false;
            }
            ui.end_row();

            ui.label(RichText::new("CAN ID").color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut app.manual_input.can_id)
                    .id(ui.make_persistent_id("manual_can_id_input"))
                    .desired_width(430.0)
                    .hint_text("Example: 0x40E or 1038"),
            );
            ui.end_row();

            ui.label(RichText::new("CAN data").color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut app.manual_input.can_data)
                    .id(ui.make_persistent_id("manual_can_data_input"))
                    .desired_width(430.0)
                    .hint_text("Example: 00 4B 03 01 01 00"),
            );
            ui.end_row();

            ui.label(RichText::new("DLC").color(MUTED));
            ui.label(
                RichText::new("Computed from data (0-8 bytes)")
                    .size(10.5)
                    .color(MUTED),
            );
            ui.end_row();
        });

    ui.add_space(10.0);
    let insert = ui
        .push_id("manual_insert_control", |ui| {
            ui.add(
                egui::Button::new(RichText::new("Insert frame").strong())
                    .fill(ACCENT)
                    .corner_radius(6.0)
                    .min_size(Vec2::new(112.0, 32.0)),
            )
        })
        .inner
        .clicked();
    if insert {
        app.add_manual_frame();
    }
    if let Some(message) = &app.manual_input.message {
        ui.add_space(8.0);
        input_status(ui, message);
    }
}

fn ai_input_panel(ui: &mut egui::Ui, app: &mut AnalyzerApp) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("AI structured import")
                .size(15.0)
                .color(TEXT)
                .strong(),
        );
        chip(ui, "glm-5-turbo", PURPLE);
        chip(ui, "Function Calling", ACCENT);
    });
    ui.label(
        RichText::new(
            "Natural-language or pasted frames are normalized, validated, then inserted as an array.",
        )
        .size(10.5)
        .color(MUTED),
    );
    ui.add_space(9.0);

    egui::Grid::new("ai_connection_fields")
        .num_columns(2)
        .min_col_width(118.0)
        .spacing([12.0, 9.0])
        .show(ui, |ui| {
            ui.label(RichText::new("API Key").color(MUTED));
            let response = ui.add(
                egui::TextEdit::singleline(&mut app.ai_input.api_key)
                    .id(ui.make_persistent_id("zai_api_key_input"))
                    .desired_width(430.0)
                    .password(true)
                    .hint_text("Required; kept in memory only"),
            );
            if app.input_needs_focus {
                response.request_focus();
                app.input_needs_focus = false;
            }
            ui.end_row();

            ui.label(RichText::new("API endpoint").color(MUTED));
            egui::ComboBox::from_id_salt("zai_endpoint_selector")
                .selected_text(app.ai_input.endpoint.label())
                .width(210.0)
                .show_ui(ui, |ui| {
                    for endpoint in AiEndpoint::ALL {
                        ui.selectable_value(
                            &mut app.ai_input.endpoint,
                            endpoint,
                            endpoint.label(),
                        );
                    }
                });
            ui.end_row();

            if app.ai_input.endpoint == AiEndpoint::CustomBase {
                ui.label(RichText::new("Base URL").color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut app.ai_input.custom_base_url)
                        .id(ui.make_persistent_id("zai_custom_base_url_input"))
                        .desired_width(410.0)
                        .hint_text("https://example.com/api/paas/v4"),
                )
                .on_hover_text(
                    "A chat/completions path is appended by zai-rs. HTTP is allowed only for localhost.",
                );
                ui.end_row();
            }
        });

    ui.add_space(7.0);
    ui.label(RichText::new("Messages to structure").color(MUTED));
    ui.scope(|ui| {
        ui.set_min_height(AI_INPUT_HEIGHT);
        ui.set_max_height(AI_INPUT_HEIGHT);
        egui::ScrollArea::vertical()
            .id_salt("ai_can_messages_input_scroll")
            .max_height(AI_INPUT_HEIGHT)
            .min_scrolled_height(AI_INPUT_HEIGHT)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::TextEdit::multiline(&mut app.ai_input.user_input)
                        .id(ui.make_persistent_id("ai_can_messages_input"))
                        .hint_text(
                            "Example: at 42.7 ms ID 0x40E data 00 4B 03 01 01 00; then ID 1035 data 00 CB 00 with no time",
                        )
                        .desired_rows(8)
                        .desired_width(f32::INFINITY),
                );
            });
    });

    egui::CollapsingHeader::new("Strict extraction rules")
        .id_salt("ai_prompt_rules_preview")
        .show(ui, |ui| {
            ui.label(
                RichText::new(
                    "Missing time remains null; seconds are converted to ms; IDs and bytes are range-checked; DLC is the actual byte count; no missing IDs, bytes, or timing are invented; source order is preserved.",
                )
                .size(10.5)
                .color(MUTED),
            );
        });

    ui.add_space(8.0);
    let busy = app.ai_busy();
    let run = ui
        .push_id("ai_structure_insert_control", |ui| {
            ui.add_enabled(
                !busy,
                egui::Button::new(if busy {
                    "Structuring..."
                } else {
                    "Structure and insert"
                })
                .fill(ACCENT)
                .corner_radius(6.0)
                .min_size(Vec2::new(150.0, 32.0)),
            )
        })
        .inner
        .clicked();
    if run {
        app.start_ai_import(ui.ctx().clone());
    }
    if let Some(message) = &app.ai_input.message {
        ui.add_space(8.0);
        input_status(ui, message);
    }

    if !app.ai_input.last_json.is_empty() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new("Last validated function-call JSON")
            .id_salt("ai_last_json_preview")
            .default_open(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("ai_last_json_scroll")
                    .max_height(190.0)
                    .show(ui, |ui| {
                        egui::Frame::new()
                            .fill(SURFACE)
                            .corner_radius(6.0)
                            .inner_margin(9.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&app.ai_input.last_json)
                                            .size(10.5)
                                            .color(TEXT)
                                            .monospace(),
                                    )
                                    .selectable(true)
                                    .wrap(),
                                );
                            });
                    });
            });
    }
}

fn input_status(ui: &mut egui::Ui, message: &Result<String, String>) {
    match message {
        Ok(message) => alert(ui, message, ACCENT),
        Err(message) => alert(ui, message, RED),
    }
}

fn message_list_panel(ui: &mut egui::Ui, app: &mut AnalyzerApp) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new("Messages").size(17.0).color(TEXT).strong());
            let count = app
                .document
                .as_ref()
                .map_or(0, |document| document.frames.len());
            ui.label(
                RichText::new(format!(
                    "{} shown | {count} total",
                    app.visible_indices.len()
                ))
                .size(10.0)
                .color(MUTED),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .push_id("time_sort_control", |ui| {
                    ui.add(
                        egui::Button::new(app.sort_order.label())
                            .fill(PANEL_SOFT)
                            .corner_radius(5.0)
                            .min_size(Vec2::new(92.0, 30.0)),
                    )
                })
                .inner
                .on_hover_text("Toggle chronological order")
                .clicked()
            {
                app.toggle_sort_order();
            }
        });
    });

    if let Some(error) = &app.load_error {
        ui.add_space(8.0);
        alert(ui, error, RED);
    }

    if let Some(message) = &app.operation_message {
        ui.add_space(8.0);
        match message {
            Ok(message) => alert(ui, message, ACCENT),
            Err(message) => alert(ui, message, RED),
        }
    }

    if let Some(document) = &app.document {
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            metric(ui, "TX", document.stats.tx, ACCENT);
            metric(ui, "RX", document.stats.rx, BLUE);
            metric(ui, "G1", document.stats.group1, ACCENT);
            metric(ui, "G2", document.stats.group2, BLUE);
            metric(ui, "G3", document.stats.group3, AMBER);
            metric(ui, "G4", document.stats.group4, PURPLE);
            let entered = document.stats.user_created;
            if entered > 0 {
                metric(ui, "ENTERED", entered, ACCENT);
            }
            if document.stats.warnings > 0 {
                metric(ui, "WARN", document.stats.warnings, AMBER);
            }
            if document.skipped_message_lines > 0 {
                metric(ui, "SKIPPED", document.skipped_message_lines, AMBER);
            }
            ui.label(
                RichText::new(format!("{:.1} ms", document.stats.duration_ms))
                    .size(10.0)
                    .color(MUTED)
                    .monospace(),
            );
        });
        if document.skipped_message_lines > 0 {
            ui.add_space(6.0);
            alert(
                ui,
                &format!(
                    "{} message-like line(s) were invalid and skipped while loading",
                    document.skipped_message_lines
                ),
                AMBER,
            );
        }
    }

    if app
        .document
        .as_ref()
        .is_some_and(|document| document.stats.io_assembly_candidates > 0)
    {
        ui.add_space(10.0);
        let mut selection = app.io_assembly;
        if io_assembly_controls(ui, &mut selection) {
            app.set_io_assembly_selection(selection);
        }
    }

    ui.add_space(10.0);
    if filter_bar(ui, &mut app.filters) {
        app.refresh_visible_indices();
    }
    ui.add_space(8.0);

    let Some(document) = &app.document else {
        empty_state(
            ui,
            "No trace loaded",
            "Open or drop a PCAN-Explorer trace file to begin.",
        );
        return;
    };

    if app.visible_indices.is_empty() {
        empty_state(
            ui,
            "No matching messages",
            "Clear the search or change the active filters.",
        );
        return;
    }

    let visible_indices = &app.visible_indices;
    let selected_index = app.selected_index;
    let scroll_to_position = app.scroll_to_position.take();
    let table_width = MESSAGE_TABLE_WIDTH.max(ui.available_width());
    let viewport_height = ui.available_height();
    let mut clicked_index = None;
    let mut rendered_row_range = 0..0;
    egui::ScrollArea::horizontal()
        .id_salt("message_table_horizontal_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(table_width);
            table_header(ui, table_width);
            ui.add_space(2.0);
            let mut rows = egui::ScrollArea::vertical()
                .id_salt("message_table_vertical_scroll")
                .auto_shrink([false, false]);
            if let Some(position) = scroll_to_position {
                let centered_offset = position as f32 * MESSAGE_ROW_HEIGHT
                    - (viewport_height - MESSAGE_ROW_HEIGHT) * 0.5;
                rows = rows.vertical_scroll_offset(centered_offset.max(0.0));
            }
            rows.show_rows(
                ui,
                MESSAGE_ROW_HEIGHT,
                visible_indices.len(),
                |ui, row_range| {
                    rendered_row_range = row_range.clone();
                    for row in row_range {
                        let source_index = visible_indices[row];
                        let frame = &document.frames[source_index];
                        if ui
                            .push_id(("message_row_position", row), |ui| {
                                message_row(
                                    ui,
                                    &frame.message,
                                    frame.analysis.as_ref(),
                                    frame.origin,
                                    selected_index == Some(source_index),
                                    row,
                                    table_width,
                                )
                            })
                            .inner
                        {
                            clicked_index = Some(source_index);
                        }
                    }
                },
            );
        });
    app.rendered_row_range = rendered_row_range;
    if let Some(index) = clicked_index {
        app.selected_index = Some(index);
    }
}

fn io_assembly_controls(ui: &mut egui::Ui, selection: &mut IoAssemblySelection) -> bool {
    let mut changed = false;
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(7.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("I/O ASSEMBLY MAPPING")
                        .size(10.5)
                        .color(MUTED)
                        .strong(),
                );
                ui.label(
                    RichText::new(format!(
                        "Vol1 6-29 / 6-39 + supplied device-table/R02 mappings · Host MAC {} · Output host → device · Input device → host",
                        selection.host_mac_id
                    ))
                    .size(11.0)
                    .color(MUTED),
                );
            });
            ui.label(
                RichText::new(
                    "Select each direction once; the mapping is saved locally and reused for later traces",
                )
                .size(10.5)
                .color(MUTED),
            );
            ui.label(
                RichText::new(
                    "No implicit EDS scaling · Counts conversion requires device Data Units and Full Scale",
                )
                .size(10.5)
                .color(MUTED),
            );
            ui.add_space(7.0);
            egui::Grid::new("io_assembly_selectors")
                .num_columns(2)
                .min_col_width(112.0)
                .spacing([12.0, 7.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Input instance").size(11.5).color(TEXT));
                    changed |= assembly_combo(
                        ui,
                        "input_assembly_instance",
                        &mut selection.input_instance,
                        INPUT_ASSEMBLIES,
                        "Select input instance…",
                    );
                    ui.end_row();

                    ui.label(RichText::new("Output instance").size(11.5).color(TEXT));
                    changed |= assembly_combo(
                        ui,
                        "output_assembly_instance",
                        &mut selection.output_instance,
                        OUTPUT_ASSEMBLIES,
                        "Select output instance…",
                    );
                    ui.end_row();
                });
        });
    changed
}

fn assembly_combo(
    ui: &mut egui::Ui,
    id: &'static str,
    selected: &mut Option<u8>,
    instances: &'static [IoAssemblyInstance],
    placeholder: &'static str,
) -> bool {
    let selected_text = selected
        .and_then(|number| instances.iter().find(|instance| instance.number == number))
        .map_or_else(
            || placeholder.to_owned(),
            |instance| {
                format!(
                    "{} (0x{:02X}) — {} · {}",
                    instance.number,
                    instance.number,
                    instance.name,
                    instance.numeric_format().label()
                )
            },
        );
    let mut changed = false;
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected_text)
        .width(ui.available_width().max(260.0))
        .show_ui(ui, |ui| {
            changed |= ui
                .selectable_value(selected, None, "Not selected — keep raw I/O data")
                .changed();
            for instance in instances {
                let label = format!(
                    "{} (0x{:02X}) — {} · {} B · {} · {}",
                    instance.number,
                    instance.number,
                    instance.name,
                    instance.byte_len,
                    instance.profile,
                    instance.numeric_format().label()
                );
                let response = ui
                    .selectable_value(selected, Some(instance.number), label)
                    .on_hover_text(instance.requirements);
                changed |= response.changed();
            }
        });
    changed
}

fn filter_bar(ui: &mut egui::Ui, filters: &mut MessageFilters) -> bool {
    let search_id = ui.make_persistent_id("message_search_input");
    let mut changed = ui
        .add(
            egui::TextEdit::singleline(&mut filters.query)
                .id(search_id)
                .hint_text("Search ID, data, service, field...")
                .desired_width(f32::INFINITY),
        )
        .changed();

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Scope").size(10.0).color(MUTED));
        egui::ComboBox::from_id_salt("frame_scope_filter")
            .selected_text(filters.scope.label())
            .width(104.0)
            .show_ui(ui, |ui| {
                for scope in FrameScope::ALL {
                    changed |= ui
                        .selectable_value(&mut filters.scope, scope, scope.label())
                        .changed();
                }
            });
        ui.add_space(6.0);
        ui.label(RichText::new("Direction").size(10.0).color(MUTED));
        egui::ComboBox::from_id_salt("direction_filter")
            .selected_text(filters.direction.label())
            .width(64.0)
            .show_ui(ui, |ui| {
                for direction in DirectionFilter::ALL {
                    changed |= ui
                        .selectable_value(&mut filters.direction, direction, direction.label())
                        .changed();
                }
            });
        let filters_active = !filters.query.is_empty()
            || filters.scope != FrameScope::All
            || filters.direction != DirectionFilter::All;
        if filters_active
            && ui
                .push_id("reset_filters_control", |ui| ui.small_button("Reset"))
                .inner
                .clicked()
        {
            *filters = MessageFilters::default();
            changed = true;
        }
    });
    changed
}

fn table_header(ui: &mut egui::Ui, width: f32) {
    egui::Frame::new()
        .fill(SURFACE)
        .corner_radius(5.0)
        .inner_margin(egui::Margin::symmetric(0, 2))
        .show(ui, |ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 26.0), Sense::hover());
            paint_message_columns(ui, rect, None, None, None, MUTED);
        });
}

fn message_row(
    ui: &mut egui::Ui,
    message: &TraceMessage,
    analysis: Option<&FrameAnalysis>,
    origin: FrameOrigin,
    selected: bool,
    row: usize,
    width: f32,
) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width, MESSAGE_ROW_HEIGHT), Sense::click());
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            true,
            selected,
            format!(
                "Frame {}, ID {:03X}, {}, data {}",
                message.number,
                message.identifier,
                message.direction,
                message.data_hex()
            ),
        )
    });
    if row % 2 == 1 {
        ui.painter()
            .rect_filled(rect.shrink(1.0), 4.0, PANEL_SOFT.gamma_multiply(0.5));
    }
    if selected {
        ui.painter()
            .rect_filled(rect.shrink(1.0), 4.0, ACCENT.gamma_multiply(0.18));
        ui.painter().rect_stroke(
            rect.shrink(1.0),
            4.0,
            Stroke::new(1.0, ACCENT.gamma_multiply(0.8)),
            egui::StrokeKind::Inside,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(rect.shrink(1.0), 4.0, PANEL_SOFT);
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect.shrink(2.0),
            4.0,
            Stroke::new(1.0, BLUE),
            egui::StrokeKind::Inside,
        );
    }

    let direction_color = if message.direction.eq_ignore_ascii_case("Tx") {
        ACCENT
    } else {
        BLUE
    };
    paint_message_columns(
        ui,
        rect,
        Some(message),
        analysis,
        Some(origin),
        direction_color,
    );
    let clicked = response.clicked();
    if clicked {
        response.request_focus();
        response.ctx.request_repaint();
    }
    clicked
}

fn paint_message_columns(
    ui: &egui::Ui,
    rect: egui::Rect,
    message: Option<&TraceMessage>,
    analysis: Option<&FrameAnalysis>,
    origin: Option<FrameOrigin>,
    direction_color: Color32,
) {
    let mono = FontId::new(12.0, FontFamily::Monospace);
    let y = rect.center().y;
    let x = rect.left();
    let painter = ui.painter();
    let (number, time, bus, direction, identifier, dlc, data) = match message {
        Some(message) => (
            message.number.to_string(),
            message
                .time_offset_ms
                .map(|time| format!("{time:.1}"))
                .unwrap_or_default(),
            message.bus.to_string(),
            message.direction.clone(),
            format!("{:03X}", message.identifier),
            message.dlc.to_string(),
            message.data_hex(),
        ),
        None => (
            "No.".into(),
            "Time ms".into(),
            "Bus".into(),
            "Dir".into(),
            "ID".into(),
            "DLC".into(),
            "Data".into(),
        ),
    };
    let normal = if message.is_some() { TEXT } else { MUTED };
    painter.text(
        Pos2::new(x + 42.0, y),
        Align2::RIGHT_CENTER,
        number,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 128.0, y),
        Align2::RIGHT_CENTER,
        time,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 166.0, y),
        Align2::RIGHT_CENTER,
        bus,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 205.0, y),
        Align2::RIGHT_CENTER,
        direction,
        mono.clone(),
        direction_color,
    );
    painter.text(
        Pos2::new(x + 252.0, y),
        Align2::RIGHT_CENTER,
        identifier,
        mono.clone(),
        if message.is_some() { BLUE } else { MUTED },
    );
    painter.text(
        Pos2::new(x + 290.0, y),
        Align2::RIGHT_CENTER,
        dlc,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 310.0, y),
        Align2::LEFT_CENTER,
        data,
        mono,
        normal,
    );
    painter.text(
        Pos2::new(x + 555.0, y),
        Align2::LEFT_CENTER,
        origin.map_or("Source", FrameOrigin::label),
        FontId::new(11.0, FontFamily::Monospace),
        match origin {
            Some(FrameOrigin::Manual) => ACCENT,
            Some(FrameOrigin::Ai) => PURPLE,
            Some(FrameOrigin::File) => MUTED,
            None => MUTED,
        },
    );
    let meaning = analysis.map_or_else(
        || {
            if message.is_some() {
                String::new()
            } else {
                "Meaning".into()
            }
        },
        analysis_summary_label,
    );
    painter.text(
        Pos2::new(x + 650.0, y),
        Align2::LEFT_CENTER,
        meaning,
        FontId::new(11.0, FontFamily::Proportional),
        analysis.map_or(MUTED, analysis_color),
    );
}

fn selected_message_panel(ui: &mut egui::Ui, app: &mut AnalyzerApp) {
    details_toolbar(ui, app);
    ui.add_space(10.0);

    let Some(source_index) = app.selected_source_index() else {
        empty_state(
            ui,
            "No message selected",
            "Select a row from the message browser to inspect it.",
        );
        return;
    };
    let Some(document) = &app.document else {
        return;
    };
    let frame = &document.frames[source_index];
    let message = &frame.message;
    let analysis = frame.analysis.as_ref();
    let origin = frame.origin;

    egui::ScrollArea::vertical()
        .id_salt("message_details_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            selected_summary(ui, message, origin);
            ui.add_space(14.0);
            section_label(ui, "CAN IDENTIFIER");
            card(ui, |ui| match message.decoded_identifier() {
                Ok(decoded) => decoded_identifier_panel(ui, decoded),
                Err(error) => {
                    ui.label(
                        RichText::new(format!("0x{:X}", message.identifier))
                            .size(26.0)
                            .color(RED)
                            .strong()
                            .monospace(),
                    );
                    ui.label(RichText::new(error.to_string()).color(RED));
                }
            });
            ui.add_space(14.0);
            data_decoder_panel(ui, source_index, message, analysis);
        });
}

fn details_toolbar(ui: &mut egui::Ui, app: &mut AnalyzerApp) {
    let selected_position = app.selected_position();
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Message inspector")
                .size(17.0)
                .color(TEXT)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let can_next =
                selected_position.is_some_and(|position| position + 1 < app.visible_indices.len());
            if ui
                .push_id("next_message_control", |ui| {
                    ui.add_enabled(can_next, egui::Button::new("Next"))
                })
                .inner
                .clicked()
            {
                app.select_relative(1);
            }
            let can_previous = selected_position.is_some_and(|position| position > 0);
            if ui
                .push_id("previous_message_control", |ui| {
                    ui.add_enabled(can_previous, egui::Button::new("Previous"))
                })
                .inner
                .clicked()
            {
                app.select_relative(-1);
            }
            if let Some(position) = selected_position {
                ui.add_sized(
                    [76.0, 28.0],
                    egui::Label::new(
                        RichText::new(format!("{} / {}", position + 1, app.visible_indices.len()))
                            .size(11.0)
                            .color(MUTED)
                            .monospace(),
                    ),
                );
            }
        });
    });
}

fn selected_summary(ui: &mut egui::Ui, message: &TraceMessage, origin: FrameOrigin) {
    let direction_color = if message.direction.eq_ignore_ascii_case("Tx") {
        ACCENT
    } else {
        BLUE
    };
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("Frame #{}", message.number))
                    .size(14.0)
                    .color(TEXT)
                    .strong()
                    .monospace(),
            );
            if let Some(time) = message.time_offset_ms {
                chip(ui, &format!("{time:.1} ms"), MUTED);
            } else {
                chip(ui, "Time not set", MUTED);
            }
            chip(ui, &format!("Bus {}", message.bus), MUTED);
            chip(ui, &message.direction, direction_color);
            chip(ui, &format!("DLC {}", message.dlc), MUTED);
            chip(
                ui,
                origin.label(),
                match origin {
                    FrameOrigin::File => MUTED,
                    FrameOrigin::Manual => ACCENT,
                    FrameOrigin::Ai => PURPLE,
                },
            );
        });
    });
}

fn data_decoder_panel(
    ui: &mut egui::Ui,
    source_index: usize,
    message: &TraceMessage,
    analysis: Option<&FrameAnalysis>,
) {
    ui.horizontal(|ui| {
        section_label(ui, "DEVICENET DATA DECODER");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let (label, color) = analysis.map_or(("NOT DEVICENET", MUTED), |analysis| {
                (analysis.function.label(), analysis_color(analysis))
            });
            chip(ui, label, color);
        });
    });
    ui.add_space(7.0);

    let raw = if message.data.is_empty() {
        "(no data)".to_owned()
    } else {
        message.data_hex()
    };
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(7.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("RAW").size(10.5).color(MUTED).strong());
                ui.label(
                    RichText::new(&raw)
                        .size(13.0)
                        .color(TEXT)
                        .strong()
                        .monospace(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .push_id(("copy_raw_control", source_index), |ui| {
                            ui.small_button("Copy")
                        })
                        .inner
                        .clicked()
                    {
                        ui.ctx().copy_text(raw.clone());
                    }
                });
            });
        });
    ui.add_space(10.0);

    let Some(analysis) = analysis else {
        alert(
            ui,
            "The frame could not be decoded as a standard 11-bit DeviceNet identifier.",
            MUTED,
        );
        return;
    };

    let display_title = humanize_service_text(&analysis.title);
    ui.label(
        RichText::new(display_title)
            .size(15.0)
            .color(analysis_color(analysis))
            .strong(),
    );
    ui.add_space(7.0);
    if let Some(subject) = analysis.subject {
        semantic_subject_card(ui, subject, analysis_color(analysis));
        ui.add_space(10.0);
    }

    let values = analysis
        .fields
        .iter()
        .filter(|field| field.role == DecodedFieldRole::Value)
        .collect::<Vec<_>>();
    let context = analysis
        .fields
        .iter()
        .filter(|field| {
            field.role != DecodedFieldRole::Value
                && (analysis.subject.is_none() || field.role != DecodedFieldRole::Target)
        })
        .collect::<Vec<_>>();

    if !values.is_empty() {
        section_label(ui, "PARSED VALUES");
        ui.add_space(6.0);
        decoded_field_card(ui, ("decoded_values", source_index), &values, true);
    }
    if !context.is_empty() {
        if !values.is_empty() {
            ui.add_space(9.0);
        }
        egui::CollapsingHeader::new(if analysis.subject.is_some() {
            "Protocol and correlation details"
        } else {
            "Decoded fields"
        })
        .id_salt(("decoded_context", source_index))
        .default_open(values.is_empty())
        .show(ui, |ui| {
            decoded_field_card(
                ui,
                ("decoded_context_fields", source_index),
                &context,
                false,
            );
        });
    }

    if !analysis.warnings.is_empty() {
        ui.add_space(9.0);
        for warning in &analysis.warnings {
            alert(ui, &format!("Warning: {warning}"), AMBER);
        }
    }
}

fn analysis_summary_label(analysis: &FrameAnalysis) -> String {
    match analysis.subject {
        Some(AnalysisSubject::Explicit(subject)) => format!(
            "{} · {} / {}",
            subject.operation.label(),
            subject.instance_name,
            subject.attribute_name
        ),
        Some(AnalysisSubject::IoAssembly(subject)) => format!(
            "{} Assembly {} · {}",
            subject.direction.label(),
            subject.number,
            subject.name
        ),
        None => humanize_service_text(&analysis.title),
    }
}

fn semantic_subject_card(ui: &mut egui::Ui, subject: AnalysisSubject, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.09))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.55)))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            match subject {
                AnalysisSubject::Explicit(subject) => {
                    ui.horizontal_wrapped(|ui| {
                        chip(ui, subject.operation.label(), color);
                        chip(
                            ui,
                            if subject.writable {
                                "GET / SET"
                            } else {
                                "GET only"
                            },
                            if subject.writable { ACCENT } else { MUTED },
                        );
                        chip(ui, subject.data_type, BLUE);
                    });
                    ui.add_space(7.0);
                    ui.label(
                        RichText::new(subject.target_label())
                            .size(18.0)
                            .color(TEXT)
                            .strong(),
                    );
                    ui.label(RichText::new(subject.object_name).size(11.0).color(MUTED));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(subject.address_label())
                            .size(11.5)
                            .color(color)
                            .monospace(),
                    );
                }
                AnalysisSubject::IoAssembly(subject) => {
                    let direction_color = match subject.direction {
                        devicenet_identifier_analyzer::IoAssemblyDirection::Input => BLUE,
                        devicenet_identifier_analyzer::IoAssemblyDirection::Output => ACCENT,
                    };
                    ui.horizontal_wrapped(|ui| {
                        chip(ui, subject.direction.label(), direction_color);
                        chip(ui, &format!("Instance {}", subject.number), color);
                        chip(ui, &format!("{} bytes", subject.byte_len), MUTED);
                    });
                    ui.add_space(7.0);
                    ui.label(RichText::new(subject.name).size(18.0).color(TEXT).strong());
                    ui.label(RichText::new(subject.profile).size(11.0).color(MUTED));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(match subject.direction {
                            devicenet_identifier_analyzer::IoAssemblyDirection::Input => {
                                "Device → host · decoded with the selected Input instance"
                            }
                            devicenet_identifier_analyzer::IoAssemblyDirection::Output => {
                                "Host → device · decoded with the selected Output instance"
                            }
                        })
                        .size(11.5)
                        .color(direction_color),
                    );
                }
            }
        });
}

fn decoded_field_card(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    fields: &[&DecodedField],
    prominent: bool,
) {
    egui::Frame::new()
        .fill(if prominent { SURFACE } else { PANEL })
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(9.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new(id)
                .num_columns(2)
                .min_col_width(126.0)
                .spacing([16.0, if prominent { 12.0 } else { 8.0 }])
                .striped(!prominent)
                .show(ui, |ui| {
                    for field in fields {
                        let service_code = field.service_code;
                        let name_response = ui.add(
                            egui::Label::new(
                                RichText::new(&field.name)
                                    .size(if prominent { 11.5 } else { 11.0 })
                                    .color(if prominent { BLUE } else { MUTED })
                                    .strong(),
                            )
                            .wrap(),
                        );
                        let display_value = if service_code.is_some() {
                            humanize_service_text(&field.value)
                        } else {
                            field.value.clone()
                        };
                        let value_response = ui
                            .vertical(|ui| {
                                let response = ui
                                    .horizontal_wrapped(|ui| {
                                        let response = ui.add(
                                            egui::Label::new(
                                                RichText::new(display_value)
                                                    .size(if prominent { 16.0 } else { 12.0 })
                                                    .color(TEXT)
                                                    .monospace()
                                                    .strong(),
                                            )
                                            .wrap(),
                                        );
                                        if let Some(unit) = &field.unit {
                                            chip(ui, unit, ACCENT);
                                        }
                                        response
                                    })
                                    .inner;
                                if let Some(description) = &field.description {
                                    ui.add_space(2.0);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(description).size(11.0).color(MUTED),
                                        )
                                        .wrap(),
                                    );
                                }
                                response
                            })
                            .inner;
                        if let Some(code) = service_code {
                            add_service_tooltip(name_response, code, &field.value);
                            add_service_tooltip(value_response, code, &field.value);
                        }
                        ui.end_row();
                    }
                });
        });
}

fn humanize_service_text(value: &str) -> String {
    value.replace('_', " ")
}

fn add_service_tooltip(response: egui::Response, code: u8, value: &str) {
    let description = contextual_service_description(code, value);
    response
        .on_hover_ui(|ui| {
            ui.set_max_width(360.0);
            ui.label(
                RichText::new(format!("Service Code 0x{code:02X}"))
                    .size(12.0)
                    .color(ACCENT)
                    .strong()
                    .monospace(),
            );
            ui.add_space(3.0);
            ui.add(egui::Label::new(RichText::new(description).size(12.0).color(TEXT)).wrap());
            ui.add_space(3.0);
            ui.add(
                egui::Label::new(
                    RichText::new("Responses set bit 7 (request service + 0x80).")
                        .size(10.0)
                        .color(MUTED),
                )
                .wrap(),
            );
        })
        .on_hover_cursor(egui::CursorIcon::Help);
}

fn contextual_service_description(code: u8, value: &str) -> &'static str {
    match (code, value) {
        (0x4b, value) if value.contains("Open_Explicit") => {
            "Establishes a DeviceNet Explicit Messaging Connection through the UCMM."
        }
        (0x4b, value) if value.contains("Allocate_Controller") => {
            "Allocates the requested predefined Controller/Device connection set."
        }
        (0x4b, value) if value.contains("Allocate_Offline") => {
            "Claims ownership of the DeviceNet Offline Connection Set."
        }
        (0x4b, value) if value.contains("Who") => {
            "Discovers a communication-faulted node's Vendor ID and Serial Number."
        }
        (0x4c, value) if value.contains("Close_Connection") => {
            "Deletes the selected DeviceNet connection and releases its resources."
        }
        (0x4c, value) if value.contains("Release_Controller") => {
            "Releases selected predefined Controller/Device connections."
        }
        (0x4c, value) if value.contains("Identify") => {
            "Finds or visually identifies communication-faulted nodes."
        }
        (0x4d, value) if value.contains("Heartbeat") => {
            "Broadcasts the current DeviceNet device state and fault information."
        }
        (0x4d, value) if value.contains("Change_MAC") => {
            "Changes the MAC ID of a matching communication-faulted node."
        }
        (0x4e, value) if value.contains("Shutdown") => {
            "Reports the class, instance, and reason responsible for device shutdown."
        }
        _ => service_description(code),
    }
}

fn decoded_identifier_panel(ui: &mut egui::Ui, decoded: DecodedIdentifier) {
    let color = group_color(decoded.group);
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format!("0x{:03X}", decoded.raw))
                .size(28.0)
                .color(TEXT)
                .strong()
                .monospace(),
        );
        chip(ui, decoded.group.label(), color);
        ui.label(
            RichText::new(decoded.binary())
                .size(13.0)
                .color(MUTED)
                .monospace(),
        );
    });
    ui.add_space(11.0);
    bit_fields(ui, decoded);
}

fn bit_fields(ui: &mut egui::Ui, decoded: DecodedIdentifier) {
    ui.horizontal_wrapped(|ui| match decoded.fields {
        IdentifierFields::Group1 {
            message_id,
            source_mac_id,
        } => {
            bit_chip(ui, "GROUP", "0", MUTED);
            bit_chip(ui, "MESSAGE ID [9:6]", &format!("{message_id:04b}"), ACCENT);
            bit_chip(
                ui,
                "SOURCE MAC [5:0]",
                &format!("{source_mac_id:06b}"),
                BLUE,
            );
        }
        IdentifierFields::Group2 { mac_id, message_id } => {
            bit_chip(ui, "GROUP", "10", MUTED);
            bit_chip(ui, "MAC ID [8:3]", &format!("{mac_id:06b}"), BLUE);
            bit_chip(ui, "MESSAGE ID [2:0]", &format!("{message_id:03b}"), ACCENT);
        }
        IdentifierFields::Group3 {
            message_id,
            source_mac_id,
        } => {
            bit_chip(ui, "GROUP", "11", MUTED);
            bit_chip(ui, "MESSAGE ID [8:6]", &format!("{message_id:03b}"), AMBER);
            bit_chip(
                ui,
                "SOURCE MAC [5:0]",
                &format!("{source_mac_id:06b}"),
                BLUE,
            );
        }
        IdentifierFields::Group4 { message_id } => {
            bit_chip(ui, "GROUP", "11111", MUTED);
            bit_chip(ui, "MESSAGE ID [5:0]", &format!("{message_id:06b}"), PURPLE);
        }
        IdentifierFields::Invalid => {
            bit_chip(ui, "RESERVED PREFIX", "1111111", RED);
            bit_chip(
                ui,
                "INVALID BITS",
                &format!("{:04b}", decoded.raw & 0x0f),
                MUTED,
            );
        }
    });
}

fn bit_chip(ui: &mut egui::Ui, label: &str, bits: &str, color: Color32) {
    egui::Frame::new()
        .fill(PANEL_SOFT)
        .corner_radius(5.0)
        .inner_margin(egui::Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).size(10.5).color(MUTED));
                ui.label(
                    RichText::new(bits)
                        .size(12.0)
                        .color(color)
                        .strong()
                        .monospace(),
                );
            });
        });
}

fn metric(ui: &mut egui::Ui, label: &str, value: usize, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(6, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{label} {value}"))
                    .size(10.0)
                    .color(color)
                    .strong(),
            );
        });
}

fn chip(ui: &mut egui::Ui, label: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.14))
        .corner_radius(5.0)
        .inner_margin(egui::Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(10.5).color(color).strong());
        });
}

fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui);
        });
}

fn alert(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.55)))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(9, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).size(11.5).color(color)).wrap());
        });
}

fn empty_state(ui: &mut egui::Ui, title: &str, description: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(70.0);
        ui.label(RichText::new(title).size(16.0).color(TEXT).strong());
        ui.add_space(4.0);
        ui.label(RichText::new(description).size(11.0).color(MUTED));
    });
}

fn section_label(ui: &mut egui::Ui, label: &str) {
    ui.label(RichText::new(label).size(10.5).color(MUTED).strong());
}

fn analysis_color(analysis: &FrameAnalysis) -> Color32 {
    match analysis.function {
        FrameFunction::ConnectedExplicitRequest
        | FrameFunction::Group3UnconnectedRequest
        | FrameFunction::Group2(
            Group2Function::ExplicitRequest | Group2Function::UnconnectedExplicitRequest,
        ) => ACCENT,
        FrameFunction::ConnectedExplicitResponse
        | FrameFunction::Group3UnconnectedResponse
        | FrameFunction::Group2(Group2Function::ExplicitOrUnconnectedResponse) => BLUE,
        FrameFunction::Group2(Group2Function::DuplicateMacIdCheck)
        | FrameFunction::Group3Invalid => AMBER,
        FrameFunction::Group1Connection => ACCENT,
        FrameFunction::Group1IoMulticastPollResponse
        | FrameFunction::Group1IoChangeOfStateOrCyclic
        | FrameFunction::Group1IoBitStrobeResponse
        | FrameFunction::Group1IoPollResponseOrChangeOfStateAck => PURPLE,
        FrameFunction::Group3Connection => AMBER,
        FrameFunction::Group4Reserved
        | FrameFunction::Group4CommunicationFaultedResponse
        | FrameFunction::Group4CommunicationFaultedRequest
        | FrameFunction::Group4OfflineOwnershipResponse
        | FrameFunction::Group4OfflineOwnershipRequest
        | FrameFunction::Group2(
            Group2Function::IoBitStrobeCommand
            | Group2Function::IoMulticastPollCommand
            | Group2Function::ChangeOfStateOrCyclicAck
            | Group2Function::IoPollOrChangeOfStateOrCyclic,
        ) => PURPLE,
        FrameFunction::InvalidIdentifier => RED,
    }
}

fn group_color(group: MessageGroup) -> Color32 {
    match group {
        MessageGroup::Group1 => ACCENT,
        MessageGroup::Group2 => BLUE,
        MessageGroup::Group3 => AMBER,
        MessageGroup::Group4 => PURPLE,
        MessageGroup::Invalid => RED,
    }
}
