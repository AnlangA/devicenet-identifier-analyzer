use crate::ai_import::AiEndpoint;
use crate::app::{AnalyzerApp, DirectionFilter, FrameScope, InputTab, MessageFilters};
use crate::frame_input::FrameOrigin;
use crate::theme::{
    ACCENT, AMBER, BG, BLUE, BORDER, MUTED, PANEL, PANEL_SOFT, PURPLE, RED, SURFACE, TEXT,
};
use devicenet_identifier_analyzer::{
    DecodedIdentifier, FrameAnalysis, FrameFunction, Group2Function, IdentifierFields,
    MessageGroup, TraceMessage, service_description,
};
use eframe::egui::{
    self, Align2, Color32, FontFamily, FontId, Pos2, RichText, Sense, Stroke, Vec2,
};
use rfd::FileDialog;

const MESSAGE_TABLE_WIDTH: f32 = 735.0;
const MESSAGE_ROW_HEIGHT: f32 = 25.0;
const AI_INPUT_HEIGHT: f32 = 150.0;

impl eframe::App for AnalyzerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_ai_job(ui.ctx());
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

        egui::Panel::top("application_header")
            .exact_size(80.0)
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .stroke(Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(22, 14)),
            )
            .show(ui, |ui| header(ui, self));

        let browser_max_width = (ui.available_width() - 430.0).clamp(470.0, 820.0);
        egui::Panel::left("message_browser")
            .resizable(true)
            .default_size(620.0)
            .size_range(470.0..=browser_max_width)
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
    ui.horizontal(|ui| {
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

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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

            if let Some(document) = &app.document {
                ui.add_space(8.0);
                let file = ui.label(RichText::new(document.file_name()).size(11.0).color(MUTED));
                file.on_hover_text(document.path.display().to_string());
            }
        });
    });
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
                        ui.selectable_value(&mut app.input_tab, InputTab::Manual, "Manual entry");
                        ui.selectable_value(
                            &mut app.input_tab,
                            InputTab::Ai,
                            "AI structured entry",
                        );
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
            ui.add(
                egui::TextEdit::singleline(&mut app.manual_input.time_ms)
                    .id(ui.make_persistent_id("manual_time_ms_input"))
                    .hint_text("Optional; leave empty"),
            );
            ui.end_row();

            ui.label(RichText::new("CAN ID").color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut app.manual_input.can_id)
                    .id(ui.make_persistent_id("manual_can_id_input"))
                    .hint_text("Example: 0x40E or 1038"),
            );
            ui.end_row();

            ui.label(RichText::new("CAN data").color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut app.manual_input.can_data)
                    .id(ui.make_persistent_id("manual_can_data_input"))
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
        chip(ui, "zai-rs 0.6.0", BLUE);
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
            ui.add(
                egui::TextEdit::singleline(&mut app.ai_input.api_key)
                    .id(ui.make_persistent_id("zai_api_key_input"))
                    .password(true)
                    .hint_text("Required; kept in memory only"),
            );
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
                .map_or(0, |document| document.trace.messages.len());
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
            let entered = document
                .origins
                .iter()
                .filter(|origin| origin.is_user_created())
                .count();
            if entered > 0 {
                metric(ui, "ENTERED", entered, ACCENT);
            }
            if document.stats.warnings > 0 {
                metric(ui, "WARN", document.stats.warnings, AMBER);
            }
            ui.label(
                RichText::new(format!("{:.1} ms", document.stats.duration_ms))
                    .size(10.0)
                    .color(MUTED)
                    .monospace(),
            );
        });
    }

    ui.add_space(10.0);
    if filter_bar(ui, &mut app.filters) {
        app.refresh_visible_indices();
    }
    ui.add_space(8.0);

    table_header(ui);
    ui.add_space(2.0);

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
    let mut clicked_index = None;
    egui::ScrollArea::both()
        .id_salt("message_table_scroll")
        .auto_shrink([false, false])
        .show_rows(
            ui,
            MESSAGE_ROW_HEIGHT,
            visible_indices.len(),
            |ui, row_range| {
                ui.set_min_width(MESSAGE_TABLE_WIDTH);
                for row in row_range {
                    let source_index = visible_indices[row];
                    let message = &document.trace.messages[source_index];
                    if ui
                        .push_id(("message_row_position", row), |ui| {
                            message_row(
                                ui,
                                message,
                                document.origins[source_index],
                                selected_index == Some(source_index),
                            )
                        })
                        .inner
                    {
                        clicked_index = Some(source_index);
                    }
                }
            },
        );
    if let Some(index) = clicked_index {
        app.selected_index = Some(index);
    }
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

fn table_header(ui: &mut egui::Ui) {
    egui::Frame::new()
        .fill(SURFACE)
        .corner_radius(5.0)
        .inner_margin(egui::Margin::symmetric(0, 2))
        .show(ui, |ui| {
            let (rect, _) = ui.allocate_exact_size(
                Vec2::new(ui.available_width().max(370.0), 24.0),
                Sense::hover(),
            );
            paint_message_columns(ui, rect, None, None, MUTED);
        });
}

fn message_row(
    ui: &mut egui::Ui,
    message: &TraceMessage,
    origin: FrameOrigin,
    selected: bool,
) -> bool {
    let width = MESSAGE_TABLE_WIDTH.max(ui.available_width());
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width, MESSAGE_ROW_HEIGHT), Sense::click());
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
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

    let direction_color = if message.direction.eq_ignore_ascii_case("Tx") {
        ACCENT
    } else {
        BLUE
    };
    paint_message_columns(ui, rect, Some(message), Some(origin), direction_color);
    let clicked = response.clicked();
    if clicked {
        response.ctx.request_repaint();
    }
    clicked
}

fn paint_message_columns(
    ui: &egui::Ui,
    rect: egui::Rect,
    message: Option<&TraceMessage>,
    origin: Option<FrameOrigin>,
    direction_color: Color32,
) {
    let mono = FontId::new(11.5, FontFamily::Monospace);
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
        Pos2::new(x + 44.0, y),
        Align2::RIGHT_CENTER,
        number,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 142.0, y),
        Align2::RIGHT_CENTER,
        time,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 190.0, y),
        Align2::RIGHT_CENTER,
        bus,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 235.0, y),
        Align2::RIGHT_CENTER,
        direction,
        mono.clone(),
        direction_color,
    );
    painter.text(
        Pos2::new(x + 300.0, y),
        Align2::RIGHT_CENTER,
        identifier,
        mono.clone(),
        if message.is_some() { BLUE } else { MUTED },
    );
    painter.text(
        Pos2::new(x + 347.0, y),
        Align2::RIGHT_CENTER,
        dlc,
        mono.clone(),
        normal,
    );
    painter.text(
        Pos2::new(x + 370.0, y),
        Align2::LEFT_CENTER,
        data,
        mono,
        normal,
    );
    painter.text(
        Pos2::new(x + 660.0, y),
        Align2::LEFT_CENTER,
        origin.map_or("Source", FrameOrigin::label),
        FontId::new(10.0, FontFamily::Monospace),
        match origin {
            Some(FrameOrigin::Manual) => ACCENT,
            Some(FrameOrigin::Ai) => PURPLE,
            Some(FrameOrigin::File) => MUTED,
            None => MUTED,
        },
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
    let message = &document.trace.messages[source_index];
    let analysis = document.analyses[source_index].as_ref();
    let origin = document.origins[source_index];

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
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Message inspector")
                .size(17.0)
                .color(TEXT)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let can_next = app
                .selected_position()
                .is_some_and(|position| position + 1 < app.visible_indices.len());
            if ui
                .push_id("next_message_control", |ui| {
                    ui.add_enabled(can_next, egui::Button::new("Next"))
                })
                .inner
                .clicked()
            {
                app.select_relative(1);
            }
            let can_previous = app.selected_position().is_some_and(|position| position > 0);
            if ui
                .push_id("previous_message_control", |ui| {
                    ui.add_enabled(can_previous, egui::Button::new("Previous"))
                })
                .inner
                .clicked()
            {
                app.select_relative(-1);
            }
            if let Some(position) = app.selected_position() {
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
                ui.label(RichText::new("RAW").size(9.0).color(MUTED).strong());
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
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new(("decoded_fields", source_index))
                .num_columns(2)
                .min_col_width(112.0)
                .spacing([14.0, 8.0])
                .striped(true)
                .show(ui, |ui| {
                    for field in &analysis.fields {
                        let service_code = service_code_from_field(&field.name, &field.value);
                        let name_response = ui.add(
                            egui::Label::new(RichText::new(&field.name).size(10.0).color(MUTED))
                                .wrap(),
                        );
                        let display_value = if service_code.is_some() {
                            humanize_service_text(&field.value)
                        } else {
                            field.value.clone()
                        };
                        let value_response = ui.add(
                            egui::Label::new(
                                RichText::new(display_value)
                                    .size(11.0)
                                    .color(TEXT)
                                    .monospace(),
                            )
                            .wrap(),
                        );
                        if let Some(code) = service_code {
                            add_service_tooltip(name_response, code, &field.value);
                            add_service_tooltip(value_response, code, &field.value);
                        }
                        ui.end_row();
                    }
                });
        });

    if !analysis.warnings.is_empty() {
        ui.add_space(9.0);
        for warning in &analysis.warnings {
            alert(ui, &format!("Warning: {warning}"), AMBER);
        }
    }
}

fn service_code_from_field(name: &str, value: &str) -> Option<u8> {
    if !matches!(name, "Service" | "Request service") {
        return None;
    }
    let code = value.split_whitespace().next()?.strip_prefix("0x")?;
    u8::from_str_radix(code, 16).ok()
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
                ui.label(RichText::new(label).size(9.0).color(MUTED));
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
                    .size(9.0)
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
            ui.label(RichText::new(label).size(9.5).color(color).strong());
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
            ui.add(egui::Label::new(RichText::new(text).size(10.5).color(color)).wrap());
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
    ui.label(RichText::new(label).size(9.5).color(MUTED).strong());
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
