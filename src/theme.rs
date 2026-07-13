use eframe::egui::{self, Color32, FontFamily, FontId, Stroke, Vec2};

pub(crate) const BG: Color32 = Color32::from_rgb(11, 17, 28);
pub(crate) const PANEL: Color32 = Color32::from_rgb(20, 28, 43);
pub(crate) const PANEL_SOFT: Color32 = Color32::from_rgb(27, 37, 55);
pub(crate) const SURFACE: Color32 = Color32::from_rgb(9, 15, 25);
pub(crate) const BORDER: Color32 = Color32::from_rgb(47, 61, 84);
pub(crate) const TEXT: Color32 = Color32::from_rgb(235, 240, 248);
pub(crate) const MUTED: Color32 = Color32::from_rgb(145, 158, 181);
pub(crate) const ACCENT: Color32 = Color32::from_rgb(73, 203, 174);
pub(crate) const BLUE: Color32 = Color32::from_rgb(91, 155, 255);
pub(crate) const AMBER: Color32 = Color32::from_rgb(245, 183, 74);
pub(crate) const RED: Color32 = Color32::from_rgb(243, 103, 116);
pub(crate) const PURPLE: Color32 = Color32::from_rgb(187, 135, 255);

pub(crate) fn configure(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = SURFACE;
    style.visuals.faint_bg_color = PANEL_SOFT.gamma_multiply(0.55);
    style.visuals.widgets.inactive.bg_fill = PANEL_SOFT;
    style.visuals.widgets.inactive.weak_bg_fill = PANEL_SOFT;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, MUTED);
    style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(5);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(39, 52, 75);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(39, 52, 75);
    style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(5);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(45, 61, 87);
    style.visuals.widgets.active.weak_bg_fill = Color32::from_rgb(45, 61, 87);
    style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(5);
    style.visuals.widgets.open.corner_radius = egui::CornerRadius::same(5);
    style.visuals.selection.bg_fill = ACCENT.gamma_multiply(0.28);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.window_stroke = Stroke::new(1.0, BORDER);
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 6.0);
    style.spacing.tooltip_width = 380.0;
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(14.0, FontFamily::Proportional),
    );
    ctx.set_style_of(egui::Theme::Dark, style);
}
