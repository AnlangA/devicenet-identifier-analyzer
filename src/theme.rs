use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, FontId, Stroke, Vec2};

/// 嵌入的宋体中文字体（思源宋体 Noto Serif CJK SC，Regular 字重）。
/// 使用 `include_bytes!` 在编译期将字体嵌入二进制，确保应用独立分发。
static NOTO_SERIF_SC: &[u8] = include_bytes!("../assets/fonts/NotoSerifSC-Regular.otf");

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
    install_fonts(ctx);
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

/// 安装嵌入的中文字体（思源宋体）作为 Proportional 的最高优先级字体，
/// 同时挂到 Monospace 末尾作为回退，使中文字符在等宽场景也能显示。
///
/// 这是 egui 0.35 推荐的字体嵌入方式：
/// 1. 从 `FontDefinitions::default()` 起步（保留内置拉丁字体）。
/// 2. `font_data` 中插入自定义字体的二进制（`.ttf` / `.otf` 均可）。
/// 3. 在 `families` 中将自定义字体名加入相应 `FontFamily`，靠前的字体优先匹配。
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "noto-serif-sc".to_owned(),
        std::sync::Arc::new(FontData::from_static(NOTO_SERIF_SC)),
    );

    // 最高优先级：中文字符优先由宋体渲染。
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, "noto-serif-sc".to_owned());

    // Monospace 末尾追加作为回退，避免破坏等宽英文字体的排版。
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .push("noto-serif-sc".to_owned());

    ctx.set_fonts(fonts);
}
