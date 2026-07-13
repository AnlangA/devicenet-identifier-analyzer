mod ai_import;
mod app;
mod frame_input;
mod theme;
mod ui;

use app::AnalyzerApp;
use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("DeviceNet Trace Analyzer")
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([980.0, 640.0]),
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "devicenet-trace-analyzer",
        options,
        Box::new(|cc| Ok(Box::new(AnalyzerApp::new(cc)))),
    )
}
