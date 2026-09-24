fn main() {
    slint_build::compile("ui/appwindow.slint").expect("Failed to compile Slint UI");

    // Windows app branding: taskbar / Alt-Tab / exe icon.
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        if std::path::Path::new("assets/app.ico").exists() {
            res.set_icon("assets/app.ico");
        }
        let _ = res.compile();
    }
}
