// No console window behind the GUI in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> anyhow::Result<()> {
    opencrt::gui_main()
}
