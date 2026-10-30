//! Render the main window off-screen to a PNG-convertible PPM, for checking the
//! look without opening a window: `cargo run --example ui_snapshot -- out.ppm dark main`.
//! Scenes: main, groups, session-options, connection, terminal, forwards, global-options, credentials, about, login, script, agent, keygen, firewall, schemes, hex, button, active, files, files-narrow, overwrite, quick-open.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{Color, ModelRc, PhysicalSize, SharedString, VecModel};

slint::include_modules!();

struct Offscreen(Rc<MinimalSoftwareWindow>);

impl Platform for Offscreen {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [out, theme, scene] = [0, 1, 2].map(|i| args.get(i).cloned().unwrap_or_default());
    let (width, height) = if scene == "files" { (1300, 760) } else { (1100, 720) };

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Offscreen(window.clone()))).unwrap();
    window.set_size(PhysicalSize::new(width, height));
    let ui = MainWindow::new().unwrap();
    ui.set_theme_mode(if theme == "dark" { 2 } else { 1 });
    ui.set_version("0.1.0".into());
    ui.set_settings_dir("~/.config/opencrt".into());
    ui.set_terminal_bg(Color::from_rgb_u8(0x0a, 0x0d, 0x1f));

    let grouped = scene == "groups";
    let tab = |title: &str, state, group: i32, shown| TabData {
        title: title.into(),
        protocol: 0,
        state,
        color: Color::from_argb_u8(0, 0, 0, 0),
        group: if grouped { group } else { 0 },
        shown: if grouped { shown } else { group == 0 && shown },
        activity: title.starts_with("web1"),
        scripting: title == "Local Shell",
        locked: scene == "active" && title == "Local Shell",
        picked: scene == "active" && title != "Local Shell",
        hidden: false,
        index: 0,
    };
    ui.set_tabs(model(vec![tab("ops@core-sw1", 1, 0, true), tab("web1.example.com", 0, 0, false), tab("Local Shell", 2, 1, true)]));
    ui.set_group_count(if grouped { 2 } else { 1 });
    ui.set_active_tab(0);
    let row = |label: &str, depth, folder, protocol| SessionRow {
        label: label.into(),
        // Shows a session's notes beside its name.
        note: if label == "core-sw1" { "Rack 3, Oslo" } else { "" }.into(),
        depth,
        folder,
        expanded: folder,
        ssh: protocol == 0,
        picked: false,
        protocol,
    };
    ui.set_session_rows(model(vec![
        row("SecureCRT", 0, true, 0),
        row("Network", 1, true, 0),
        row("core-sw1", 2, false, 0),
        row("edge-rtr1", 2, false, 1),
        row("console", 2, false, 3),
        row("Windows desktop", 1, false, 5),
        row("Local Shell", 1, false, 4),
    ]));
    ui.set_session_selected(2);
    ui.set_sessions_open(true);
    ui.set_dock_width(240.0);
    ui.set_status_text("Connected".into());

    match scene.as_str() {
        "session-options" | "connection" | "forwards" | "terminal" | "log-options" | "remote-desktop" => {
            ui.set_so_name("core-sw1".into());
            ui.set_so_notes("Rack 3, Oslo\nAsk ops before rebooting".into());
            ui.set_so_host("core-sw1.example.net".into());
            ui.set_so_port("22".into());
            ui.set_so_user("ops".into());
            ui.set_so_category(match scene.as_str() {
                "forwards" => 5,
                "terminal" => 2,
                "log-options" => 4,
                "connection" => 0,
                "remote-desktop" => 8,
                _ => 1,
            });
            if scene == "remote-desktop" {
                ui.set_so_protocol(5);
                ui.set_so_rdp_width("1920".into());
                ui.set_so_rdp_height("1080".into());
                ui.set_so_rdp_speed(1);
                ui.set_so_rdp_sound(true);
                ui.set_so_rdp_share("~/Shared".into());
                ui.set_so_rdp_h264(true);
            }
            ui.set_encoding_names(model(vec![SharedString::from("UTF-8"), "Shift_JIS (Japanese)".into()]));
            ui.set_so_columns("132".into());
            ui.set_credential_choices(model(vec![SharedString::from("None"), "Network admin".into()]));
            ui.set_so_credential(1);
            let fwd = |name: &str, kind: &str, listen: &str, dest: &str| ForwardRow {
                name: name.into(),
                kind: kind.into(),
                listen: listen.into(),
                dest: dest.into(),
                app: "".into(),
                enabled: true,
            };
            ui.set_so_forward_rows(model(vec![fwd("Grafana", "Local", "3000", "SSH server:3000"), fwd("", "SOCKS", "1080", "any (SOCKS)")]));
            ui.set_dialog(5);
        }
        "global-options" => ui.set_dialog(6),
        "print-options" => {
            ui.set_go_category(7);
            ui.set_go_print_font("10".into());
            ui.set_dialog(6);
        }
        "paste-options" => {
            ui.set_go_category(2);
            ui.set_go_confirm_paste(true);
            ui.set_go_line_delay("200".into());
            ui.set_go_wait_prompt("# ".into());
            ui.set_dialog(6);
        }
        "credentials" => {
            ui.set_credential_rows(model(vec![CredentialRow { name: "Network admin".into(), user: "netadmin".into() }]));
            ui.set_dialog(12);
        }
        "about" => ui.set_dialog(4),
        "update" => {
            ui.set_update_version("0.2.1".into());
            ui.set_update_status("OpenCRT 0.2.1 is available. Update Now installs it and restarts OpenCRT.".into());
            ui.set_update_installable(true);
            ui.set_dialog(4);
        }
        "script" => {
            ui.set_script_text("Password for admin on core-sw1".into());
            ui.set_script_input(true);
            ui.set_script_secret(true);
            ui.set_dialog(13);
        }
        "agent" => {
            ui.set_agent_rows(model(vec![SharedString::from("ssh-ed25519    SHA256:3fJ8x1qkV0pR1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6    /home/me/.ssh/id_ed25519")]));
            ui.set_dialog(14);
        }
        "keygen" => {
            ui.set_kg_types(model(vec![SharedString::from("Ed25519 (recommended)"), "RSA 4096".into()]));
            ui.set_kg_file("/home/me/.ssh/id_ed25519".into());
            ui.set_kg_comment("me@desk".into());
            ui.set_dialog(10);
        }
        "firewall" => {
            ui.set_firewall_rows(model(vec![CredentialRow { name: "Office proxy".into(), user: "Http proxy.lan:3128 as me".into() }]));
            ui.set_fw_name("Office proxy".into());
            ui.set_fw_kind(2);
            ui.set_fw_host("proxy.lan".into());
            ui.set_fw_port("3128".into());
            ui.set_fw_user("me".into());
            ui.set_fw_editing(true);
            ui.set_dialog(15);
        }
        "schemes" => {
            ui.set_scheme_names(model(vec![SharedString::from("OpenCRT Dark"), "Solarized dark".into(), "Mine".into()]));
            ui.set_sc_selected(2);
            ui.set_sc_name("Mine".into());
            ui.set_sc_fg("#d9dcec".into());
            ui.set_sc_bg("#0a0d1f".into());
            ui.set_sc_cursor("#f8b332".into());
            let ansi = ["#1b2044", "#f05d5e", "#4ccb7b", "#f8b332", "#5aa9ff", "#c67bf0", "#4fd1d9", "#c5c9e0"];
            ui.set_sc_ansi(model(ansi.iter().chain(ansi.iter()).map(|c| SharedString::from(*c)).collect()));
            let swatch = |h: &str| {
                let v = u32::from_str_radix(&h[1..], 16).unwrap();
                Color::from_rgb_u8((v >> 16) as u8, (v >> 8) as u8, v as u8)
            };
            let mut swatches = vec![swatch("#d9dcec"), swatch("#0a0d1f"), swatch("#f8b332"), Color::from_argb_u8(0, 0, 0, 0)];
            swatches.extend(ansi.iter().chain(ansi.iter()).map(|h| swatch(h)));
            ui.set_sc_swatches(model(swatches));
            ui.set_sc_editable(true);
            ui.set_dialog(16);
        }
        "hex" => {
            ui.set_hex_view(true);
            ui.set_hex_lines(model(vec![
                SharedString::from("00000000  48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0d 0a 1b  Hello, world!..."),
                "00000010  5b 30 6d                                         [0m".into(),
            ]));
        }
        "button" => {
            ui.set_bb_title("Button Bar Button".into());
            ui.set_bb_label("Wireshark".into());
            ui.set_bb_kind(3);
            ui.set_bb_text("wireshark -k".into());
            ui.set_bb_color(5);
            ui.set_command_window(true);
            ui.set_show_button_bar(true);
            ui.set_bar_buttons(model(vec![BarRow { label: "show ver".into(), color: Color::from_rgb_u8(70, 130, 220), index: 0 }]));
            ui.set_dialog(9);
        }
        "editor" => {
            ui.set_se_title("Script Editor - backup.rhai".into());
            ui.set_se_text("if wait_for(\"login:\", 10) { send(\"admin\\r\"); }\nupload(\"zmodem\", \"router.cfg\");\nsend(\"rz\\r\");".into());
            ui.set_se_message("No syntax errors.".into());
            ui.set_dialog(19);
        }
        "drop" => {
            ui.set_drop_message("Send firmware.bin with:".into());
            ui.set_drop_sftp(true);
            ui.set_dialog(18);
        }
        "quick-open" => {
            let row = |label: &str, detail: &str, protocol, typed| QuickRow { label: label.into(), detail: detail.into(), protocol, typed };
            ui.set_quick_query("core".into());
            ui.set_quick_rows(model(vec![
                row("core-sw1", "Network  ·  ops@core-sw1.example.net", 0, false),
                row("core-rtr2", "Network  ·  10.20.0.2", 1, false),
                row("Connect to core", "SSH2 (Shift+Enter: SFTP GUI tab)", 0, true),
            ]));
            ui.set_quick_selected(0);
            ui.set_dialog(20);
        }
        "overwrite" => {
            ui.set_confirm_message("/mnt/SSD-RAIDZ/seeding/debian-13.iso already exists. Overwrite it?".into());
            ui.set_confirm_option("Do the same for the rest of the queue".into());
            ui.set_dialog(7);
        }
        "paste" => {
            ui.set_paste_message("These 3 lines will be pasted. Change them first if needed.".into());
            ui.set_paste_value("conf t\ninterface Gi0/1\nshutdown".into());
            ui.set_dialog(17);
        }
        "scratch" => {
            ui.set_sessions_open(false);
            ui.set_scratch_open(true);
            ui.set_scratch_text("show version\nshow interfaces status\nshow ip route".into());
        }
        "files" | "files-narrow" => {
            ui.set_sessions_open(scene == "files-narrow");
            let file = |name: &str, size: &str, kind: &str, dir, selected| FileRow {
                name: name.into(),
                size: size.into(),
                kind: kind.into(),
                modified: "2026-10-29 13:55".into(),
                permissions: if dir { "drwxr-xr-x" } else { "-rw-r--r--" }.into(),
                owner: "apps apps".into(),
                dir,
                selected,
            };
            let up = FileRow { name: "..".into(), dir: true, ..Default::default() };
            let job = |local: &str, upload, remote: &str, status: &str, progress| QueueRow {
                local: local.into(),
                upload,
                remote: remote.into(),
                size: "31.5 GB".into(),
                status: status.into(),
                progress,
                selected: false,
            };
            ui.set_files_views(model(vec![FilesView {
                tab: 0,
                x: 0.0,
                y: 0.0,
                width: if scene == "files" { 1270.0 } else { 820.0 },
                height: 590.0,
                local_dir: "/home/ops/Downloads".into(),
                remote_dir: "/mnt/SSD-RAIDZ/seeding".into(),
                local_rows: model(vec![up.clone(), file("COD4", "", "Folder", true, false), file("notes.txt", "2.1 KB", "TXT file", false, false)]),
                remote_rows: model(vec![
                    up,
                    file("backups", "", "Folder", true, false),
                    file("ISOs", "", "Folder", true, false),
                    file("debian-13.iso", "3.7 GB", "ISO file", false, true),
                    file("Finding.Emily.2026.mkv", "31.5 GB", "MKV file", false, false),
                ]),
                local_status: "1 file and 1 folder. Total size: 2.1 KB".into(),
                remote_status: "Selected 1 file. Total size: 3.7 GB".into(),
                local_sort: 0,
                remote_sort: 3,
                local_filter: "".into(),
                remote_filter: "iso".into(),
                local_hidden: false,
                remote_hidden: true,
                linked: true,
                follow: true,
                queue: model(vec![
                    job("/home/ops/Downloads/debian-13.iso", false, "/mnt/SSD-RAIDZ/seeding/debian-13.iso", "1.2 GB of 3.7 GB (32%), 98.1 MB/s", 0.32),
                    job("/home/ops/Downloads/notes.txt", true, "/mnt/SSD-RAIDZ/seeding/notes.txt", "", -1.0),
                ]),
                list: 0,
                waiting: 2,
                failed: 1,
                finished: 14,
            }]));
        }
        "active" => {
            ui.set_sessions_open(false);
            ui.set_active_open(true);
            ui.set_active_tabs(ui.get_tabs());
        }
        "login" => {
            ui.set_auth_title("Log in to rdp: ops@desk1".into());
            ui.set_auth_fields(model(vec![PromptField { label: "Password for ops@desk1:".into(), echo: false }]));
            ui.set_auth_answers(model(vec![SharedString::new()]));
            ui.set_auth_can_save(true);
            ui.set_auth_credentials(model(vec![SharedString::from("Type the password"), "Network admin".into()]));
            ui.set_dialog(2);
        }
        _ => {}
    }

    ui.show().unwrap();
    slint::platform::update_timers_and_animations();
    let mut pixels = vec![PremultipliedRgbaColor::default(); (width * height) as usize];
    window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, width as usize);
    });
    let mut ppm = format!("P6 {width} {height} 255\n").into_bytes();
    ppm.extend(pixels.iter().flat_map(|p| [p.red, p.green, p.blue]));
    std::fs::write(&out, ppm).unwrap();
}
