//! On Plasma Wayland KWin draws the title bar: ask it for the Breeze colour
//! scheme that matches OpenCRT's theme (org_kde_kwin_server_decoration_palette).

use std::cell::RefCell;
use std::path::PathBuf;

use slint::winit_030::winit::raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle};
use slint::winit_030::winit::window::{Theme, Window};
use wayland_backend::client::{Backend, ObjectId};
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::{wl_registry::WlRegistry, wl_surface::WlSurface};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle};
use wayland_protocols_plasma::server_decoration_palette::client::org_kde_kwin_server_decoration_palette::OrgKdeKwinServerDecorationPalette as Palette;
use wayland_protocols_plasma::server_decoration_palette::client::org_kde_kwin_server_decoration_palette_manager::OrgKdeKwinServerDecorationPaletteManager as Manager;

struct State;

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(_: &mut Self, _: &WlRegistry, _: <WlRegistry as Proxy>::Event, _: &GlobalListContents, _: &Connection, _: &QueueHandle<Self>) {}
}
wayland_client::delegate_noop!(State: ignore Manager);
wayland_client::delegate_noop!(State: ignore Palette);

thread_local! {
    /// Kept while the window lives: KWin drops the colours with the palette object.
    static PALETTE: RefCell<Option<(Connection, EventQueue<State>, Palette)>> = const { RefCell::new(None) };
}

/// Breeze Dark or Breeze Light for `theme`; None goes back to the desktop's scheme.
pub fn follow(window: &Window, theme: Option<Theme>) {
    let scheme = match theme {
        Some(Theme::Dark) => scheme_path("BreezeDark"),
        Some(Theme::Light) => scheme_path("BreezeLight"),
        None => String::new(),
    };
    PALETTE.with_borrow_mut(|slot| {
        if slot.is_none() && !scheme.is_empty() {
            *slot = palette_for(window);
        }
        if let Some((connection, _, palette)) = slot {
            palette.set_palette(scheme);
            let _ = connection.flush();
        }
    });
}

/// None off Wayland or when the compositor is not KWin.
fn palette_for(window: &Window) -> Option<(Connection, EventQueue<State>, Palette)> {
    let RawDisplayHandle::Wayland(display) = window.display_handle().ok()?.as_raw() else {
        return None;
    };
    let RawWindowHandle::Wayland(surface) = window.window_handle().ok()?.as_raw() else {
        return None;
    };
    // SAFETY: winit keeps the display and the surface alive as long as the window.
    let connection = Connection::from_backend(unsafe { Backend::from_foreign_display(display.display.as_ptr().cast()) });
    let (globals, queue) = registry_queue_init::<State>(&connection).ok()?;
    let manager: Manager = globals.bind(&queue.handle(), 1..=1, ()).ok()?;
    // SAFETY: a live wl_surface of that display, as above.
    let id = unsafe { ObjectId::from_ptr(WlSurface::interface(), surface.surface.as_ptr().cast()) }.ok()?;
    let surface = WlSurface::from_id(&connection, id).ok()?;
    let palette = manager.create(&surface, &queue.handle(), ());
    Some((connection, queue, palette))
}

/// The installed `<name>.colors` file, or "" (the desktop's scheme) when there is none.
fn scheme_path(name: &str) -> String {
    let home = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| std::env::home_dir().map(|h| h.join(".local/share")));
    let dirs = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
    home.into_iter()
        .chain(dirs.split(':').map(PathBuf::from))
        .map(|dir| dir.join("color-schemes").join(format!("{name}.colors")))
        .find(|path| path.is_file())
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_scheme_means_the_desktop_default() {
        assert_eq!(super::scheme_path("NoSuchScheme"), "");
    }
}
