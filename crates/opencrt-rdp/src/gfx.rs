//! The Graphics Pipeline ([MS-RDPEGFX]), which Windows' own client uses: the
//! desktop arrives as H.264 (AVC420) and a few lossless codecs, drawn into
//! surfaces the server creates, fills, copies and caches. [`Handler`] turns
//! the channel's callbacks into [`Event`]s; the session loop applies them to
//! a [`Canvas`], whose `output` (RGBA) is the desktop OpenCRT shows.
//!
//! [MS-RDPEGFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use ironrdp::graphics::clearcodec::ClearCodecDecoder;
use ironrdp::graphics::progressive::ProgressiveDecoder;
use ironrdp::graphics::rdp6::BitmapStreamDecoder;
use ironrdp::pdu::geometry::ExclusiveRectangle;
use ironrdp_egfx::client::{BitmapUpdate, GraphicsPipelineHandler, Surface};
use ironrdp_egfx::pdu::{
    CacheToSurfacePdu, CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags, CapabilitiesV10Flags,
    CapabilitySet, Codec1Type, EvictCacheEntryPdu, GfxPdu, MapSurfaceToScaledOutputPdu, SolidFillPdu,
    SurfaceToCachePdu, SurfaceToSurfacePdu, WireToSurface2Pdu,
};
use tokio::sync::mpsc::UnboundedSender;

/// A rectangle as (left, top, width, height).
type Area = (u32, u32, u32, u32);

fn area(r: &ExclusiveRectangle) -> Area {
    let (left, top) = (u32::from(r.left), u32::from(r.top));
    (left, top, u32::from(r.right).saturating_sub(left), u32::from(r.bottom).saturating_sub(top))
}

#[derive(Debug)]
pub enum Event {
    /// The desktop is (now) this size; everything is created afresh.
    Reset(u32, u32),
    Created { id: u16, width: u32, height: u32 },
    Deleted(u16),
    /// The surface is shown with its top left at (x, y) of the desktop.
    Mapped { id: u16, x: u32, y: u32 },
    /// Pixels (RGBA rows of the area's width) for a surface.
    Pixels { id: u16, at: Area, rgba: Vec<u8> },
    /// The same, but fully transparent pixels leave the surface as it is:
    /// ClearCodec need not draw all of its area.
    Partial { id: u16, at: Area, rgba: Vec<u8> },
    Fill { id: u16, rgba: [u8; 4], areas: Vec<Area> },
    Copy { from: u16, at: Area, to: u16, points: Vec<(u32, u32)> },
    ToCache { id: u16, at: Area, slot: u16 },
    FromCache { slot: u16, id: u16, points: Vec<(u32, u32)> },
    Evict(u16),
    /// For the connection log.
    Note(String),
}

pub struct Handler {
    events: UnboundedSender<Event>,
    clear: ClearCodecDecoder,
    planar: BitmapStreamDecoder,
    /// Codecs already reported as not decoded, or as seen (each once).
    unsupported: Vec<String>,
    seen: Vec<String>,
    /// Pictures that failed, by codec (the log keeps the first few of each).
    failures: HashMap<&'static str, u32>,
    progressive: ProgressiveDecoder,
    /// Surface sizes, which Progressive tiles need.
    sizes: HashMap<u16, (u16, u16)>,
    /// Pictures per codec since `counted`, for the log every STATS_EVERY.
    counts: BTreeMap<String, u32>,
    counted: Instant,
    dump: Option<(std::path::PathBuf, u32)>,
}

const STATS_EVERY: Duration = Duration::from_secs(10);

impl Handler {
    pub fn new(events: UnboundedSender<Event>) -> Self {
        Handler {
            events,
            clear: ClearCodecDecoder::new(),
            planar: BitmapStreamDecoder::default(),
            unsupported: Vec::new(),
            seen: Vec::new(),
            failures: HashMap::new(),
            progressive: ProgressiveDecoder::new(),
            sizes: HashMap::new(),
            counts: BTreeMap::new(),
            counted: Instant::now(),
            dump: std::env::var_os("OPENCRT_RDP_DUMP").map(|d| (d.into(), 0)),
        }
    }

    fn send(&self, event: Event) {
        let _ = self.events.send(event);
    }

    /// The first picture of each codec, and how many of each, for the connection log.
    fn saw(&mut self, name: String, at: Area) {
        *self.counts.entry(name.clone()).or_default() += 1;
        if self.counted.elapsed() >= STATS_EVERY {
            let counts: Vec<String> = self.counts.iter().map(|(codec, n)| format!("{codec} {n}")).collect();
            self.send(Event::Note(format!("graphics: pictures in the last {}s: {}", self.counted.elapsed().as_secs(), counts.join(", "))));
            self.counts.clear();
            self.counted = Instant::now();
        }
        if !self.seen.contains(&name) {
            self.send(Event::Note(format!("graphics: first {name} picture, {}x{} at {},{}", at.2, at.3, at.0, at.1)));
            self.seen.push(name);
        }
    }

    /// A picture that did not decode: logged for the first few of each codec.
    fn failed(&mut self, codec: &'static str, why: String) {
        let n = self.failures.entry(codec).or_default();
        *n += 1;
        if *n <= 5 {
            self.send(Event::Note(format!("graphics: {codec} picture not decoded: {why}")));
        }
    }

    fn unsupported(&mut self, what: String) {
        if !self.unsupported.contains(&what) {
            self.send(Event::Note(format!("graphics: {what} is not decoded")));
            self.unsupported.push(what);
        }
    }
}

impl GraphicsPipelineHandler for Handler {
    /// RDP 10 only, H.264 on: Windows then sends video as AVC420, the rest as
    /// ClearCodec, Planar and Progressive. Not as a thin client
    /// (AVC_THIN_CLIENT): Windows then sends the whole screen as AVC444v2,
    /// which IronRDP does not decode.
    fn capabilities(&self) -> Vec<CapabilitySet> {
        use CapabilitiesV104Flags as V104;
        use CapabilitiesV107Flags as V107;
        let v104 = V104::SMALL_CACHE;
        vec![
            CapabilitySet::V10_7 { flags: V107::SMALL_CACHE | V107::SCALEDMAP_DISABLE },
            CapabilitySet::V10_6 { flags: v104 },
            CapabilitySet::V10_5 { flags: v104 },
            CapabilitySet::V10_4 { flags: v104 },
            CapabilitySet::V10_3 { flags: CapabilitiesV103Flags::empty() },
            CapabilitySet::V10_2 { flags: CapabilitiesV10Flags::SMALL_CACHE },
            CapabilitySet::V10 { flags: CapabilitiesV10Flags::SMALL_CACHE },
        ]
    }

    fn on_capabilities_confirmed(&mut self, caps: &CapabilitySet) {
        self.send(Event::Note(format!("graphics pipeline on: {caps:?}")));
    }

    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        self.progressive.reset();
        self.sizes.clear();
        self.send(Event::Reset(width, height));
    }

    fn on_surface_created(&mut self, surface: &Surface) {
        self.sizes.insert(surface.id, (surface.width, surface.height));
        self.send(Event::Created { id: surface.id, width: surface.width.into(), height: surface.height.into() });
    }

    fn on_surface_deleted(&mut self, id: u16) {
        self.sizes.remove(&id);
        self.progressive.delete_context(id.into());
        self.send(Event::Deleted(id));
    }

    fn on_surface_mapped(&mut self, id: u16, x: u32, y: u32) {
        self.send(Event::Note(format!("graphics: surface {id} shown at {x},{y}")));
        self.send(Event::Mapped { id, x, y });
    }

    /// Asked not to (SCALEDMAP_DISABLE); if it comes anyway, shown unscaled.
    fn on_map_surface_to_scaled_output(&mut self, pdu: &MapSurfaceToScaledOutputPdu) {
        let (id, x, y) = (pdu.surface_id, pdu.output_origin_x, pdu.output_origin_y);
        let (w, h) = (pdu.target_width, pdu.target_height);
        self.send(Event::Note(format!("graphics: surface {id} shown at {x},{y}, scaled to {w}x{h}")));
        self.send(Event::Mapped { id, x, y });
    }

    fn on_bitmap_updated(&mut self, update: &BitmapUpdate) {
        let (left, top, ..) = area(&update.destination_rectangle);
        let at = (left, top, update.width.into(), update.height.into());
        self.saw(format!("{:?}", update.codec_id), at);
        if update.data.len() == at.2 as usize * at.3 as usize * 4 {
            self.send(Event::Pixels { id: update.surface_id, at, rgba: update.data.clone() });
        }
    }

    /// RemoteFX Progressive: 64x64 tiles of the surface.
    fn on_wire_to_surface2(&mut self, pdu: &WireToSurface2Pdu) {
        let id = pdu.surface_id;
        let Some(&(w, h)) = self.sizes.get(&id) else {
            return;
        };
        if let Some((dir, n)) = self.dump.as_mut() {
            *n += 1;
            let _ = std::fs::write(dir.join(format!("{n:06}-{id}-{w}x{h}.prog")), &pdu.bitmap_data);
        }
        // Tile state per surface, not per codec context: Windows uses a new
        // context id for each picture (FreeRDP keys it by surface too).
        match self.progressive.decode_bitmap(id.into(), w, h, &pdu.bitmap_data) {
            Ok(tiles) => {
                for tile in tiles {
                    let (tx, ty) = (u32::from(tile.x_idx) * 64, u32::from(tile.y_idx) * 64);
                    self.saw("Progressive".into(), (tx, ty, 64, 64));
                    // Only where the region's rectangles cover the tile.
                    for (x, y, w, h) in tile.rects {
                        let (x, y, w, h) = (usize::from(x), usize::from(y), usize::from(w), usize::from(h));
                        let rgba = (y..y + h).flat_map(|row| &tile.pixels[(row * 64 + x) * 4..(row * 64 + x + w) * 4]).copied().collect();
                        self.send(Event::Pixels { id, at: (tx + x as u32, ty + y as u32, w as u32, h as u32), rgba });
                    }
                }
            }
            Err(e) => self.failed("Progressive", format!("{} bytes: {e}", pdu.bitmap_data.len())),
        }
    }

    fn on_solid_fill(&mut self, pdu: &SolidFillPdu) {
        let c = &pdu.fill_pixel;
        self.send(Event::Fill { id: pdu.surface_id, rgba: [c.r, c.g, c.b, 255], areas: pdu.rectangles.iter().map(area).collect() });
    }

    fn on_surface_to_surface(&mut self, pdu: &SurfaceToSurfacePdu) {
        self.send(Event::Copy {
            from: pdu.source_surface_id,
            at: area(&pdu.source_rectangle),
            to: pdu.destination_surface_id,
            points: pdu.destination_points.iter().map(|p| (p.x.into(), p.y.into())).collect(),
        });
    }

    fn on_surface_to_cache(&mut self, pdu: &SurfaceToCachePdu) {
        self.send(Event::ToCache { id: pdu.surface_id, at: area(&pdu.source_rectangle), slot: pdu.cache_slot });
    }

    fn on_cache_to_surface(&mut self, pdu: &CacheToSurfacePdu) {
        self.send(Event::FromCache {
            slot: pdu.cache_slot,
            id: pdu.surface_id,
            points: pdu.destination_points.iter().map(|p| (p.x.into(), p.y.into())).collect(),
        });
    }

    fn on_evict_cache_entry(&mut self, pdu: &EvictCacheEntryPdu) {
        self.send(Event::Evict(pdu.cache_slot));
    }

    /// The lossless codecs IronRDP's pipeline leaves to us: ClearCodec (text,
    /// window edges) and Planar.
    fn on_unhandled_pdu(&mut self, pdu: &GfxPdu) {
        let GfxPdu::WireToSurface1(pdu) = pdu else {
            return;
        };
        let at = area(&pdu.destination_rectangle);
        let (w, h) = (at.2 as u16, at.3 as u16);
        self.saw(format!("{:?}", pdu.codec_id), at);
        let rgba = match pdu.codec_id {
            Codec1Type::ClearCodec => match self.clear.decode(&pdu.bitmap_data, w, h) {
                Ok(mut rgba) => {
                    rgba.as_chunks_mut::<4>().0.iter_mut().for_each(|p| p.swap(0, 2));
                    Some(rgba)
                }
                Err(e) => {
                    let head: Vec<String> = pdu.bitmap_data.iter().take(8).map(|b| format!("{b:02x}")).collect();
                    let why = format!("{w}x{h} at {},{} ({} bytes, starting {}): {e}", at.0, at.1, pdu.bitmap_data.len(), head.join(" "));
                    self.failed("ClearCodec", why);
                    return;
                }
            },
            Codec1Type::Planar => {
                let mut rgb = Vec::new();
                self.planar
                    .decode_bitmap_stream_to_rgb24(&pdu.bitmap_data, &mut rgb, w.into(), h.into())
                    .ok()
                    .map(|()| rgb.as_chunks::<3>().0.iter().flat_map(|p| [p[0], p[1], p[2], 255]).collect())
            }
            // Left here by the client when OpenH264 gave no picture.
            Codec1Type::Avc420 => {
                self.failed("H.264", format!("{} bytes", pdu.bitmap_data.len()));
                return;
            }
            other => {
                self.unsupported(format!("{other:?}"));
                return;
            }
        };
        match rgba.filter(|px: &Vec<u8>| px.len() == usize::from(w) * usize::from(h) * 4) {
            Some(rgba) if pdu.codec_id == Codec1Type::ClearCodec => self.send(Event::Partial { id: pdu.surface_id, at, rgba }),
            Some(rgba) => self.send(Event::Pixels { id: pdu.surface_id, at, rgba }),
            None => self.send(Event::Note(format!("graphics: a {:?} picture could not be decoded", pdu.codec_id))),
        }
    }
}

/// RGBA pixels, `width` x `height`.
#[derive(Clone, Default)]
struct Pixels {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Pixels {
    fn new(width: u32, height: u32) -> Self {
        Pixels { width, height, rgba: vec![0; width as usize * height as usize * 4] }
    }

    /// The part of `self` at `at` (clipped), as its own picture.
    fn cut(&self, at: Area) -> Pixels {
        let mut part = Pixels::new(at.2, at.3);
        part.paste(self, (at.0, at.1), (0, 0), (at.2, at.3));
        part
    }

    /// Copy the `size` area of `from` at `src` to `dst` here; whatever falls
    /// outside either picture is left out.
    fn paste(&mut self, from: &Pixels, src: (u32, u32), dst: (u32, u32), size: (u32, u32)) {
        let w = size.0.min(from.width.saturating_sub(src.0)).min(self.width.saturating_sub(dst.0)) as usize;
        let h = size.1.min(from.height.saturating_sub(src.1)).min(self.height.saturating_sub(dst.1)) as usize;
        for row in 0..h {
            let s = ((src.1 as usize + row) * from.width as usize + src.0 as usize) * 4;
            let d = ((dst.1 as usize + row) * self.width as usize + dst.0 as usize) * 4;
            self.rgba[d..d + w * 4].copy_from_slice(&from.rgba[s..s + w * 4]);
        }
    }

    /// `paste` of a whole picture at `dst`, except its fully transparent pixels.
    fn over(&mut self, from: &Pixels, dst: (u32, u32)) {
        let w = from.width.min(self.width.saturating_sub(dst.0)) as usize;
        let h = from.height.min(self.height.saturating_sub(dst.1)) as usize;
        for row in 0..h {
            let s = row * from.width as usize * 4;
            let d = ((dst.1 as usize + row) * self.width as usize + dst.0 as usize) * 4;
            let to = self.rgba[d..d + w * 4].as_chunks_mut::<4>().0;
            for (to, px) in to.iter_mut().zip(from.rgba[s..s + w * 4].as_chunks::<4>().0) {
                if px[3] != 0 {
                    *to = *px;
                }
            }
        }
    }

    fn fill(&mut self, at: Area, rgba: [u8; 4]) {
        let w = at.2.min(self.width.saturating_sub(at.0)) as usize;
        let h = at.3.min(self.height.saturating_sub(at.1)) as usize;
        for row in 0..h {
            let d = ((at.1 as usize + row) * self.width as usize + at.0 as usize) * 4;
            self.rgba[d..d + w * 4].as_chunks_mut::<4>().0.fill(rgba);
        }
    }
}

struct Layer {
    pixels: Pixels,
    /// Where it shows on the desktop, once mapped.
    shown_at: Option<(u32, u32)>,
}

/// The server's surfaces and cache, and the desktop they make.
pub struct Canvas {
    output: Pixels,
    layers: HashMap<u16, Layer>,
    cache: HashMap<u16, Pixels>,
}

impl Canvas {
    pub fn new(width: u32, height: u32) -> Self {
        let mut output = Pixels::new(width, height);
        output.rgba.as_chunks_mut::<4>().0.fill([0, 0, 0, 255]);
        Canvas { output, layers: HashMap::new(), cache: HashMap::new() }
    }

    /// A new desktop after a graphics reset: the surfaces are gone, the
    /// cache stays (the server keeps drawing from it).
    pub fn reset(self, width: u32, height: u32) -> Self {
        Canvas { cache: self.cache, ..Canvas::new(width, height) }
    }

    pub fn width(&self) -> u32 {
        self.output.width
    }

    pub fn height(&self) -> u32 {
        self.output.height
    }

    /// The desktop as RGBA rows.
    pub fn rgba(&self) -> &[u8] {
        &self.output.rgba
    }

    /// Show the `at` part of surface `id` on the desktop, if it is mapped.
    fn show(&mut self, id: u16, at: Area) {
        if let Some(layer) = self.layers.get(&id)
            && let Some((x, y)) = layer.shown_at
        {
            self.output.paste(&layer.pixels, (at.0, at.1), (x + at.0, y + at.1), (at.2, at.3));
        }
    }

    /// Apply one event; true when the desktop may have changed. (Reset and
    /// Note are the session's to handle.)
    pub fn apply(&mut self, event: Event) -> bool {
        match event {
            Event::Created { id, width, height } => {
                self.layers.insert(id, Layer { pixels: Pixels::new(width, height), shown_at: None });
                false
            }
            Event::Deleted(id) => self.layers.remove(&id).is_some_and(|l| l.shown_at.is_some()),
            Event::Mapped { id, x, y } => match self.layers.get_mut(&id) {
                Some(layer) => {
                    layer.shown_at = Some((x, y));
                    let whole = (0, 0, layer.pixels.width, layer.pixels.height);
                    self.show(id, whole);
                    true
                }
                None => false,
            },
            Event::Pixels { id, at, rgba } => match self.layers.get_mut(&id) {
                Some(layer) => {
                    let patch = Pixels { width: at.2, height: at.3, rgba };
                    layer.pixels.paste(&patch, (0, 0), (at.0, at.1), (at.2, at.3));
                    self.show(id, at);
                    true
                }
                None => false,
            },
            Event::Partial { id, at, rgba } => match self.layers.get_mut(&id) {
                Some(layer) => {
                    layer.pixels.over(&Pixels { width: at.2, height: at.3, rgba }, (at.0, at.1));
                    self.show(id, at);
                    true
                }
                None => false,
            },
            Event::Fill { id, rgba, areas } => match self.layers.get_mut(&id) {
                Some(layer) => {
                    for &a in &areas {
                        layer.pixels.fill(a, rgba);
                    }
                    for a in areas {
                        self.show(id, a);
                    }
                    true
                }
                None => false,
            },
            Event::Copy { from, at, to, points } => {
                // Cut first: source and destination may be the same surface.
                let Some(part) = self.layers.get(&from).map(|l| l.pixels.cut(at)) else {
                    return false;
                };
                let Some(layer) = self.layers.get_mut(&to) else {
                    return false;
                };
                for &(x, y) in &points {
                    layer.pixels.paste(&part, (0, 0), (x, y), (part.width, part.height));
                }
                for (x, y) in points {
                    self.show(to, (x, y, part.width, part.height));
                }
                true
            }
            Event::ToCache { id, at, slot } => {
                if let Some(layer) = self.layers.get(&id) {
                    self.cache.insert(slot, layer.pixels.cut(at));
                }
                false
            }
            Event::FromCache { slot, id, points } => {
                let (Some(part), Some(layer)) = (self.cache.get(&slot), self.layers.get_mut(&id)) else {
                    return false;
                };
                let size = (part.width, part.height);
                for &(x, y) in &points {
                    layer.pixels.paste(part, (0, 0), (x, y), size);
                }
                for (x, y) in points {
                    self.show(id, (x, y, size.0, size.1));
                }
                true
            }
            Event::Evict(slot) => {
                self.cache.remove(&slot);
                false
            }
            Event::Reset(..) | Event::Note(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: [u8; 4] = [255, 0, 0, 255];
    const BLUE: [u8; 4] = [0, 0, 255, 255];

    fn px(canvas: &Canvas, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * canvas.width() + x) * 4) as usize;
        canvas.rgba()[i..i + 4].try_into().unwrap()
    }

    #[test]
    fn mapped_surfaces_make_the_desktop() {
        let mut canvas = Canvas::new(8, 4);
        assert_eq!(px(&canvas, 0, 0), [0, 0, 0, 255], "black until drawn");
        canvas.apply(Event::Created { id: 1, width: 4, height: 4 });
        // Drawn before it is mapped: shown once it is.
        canvas.apply(Event::Fill { id: 1, rgba: RED, areas: vec![(0, 0, 2, 2)] });
        assert_eq!(px(&canvas, 5, 1), [0, 0, 0, 255]);
        assert!(canvas.apply(Event::Mapped { id: 1, x: 4, y: 0 }));
        assert_eq!(px(&canvas, 5, 1), RED);
        assert_eq!(px(&canvas, 6, 1), [0, 0, 0, 0], "the surface's own undrawn pixels");
        // Pixels land at their place in the surface, so at +4 on the desktop.
        canvas.apply(Event::Pixels { id: 1, at: (2, 3, 2, 1), rgba: [BLUE, BLUE].concat() });
        assert_eq!((px(&canvas, 6, 3), px(&canvas, 7, 3)), (BLUE, BLUE));
        // A surface's part reaching past the desktop is clipped, not wrapped.
        canvas.apply(Event::Created { id: 2, width: 4, height: 4 });
        canvas.apply(Event::Fill { id: 2, rgba: BLUE, areas: vec![(0, 0, 4, 4)] });
        canvas.apply(Event::Mapped { id: 2, x: 6, y: 2 });
        assert_eq!(px(&canvas, 7, 3), BLUE);
        assert_eq!(px(&canvas, 0, 0), [0, 0, 0, 255]);
    }

    /// A real H.264 picture through the whole pipeline: IronRDP's EGFX server
    /// encodes, our handler and canvas turn what the client decodes into the desktop.
    #[test]
    fn h264_through_the_pipeline() {
        use ironrdp::dvc::{DvcMessage, DvcProcessor};
        use ironrdp_egfx::client::GraphicsPipelineClient;
        use ironrdp_egfx::pdu::{Avc420Region, CapabilitiesAdvertisePdu, annex_b_to_avc};
        use ironrdp_egfx::server::{GraphicsPipelineHandler as ServerHandler, GraphicsPipelineServer};
        use openh264::formats::{RgbSliceU8, YUVBuffer};

        struct Quiet;
        impl ServerHandler for Quiet {
            fn capabilities_advertise(&mut self, _: &CapabilitiesAdvertisePdu) {}
            fn on_ready(&mut self, _: &CapabilitySet) {}
        }
        let bytes = |messages: Vec<DvcMessage>| -> Vec<Vec<u8>> {
            messages.iter().map(|m| ironrdp::core::encode_vec(m.as_ref()).unwrap()).collect()
        };
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
        let decoder = ironrdp_egfx::decode::OpenH264Decoder::new().unwrap();
        let mut client = GraphicsPipelineClient::new(Box::new(Handler::new(events)), Some(Box::new(decoder)));
        let mut server = GraphicsPipelineServer::new(Box::new(Quiet));
        // Messages each way until both are done.
        let exchange = |client: &mut GraphicsPipelineClient, server: &mut GraphicsPipelineServer, mut to_server: Vec<Vec<u8>>| loop {
            let mut to_client = Vec::new();
            for message in to_server.drain(..) {
                to_client.extend(bytes(server.process(1, &message).unwrap()));
            }
            to_client.extend(bytes(server.drain_output()));
            if to_client.is_empty() {
                break;
            }
            for message in to_client {
                to_server.extend(bytes(client.process(1, &message).unwrap()));
            }
        };
        let _ = server.start(1).unwrap();
        let hello = bytes(client.start(1).unwrap());
        exchange(&mut client, &mut server, hello);
        assert!(server.is_ready() && server.supports_avc420(), "RDP 10 with H.264 agreed");

        // A 64x32 desktop: red left half, blue right half, as H.264
        // (length-prefixed, as IronRDP's server sends it).
        let (w, h) = (64u16, 32u16);
        server.resize(w, h);
        let id = server.create_surface(w, h).unwrap();
        assert!(server.map_surface_to_output(id, 0, 0));
        let rgb: Vec<u8> = (0..w as usize * h as usize).flat_map(|i| if i % usize::from(w) < 32 { [255, 0, 0] } else { [0, 0, 255] }).collect();
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&rgb, (w.into(), h.into())));
        let mut encoder = openh264::encoder::Encoder::new().unwrap();
        let annex_b = encoder.encode(&yuv).unwrap().to_vec();
        let region = Avc420Region { left: 0, top: 0, right: w - 1, bottom: h - 1, quantization_parameter: 22, quality: 100 };
        assert!(server.send_avc420_frame(id, &annex_b_to_avc(&annex_b), &[region], 0).is_some());
        exchange(&mut client, &mut server, Vec::new());
        // Then as Windows sends it: Annex B as it is, a picture of the whole
        // surface (yellow | green) for its right half only.
        let rgb: Vec<u8> = (0..w as usize * h as usize).flat_map(|i| if i % usize::from(w) < 32 { [255, 255, 0] } else { [0, 255, 0] }).collect();
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&rgb, (w.into(), h.into())));
        let annex_b = encoder.encode(&yuv).unwrap().to_vec();
        let region = Avc420Region { left: 32, top: 0, right: w - 1, bottom: h - 1, quantization_parameter: 22, quality: 100 };
        assert!(server.send_avc420_frame(id, &annex_b, &[region], 0).is_some());
        exchange(&mut client, &mut server, Vec::new());

        let mut canvas = None;
        while let Ok(event) = received.try_recv() {
            match event {
                Event::Reset(width, height) => canvas = Some(Canvas::new(width, height)),
                Event::Note(_) => {}
                event => {
                    canvas.as_mut().expect("reset first").apply(event);
                }
            }
        }
        let canvas = canvas.expect("the server reset the graphics");
        assert_eq!((canvas.width(), canvas.height()), (64, 32));
        // H.264 is lossy: close, not exact.
        let near = |got: [u8; 4], want: [u8; 3]| got.iter().zip(want).all(|(&g, w)| g.abs_diff(w) <= 48);
        assert!(near(px(&canvas, 10, 10), [255, 0, 0]), "left: {:?}", px(&canvas, 10, 10));
        assert!(near(px(&canvas, 50, 20), [0, 255, 0]), "right: {:?}", px(&canvas, 50, 20));
    }

    /// A ClearCodec band with a short V-bar laid out as Windows sends it
    /// (shortVBarYOn in the first byte, shortVBarYOff in the next six bits);
    /// IronRDP 0.9 read it the other way round (see vendor/ironrdp-pdu).
    #[test]
    fn clearcodec_short_vbars_as_windows_sends_them() {
        // One column, rows 0..4: background grey, rows 1 and 2 from the V-bar.
        let mut bands = Vec::new();
        for v in [0u16, 0, 0, 3] {
            bands.extend(v.to_le_bytes()); // xStart, xEnd, yStart, yEnd
        }
        bands.extend([0x80, 0x80, 0x80]); // background, BGR
        bands.extend(((3u16 << 8) | 1).to_le_bytes()); // short V-bar miss: yOn 1, yOff 3
        bands.extend([0, 0, 255, 255, 0, 0]); // red, blue (BGR)
        let mut stream = vec![0u8, 0]; // flags, sequence number
        for count in [0, bands.len() as u32, 0] {
            stream.extend(count.to_le_bytes()); // residual, bands, subcodec byte counts
        }
        stream.extend(&bands);
        let bgra = ClearCodecDecoder::new().decode(&stream, 1, 4).expect("decodes");
        let rows: Vec<[u8; 4]> = bgra.as_chunks::<4>().0.to_vec();
        assert_eq!(rows, [[0x80, 0x80, 0x80, 255], [0, 0, 255, 255], [255, 0, 0, 255], [0x80, 0x80, 0x80, 255]]);
    }

    #[test]
    fn clearcodec_one_colour_rlex_as_windows_sends_it() {
        // An 89x2 area in one colour (33 bytes, as in a Windows 11 log):
        // packed byte (stop 0, depth 0), a run of 177, then the one-pixel suite.
        let rlex = [1, 0x10, 0x20, 0x30, 0x00, 177];
        let mut sub = Vec::new();
        for v in [0u16, 0, 89, 2] {
            sub.extend(v.to_le_bytes()); // xStart, yStart, width, height
        }
        sub.extend((rlex.len() as u32).to_le_bytes());
        sub.push(2); // RLEX
        sub.extend(rlex);
        let mut stream = vec![0u8, 0x2b];
        for count in [0, 0, sub.len() as u32] {
            stream.extend(count.to_le_bytes()); // residual, bands, subcodec byte counts
        }
        stream.extend(&sub);
        assert_eq!(stream.len(), 33);
        let bgra = ClearCodecDecoder::new().decode(&stream, 89, 2).expect("decodes");
        assert!(bgra.as_chunks::<4>().0.iter().all(|p| *p == [0x10, 0x20, 0x30, 255]));
    }

    /// ClearCodec without a residual layer draws only what its bands and
    /// subcodecs cover; the rest of its area keeps what the surface had.
    #[test]
    fn clearcodec_leaves_what_it_does_not_draw() {
        use ironrdp_egfx::pdu::{PixelFormat, WireToSurface1Pdu};
        let rlex = [1, 0x10, 0x20, 0x30, 0x00, 3]; // one colour, a run of 3 and the suite: 2x2
        let mut sub = Vec::new();
        for v in [0u16, 0, 2, 2] {
            sub.extend(v.to_le_bytes()); // xStart, yStart, width, height
        }
        sub.extend((rlex.len() as u32).to_le_bytes());
        sub.push(2); // RLEX
        sub.extend(rlex);
        let mut stream = vec![0u8, 0];
        for count in [0, 0, sub.len() as u32] {
            stream.extend(count.to_le_bytes()); // no residual, no bands
        }
        stream.extend(&sub);
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
        let mut handler = Handler::new(events);
        handler.on_unhandled_pdu(&GfxPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id: 1,
            codec_id: Codec1Type::ClearCodec,
            pixel_format: PixelFormat::XRgb,
            destination_rectangle: ExclusiveRectangle { left: 0, top: 0, right: 4, bottom: 2 },
            bitmap_data: stream,
        }));
        let mut canvas = Canvas::new(4, 2);
        canvas.apply(Event::Created { id: 1, width: 4, height: 2 });
        canvas.apply(Event::Mapped { id: 1, x: 0, y: 0 });
        canvas.apply(Event::Fill { id: 1, rgba: RED, areas: vec![(0, 0, 4, 2)] });
        while let Ok(event) = received.try_recv() {
            canvas.apply(event);
        }
        assert_eq!([px(&canvas, 1, 1), px(&canvas, 2, 0), px(&canvas, 3, 1)], [[0x30, 0x20, 0x10, 255], RED, RED]);
    }

    #[test]
    fn clearcodec_glyph_hit_for_a_smaller_area() {
        // Glyph 5: 2x2 of one colour (a residual run of 4).
        let mut store = vec![0x01, 0, 5, 0];
        for count in [4u32, 0, 0] {
            store.extend(count.to_le_bytes());
        }
        store.extend([0x10, 0x20, 0x30, 4]);
        let mut clear = ClearCodecDecoder::new();
        assert_eq!(clear.decode(&store, 2, 2).expect("stored").len(), 16);
        // Windows then reuses it for a 1x2 area (glyph hit, as in a Windows 11 log).
        let hit = clear.decode(&[0x03, 1, 5, 0], 1, 2).expect("a hit for an area the glyph covers");
        assert_eq!(hit, [0x10, 0x20, 0x30, 255, 0x10, 0x20, 0x30, 255]);
    }

    /// Progressive as Windows sends it: SYNC and CONTEXT once, full-quality
    /// tiles (quality 0xFF, no progressive table), a new codec context id for
    /// the next picture without CONTEXT.
    #[test]
    fn progressive_tiles_as_windows_sends_them() {
        use ironrdp::graphics::progressive::{encode_first_pass, rgba_to_ycbcr};
        use ironrdp::pdu::codecs::rfx::RfxRectangle;
        use ironrdp::pdu::codecs::rfx::progressive::*;
        use ironrdp_egfx::pdu::{Codec2Type, PixelFormat};

        // Windows' quantization (66 76 88 99 a9 on the wire).
        let quant = ComponentCodecQuant { ll3: 6, hl3: 6, lh3: 6, hh3: 7, hl2: 8, lh2: 8, hh2: 9, hl1: 9, lh1: 9, hh1: 10 };
        let encode = |rgb: [u8; 3]| -> [Vec<u8>; 3] {
            let rgba: Vec<u8> = (0..4096).flat_map(|_| [rgb[0], rgb[1], rgb[2], 255]).collect();
            let (mut y, mut cb, mut cr) = (vec![0i16; 4096], vec![0i16; 4096], vec![0i16; 4096]);
            rgba_to_ycbcr(&rgba, &mut y, &mut cb, &mut cr);
            // With 5 fractional bits, as Windows encodes (and FreeRDP decodes).
            [y, cb, cr].map(|c| c.iter().map(|v| v << 5).collect::<Vec<i16>>()).map(|mut c| {
                let mut out = vec![0u8; 16384];
                let n = encode_first_pass(&mut c, &mut out, &quant, &ComponentCodecQuant::LOSSLESS, true).unwrap();
                out.truncate(n);
                out
            })
        };
        let stream = |context: bool, x_idx: u16, data: &[Vec<u8>; 3]| -> Vec<u8> {
            let tile = TileFirst {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx,
                y_idx: 0,
                flags: 0,
                quality: 0xFF,
                y_data: &data[0],
                cb_data: &data[1],
                cr_data: &data[2],
                tail_data: &[],
            };
            let rects = vec![RfxRectangle { x: x_idx * 64, y: 0, width: 64, height: 64 }];
            let region = ProgressiveRegion {
                tile_size: 64,
                rects,
                quant_vals: vec![quant],
                quant_prog_vals: vec![],
                flags: FLAG_DWT_REDUCE_EXTRAPOLATE,
                tiles: vec![ProgressiveTile::First(tile)],
            };
            let mut blocks = Vec::new();
            if context {
                blocks.push(ProgressiveBlock::Sync(ProgressiveSyncPdu));
                blocks.push(ProgressiveBlock::Context(ProgressiveContextPdu { context_id: 0, tile_size: 64, flags: FLAG_DWT_REDUCE_EXTRAPOLATE }));
            }
            blocks.push(ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu { frame_index: 0, region_count: 1 }));
            blocks.push(ProgressiveBlock::Region(region));
            blocks.push(ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu));
            encode_progressive_stream(&blocks).unwrap()
        };

        let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
        let mut handler = Handler::new(events);
        handler.sizes.insert(1, (128, 64));
        let (red, blue) = (encode([255, 0, 0]), encode([0, 0, 255]));
        for (context_id, context, x_idx, data) in [(7, true, 0, &red), (8, false, 1, &blue)] {
            let bitmap_data = stream(context, x_idx, data);
            handler.on_wire_to_surface2(&WireToSurface2Pdu {
                surface_id: 1,
                codec_id: Codec2Type::RemoteFxProgressive,
                codec_context_id: context_id,
                pixel_format: PixelFormat::XRgb,
                bitmap_data,
            });
        }
        let mut canvas = Canvas::new(128, 64);
        canvas.apply(Event::Created { id: 1, width: 128, height: 64 });
        canvas.apply(Event::Mapped { id: 1, x: 0, y: 0 });
        while let Ok(event) = received.try_recv() {
            if let Event::Note(text) = &event {
                assert!(!text.contains("not decoded"), "{text}");
            }
            canvas.apply(event);
        }
        let near = |got: [u8; 4], want: [u8; 3]| got.iter().zip(want).all(|(&g, w)| g.abs_diff(w) <= 24);
        assert!(near(px(&canvas, 30, 30), [255, 0, 0]), "first tile: {:?}", px(&canvas, 30, 30));
        assert!(near(px(&canvas, 100, 30), [0, 0, 255]), "second tile: {:?}", px(&canvas, 100, 30));
    }

    /// Not a test: replays $REPLAY_DIR/*.prog (from OPENCRT_RDP_DUMP) to $REPLAY_DIR/ours.ppm.
    #[test]
    #[ignore]
    fn replay() {
        use ironrdp_egfx::pdu::{Codec2Type, PixelFormat};
        let dir = std::path::PathBuf::from(std::env::var("REPLAY_DIR").unwrap());
        let limit: usize = std::env::var("REPLAY_LIMIT").ok().and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);
        let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|n| n.ends_with(".prog")).collect();
        names.sort();
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
        let mut handler = Handler::new(events);
        let mut canvas: Option<Canvas> = None;
        for name in names.iter().take(limit) {
            let parts: Vec<&str> = name.trim_end_matches(".prog").split('-').collect();
            let id: u16 = parts[1].parse().unwrap();
            let (w, h) = parts[2].split_once('x').unwrap();
            let (w, h): (u16, u16) = (w.parse().unwrap(), h.parse().unwrap());
            let c = canvas.get_or_insert_with(|| {
                let mut c = Canvas::new(w.into(), h.into());
                c.apply(Event::Created { id, width: w.into(), height: h.into() });
                c.apply(Event::Mapped { id, x: 0, y: 0 });
                c
            });
            handler.sizes.insert(id, (w, h));
            let bitmap_data = std::fs::read(dir.join(name)).unwrap();
            handler.on_wire_to_surface2(&WireToSurface2Pdu { surface_id: id, codec_id: Codec2Type::RemoteFxProgressive, codec_context_id: 0, pixel_format: PixelFormat::XRgb, bitmap_data });
            while let Ok(event) = received.try_recv() {
                match event {
                    Event::Note(t) => eprintln!("{name}: {t}"),
                    e => {
                        c.apply(e);
                    }
                }
            }
        }
        let c = canvas.unwrap();
        let mut out = format!("P6 {} {} 255\n", c.width(), c.height()).into_bytes();
        out.extend(c.rgba().chunks(4).flat_map(|p| [p[0], p[1], p[2]]));
        std::fs::write(dir.join("ours.ppm"), out).unwrap();
    }

    #[test]
    fn copies_and_the_cache() {
        let mut canvas = Canvas::new(4, 2);
        canvas.apply(Event::Created { id: 1, width: 4, height: 2 });
        canvas.apply(Event::Mapped { id: 1, x: 0, y: 0 });
        canvas.apply(Event::Pixels { id: 1, at: (0, 0, 2, 1), rgba: [RED, BLUE].concat() });
        // Within the same surface, overlapping: the source is read first.
        canvas.apply(Event::Copy { from: 1, at: (0, 0, 2, 1), to: 1, points: vec![(1, 0)] });
        assert_eq!([px(&canvas, 0, 0), px(&canvas, 1, 0), px(&canvas, 2, 0)], [RED, RED, BLUE]);
        // Cached, then drawn twice from the cache.
        canvas.apply(Event::ToCache { id: 1, at: (1, 0, 2, 1), slot: 7 });
        canvas.apply(Event::FromCache { slot: 7, id: 1, points: vec![(0, 1), (2, 1)] });
        assert_eq!([px(&canvas, 0, 1), px(&canvas, 1, 1), px(&canvas, 2, 1), px(&canvas, 3, 1)], [RED, BLUE, RED, BLUE]);
        // A reset keeps the cache.
        let mut canvas = canvas.reset(4, 2);
        canvas.apply(Event::Created { id: 2, width: 4, height: 2 });
        canvas.apply(Event::Mapped { id: 2, x: 0, y: 0 });
        assert!(canvas.apply(Event::FromCache { slot: 7, id: 2, points: vec![(0, 0)] }));
        assert_eq!([px(&canvas, 0, 0), px(&canvas, 1, 0)], [RED, BLUE]);
        canvas.apply(Event::Evict(7));
        assert!(!canvas.apply(Event::FromCache { slot: 7, id: 1, points: vec![(0, 0)] }), "an evicted entry draws nothing");
        // Gone surfaces and unknown ones are ignored.
        assert!(canvas.apply(Event::Deleted(2)));
        assert!(!canvas.apply(Event::Fill { id: 2, rgba: RED, areas: vec![(0, 0, 1, 1)] }));
    }
}
