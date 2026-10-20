//! The Graphics Pipeline ([MS-RDPEGFX]), which Windows' own client uses: the
//! desktop arrives as H.264 (AVC420) and a few lossless codecs, drawn into
//! surfaces the server creates, fills, copies and caches. [`Handler`] turns
//! the channel's callbacks into [`Event`]s; the session loop applies them to
//! a [`Canvas`], whose `output` (RGBA) is the desktop OpenCRT shows.
//!
//! [MS-RDPEGFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0

use std::collections::HashMap;

use ironrdp::graphics::clearcodec::ClearCodecDecoder;
use ironrdp::graphics::rdp6::BitmapStreamDecoder;
use ironrdp::pdu::geometry::ExclusiveRectangle;
use ironrdp_egfx::client::{BitmapUpdate, GraphicsPipelineHandler, Surface};
use ironrdp_egfx::pdu::{
    CacheToSurfacePdu, CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags, CapabilitiesV10Flags,
    CapabilitySet, Codec1Type, EvictCacheEntryPdu, GfxPdu, SolidFillPdu, SurfaceToCachePdu, SurfaceToSurfacePdu,
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
    /// Codecs already reported as not decoded (each once).
    unsupported: Vec<String>,
}

impl Handler {
    pub fn new(events: UnboundedSender<Event>) -> Self {
        Handler { events, clear: ClearCodecDecoder::new(), planar: BitmapStreamDecoder::default(), unsupported: Vec::new() }
    }

    fn send(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn unsupported(&mut self, what: String) {
        if !self.unsupported.contains(&what) {
            self.send(Event::Note(format!("graphics: {what} is not decoded")));
            self.unsupported.push(what);
        }
    }
}

impl GraphicsPipelineHandler for Handler {
    /// RDP 10 only, H.264 on: in RDP 10 Windows sends the screen as AVC420
    /// (unless told by policy to use AVC444, which IronRDP does not decode).
    /// RDP 8.x mixes in codecs that cannot be decoded here, so a server with
    /// only those keeps sending the classic (RemoteFX) way.
    fn capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::V10_7 { flags: CapabilitiesV107Flags::SMALL_CACHE },
            CapabilitySet::V10_6 { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_5 { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_4 { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_3 { flags: CapabilitiesV103Flags::empty() },
            CapabilitySet::V10_2 { flags: CapabilitiesV10Flags::SMALL_CACHE },
            CapabilitySet::V10 { flags: CapabilitiesV10Flags::SMALL_CACHE },
        ]
    }

    fn on_capabilities_confirmed(&mut self, caps: &CapabilitySet) {
        self.send(Event::Note(format!("graphics pipeline on: {caps:?}")));
    }

    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        self.send(Event::Reset(width, height));
    }

    fn on_surface_created(&mut self, surface: &Surface) {
        self.send(Event::Created { id: surface.id, width: surface.width.into(), height: surface.height.into() });
    }

    fn on_surface_deleted(&mut self, id: u16) {
        self.send(Event::Deleted(id));
    }

    fn on_surface_mapped(&mut self, id: u16, x: u32, y: u32) {
        self.send(Event::Mapped { id, x, y });
    }

    fn on_bitmap_updated(&mut self, update: &BitmapUpdate) {
        let (left, top, ..) = area(&update.destination_rectangle);
        let at = (left, top, update.width.into(), update.height.into());
        if update.data.len() == at.2 as usize * at.3 as usize * 4 {
            self.send(Event::Pixels { id: update.surface_id, at, rgba: update.data.clone() });
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
            if let GfxPdu::WireToSurface2(_) = pdu {
                self.unsupported("RemoteFX Progressive".into());
            }
            return;
        };
        let at = area(&pdu.destination_rectangle);
        let (w, h) = (at.2 as u16, at.3 as u16);
        let rgba = match pdu.codec_id {
            Codec1Type::ClearCodec => self.clear.decode(&pdu.bitmap_data, w, h).ok().map(|bgra| {
                let mut rgba = bgra;
                rgba.as_chunks_mut::<4>().0.iter_mut().for_each(|p| p.swap(0, 2));
                rgba
            }),
            Codec1Type::Planar => {
                let mut rgb = Vec::new();
                self.planar
                    .decode_bitmap_stream_to_rgb24(&pdu.bitmap_data, &mut rgb, w.into(), h.into())
                    .ok()
                    .map(|()| rgb.as_chunks::<3>().0.iter().flat_map(|p| [p[0], p[1], p[2], 255]).collect())
            }
            other => {
                self.unsupported(format!("{other:?}"));
                return;
            }
        };
        match rgba.filter(|px: &Vec<u8>| px.len() == usize::from(w) * usize::from(h) * 4) {
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

        // A 64x32 desktop: red left half, blue right half, as H.264.
        let (w, h) = (64u16, 32u16);
        server.resize(w, h);
        let id = server.create_surface(w, h).unwrap();
        assert!(server.map_surface_to_output(id, 0, 0));
        let rgb: Vec<u8> = (0..w as usize * h as usize).flat_map(|i| if i % usize::from(w) < 32 { [255, 0, 0] } else { [0, 0, 255] }).collect();
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&rgb, (w.into(), h.into())));
        let annex_b = openh264::encoder::Encoder::new().unwrap().encode(&yuv).unwrap().to_vec();
        let region = Avc420Region { left: 0, top: 0, right: w - 1, bottom: h - 1, quantization_parameter: 22, quality: 100 };
        assert!(server.send_avc420_frame(id, &annex_b_to_avc(&annex_b), &[region], 0).is_some());
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
        assert!(near(px(&canvas, 50, 20), [0, 0, 255]), "right: {:?}", px(&canvas, 50, 20));
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
        canvas.apply(Event::Evict(7));
        assert!(!canvas.apply(Event::FromCache { slot: 7, id: 1, points: vec![(0, 0)] }), "an evicted entry draws nothing");
        // Gone surfaces and unknown ones are ignored.
        assert!(canvas.apply(Event::Deleted(1)));
        assert!(!canvas.apply(Event::Fill { id: 1, rgba: RED, areas: vec![(0, 0, 1, 1)] }));
    }
}
