//! The clipboard both ways over the CLIPRDR channel: Unicode text, and
//! pictures as device-independent bitmaps (CF_DIB), which is what a
//! screenshot or Paint puts on a Windows clipboard.
//!
//! IronRDP calls the backend from inside the session's PDU processing, so it
//! cannot answer there: it queues what the channel should send next, and the
//! session loop hands that to the channel (see [`send`]).

use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::cliprdr::{Client, CliprdrClient, CliprdrSvcMessages};
use opencrt_rdp_proto::FromHelper;
use tokio::sync::mpsc::UnboundedSender;

use crate::Out;

const TEXT: ClipboardFormat = ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT);
const DIB: ClipboardFormat = ClipboardFormat::new(ClipboardFormatId::CF_DIB);

/// What OpenCRT's clipboard holds, as offered to the server.
#[derive(Debug)]
enum Local {
    Text(String),
    /// Already a CF_DIB.
    Image(Vec<u8>),
}

#[derive(Debug)]
pub struct Clipboard {
    local: Option<Local>,
    /// The format asked of the server, whose answer is on its way.
    fetching: Option<ClipboardFormatId>,
    /// What the channel should send next (handled by the session loop).
    queue: UnboundedSender<ClipboardMessage>,
    /// What was copied on the server goes straight to OpenCRT.
    out: Out,
}

ironrdp::core::impl_as_any!(Clipboard);

impl Clipboard {
    pub fn new(queue: UnboundedSender<ClipboardMessage>, out: Out) -> Self {
        Clipboard { local: None, fetching: None, queue, out }
    }

    /// OpenCRT's clipboard now holds text: offer it to the server.
    pub fn set_text(&mut self, text: String) {
        self.local = Some(Local::Text(text));
        let _ = self.queue.send(ClipboardMessage::SendInitiateCopy(vec![TEXT]));
    }

    /// OpenCRT's clipboard now holds a picture (RGBA rows): offer it as a bitmap.
    pub fn set_image(&mut self, width: u32, height: u32, rgba: &[u8]) {
        self.local = Some(Local::Image(rgba_to_dib(width, height, rgba)));
        let _ = self.queue.send(ClipboardMessage::SendInitiateCopy(vec![DIB]));
    }

    fn formats(&self) -> Vec<ClipboardFormat> {
        match self.local {
            Some(Local::Text(_)) => vec![TEXT],
            Some(Local::Image(_)) => vec![DIB],
            None => Vec::new(),
        }
    }
}

impl CliprdrBackend for Clipboard {
    fn temporary_directory(&self) -> &str {
        "" // files are not offered either way
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {
        let _ = self.queue.send(ClipboardMessage::SendInitiateCopy(self.formats()));
    }

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // Fetched at once, so it is on OpenCRT's clipboard when pasted; text
        // wins when both are there (an office program copies both).
        let wanted = [TEXT.id, DIB.id].into_iter().find(|&id| available_formats.iter().any(|f| f.id == id));
        self.fetching = wanted;
        if let Some(id) = wanted {
            let _ = self.queue.send(ClipboardMessage::SendInitiatePaste(id));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let response = match &self.local {
            Some(Local::Text(text)) if request.format == TEXT.id => FormatDataResponse::new_unicode_string(text),
            Some(Local::Image(dib)) if request.format == DIB.id => FormatDataResponse::new_data(dib.clone()),
            _ => FormatDataResponse::new_error(),
        };
        let _ = self.queue.send(ClipboardMessage::SendFormatData(response));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            return;
        }
        let message = match self.fetching.take() {
            Some(format) if format == TEXT.id => response.to_unicode_string().ok().map(FromHelper::Clipboard),
            Some(format) if format == DIB.id => {
                dib_to_rgba(response.data()).map(|(width, height, rgba)| FromHelper::ClipboardImage { width, height, rgba })
            }
            _ => None,
        };
        if let Some(message) = message {
            let _ = self.out.send(message);
        }
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        let _ = self.queue.send(ClipboardMessage::SendFileContentsResponse(FileContentsResponse::new_error(
            request.stream_id,
        )));
    }

    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _: LockDataId) {}

    fn on_unlock(&mut self, _: LockDataId) {}
}

/// The channel messages for a queued message (None for kinds never queued).
pub fn send(cliprdr: &mut CliprdrClient, message: ClipboardMessage) -> anyhow::Result<Option<CliprdrSvcMessages<Client>>> {
    Ok(Some(match message {
        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats)?,
        ClipboardMessage::SendFormatData(data) => cliprdr.submit_format_data(data)?,
        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format)?,
        ClipboardMessage::SendFileContentsResponse(response) => cliprdr.submit_file_contents(response)?,
        _ => return Ok(None),
    }))
}

/// Biggest picture accepted from the server, per side.
const MAX_SIDE: u32 = 16384;

/// RGBA rows as a CF_DIB: a BITMAPINFOHEADER, then 32-bit BGRA rows bottom up.
pub fn rgba_to_dib(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let size = width as usize * height as usize * 4;
    let mut dib = Vec::with_capacity(40 + size);
    dib.extend(40u32.to_le_bytes()); // header size
    dib.extend((width as i32).to_le_bytes());
    dib.extend((height as i32).to_le_bytes()); // positive: bottom-up rows
    dib.extend(1u16.to_le_bytes()); // planes
    dib.extend(32u16.to_le_bytes()); // bits per pixel
    dib.extend(0u32.to_le_bytes()); // BI_RGB
    dib.extend((size as u32).to_le_bytes());
    dib.extend(2835i32.to_le_bytes()); // 72 dpi
    dib.extend(2835i32.to_le_bytes());
    dib.extend(0u32.to_le_bytes()); // colours used
    dib.extend(0u32.to_le_bytes()); // colours important
    for row in rgba.chunks_exact(width as usize * 4).rev() {
        for p in row.as_chunks::<4>().0 {
            dib.extend([p[2], p[1], p[0], p[3]]);
        }
    }
    dib
}

/// A CF_DIB (or the CF_DIBV5 form of one) as (width, height, RGBA rows): 24-
/// and 32-bit pictures, uncompressed or with the usual BGR bit masks.
pub fn dib_to_rgba(dib: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(dib.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(dib.get(at..at + 4)?.try_into().ok()?));
    let header = u32_at(0)? as usize;
    let width = u32_at(4)? as i32;
    let height = u32_at(8)? as i32;
    let bits = u16_at(14)?;
    let compression = u32_at(16)?;
    let colours = u32_at(32)? as usize;
    if header < 40 || width <= 0 || height == 0 || width.unsigned_abs() > MAX_SIDE || height.unsigned_abs() > MAX_SIDE {
        return None;
    }
    // BI_BITFIELDS: the masks follow a plain header, or are part of a V4/V5 one.
    let masks = match compression {
        0 => 0,
        3 if bits == 32 => {
            // Right after a plain header, or the V4/V5 header's own mask fields: offset 40 either way.
            if (u32_at(40)?, u32_at(44)?, u32_at(48)?) != (0x00ff_0000, 0x0000_ff00, 0x0000_00ff) {
                return None;
            }
            if header == 40 { 12 } else { 0 }
        }
        _ => return None,
    };
    if bits != 24 && bits != 32 {
        return None;
    }
    let (w, h) = (width as usize, height.unsigned_abs() as usize);
    let stride = (w * bits as usize).div_ceil(32) * 4;
    let pixels = dib.get(header + masks + colours * 4..)?;
    if pixels.len() < stride * h {
        return None;
    }
    let step = bits as usize / 8;
    let mut rgba = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        // Rows run bottom up unless the height is negative.
        let row = if height > 0 { h - 1 - y } else { y };
        for p in pixels[row * stride..row * stride + w * step].chunks_exact(step) {
            rgba.extend([p[2], p[1], p[0], if step == 4 { p[3] } else { 255 }]);
        }
    }
    // Most 32-bit bitmaps leave the alpha byte at 0: they are opaque.
    if step == 4 && rgba.as_chunks::<4>().0.iter().all(|p| p[3] == 0) {
        rgba.as_chunks_mut::<4>().0.iter_mut().for_each(|p| p[3] = 255);
    }
    Some((w as u32, h as u32, rgba))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2x2 picture: red, green on top; blue, half-transparent white below.
    const RGBA: [u8; 16] = [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 128];

    #[test]
    fn pictures_survive_the_round_trip() {
        let dib = rgba_to_dib(2, 2, &RGBA);
        assert_eq!(dib.len(), 40 + 16);
        // Bottom-up BGRA: the first stored row is the picture's last.
        assert_eq!(&dib[40..44], [255, 0, 0, 255], "blue, as BGRA");
        assert_eq!(dib_to_rgba(&dib), Some((2, 2, RGBA.to_vec())));
    }

    #[test]
    fn windows_bitmaps_are_read() {
        // 24-bit, top-down (negative height), rows padded to 4 bytes.
        let mut dib = rgba_to_dib(1, 1, &[0; 4])[..40].to_vec();
        dib[8..12].copy_from_slice(&(-2i32).to_le_bytes());
        dib[14..16].copy_from_slice(&24u16.to_le_bytes());
        dib.extend([0, 0, 255, 0, /* row 2: */ 255, 0, 0, 0]);
        assert_eq!(dib_to_rgba(&dib), Some((1, 2, vec![255, 0, 0, 255, 0, 0, 255, 255])));
        // 32-bit with the alpha byte left at 0 is opaque.
        let mut dib = rgba_to_dib(1, 1, &[10, 20, 30, 0]);
        assert_eq!(dib_to_rgba(&dib), Some((1, 1, vec![10, 20, 30, 255])));
        // BI_BITFIELDS with the usual masks after a plain header.
        dib[16..20].copy_from_slice(&3u32.to_le_bytes());
        dib.splice(40..40, [0x00ff_0000u32, 0x0000_ff00, 0x0000_00ff].iter().flat_map(|m| m.to_le_bytes()));
        assert_eq!(dib_to_rgba(&dib), Some((1, 1, vec![10, 20, 30, 255])));
    }

    #[test]
    fn broken_bitmaps_are_refused() {
        let dib = rgba_to_dib(2, 2, &RGBA);
        assert_eq!(dib_to_rgba(&dib[..50]), None, "pixels cut short");
        assert_eq!(dib_to_rgba(&dib[..20]), None, "header cut short");
        let mut paletted = dib.clone();
        paletted[14..16].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(dib_to_rgba(&paletted), None, "8-bit pictures are not supported");
        let mut huge = dib;
        huge[4..8].copy_from_slice(&100_000i32.to_le_bytes());
        assert_eq!(dib_to_rgba(&huge), None);
    }
}
